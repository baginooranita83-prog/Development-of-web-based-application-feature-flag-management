from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pathlib import Path
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Optional
import os
import jwt

from database import engine, Base, SessionLocal
from models import FeatureFlag, User, Environment,FlagVersion
from services.flag_service import (
    create_flag as create_flag_service,
    get_all_flags as get_all_flags_service,
    update_flag as update_flag_service,
)
from milestone3_api import create_milestone3_router, write_audit_log


# Load environment settings
load_dotenv(Path(__file__).resolve().parent / ".env")

app = FastAPI(
    
    title="Feature Flag Management System",
    description="API for managing users, environments, and feature flags.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration, login, and protected user endpoints"},
        {"name": "Feature Flags", "description": "Create, view, and update feature flags"},
        {"name": "Environments", "description": "Create, view, update, and delete environments"},
        {"name": "Health", "description": "Check application health"},
        {"name": "General", "description": "Home and dashboard pages"},
    ],
)

password_hash = PasswordHash.recommended()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if not JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY is missing. Check your .env file.")

security = HTTPBearer()


# ---------------- JWT UTILITIES ----------------

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
):
    token_data = data.copy()

    expiry = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    token_data.update({"exp": expiry})

    return jwt.encode(
        token_data,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )


# ---------------- AUTHENTICATION ----------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        email = payload.get("sub")

        if not email:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    db: Session = SessionLocal()

    try:
        user = db.query(User).filter(User.email == email).first()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="Your account is inactive"
            )

        return user.email

    finally:
        db.close()

# ---------------- ADMIN AUTHORIZATION ----------------

def require_admin(
    current_user: str = Depends(get_current_user)
):
    db: Session = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == current_user
        ).first()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        if user.role != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )

        return user.email

    finally:
        db.close()

app.include_router(create_milestone3_router(require_admin))


# ---------------- REQUEST MODELS ----------------

class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str

class FeatureFlagCreate(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    type: str = Field(default="boolean")
    default_value: Optional[object] = None
    enabled: bool = True
    description: Optional[str] = None
    environment_id: Optional[int] = None


class FeatureFlagUpdate(BaseModel):
    key: Optional[str] = Field(default=None, min_length=1, max_length=100)
    type: Optional[str] = None
    default_value: Optional[object] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None
    environment_id: Optional[int] = None


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = None


class EnvironmentUpdate(BaseModel):
    name: Optional[str] = Field(default=None,min_length=1,max_length=100) 
    description: Optional[str] = None


# ---------------- DATABASE ----------------

# Existing database schema is managed by Alembic.
Base.metadata.create_all(bind=engine)


# ---------------- HOME AND DASHBOARD ----------------

@app.get("/", tags=["General"])
def home():
    return FileResponse(
        Path(__file__).resolve().parent / "index.html"
    )


@app.get("/dashboard", tags=["General"])
def dashboard():
    return FileResponse(
        Path(__file__).resolve().parent / "dashboard.html"
    )


@app.get("/health", tags=["Health"])
def health_check():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")

        return {
            "status": "healthy",
            "database": "connected"
        }

    except Exception:
        return {
            "status": "unhealthy",
            "database": "disconnected"
        }


# ---------------- REGISTER ----------------

@app.post("/register", tags=["Authentication"])
@app.post("/api/auth/register", tags=["Authentication"])
def register_user(user_data: UserCreate):
    db: Session = SessionLocal()

    try:
        email = str(user_data.email).lower()

        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="Email is already registered"
            )

        new_user = User(
            name=user_data.name.strip(),
            email=email,
            hashed_password=password_hash.hash(user_data.password),
            role="user",
            is_active=True
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "message": "Account created successfully"
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ---------------- LOGIN ----------------

@app.post("/login", tags=["Authentication"])
@app.post("/api/auth/login", tags=["Authentication"])
def login_user(user_data: UserLogin):
    db: Session = SessionLocal()

    try:
        email = str(user_data.email).lower()

        user = db.query(User).filter(
            User.email == email
        ).first()

        if not user or not password_hash.verify(
            user_data.password,
            user.hashed_password
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="Your account is inactive. Please contact the administrator."
            )

        access_token = create_access_token(
            data={"sub": user.email}
        )

        return {
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "bearer",
            "redirect": "/dashboard"
        }

    finally:
        db.close()


# ---------------- CURRENT USER ----------------

@app.get("/me", tags=["Authentication"])
@app.get("/api/auth/me", tags=["Authentication"])
def get_my_profile(
    current_user: str = Depends(get_current_user)
):
    db: Session = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == current_user
        ).first()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        return {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at
        }

    finally:
        db.close()


# ---------------- PROTECTED ADMIN TEST ----------------

@app.get("/api/auth/admin-test", tags=["Authentication"])
def admin_test(
    current_user: str = Depends(require_admin)
):
    return {
        "message": "Authenticated access granted",
        "user": current_user
    }


# ---------------- FEATURE FLAGS ----------------

@app.post("/flags", tags=["Feature Flags"])
def create_flag(
    flag_name: str,
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        flag = create_flag_service(db, flag_name)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="CREATE",
            resource_type="FEATURE_FLAG",
            resource_id=flag.id,
            details={
                "flag_name": flag.flag_name,
                "enabled": flag.enabled
            }
        )

        return {
            "id": flag.id,
            "flag_name": flag.flag_name,
            "enabled": flag.enabled
        }

    finally:
        db.close()


@app.get("/flags", tags=["Feature Flags"])
def get_flags(
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        flags = get_all_flags_service(db)

        return [
            {
                "id": flag.id,
                "flag_name": flag.flag_name,
                "enabled": flag.enabled
            }
            for flag in flags
        ]

    finally:
        db.close()


@app.put("/flags/{flag_id}", tags=["Feature Flags"])
def update_flag(
    flag_id: int,
    enabled: bool,
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        flag = update_flag_service(db, flag_id, enabled)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="UPDATE",
            resource_type="FEATURE_FLAG",
            resource_id=flag.id,
            details={
                "flag_name": flag.flag_name,
                "enabled": flag.enabled
            }
        )

        return {
            "id": flag.id,
            "flag_name": flag.flag_name,
            "enabled": flag.enabled
        }

    finally:
        db.close()


# ---------------- ENVIRONMENTS ----------------

@app.post("/environments", tags=["Environments"])
def create_environment(
    name: str,
    description: str = "",
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        existing = db.query(Environment).filter(
            Environment.name == name
        ).first()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Environment already exists"
            )

        environment = Environment(
            name=name,
            description=description
        )

        db.add(environment)
        db.commit()
        db.refresh(environment)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="CREATE",
            resource_type="ENVIRONMENT",
            resource_id=environment.id,
            details={
                "name": environment.name,
                "description": environment.description
            }
        )

        return {
            "id": environment.id,
            "name": environment.name,
            "description": environment.description
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@app.get("/environments", tags=["Environments"])
def get_environments(
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        environments = db.query(Environment).all()

        return [
            {
                "id": environment.id,
                "name": environment.name,
                "description": environment.description
            }
            for environment in environments
        ]

    finally:
        db.close()


@app.put("/environments/{environment_id}", tags=["Environments"])
def update_environment(
    environment_id: int,
    name: str,
    description: str = "",
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(
                status_code=404,
                detail="Environment not found"
            )

        duplicate = db.query(Environment).filter(
            Environment.name == name,
            Environment.id != environment_id
        ).first()

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="Environment name already exists"
            )

        environment.name = name
        environment.description = description

        db.commit()
        db.refresh(environment)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="UPDATE",
            resource_type="ENVIRONMENT",
            resource_id=environment.id,
            details={
                "name": environment.name,
                "description": environment.description
            }
        )

        return {
            "id": environment.id,
            "name": environment.name,
            "description": environment.description
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


@app.delete("/environments/{environment_id}", tags=["Environments"])
def delete_environment(
    environment_id: int,
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(
                status_code=404,
                detail="Environment not found"
            )

        from models import FlagVersion

        linked_versions = db.query(FlagVersion).filter(
            FlagVersion.environment_id == environment_id
        ).first()

        if linked_versions:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete this environment because feature flag versions are linked to it."
            )
        deleted_environment_name = environment.name
        deleted_environment_description = environment.description

        db.delete(environment)
        db.commit()
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="DELETE",
            resource_type="ENVIRONMENT",
            resource_id=environment_id,
            details={
                "name": deleted_environment_name,
                "description": deleted_environment_description
            }
        )

        return {
            "message": "Environment deleted successfully"
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()



@app.get("/api/v1/flags", tags=["Feature Flags"])
def list_flags_v1(
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        flags = db.query(FeatureFlag).all()

        return [
            {
                "id": flag.id,
                "key": flag.flag_name,
                "type": flag.flag_type,
                "default_value": flag.default_value,
                "enabled": flag.enabled,
                "description": flag.description,
                "environment_id": flag.environment_id,
                "created_at": flag.created_at,
                "updated_at": flag.updated_at
            }
            for flag in flags
        ]

    finally:
        db.close()

# ---------------- ENVIRONMENT V1 APIs ----------------

# 1. GET ALL ENVIRONMENTS
@app.get("/api/v1/environments", tags=["Environments"])
def list_environments_v1(
    current_user: str = Depends(require_admin)
):
    db: Session = SessionLocal()

    try:
        environments = db.query(Environment).all()

        return [
            {
                "id": env.id,
                "name": env.name,
                "description": env.description
            }
            for env in environments
        ]

    finally:
        db.close()

# 2. CREATE ENVIRONMENT V1
@app.post("/api/v1/environments", tags=["Environments"])
def create_environment_v1(
    environment: EnvironmentCreate,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()
    try:
        name = environment.name.strip()

        if not name:
            raise HTTPException(status_code=400, detail="Environment name cannot be empty")

        existing = db.query(Environment).filter(
            Environment.name == name
        ).first()

        if existing:
            raise HTTPException(status_code=409, detail="Environment already exists")

        new_environment = Environment(
            name=name,
            description=environment.description
        )

        db.add(new_environment)
        db.commit()
        db.refresh(new_environment)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="CREATE",
            resource_type="ENVIRONMENT",
            resource_id=new_environment.id,
            details={
                "name": new_environment.name,
                "description": new_environment.description
            }
        )

        return {
            "id": new_environment.id,
            "name": new_environment.name,
            "description": new_environment.description
        }
    finally:
        db.close()


# 3. GET ENVIRONMENT BY ID
@app.get("/api/v1/environments/{environment_id}", tags=["Environments"])
def get_environment_v1(
    environment_id: int,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()
    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(status_code=404, detail="Environment not found")

        return environment
    finally:
        db.close()


# 4. UPDATE ENVIRONMENT
@app.put("/api/v1/environments/{environment_id}", tags=["Environments"])
def update_environment_v1(
    environment_id: int,
    data: EnvironmentUpdate,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()
    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(status_code=404, detail="Environment not found")

        updates = data.model_dump(exclude_unset=True)

        if "name" in updates:
            if updates["name"] is None or not updates["name"].strip():
                raise HTTPException(status_code=400, detail="Environment name cannot be empty")

            updates["name"] = updates["name"].strip()

            duplicate = db.query(Environment).filter(
                Environment.name == updates["name"],
                Environment.id != environment_id
            ).first()

            if duplicate:
                raise HTTPException(status_code=409, detail="Environment name already exists")

        for key, value in updates.items():
            setattr(environment, key, value)

        db.commit()
        db.refresh(environment)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="UPDATE",
            resource_type="ENVIRONMENT",
            resource_id=environment.id,
            details={
                "name": environment.name,
                "description": environment.description
            }
        )

        return {
            "id": environment.id,
            "name": environment.name,
            "description": environment.description
        }
    finally:
        db.close()


# 5. DELETE ENVIRONMENT
@app.delete("/api/v1/environments/{environment_id}", tags=["Environments"])
def delete_environment_v1(
    environment_id: int,
    current_user: str = Depends(require_admin)
):
    from models import EvaluationStats

    db = SessionLocal()
    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(status_code=404, detail="Environment not found")

        has_flags = db.query(FeatureFlag).filter(
            FeatureFlag.environment_id == environment_id
        ).first()

        has_versions = db.query(FlagVersion).filter(
            FlagVersion.environment_id == environment_id
        ).first()

        has_stats = db.query(EvaluationStats).filter(
            EvaluationStats.environment_id == environment_id
        ).first()

        if has_flags or has_versions or has_stats:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete environment because it is linked to other records"
            )
        deleted_environment_name = environment.name
        deleted_environment_description = environment.description

        db.delete(environment)
        db.commit()
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="DELETE",
            resource_type="ENVIRONMENT",
            resource_id=environment_id,
            details={
                "name": deleted_environment_name,
                "description": deleted_environment_description
            }
        )


        return {"message": "Environment deleted successfully"}
    finally:
        db.close()


# 6. GET FLAGS BY ENVIRONMENT
@app.get("/api/v1/environments/{environment_id}/flags", tags=["Environments"])
def get_environment_flags_v1(
    environment_id: int,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()
    try:
        environment = db.query(Environment).filter(
            Environment.id == environment_id
        ).first()

        if not environment:
            raise HTTPException(status_code=404, detail="Environment not found")

        flags = db.query(FeatureFlag).filter(
            FeatureFlag.environment_id == environment_id
        ).all()

        return [
            {
                "id": flag.id,
                "flag_name": flag.flag_name,
                "enabled": flag.enabled,
                "environment_id": flag.environment_id
            }
            for flag in flags
        ]
    finally:
        db.close()

# 1. CREATE FEATURE FLAG V1
@app.post("/api/v1/flags", tags=["Feature Flags"])
def create_flag_v1(
    flag_data: FeatureFlagCreate,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()

    try:
        if flag_data.environment_id is not None:
            environment = db.query(Environment).filter(
                Environment.id == flag_data.environment_id
            ).first()

            if not environment:
                raise HTTPException(404, "Environment not found")

        existing = db.query(FeatureFlag).filter(
            FeatureFlag.flag_name == flag_data.key
        ).first()

        if existing:
            raise HTTPException(409, "Feature flag already exists")

        flag = FeatureFlag(
            flag_name=flag_data.key,
            flag_type=flag_data.type,
            default_value=flag_data.default_value,
            enabled=flag_data.enabled,
            description=flag_data.description,
            environment_id=flag_data.environment_id
        )

        db.add(flag)
        db.commit()
        db.refresh(flag)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="CREATE",
            resource_type="FEATURE_FLAG",
            resource_id=flag.id,
            details={
                "flag_name": flag.flag_name,
                "type": flag.flag_type,
                "enabled": flag.enabled,
                "environment_id": flag.environment_id
            }
        )

        return {
            "id": flag.id,
            "key": flag.flag_name,
            "type": flag.flag_type,
            "default_value": flag.default_value,
            "enabled": flag.enabled,
            "description": flag.description,
            "environment_id": flag.environment_id
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# 2. GET FEATURE FLAG BY ID
@app.get("/api/v1/flags/{flag_id}", tags=["Feature Flags"])
def get_flag_v1(
    flag_id: int,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()

    try:
        flag = db.query(FeatureFlag).filter(
            FeatureFlag.id == flag_id
        ).first()

        if not flag:
            raise HTTPException(404, "Feature flag not found")

        return {
            "id": flag.id,
            "key": flag.flag_name,
            "type": flag.flag_type,
            "default_value": flag.default_value,
            "enabled": flag.enabled,
            "description": flag.description,
            "environment_id": flag.environment_id
        }

    finally:
        db.close()


# 3. UPDATE FEATURE FLAG
@app.put("/api/v1/flags/{flag_id}", tags=["Feature Flags"])
def update_flag_v1(
    flag_id: int,
    flag_data: FeatureFlagUpdate,
    current_user: str = Depends(require_admin)
):
    db = SessionLocal()

    try:
        flag = db.query(FeatureFlag).filter(
            FeatureFlag.id == flag_id
        ).first()

        if not flag:
            raise HTTPException(404, "Feature flag not found")

        updates = flag_data.model_dump(exclude_unset=True)

        if "key" in updates:
            if not updates["key"] or not updates["key"].strip():
                raise HTTPException(422, "Flag key cannot be empty")
            updates["key"] = updates["key"].strip()
            duplicate = db.query(FeatureFlag).filter(
                FeatureFlag.flag_name == updates["key"],
                FeatureFlag.id != flag_id
            ).first()

            if duplicate:
                raise HTTPException(409, "Feature flag already exists")

            flag.flag_name = updates.pop("key")

        if "type" in updates:
            if updates["type"] is None:
                raise HTTPException(422, "Flag type cannot be empty")

            flag.flag_type = updates.pop("type")

        if "environment_id" in updates:
            env_id = updates["environment_id"]

            if env_id is not None:
                environment = db.query(Environment).filter(
                    Environment.id == env_id
                ).first()

                if not environment:
                    raise HTTPException(404, "Environment not found")

        for field, value in updates.items():
            setattr(flag, field, value)

        db.commit()
        db.refresh(flag)
        write_audit_log(
            db=db,
            admin_email=current_user,
            action="UPDATE",
            resource_type="FEATURE_FLAG",
            resource_id=flag.id,
            details={
                "flag_name": flag.flag_name,
                "type": flag.flag_type,
                "default_value": flag.default_value,
                "enabled": flag.enabled,
                "description": flag.description,
                "environment_id": flag.environment_id
            }
        )

        return {
            "id": flag.id,
            "key": flag.flag_name,
            "type": flag.flag_type,
            "default_value": flag.default_value,
            "enabled": flag.enabled,
            "description": flag.description,
            "environment_id": flag.environment_id
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()





# 2. CREATE ENVIRONMENT
@app.delete("/api/v1/flags/{flag_id}", tags=["Feature Flags"])

def delete_flag_v1(
    flag_id: int,
    current_user: str = Depends(require_admin)
):
    from models import TargetingRule, EvaluationStats

    db: Session = SessionLocal()

    try:
        flag = db.query(FeatureFlag).filter(
            FeatureFlag.id == flag_id
        ).first()

        if not flag:
            raise HTTPException(
                status_code=404,
                detail="Feature flag not found"
            )

        # Check related flag versions
        if db.query(FlagVersion).filter(
            FlagVersion.feature_flag_id == flag_id
        ).first():
            raise HTTPException(
                status_code=409,
                detail="Cannot delete flag because versions are linked to it."
            )

        # Check related targeting rules
        if db.query(TargetingRule).filter(
            TargetingRule.feature_flag_id == flag_id
        ).first():
            raise HTTPException(
                status_code=409,
                detail="Cannot delete flag because targeting rules are linked to it."
            )

        # Check related evaluation statistics
        if db.query(EvaluationStats).filter(
            EvaluationStats.feature_flag_id == flag_id
        ).first():
            raise HTTPException(
                status_code=409,
                detail="Cannot delete flag because evaluation statistics are linked to it."
            )

        db.delete(flag)
        db.commit()

        return {
            "message": "Feature flag deleted successfully",
            "id": flag_id
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()




import os
import secrets
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from database import SessionLocal
from models import AuditLog, User, EvaluationStats, FeatureFlag,Environment
from services.targeting_service import (
    create_targeting_rule,
    get_targeting_rules,
    update_targeting_rule,
    delete_targeting_rule,
)
from services.group_service import (
    create_group,
    get_all_groups,
    add_user_to_group,
    remove_user_from_group,
)
from services.rollout_service import (
    set_rollout_percentage,
    toggle_flag,
)
from services.evaluation_service import evaluate_flag


# ---------------- REQUEST MODELS ----------------

class TargetingRuleCreate(BaseModel):
    rule_name: str = Field(min_length=1, max_length=100)
    rule_type: Literal["user", "specific_user", "group"]
    attribute: str = Field(min_length=1, max_length=100)
    operator: str = Field(min_length=1, max_length=50)
    value: Any
    result: bool
    priority: int = 100


class TargetingRuleUpdate(BaseModel):
    rule_name: str = Field(min_length=1, max_length=100)
    operator: str = Field(min_length=1, max_length=50)
    attribute: str = Field(min_length=1, max_length=100)
    value: Any
    result: bool
    priority: int = 100
    is_active: bool = True


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = None


class RolloutUpdate(BaseModel):
    percentage: int = Field(ge=0, le=100)


class FlagToggle(BaseModel):
    enabled: bool


class FlagEvaluationRequest(BaseModel):
    external_id: str = Field(min_length=1, max_length=255)
    environment: str = Field(min_length=1, max_length=100)


# ---------------- TRUSTED APP AUTHENTICATION ----------------

evaluation_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False
)


def require_evaluation_api_key(

    api_key: Optional[str] = Depends(evaluation_api_key_header)
):
    configured_key = os.getenv("EVALUATION_API_KEY")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="Evaluation API authentication is not configured"
        )

    if not api_key or not secrets.compare_digest(
        api_key,
        configured_key
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing application API key"
        )

    return True


# ---------------- ROUTER FACTORY ----------------

def write_audit_log(
    db: Session,
    admin_email: str,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None
):
    admin_user = db.query(User).filter(
        User.email == admin_email
    ).first()

    if not admin_user:
        raise HTTPException(
            status_code=404,
            detail="Administrator not found for audit logging"
        )

    audit_record = AuditLog(
        user_id=admin_user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details
    )

    db.add(audit_record)
    db.commit()
def create_milestone3_router(admin_dependency):
    router = APIRouter()

    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    # ---------------- TARGETING RULE APIs ----------------

    @router.post("/api/v1/flags/{flag_id}/rules", tags=["Targeting Rules"])
    def create_rule_api(
        flag_id: int,
        data: TargetingRuleCreate,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        rule = create_targeting_rule(
            db=db,
            flag_id=flag_id,
            rule_name=data.rule_name,
            rule_type=data.rule_type,
            attribute=data.attribute,
            operator=data.operator,
            value=data.value,
            result=data.result,
            priority=data.priority
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="CREATE",
            resource_type="TARGETING_RULE",
            resource_id=rule.id,
            details={
                "rule_name": rule.rule_name,
                "flag_id": flag_id
            }
        )


        return {
            "id": rule.id,
            "flag_id": rule.feature_flag_id,
            "rule_name": rule.rule_name,
            "rule_type": rule.rule_type,
            "attribute": rule.attribute,
            "operator": rule.operator,
            "value": rule.value,
            "result": rule.result,
            "priority": rule.priority,
            "is_active": rule.is_active
        }

    @router.get("/api/v1/flags/{flag_id}/rules", tags=["Targeting Rules"])
    def list_rules_api(
        flag_id: int,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        rules = get_targeting_rules(db, flag_id)

        return [
            {
                "id": rule.id,
                "flag_id": rule.feature_flag_id,
                "rule_name": rule.rule_name,
                "rule_type": rule.rule_type,
                "attribute": rule.attribute,
                "operator": rule.operator,
                "value": rule.value,
                "result": rule.result,
                "priority": rule.priority,
                "is_active": rule.is_active
            }
            for rule in rules
        ]

    @router.put("/api/v1/rules/{rule_id}", tags=["Targeting Rules"])
    def update_rule_api(
        rule_id: int,
        data: TargetingRuleUpdate,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        rule = update_targeting_rule(
            db=db,
            rule_id=rule_id,
            rule_name=data.rule_name,
            operator=data.operator,
            attribute=data.attribute,
            value=data.value,
            result=data.result,
            priority=data.priority,
            is_active=data.is_active
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="UPDATE",
            resource_type="TARGETING_RULE",
            resource_id=rule.id,
            details={
                "rule_name": rule.rule_name
            }
        )


        return {
            "message": "Targeting rule updated successfully",
            "id": rule.id,
            "rule_name": rule.rule_name,
            "result": rule.result,
            "priority": rule.priority,
            "is_active": rule.is_active
        }

    @router.delete("/api/v1/rules/{rule_id}", tags=["Targeting Rules"])
    def delete_rule_api(
        rule_id: int,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        result = delete_targeting_rule(db, rule_id)

        write_audit_log(
            db=db,
            admin_email=admin,
            action="DELETE",
            resource_type="TARGETING_RULE",
            resource_id=rule_id,
            details={
                "message": result["message"]
            }
        )

        return result


    # ---------------- USER GROUP APIs ----------------

    @router.post("/api/v1/groups", tags=["User Groups"])
    def create_group_api(
        data: GroupCreate,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        group = create_group(
            db,
            data.name.strip(),
            data.description
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="CREATE",
            resource_type="USER_GROUP",
            resource_id=group.id,
            details={
                "group_name": group.name
            }
        )



        return {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_at": group.created_at
        }

    @router.get("/api/v1/groups", tags=["User Groups"])
    def list_groups_api(
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        groups = get_all_groups(db)

        return [
            {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "created_at": group.created_at
            }
            for group in groups
        ]

    @router.post(
        "/api/v1/groups/{group_id}/members",
        tags=["User Groups"]
    )
    def add_group_member_api(
        group_id: int,
        user_id: int,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        membership = add_user_to_group(
            db,
            group_id,
            user_id
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="ADD_MEMBER",
            resource_type="USER_GROUP",
            resource_id=group_id,
            details={
                "end_user_id": user_id,
                "membership_id": membership.id
            }
        )


        return {
            "id": membership.id,
            "group_id": membership.group_id,
            "user_id": membership.end_user_id,
            "message": "User added to group successfully"
        }

    @router.delete(
        "/api/v1/groups/{group_id}/members/{user_id}",
        tags=["User Groups"]
    )

    def remove_group_member_api(
        group_id: int,
        user_id: int,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        result = remove_user_from_group(
            db,
            group_id,
            user_id
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="REMOVE_MEMBER",
            resource_type="USER_GROUP",
            resource_id=group_id,
            details={
                "end_user_id": user_id
            }
        )

        return result






    # ---------------- ROLLOUT AND KILL SWITCH APIs ----------------
    @router.put(
        "/api/v1/flags/{flag_id}/rollout",
        tags=["Feature Flags"]
    )
    def update_rollout_api(
        flag_id: int,
        data: RolloutUpdate,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        result = set_rollout_percentage(
            db,
            flag_id,
            data.percentage
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="UPDATE_ROLLOUT",
            resource_type="FEATURE_FLAG",
            resource_id=flag_id,
            details={
                "rollout_percentage": result["rollout_percentage"],
                "flag_name": result["flag_name"]
            }
        )

        return result


    @router.put(
        "/api/v1/flags/{flag_id}/toggle",
        tags=["Feature Flags"]
    )
    def toggle_flag_api(
        flag_id: int,
        data: FlagToggle,
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):

        result = toggle_flag(
            db,
            flag_id,
            data.enabled
        )

        write_audit_log(
            db=db,
            admin_email=admin,
            action="TOGGLE",
            resource_type="FEATURE_FLAG",
            resource_id=flag_id,
            details={
                "enabled": data.enabled
            }
        )

        return result



    # ---------------- FLAG EVALUATION API ----------------

    @router.post(
        "/api/v1/flags/{flag_id}/evaluate",
        tags=["Flag Evaluation"]
    )
    def evaluate_flag_api(
        flag_id: int,
        data: FlagEvaluationRequest,
        db: Session = Depends(get_db),
        authenticated_app: bool = Depends(
            require_evaluation_api_key
        )
    ):
        result = evaluate_flag(
            db=db,
            flag_id=flag_id,
            external_id=data.external_id,
            environment_name=data.environment
        )

        flag = db.query(FeatureFlag).filter(
            FeatureFlag.id == flag_id
        ).first()

        if not flag:
            raise HTTPException(
                status_code=404,
                detail="Feature flag not found"
            )

        enabled_increment = 0
        disabled_increment = 0

        if flag.flag_type == "boolean" and type(result["value"]) is bool:
            if result["value"] is True:
                enabled_increment = 1
            else:
                disabled_increment = 1

        stats_table = EvaluationStats.__table__

        statement = pg_insert(stats_table).values(
            feature_flag_id=flag_id,
            environment_id=flag.environment_id,
            evaluation_count=1,
            enabled_count=enabled_increment,
            disabled_count=disabled_increment
        )

        statement = statement.on_conflict_do_update(
            constraint="uq_evaluation_stats_flag_environment",
            set_={
                "evaluation_count": stats_table.c.evaluation_count + 1,
                "enabled_count": stats_table.c.enabled_count + enabled_increment,
                "disabled_count": stats_table.c.disabled_count + disabled_increment,
            }
        )

        db.execute(statement)
        db.commit()

        return result

    # ---------------- ANALYTICS API ----------------

    @router.get("/api/v1/analytics", tags=["Analytics"])
    def get_analytics_api(
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        records = (
            db.query(EvaluationStats, FeatureFlag, Environment)
            .join(
                FeatureFlag,
                EvaluationStats.feature_flag_id == FeatureFlag.id
            )
            .outerjoin(
                Environment,
                EvaluationStats.environment_id == Environment.id
            )
            .order_by(EvaluationStats.recorded_at.desc())
            .all()
        )

        return [
            {
                "feature_flag_id": stats.feature_flag_id,
                "flag_name": flag.flag_name,
                "environment": environment.name if environment else None,
                "evaluation_count": stats.evaluation_count,
                "enabled_count": stats.enabled_count,
                "disabled_count": stats.disabled_count,
                "recorded_at": stats.recorded_at
            }
            for stats, flag, environment in records
        ]

    # ---------------- AUDIT LOGS API ----------------

    @router.get("/api/v1/audit-logs", tags=["Audit Logs"])
    def get_audit_logs_api(
        db: Session = Depends(get_db),
        admin: str = Depends(admin_dependency)
    ):
        records = (
            db.query(AuditLog, User.email)
            .outerjoin(User, AuditLog.user_id == User.id)
            .order_by(AuditLog.created_at.desc())
            .limit(100)
            .all()
        )

        return [
            {
                "id": log.id,
                "admin_email": email,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "created_at": log.created_at
            }
            for log, email in records
        ]
    return router

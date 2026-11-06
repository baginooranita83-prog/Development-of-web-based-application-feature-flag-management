import os
import secrets
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import SessionLocal
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
        return delete_targeting_rule(db, rule_id)

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
        return remove_user_from_group(
            db,
            group_id,
            user_id
        )

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
        return set_rollout_percentage(
            db,
            flag_id,
            data.percentage
        )

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
        return toggle_flag(
            db,
            flag_id,
            data.enabled
        )

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
        return evaluate_flag(
            db=db,
            flag_id=flag_id,
            external_id=data.external_id,
            environment_name=data.environment
        )

    return router
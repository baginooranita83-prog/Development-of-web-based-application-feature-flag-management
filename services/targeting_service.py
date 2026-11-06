from sqlalchemy.orm import Session
from fastapi import HTTPException
from models import FeatureFlag, TargetingRule


def create_targeting_rule(
    db: Session,
    flag_id: int,
    rule_name: str,
    rule_type: str,
    attribute: str,
    operator: str,
    value,
    result: bool,
    priority: int = 100,
):
    flag = db.query(FeatureFlag).filter(
        FeatureFlag.id == flag_id
    ).first()

    if not flag:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found"
        )

    new_rule = TargetingRule(
        feature_flag_id=flag_id,
        rule_name=rule_name,
        rule_type=rule_type,
        attribute=attribute,
        operator=operator,
        value=value,
        result=result,
        priority=priority,
        is_active=True,
    )

    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    return new_rule


def get_targeting_rules(db: Session, flag_id: int):
    flag = db.query(FeatureFlag).filter(
        FeatureFlag.id == flag_id
    ).first()

    if not flag:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found"
        )

    return (
        db.query(TargetingRule)
        .filter(TargetingRule.feature_flag_id == flag_id)
        .order_by(
            TargetingRule.priority.asc(),
            TargetingRule.id.asc()
        )
        .all()
    )


def update_targeting_rule(
    db: Session,
    rule_id: int,
    rule_name: str,
    operator: str,
    attribute: str,
    value,
    result: bool,
    priority: int,
    is_active: bool,
):
    rule = db.query(TargetingRule).filter(
        TargetingRule.id == rule_id
    ).first()

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Targeting rule not found"
        )

    rule.rule_name = rule_name
    rule.operator = operator
    rule.attribute = attribute
    rule.value = value
    rule.result = result
    rule.priority = priority
    rule.is_active = is_active

    db.commit()
    db.refresh(rule)

    return rule


def delete_targeting_rule(db: Session, rule_id: int):
    rule = db.query(TargetingRule).filter(
        TargetingRule.id == rule_id
    ).first()

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Targeting rule not found"
        )

    db.delete(rule)
    db.commit()

    return {
        "message": "Targeting rule deleted successfully",
        "id": rule_id
    }
from sqlalchemy.orm import Session
from fastapi import HTTPException

from models import FeatureFlag


# -----------------------------------------
# SET FEATURE FLAG ROLLOUT PERCENTAGE
# -----------------------------------------

def set_rollout_percentage(
    db: Session,
    flag_id: int,
    percentage: int
):
    if percentage < 0 or percentage > 100:
        raise HTTPException(
            status_code=400,
            detail="Rollout percentage must be between 0 and 100"
        )

    flag = db.query(FeatureFlag).filter(
        FeatureFlag.id == flag_id
    ).first()

    if not flag:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found"
        )

    flag.rollout_percentage = percentage

    db.commit()
    db.refresh(flag)

    return {
        "message": "Rollout percentage updated successfully",
        "flag_id": flag.id,
        "flag_name": flag.flag_name,
        "rollout_percentage": flag.rollout_percentage
    }


# -----------------------------------------
# FEATURE FLAG TOGGLE / KILL SWITCH
# -----------------------------------------

def toggle_flag(
    db: Session,
    flag_id: int,
    enabled: bool
):
    flag = db.query(FeatureFlag).filter(
        FeatureFlag.id == flag_id
    ).first()

    if not flag:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found"
        )

    flag.enabled = enabled

    db.commit()
    db.refresh(flag)

    return {
        "message": "Feature flag status updated successfully",
        "flag_id": flag.id,
        "flag_name": flag.flag_name,
        "enabled": flag.enabled
    }
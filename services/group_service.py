from sqlalchemy.orm import Session
from fastapi import HTTPException
from models import UserGroup, UserGroupMembership, EndUser


def create_group(db: Session, name: str, description: str = None):
    existing_group = db.query(UserGroup).filter(
        UserGroup.name == name
    ).first()

    if existing_group:
        raise HTTPException(
            status_code=409,
            detail="Group already exists"
        )

    new_group = UserGroup(
        name=name,
        description=description
    )

    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    return new_group


def get_all_groups(db: Session):
    return db.query(UserGroup).order_by(UserGroup.id.asc()).all()


def add_user_to_group(db: Session, group_id: int, user_id: int):
    group = db.query(UserGroup).filter(
        UserGroup.id == group_id
    ).first()

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    end_user = db.query(EndUser).filter(
        EndUser.id == user_id
    ).first()

    if not end_user:
        raise HTTPException(status_code=404, detail="End user not found")

    existing_membership = db.query(UserGroupMembership).filter(
        UserGroupMembership.group_id == group_id,
        UserGroupMembership.end_user_id == user_id
    ).first()

    if existing_membership:
        raise HTTPException(
            status_code=409,
            detail="User is already a member of this group"
        )

    membership = UserGroupMembership(
        group_id=group_id,
        end_user_id=user_id
    )

    db.add(membership)
    db.commit()
    db.refresh(membership)

    return membership


def remove_user_from_group(db: Session, group_id: int, user_id: int):
    membership = db.query(UserGroupMembership).filter(
        UserGroupMembership.group_id == group_id,
        UserGroupMembership.end_user_id == user_id
    ).first()

    if not membership:
        raise HTTPException(
            status_code=404,
            detail="Group membership not found"
        )

    db.delete(membership)
    db.commit()

    return {"message": "User removed from group successfully"}
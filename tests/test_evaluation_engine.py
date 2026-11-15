import pytest
from fastapi import HTTPException
from models import (
    Environment,
    FeatureFlag,
    EndUser,
    TargetingRule,
    UserGroup,
    UserGroupMembership
)
from services.evaluation_service import evaluate_flag


def create_test_data(db_session, enabled=True, rollout=0, default=False):
    environment = Environment(name="Development")
    db_session.add(environment)
    db_session.flush()

    flag = FeatureFlag(
        flag_name="test_checkout",
        enabled=enabled,
        rollout_percentage=rollout,
        default_value=default,
        environment_id=environment.id
    )

    user = EndUser(
        external_id="Customer_101",
        attributes={"city": "Bangalore"}
    )

    db_session.add_all([flag, user])
    db_session.commit()

    return flag, user


def test_disabled_flag_returns_off(db_session):
    flag, user = create_test_data(db_session, enabled=False)

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is False
    assert result["reason"] == "FLAG_DISABLED"


def test_default_value_is_returned(db_session):
    flag, user = create_test_data(
        db_session, enabled=True, rollout=0, default=True
    )

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is True
    assert result["reason"] == "DEFAULT_VALUE"


def test_full_percentage_rollout_returns_on(db_session):
    flag, user = create_test_data(
        db_session, enabled=True, rollout=100
    )

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is True
    assert result["reason"] == "PERCENTAGE_ROLLOUT"


def test_user_targeting_rule_returns_on(db_session):
    flag, user = create_test_data(db_session, enabled=True)

    rule = TargetingRule(
        feature_flag_id=flag.id,
        rule_name="Bangalore customer rule",
        rule_type="user",
        attribute="city",
        operator="equals",
        value="Bangalore",
        result=True,
        priority=1,
        is_active=True
    )

    db_session.add(rule)
    db_session.commit()

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is True
    assert result["reason"] == "USER_RULE_MATCH"


def test_group_targeting_rule_returns_on(db_session):
    flag, user = create_test_data(db_session, enabled=True)

    group = UserGroup(name="Beta Testers")
    db_session.add(group)
    db_session.commit()

    membership = UserGroupMembership(
        end_user_id=user.id,
        group_id=group.id
    )
    db_session.add(membership)

    rule = TargetingRule(
        feature_flag_id=flag.id,
        rule_name="Beta testers rule",
        rule_type="group",
        attribute="group_name",
        operator="equals",
        value="Beta Testers",
        result=True,
        priority=1,
        is_active=True
    )

    db_session.add(rule)
    db_session.commit()

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is True
    assert result["reason"] == "GROUP_RULE_MATCH"


def test_non_matching_user_rule_uses_default(db_session):
    flag, user = create_test_data(
        db_session, enabled=True, rollout=0, default=False
    )

    rule = TargetingRule(
        feature_flag_id=flag.id,
        rule_name="Delhi customer rule",
        rule_type="user",
        attribute="city",
        operator="equals",
        value="Delhi",
        result=True,
        priority=1,
        is_active=True
    )

    db_session.add(rule)
    db_session.commit()

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is False
    assert result["reason"] == "DEFAULT_VALUE"


def test_zero_percent_rollout_returns_default(db_session):
    flag, user = create_test_data(
        db_session, enabled=True, rollout=0, default=False
    )

    result = evaluate_flag(
        db_session, flag.id, user.external_id, "Development"
    )

    assert result["value"] is False
    assert result["reason"] == "DEFAULT_VALUE"

def test_missing_feature_flag_returns_404(db_session):
    with pytest.raises(HTTPException) as error:
        evaluate_flag(
            db_session,
            999,
            "Customer_101",
            "Development"
        )

    assert error.value.status_code == 404

def test_missing_environment_returns_404(db_session):
    with pytest.raises(HTTPException) as error:
        evaluate_flag(
            db_session,
            999,
            "Customer_101",
            "UnknownEnvironment"
        )

    assert error.value.status_code == 404
import hashlib

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import (
    Environment,
    FeatureFlag,
    EndUser,
    TargetingRule,
    UserGroup,
    UserGroupMembership,
)


# --------------------------------------------------
# USER ATTRIBUTE HELPER
# --------------------------------------------------

def get_user_attribute(end_user: EndUser, attribute: str):
    if attribute == "external_id":
        return end_user.external_id

    if attribute == "id":
        return end_user.id

    attributes = end_user.attributes or {}
    return attributes.get(attribute)


# --------------------------------------------------
# OPERATOR MATCHING
# --------------------------------------------------

def matches_operator(actual, operator: str, expected) -> bool:
    if operator in ("equals", "eq", "=="):
        return actual == expected

    if operator in ("not_equals", "ne", "!="):
        return actual != expected

    if operator == "in":
        if not isinstance(expected, (list, tuple, set, str)):
            raise HTTPException(
                status_code=400,
                detail="'in' operator requires a list or string value"
            )
        return actual in expected

    if operator == "not_in":
        if not isinstance(expected, (list, tuple, set, str)):
            raise HTTPException(
                status_code=400,
                detail="'not_in' operator requires a list or string value"
            )
        return actual not in expected

    if operator == "contains":
        if isinstance(actual, (list, tuple, set, str)):
            return expected in actual

        if isinstance(actual, dict):
            return expected in actual

        return False

    raise HTTPException(
        status_code=400,
        detail=f"Unsupported targeting operator: {operator}"
    )


# --------------------------------------------------
# SPECIFIC USER RULE MATCHING
# --------------------------------------------------

def matches_user_rule(rule: TargetingRule, end_user: EndUser) -> bool:
    actual = get_user_attribute(end_user, rule.attribute)

    return matches_operator(
        actual,
        rule.operator,
        rule.value
    )


# --------------------------------------------------
# GROUP RULE MATCHING
# --------------------------------------------------

def matches_group_rule(
    rule: TargetingRule,
    group_names: list,
    group_ids: list
) -> bool:

    if rule.attribute in ("group", "group_name", "name"):
        actual_values = group_names

    elif rule.attribute == "group_id":
        actual_values = [str(group_id) for group_id in group_ids]

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported group attribute: {rule.attribute}"
        )

    if rule.operator in ("equals", "eq", "==", "contains"):
        return rule.value in actual_values

    if rule.operator == "in":
        if not isinstance(rule.value, list):
            raise HTTPException(
                status_code=400,
                detail="Group 'in' operator requires a list value"
            )

        return any(value in rule.value for value in actual_values)

    raise HTTPException(
        status_code=400,
        detail=f"Unsupported group operator: {rule.operator}"
    )


# --------------------------------------------------
# STABLE PERCENTAGE ROLLOUT
# --------------------------------------------------

def get_user_bucket(user_identity: str, flag_key: str) -> int:
    combined_key = f"{user_identity}:{flag_key}"

    hash_value = hashlib.sha256(
        combined_key.encode("utf-8")
    ).hexdigest()

    return int(hash_value[:8], 16) % 100


# --------------------------------------------------
# EVALUATION RESULT HELPER
# --------------------------------------------------

def build_evaluation_result(
    flag: FeatureFlag,
    environment: Environment,
    external_id: str,
    value,
    reason: str,
    bucket=None,
    matched_rule_id=None
):
    return {
        "flag_id": flag.id,
        "flag_key": flag.flag_name,
        "environment": environment.name,
        "external_id": external_id,
        "value": value,
        "reason": reason,
        "bucket": bucket,
        "matched_rule_id": matched_rule_id,
    }


# --------------------------------------------------
# MAIN FEATURE FLAG EVALUATION
# --------------------------------------------------

def evaluate_flag(
    db: Session,
    flag_id: int,
    external_id: str,
    environment_name: str
):

    # 1. Resolve the exact requested environment.

    environment = db.query(Environment).filter(
        Environment.name == environment_name
    ).first()

    if not environment:
        raise HTTPException(
            status_code=404,
            detail="Environment not found"
        )

    # Resolve the flag only inside that environment.
    # No fallback to another environment.

    flag = db.query(FeatureFlag).filter(
        FeatureFlag.id == flag_id,
        FeatureFlag.environment_id == environment.id
    ).first()

    if not flag:
        raise HTTPException(
            status_code=404,
            detail="Feature flag not found in the requested environment"
        )

    # 2. Global kill switch.

    if not flag.enabled:
        return build_evaluation_result(
            flag,
            environment,
            external_id,
            False,
            "FLAG_DISABLED"
        )

    # Find the separate end-user identity.
    # Dashboard administrator accounts are not used here.

    end_user = db.query(EndUser).filter(
        EndUser.external_id == external_id
    ).first()

    if not end_user:
        raise HTTPException(
            status_code=404,
            detail="End user not found"
        )

    # Load active rules in deterministic priority order.

    rules = db.query(TargetingRule).filter(
        TargetingRule.feature_flag_id == flag.id,
        TargetingRule.is_active.is_(True)
    ).order_by(
        TargetingRule.priority.asc(),
        TargetingRule.id.asc()
    ).all()

    # 3. Specific-user rules have first precedence.

    user_rules = [
        rule for rule in rules
        if rule.rule_type.lower() in ("user", "specific_user")
    ]

    for rule in user_rules:
        if matches_user_rule(rule, end_user):
            return build_evaluation_result(
                flag,
                environment,
                external_id,
                rule.result,
                "USER_RULE_MATCH",
                matched_rule_id=rule.id
            )

    # 4. Group rules have second precedence.

    group_rows = db.query(
        UserGroup.id,
        UserGroup.name
    ).join(
        UserGroupMembership,
        UserGroup.id == UserGroupMembership.group_id
    ).filter(
        UserGroupMembership.end_user_id == end_user.id
    ).all()

    group_ids = [row.id for row in group_rows]
    group_names = [row.name for row in group_rows]

    group_rules = [
        rule for rule in rules
        if rule.rule_type.lower() == "group"
    ]

    for rule in group_rules:
        if matches_group_rule(rule, group_names, group_ids):
            return build_evaluation_result(
                flag,
                environment,
                external_id,
                rule.result,
                "GROUP_RULE_MATCH",
                matched_rule_id=rule.id
            )

    # 5. Stable percentage rollout.

    percentage = flag.rollout_percentage

    if percentage < 0 or percentage > 100:
        raise HTTPException(
            status_code=400,
            detail="Rollout percentage must be between 0 and 100"
        )

    bucket = get_user_bucket(
        end_user.external_id,
        flag.flag_name
    )

    if bucket < percentage:
        return build_evaluation_result(
            flag,
            environment,
            external_id,
            True,
            "PERCENTAGE_ROLLOUT",
            bucket=bucket
        )

    # 6. No rule or rollout grants access.
    # Return the configured default value.

    default_value = (
        flag.default_value
        if flag.default_value is not None
        else False
    )

    return build_evaluation_result(
        flag,
        environment,
        external_id,
        default_value,
        "DEFAULT_VALUE",
        bucket=bucket
    )
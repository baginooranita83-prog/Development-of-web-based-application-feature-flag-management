import pytest
from types import SimpleNamespace
from fastapi import HTTPException

from services.evaluation_service import (
    get_user_attribute,
    matches_operator,
    matches_user_rule,
    get_user_bucket,
)


# Test user attribute retrieval
def test_get_user_external_id():
    user = SimpleNamespace(
        id=1,
        external_id="Customer_101",
        attributes={}
    )

    assert get_user_attribute(user, "external_id") == "Customer_101"


# Test custom user attributes
def test_get_user_custom_attribute():
    user = SimpleNamespace(
        id=1,
        external_id="Customer_101",
        attributes={"city": "Bangalore"}
    )

    assert get_user_attribute(user, "city") == "Bangalore"


# Test equality operator
def test_matches_operator_equals():
    assert matches_operator("Bangalore", "equals", "Bangalore") is True


# Test not-equals operator
def test_matches_operator_not_equals():
    assert matches_operator("Delhi", "not_equals", "Bangalore") is True


# Test IN operator
def test_matches_operator_in():
    assert matches_operator("admin", "in", ["admin", "manager"]) is True


# Test CONTAINS operator
def test_matches_operator_contains():
    assert matches_operator("Python", "contains", "Py") is True


# Test unsupported operator
def test_matches_operator_invalid():
    with pytest.raises(HTTPException) as error:
        matches_operator("admin", "unknown", "admin")

    assert error.value.status_code == 400


# Test invalid IN value
def test_matches_operator_invalid_in_value():
    with pytest.raises(HTTPException) as error:
        matches_operator("admin", "in", 123)

    assert error.value.status_code == 400


# Test specific user rule
def test_matches_user_rule():
    user = SimpleNamespace(
        id=1,
        external_id="Customer_101",
        attributes={"city": "Bangalore"}
    )

    rule = SimpleNamespace(
        attribute="city",
        operator="equals",
        value="Bangalore"
    )

    assert matches_user_rule(rule, user) is True


# Test stable percentage bucket
def test_user_bucket_is_stable():
    first = get_user_bucket("Customer_101", "new_checkout")
    second = get_user_bucket("Customer_101", "new_checkout")

    assert first == second


# Test bucket boundary
def test_user_bucket_is_between_zero_and_ninety_nine():
    bucket = get_user_bucket("Customer_101", "new_checkout")

    assert 0 <= bucket <= 99
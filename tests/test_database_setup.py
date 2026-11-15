from sqlalchemy import inspect


def test_temporary_database_tables_exist(db_session):
    inspector = inspect(db_session.get_bind())

    tables = inspector.get_table_names()

    assert "environments" in tables
    assert "feature_flags" in tables
    assert "end_users" in tables
    assert "targeting_rules" in tables
    assert "user_groups" in tables
    assert "user_group_memberships" in tables
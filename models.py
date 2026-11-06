from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Float,
    JSON,
    UniqueConstraint,
    CheckConstraint,
    func,
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    


class Environment(Base):
    __tablename__ = "environments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True
    )

    flag_versions = relationship(
        "FlagVersion",
        back_populates="environment"
    )

    feature_flags = relationship(
        "FeatureFlag",
        back_populates="environment"
    )


class FeatureFlag(Base):
    __tablename__ = "feature_flags"

    id = Column(Integer, primary_key=True, index=True)
    flag_name = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    rollout_percentage = Column(
        Integer,
        nullable=False,
        default=0,
        server_default="0"
    )


    flag_type = Column(
        "type",
        String,
        nullable=False,
        default="boolean",
        server_default="boolean"
    )
    default_value = Column(JSON, nullable=True)
    description = Column(String, nullable=True)
    environment_id = Column(
        Integer,
        ForeignKey("environments.id"),
        nullable=True
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=True
    )

    environment = relationship(
        "Environment",
        back_populates="feature_flags"
    )

    versions = relationship(
        "FlagVersion",
        back_populates="feature_flag"
    )

    targeting_rules = relationship(
        "TargetingRule",
        back_populates="feature_flag"
    )

    __table_args__ = (
        CheckConstraint(
            "rollout_percentage >= 0 AND rollout_percentage <= 100",
            name="ck_feature_flags_rollout_percentage"
        ),
    )


class FlagVersion(Base):
    __tablename__ = "flag_versions"

    id = Column(Integer, primary_key=True, index=True)
    feature_flag_id = Column(
        Integer,
        ForeignKey("feature_flags.id"),
        nullable=False
    )
    environment_id = Column(
        Integer,
        ForeignKey("environments.id"),
        nullable=False
    )
    version_number = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    percentage_rollout = Column(Integer, default=100, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    feature_flag = relationship(
        "FeatureFlag",
        back_populates="versions"
    )
    environment = relationship(
        "Environment",
        back_populates="flag_versions"
    )

    __table_args__ = (
        UniqueConstraint(
            "feature_flag_id",
            "environment_id",
            "version_number",
            name="uq_flag_environment_version"
        ),
    )

class EndUser(Base):
    __tablename__ = "end_users"

    id = Column(Integer, primary_key=True, index=True)
    external_id = Column(String, unique=True, index=True, nullable=False)
    attributes = Column(JSON, nullable=False, default=dict)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    group_memberships = relationship(
        "UserGroupMembership",
        back_populates="end_user"
    )


class UserGroup(Base):
    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    memberships = relationship(
        "UserGroupMembership",
        back_populates="group"
    )


class UserGroupMembership(Base):
    __tablename__ = "user_group_memberships"

    id = Column(Integer, primary_key=True, index=True)
    end_user_id = Column(Integer,ForeignKey("end_users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("user_groups.id"), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    end_user = relationship(
        "EndUser",
        back_populates="group_memberships"
    )
    group = relationship(
        "UserGroup",
        back_populates="memberships"
    )

    __table_args__ = (
        UniqueConstraint("end_user_id", "group_id", name="uq_end_user_group"),
    )


class TargetingRule(Base):
    __tablename__ = "targeting_rules"

    id = Column(Integer, primary_key=True, index=True)
    feature_flag_id = Column(
        Integer,
        ForeignKey("feature_flags.id"),
        nullable=False
    )
    rule_name = Column(String, nullable=False)
    rule_type = Column(String, nullable=False)
    attribute = Column(String, nullable=False)
    operator = Column(String, nullable=False)
    comparison_value = Column(String, nullable=True)
    value = Column(JSON, nullable=False)
    result = Column(Boolean, nullable=False)
    priority = Column(Integer, nullable=False, default=100, server_default="100")
    is_active = Column(Boolean, nullable=False, default=True, server_default="true")
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    feature_flag = relationship(
        "FeatureFlag",
        back_populates="targeting_rules"
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class EvaluationStats(Base):
    __tablename__ = "evaluation_stats"

    id = Column(Integer, primary_key=True, index=True)
    feature_flag_id = Column(
        Integer,
        ForeignKey("feature_flags.id"),
        nullable=False
    )
    environment_id = Column(
        Integer,
        ForeignKey("environments.id"),
        nullable=True
    )
    evaluation_count = Column(Integer, default=0, nullable=False)
    enabled_count = Column(Integer, default=0, nullable=False)
    disabled_count = Column(Integer, default=0, nullable=False)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now())
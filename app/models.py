from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum("manager", "team_lead", "developer", "tester", name="user_roles"), nullable=False, default="developer")


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum("bug", "task", name="task_types"), nullable=False)
    priority = Column(Enum("critical", "high", "medium", "low", name="task_priorities"))
    status = Column(
        Enum("To do", "In progress", "Code review", "Dev test", "Testing", "Done", "Wontfix", name="task_statuses"),
        nullable=False,
        default="To do"
    )
    title = Column(String, nullable=False)
    description = Column(String)
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

    assignee = relationship("User", foreign_keys=[assignee_id])
    creator = relationship("User", foreign_keys=[creator_id])
    blocked_by = relationship(
        "Task",
        secondary="task_dependencies",
        primaryjoin="Task.id == TaskDependency.blocked_id",
        secondaryjoin="Task.id == TaskDependency.blocking_id",
        backref="blocks"
    )

class TaskDependency(Base):
    __tablename__ = "task_dependencies"

    blocking_id = Column(Integer, ForeignKey("tasks.id"), primary_key=True)
    blocked_id = Column(Integer, ForeignKey("tasks.id"), primary_key=True)
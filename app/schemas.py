from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class UserBase(BaseModel):
    username: str
    role: str

class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        from_attributes = True

class TaskBase(BaseModel):
    type: str
    title: str
    description: Optional[str] = None


class TaskCreate(TaskBase):
    creator_id: int
    status: str = "To do"


class Task(TaskBase):
    id: int
    status: str
    priority: Optional[str] = None
    assignee_id: Optional[int] = None
    creator_id: int
    created_at: datetime
    updated_at: datetime
    blocked_by: List[int] = []
    blocks: List[int] = []

    class Config:
        from_attributes = True


class TaskUpdate(BaseModel):
    status: Optional[str] = None
    assignee_id: Optional[int] = None
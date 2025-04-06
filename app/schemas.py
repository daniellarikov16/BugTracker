from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    role: str
    class Config:
        from_attributes = True
class UserUpdateUsername(BaseModel):
    id: int
    new_username: str
class UserUpdateRole(BaseModel):
    id: int
    new_role: str
class TaskBase(BaseModel):
    type: str
    title: str
    description: Optional[str] = None

class TaskCreate(TaskBase):
    priority: str
    assignee_id: Optional[int] = Field(None)
    blocks: List[int] = Field(default_factory=list)
    blocked_by: List[int] = Field(default_factory=list)

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

class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str
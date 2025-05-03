from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import EmailStr
from sqlmodel import Field, SQLModel


class Action(str, Enum):
    register = "register"
    reset_password = "reset_password"


class Status(str, Enum):
    pending = "pending"
    active = "active"


class Role(str, Enum):
    admin = "admin"
    user = "user"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    validation_code: Optional[str] = None
    code_expires_at: Optional[datetime] = None
    status: Status = Field(default=Status.pending)
    role: Role = Field(default=Role.user)
    hashed_password: str


class UserCreate(SQLModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    validation_code: Optional[str] = None
    code_expires_at: Optional[datetime] = None
    status: Optional[Status] = Status.pending
    password: str
    role: Optional[Role] = Role.user


class UserInDB(UserCreate):
    hashed_password: str

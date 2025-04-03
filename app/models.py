from enum import Enum
from typing import Optional

from pydantic import EmailStr
from sqlmodel import Field, SQLModel


class Role(str, Enum):
    admin = "admin"
    user = "user"


# User model for SQLAlchemy & Pydantic integration
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: Role = Field(default=Role.user)
    hashed_password: str


# UserCreate model to validate incoming data (Pydantic)
class UserCreate(SQLModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    role: Optional[Role] = Role.user


# UserInDB model for responses (Pydantic)
class UserInDB(UserCreate):
    hashed_password: str

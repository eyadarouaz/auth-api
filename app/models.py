from typing import Optional

from pydantic import EmailStr
from sqlmodel import Field, SQLModel


# User model for SQLAlchemy & Pydantic integration
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    hashed_password: str


# UserCreate model to validate incoming data (Pydantic)
class UserCreate(SQLModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str


# UserInDB model for responses (Pydantic)
class UserInDB(UserCreate):
    hashed_password: str

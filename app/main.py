import logging
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session, select

from app.database import get_db
from app.logging_config import setup_logging
from app.models import User

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI()


@app.get("/")
def read_root():
    logger.info("Root endpoint accessed")
    return {"message": "Welcome to the User Authentication API"}


@app.get("/users", response_model=List[User])
def read_users(db: Session = Depends(get_db)):
    statement = select(User)
    users = db.exec(statement).all()
    return users


@app.get("/users/{user_id}", response_model=User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    statement = select(User).where(User.id == user_id)
    user = db.exec(statement).first()
    if user is None:
        raise HTTPException(status_code=404, detail={"message": "User not found"})
    return user

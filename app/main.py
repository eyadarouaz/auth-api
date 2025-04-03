import logging
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from sqlmodel import Session, SQLModel, select

from app.database import engine, get_db
from app.logging_config import setup_logging
from app.models import User, UserCreate
from app.utils import create_access_token, hash_password, verify_password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI()


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(bind=engine)
    logger.info("Tables created (if not already existing)")


@app.get("/")
def read_root():
    logger.info("Root endpoint accessed")
    return {"message": "Welcome to the User Authentication API"}


@app.get("/users", response_model=List[User])
def read_users(db: Session = Depends(get_db)):
    statement = select(User)
    users = db.exec(statement).all()
    if not users:
        raise HTTPException(status_code=404, detail={"message": "No users found"})
    return users


@app.get("/users/{user_id}", response_model=User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    statement = select(User).where(User.id == user_id)
    user = db.exec(statement).first()
    if user is None:
        raise HTTPException(status_code=404, detail={"message": "User not found"})
    return user


@app.post("/users", response_model=User)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already registered",
        )

    hashed_password = hash_password(user.password)
    user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        hashed_password=hashed_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return JSONResponse(content=user.dict(), status_code=201)


@app.post("/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": db_user.username, "id": db_user.id})

    return {"access_token": access_token, "token_type": "bearer"}

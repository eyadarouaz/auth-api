import logging
import secrets
import string
from typing import List

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlmodel import Session, SQLModel, select

from app.config import settings
from app.database import engine, get_db
from app.logging_config import setup_logging
from app.models import User, UserCreate
from app.utils import create_access_token, hash_password, verify_password, verify_token

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    try:
        user_data = verify_token(token)

        if user_data is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.id == user_data["id"]).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred",
        )


def generate_validation_code(length: int = 8) -> str:
    characters = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


async def send_validation_code_event(email: str, code: str, user_id: int):
    payload = {
        "eventType": "SEND_VALIDATION_CODE",
        "email": email,
        "code": code,
        "userId": str(user_id),
    }

    async with ServiceBusClient.from_connection_string(
        settings.CONNECTION_STRING
    ) as client:
        sender = client.get_queue_sender(queue_name=settings.QUEUE_NAME)
        async with sender:
            message = ServiceBusMessage(str(payload))
            await sender.send_messages(message)
            logger.info(f"Sent validation code event for {email}")


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(bind=engine)
    logger.info("Tables created (if not already existing)")


@app.get("/")
def read_root():
    logger.info("Root endpoint accessed")
    return {"message": "Welcome to the User Authentication API"}


@app.get("/users", response_model=List[User])
def read_users(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    statement = select(User)
    users = db.exec(statement).all()
    if not users:
        raise HTTPException(status_code=404, detail={"message": "No users found"})
    return users


@app.get("/users/{user_username}", response_model=User)
def read_user(
    user_username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    statement = select(User).where(User.username == user_username)
    user = db.exec(statement).first()
    if user is None:
        raise HTTPException(status_code=404, detail={"message": "User not found"})
    return user


@app.post("/register", response_model=User)
def create_user(
    user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already registered",
        )

    hashed_password = hash_password(user.password)
    validation_code = generate_validation_code()
    new_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        validation_code=validation_code,
        status=user.status,
        role=user.role,
        hashed_password=hashed_password,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    background_tasks.add_task(
        send_validation_code_event, user.email, validation_code, new_user.id
    )

    return JSONResponse(content=user.dict(), status_code=201)


@app.post("/validate")
def validate_code(email: str, code: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.validation_code != code:
        raise HTTPException(status_code=400, detail="Invalid code")

    db_user.status = "active"
    db_user.validation_code = None
    db.commit()
    db.refresh(db_user)

    return {"message": "Account validated successfully"}


@app.post("/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if (
        not db_user
        or not verify_password(user.password, db_user.hashed_password)
        or db_user.status == "pending"
    ):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": db_user.username, "id": db_user.id})

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=User)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user

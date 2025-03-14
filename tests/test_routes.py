import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.database import get_db
from app.main import app
from app.models import User
from tests.factories import UserFactory

BASE_URL = "/users"

DATABASE_URI = os.getenv(
    "DATABASE_URI",
)

engine = create_engine(DATABASE_URI, echo=True)


@pytest.fixture(scope="function")
def setup_and_teardown():
    """Clear the database before each test"""

    SQLModel.metadata.drop_all(bind=engine)
    SQLModel.metadata.create_all(bind=engine)

    yield

    SQLModel.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create a new database session for each test."""
    session = Session(engine)
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def override_get_db():
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

######################################################################
#  T E S T   C A S E S
######################################################################


@pytest.fixture(scope="function")
def setup_db(db_session):
    """Fixture to clean the DB before each test"""
    db_session.query(User).delete()
    db_session.commit()
    yield db_session


######################################################################
#  H E L P E R   M E T H O D S
######################################################################


def _create_users(db_session, count):
    """Factory method to create users in bulk"""
    users = []
    for _ in range(count):
        user = UserFactory()
        response = client.post(
            BASE_URL,
            json={
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "password": "defaultpassword",
            },
        )

        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.json()}")
        assert response.status_code == 201, "Could not create test User"

        new_user = response.json()
        user.id = new_user["id"]
        users.append(user)
    return users


######################################################################
#  A U T H   T E S T   C A S E S
######################################################################


def test_read_root():
    """Test the root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User Authentication API"}


def test_read_a_user(db_session, setup_and_teardown):
    """It should Read a single user"""
    user = _create_users(setup_db, 1)[0]
    response = client.get(
        f"{BASE_URL}/{user.id}",
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == user.username
    assert data["email"] == user.email

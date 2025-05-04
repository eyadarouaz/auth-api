import os
from unittest.mock import patch

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
    f"postgresql://postgres:{os.getenv('POSTGRES_PASSWORD')}@postgres:5432/postgres",
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


@pytest.fixture(autouse=True)
def mock_asb_service():
    with patch(
        "app.main.send_validation_code_event"
    ) as mock_send_validation_code_event:
        mock_send_validation_code_event.return_value = None
        yield mock_send_validation_code_event


######################################################################
#  H E L P E R   M E T H O D S
######################################################################


def _create_users(db_session, count):
    """Factory method to create users in bulk"""
    users = []
    for _ in range(count):
        user = UserFactory()
        response = client.post(
            "/register",
            json={
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "validation_code": user.validation_code,
                "code_expires_at": user.code_expires_at,
                "status": user.status,
                "role": user.role,
                "password": "defaultpassword",
            },
        )

        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.json()}")
        assert response.status_code == 201, "Could not create test User"

        new_user = response.json()
        user.username = new_user["username"]
        users.append(user)
    return users


def _login_user(db_session):
    user = UserFactory()

    response = client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    assert response.status_code == 201

    login_data = {
        "username": user.username,
        "email": user.email,
        "password": "defaultpassword",
    }

    response = client.post("/login", json=login_data)

    assert response.status_code == 200, "Login failed"
    token = response.json().get("access_token")
    assert token, "No access token received"

    return user, token


######################################################################
#  A U T H   T E S T   C A S E S
######################################################################


def test_read_root():
    """Test the root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the User Authentication API"}


def test_read_all_users(db_session, setup_and_teardown):
    """It should Read all users"""
    _create_users(setup_db, 5)

    token = _login_user(db_session)[1]  # This creates another user

    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(BASE_URL, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 6


def test_read_a_user(db_session, setup_and_teardown):
    """It should Read a single user"""
    user = _create_users(setup_db, 1)[0]

    token = _login_user(db_session)[1]

    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{BASE_URL}/{user.username}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == user.username
    assert data["email"] == user.email


def test_user_not_found(db_session, setup_and_teardown):
    """It should NOT Read a non existant user"""
    token = _login_user(db_session)[1]

    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"{BASE_URL}/0", headers=headers)
    assert response.status_code == 404


def test_register_user(db_session, setup_and_teardown):
    """It should Create a user"""
    user = UserFactory()
    response = client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": user.status,
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    assert response.status_code == 201


def test_register_duplicate_user(db_session, setup_and_teardown):
    """It should NOT Create a user with duplicate email"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": user.status,
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/register",
        json={
            "username": "different_username",
            "email": user.email,
            "full_name": "Different Name",
            "validation_code": "H5231F",
            "status": "active",
            "role": "admin",
            "password": "anotherpassword",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already used"


def test_activate_account(db_session, setup_and_teardown):
    """It should activate account"""
    user = UserFactory()
    response_register = client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": user.status,
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/validate",
        params={
            "email": user.email,
            "code": response_register.json()["validation_code"],
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"
    assert response.json()["message"] == "Account validated successfully"


def test_activate_account_invalid_code(db_session, setup_and_teardown):
    """It should activate account"""

    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": user.status,
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/validate",
        params={"email": user.email, "code": "ANYCODE"},
    )
    assert response.status_code == 400


def test_activate_non_existant_account(db_session, setup_and_teardown):
    """It should return 404 Not Found"""

    response = client.post(
        "/validate",
        params={"email": "any@email.com", "code": "123456"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_login_user(db_session, setup_and_teardown):
    """It should log in a user"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/login",
        json={
            "username": user.username,
            "email": user.email,
            "password": "defaultpassword",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "token_type" in response.json()


def test_login_user_incorrect_password(db_session, setup_and_teardown):
    """It should not log in a user with incorrect password"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/login",
        json={
            "username": user.username,
            "email": user.email,
            "password": "wrongpassword",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_user_incorrect_username(db_session, setup_and_teardown):
    """It should not log in a user with incorrect username"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/login",
        json={
            "username": "wronguser",
            "email": "wrong@email.com",
            "password": "defaultpassword",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_user_pending_account(db_session, setup_and_teardown):
    """It should not log in a user with an inactive account"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "pending",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/login",
        json={
            "username": user.username,
            "email": user.email,
            "password": "defaultpassword",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect username or password"


def test_read_current_user(db_session, setup_and_teardown):
    """It should return the current user"""
    user, token = _login_user(db_session)

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/me", headers=headers)
    assert response.status_code == 200

    user_data = response.json()
    assert "id" in user_data
    assert user_data["username"] == user.username


def test_read_current_user_invalid_token(db_session, setup_and_teardown):
    """It should not get a current user"""
    fake_token = "this.is.not.a.jwt.token"
    headers = {"Authorization": f"Bearer {fake_token}"}
    response = client.get("/me", headers=headers)
    assert response.status_code == 500


def test_request_reset_password(db_session, setup_and_teardown):
    """It should successfully send a verification code"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )
    response = client.post(
        "/reset-pwd",
        params={"email": user.email},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Verification code sent"


def test_change_password(db_session, setup_and_teardown):
    """It should successfully update the password"""
    user = UserFactory()
    client.post(
        "/register",
        json={
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "validation_code": user.validation_code,
            "status": "active",
            "role": user.role,
            "password": "defaultpassword",
        },
    )

    response_reset = client.post(
        "/reset-pwd",
        params={"email": user.email},
    )

    response = client.post(
        "/change-pwd",
        params={
            "email": user.email,
            "new_password": "newpassword",
            "code": response_reset.json()["code"],
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Password successfully changed"


def test_access_protected_route_without_token(db_session, setup_and_teardown):
    """Test accessing a protected route without a token"""

    response = client.get(BASE_URL)
    assert response.status_code == 401, "Access without token should be denied"
    assert response.json()["detail"] == "Not authenticated"


def test_access_protected_route_with_invalid_token(db_session, setup_and_teardown):
    """Test accessing a protected route with an invalid token"""

    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get(BASE_URL, headers=headers)

    assert response.status_code == 500

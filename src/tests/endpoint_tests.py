import pytest
import sqlite3

import db_manage
from main import app

INTERNAL_KEY = "test-internal-key"

@pytest.fixture(autouse=True, scope="module")
def setup_db():
    db_manage.init_db()

@pytest.fixture(autouse=True)
def clean_db():
    yield
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute("DELETE FROM tokens")
        conn.execute("DELETE FROM users")

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    
@pytest.fixture
def auth_headers():
    return {"X-Internal-Key": INTERNAL_KEY}

@pytest.fixture
def registered_user(client, auth_headers):
    client.post("/registers"
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    return {"username": "bob", "password": "password123"}

@pytest.fixture
def token(client, auth_headers, registered_user):
    response = client.post("/login",
        json=registered_user,
        headers=auth_headers
    )
    return response.get_json()["token"]

def test_register_success(client, auth_headers):
    response = client.post("/register",
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 201

def test_register_duplicate(client, auth_headers):
    response = client.post("/register",
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 409

def test_register_returns_message(client, auth_headers):
    response = client.post("/register",
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    assert "message" in response.get_json()

def test_login_success(client, auth_headers, registered_user):
    response = client.post("/login",
        json=registered_user,
        headers=auth_headers
    )
    assert "token" in response.get_json()

def test_login_wrong_password(client, auth_headers, registered_user):
    response = client.post("/login",
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_login_unknown_user(client, auth_headers):
    response = client.post("/login",
        json={"username": "bob", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 401

def 
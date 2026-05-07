# test_endpoints.py
import pytest
import sqlite3
from main import app
import db_manage

INTERNAL_KEY = "test-internal-key"
ALLOWED_IP = "192.168.1.1"

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
    return {
        "X-Internal-Key": INTERNAL_KEY,
        "REMOTE_ADDR": ALLOWED_IP
    }

@pytest.fixture
def admin_headers(client, auth_headers):
    db_manage.register("admin", "adminpassword123", "admin")
    response = client.post("/api/login",
        json={"username": "admin", "password": "adminpassword123"},
        headers=auth_headers
    )
    
    token = response.get_json()["token"]
    return {**auth_headers, "Authorization": f"Bearer {token}"}

@pytest.fixture
def user_headers(client, auth_headers):
    db_manage.register("alice", "password123", "user")
    response = client.post("/api/login",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    token = response.get_json()["token"]
    return {**auth_headers, "Authorization": f"Bearer {token}"}

# ── login ────────────────────────────────────────────────────────────────────

def test_login_success(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 200

def test_login_returns_token(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    assert "token" in response.get_json()

def test_login_wrong_password(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        json={"username": "alice", "password": "wrongpassword"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_login_unknown_user(client, auth_headers):
    response = client.post("/api/login",
        json={"username": "nobody", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_login_no_body(client, auth_headers):
    response = client.post("/api/login", headers=auth_headers)
    assert response.status_code == 400

def test_login_missing_username(client, auth_headers):
    response = client.post("/api/login",
        json={"password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 400

def test_login_missing_password(client, auth_headers):
    response = client.post("/api/login",
        json={"username": "alice"},
        headers=auth_headers
    )
    assert response.status_code == 400

def test_login_rejected_ip(client):
    response = client.post("/api/login",
        json={"username": "alice", "password": "password123"}
    )
    assert response.status_code == 403

def test_login_rejected_api_key(client):
    response = client.post("/api/login",
        json={"username": "alice", "password": "password123"},
        environ_base={"REMOTE_ADDR": ALLOWED_IP}
    )
    assert response.status_code == 403

# ── register ─────────────────────────────────────────────────────────────────

def test_register_success(client, admin_headers):
    response = client.post("/api/register",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 201

def test_register_duplicate(client, admin_headers):
    client.post("/api/register",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    response = client.post("/api/register",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 409

def test_register_no_token(client, auth_headers):
    response = client.post("/api/register",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_register_no_body(client, admin_headers):
    response = client.post("/api/register", headers=admin_headers)
    assert response.status_code == 400

def test_register_missing_username(client, admin_headers):
    response = client.post("/api/register",
        json={"password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 400

def test_register_missing_password(client, admin_headers):
    response = client.post("/api/register",
        json={"username": "bob", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 400

# ── revoke token ──────────────────────────────────────────────────────────────

def test_revoke_token_success(client, admin_headers):
    db_manage.register("alice", "password123")
    alice_id = db_manage.get_id_from_username("alice")
    target_token = db_manage.create_token(alice_id)
    response = client.post("/api/revoke/token",
        json={"target": target_token},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_revoke_token_invalidates_token(client, admin_headers):
    db_manage.register("alice", "password123")
    alice_id = db_manage.get_id_from_username("alice")
    target_token = db_manage.create_token(alice_id)
    client.post("/api/revoke/token",
        json={"target": target_token},
        headers=admin_headers
    )
    assert db_manage.validate_token(target_token) is None

def test_revoke_token_no_token(client, auth_headers):
    response = client.post("/api/revoke/token",
        json={"target": "sometoken"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_revoke_token_no_body(client, admin_headers):
    response = client.post("/api/revoke/token", headers=admin_headers)
    assert response.status_code == 400

# ── revoke all tokens ─────────────────────────────────────────────────────────

def test_revoke_all_tokens_success(client, user_headers):
    alice_id = db_manage.get_id_from_username("alice")
    db_manage.create_token(alice_id)
    db_manage.create_token(alice_id)
    response = client.post("/api/revoke/tokens", headers=user_headers)
    assert response.status_code == 204

def test_revoke_all_tokens_clears_tokens(client, user_headers):
    alice_id = db_manage.get_id_from_username("alice")
    db_manage.create_token(alice_id)
    db_manage.create_token(alice_id)
    client.post("/api/revoke/tokens", headers=user_headers)
    assert db_manage.get_user_tokens(alice_id) == []

def test_revoke_all_tokens_no_token(client, auth_headers):
    response = client.post("/api/revoke/tokens", headers=auth_headers)
    assert response.status_code == 401

# ── change username ───────────────────────────────────────────────────────────

def test_change_username_success(client, admin_headers):
    response = client.post("/api/change/username",
        json={"new_username": "newadmin"},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_change_username_not_admin(client, user_headers):
    response = client.post("/api/change/username",
        json={"new_username": "newalice"},
        headers=user_headers
    )
    assert response.status_code == 403

def test_change_username_duplicate(client, admin_headers, user_headers):
    response = client.post("/api/change/username",
        json={"new_username": "alice"},
        headers=admin_headers
    )
    assert response.status_code == 409

def test_change_username_no_token(client, auth_headers):
    response = client.post("/api/change/username",
        json={"new_username": "newname"},
        headers=auth_headers
    )
    assert response.status_code == 401

# ── change password ───────────────────────────────────────────────────────────

def test_change_password_success(client, user_headers):
    response = client.post("/api/change/password",
        json={"new_password": "newpassword123"},
        headers=user_headers
    )
    assert response.status_code == 204

def test_change_password_updates_password(client, auth_headers, user_headers):
    client.post("/api/change/password",
        json={"new_password": "newpassword123"},
        headers=user_headers
    )
    response = client.post("/api/login",
        json={"username": "alice", "password": "newpassword123"},
        headers=auth_headers
    )
    assert response.status_code == 200

def test_change_password_no_token(client, auth_headers):
    response = client.post("/api/change/password",
        json={"new_password": "newpassword123"},
        headers=auth_headers
    )
    assert response.status_code == 401

# ── get role ──────────────────────────────────────────────────────────────────

def test_get_role_success(client, user_headers):
    response = client.post("/api/role", headers=user_headers)
    assert response.status_code == 200

def test_get_role_returns_role(client, user_headers):
    response = client.post("/api/role", headers=user_headers)
    assert "data" in response.get_json()

def test_get_role_default_is_user(client, user_headers):
    response = client.post("/api/role", headers=user_headers)
    assert response.get_json()["data"] == "user"

def test_get_role_no_token(client, auth_headers):
    response = client.post("/api/role", headers=auth_headers)
    assert response.status_code == 401

# ── change role ───────────────────────────────────────────────────────────────

def test_change_role_success(client, admin_headers):
    response = client.post("/api/change/role",
        json={"role": "moderator"},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_change_role_updates_role(client, admin_headers):
    client.post("/api/change/role",
        json={"role": "moderator"},
        headers=admin_headers
    )
    response = client.post("/api/role", headers=admin_headers)
    assert response.get_json()["data"] == "moderator"

def test_change_role_no_token(client, auth_headers):
    response = client.post("/api/change/role",
        json={"role": "admin"},
        headers=auth_headers
    )
    assert response.status_code == 401
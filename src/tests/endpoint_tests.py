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
        "X-Internal-Key": INTERNAL_KEY
    }

@pytest.fixture
def admin_headers(client, auth_headers):
    db_manage.register("admin", "adminpassword123", "admin")
    response = client.post("/api/login",
        json={"username": "admin", "password": "adminpassword123"},
        headers=auth_headers
    )
    print(response.get_json())
    token = response.get_json()["token"]
    return {**auth_headers, "Authorization": f"Bearer {token}"}

@pytest.fixture
def user_headers(client, auth_headers):
    db_manage.register("alice", "password123", "user")
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    print(response.get_json())
    token = response.get_json()["token"]
    return {**auth_headers, "Authorization": f"Bearer {token}"}

# ── login ────────────────────────────────────────────────────────────────────

def test_login_success(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 200

def test_login_returns_token(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "password123"},
        headers=auth_headers
    )
    assert "token" in response.get_json()

def test_login_wrong_password(client, auth_headers):
    db_manage.register("alice", "password123")
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "wrongpassword"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_login_unknown_user(client, auth_headers):
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "nobody", "password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_login_no_body(client, auth_headers):
    response = client.post("/api/login", headers=auth_headers, content_type="application/json")
    assert response.status_code == 400

def test_login_missing_username(client, auth_headers):
    response = client.post("/api/login",
        content_type="application/json",
        json={"password": "password123"},
        headers=auth_headers
    )
    assert response.status_code == 400

def test_login_missing_password(client, auth_headers):
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice"},
        headers=auth_headers
    )
    assert response.status_code == 400

def test_login_rejected_ip(client):
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "password123"}
    )
    assert response.status_code == 403

def test_login_rejected_api_key(client):
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "password123"},
        environ_base={"REMOTE_ADDR": str(ALLOWED_IP)}
    )
    assert response.status_code == 403

# ── register ─────────────────────────────────────────────────────────────────

def test_register_success(client, admin_headers):
    response = client.post("/api/admin/register",
        content_type="application/json",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 201

def test_register_duplicate(client, admin_headers):
    client.post("/api/admin/register",
        content_type="application/json",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    response = client.post("/api/admin/register",
        content_type="application/json",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 409

def test_register_no_token(client, auth_headers):
    response = client.post("/api/admin/register",
        content_type="application/json",
        json={"username": "bob", "password": "password123", "role": "user"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_register_no_body(client, admin_headers):
    response = client.post("/api/admin/register", headers=admin_headers, content_type="application/json")
    assert response.status_code == 400

def test_register_missing_username(client, admin_headers):
    response = client.post("/api/admin/register",
        content_type="application/json",
        json={"password": "password123", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 400

def test_register_missing_password(client, admin_headers):
    response = client.post("/api/admin/register",
        content_type="application/json",
        json={"username": "bob", "role": "user"},
        headers=admin_headers
    )
    assert response.status_code == 400

# ── revoke token ──────────────────────────────────────────────────────────────

def test_revoke_token_success(client, admin_headers):
    db_manage.register("alice", "password123")
    alice_id = db_manage.get_id_by_username("alice")
    target_token = db_manage.create_token(alice_id)
    response = client.post("/api/revoke/token",
        content_type="application/json",
        json={"target": target_token},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_revoke_token_invalidates_token(client, admin_headers):
    db_manage.register("alice", "password123")
    alice_id = db_manage.get_id_by_username("alice")
    target_token = db_manage.create_token(alice_id)
    client.post("/api/revoke/token",
        content_type="application/json",
        json={"target": target_token},
        headers=admin_headers
    )
    assert db_manage.verify_token(target_token) is False

def test_revoke_token_no_token(client, auth_headers):
    response = client.post("/api/revoke/token",
        content_type="application/json",
        json={"target": "sometoken"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_revoke_token_no_body(client, admin_headers):
    response = client.post("/api/revoke/token", headers=admin_headers, content_type="application/json")
    assert response.status_code == 400

# ── revoke all tokens ─────────────────────────────────────────────────────────

def test_revoke_all_tokens_success(client, user_headers, content_type="application/json"):
    alice_id = db_manage.get_id_by_username("alice")
    db_manage.create_token(alice_id)
    db_manage.create_token(alice_id)
    response = client.post("/api/revoke/tokens", headers=user_headers, content_type="application/json")
    assert response.status_code == 204

def test_revoke_all_tokens_clears_tokens(client, user_headers):
    alice_id = db_manage.get_id_by_username("alice")
    db_manage.create_token(alice_id)
    db_manage.create_token(alice_id)
    client.post("/api/revoke/tokens", headers=user_headers, content_type="application/json")
    assert db_manage.get_all_tokens(alice_id) == []

def test_revoke_all_tokens_no_token(client, auth_headers):
    response = client.post("/api/revoke/tokens", headers=auth_headers, content_type="application/json")
    assert response.status_code == 401

# ── change username ───────────────────────────────────────────────────────────

def test_change_username_success(client, admin_headers,):
    response = client.post("/api/admin/change/username",
        content_type="application/json",
        json={"new_username": "newadmin"},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_change_username_not_admin(client, user_headers):
    response = client.post("/api/admin/change/username",
        content_type="application/json",
        json={"new_username": "newalice"},
        headers=user_headers
    )
    assert response.status_code == 403

def test_change_username_duplicate(client, admin_headers, user_headers):
    response = client.post("/api/admin/change/username",
        content_type="application/json",
        json={"new_username": "alice"},
        headers=admin_headers
    )
    assert response.status_code == 409

def test_change_username_no_token(client, auth_headers):
    response = client.post("/api/admin/change/username",
        content_type="application/json",
        json={"new_username": "newname"},
        headers=auth_headers
    )
    assert response.status_code == 401

# ── change password ───────────────────────────────────────────────────────────

def test_change_password_success(client, user_headers):
    response = client.post("/api/change/password",
        content_type="application/json",
        json={"new_password": "newpassword123"},
        headers=user_headers
    )
    assert response.status_code == 204

def test_change_password_updates_password(client, auth_headers, user_headers):
    client.post("/api/change/password",
        content_type="application/json",
        json={"new_password": "newpassword123"},
        headers=user_headers
    )
    response = client.post("/api/login",
        content_type="application/json",
        json={"username": "alice", "password": "newpassword123"},
        headers=auth_headers
    )
    assert response.status_code == 200

def test_change_password_no_token(client, auth_headers):
    response = client.post("/api/change/password",
        content_type="application/json",
        json={"new_password": "newpassword123"},
        headers=auth_headers
    )
    assert response.status_code == 401

# ── get role any ──────────────────────────────────────────────────────────────

def test_get_any_role_success(client, admin_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.get("/api/admin/role", 
        content_type="application/json",
        json={"target": target_id},
        headers=admin_headers
    )
    assert response.status_code == 200

def test_get_any_role_returns_role(client, admin_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.get("/api/admin/role",
        content_type="application/json",
        json={"target": target_id},
        headers=admin_headers
    )
    assert "role" in response.get_json()

def test_get_any_role_default_is_user(client, admin_headers): # FIX THIS !)!)!))!))!)!)!)!))!)!)!)!))!)!)!)!))!)!)!)!))!)!)!)!)!)!)!)!)!)
    response = client.get("/api/admin/role", headers=admin_headers, content_type="application/json")
    assert response.get_json()["role"] == "user"

def test_get_any_role_no_token(client, admin_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.get("/api/admin/role",
        content_type="application/json",
        json={"target": target_id},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_get_any_role_no_admin(client, user_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.get("/api/admin/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=user_headers        
    )
    assert response.status_code == 401
    
def test_get_any_role_nonexistent_target(client, admin_headers):
    target_id = 999999
    response = client.get("/api/admin/role",
        content_type="application/json",
        json={"target": target_id},
        headers=admin_headers
    )
    assert response.status_code == 404

# ── change role ───────────────────────────────────────────────────────────────

def test_change_role_success(client, admin_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.post("/api/admin/change/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=admin_headers
    )
    assert response.status_code == 204

def test_change_role_updates_role(client, admin_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    client.post("/api/admin/change/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=admin_headers
    )
    response = client.get(f"/api/admin/role/{target_id}", headers=admin_headers)
    assert response.get_json()["role"] == "admin"

def test_change_role_no_token(client, auth_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.post("/api/admin/change/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=auth_headers
    )
    assert response.status_code == 401

def test_change_role_no_admin(client, user_headers):
    db_manage.register("bob", "password123")
    target_id = db_manage.get_id_by_username("bob")
    response = client.post("/api/admin/change/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=user_headers        
    )
    assert response.status_code == 401
    
def test_change_role_nonexistent_target(client, admin_headers):
    target_id = 999999
    response = client.post("/api/admin/change/role",
        content_type="application/json",
        json={"target": target_id, "role": "admin"},
        headers=admin_headers
    )
    assert response.status_code == 404
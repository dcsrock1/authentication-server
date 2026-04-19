import db_manage
import pytest
import sqlite3
import datetime

@pytest.fixture(autouse=True, scope="module")
def setup_db():
    db_manage.init_db()

@pytest.fixture(autouse=True)
def clean_db():
    yield
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute(
            "DELETE FROM tokens"
        )
        conn.execute(
            "DELETE FROM users"
        )
    
@pytest.fixture
def user_id():
    db_manage.register("bob", "password123")
    return db_manage.verify_password("bob", "password123")

def test_create_token_returns_string(user_id):
    token = db_manage.create_token(user_id)
    assert isinstance(token, str)

def test_create_token_is_not_empty(user_id):
    token = db_manage.create_token(user_id)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
    assert row is not None

def test_create_token_stored_in_db(user_id):
    token = db_manage.create_token(user_id)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
    assert row is not None

def test_verify_token_returns_user_id(user_id):
    token = db_manage.create_token(user_id)
    result = db_manage.verify_token(token)
    assert result == user_id

def test_verify_token_invalid_returns_false():
    result = db_manage.verify_token("invalidtoken")
    assert result == False

def test_verify_token_updates_last_used_at(user_id):
    token = db_manage.create_token(user_id)
    db_manage.verify_token(token)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT last_used_at FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
    assert row[0] is not None

def test_verify_token_expired_returns_false(user_id):
    token = db_manage.create_token(user_id)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute(
            "UPDATE tokens SET expires_at = ? WHERE token = ?",
            ((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat(), token)
        )
    result = db_manage.verify_token(token)
    assert result == False

def test_verify_token_expired_deleted_from_db(user_id):
    token = db_manage.create_token(user_id)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute(
            "UPDATE tokens SET expires_at = ? WHERE token = ?",
            ((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat(), token)
        )
    db_manage.verify_token(token)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
    assert row is None

def test_revoke_token_removes_from_db(user_id):
    token = db_manage.create_token(user_id)
    db_manage.revoke_token(token)
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
    assert row is None

def test_revoke_token_invalidates_token(user_id):
    token = db_manage.create_token(user_id)
    db_manage.revoke_token(token)
    assert db_manage.verify_token(token) is False

def test_revoke_all_tokens_removes_all(user_id):
    db_manage.create_token(user_id)
    db_manage.create_token(user_id)
    db_manage.create_token(user_id)
    db_manage.revoke_all_tokens(user_id)
    assert db_manage.get_all_tokens(user_id) == []

def test_unique_tokens(user_id):
    token1 = db_manage.create_token(user_id)
    token2 = db_manage.create_token(user_id)
    assert token1 != token2
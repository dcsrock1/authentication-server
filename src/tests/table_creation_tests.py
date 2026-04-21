import pytest
import sqlite3

import db_manage




@pytest.fixture(autouse=True, scope="module")
def setup_db():
    db_manage.init_db()

@pytest.fixture
def tables():
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        return {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

@pytest.fixture
def user_columns():
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        return {
            row[1] for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }
    
@pytest.fixture
def token_columns():
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        return {
            row[1] for row in conn.execute(
                "PRAGMA table_info(tokens)"
            ).fetchall()
        }

# Table test functions
def test_users_table_exists(tables):
    assert "users" in tables, "Missing table: Users"

def test_tokens_table_exists(tables):
    assert "tokens" in tables, "Missing table: tokens"

def test_users_has_id(user_columns):
    assert "id" in user_columns, "Users table missing column: id"

def test_users_has_username(user_columns):
    assert "username" in user_columns, "Users table missing column: username"

def test_users_has_password_hash(user_columns):
    assert "password_hash" in user_columns, "Users table missing column: password_hash"

def test_users_has_created_at(user_columns):
    assert "created_at" in user_columns, "Users table missing column: created_at"

def test_tokens_has_id(token_columns):
    assert "id" in token_columns, "Tokens table missing column: id"

def test_tokens_has_user_id(token_columns):
    assert "user_id" in token_columns, "Tokens table missing column: user_id"

def test_tokens_has_token(token_columns):
    assert "token" in token_columns, "Tokens table missing column: token"

def test_tokens_has_created_at(token_columns):
    assert "created_at" in token_columns, "Tokens table missing column: created_at"

def test_tokens_has_expires_at(token_columns):
    assert "expires_at" in token_columns, "Tokens table missing column: expires_at"

def test_tokens_has_last_used_at(token_columns):
    assert "last_used_at" in token_columns, "Tokens table missing column: last_used_at"

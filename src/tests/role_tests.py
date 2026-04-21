import pytest
import sqlite3

import db_manage

@pytest.fixture(autouse=True, scope="module")
def setup_db():
    db_manage.init_db()

@pytest.fixture(autouse=True)
def clean_db():
    yield
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute(
            "DELETE FROM users"
        )

@pytest.fixture
def user_id():
    db_manage.register("bob", "password123")
    return db_manage.verify_password("bob", "password123")

def test_get_role_returns_string(user_id):
    role = db_manage.get_role(user_id)
    assert isinstance(role, str)

def test_get_role_default_is_user(user_id):
    role = db_manage.get_role(user_id)
    assert role == "user"

def test_get_role_invalid_user_returns_false():
    assert not db_manage.get_role(99999)

def test_set_role_changes_role(user_id):
    db_manage.set_role(user_id, "admin")
    assert db_manage.get_role(user_id)

def test_set_role_can_set_back_to_user(user_id):
    db_manage.set_role(user_id, "admin")
    db_manage.set_role(user_id, "user")
    assert db_manage.get_role(user_id)

def test_set_role_persists_in_db(user_id):
    db_manage.set_role(user_id, "admin")
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    assert row[0] == "admin"

def test_set_role_invalid():
    with pytest.raises(KeyError):
        db_manage.set_role(99999, "admin")
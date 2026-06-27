import db_manage
import sqlite3
import pytest

@pytest.fixture(autouse=True, scope="module")
def setup_db():
    db_manage.init_db()

@pytest.fixture(autouse=True)
def clean_db():
    yield
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        conn.execute("DELETE FROM users")

def test_register_create_user():
    db_manage.register("bob", "password123")
    assert db_manage.user_exists(db_manage.get_id_by_username("bob")), "User not found, user creation failed"

def test_register_hashes_password():
    db_manage.register("bob", "password123")
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = 'bob'"
        ).fetchone()
    assert row[0] != "password123", "Password has not been hashed, SERIOUS SECURITY ISSUE"

def test_register_duplicate_username_raises():
    db_manage.register("bob", "password123")
    with pytest.raises(ValueError):
        db_manage.register("bob", "password321")

def test_register_different_users():
    db_manage.register("bob", "password123")
    db_manage.register("james", "password321")
    assert db_manage.user_exists(db_manage.get_id_by_username("bob"))
    assert db_manage.user_exists(db_manage.get_id_by_username("james"))
    

def test_register_unique_hashes():
    db_manage.register("bob", "password123")
    db_manage.register("james", "password321")
    with sqlite3.connect(db_manage.DB_PATH) as conn:
        bob_hash = conn.execute(
            "SELECT password_hash FROM users WHERE username = 'bob'"
        ).fetchone()[0]
        james_hash = conn.execute(
            "SELECT password_hash FROM users WHERE username = 'james'"
        ).fetchone()[0]

        assert bob_hash != james_hash, "Password hash is used twice, SERIOUS SECURITY ISSUE"

def test_register_password_verify():
    db_manage.register("bob", "password123")
    assert db_manage.verify_password("bob", "password123"), "Password verification test has failed, please check password_verify function"

def test_register_wrong_password_verify():
    db_manage.register("bob", "password123")
    assert not db_manage.verify_password("bob", "password321"), "Password verification failed allowing any password to be used to login, SERIOUS SECURITY ISSUE"

def test_username_change():
    db_manage.register("bob", "password123")
    db_manage.change_username(db_manage.get_id_by_username("bob"), "james")
    assert db_manage.user_exists(db_manage.get_id_by_username("james")), "Username modification failed"

def test_password_change():
    db_manage.register("bob", "password123")
    db_manage.change_password(db_manage.get_id_by_username("bob"), "password321")
    assert db_manage.verify_password("bob", "password321") != False, "Password modification failed"


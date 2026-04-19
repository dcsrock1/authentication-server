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

def 
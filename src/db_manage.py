import sqlite3
import os
import secrets
import datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


#DB_PATH = os.environ["DB_PATH"]
DB_PATH = 'C:/Users/fletc/Documents/Projects/HASS/Authentication Server/src/tests/auth.db'
#PEPPER = os.environ["PASSWORD_PEPPER"]
PEPPER = "a3f8c2e1b4d6f9a2c5e8b1d4f7a0c3e6b9d2f5a8c1e4b7d0f3a6c9e2b5d8f1a4"

ph = PasswordHasher(
    time_cost=2,
    parallelism=2,
)

# Function for initialising the database and creating it if it does not exist
def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )    
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                last_used_at TEXT
            )
        """)


# Function for registering new user accounts with the database
def register(username: str, password: str) -> None:
    peppered = password + PEPPER
    pw_hash = ph.hash(peppered)
    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash)
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{username}' already exists")
    


def change_username(user_id: int, new_username: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        try:
            cursor = conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (new_username, user_id)
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{new_username}' is already taken")
        if cursor.rowcount == 0:
            raise KeyError(f"User '{user_id}' not found")

# function for changing the password in the database
def change_password(user_id: int, new_password: str) -> None:
    peppered = new_password + PEPPER
    new_hash = ph.hash(peppered)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id)
        )
        if cursor.rowcount == 0:
            raise KeyError(f"User ID '{user_id}' not found")

# Function for verifying password against the hash in the DB
def verify_password(username: str, password: str) -> int | bool:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    if row is None:
        return False
    
    peppered = password + PEPPER
    try:
        ph.verify(row["password_hash"], peppered)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    
    if ph.check_needs_rehash(row["password_hash"]):
        _update_hash(username, peppered) 
    
    return get_id_by_username(username)

# Assisting function for updating the hash in the database
def _update_hash(username: str, peppered_password: str) -> None:
    new_hash = ph.hash(peppered_password)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )

# function to check if the the user exists
def user_exists(username: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?) AS user_exists",
            (username,)
        ).fetchone()
    if row is None:
        return False
    else:
        return True
    
def get_id_by_username(username: str) -> int | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    if row is None:
        raise KeyError(f"User '{username}' not found")
    else:
        return row[0]

def get_user_details(user_id: int) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if row is None:
            raise KeyError(f"User ID '{user_id}' not found")
        else:
            return dict(row)

# function to create tokens for user sessions
def create_token(user_id: int, days_valid: int = 30) -> str:
    token = secrets.token_hex(32)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user_id, token, expires_at.isoformat())
        )
    return token

# function to validate session tokens
def verify_token(token: str) -> int | bool:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, expires_at FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
        
        if row is None:
            return False
        
        if datetime.datetime.fromisoformat(row["expires_at"]) < datetime.datetime.now(datetime.timezone.utc):
            conn.execute(
                "DELETE FROM tokens WHERE token = ?",
                (token,)
            )
            return False
        
        conn.execute(
            "UPDATE tokens SET last_used_at = ? WHERE token = ?",
            (datetime.datetime.now(datetime.timezone.utc).isoformat(), token)
        )
        return row["user_id"]

# function to revoke a single token
def revoke_token(token: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE token = ?",
            (token,)
        )

# function to revoke all tokens at once
def revoke_all_tokens(user_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE user_id = ?",
            (user_id,)
        )

# function to get all tokens tied to a user id
def get_all_tokens(user_id: int) -> list:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM tokens WHERE user_id = ?",
            (user_id,)
        ).fetchall()
    return [dict(row) for row in rows]

# simplifies extracting the id from the token
def extract_id_from_token(token: str) -> int:
    user_id = token[:-42]
    return user_id

# simplifies extraction the expiry date from the token
def extract_expiry_date_from_token(token: str) -> str:
    expiry_date = token[-10:]
    return expiry_date

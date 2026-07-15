import sqlite3
import uuid
import pyotp
import secrets
import datetime
import time
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
        # create and define the users table if it does not already exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )    
        """)

        # create and define the tokens table if it does not already exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                last_used_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL 
                created_at   TEXT DEFAULT (datetime('now')),
                last_used_at TEXT
            )
        """)
        # create and define the totp table if it does not already exist
#        conn.execute("""
#            CREATE TABLE IF NOT EXISTS totp (
#                id INTEGER PRIMARY KEY AUTOINCREMENT,
#                user_id TEXT NOT NULL REFERENCES users(id),
#                secret TEXT UNIQUE NOT NULL,
#                created_at TEXT DEFAULT (datetime('now')),
#            )
#        """)


# function for adding new users into the database
def register(username: str, password: str, role: str="user") -> None:

    # create a uuid for the user_id field
    user_id = str(uuid.uuid4())

    # append the pepper to the end of the password and hash the result
    peppered = password + PEPPER 
    pw_hash = ph.hash(peppered)

    # connect to the database and add a new user to the users table with the correct values
    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
                (user_id, username, pw_hash, role)
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{username}' already exists")
    

# function for changing the username of a user in the database
def change_username(user_id: str, new_username: str) -> None:

    # connect to the database and change the username of the user with the matching user_id
    with sqlite3.connect(DB_PATH) as conn:
        try:
            cursor = conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (new_username, user_id)
            )
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{new_username}' is already taken")
        
        # check if row count is equal to 0 to determine if the user exists or not
        if cursor.rowcount == 0:
            raise KeyError(f"User '{user_id}' not found")

# function for changing the password in the database
def change_password(user_id: str, new_password: str) -> None:

    # append the pepper to the end of the password and hash the result
    peppered = new_password + PEPPER
    new_hash = ph.hash(peppered)

    # connect to the database and change the password hash in the users table to the new password
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id)
        )

        # check if row count is equal to 0 to determine if the user exists or not
        if cursor.rowcount == 0:
            raise KeyError(f"User ID '{user_id}' not found")

# function to check a password to make sure that it meets security standards
def password_secure_check(password: str):

    if len(password) < 9: # ensure password is more than 9 characters
        return False
    
    if password.isdigit(): # ensure password is not just digits
        return False
    
    if password.isalpha(): # ensure the password is not just alphabetical characters
        return False
    
    return True # return true if all check passed successfully

# function for verifying password against the hash in the DB
def verify_password(username: str, password: str) -> int | bool:

    # connect to the database and retrieve the password hash from the users table
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    # check if row is none to determine if the user exists
    if row is None:
        raise KeyError(f"User '{username}' not found")
    
    # append the pepper to the password string
    peppered = password + PEPPER 

    # attempt to verify that the password hash in the users table matches the hashed version of the password supplied to this function
    try:
        ph.verify(row["password_hash"], peppered)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    
    # check if the hash stored in the database needs to be updated to meet new hashing parameters
    if ph.check_needs_rehash(row["password_hash"]):
        _update_hash(username, peppered) 
    
    return get_id_by_username(username) # TODO: Replace this with a less janky method of getting the ID as this function should only be used when absolutely needed

# Assisting function for updating the hash in the database
def _update_hash(username: str, peppered_password: str) -> None:
    
    # hash the password with the new hashing parameters
    new_hash = ph.hash(peppered_password)

    # connect to the database and update the password hash to the new hash using the new hashing parameters
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )

# function to check if the the user exists
def user_exists(user_id: str) -> bool:

    # connect to the database and check if a user with the user_id specified exists in the users entity
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?) AS user_exists",
            (user_id,)
        ).fetchone()
    return bool(row[0])
    
# function to check if a username is in use
def check_username(username: str) -> bool:
    
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            ""
        )


# utility function to translate the username to the user_id (mainly used in testing)
def get_id_by_username(username: str) -> int | None:

    # connect to the database and find the row with the matching username then return the corresponding user_id
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    
    # check if row is none to verify if the user actually exists or not
    if row is None:
        raise KeyError(f"User '{username}' not found")

    return row[0]

# function to retrieve a dictionary of all user details stored in the database
def get_user_details(user_id: str) -> dict | None:

    # connect to the database and retrieve all user information
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        # check if row is none to confirm if the user exists or not
        if row is None:
            raise KeyError(f"User ID '{user_id}' not found")
        
        return dict(row)

# function to create tokens for user sessions
def create_token(user_id: str, days_valid: int = 30) -> str:

    # generate a 32 character secret and append the expiry time in days to the end of the string
    token = secrets.token_hex(32)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)

    # connect to the database and insert the newly generated token into the tokens table
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user_id, token, expires_at.isoformat())
        )

    return token # return new token to caller

# function to validate session tokens
def verify_token(token: str) -> int | bool:

    # connect to the database and retrieve the matching token if one exists
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, expires_at FROM tokens WHERE token = ?",
            (token,)
        ).fetchone()
        
        # check if the row is none to confirm if the token exists or not
        if row is None:
            return False
        
        # check if the token is past its expiry and automatically remove it form the database
        if datetime.datetime.fromisoformat(row["expires_at"]) < datetime.datetime.now(datetime.timezone.utc):
            conn.execute(
                "DELETE FROM tokens WHERE token = ?",
                (token,)
            )
            return False
        
        # update the last used attribute of the token
        conn.execute(
            "UPDATE tokens SET last_used_at = ? WHERE token = ?",
            (datetime.datetime.now(datetime.timezone.utc).isoformat(), token)
        )

        return row["user_id"] # return the user_id if the token is successfully verified

# function to revoke a single token
def revoke_token(token: str) -> None:

    # connect to the database and remove the token matching the supplied token argument
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE token = ?",
            (token,)
        )

# function to revoke all tokens at once
def revoke_all_tokens(user_id: str) -> None:

    # connect to the database and remove all tokens linked to the specified user_id
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM tokens WHERE user_id = ?",
            (user_id,)
        )

# function to get all tokens tied to a user id
def get_all_tokens(user_id: str) -> list:

    # connect to the database and retrieve a list of all tokens currently registered to a specific user_id
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

# simplifies extracting the expiry date from the token
def extract_expiry_date_from_token(token: str) -> str:
    expiry_date = token[-10:]
    return expiry_date

# sets role of a user
def set_role(user_id: str, role: str) -> None:

    # connect to the database and update the role attribute of a user in the users table
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id)
        )

    # check if the rowcount is equal to 0 to confirm if the user exists or not
    if cursor.rowcount == 0:
        raise KeyError(f"User ID '{user_id}' not found")
    
# gets the role of a user
def get_role(user_id: str) -> str:

    # connect to the database and retrieve the role of a specified user_id
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        # check if the row is none to confirm if the user exists or not
        if row is None:
            raise KeyError(f"User ID '{user_id}' not found")
        return row[0]

# Creates an api key that does not expire tied to a specific user account
def create_api_key(user_id: str, label: str) -> str:
    token = secrets.token_hex(32)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO api_keys (user_id, token, label) VALUES (?, ?, ?)",
            (user_id, token, label)
        ) 
    return token

# Verifies an api token is valid and returns the user id it is tied to
def verify_api_key(token: str) -> str | False:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT user_id FROM api_keys WHERE token = ?",
            (token,)
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE token = ?",
            (datetime.now(datetime.timezone.utc).isoformat(), token)
        )
    return row[0]
    
# Revokes an api token from a user
def revoke_api_key(token: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM api_keys WHERE token = ?", (token,)
        )
        if cursor.rowcount == 0:
            raise KeyError("API token not found")

# gets a list of all api keys parsed from SQL to a python dict
def get_api_keys(user_id: str) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, label, created_at, last_used_at FROM api_keys WHERE user_id = ?",
            (user_id,)
        ).fetchall()
    return [dict(row) for row in rows]
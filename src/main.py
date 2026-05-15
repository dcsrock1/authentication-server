from flask import Flask, request, jsonify, abort
from flask_restful import Api, Resource
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
import json
import os

import db_manage

API_KEY = "test-internal-key"
ALLOWED_IPS = ["192.168.1.1"]
LOG_PATH = "auth_events.json"

app = Flask(__name__)
api = Api(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

def log_event(event_type: str, severity: str, details: dict={}) -> None:
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "severity": severity,
        "event": event_type,
        "ip": str(request.remote_addr),
        "request_method": str(request.method),
        "request_path": str(request.path),
        "request_content_type": str(request.content_type),
        **details
    }
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as data:
            log = json.load(data)
    else:
        log = []
    log.append(event)

    with open(LOG_PATH, "w") as data:
        json.dump(log, data)


@app.before_request
def check_ip_and_key():
    ip = request.remote_addr
    key = request.headers.get("X-Internal-Key")
    #if ip not in ALLOWED_IPS:
    #    log_event("ip_rejected", "warning")
    #    abort(403)
    if key != API_KEY:
        log_event("API_key_rejected", "warning")
        abort(403)

"""
Description: Allow users to send in a username and password to be verified, once its has been verified a token is returned
Input: username -> str, password -> str
Requires token: false
"""
class Login(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("username"), str):
            log_event("invalid_request", "warning", {"details": "No username"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("password"), str):
            log_event("invalid_request", "warning", {"details": "No password"})
            return {"info": "Malformed request"}, 400
        
        try:
            id = db_manage.verify_password(data["username"], data["password"])
            if not id:
                log_event("login_failed", "warning", {"username": data["username"], "details": "Username or password incorrect"})
                return {"info": "Username or password is incorrect"}, 401
            else:
                log_event("login_successful", "info")
                return {"info": "Successful login", "token": db_manage.create_token(id)}, 200
        except Exception as e:
            log_event("internal_error", "error")
            return {"info": "An internal error has occurred"}, 500

"""
Description: Register a new user. User calling this endpoint must have admin role
Inputs  username -> str, password -> str, new_role -> str
Requires token: true
"""
class Register(Resource): # done
    def post(self):
        data = request.get_json()
        if not data:
            log_event("invalid_request", "warning", {"details": "No data in Body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("username"), str):
            log_event("invalid_request", "warning", {"details": "No username"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("password"), str):
            log_event("invalid_request", "warning", {"details": "No password"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("new_role"), str):
            log_event("invalid_request", "warning", {"details": "No role"})
            return {"info": "Malformed request"}, 400
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning", {"details": "No token"})
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning", {"details": "Token is invalid"})
            return {"info": "Invalid or expired token"}, 401
        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 401
        
        try:
            db_manage.register(data["username"], data["password"], data["new_role"])
            log_event("user_created", "info")
            return {"info": "User created"}, 201
        except ValueError as e:
            log_event("user_creation_failed", "error", {"reason": f"username {data["username"]} is already in use"})
            return {"info": "username already exists"}, 409
        except Exception as e:
            log_event("internal_error", "error")   
            return {"info": "An internal error has occurred"}, 500
        
class RevokeToken(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": "No target"})
            return {"info": "Malformed request"}, 400
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            db_manage.revoke_token(data["target"])
            log_event("token_revoked", "info", {"user_id": user_id, "token_id": token[-10:]})
            return {"info": "Token has been successfully revoked"}, 204
        
class RevokeAllTokens(Resource): 
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            db_manage.revoke_all_tokens(user_id)
            log_event("tokens_revoked", "info", {"user_id": user_id})
            return {"info": "All tokens have been successfully revoked"}, 204
        

class ChangeUsername(Resource): 
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            if db_manage.get_role(user_id) != "admin":
                log_event("authorization_invalid", "warning", {"user_id": user_id})
                return {"info": "Account does not have authorization"}, 403
            else:
                try:
                    db_manage.change_username(user_id, data["new_username"])
                    log_event("username_changed", "info", {"user_id": user_id})
                    return {"info": "Username has been changed"}, 204
                except ValueError as e:
                    log_event("username_exists", "warning", {"user_id": user_id})
                    return {"info": "Username already in use"}, 409
            
class ChangePassword(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            db_manage.change_password(user_id, data["new_password"])
            log_event("password_changed", "info", {"user_id": user_id})
            return {"info": "password has been changed"}, 204
        
class GetRole(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            role = db_manage.get_role(user_id)
            log_event("role_returned", "info", {"user_id": user_id})
            return {"info": role}, 200


class ChangeRole(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning", {})
            return {"info": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        else:
            db_manage.set_role(user_id, data["role"])
            log_event("role_changed", "info", {"user_id": user_id})
            return {"info": "role has been changed"}, 204
        
api.add_resource(Login, "/api/login")
api.add_resource(Register, "/api/register")
api.add_resource(RevokeToken, "/api/revoke/token")
api.add_resource(RevokeAllTokens, "/api/revoke/tokens")
api.add_resource(ChangeUsername, "/api/change/username")
api.add_resource(ChangePassword, "/api/change/password")
api.add_resource(GetRole, "/api/role")
api.add_resource(ChangeRole, "/api/change/role")

if __name__ == "__main__":
    app.run("0.0.0.0", port=9444)
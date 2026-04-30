from flask import Flask, request, jsonify, abort
from flask_restful import Api, Resource
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
import json
import os

import db_manage

API_KEY = os.environ["INTERNAL_API_KEY"]
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
        "ip": request.remote_addr,
        "request_method": request.method,
        "request_path": request.path,
        "request_content_type": request.content_type
        **details
    }
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as data:
            log = json.load(data)
    else:
        log = []
    log.append(event)

    with open(LOG_PATH, "w") as data:
        json.dump(log)


@app.before_request
def check_ip_and_key():
    ip = request.remote_addr
    key = request.headers.get("X-Internal-Key")
    if ip not in ALLOWED_IPS:
        log_event("ip_rejected", "warning")
        abort(403)
    if key != API_KEY:
        log_event("API_key_rejected", "warning")
        abort(403)


class Login(Resource): # done
    def post(self):
        data = request.get_json()
        try:
            id = db_manage.verify_password(data["username"], data["password]"])
            if not id:
                log_event("login_failed", "warning", {"username": data["username"], "reason": "username or password incorrect"})
                return {"error": "Username or password is incorrect"}, 401
            else:
                log_event("login_successful", "info", )
                return {"message": "Successful login", "token": db_manage.create_token(db_manage.get_user_id(data["username"]))}, 200
        except Exception as e:
            log_event("login_failed", "error", {""})
            return {"error": str(e)}, 500

class Register(Resource): # done
    def post(self):
        data = request.get_json()
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        try:
            db_manage.register(data["username"], data["password"], data["role"])
            log_event("user_created", "info")
            return {"message": "User created"}, 201
        except ValueError as e:
            log_event("user_creation_failed", "error", {"reason": f"username {data["username"]} is already in use"})
            return {"error": str(e)}, 409
        except Exception as e:
            log_event("user_creation_failed", "error", {"new_username": data["username"], "error_data": str(e)})     
            return {"error": str(e)}, 500
        
class RevokeToken(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            db_manage.revoke_token(data["target"])
            log_event("token_revoked", "info", {"user_id": user_id, "token_id": token[-10:]})
            return {"message": "Token has been successfully revoked"}, 204
        
class RevokeAllTokens(Resource): 
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            db_manage.revoke_all_tokens(user_id)
            log_event("tokens_revoked", "info", {"user_id": user_id})
            return {"message": "All tokens have been successfully revoked"}, 204
        

class ChangeUsername(Resource): 
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            if db_manage.get_role(user_id) != "admin":
                log_event("authorization_invalid", "warning", {"user_id": user_id})
                return {"error": "Account does not have authorization"}, 403
            else:
                try:
                    db_manage.change_username(user_id, data["new_username"])
                    log_event("username_changed", "info", {"user_id": user_id})
                    return {"message": "Username has been changed"}, 204
                except ValueError as e:
                    log_event("username_exists", "warning", {"user_id": user_id})
                    return {"error": "Username already in use"}, 409
            
class ChangePassword(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            db_manage.change_password(user_id, data["new_password"])
            log_event("password_changed", "info", {"user_id": user_id})
            return {"message": "password has been changed"}, 204
        
class GetRole(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            role = db_manage.get_role(user_id)
            log_event("role_returned", "info", {"user_id": user_id})
            return {"data": role}


class ChangeRole(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        data = request.get_json()
        if not token:
            log_event("no_token", "warning")
            return {"error", "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            log_event("invalid_token", "warning")
            return {"error": "Invalid or expired token"}, 401
        else:
            db_manage.set_role(user_id, data["role"])
            log_event("role_changed", "info", {"user_id": user_id})
            return {"message": "role has been changed"}, 204
        
api.add_resource(Login, "/api/login")
api.add_resource(Register, "/api/register")
api.add_resource(RevokeToken, "/api/revoke/token")
api.add_resource(RevokeAllTokens, "/api/revoke/tokens")
api.add_resource(ChangeUsername, "/api/change/username")
api.add_resource(ChangePassword, "/api/change/password")
api.add_resource(GetRole, "/api/role")
api.add_resource(ChangeRole, "/api/change/role")


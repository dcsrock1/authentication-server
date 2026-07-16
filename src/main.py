from flask import Flask, request, jsonify, abort
from flask_restful import Api, Resource
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
import json
import os

import db_manage

API_KEY = "test-internal-key"
ALLOWED_IPS = ["192.168.1.1", "127.0.0.1"]
LOG_PATH = "auth_events.json"

app = Flask(__name__)
api = Api(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], )

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
    if ip not in ALLOWED_IPS:
        log_event("ip_rejected", "warning")
        abort(403)
    if key != API_KEY:
        log_event("API_key_rejected", "warning")
        abort(403)

"""
Description: Allows users to send in a username and password to be verified, once its has been verified a token is returned
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
            user_id = db_manage.verify_password(data["username"], data["password"])

            if not user_id:
                log_event("login_failed", "warning", {"username": db_manage.get_id_by_username(data["username"]), "details": "Password is incorrect"})
                return {"info": "Username or password is incorrect"}, 401
            else:
                log_event("login_successful", "info")
                return {"info": "Successful login", "token": db_manage.create_token(user_id)}, 200
        except KeyError:
            log_event("login_failed", "warning", {"username": data["username"], "details": "User does not exist"})
            return {"info": "Username or password is incorrect"}, 401

"""
Description: Allows admin users to register new users
Inputs  username -> str, password -> str, role -> str
Requires token: true
"""
class AdminRegister(Resource): # done
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
        elif not isinstance(data.get("role"), str):
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
            return {"info": "Not authorized"}, 403
        
        try:
            db_manage.register(data["username"], data["password"], data["role"])
            log_event("user_created", "info")
            return {"info": "User created"}, 201
        except ValueError as e:
            log_event("user_creation_failed", "error", {"reason": f"username {data["username"]} is already in use"})
            return {"info": "username already exists"}, 409

        
class RevokeToken(Resource):
    def delete(self):
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


        db_manage.revoke_token(data["target"])
        log_event("token_revoked", "info", {"user_id": user_id, "token_id": token[-10:]})
        return {"info": "Token has been successfully revoked"}, 204

    

class RevokeAllTokens(Resource): 
    def delete(self):
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        db_manage.revoke_all_tokens(user_id)
        log_event("tokens_revoked", "info", {"user_id": user_id})
        return {"info": "All tokens have been successfully revoked"}, 204
        

class GetAllTokens(Resource):
    def get(self):
        
        token = request.headers.get("Authorization ", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        log_event("get_tokens", "info", {"user_id": user_id, "details": "User request list of all sessions tokens"})
        return db_manage.get_all_tokens(user_id)

class AdminChangeUsername(Resource): 
    def post(self):
        data = request.get_json()

        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": "No target"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("username"), str):
            log_event("invalid_request", "warning", {"details": "No username"})
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
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
                    db_manage.change_username(user_id, data["username"])
                    log_event("username_changed", "info", {"user_id": user_id})
                    return {"info": "Username has been changed"}, 204
                except ValueError as e:
                    log_event("username_exists", "warning", {"user_id": user_id})
                    return {"info": "Username already in use"}, 409
            
"""
Description: Allows a user to change their own password
Input: password -> str
Requires token: true
"""
class ChangePassword(Resource):
    def post(self):
        data = request.get_json()

        if not data:
            log_event("invalid_request", "warning", {"details": "no data in body"})
            return {"info": "Malformed request"}, 400
        if not isinstance(data.get("password"), str):
            log_event("invalid_request", "warning", {"details": "no password"})
            return {"info": "Malformed request"}, 400
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401

        if not db_manage.password_secure_check(data["password"]):
            log_event("Insecure_password", "warning", {"user_id": user_id, "details": "Password provided is insecure"})
            return {"info": "Insecure password, password change failed"}, 400

        db_manage.change_password(user_id, data["password"])
        log_event("password_changed", "info", {"user_id": user_id})
        return {"info": "password has been changed"}, 204
        

"""
Description: Allows an admin user to change the password of any user
Input: target -> int, password -> str
Requires token: true
"""
class AdminChangePassword(Resource):
    def post(self):
        data = request.get_json()
        
        if not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": ""})
        if not isinstance(data.get("password"), str):
            log_event("invalid_request", "warning", {"details": "no password"})
            return {"info": "Malformed request"}, 400
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401

        if not db_manage.user_exists(data["target"]):
            log_event("user_not_found", "warning", {"user_id": user_id, "target": data["target"], "details": "Target user not found"})
            return {"info": "User "}, 404

        if not db_manage.password_secure_check(data["password"]):
            log_event("Insecure_password", "warning", {"user_id": user_id, "details": "Password provided is insecure"})
            return {"info": "Insecure password, password change failed"}, 400

        db_manage.change_password(data["target"], data["password"])
        log_event("password_changed", "info", {"user_id": user_id, "target": data["target"]})
        
"""
Description: Allows a user to retrieve there own role
Input: None
Requires token: true
"""
class GetRole(Resource):
    def get(self):
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        role = db_manage.get_role(user_id)
        log_event("role_returned", "info", {"user_id": user_id})
        return {"role": role}, 200


"""
Description: Allows admin users to retrieve the role of another user
Input: target -> int
Requires token: true
"""
class AdminGetRole(Resource):
    def get(self, target):

        if not isinstance(target, str):
            log_event("invalid_request", "warning", {"details": "No target id"})
            return {"info": "Malformed request"}, 400
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning", {"details": "No Token"})
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning", {"details": "Token is invalid"})
            return {"info": "Invalid or expired token"}, 401

        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"user_id": user_id, "target": target, "details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 403
        if not db_manage.user_exists(target):
            log_event("user_not_found", "warning", {"user_id": user_id, "target": target, "details": "Target user not found"})
            return {"info": "User not found"}, 404

        role = db_manage.get_role(target)
        log_event("role_returned", "info", {"user_id": user_id, "target": target})
        return {"role": role}, 200
        


"""
Description: Allows admin users to modify the role of another user
Input: target -> int, role -> str
Requires token: true
"""
class AdminChangeRole(Resource):
    def post(self):
        data = request.get_json()
        
        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": "No target"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("role"), str):
            log_event("invalid_request", "warning", {"details": "No role"})
            return {"info": "Malformed request"}, 400

        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning", {"details": "No token"})
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 403
        
        if not db_manage.user_exists(data["target"]):
            log_event("user_not_found", "warning", {"user_id": user_id, "target": data["target"], "details": "Target user not found"})
            return {"info": "User not found"}, 404
    
        db_manage.set_role(data["target"], data["role"])
        log_event("role_changed", "info", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "Role was updated successfully"})
        return {"info": "role has been changed"}, 204

class CreateApiKey(Resource):
    def post(self):
        data = request.get_json()

        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("label"), str):
            log_event("invalid_request", "warning", {"details": "No label"})
            return {"info": "Malformed request"}, 400

        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401

        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        return {"api_key": db_manage.create_api_token(user_id, data["label"])}, 200
        

class AdminCreateApiKey(Resource):
    def post(self):
        data = request.get_json()

        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": "No target"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("label"), str):
            log_event("invalid_request", "warning", {"details": "No label"})
            return {"info": "Malformed request"}, 400

        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning")
            return {"info": "No token provided"}, 401

        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 403
            
        if not db_manage.user_exists(data["target"]):
            log_event("user_not_found", "warning", {"user_id": user_id, "target": data["target"], "details": "Target user not found"})
            return {"info": "User not found"}, 404

        log_event("API_k")
        return {"api_key": db_manage.create_api_token(data["target"], data["label"])}, 200
        
class RevokeApiKey(Resource):
    def delete(self):
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
        
        if db_manage.verify_api_key(data["target"]) != user_id:
            log_event("key_user_mismatch", "warning", {"user_id": user_id, "details": "User attempted to revoke an API key that does not belong to them"})
            return {"info": "API key not found"}, 404

        log_event("api_key_revoke", "info", {"user_id": user_id, "details": "A user has revoked their API key"})
        return {"info": "token revoked successfully"}, 204
        
        
class AdminRevokeApiKey(Resource):
    def delete(self):
        data = request.get_json()

        if not data:
            log_event("invalid_request", "warning", {"details": "No data in body"})
            return {"info": "Malformed request"}, 400
        elif not isinstance(data.get("target"), str):
            log_event("invalid_request", "warning", {"details": "No target"})
        
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            log_event("no_token", "warning", {"details": ""})
            return {"info": "No token provided"}, 401

        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 403
    
        if db_manage.user_exists(data["target"]):
            log_event("user_not_found", "warning", {"user_id": user_id, "target": data["target"], "details": "Target user not found"})
            return {"info": "API token successfully revoked"}, 204
        
class GetApiKeys(Resource):
    def get(self):
        
        token = request.headers.get("Authorization ", "").removeprefix("Bearer ")
        if not token:
            log_event("invalid_token", "warning")
            return {"info": "No token provided"}, 401
        
        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401


        log_event("get_api_keys", "info", {"user_id": user_id, "details": "user retrieved all api keys tied to the account"})
        return jsonify(db_manage.get_api_keys(user_id))

class AdminGetApiKeys(Resource):
    def get(self, target):

        if target.isalpha():
            log_event("invalid_request", "warning", {"details": "target is inscorrectly passed"})

        token = request.headers.get("Authorization ", "").removeprefix("Bearer ")
        if not token:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401

        user_id = db_manage.verify_token(token)
        if not user_id:
            log_event("invalid_token", "warning")
            return {"info": "Invalid or expired token"}, 401
        
        if db_manage.get_role(user_id) != "admin":
            log_event("authorization_error", "warning", {"user_id": user_id, "target": data["target"], "role": data["role"], "details": "User does not have correct permission level"})
            return {"info": "Not authorized"}, 403
        
        log_event("get_api_keys", "info", {"user_id":user_id, "target": target, "details": "admin retrieved api keys from user"})
        return db_manage.get_api_keys(target)        
        

api.add_resource(Login, "/api/login")
api.add_resource(RevokeToken, "/api/revoke/token")
api.add_resource(RevokeAllTokens, "/api/revoke/tokens")
api.add_resource(ChangePassword, "/api/change/password")
api.add_resource(GetRole, "/api/role")
api.add_resource(CreateApiKey, "/api/create/api_key")
api.add_resource(RevokeApiKey, "/api/revoke/api_token")
api.add_resource(GetApiKeys, "/api/get/api_keys")

api.add_resource(AdminRegister, "/api/admin/register")
api.add_resource(AdminChangeRole, "/api/admin/change/role")
api.add_resource(AdminChangeUsername, "/api/admin/change/username")
api.add_resource(AdminChangePassword, "/api/admin/change/password")
api.add_resource(AdminGetRole, "/api/admin/role/<target>")
api.add_resource(AdminCreateApiKey, "/api/admin/create/api_key")
api.add_resource(AdminRevokeApiKey, "/api/admin/revoke/api_token")
api.add_resource(AdminGetApiKeys, "/api/admin/get/api_keys/<target>")

if __name__ == "__main__":
    app.run("0.0.0.0", port=9444)
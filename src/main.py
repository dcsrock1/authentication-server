from flask import Flask, request, jsonify, abort
from flask_restful import Api, Resource
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os

import db_manage

app = Flask(__name__)
api = Api(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

logging.basicConfig(
    filename="auth.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

API_KEY = os.environ["INTERNAL_API_KEY"]

ALLOWED_IPS = ["192.168.1.1"]

@app.before_request
def check_ip_and_key():
    ip = request.remote_addr
    key = request.headers.get("X-Internal-Key")
    if ip not in ALLOWED_IPS:
        logging.warning(f"Unauthorised IP address attempted to send a request from {ip}")
        abort(403)
    if key != API_KEY:
        logging.warning(f"API key has not been sent or is not correct, they key sent was {key} request originated from {ip}")
        abort(403)

class Register(Resource):
    def post(self):
        data = request.get_json()
        try:
            db_manage.register(data["username"], data["password"])
            return {"message": "User created"}, 201
        except ValueError as e:
            logging.warning(f"A user creation request failed due to the username already being in use username: {data["username"]}")
            return {"error": str(e)}, 409
        except Exception as e:
            logging.error(f"An error has occurred: {str(e)}")        
            return {"error": str(e)}, 500

class Login(Resource):
    def post(self):
        data = request.get_json()
        try:
            id = db_manage.verify_password(data["username"], data["password]"])
            if not id:
                return {"error": "Username or password is incorrect"}, 401
            else:
                return {"message": "Successful login", "token": db_manage.create_token(db_manage.get_user_id(data["username"]))}, 200
        except Exception as e:
            logging.error(f"An error has occurred: {str(e)}")
            return {"error": str(e)}, 500
        
class RevokeToken(Resource):
    def post(self):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return {"error": "No token provided"}, 401
        user_id = db_manage.verify_token(token)
        if user_id == False:
            return {"error": "Invalid or expired token"}, 401
        else:
            return {"message": "Token has been successfully revoked"}, 204
            
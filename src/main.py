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
def check_ip():
    ip = request.remote_addr
    key = request.headers.get("X-Internal-Key")
    if ip not in ALLOWED_IPS:
        logging.warning(f"Unauthorised IP address attempted to send a request from {ip}")
        abort(403)
    if key != API_KEY:
        logging.warning(f"API key has not been sent or is not correct, they key sent was {key} request originated from {ip}")

class Register(Resource):
    def post(self):
        data = request.get_json()
        try:
            db_manage.register(data["username"], data["password"])
            return {"message": "User created"}, 201
        except ValueError as e:
            logging.warning(f"A user creation request failed due to the username already being in use username: {data["username"]}")
            return {"error": str(e)}, 409
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        try:
            if db_manage.user_exists(data["username"]):
                return {"error": "user does not exist"}, 404
            elif db_manage.verify_password(data["username"], data["password"]):
                return {"message": "Successful login", "token": db_manage.create_token(db_manage.get_user_id(data["username"]))}
        except Exception as e:
            logging.error(f"An error has occurred: {str(e)}")
            return {"error": str(e)}, 500
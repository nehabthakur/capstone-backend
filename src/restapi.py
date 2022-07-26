import hashlib
import json
import os
from datetime import timedelta
from typing import Optional, Dict, Any

from flask import Flask, Response, jsonify, request
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, create_access_token

from src.utils.mongo_helper import MongoHelper

app = Flask(__name__)
jwt = JWTManager(app)
cors = CORS(
    app,
    origin='*',
    allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Credentials"],
    supports_credentials=True
)

app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = 'dummy_secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

credentials = json.loads(os.environ['MONGO_CREDS'])


@app.route("/sign-up", methods=["POST"])
@cross_origin()
def sign_up() -> Response:
    body = request.get_json()
    email = body.get("email", "")
    password = body.get("password", "")
    name = body.get("name", "")

    if not email or not password or not name:
        return Response("Body doesn't contain required parameters", 400)

    _id = hashlib.sha256(email.encode('UTF-8')).hexdigest()

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='users',
        query={
            '_id': _id
        }
    )

    if result:
        return Response(f"User with email: {email} already registered", 409)

    mongo_helper.insert_doc(
        database='capstone',
        collection='users',
        record={
            '_id': _id,
            'email': email,
            'password_hash': hashlib.sha256(password.encode('UTF-8')).hexdigest(),
            'name': name,
            'roles': ['student']
        }
    )

    return Response("User successfully registered", 201)


@app.route("/sign-in", methods=["POST"])
@cross_origin(origin='*', headers=['Content-Type'])
def sign_in() -> Response:
    body = request.get_json()

    if not all([field in body for field in ('email', 'password')]):
        return Response("Required fields are email and password", 400)

    email = body["email"]
    password_hash = hashlib.sha256(body["password"].encode('UTF-8')).hexdigest()

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='users',
        query={
            '_id': hashlib.sha256(email.encode('UTF-8')).hexdigest()
        }
    )

    if not result or result['password_hash'] != password_hash:
        return Response("Invalid Credentials", 401)

    del result["_id"]
    del result["password_hash"]

    return jsonify({'token': create_access_token(email), **result})


def authenticate(email) -> Optional[Dict[str, Any]]:
    mongo_helper = MongoHelper(credentials)
    response = mongo_helper.get_doc(
        database='capstone',
        collection='users',
        query={
            '_id': hashlib.sha256(email.encode('UTF-8')).hexdigest()
        }
    )

    return response


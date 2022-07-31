import hashlib
import json
import os
from datetime import timedelta
from typing import Optional, Dict, Any

from flask import Flask, Response, jsonify, request
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request

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


@app.before_request
def before_request():
    if request.path not in ('/sign-in', '/sign-up'):
        verify_jwt_in_request()

    if request.method == 'OPTIONS':
        return Response(status=200)


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


@app.route("/supervisor/all", methods=["GET"])
@cross_origin(origin='*', headers=['Content-Type'])
def get_all_supervisors() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details:
        return Response("User not found", 404)

    mongo_helper = MongoHelper(credentials)

    result = mongo_helper.get_docs(
        database='capstone',
        collection='supervisors',
        query={}
    )

    output = []
    for supervisor in result:
        del supervisor["_id"]
        output.append(supervisor)

    return jsonify(output)


@app.route("/supervisor/<supervisor_id>", methods=["GET"])
@cross_origin(origin='*', headers=['Content-Type'])
def get_supervisor(supervisor_id: str) -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={
            '_id': hashlib.sha256(supervisor_id.encode('UTF-8')).hexdigest()
        }
    )

    if not result:
        return Response("Supervisor not found", 404)

    return jsonify(result)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/supervisor", methods=["POST"])
def update_supervisor() -> Response:
    user_details = authenticate(get_jwt_identity())
    if any(role not in ('supervisor', 'project_coordinator') for role in user_details['roles']):
        return Response("User is not authorized to perform this action", 403)

    body = request.get_json()
    required_fields = ('name', 'email', 'areas', 'project_ideas', 'info', 'slots')

    if not any([field in body for field in required_fields]):
        return Response(f"Required fields are {required_fields}", 400)

    mongo_helper = MongoHelper(credentials)
    _id = hashlib.sha256(body['email'].encode('UTF-8')).hexdigest()

    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={
            '_id': _id
        }
    )

    if not result:
        return Response("User not found", 404)

    for field in required_fields:
        if field in body:
            result[field] = body[field]

    mongo_helper.insert_doc(
        database='capstone',
        collection='supervisors',
        record=result
    )

    return Response("Supervisor details updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/overview", methods=["GET"])
def get_student_overview() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='students',
        query={
            '_id': hashlib.sha256(user_details['email'].encode('UTF-8')).hexdigest()
        }
    )

    if not result:
        return Response("User not found", 404)

    del result["_id"]

    return jsonify(result)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/shortlist", methods=["POST"])
def update_supervisor_shortlist() -> Response:
    user_details = authenticate(get_jwt_identity())

    if any(role in ('supervisor', 'project_coordinator') for role in user_details['roles']):
        return Response("User is not authorized to perform this action", 403)

    body = request.get_json()
    required_fields = ('supervisor_1', 'supervisor_2', 'supervisor_3', 'supervisor_4', 'supervisor_5')

    if not any([field in body for field in required_fields]):
        return Response(f"Required fields are {required_fields}", 400)

    mongo_helper = MongoHelper(credentials)

    result = mongo_helper.get_doc(
        database='capstone',
        collection='students',
        query={'_id': hashlib.sha256(user_details['email'].encode('UTF-8')).hexdigest()}
    )

    if not result:
        return Response("User not found", 404)

    for field in required_fields:
        if field in body:
            result[field] = body[field]

    mongo_helper.insert_doc(
        database='capstone',
        collection='students',
        record=result
    )

    return Response("Supervisor shortlist updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/shortlist", methods=["GET"])
def get_student_shortlist() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='students',
        query={
            '_id': hashlib.sha256(user_details['email'].encode('UTF-8')).hexdigest()
        }
    )

    if not result:
        return Response("User not found", 404)

    del result["_id"]

    return jsonify(result)

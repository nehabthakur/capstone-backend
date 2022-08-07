import hashlib
import json
import os
from datetime import timedelta
from io import StringIO
from typing import Optional, Dict, Any

import pandas as pd
from flask import Flask, Response, jsonify, request
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request
from werkzeug.utils import secure_filename

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
    if request.path != '/sign-in':
        verify_jwt_in_request()

    if request.method == 'OPTIONS':
        return Response(status=200)


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
@app.route("/supervisor/overview", methods=["GET"])
def get_supervisor_overview() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'supervisor' not in user_details['roles']:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={'_id': hashlib.sha256(user_details['email'].encode('UTF-8')).hexdigest()}
    )

    if not result:
        return Response("Supervisor not found", 404)

    del result['_id']

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

    if not user_details or 'student' not in user_details['roles']:
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
        if field in body and body[field]:
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


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/info", methods=["POST"])
def update_student_info() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'project_coordinator' not in user_details['roles']:
        return Response("Unauthorized", 401)

    form_data = request.files.get('file')
    if not form_data:
        return Response("No file provided", 400)

    file_name = secure_filename(form_data.filename)
    if not file_name.endswith('.csv'):
        return Response("File must be a CSV", 400)

    file_data = form_data.read().decode('UTF-8')

    df = pd.read_csv(StringIO(file_data))
    df.drop_duplicates(inplace=True)

    if df.empty:
        return Response("No data found", 400)

    required_columns = (
        'Student Code', 'Name', 'Enrolment Status', 'Programme', 'Route', 'Start Date', 'QM Email', 'Username')

    if not all([column in df.columns for column in required_columns]):
        return Response(f"Required columns are {required_columns}", 400)

    column_mappings = {
        'Student Code': 'student_code',
        'Name': 'name',
        'Enrolment Status': 'enrolment_status',
        'Programme': 'programme',
        'Route': 'route',
        'Start Date': 'start_date',
        'QM Email': 'email',
        'Username': 'username'
    }

    df.rename(columns=column_mappings, inplace=True)

    df['_id'] = df['email'].apply(lambda x: hashlib.sha256(x.encode('UTF-8')).hexdigest())
    students = df.to_dict(orient='records')
    df['password_hash'] = hashlib.sha256('user123'.encode('UTF-8')).hexdigest()
    df['roles'] = [['student']] * len(df)
    users = df[['_id', 'email', 'name', 'password_hash', 'roles']].to_dict(orient='records')

    mongo_helper = MongoHelper(credentials)

    for student in students:
        mongo_helper.insert_doc(
            database='capstone',
            collection='students',
            record=student
        )

    for user in users:
        mongo_helper.insert_doc(
            database='capstone',
            collection='users',
            record=user
        )

    return Response("Student info updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/supervisor/info", methods=["POST"])
def update_supervisor_info() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'project_coordinator' not in user_details['roles']:
        return Response("Unauthorized", 401)

    form_data = request.files.get('file')
    if not form_data:
        return Response("No file provided", 400)

    file_name = secure_filename(form_data.filename)
    if not file_name.endswith('.csv'):
        return Response("File must be a CSV", 400)

    file_data = form_data.read().decode('UTF-8')

    df = pd.read_csv(StringIO(file_data))
    df.drop_duplicates(inplace=True)

    if df.empty:
        return Response("No data found", 400)

    required_columns = ('Supervisor Code', 'Name', 'Position', 'Department', 'QM Email', 'Username', 'Slots')
    if not all([column in df.columns for column in required_columns]):
        return Response(f"Required columns are {required_columns}", 400)

    column_mappings = {
        'Supervisor Code': 'supervisor_code',
        'Name': 'name',
        'Position': 'position',
        'Department': 'department',
        'QM Email': 'email',
        'Username': 'username',
        'Slots': 'slots'
    }

    df.rename(columns=column_mappings, inplace=True)

    df['_id'] = df['email'].apply(lambda x: hashlib.sha256(x.encode('UTF-8')).hexdigest())
    supervisors = df.to_dict(orient='records')
    df['password_hash'] = hashlib.sha256('user123'.encode('UTF-8')).hexdigest()
    df['roles'] = [['supervisor', 'examiner']] * len(df)
    users = df[['_id', 'email', 'name', 'password_hash', 'roles']].to_dict(orient='records')

    mongo_helper = MongoHelper(credentials)

    for supervisor in supervisors:
        mongo_helper.insert_doc(
            database='capstone',
            collection='supervisors',
            record=supervisor
        )

    for user in users:
        mongo_helper.insert_doc(
            database='capstone',
            collection='users',
            record=user
        )

    return Response("Supervisor info updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/secondary_examiner/info", methods=["POST"])
def update_secondary_examiner_info() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'project_coordinator' not in user_details['roles']:
        return Response("Unauthorized", 401)

    form_data = request.files.get('file')
    if not form_data:
        return Response("No file provided", 400)

    file_name = secure_filename(form_data.filename)
    if not file_name.endswith('.csv'):
        return Response("File must be a CSV", 400)

    file_data = form_data.read().decode('UTF-8')

    df = pd.read_csv(StringIO(file_data))
    df.drop_duplicates(inplace=True)

    if df.empty:
        return Response("No data found", 400)

    required_columns = ('Student Id', 'Student Email', 'Student Name', 'Secondary Examiner Id', 'Secondary Examiner Email', 'Secondary Examiner Name')
    if not all([column in df.columns for column in required_columns]):
        return Response(f"Required columns are {required_columns}", 400)

    column_mappings = {
        'Student Id': 'student_id',
        'Student Email': 'student_email',
        'Student Name': 'student_name',
        'Secondary Examiner Id': 'secondary_examiner_id',
        'Secondary Examiner Email': 'secondary_examiner_email',
        'Secondary Examiner Name': 'secondary_examiner_name',
    }

    df.rename(columns=column_mappings, inplace=True)
    df['_id'] = df['student_email'].apply(lambda x: hashlib.sha256(x.encode('UTF-8')).hexdigest())

    mongo_helper = MongoHelper(credentials)

    for row in df.iterrows():
        result = mongo_helper.get_doc(
            database='capstone',
            collection='students',
            query={'_id': row['_id']}
        )

        if not result:
            continue

        result['second_examiner'] = {
            'name': row['secondary_examiner_name'],
            'email': row['secondary_examiner_email']
        }

        mongo_helper.insert_doc(
            database='capstone',
            collection='students',
            record=result
        )


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/project_info", methods=["POST"])
def update_student_project_info() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'student' not in user_details['roles']:
        return Response("Unauthorized", 401)

    required_fields = ('title', 'description')

    body = request.get_json()

    if not body or not all([field in body for field in required_fields]):
        return Response("Empty body or Missing required fields", 400)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='students',
        query={'_id': user_details['_id']}
    )

    if not result:
        return Response("Student not found", 400)

    result['project'] = {
        'title': body['title'],
        'description': body['description']
    }

    mongo_helper.insert_doc(
        database='capstone',
        collection='students',
        record=result
    )

    return Response("Project info updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/supervisor/project_info", methods=["POST"])
def update_supervisor_project_info() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'supervisor' not in user_details['roles']:
        return Response("Unauthorized", 401)

    required_fields = ('areas', 'info', 'projects')

    body = request.get_json()
    if not body or not all([field in body for field in required_fields]):
        return Response(f"Empty body or Missing required fields {required_fields}", 400)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={'_id': user_details['_id']}
    )

    if not result:
        return Response("Supervisor not found", 400)

    result['areas'] = body['areas']
    result['info'] = body['info']
    result['projects'] = body['projects']

    mongo_helper.insert_doc(
        database='capstone',
        collection='supervisors',
        record=result
    )

    return Response("Project info updated", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/project_proposal/<supervisor_email>", methods=["GET"])
def get_student_project_proposal(supervisor_email: str) -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'student' not in user_details['roles']:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='proposals',
        query={'_id': hashlib.sha256(f"{user_details['email']}-{supervisor_email}".encode('UTF-8')).hexdigest()}
    )

    if not result:
        return jsonify({'error': 'Proposal not found'})

    return jsonify(result)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/student/project_proposal", methods=["POST"])
def create_student_project_proposal() -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details or 'student' not in user_details['roles']:
        return Response("Unauthorized", 401)

    required_fields = ('supervisor_email', 'title', 'aim', 'rationale')

    body = request.get_json()
    if not body or not all([field in body for field in required_fields]):
        return Response(f"Empty body or Missing required fields {required_fields}", 400)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='proposals',
        query={'student_email': user_details['email'], 'supervisor_email': body['supervisor_email']}
    )

    if result:
        return Response("Proposal already exists", 400)

    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={'_id': hashlib.sha256(body['supervisor_email'].encode('UTF-8')).hexdigest()}
    )

    if not result:
        return Response("Supervisor not found", 400)

    result = mongo_helper.get_doc(
        database='capstone',
        collection='students',
        query={'_id': hashlib.sha256(user_details['email'].encode('UTF-8')).hexdigest()}
    )

    if not result:
        return Response("Student not found", 400)

    result = mongo_helper.get_doc(
        database='capstone',
        collection='proposals',
        query={'student_email': user_details['email'], 'supervisor_email': body['supervisor_email']}
    )

    if result:
        return Response("Proposal already exists", 400)

    doc = {
        '_id': hashlib.sha256(f"{user_details['email']}-{body['supervisor_email']}".encode('UTF-8')).hexdigest(),
        'student_email': user_details['email'],
        'supervisor_email': body['supervisor_email'],
        'title': body['title'],
        'aim': body['aim'],
        'rationale': body['rationale'],
    }

    mongo_helper.insert_doc(
        database='capstone',
        collection='proposals',
        record=doc
    )

    return Response("Proposal created", 200)


@cross_origin(origin='*', headers=['Content-Type'])
@app.route("/supervisor/info/<supervisor_email>", methods=["GET"])
def get_supervisor_info(supervisor_email: str) -> Response:
    user_details = authenticate(get_jwt_identity())

    if not user_details:
        return Response("Unauthorized", 401)

    mongo_helper = MongoHelper(credentials)
    result = mongo_helper.get_doc(
        database='capstone',
        collection='supervisors',
        query={'_id': hashlib.sha256(supervisor_email.encode('UTF-8')).hexdigest()}
    )

    if not result:
        return Response("Supervisor not found", 400)

    return jsonify(result)

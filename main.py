"""

Jacqueline Weems, 11/19/2024
Oregon State University CS 493-400
Assignment 6: Portfolio Project Tarpaulin

"""

from urllib.request import urlopen
import json
import io
from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
from google.cloud.datastore.query import PropertyFilter
import requests
from jose import jwt
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

# Constants
USERS = 'users'
PHOTO_BUCKET = 'hw6-avatars-weemsj'
COURSES = 'courses'
AVATAR = 'avatar'

# Error messages
BAD_REQUEST = {"Error": "The request body is invalid"}  # 400
UNAUTHORIZED = {"Error": "Unauthorized"}  # 401
FORBIDDEN = {"Error": "You don't have permission on this resource"}  # 403
NOT_FOUND = {"Error": "Not found"}  # 404
ENROLLMENT_ERROR = {"Error": "Enrollment data is invalid"}  # 409

# AuthO Constants
CLIENT_ID = 'xZ03U9AWJ1RUsDouipKRx2XJUjjpZRL6'
CLIENT_SECRET = (
    'PJlmG13EUpNQd9nt7fPXNUKSjGhqBCXgykgyfYuqfB83xljQE4msSp2Z-INJrfXS'
)
DOMAIN = 'dev-istbbahf67axg5b2.us.auth0.com'
ALGORITHMS = ['RS256']

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=f'https://{DOMAIN}/',
    access_token_url=f'https://{DOMAIN}/oauth/token',
    authorize_url=f'https://{DOMAIN}/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    """AuthError is a class that inherits from the Exception class.
    This code is adapted from https://auth0.com/docs/quickstart/backend/python/
    01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885
    #create-the-jwt-validation-decorator
    """
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Handle AuthError exceptions by returning a JSON response with the error.
    This code is adapted from https://auth0.com/docs/quickstart/backend/python/
    01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885
    #create-the-jwt-validation-decorator"""
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(req):
    """Verify the JWT supplied in the Authorization header as a Bearer token.
    This code is adapted from https://auth0.com/docs/quickstart/backend/python/
    01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885
    #create-the-jwt-validation-decorator
    """
    print(type(req))
    if isinstance(req, str):
        token = req
    elif 'Authorization' not in req.headers:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)
    else:
        auth_header = req.headers['Authorization'].split()
        token = auth_header[1]

    jsonurl = urlopen(f'https://{DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError as e:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401) from e

    if unverified_header['alg'] == 'HS256':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer=f'https://{DOMAIN}/'
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token is expired.'
            }, 401) from e
        except jwt.JWTClaimsError as e:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience '
                               'and issuer.'
            }, 401) from e
        except Exception as e:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 401) from e

        return payload
    else:
        raise AuthError({
            'code': 'no_rsa_key',
            'description': 'No RSA key in JWKS.'
        }, 401)


def clear_datastore():
    """ Clear Datastore """
    query = client.query(kind=USERS)
    users = list(query.fetch())
    for user in users:
        client.delete(user.key)

    query = client.query(kind=COURSES)
    courses = list(query.fetch())
    for course in courses:
        client.delete(course.key)


def create_user(username, password, role):
    """ Create User """
    if role == 'admin':
        data = {
            'username': username,
            'password': password,
            'role': role
        }
    else:
        data = {
            'username': username,
            'password': password,
            'role': role,
            'courses': []
        }
    new_user = datastore.Entity(key=client.key(USERS))
    new_user.update(data)
    client.put(new_user)
    return new_user


def is_admin(payload):
    """ Helper function to check if the JWT is owned by an admin."""
    query = client.query(kind=USERS)
    admin = list(query.add_filter(
        filter=PropertyFilter('role', '=', 'admin')
    ).fetch())
    return payload['sub'] == admin[0]['sub']


def is_user(payload, user_id):
    """Helper function to check if the JWT is owned by the user_id."""
    user = get_user_by_id(user_id)
    return payload['sub'] == user['sub']


def get_user_by_id(user_id):
    """ helper function to Get User by ID """
    user_key = client.key(USERS, int(user_id))
    user = client.get(user_key)
    return user


@app.route('/')
def index():
    """ Friendly welcome message that directs users to the login page. """
    return 'Welcome to the Tarpaulin API, navigate to /users/login to login.'


@app.route('/' + USERS + '/login', methods=['POST'])
def login():
    """Login endpoint that generates a JWT for a registered user of the app
    by sending a request to AuthO domain created for this api to get a token.
    The Request must include a JSON body with a username and password.

    Returns:
        JSON response: token with response status:
                        200 if successful,
                        400 if request body is invalid,
                        401 if username and/or password is incorrect.
    """
    content = request.get_json()
    try:
        username = content['username']
        password = content['password']
    except KeyError:
        return BAD_REQUEST, 400
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET}
    headers = {'content-type': 'application/json'}
    url = f'https://{DOMAIN}/oauth/token'
    r = requests.post(url, json=body, headers=headers, timeout=3)
    if 'error' in r.json():
        return UNAUTHORIZED, 401
    user_data = r.json()
    user_jwt = user_data['id_token']
    try:
        payload = verify_jwt(user_jwt)
    except AuthError:
        return UNAUTHORIZED, 401
    query = client.query(kind=USERS)
    users = list(query.add_filter(filter=PropertyFilter(
        'username', '=', username)).fetch())
    user = users[0]
    user.update(
        {'sub': payload['sub']}
    )
    client.put(user)
    return {'token': user_jwt}, 200


@app.route('/' + USERS, methods=['GET'])
def get_users():
    """Endpoint to get all users from the kind "users" in Datastore.
    This endpoint is only accessible to users with the role "admin".
    Must include JWT as Bearer token in the Authorization header.

    Returns:
        JSON response: User with 3 properties, "id", "role", and "sub" ,
                        with response status:
                        200 if successful,
                        401 if JWT is missing or invalid,
                        403 if user is not an admin.
    """
    # check credintaials if JWT is invalid return 401
    try:
        payload = verify_jwt(request)

    except AuthError:
        return UNAUTHORIZED, 401

    # if user is not admin return 403
    if not is_admin(payload):
        return FORBIDDEN, 403
    # return all users
    else:
        query = client.query(kind=USERS)
        users = list(query.fetch())
        for user in users:
            user['id'] = user.key.id
            user.pop('password', None)
            user.pop('username', None)
            user.pop('courses', None)
        return users, 200


@app.route('/' + USERS + '/<user_id>', methods=['GET'])
def get_user(user_id):
    """Endpoint to get a user by their id from the kind "users" in Datastore.
    This endpoint is only accessible to users with the role "admin" or the
    user who owns the JWT. Must include JWT as Bearer token in the
    Authorization header.

    Args:
        user_id (int): The id of the user to be retrieved.

    Returns:
        JSON response: The response will always include 3 properties, "id",
                        "role", and "sub". Regardless of the role, if the user
                        has an avatar, the response will also include
                        "avatar_url". If the user role is "student" or
                        "instructor", the response will always include
                        "courses" as an array of course URLs.
                        The response status will be:
                        200 if successful,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't exist or the user is not an
                        authorized user.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    user = get_user_by_id(user_id)
    if not user:
        return FORBIDDEN, 403
    if not is_admin(payload) and not is_user(payload, user_id):
        return FORBIDDEN, 403
    user['id'] = user.key.id
    user.pop('password', None)
    user.pop('username', None)
    return user, 200


@app.route('/users/<user_id>/avatar', methods=['POST'])
def upload_avatar(user_id):
    """Upload the .png in the request body to the Google Cloud Storage bucket
    if there is already an avatar for the user, it will be replaced.
    This endpoint is only accessible to user who owns the JWT.
    The JWT must be included as a Bearer token in the Authorization header.

    Args:
        user_id (int): The id of the user to upload the avatar for.

    Returns:
        JSON response: The response will include the "avatar_url".
                        The response status will be:
                        200 if successful,
                        400 if the request body is invalid,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't own the JWT
    """
    if 'file' not in request.files:
        return BAD_REQUEST, 400

    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    user = get_user_by_id(user_id)
    if not user or not is_user(payload, user_id):
        return FORBIDDEN, 403
    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    user['avatar_url'] = request.url
    user['avatar_name'] = file_obj.filename
    client.put(user)
    user.pop('password', None)
    user.pop('username', None)
    user.pop('sub', None)
    user.pop('role', None)
    user.pop('courses', None)
    user.pop('avatar_name', None)
    return (user, 200)


@app.route('/' + USERS + '/<user_id>/' + AVATAR, methods=['GET'])
def get_avatar(user_id):
    """Endpoint to get the avatar for a user by their id from the kind "users".
    This endpoint is only accessible to users who own the JWT. Must include JWT
    as Bearer token in the Authorization header.

    Args:
        user_id (int): The id of the user to get the avatar for.

    Returns:
        File response: The avatar image file.
                       The response status will be:
                            200 if successful,
                            401 if JWT is missing or invalid,
                            403 if the user doesn't own the JWT,
                            404 if the user doesn't have an avatar.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401

    user = get_user_by_id(user_id)
    if not user or not is_user(payload, user_id):
        return FORBIDDEN, 403
    if 'avatar_url' not in user:
        return NOT_FOUND, 404
    file_name = user['avatar_name']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return send_file(file_obj,
                     mimetype='image/jpeg',
                     download_name=file_name), 200


@app.route('/' + USERS + '/<user_id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(user_id):
    """Endpoint to delete the avatar for a user by their id from the kind.
    This endpoint is only accessible to users who own the JWT. Must include JWT
    as Bearer token in the Authorization header.

    Args:
        user_id (int): The id of the user to delete the avatar for.

    Returns:
        JSON response: None if successful. JSON on failure.
                        The response status will be:
                        204 if successful,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't own the JWT,
                        404 if the user doesn't have an avatar.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401

    user = get_user_by_id(user_id)
    if not user or not is_user(payload, user_id):
        return FORBIDDEN, 403
    if 'avatar_url' not in user:
        return NOT_FOUND, 404
    file_name = user['avatar_name']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()
    user.pop('avatar_url', None)
    user.pop('avatar_name', None)
    client.put(user)
    return '', 204


@app.route('/' + COURSES, methods=['POST'])
def create_course():
    """This endpoint creates a new course in the Datastore. The request must
    include a JSON body with the following properties: "subject", "number",
    "title", "term", "instructor_id". The instructor_id must be the id of an
    instructor in the Datastore. This endpoint is only accessible to users with
    the role "admin". Must include JWT as Bearer token in the Authorization
    header.

    Returns:
        JSON response: On success, the response will include the course with
                        the properties "id", "subject", "number", "title",
                        "term", "instructor_id", "students", and "self".
                        The response status will be:
                        201 if successful,
                        400 if the request body is invalid,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't have the role "admin".
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    # if user is not admin return 403
    if not is_admin(payload):
        return FORBIDDEN, 403
    content = request.get_json()
    try:
        instructor = get_user_by_id(content['instructor_id'])
        if not instructor or instructor['role'] != 'instructor':
            return BAD_REQUEST, 400
        new_course = datastore.Entity(key=client.key(COURSES))
        new_course.update(
            {
                'subject': content['subject'],
                'number': content['number'],
                'title': content['title'],
                'term': content['term'],
                'instructor_id': content['instructor_id'],
                'students': []
                })
        client.put(new_course)
        client.put(instructor)
        new_course['id'] = new_course.key.id
        new_course['self'] = request.url + '/' + str(new_course.key.id)
        client.put(new_course)
        new_course.pop('students', None)
        instructor['courses'].append(new_course['self'])
        client.put(instructor)
        return new_course, 201
    except KeyError:
        return BAD_REQUEST, 400


@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    """This endpoint returns paginated courses from the Datastore. There are
    two optional query parameters, "offset" and "limit".

    Returns:
        JSON response: The response will include an array of courses with the
                        properties "id", "subject", "number", "title", "term",
                        "instructor_id", and "self". If there are more courses
                        to be retrieved, the response will also include a
                        "next" property with the URL to retrieve the next page
                        of courses. The courses will be sorted by "subject".
                        The response status will be:
                        200 if successful.
    """
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=3, type=int)
    count = len(list(client.query(kind=COURSES).fetch()))
    next_url = None
    if offset + limit >= count:
        next_url = None
    else:
        next_url = request.host_url + COURSES + '?offset=' +\
            str(offset + limit) + '&limit=' + str(limit)

    query = client.query(kind=COURSES)
    query.order = ['subject']
    courses = list(query.fetch(offset=offset, limit=limit))
    return {'courses': courses, 'next': next_url}, 200


@app.route('/' + COURSES + '/<course_id>', methods=['GET'])
def get_course(course_id):
    """This endpoint returns a course by its id from the Datastore.
    The response will not include the "students" property.

    Args:
        course_id (int): The id of the course to be retrieved.

    Returns:
        JSON response: The response will include the course with the properties
                        "id", "subject", "number", "title", "term",
                        "instructor_id", and "self".
                        The response status will be:
                        200 if successful,
                        404 if the course doesn't exist.
    """
    course_key = client.key(COURSES, int(course_id))
    course = client.get(course_key)
    if not course:
        return NOT_FOUND, 404
    course.pop('students', None)
    return course, 200


@app.route('/' + COURSES + '/<course_id>', methods=['PATCH'])
def update_course(course_id):
    """This endpoint updates a course by its id in the Datastore. Student
    enrollment can not be updated with this endpoint. This enpoint is only
    accessible to users with the role "admin". Must include JWT as Bearer token
    in the Authorization header.

    Args:
        course_id (int): The id of the course to be updated.

    Returns:
        JSON response: The response will include the updated course with the
                        properties "id", "subject", "number", "title", "term",
                        "instructor_id", and "self".
                        The response status will be:
                        200 if successful,
                        400 if the request body is invalid,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't have the role "admin" or the
                        course doesn't exist.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    course_key = client.key(COURSES, int(course_id))
    course = client.get(course_key)
    if not course or not is_admin(payload):
        return FORBIDDEN, 403
    content = request.get_json()
    try:
        if 'instructor_id' in content:
            # check if the new instructor is an instructor
            new_instructor = get_user_by_id(content['instructor_id'])
            if not new_instructor or new_instructor['role'] != 'instructor':
                return BAD_REQUEST, 400
            # update the instructor's courses
            new_instructor['courses'].append(course['self'])
            client.put(new_instructor)
            # update the old instructor's courses
            old_instructor = get_user_by_id(course['instructor_id'])
            old_instructor['courses'].remove(course['self'])
            client.put(old_instructor)
        # update the course
        course.update(content)
        client.put(course)
        course.pop('students', None)
        return course, 200
    except KeyError:
        return BAD_REQUEST, 400


@app.route('/' + COURSES + '/<course_id>', methods=['DELETE'])
def delete_course(course_id):
    """This endpoint deletes a course by its id from the Datastore. This
    also removes the course from the instructor and students who are enrolled
    in the course. This endpoint is only accessible to users with the role
    "admin". Must include JWT as Bearer token in the Authorization header.

    Args:
        course_id (int): The id of the course to be deleted.

    Returns:
        JSON response: On success, the response will be empty. JSON on failure.
                        The response status will be:
                        204 if successful,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't have the role "admin" or the
                        course doesn't exist.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    course_key = client.key(COURSES, int(course_id))
    course = client.get(course_key)
    if not course or not is_admin(payload):
        return FORBIDDEN, 403
    students = course['students']
    instructor_id = course['instructor_id']
    instructor = get_user_by_id(instructor_id)
    instructor['courses'].remove(course['self'])
    client.put(instructor)
    for student_id in students:
        student = get_user_by_id(student_id)
        student['courses'].remove(course['self'])
        client.put(student)

    client.delete(course_key)
    return '', 204


@app.route('/' + COURSES + '/<course_id>/students', methods=['PATCH'])
def update_course_enrollment(course_id):
    """This endpoint enrolls and unenrolls students in a course. This endpoint
    is only accessible to users with the role "admin" or the instructor of the
    course. Must include JWT as Bearer token in the Authorization header.
    The request must include a JSON body with the properties "add" and "remove"

    Args:
        course_id (int): The id of the course to update the enrollment for.

    Returns:
        JSON response: On success, the response will be empty. JSON on failure.
                        The response status will be:
                        200 if successful,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't have the role "admin", the user
                        is not the instructor of the course, or the course
                        doesn't exist.
                        409 if the enrollment data is invalid.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    course_key = client.key(COURSES, int(course_id))
    course = client.get(course_key)
    instructor_id = course['instructor_id']
    if not course or\
            not is_admin(payload) and\
            not is_user(payload, instructor_id):
        return FORBIDDEN, 403
    content = request.get_json()
    try:
        to_add = content['add']
        print(to_add)
        to_remove = content['remove']
        if to_add != [] and to_remove != []:
            for student in to_add:
                if student in to_remove:
                    return ENROLLMENT_ERROR, 409
        if to_add != []:
            for student_id in to_add:
                student = get_user_by_id(student_id)
                if not student or student['role'] != 'student':
                    return ENROLLMENT_ERROR, 409
                student_courses = student['courses']
                course_enrollment = course['students']
                if course['self'] not in student_courses and student.key.id\
                        not in course_enrollment:
                    student['courses'].append(course['self'])
                    course['students'].append(student.key.id)
                client.put(student)
                client.put(course)
        if to_remove != []:
            for student_id in to_remove:
                student = get_user_by_id(student_id)
                if not student or student['role'] != 'student':
                    return ENROLLMENT_ERROR, 409
                student_courses = student['courses']
                course_enrollment = course['students']
                if course['self'] in student_courses and student.key.id\
                        in course_enrollment:
                    student['courses'].remove(course['self'])
                    course['students'].remove(student.key.id)
                client.put(student)
                client.put(course)
        return '', 200
    except KeyError:
        return BAD_REQUEST, 400


@app.route('/' + COURSES + '/<course_id>/students', methods=['GET'])
def get_course_students(course_id):
    """This endpoint returns the students enrolled in a course. This endpoint
    is only accessible to users with the role "admin" or the instructor of the
    course. Must include JWT as Bearer token in the Authorization header.

    Args:
        course_id (int): The id of the course to get the students for.

    Returns:
        JSON response: The response will include an array of student ids.
                        The response status will be:
                        200 if successful,
                        401 if JWT is missing or invalid,
                        403 if the user doesn't have the role "admin", the user
                        is not the instructor of the course, or the course
                        doesn't exist.
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    course_key = client.key(COURSES, int(course_id))
    course = client.get(course_key)
    if not course:
        return FORBIDDEN, 403
    instructor_id = course['instructor_id']
    if not is_admin(payload) and\
            not is_user(payload, instructor_id):
        return FORBIDDEN, 403
    students = course['students']
    return students, 200


if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)
    # Clear datastore
    clear_datastore()
    # Create users
    create_user('admin1@osu.com', 'User1234', 'admin')
    create_user('instructor1@osu.com', 'User1234', 'instructor')
    create_user('instructor2@osu.com', 'User1234', 'instructor')
    create_user('student1@osu.com', 'User1234', 'student')
    create_user('student2@osu.com', 'User1234', 'student')
    create_user('student3@osu.com', 'User1234', 'student')
    create_user('student4@osu.com', 'User1234', 'student')
    create_user('student5@osu.com', 'User1234', 'student')
    create_user('student6@osu.com', 'User1234', 'student')

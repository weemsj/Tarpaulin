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
USERS = 'Users'
PHOTO_BUCKET = 'hw6-avatars-weemsj'

# Error messages
BAD_REQUEST = {"Error": "The request body is invalid"}  # 400
UNAUTHORIZED = {"Error": "Unauthorized"}  # 401
FORBIDDEN = {"Error": "You don't have permission on this resource"}  # 403
NOT_FOUND = {"Error": "Not found"}  # 404

# AuthO Constants
CLIENT_ID = 'xZ03U9AWJ1RUsDouipKRx2XJUjjpZRL6'
CLIENT_SECRET = 'PJlmG13EUpNQd9nt7fPXNUKSjGhqBCXgykgyfYuqfB83xljQE4msSp2Z-INJrfXS'
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
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(req):
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
                'description': 'Incorrect claims. Please, check the audience and issuer.'
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
    query = client.query(kind=USERS)
    users = list(query.fetch())
    for user in users:
        client.delete(user.key)


def create_user(username, password, role):
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


@app.route('/')
def index():
    return 'Welcome to the Tarpaulin API, navigate to /users/login to login.'     


@app.route('/users/login', methods=['POST'])
def login():
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
    users = list(query.add_filter('username', '=', username).fetch())
    user = users[0]
    user.update(
        {'sub': payload['sub']}
    )
    client.put(user)
    return {'token': user_jwt}, 200


@app.route('/users', methods=['GET'])
def get_users():
    """_summary_

    Returns:
        _type_: _description_
    """
    # check credintaials if JWT is invalid return 401
    try:
        payload = verify_jwt(request)

    except AuthError:
        return UNAUTHORIZED, 401

    # if user is not admin return 403
    query = client.query(kind=USERS)
    admin = list(query.add_filter('role', '=', 'admin').fetch())
    if payload['sub'] != admin[0]['sub']:
        return FORBIDDEN, 403
    # return all users
    else:
        query = client.query(kind=USERS)
        users = list(query.fetch())
        for user in users:
            user['id'] = user.key.id
            user.pop('password', None)
            user.pop('username', None)
        return users, 200


@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """_summary_

    Args:
        user_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    user_key = client.key(USERS, int(user_id))
    user = client.get(user_key)
    if not user:
        return FORBIDDEN, 403
    if user['role'] != 'admin' and user['sub'] != payload['sub']:
        return FORBIDDEN, 403
    user['id'] = user.key.id
    user.pop('password', None)
    user.pop('username', None)
    return user, 200


@app.route('/users/<user_id>/avatar', methods=['POST'])
def upload_avatar(user_id):
    """_summary_

    Args:
        user_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    if 'file' not in request.files:
        return BAD_REQUEST, 400

    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401

    user_key = client.key(USERS, int(user_id))
    user = client.get(user_key)
    if not user:
        return FORBIDDEN, 403
    if user['role'] != 'admin' and user['sub'] != payload['sub']:
        return FORBIDDEN, 403
    file_obj = request.files['file']
    print(file_obj)
    print(file_obj.filename)
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


@app.route('/users/<user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    """_summary_

    Args:
        user_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401

    user_key = client.key(USERS, int(user_id))
    user = client.get(user_key)
    if not user:
        return FORBIDDEN, 403
    if user['role'] != 'admin' and user['sub'] != payload['sub']:
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


@app.route('/users/<user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    """_summary_

    Args:
        user_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401

    user_key = client.key(USERS, int(user_id))
    user = client.get(user_key)
    if not user:
        return FORBIDDEN, 403
    if user['role'] != 'admin' and user['sub'] != payload['sub']:
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


@app.route('courses', methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return UNAUTHORIZED, 401
    if payload['role'] != 'admin':
        return FORBIDDEN, 403
    content = request.get_json()
    try:
        subject = content['subject']
        number = content['number']
        title = content['title']
        term = content['term']
        instructor = content['instructor']
    except KeyError:
        return BAD_REQUEST, 400
    instructor_key = client.key(USERS, int(instructor))
    instructor = client.get(instructor_key)
    if not instructor:
        return BAD_REQUEST, 400
    






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

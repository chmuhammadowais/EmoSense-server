from datetime import timedelta
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt
)
import psycopg2

app = Flask(__name__)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)

blacklist = set()
dbConfig = {
    'host': 'localhost',
    'port': 5432,
    'user': 'postgres',
    'password': 'admin',
    'database': 'EmoSense',
}

def get_connection():
    """Establish and return a database connection."""
    return psycopg2.connect(**dbConfig)

def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    """Execute a database query with provided parameters."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        conn.commit()
        if fetch_one:
            return cursor.fetchone()
        if fetch_all:
            return cursor.fetchall()
        return cursor.rowcount
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()

def parameters_checker(required_fields=None, data=None):
    """Check for missing fields in the provided data."""
    if data is None:
        data = {}
    if required_fields is None:
        required_fields = []
    return [field for field in required_fields if field not in data]

@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    missing_fields = parameters_checker(
        required_fields=['full_name', 'email', 'password'], data=data
    )
    if missing_fields:
        return jsonify({'msg': f'Missing fields {", ".join(missing_fields)}', 'success': False}), 400

    query = "INSERT INTO USERS (full_name, email, password) VALUES (%s, %s, %s) RETURNING ID;"
    try:
        user_id = execute_query(query, (data['full_name'], data['email'], data['password']), fetch_one=True)
        return jsonify({'id': user_id[0], 'msg': f'User {data["full_name"]} registered successfully', 'success': True}), 200
    except Exception as error:
        return jsonify({'msg': 'Failed to register user', 'error': str(error), 'success': False}), 400

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate a user."""
    data = request.get_json()
    if not data:
        return jsonify({'msg': 'No JSON payload', 'success': False}), 400

    missing_fields = parameters_checker(required_fields=['email', 'password'], data=data)
    if missing_fields:
        return jsonify({'msg': f'Missing fields {", ".join(missing_fields)}', 'success': False}), 400

    query = "SELECT id, full_name, email, password FROM USERS WHERE email = %s;"
    try:
        user = execute_query(query, (data['email'],), fetch_one=True)
        if not user:
            return jsonify({'msg': f'User {data["email"]} not found', 'success': False}), 404

        user_id, full_name, email, password = user
        if password != data['password']:
            return jsonify({'msg': 'Invalid password', 'success': False}), 401

        access_token = create_access_token(identity=str(user_id))
        return jsonify({'id': user_id, 'full_name': full_name, 'email': email, 'access_token': access_token}), 200
    except Exception as error:
        return jsonify({'msg': 'Login failed', 'error': str(error), 'success': False}), 400

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout a user by blacklisting their token."""
    jti = get_jwt()["jti"]
    if jti in blacklist:
        return jsonify({'msg': 'Token already blacklisted', 'success': False}), 400
    blacklist.add(jti)
    return jsonify({'msg': 'Successfully logged out', 'success': True}), 200

@app.route('/api/update/<int:id>', methods=['PUT'])
@jwt_required()
def update(id):
    """Update user details."""
    data = request.get_json()
    missing_fields = parameters_checker(
        required_fields=['full_name', 'email', 'password'], data=data
    )
    if missing_fields:
        return jsonify({'msg': f'Missing fields {", ".join(missing_fields)}', 'success': False}), 400

    query = "UPDATE USERS SET full_name = %s, email = %s, password = %s WHERE id = %s;"
    try:
        rows_affected = execute_query(query, (data['full_name'], data['email'], data['password'], id))
        if rows_affected == 1:
            return jsonify({'success': True, 'msg': 'User updated successfully', 'id': id}), 200
        else:
            return jsonify({'success': False, 'msg': 'User not found or no changes made', 'id': id}), 404
    except Exception as error:
        return jsonify({'msg': 'Failed to update user', 'error': str(error), 'success': False}), 400

if __name__ == '__main__':
    app.run()

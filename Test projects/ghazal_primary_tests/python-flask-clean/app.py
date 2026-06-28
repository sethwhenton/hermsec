"""
Ghazal Python Flask Clean Application
Demonstrates secure coding patterns - zero vulnerabilities expected
"""
import os
import hashlib
import secrets
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# SAFE: Secret key from environment variable
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# SAFE: Debug mode disabled
app.config['DEBUG'] = False

# SAFE: Database credentials from environment
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')

# SAFE: Parameterized SQL query
@app.route('/api/users')
def get_users():
    user_id = request.args.get('id')
    # Validate input
    if not user_id or not user_id.isdigit():
        return jsonify({'error': 'Invalid user ID'}), 400
    conn = sqlite3.connect('ghazal.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)

# SAFE: Parameterized login query
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    conn = sqlite3.connect('ghazal.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({'success': True})
    return jsonify({'success': False}), 401

# SAFE: subprocess with argument list (no shell=True)
import subprocess
@app.route('/api/ping')
def ping():
    host = request.args.get('host')
    # Validate: only allow valid hostnames/IPs
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        return jsonify({'error': 'Invalid host'}), 400
    result = subprocess.run(
        ['ping', '-c', '4', host],
        capture_output=True, text=True, timeout=10
    )
    return jsonify({'output': result.stdout})

# SAFE: Path traversal prevention
@app.route('/api/file')
def read_file():
    filename = request.args.get('name')
    # Validate filename
    if not filename or not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return jsonify({'error': 'Invalid filename'}), 400
    import os.path
    filepath = os.path.join('/var/data', os.path.basename(filename))
    # Ensure resolved path is within allowed directory
    resolved = os.path.realpath(filepath)
    if not resolved.startswith('/var/data'):
        return jsonify({'error': 'Access denied'}), 403
    try:
        with open(resolved, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

# SAFE: HTML escaping for XSS prevention
from markupsafe import escape
@app.route('/api/greet')
def greet():
    name = escape(request.args.get('name', 'World'))
    return f'<h1>Hello {name}!</h1>'

# SAFE: No eval, use safe math operations
@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    a = data.get('a')
    b = data.get('b')
    op = data.get('op')
    if not all(isinstance(x, (int, float)) for x in [a, b]):
        return jsonify({'error': 'Invalid numbers'}), 400
    ops = {
        'add': lambda x, y: x + y,
        'sub': lambda x, y: x - y,
        'mul': lambda x, y: x * y,
        'div': lambda x, y: x / y if y != 0 else None,
    }
    if op not in ops:
        return jsonify({'error': 'Invalid operation'}), 400
    result = ops[op](a, b)
    return jsonify({'result': result})

# SAFE: Strong hash with salt
@app.route('/api/hash')
def hash_password():
    password = request.args.get('password')
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return jsonify({'hash': hashed.hex(), 'salt': salt})

# SAFE: Token generation with secrets module
@app.route('/api/token')
def generate_token():
    token = secrets.token_hex(32)
    return jsonify({'token': token})

# SAFE: No debug mode, no host 0.0.0.0
if __name__ == '__main__':
    app.run(port=5000)

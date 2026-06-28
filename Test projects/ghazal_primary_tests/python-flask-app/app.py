"""
Ghazal Python Flask Vulnerable Application
Deliberately vulnerable for Hermsec benchmark testing
"""
import os
import pickle
import subprocess
import hashlib
import sqlite3
import yaml
import random
import string
from flask import Flask, request, render_template_string, redirect, send_file, jsonify

app = Flask(__name__)

# VULN 1: Hardcoded secret key (CWE-798)
app.secret_key = 'ghazal-flaREPLACE_WITH_API_KEY'

# VULN 2: Debug mode enabled (CWE-489)
app.config['DEBUG'] = True

# VULN 3: Hardcoded database credentials (CWE-798)
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = 'admin123!@#'

# VULN 4: SQL Injection - f-string query (CWE-89)
@app.route('/api/users')
def get_users():
    user_id = request.args.get('id')
    conn = sqlite3.connect('ghazal.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    results = cursor.fetchall()
    return jsonify(results)

# VULN 5: SQL Injection - string concatenation (CWE-89)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect('ghazal.db')
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(sql)
    user = cursor.fetchone()
    if user:
        return jsonify({'success': True, 'token': 'ghazal-auth-token'})
    return jsonify({'success': False})

# VULN 6: Command Injection via subprocess (CWE-78)
@app.route('/api/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.check_output(f'ping -c 4 {host}', shell=True)
    return result

# VULN 7: Command Injection via os.system (CWE-78)
@app.route('/api/dns')
def dns_lookup():
    domain = request.args.get('domain')
    os.system(f'nslookup {domain}')
    return jsonify({'status': 'executed'})

# VULN 8: Path Traversal (CWE-22)
@app.route('/api/file')
def read_file():
    filename = request.args.get('name')
    filepath = os.path.join('/var/data', filename)
    with open(filepath, 'r') as f:
        return f.read()

# VULN 9: Path Traversal via send_file (CWE-22)
@app.route('/api/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/var/uploads/{filename}')

# VULN 10: Template Injection / XSS (CWE-79)
@app.route('/api/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {name}!</h1>'
    return render_template_string(template)

# VULN 11: XSS via render_template_string with user input (CWE-79)
@app.route('/api/render')
def render():
    user_input = request.args.get('content')
    return render_template_string(f'<div>{user_input}</div>')

# VULN 12: Unsafe eval() (CWE-95)
@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    expression = data.get('expression')
    result = eval(expression)
    return jsonify({'result': result})

# VULN 13: Unsafe pickle deserialization (CWE-502)
@app.route('/api/load', methods=['POST'])
def load_object():
    data = request.get_data()
    obj = pickle.loads(data)
    return jsonify({'loaded': str(obj)})

# VULN 14: Unsafe YAML loading (CWE-502)
@app.route('/api/config', methods=['POST'])
def load_config():
    data = request.get_data().decode()
    config = yaml.load(data)
    return jsonify(config)

# VULN 15: Weak hash - MD5 (CWE-328)
@app.route('/api/hash')
def hash_password():
    password = request.args.get('password')
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'hash': hashed})

# VULN 16: TLS verification disabled (CWE-295)
@app.route('/api/fetch')
def fetch_url():
    import requests as req
    url = request.args.get('url')
    response = req.get(url, verify=False)
    return response.text

# VULN 17: Weak random token generation (CWE-330)
@app.route('/api/token')
def generate_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return jsonify({'token': token})

# VULN 18: Hardcoded API keys (CWE-798)
OPENAI_KEY = 'REPLACE_WITH_API_KEY'
GITHUB_TOKEN = 'REPLACE_WITH_GITHUB_TOKEN'

# VULN 19: Unsafe redirect (CWE-601)
@app.route('/api/redirect')
def unsafe_redirect():
    url = request.args.get('url')
    return redirect(url)

# VULN 20: Verbose error exposure (CWE-209)
@app.errorhandler(500)
def handle_error(e):
    return jsonify({
        'error': str(e),
        'traceback': repr(e)
    }), 500

if __name__ == '__main__':
    # VULN 21: Running with debug and host 0.0.0.0 (CWE-489, CWE-668)
    app.run(host='0.0.0.0', port=5000, debug=True)

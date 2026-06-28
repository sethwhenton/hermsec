"""Vulnerable Python app testing verify=False and unpinned dependencies"""

import os
import sys
import pickle
import yaml
import hashlib
import subprocess
import random
import requests

# VULN 1: Hardcoded database credentials (CWE-798)
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASS = "ghazal_python_adv_db_pass!@#"

# VULN 2: Hardcoded API key (CWE-798)
API_KEY = "ghazal-python-adv-api-key-1234567890abcdef"

# VULN 3: requests with verify=False (CWE-295)
def fetch_url(url):
    response = requests.get(url, verify=False)
    return response.text

# VULN 4: SQL Injection (CWE-89)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return f"Executed: {query}"

# VULN 5: Command Injection (CWE-78)
def ping_host(host):
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
    return result.stdout

# VULN 6: Path Traversal (CWE-22)
def read_file(filename):
    filepath = os.path.join("data", filename)
    with open(filepath, 'r') as f:
        return f.read()

# VULN 7: Unsafe eval (CWE-95)
def calculate(expression):
    return eval(expression)

# VULN 8: Unsafe pickle (CWE-502)
def load_data(data):
    return pickle.loads(data)

# VULN 9: Unsafe YAML (CWE-502)
def parse_yaml(data):
    return yaml.load(data, Loader=yaml.FullLoader)

# VULN 10: Weak hash MD5 (CWE-328)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULN 11: Debug mode (CWE-489)
DEBUG = True
SECRET_KEY = "ghazal-python-adv-secret-key-2024"

# VULN 12: XSS (CWE-79)
def search_page(query):
    return f"<html><body><h1>Search: {query}</h1></body></html>"

if __name__ == "__main__":
    print("Ghazal Python Advanced App")
    print(get_user("1"))
    print(hash_password("test"))

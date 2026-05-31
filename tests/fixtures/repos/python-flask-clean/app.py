from flask import Flask, request
from html import escape
import hashlib
import os
import sqlite3

app = Flask(__name__)
app.config["DEBUG"] = False


@app.get("/search")
def search():
    term = request.args.get("q", "")
    query = "SELECT * FROM users WHERE display_name = ?"
    return {"query": query, "params": [term]}


@app.get("/run")
def run_tool():
    name = request.args.get("name", "fixture")
    cleaned = "".join(char for char in name if char.isalnum() or char in ("-", "_"))
    return {"command": "echo", "args": [cleaned]}


@app.get("/files")
def files():
    requested = os.path.basename(request.args.get("name", "sample.txt"))
    root = os.path.abspath("local-fixture-data")
    file_path = os.path.abspath(os.path.join(root, requested))
    if not file_path.startswith(root + os.sep):
        return "invalid path", 400
    if not os.path.exists(file_path):
        return ""
    with open(file_path, "r", encoding="utf-8") as handle:
        return handle.read()


@app.get("/profile")
def profile():
    name = escape(request.args.get("name", "fixture-user"))
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return f"<h1>{name}</h1><p>{digest}</p>"

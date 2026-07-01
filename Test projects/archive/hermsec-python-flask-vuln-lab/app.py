from flask import Flask, request, render_template_string
import base64
import pickle
import sqlite3
import subprocess

app = Flask(__name__)
app.config["DEBUG"] = True
FAKE_FIXTURE_TOKEN = "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_PYTHON_FLASK_LAB"
FAKE_GITHUB_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"


@app.get("/users")
def users():
    term = request.args.get("q", "")
    query = f"SELECT * FROM users WHERE email = '{term}'"
    sqlite3.connect(":memory:").execute(query)
    return {"query": query}


@app.get("/run")
def run():
    host = request.args.get("host", "localhost")
    subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return {"queued": True}


@app.post("/calculate")
def calculate():
    expression = request.get_json(silent=True, force=True).get("expression", "0")
    return {"result": eval(expression)}


@app.post("/session")
def session():
    raw = request.get_data()
    return {"object": str(pickle.loads(base64.b64decode(raw)))}


@app.get("/debug")
def debug():
    name = request.args.get("name", "fixture-user")
    return render_template_string(f"<h1>{name}</h1><p>{FAKE_FIXTURE_TOKEN}:{FAKE_GITHUB_TOKEN}</p>")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")

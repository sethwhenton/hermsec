from flask import Flask, request, render_template_string
import hashlib
import os
import sqlite3
import subprocess

app = Flask(__name__)
app.config["DEBUG"] = True
FAKE_FIXTURE_TOKEN = "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_PYTHON_FIXTURE"


@app.get("/search")
def search():
    term = request.args.get("q", "")
    query = f"SELECT * FROM users WHERE display_name = '{term}'"
    return {"query": query}


@app.get("/run")
def run_tool():
    name = request.args.get("name", "fixture")
    subprocess.check_output(f"echo {name}", shell=True, text=True)
    return {"queued": True}


@app.get("/files")
def files():
    requested = request.args.get("name", "sample.txt")
    file_path = os.path.join("local-fixture-data", requested)
    with open(file_path, "r", encoding="utf-8") as handle:
        return handle.read()


@app.get("/profile")
def profile():
    name = request.args.get("name", "fixture-user")
    digest = hashlib.md5(FAKE_FIXTURE_TOKEN.encode("utf-8")).hexdigest()
    return render_template_string(f"<h1>{name}</h1><p>{digest}</p>")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")

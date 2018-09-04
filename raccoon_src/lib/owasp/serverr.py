import os
from flask import Flask, request


app = Flask(__name__)


@app.route("/load")
def traversal_exploit():
    file_name = request.args.get("filename")
    with open(file_name, "r") as file:
        return file.read()


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)


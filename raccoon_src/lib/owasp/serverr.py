from flask import Flask, request
import os
import sys

app = Flask(__name__)


@app.route("/")
def traversal_exploit():
    file_name = request.args.get("filename")
    print("Query string received: {}".format(file_name), file=sys.stdout)
    print("Does this file exist: {}".format(os.path.isfile(file_name)), file=sys.stdout)
    try:
        with open(file_name, "r") as file:
            return file.read()
    except FileNotFoundError:
        print("FAYEL NOT FAND")
        return "File Not Found"
    except PermissionError:
        print("FORBID ")
        return "Permission Denied"


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)


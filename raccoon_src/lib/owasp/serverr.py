from flask import Flask, request


app = Flask(__name__)


@app.route("/")
def traversal_exploit():
    file_name = request.args.get("filename")
    try:
        with open(file_name, "r") as file:
            return file.read()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)


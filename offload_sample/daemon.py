from flask import Flask, request, jsonify

app = Flask(__name__)

homepage_message = """
hello world!
"""

@app.route('/')
def home():
    return homepage_message


@app.route('/sign', methods=['POST'])
def sign():
    content = request.json
    print(content['mytext'])
    return jsonify({"size":1, "signature": "haha"})
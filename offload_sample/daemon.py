from flask import Flask, request, jsonify
import google.auth.transport.tls_sign


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
    print(content)
    return jsonify({"size":1, "signature": "haha"})
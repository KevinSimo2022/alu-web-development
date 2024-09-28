#!/usr/bin/env python3
"""Basic Flask app"""

from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth

AUTH = Auth()
app = Flask(__name__)

app.url_map.strict_slashes = False

@app.route('/')
def hello_world():
    """Hello world route"""
    return jsonify({"message": "Hello World"})


@app.route('/users', methods=['POST'])
def register_user():
    """Register user"""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """Login user"""
    email = request.form.get("email")
    password = request.form.get("password")
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = make_response(jsonify({"message": "OK"}))
            response.set_cookie('session_id', session_id)
            return response
    abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    """Logout user"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return jsonify({"message": "OK"})
    abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    """Get user profile"""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email})
    abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """Get reset password token"""
    email = request.form.get("email")
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"message": "OK", "reset_token": token})
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update user password"""
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, password)
        return jsonify({"message": "OK"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

"""Minimal "Login with CTFd" relying-party, for exercising the IdP plugin.

This is a *confidential* OAuth2 client: it authenticates to the token endpoint
with a client secret, so no PKCE is required. It performs the authorization
code flow by hand (with plain ``requests``) to keep the moving parts visible.

Browser-facing URLs (the authorize redirect) use CTFD_PUBLIC_URL; back-channel
calls (token + userinfo) use CTFD_INTERNAL_URL so they work over the compose
network. See docker-compose.yml.
"""

import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, request, session

PUBLIC_URL = os.environ.get("CTFD_PUBLIC_URL", "http://localhost:8000").rstrip("/")
INTERNAL_URL = os.environ.get("CTFD_INTERNAL_URL", PUBLIC_URL).rstrip("/")
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")
SCOPE = os.environ.get("OAUTH_SCOPE", "openid profile email")

app = Flask(__name__)
app.secret_key = "demo-client-secret"
# Cookies are scoped by host but NOT by port, so without a distinct name this
# app's "session" cookie on localhost would collide with CTFd's on :8000 and the
# OAuth `state` check would fail. Use a unique cookie name to stay isolated.
app.config["SESSION_COOKIE_NAME"] = "oauth2_demo_client_session"


@app.route("/")
def index():
    if not CLIENT_ID or not CLIENT_SECRET:
        return (
            "<h2>CTFd OAuth2 demo client</h2>"
            "<p style='color:#b00'>OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET are not set.</p>"
            "<p>Register a <b>confidential</b> application in CTFd admin "
            "(redirect URI <code>{}</code>), copy its credentials into a "
            "<code>.env</code> file, then restart this service.</p>".format(REDIRECT_URI)
        )
    return (
        "<h2>CTFd OAuth2 demo client</h2>"
        '<p><a href="/login">Login with CTFd &rarr;</a></p>'
    )


@app.route("/login")
def login():
    state = secrets.token_urlsafe(16)
    session["state"] = state
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
    }
    return redirect(PUBLIC_URL + "/oauth/authorize?" + urlencode(params))


@app.route("/callback")
def callback():
    if "error" in request.args:
        return jsonify(dict(request.args)), 400
    if request.args.get("state") != session.get("state"):
        return "State mismatch — possible CSRF.", 400

    code = request.args.get("code")
    token_resp = requests.post(
        INTERNAL_URL + "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=10,
    )
    if token_resp.status_code != 200:
        return jsonify({"stage": "token", "response": _safe_json(token_resp)}), 400

    tokens = token_resp.json()
    userinfo_resp = requests.get(
        INTERNAL_URL + "/oauth/userinfo",
        headers={"Authorization": "Bearer " + tokens["access_token"]},
        timeout=10,
    )
    return jsonify(
        {
            "tokens": tokens,
            "userinfo": _safe_json(userinfo_resp),
        }
    )


def _safe_json(resp):
    try:
        return resp.json()
    except ValueError:
        return {"status_code": resp.status_code, "body": resp.text[:500]}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

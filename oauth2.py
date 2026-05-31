"""Authlib authorization-server wiring for the CTFd OAuth2 IdP plugin.

This module configures CTFd as an OAuth2 Authorization Server / OpenID Connect
Identity Provider. It supports:

* Authorization Code grant with PKCE (RFC 7636)  -> public & confidential apps
* Refresh Token grant (RFC 6749)
* OpenID Connect id_tokens (signed with a locally managed RSA key)
* Token Revocation (RFC 7009) and Introspection (RFC 7662)
"""

import json
import os
import time

from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator,
    create_query_client_func,
)
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7009 import RevocationEndpoint as _RevocationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import IntrospectionEndpoint as _IntrospectionEndpoint
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode

from CTFd.models import Users, db

from .models import OAuth2AuthorizationCode, OAuth2Client, OAuth2Token

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
# Where the RSA signing key is read/written. Override with the
# OAUTH2_PROVIDER_JWK_FILE env var to keep it on a shared/persistent volume
# (e.g. across Gunicorn workers or Kubernetes pods).
JWK_PATH = os.environ.get(
    "OAUTH2_PROVIDER_JWK_FILE", os.path.join(DIR_PATH, "jwks_private.json")
)

# Default lifetime (seconds) for the various token types.
ACCESS_TOKEN_LIFETIME = 3600
REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600

authorization = AuthorizationServer()
require_oauth = ResourceProtector()

# Populated lazily by ``load_jwk`` so we only generate a key once.
_JWK = None


# ---------------------------------------------------------------------------
# Signing key management (for OIDC id_tokens / the JWKS endpoint)
# ---------------------------------------------------------------------------
def load_jwk():
    """Load the RSA signing key, generating + persisting one on first use."""
    global _JWK
    if _JWK is not None:
        return _JWK

    if os.path.exists(JWK_PATH):
        with open(JWK_PATH, "r") as fh:
            _JWK = JsonWebKey.import_key(json.load(fh))
        return _JWK

    from authlib.common.security import generate_token

    _JWK = JsonWebKey.generate_key(
        "RSA",
        2048,
        options={"kid": generate_token(8), "use": "sig", "alg": "RS256"},
        is_private=True,
    )
    try:
        with open(JWK_PATH, "w") as fh:
            json.dump(_JWK.as_dict(is_private=True), fh)
        os.chmod(JWK_PATH, 0o600)
    except OSError:
        # If we cannot persist the key (read-only FS), keep it in memory for
        # the lifetime of the process.
        pass
    return _JWK


def public_jwks():
    """Return the public JWK Set served at the JWKS endpoint."""
    return {"keys": [load_jwk().as_dict(is_private=False)]}


def issuer_url():
    """Best-effort issuer identifier for id_tokens / discovery."""
    from flask import request

    from CTFd.utils import get_app_config

    configured = get_app_config("OAUTH2_PROVIDER_ISSUER")
    if configured:
        return configured.rstrip("/")
    return request.url_root.rstrip("/")


def generate_user_info(user, scope):
    """Map a CTFd user to OIDC/userinfo claims, filtered by granted scope."""
    scopes = set((scope or "").split())
    data = {"sub": str(user.id)}
    if "profile" in scopes:
        data["name"] = user.name
        data["preferred_username"] = user.name
        if getattr(user, "website", None):
            data["website"] = user.website
        if getattr(user, "country", None):
            data["locale"] = user.country
        data["profile"] = "{}/users/{}".format(issuer_url(), user.id)
        # CTFd account role, so relying parties can gate privileged actions.
        data["is_admin"] = getattr(user, "type", None) == "admin"
        data["role"] = getattr(user, "type", None) or "user"
    if "email" in scopes:
        data["email"] = user.email
        data["email_verified"] = bool(getattr(user, "verified", False))
    if "team" in scopes:
        # Only populated when CTFd is in team mode and the user has a team.
        # Resolve via team_id explicitly rather than the user.team relationship,
        # which can be stale if team_id changed during the session.
        team = None
        team_id = getattr(user, "team_id", None)
        if team_id is not None:
            from CTFd.models import Teams

            team = Teams.query.filter_by(id=team_id).first()
        if team is not None:
            data["team"] = team.name
            data["team_id"] = team.id
            if getattr(team, "website", None):
                data["team_website"] = team.website
            if getattr(team, "country", None):
                data["team_country"] = team.country
        else:
            data["team"] = None
            data["team_id"] = None
    return UserInfo(**data)


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    # Allow both confidential (secret) and public (PKCE-only) clients.
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        nonce = request.data.get("nonce")
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return Users.query.filter_by(id=authorization_code.user_id).first()


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return Users.query.filter_by(id=credential.user_id).first()

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


class OpenIDCodeGrantExtension(OpenIDCode):
    """Adds OpenID Connect id_token issuance to the authorization code grant."""

    def exists_nonce(self, nonce, request):
        exists = OAuth2AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self, grant):
        return {
            "key": load_jwk(),
            "alg": "RS256",
            "iss": issuer_url(),
            "exp": ACCESS_TOKEN_LIFETIME,
        }

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


# ---------------------------------------------------------------------------
# Revocation & Introspection endpoints
# ---------------------------------------------------------------------------
def _query_token(token, token_type_hint):
    if token_type_hint == "access_token":
        return OAuth2Token.query.filter_by(access_token=token).first()
    if token_type_hint == "refresh_token":
        return OAuth2Token.query.filter_by(refresh_token=token).first()
    item = OAuth2Token.query.filter_by(access_token=token).first()
    if item:
        return item
    return OAuth2Token.query.filter_by(refresh_token=token).first()


class RevocationEndpoint(_RevocationEndpoint):
    def query_token(self, token, token_type_hint):
        return _query_token(token, token_type_hint)

    def revoke_token(self, token, request):
        now = int(time.time())
        token.access_token_revoked_at = now
        token.refresh_token_revoked_at = now
        db.session.add(token)
        db.session.commit()


class IntrospectionEndpoint(_IntrospectionEndpoint):
    def query_token(self, token, token_type_hint):
        return _query_token(token, token_type_hint)

    def introspect_token(self, token):
        user = Users.query.filter_by(id=token.user_id).first()
        return {
            "active": True,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "scope": token.get_scope(),
            "sub": str(token.user_id),
            "username": user.name if user else None,
            "exp": token.issued_at + token.expires_in,
            "iat": token.issued_at,
            "iss": issuer_url(),
        }

    def check_permission(self, token, client, request):
        # Only the client that owns the token may introspect it.
        return token.client_id == client.client_id


# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------
def save_token(token_data, request):
    """Persist an issued token, scoping it to the CTFd user.

    We supply our own implementation instead of Authlib's
    ``create_save_token_func`` because that helper calls
    ``request.user.get_user_id()``, a method CTFd's ``Users`` model does not
    provide. CTFd users are keyed by ``id``.
    """
    user_id = request.user.id if request.user else None
    client = request.client
    item = OAuth2Token(
        client_id=client.client_id,
        user_id=user_id,
        **token_data,
    )
    db.session.add(item)
    db.session.commit()


def config_oauth(app):
    # These must be set before init_app(), which builds the default token
    # generator from them. setdefault lets a deployment override via config.
    app.config.setdefault("OAUTH2_REFRESH_TOKEN_GENERATOR", True)
    app.config.setdefault(
        "OAUTH2_TOKEN_EXPIRES_IN",
        {
            "authorization_code": ACCESS_TOKEN_LIFETIME,
            "refresh_token": ACCESS_TOKEN_LIFETIME,
        },
    )

    query_client = create_query_client_func(db.session, OAuth2Client)
    authorization.init_app(app, query_client=query_client, save_token=save_token)

    # Authorization code grant, with optional OIDC + PKCE.
    # PKCE is *optional* at the library level (confidential apps may rely on
    # their secret), but it is enforced for public clients in the authorize
    # view (see views.authorize).
    authorization.register_grant(
        AuthorizationCodeGrant,
        [OpenIDCodeGrantExtension(require_nonce=False), CodeChallenge(required=False)],
    )
    authorization.register_grant(RefreshTokenGrant)

    authorization.register_endpoint(RevocationEndpoint)
    authorization.register_endpoint(IntrospectionEndpoint)

    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())

"""HTTP routes for the CTFd OAuth2 Identity Provider plugin.

Two route groups are exposed:

* The OAuth2/OIDC protocol endpoints (``/oauth/...``, ``/.well-known/...``)
  consumed by relying-party applications.
* An admin UI (``/admin/oidc/...``) for registering and managing applications,
  plus a user page (``/oidc/authorizations``) to review/revoke granted access.
"""

import os
import time

from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

from CTFd.models import Users, db
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import authed, get_current_user

from .models import OAuth2Client, OAuth2Token
from .oauth2 import (
    ACCESS_TOKEN_LIFETIME,
    IntrospectionEndpoint,
    RevocationEndpoint,
    authorization,
    issuer_url,
    public_jwks,
    require_oauth,
)

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

# Scopes this IdP knows how to describe on the consent screen.
SUPPORTED_SCOPES = {
    "openid": "Confirm your identity",
    "profile": "Read your public profile (username, country, website)",
    "email": "Read your email address",
    "team": "Read your team (name and ID)",
}


def render(template_name, **context):
    """Render a plugin template by file, reusing CTFd's Jinja environment.

    Reading the file and using ``render_template_string`` keeps the plugin
    independent of CTFd's template-loader registration while still allowing
    ``{% extends %}`` against theme/admin base templates.
    """
    with open(os.path.join(TEMPLATES_DIR, template_name)) as fh:
        return render_template_string(fh.read(), **context)


def bypass_csrf(view_func):
    """Mark a view as exempt from CTFd's session CSRF protection.

    OAuth2 token/revocation/introspection endpoints are called by external
    clients that do not (and cannot) carry a CTFd CSRF nonce; they are instead
    protected by client authentication / PKCE.
    """
    view_func._bypass_csrf = True
    return view_func


def split_lines(value):
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def _wants_json():
    return "application/json" in request.headers.get("Accept", "")


def load_blueprint():
    blueprint = Blueprint("oidc_provider", __name__, template_folder=TEMPLATES_DIR)

    # ---------------------------------------------------------------------
    # Discovery
    # ---------------------------------------------------------------------
    @blueprint.route("/.well-known/openid-configuration")
    @blueprint.route("/.well-known/oauth-authorization-server")
    def discovery():
        issuer = issuer_url()
        return jsonify(
            {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/oauth/authorize",
                "token_endpoint": issuer + "/oauth/token",
                "userinfo_endpoint": issuer + "/oauth/userinfo",
                "revocation_endpoint": issuer + "/oauth/revoke",
                "introspection_endpoint": issuer + "/oauth/introspect",
                "jwks_uri": issuer + "/oauth/jwks",
                "scopes_supported": sorted(SUPPORTED_SCOPES.keys()),
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "authorization_code",
                    "refresh_token",
                ],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                "code_challenge_methods_supported": ["S256", "plain"],
            }
        )

    @blueprint.route("/oauth/jwks")
    def jwks():
        return jsonify(public_jwks())

    # ---------------------------------------------------------------------
    # Authorization endpoint (interactive consent)
    # ---------------------------------------------------------------------
    @blueprint.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        if not authed():
            return redirect(url_for("auth.login", next=request.full_path))

        user = get_current_user()

        if request.method == "GET":
            try:
                grant = authorization.get_consent_grant(end_user=user)
            except OAuth2Error as error:
                return jsonify(dict(error.get_body())), error.status_code

            client = grant.client
            # Enforce PKCE for public clients (no client secret).
            if not client.is_confidential and not request.args.get("code_challenge"):
                return (
                    jsonify(
                        {
                            "error": "invalid_request",
                            "error_description": "code_challenge is required for public clients (PKCE).",
                        }
                    ),
                    400,
                )

            # Trusted (first-party) apps skip the consent screen and are
            # auto-approved on behalf of the logged-in user.
            if client.is_trusted:
                return authorization.create_authorization_response(grant_user=user)

            scopes = [
                (scope, SUPPORTED_SCOPES.get(scope, scope))
                for scope in (grant.request.scope or "").split()
            ]
            return render(
                "oauth2_authorize.html",
                user=user,
                grant=grant,
                client=client,
                scopes=scopes,
                nonce=session.get("nonce"),
            )

        # POST: the user submitted the consent form.
        if request.form.get("confirm") == "yes":
            grant_user = user
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)

    # ---------------------------------------------------------------------
    # Token, revocation, introspection (machine endpoints)
    # ---------------------------------------------------------------------
    @blueprint.route("/oauth/token", methods=["POST"])
    @bypass_csrf
    def issue_token():
        return authorization.create_token_response()

    @blueprint.route("/oauth/revoke", methods=["POST"])
    @bypass_csrf
    def revoke_token():
        return authorization.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME)

    @blueprint.route("/oauth/introspect", methods=["POST"])
    @bypass_csrf
    def introspect_token():
        return authorization.create_endpoint_response(
            IntrospectionEndpoint.ENDPOINT_NAME
        )

    @blueprint.route("/oauth/userinfo", methods=["GET", "POST"])
    @bypass_csrf
    @require_oauth()
    def userinfo():
        from .oauth2 import generate_user_info

        token = current_token
        user = Users.query.filter_by(id=token.user_id).first()
        if user is None:
            abort(404)
        return jsonify(generate_user_info(user, token.get_scope()))

    # ---------------------------------------------------------------------
    # User: review & revoke authorized applications
    # ---------------------------------------------------------------------
    @blueprint.route("/oidc/authorizations")
    @authed_only
    def authorizations():
        user = get_current_user()
        tokens = (
            OAuth2Token.query.filter_by(user_id=user.id)
            .order_by(OAuth2Token.issued_at.desc())
            .all()
        )
        # Resolve client display names for each token.
        rows = []
        for token in tokens:
            if token.is_revoked():
                continue
            client = OAuth2Client.query.filter_by(client_id=token.client_id).first()
            rows.append({"token": token, "client": client})

        # The settings-page tab (settings_tab.js) consumes this as JSON.
        if request.args.get("format") == "json" or _wants_json():
            return jsonify(
                {
                    "authorizations": [
                        {
                            "id": row["token"].id,
                            "name": (
                                row["client"].client_name
                                if row["client"]
                                else row["token"].client_id
                            ),
                            "scope": row["token"].get_scope(),
                            "issued_at": row["token"].issued_at,
                        }
                        for row in rows
                    ]
                }
            )
        return render("oauth2_authorizations.html", user=user, rows=rows)

    @blueprint.route("/oidc/authorizations/<int:token_id>/revoke", methods=["POST"])
    @authed_only
    def revoke_authorization(token_id):
        user = get_current_user()
        token = OAuth2Token.query.filter_by(id=token_id, user_id=user.id).first()
        if token is None:
            abort(404)
        now = int(time.time())
        token.access_token_revoked_at = now
        token.refresh_token_revoked_at = now
        db.session.commit()
        if _wants_json():
            return jsonify({"success": True})
        return redirect(url_for("oidc_provider.authorizations"))

    # ---------------------------------------------------------------------
    # Admin: application management
    # ---------------------------------------------------------------------
    @blueprint.route("/admin/oidc")
    @admins_only
    def admin_clients():
        clients = OAuth2Client.query.order_by(OAuth2Client.id.desc()).all()
        return render("admin_oauth2_clients.html", clients=clients)

    @blueprint.route("/admin/oidc/new")
    @admins_only
    def admin_new_client():
        return render(
            "admin_oauth2_client.html",
            client=None,
            scopes=SUPPORTED_SCOPES,
            nonce=session.get("nonce"),
            new_secret=None,
        )

    @blueprint.route("/admin/oidc/create", methods=["POST"])
    @admins_only
    def admin_create_client():
        user = get_current_user()
        client = OAuth2Client(user_id=user.id if user else None)
        client.client_id = generate_token(24)
        client.client_id_issued_at = int(time.time())

        confidential = request.form.get("client_type") == "confidential"
        new_secret = None
        if confidential:
            new_secret = generate_token(48)
            client.client_secret = new_secret
            auth_method = request.form.get(
                "token_endpoint_auth_method", "client_secret_basic"
            )
            if auth_method not in ("client_secret_basic", "client_secret_post"):
                auth_method = "client_secret_basic"
        else:
            client.client_secret = ""
            auth_method = "none"

        _apply_client_metadata(client, auth_method)
        db.session.add(client)
        db.session.commit()

        # Show the generated secret exactly once.
        return render(
            "admin_oauth2_client.html",
            client=client,
            scopes=SUPPORTED_SCOPES,
            nonce=session.get("nonce"),
            new_secret=new_secret,
        )

    @blueprint.route("/admin/oidc/<int:client_pk>")
    @admins_only
    def admin_edit_client(client_pk):
        client = OAuth2Client.query.filter_by(id=client_pk).first()
        if client is None:
            abort(404)
        return render(
            "admin_oauth2_client.html",
            client=client,
            scopes=SUPPORTED_SCOPES,
            nonce=session.get("nonce"),
            new_secret=None,
        )

    @blueprint.route("/admin/oidc/<int:client_pk>/update", methods=["POST"])
    @admins_only
    def admin_update_client(client_pk):
        client = OAuth2Client.query.filter_by(id=client_pk).first()
        if client is None:
            abort(404)
        auth_method = client.token_endpoint_auth_method
        if client.is_confidential:
            auth_method = request.form.get(
                "token_endpoint_auth_method", auth_method or "client_secret_basic"
            )
            if auth_method not in ("client_secret_basic", "client_secret_post"):
                auth_method = "client_secret_basic"
        else:
            auth_method = "none"
        _apply_client_metadata(client, auth_method)
        db.session.commit()
        return redirect(url_for("oidc_provider.admin_edit_client", client_pk=client.id))

    @blueprint.route("/admin/oidc/<int:client_pk>/rotate-secret", methods=["POST"])
    @admins_only
    def admin_rotate_secret(client_pk):
        client = OAuth2Client.query.filter_by(id=client_pk).first()
        if client is None:
            abort(404)
        if not client.is_confidential:
            abort(400)
        new_secret = generate_token(48)
        client.client_secret = new_secret
        db.session.commit()
        return render(
            "admin_oauth2_client.html",
            client=client,
            scopes=SUPPORTED_SCOPES,
            nonce=session.get("nonce"),
            new_secret=new_secret,
        )

    @blueprint.route("/admin/oidc/<int:client_pk>/delete", methods=["POST"])
    @admins_only
    def admin_delete_client(client_pk):
        client = OAuth2Client.query.filter_by(id=client_pk).first()
        if client is None:
            abort(404)
        db.session.delete(client)
        db.session.commit()
        return redirect(url_for("oidc_provider.admin_clients"))

    return blueprint


def _apply_client_metadata(client, auth_method):
    """Read the admin form and write the Authlib client metadata blob."""
    redirect_uris = split_lines(request.form.get("redirect_uris"))
    selected_scopes = request.form.getlist("scopes")
    if not selected_scopes:
        selected_scopes = ["openid", "profile", "email"]

    grant_types = ["authorization_code"]
    if request.form.get("allow_refresh") == "yes":
        grant_types.append("refresh_token")

    metadata = {
        "client_name": request.form.get("client_name", "").strip() or "Unnamed app",
        "client_uri": request.form.get("client_uri", "").strip(),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": ["code"],
        "scope": " ".join(selected_scopes),
        "token_endpoint_auth_method": auth_method,
        # Trusted (first-party) apps skip the consent screen.
        "trusted": request.form.get("trusted") == "yes",
    }
    client.set_client_metadata(metadata)

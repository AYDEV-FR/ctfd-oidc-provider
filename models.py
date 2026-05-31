"""Database models for the CTFd OAuth2 Identity Provider plugin.

These models build on Authlib's SQLAlchemy mixins, which provide all of the
standard OAuth2 columns/helpers, and tie each record back to a CTFd ``Users``
row so issued tokens are scoped to a real CTFd account.
"""

import time

from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)

from CTFd.models import db

# Refresh tokens stay valid for this window from issuance (seconds).
REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600


class OAuth2Client(db.Model, OAuth2ClientMixin):
    """A registered OAuth2 application (public or confidential)."""

    __tablename__ = "oauth2_clients"

    id = db.Column(db.Integer, primary_key=True)
    # The CTFd admin/user who owns (registered) this application.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    user = db.relationship("Users")

    @property
    def is_confidential(self):
        """Confidential clients authenticate to the token endpoint with a secret."""
        return self.token_endpoint_auth_method != "none"

    @property
    def client_type(self):
        return "confidential" if self.is_confidential else "public"

    @property
    def is_trusted(self):
        """Trusted (first-party) apps skip the user consent screen.

        Stored as a custom ``trusted`` key inside Authlib's client_metadata
        JSON blob, so no schema change is required.
        """
        try:
            return bool(self.client_metadata.get("trusted"))
        except Exception:
            return False


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    """Short-lived authorization codes exchanged at the token endpoint.

    Also carries the PKCE ``code_challenge`` and OIDC ``nonce`` columns provided
    by the Authlib mixin.
    """

    __tablename__ = "oauth2_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    user = db.relationship("Users")


class OAuth2Token(db.Model, OAuth2TokenMixin):
    """Issued access/refresh tokens."""

    __tablename__ = "oauth2_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    user = db.relationship("Users")

    def is_refresh_token_active(self):
        if self.is_revoked():
            return False
        expires_at = self.issued_at + REFRESH_TOKEN_LIFETIME
        return expires_at >= time.time()

    def is_revoked(self):
        return bool(self.access_token_revoked_at or self.refresh_token_revoked_at)

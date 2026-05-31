"""Declarative provisioning of OAuth2 applications from a YAML file.

This lets you define applications as code and mount the file into the container
(infrastructure-as-code), instead of registering them by hand in the admin UI.

Enable it by pointing ``OIDC_PROVIDER_APPS_FILE`` (env var or CTFd config) at
a YAML file, e.g.:

    applications:
      - name: My Web App
        client_id: my-web-app             # required, used as the stable key
        client_secret: super-secret       # required for confidential apps
        type: confidential                # "confidential" (default) or "public"
        client_uri: https://app.example.com
        redirect_uris:
          - https://app.example.com/callback
        scopes: [openid, profile, email]
        grant_types: [authorization_code, refresh_token]
        token_endpoint_auth_method: client_secret_basic

Behaviour:

* Apps are matched by ``client_id`` and **upserted** on every startup, so
  editing the file and restarting applies the changes (IaC style).
* Public apps get ``token_endpoint_auth_method: none`` (PKCE enforced).
* Confidential apps MUST provide an explicit ``client_secret`` (secrets are
  never auto-generated or written to the log).
* Removing an app from the file does NOT delete it (delete it in the admin UI),
  to avoid accidental data loss.
"""

import os
import time

from CTFd.models import db

from .models import OAuth2Client

DEFAULT_SCOPES = ["openid", "profile", "email"]


def _config_path(app):
    return os.environ.get("OIDC_PROVIDER_APPS_FILE") or app.config.get(
        "OIDC_PROVIDER_APPS_FILE"
    )


def provision_from_yaml(app):
    """Read the configured YAML file (if any) and upsert the listed apps."""
    path = _config_path(app)
    if not path:
        return

    if not os.path.exists(path):
        app.logger.warning(
            "OIDC IdP: apps file %s not found; skipping provisioning", path
        )
        return

    try:
        import yaml
    except ImportError:
        app.logger.error(
            "OIDC IdP: PyYAML is required for YAML provisioning but is not installed."
        )
        return

    try:
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:  # malformed YAML / IO error
        app.logger.error("OIDC IdP: failed to read %s: %s", path, exc)
        return

    entries = data.get("applications") or data.get("apps") or []
    if not isinstance(entries, list):
        app.logger.error(
            "OIDC IdP: '%s' must contain a list under 'applications'", path
        )
        return

    created = updated = failed = 0
    for entry in entries:
        try:
            status = _upsert(app, entry)
            if status == "created":
                created += 1
            elif status == "updated":
                updated += 1
        except Exception as exc:
            failed += 1
            name = entry.get("name") if isinstance(entry, dict) else entry
            app.logger.error("OIDC IdP: could not provision %r: %s", name, exc)

    if created or updated:
        db.session.commit()
    app.logger.info(
        "OIDC IdP: provisioned apps from %s (created=%d, updated=%d, failed=%d)",
        path,
        created,
        updated,
        failed,
    )


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    return list(value)


def _upsert(app, entry):
    if not isinstance(entry, dict):
        raise ValueError("each application must be a mapping")

    client_id = str(entry.get("client_id") or "").strip()
    if not client_id:
        raise ValueError("client_id is required")

    app_type = str(
        entry.get("type") or ("public" if entry.get("public") else "confidential")
    ).lower()
    if app_type not in ("public", "confidential"):
        raise ValueError("type must be 'public' or 'confidential'")

    redirect_uris = [u.strip() for u in _as_list(entry.get("redirect_uris")) if u and str(u).strip()]
    if not redirect_uris:
        raise ValueError("at least one redirect_uri is required")
    scopes = _as_list(entry.get("scopes")) or list(DEFAULT_SCOPES)

    client_uri = str(entry.get("client_uri") or "").strip()
    if client_uri and not client_uri.lower().startswith(("http://", "https://")):
        # Reject non-http(s) schemes (e.g. javascript:) that would otherwise be
        # rendered as a link on the consent page.
        client_uri = ""

    grant_types = _as_list(entry.get("grant_types"))
    if not grant_types:
        grant_types = ["authorization_code", "refresh_token"]

    if app_type == "public":
        auth_method = "none"
    else:
        auth_method = entry.get("token_endpoint_auth_method", "client_secret_basic")
        if auth_method not in ("client_secret_basic", "client_secret_post"):
            auth_method = "client_secret_basic"

    existing = OAuth2Client.query.filter_by(client_id=client_id).first()
    client = existing or OAuth2Client(client_id=client_id)
    if existing is None:
        client.client_id_issued_at = int(time.time())

    client.set_client_metadata(
        {
            "client_name": str(entry.get("name") or client_id),
            "client_uri": client_uri,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": ["code"],
            "scope": " ".join(scopes),
            "token_endpoint_auth_method": auth_method,
            # Trusted (first-party) apps skip the user consent screen.
            "trusted": bool(entry.get("trusted", False)),
        }
    )

    if app_type == "public":
        client.client_secret = ""
    else:
        secret = entry.get("client_secret")
        if secret:
            client.client_secret = str(secret)
        elif existing is None:
            # Never auto-generate-and-log a secret: writing credentials to the
            # application log is a disclosure risk. For IaC the operator must
            # provide the secret explicitly (e.g. from a sealed secret / vault).
            raise ValueError(
                "client_secret is required for confidential app '%s'" % client_id
            )

    if existing is None:
        db.session.add(client)
        return "created"
    return "updated"

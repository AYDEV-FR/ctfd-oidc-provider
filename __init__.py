"""CTFd OAuth2 / OpenID Connect Identity Provider plugin.

Turns a CTFd instance into an OAuth2 Authorization Server + OIDC IdP so that
external applications can offer "Log in with CTFd". Supports both public
(PKCE) and confidential (client secret) applications.

Drop this directory into ``CTFd/plugins/`` (e.g. ``CTFd/plugins/oauth2_provider``)
and install the requirements (``pip install -r requirements.txt``).
"""

from CTFd.plugins import (
    register_plugin_assets_directory,
    register_plugin_script,
)

from .oauth2 import config_oauth, load_jwk
from .provisioning import provision_from_yaml
from .views import load_blueprint

# The plugin's import/folder name, e.g. "oauth2_provider". Used to build the
# asset URLs so the plugin keeps working if installed under a different folder.
PLUGIN_NAME = __name__.split(".")[-1]


def load(app):
    # Ensure our tables exist. Models are imported (and thus registered on the
    # metadata) via the imports above, so create_all only creates the missing
    # oauth2_* tables and leaves CTFd's schema untouched.
    app.db.create_all()

    # Configure the Authlib authorization server against CTFd's DB/session.
    config_oauth(app)

    # Pre-generate / load the signing key so the first request isn't slowed
    # and any filesystem error surfaces at startup.
    try:
        load_jwk()
    except Exception as e:  # pragma: no cover - defensive
        app.logger.warning("OAuth2 IdP: could not pre-load signing key: %s", e)

    # Register all protocol + admin + user routes.
    app.register_blueprint(load_blueprint())

    # Optionally provision applications declaratively from a mounted YAML file
    # (set OAUTH2_PROVIDER_APPS_FILE). No-op if the variable is unset.
    try:
        provision_from_yaml(app)
    except Exception as e:  # pragma: no cover - defensive
        app.logger.error("OAuth2 IdP: YAML provisioning failed: %s", e)

    # Serve the plugin's static assets, and inject a script that adds an
    # "Authorized Apps" tab to the user settings (/settings) page.
    register_plugin_assets_directory(
        app, base_path="/plugins/{}/assets".format(PLUGIN_NAME)
    )
    register_plugin_script("/plugins/{}/assets/settings_tab.js".format(PLUGIN_NAME))

    # The admin management page (/admin/oauth2) is surfaced under the admin
    # "Plugins" dropdown via config.json, so no menu-bar registration is needed.

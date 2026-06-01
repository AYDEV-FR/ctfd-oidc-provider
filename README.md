# CTFd OIDC / OAuth2 Identity Provider

[![Build OCI image](https://github.com/AYDEV-FR/ctfd-oidc-provider/actions/workflows/build-oci.yml/badge.svg)](https://github.com/AYDEV-FR/ctfd-oidc-provider/actions/workflows/build-oci.yml)
[![CI](https://github.com/AYDEV-FR/ctfd-oidc-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/AYDEV-FR/ctfd-oidc-provider/actions/workflows/ci.yml)
[![Container image](https://img.shields.io/badge/ghcr.io-aydev--fr%2Fctfd--oidc--provider-blue?logo=docker)](https://github.com/AYDEV-FR/ctfd-oidc-provider/pkgs/container/ctfd-oidc-provider)

A CTFd plugin that turns your CTFd instance into an **OAuth2 Authorization Server
and OpenID Connect (OIDC) Identity Provider**. Other applications can then offer
"**Log in with CTFd**", and CTFd issues authorization codes, access / refresh
tokens, and signed OIDC `id_token`s tied to your CTFd accounts.

Supports both **public** and **confidential** OAuth2 applications.

| Application type | Authenticates with | Requirement |
|------------------|--------------------|-------------|
| **Confidential** (server-side web apps) | a `client_secret` (Basic or POST) | secret stored securely on a server |
| **Public** (SPAs, mobile, CLI, desktop) | no secret | **PKCE is mandatory** (RFC 7636) |

Built on [Authlib](https://authlib.org/), so the OAuth2 / OIDC mechanics
(grants, token validation, PKCE, revocation, introspection) are handled by a
mature, security-reviewed library.

---

## Table of contents

- [Features](#features)
- [Installation](#installation)
  - [A. Classic plugin install](#a-classic-plugin-install)
  - [B. Kubernetes — mount as a volume (OCI image)](#b-kubernetes--mount-as-a-volume-oci-image)
  - [C. Quick start with Docker Compose (local testing)](#c-quick-start-with-docker-compose-local-testing)
- [Configuration](#configuration)
- [Registering an application](#registering-an-application)
- [Declarative provisioning from YAML](#declarative-provisioning-from-yaml)
- [Trusted (first-party) applications](#trusted-first-party-applications)
- [Endpoints](#endpoints)
- [Scopes & claims](#scopes--claims)
- [Example flows](#example-flows)
- [Security notes](#security-notes)
- [Development & contributing](#development--contributing)

---

## Features

- **Authorization Code** grant **with PKCE** (`S256` / `plain`).
- **Refresh Token** grant (optional, per application).
- **OpenID Connect** `id_token`s signed with a locally-managed RSA key (RS256).
- **UserInfo**, **Revocation** (RFC 7009) and **Introspection** (RFC 7662) endpoints.
- **Discovery**: `/.well-known/openid-configuration` + a JWKS endpoint.
- **Public & confidential** clients, with PKCE enforced for public clients.
- **Admin UI** to register / edit / delete applications and rotate secrets,
  surfaced under the admin **Plugins** menu.
- **Declarative provisioning** of applications from a mounted YAML file (IaC).
- **Trusted (first-party) apps** that skip the user consent screen.
- **Authorized Apps** tab on the user **Settings** page to review and revoke access.
- Rich claims: user `profile`, `email`, CTFd **team** and **admin / role** info.
- Ships as both a **classic CTFd plugin** and a **published OCI image** for
  Kubernetes volume mounting.

---

## Installation

> The plugin folder name becomes its Python import name. This document assumes
> **`oidc_provider`**. Keep that name unless you also update references.

### A. Classic plugin install

Like any other CTFd plugin: drop it into `CTFd/plugins/` and install its
dependencies into the same environment CTFd runs in.

```bash
# from the root of your CTFd checkout
git clone https://github.com/AYDEV-FR/ctfd-oidc-provider.git \
  CTFd/plugins/oidc_provider

pip install -r CTFd/plugins/oidc_provider/requirements.txt

# restart CTFd
```

On first run the plugin:

- creates its tables (`oauth2_clients`, `oauth2_codes`, `oauth2_tokens`)
  automatically — no manual migration needed;
- generates an RSA signing key at `oidc_provider/jwks_private.json`.

> **Keep `jwks_private.json` private and persistent.** Deleting it invalidates
> every previously issued `id_token`. In multi-worker / multi-host deployments,
> make sure all workers read the **same** key file (shared volume) or pre-seed
> one. See [Configuration](#configuration) for pinning the key via env var.

### B. Kubernetes — mount as a volume (OCI image)

Every push to `main` publishes a small **OCI image** that contains *only the
plugin and its Python dependencies* to GitHub Container Registry:

```
ghcr.io/aydev-fr/ctfd-oidc-provider:latest
```

Image layout:

| Path | Contents |
|------|----------|
| `/plugin/oidc_provider/` | the plugin package (code, templates, assets) |
| `/plugin/deps/` | vendored Python deps (Authlib, PyYAML) for `PYTHONPATH` |

This lets you run the **upstream `ctfd/ctfd` image unchanged** and inject the
plugin at runtime with an `initContainer` that copies it into shared volumes.
A complete, ready-to-apply example lives in [`k8s/`](k8s/); the essence:

```yaml
spec:
  volumes:
    - name: oidc-plugin       # holds the plugin package
      emptyDir: {}
    - name: oidc-deps         # holds the vendored python deps
      emptyDir: {}

  initContainers:
    - name: install-oidc-plugin
      image: ghcr.io/aydev-fr/ctfd-oidc-provider:latest
      command: ["sh", "-c", "cp -r /plugin/oidc_provider/. /dst-plugin/ && cp -r /plugin/deps/. /dst-deps/"]
      volumeMounts:
        - { name: oidc-plugin, mountPath: /dst-plugin }
        - { name: oidc-deps,   mountPath: /dst-deps }

  containers:
    - name: ctfd
      image: ctfd/ctfd:3.8.5
      env:
        # make the vendored deps importable, and pin a stable issuer/key
        - { name: PYTHONPATH, value: /opt/oidc-deps }
        - { name: OIDC_PROVIDER_ISSUER, value: https://ctf.example.com }
      volumeMounts:
        # mount ONLY the plugin subdir, so built-in CTFd plugins stay intact
        - { name: oidc-plugin, mountPath: /opt/CTFd/CTFd/plugins/oidc_provider }
        - { name: oidc-deps,   mountPath: /opt/oidc-deps }
```

Notes:

- Mount the plugin at the **`oidc_provider` subdirectory**, never over the
  whole `plugins/` folder — otherwise CTFd's built-in plugins disappear.
- Persist the signing key: set `OIDC_PROVIDER_JWK_FILE` to a path on a
  `PersistentVolume` (see [Configuration](#configuration)), or all pods will
  generate different keys.
- Pin a real release tag (e.g. `:v1.0.0`) in production instead of `:latest`.

### C. Quick start with Docker Compose (local testing)

The repo ships a `docker-compose.yml` + `Dockerfile` that run CTFd with the
plugin **bind-mounted**, so you can test and edit it live:

```bash
docker compose up --build
```

Open <http://localhost:8000>, complete the CTFd setup wizard, and you'll see
**OIDC Apps** under the admin **Plugins** menu.

- The `Dockerfile` extends `ctfd/ctfd` and `pip install`s the requirements.
- `AUTHLIB_INSECURE_TRANSPORT=1` is set so OAuth2 works over plain HTTP locally
  — **never** in production.
- DB / uploads / logs persist in named volumes (`docker compose down -v` wipes them).
- An example app set is auto-provisioned from
  [`oidc_apps.example.yaml`](oidc_apps.example.yaml).

**Try the full login flow** with the bundled demo relying-party:

```bash
docker compose --profile demo up --build
```

Then open <http://localhost:5000> → **Login with CTFd**. Because the demo app is
provisioned as *trusted*, consent is auto-approved and you get the issued tokens
+ `userinfo` back as JSON.

---

## Configuration

All settings are read from environment variables (or the matching CTFd config key).

| Variable | Default | Purpose |
|----------|---------|---------|
| `OIDC_PROVIDER_ISSUER` | request host | The `iss` value in `id_token`s and discovery. Pin this behind a proxy. |
| `OIDC_PROVIDER_APPS_FILE` | _unset_ | Path to a YAML file of apps to provision on startup (see below). |
| `OIDC_PROVIDER_JWK_FILE` | `oidc_provider/jwks_private.json` | Where the RSA signing key is read/written. Put it on a shared/persistent volume. |
| `AUTHLIB_INSECURE_TRANSPORT` | _unset_ | Set to `1` to allow plain HTTP. **Local dev only.** |

Behind a reverse proxy, make sure CTFd sees the correct external scheme/host
(CTFd's `ReverseProxy` setting / `X-Forwarded-*` headers) so generated URLs and
the issuer are correct.

---

## Registering an application

Go to **Admin → Plugins → OIDC Apps → Register application** and choose:

- **Confidential** — a client secret is generated and shown **once**. Use
  `client_secret_basic` (default) or `client_secret_post`.
- **Public** — no secret; the app **must** use PKCE.

Set one or more exact **redirect URIs**, pick the **scopes**, optionally enable
**refresh tokens**, and optionally mark the app **trusted** (skip consent).

---

## Declarative provisioning from YAML

Define applications as code and mount the file into the container; set
`OIDC_PROVIDER_APPS_FILE` to its path. On every startup the plugin
**upserts** the listed apps (matched by `client_id`).

```yaml
# oidc_apps.yaml
applications:
  - name: My Web App
    client_id: my-web-app             # required — the stable upsert key
    client_secret: super-secret       # required for confidential apps
    type: confidential                # "confidential" (default) or "public"
    trusted: false                    # true => skip the consent screen
    client_uri: https://app.example.com
    redirect_uris:
      - https://app.example.com/callback
    scopes: [openid, profile, email, team]
    grant_types: [authorization_code, refresh_token]
    token_endpoint_auth_method: client_secret_basic

  - name: My SPA
    client_id: my-spa
    type: public                      # no secret; PKCE enforced
    redirect_uris:
      - https://spa.example.com/callback
    scopes: [openid, profile]
```

- Apps are **upserted** every startup — edit + restart to apply changes.
- A confidential app with no `client_secret` gets one generated and logged once.
- Removing an entry does **not** delete the app (delete it from the admin UI).

---

## Trusted (first-party) applications

A **trusted** application skips the consent screen: a logged-in user sent to
`/oauth/authorize` is auto-approved and redirected straight back with a code.
Use this only for first-party apps you fully control (your own wiki/forum behind
the same login), since the user is never asked to confirm.

Enable it via the admin UI (**Trusted application** checkbox) or YAML
(`trusted: true`). Everything else — PKCE, scopes, token issuance, revocation —
behaves identically; only the interactive consent step is bypassed.

---

## Endpoints

| Purpose | URL | Auth |
|---------|-----|------|
| Discovery | `/.well-known/openid-configuration` | none |
| JWKS (public keys) | `/oauth/jwks` | none |
| Authorization | `/oauth/authorize` | CTFd login + consent |
| Token | `/oauth/token` | client auth / PKCE |
| UserInfo | `/oauth/userinfo` | Bearer access token |
| Revocation | `/oauth/revoke` | client auth |
| Introspection | `/oauth/introspect` | client auth |
| Admin: manage apps | `/admin/oidc` | CTFd admin |
| User: authorized apps | `/oidc/authorizations` | CTFd user |

---

## Scopes & claims

| Scope | Claims returned |
|-------|-----------------|
| `openid` | `sub` (CTFd user id) |
| `profile` | `name`, `preferred_username`, `website`, `locale`, `profile`, `is_admin` (bool), `role` (`admin`/`user`) |
| `email` | `email`, `email_verified` |
| `team` | `team`, `team_id` (and `team_website` / `team_country` when set) — team-mode only; `null` if the user has no team |

These claims appear both in the OIDC `id_token` and in the `/oauth/userinfo`
response, filtered by the scopes the user granted.

---

## Example flows

### Confidential app (Authorization Code)

```
GET /oauth/authorize?response_type=code
    &client_id=CLIENT_ID
    &redirect_uri=https://app.example.com/callback
    &scope=openid%20profile%20email
    &state=RANDOM
```

After consent, CTFd redirects back with `?code=...&state=...`. Exchange it:

```bash
curl -u CLIENT_ID:CLIENT_SECRET \
  -d grant_type=authorization_code \
  -d code=THE_CODE \
  -d redirect_uri=https://app.example.com/callback \
  https://ctf.example.com/oauth/token
```

### Public app (Authorization Code + PKCE)

```
# code_verifier = random 43-128 char string
# code_challenge = BASE64URL(SHA256(code_verifier))

GET /oauth/authorize?response_type=code
    &client_id=CLIENT_ID
    &redirect_uri=myapp://callback
    &scope=openid%20profile
    &state=RANDOM
    &code_challenge=CHALLENGE
    &code_challenge_method=S256
```

```bash
curl -d grant_type=authorization_code \
     -d client_id=CLIENT_ID \
     -d code=THE_CODE \
     -d redirect_uri=myapp://callback \
     -d code_verifier=THE_VERIFIER \
     https://ctf.example.com/oauth/token
```

### Using the token

```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" \
     https://ctf.example.com/oauth/userinfo
# => {"sub":"42","name":"alice","email":"alice@example.com","is_admin":false,...}
```

---

## Security notes

- PKCE is **required** for public clients and supported for confidential ones.
- Redirect URIs are matched **exactly**.
- Access tokens default to a 1-hour lifetime; refresh tokens to 30 days.
- Token endpoints are exempt from CTFd's session CSRF (they use client auth /
  PKCE instead); the interactive consent form is CSRF-protected.
- Deleting an application or revoking from **Authorized Apps** immediately
  invalidates the relevant tokens.
- **Trusted apps bypass user consent** — only mark first-party apps you control.
- `is_admin` / `role` reflect the CTFd account type at token-issue time; relying
  parties should treat them as the IdP's assertion of role.
- Always serve over HTTPS in production and keep the signing key persistent and
  secret.
- **Pin `OIDC_PROVIDER_ISSUER`** in production. Without it the issuer is derived
  from the request `Host` header, which a client can spoof — affecting the
  `id_token` `iss` claim and discovery URLs. A startup warning is logged when it
  is unset.
- **Provisioning never auto-generates or logs client secrets.** A confidential
  app defined in the YAML file must include an explicit `client_secret` (supply
  it from a sealed secret / vault); otherwise provisioning fails for that app.
- Every application must declare at least one **absolute http(s) redirect URI**;
  `client_uri` is restricted to http(s) so it can't become a `javascript:` link
  on the consent screen.

---

## Development & contributing

```bash
# byte-compile sanity check
python -m py_compile *.py

# run the full local stack (CTFd + plugin + demo client)
docker compose --profile demo up --build
```

CI (`.github/workflows/ci.yml`) byte-compiles the plugin on every push/PR. The
OCI image is built and published by
[`.github/workflows/build-oci.yml`](.github/workflows/build-oci.yml).

Issues and pull requests welcome at
<https://github.com/AYDEV-FR/ctfd-oidc-provider>.

---

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). This matches the license of CTFd itself.

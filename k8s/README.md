# Kubernetes example

Runs the **upstream `ctfd/ctfd` image unchanged** and injects this plugin at
runtime from the published OCI image
(`ghcr.io/aydev-fr/ctfd-oidc-provider`).

```bash
kubectl apply -f k8s/
```

## How it works

1. An **initContainer** uses the plugin OCI image and copies:
   - `/plugin/oauth2_provider/` → an `emptyDir` mounted at
     `/opt/CTFd/CTFd/plugins/oauth2_provider` in the CTFd container, and
   - `/plugin/deps/` (Authlib, PyYAML) → an `emptyDir` mounted at
     `/opt/oidc-deps`, which is added to `PYTHONPATH`.
2. The **CTFd container** loads the plugin like any other; the vendored deps are
   importable via `PYTHONPATH`.
3. The RSA signing key lives on a small **PVC** (`OAUTH2_PROVIDER_JWK_FILE`) so
   it persists across restarts and is shared by all workers in the pod.

## Things to change for production

- Pin a release tag (`:v1.0.0`) instead of `:latest`.
- Set a real `OAUTH2_PROVIDER_ISSUER` and a strong `SECRET_KEY` (use a `Secret`).
- Replace SQLite-on-PVC with MySQL + Redis (`DATABASE_URL` / `REDIS_URL`).
- Add an Ingress with TLS in front of the `ctfd` Service.
- If you scale beyond one pod, use a `ReadWriteMany` PVC for the signing key (or
  pre-seed it via a `Secret`) so every pod signs with the same key.

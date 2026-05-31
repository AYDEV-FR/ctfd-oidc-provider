# Test image for the CTFd OIDC IdP plugin.
#
# The official CTFd entrypoint does NOT install plugin requirements, so we bake
# the plugin's only dependency (Authlib) into the image here. The plugin *code*
# itself is bind-mounted at runtime (see docker-compose.yml), so you can edit
# the Python/templates and just restart the container to see changes — no
# rebuild needed unless requirements.txt changes.
#
# Pin a specific CTFd release for reproducibility, e.g. ctfd/ctfd:3.7.7
FROM ctfd/ctfd:latest

# The CTFd image runs as the unprivileged user 1001; switch to root only to
# install the dependency and prepare the data directory.
USER root

COPY requirements.txt /tmp/oauth2-requirements.txt
RUN pip install --no-cache-dir -r /tmp/oauth2-requirements.txt \
    && mkdir -p /data \
    && chown -R 1001:1001 /data

USER 1001

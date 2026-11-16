FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends dbus-x11 gnome-keyring libsecret-tools \
  && rm -rf /var/lib/apt/lists/*
COPY scripts/linux-secret-service-entrypoint.sh /usr/local/bin/agentsecret-keyring-acceptance
RUN chmod 0755 /usr/local/bin/agentsecret-keyring-acceptance
USER node
ENTRYPOINT ["dbus-run-session", "--", "/usr/local/bin/agentsecret-keyring-acceptance"]

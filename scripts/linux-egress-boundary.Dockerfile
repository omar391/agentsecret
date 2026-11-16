FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
COPY scripts/linux-egress-fixture.mjs /opt/linux-egress-fixture.mjs
COPY scripts/linux-egress-supervisor.mjs /opt/linux-egress-supervisor.mjs
COPY scripts/linux-egress-guest.mjs /opt/linux-egress-guest.mjs
COPY scripts/linux-egress-tcp-probes.mjs /opt/linux-egress-tcp-probes.mjs
COPY scripts/linux-egress-udp-probes.mjs /opt/linux-egress-udp-probes.mjs
USER node

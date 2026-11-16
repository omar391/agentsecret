#!/bin/sh
set -eu
printf '%s' 'synthetic-keyring-unlock-only' | gnome-keyring-daemon --unlock --components=secrets >/tmp/agentsecret-keyring-env
. /tmp/agentsecret-keyring-env
exec node /opt/linux-secret-service-acceptance.mjs

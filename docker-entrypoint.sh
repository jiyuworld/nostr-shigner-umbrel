#!/bin/sh
# umbrel bind-mounts a persistent volume at /data. if the host dir is owned by a
# different uid than nostr-shigner (uid 1000), key writes fail. so start as root,
# fix ownership, then drop privileges with su-exec.
set -e

if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown nostr-shigner:nostr-shigner /data 2>/dev/null || true
    chown -R nostr-shigner:nostr-shigner /data 2>/dev/null || true
    exec su-exec nostr-shigner:nostr-shigner "$@"
fi

exec "$@"

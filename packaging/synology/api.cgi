#!/bin/sh
set -eu
umask 077
PKG_TARGET=/var/packages/SynologyNASConnector/target
. "$PKG_TARGET/bin/node-runtime"
find_node
exec "$NODE" "$PKG_TARGET/dsm-bridge.cjs" /var/packages/SynologyNASConnector/var/config.json

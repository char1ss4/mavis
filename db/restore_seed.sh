#!/bin/sh
# Restore db/seed.sql into the running mavis-mysql container (demo safety net).
# Run from the repo root (Git Bash on Windows). Overwrites the tables in the dump.
#
# Credentials are expanded by sh *inside* the container from its own env,
# so no password appears in this script, the host command line, or its output.
set -e

SEED="${1:-db/seed.sql}"
[ -f "$SEED" ] || { echo "No seed file at $SEED" >&2; exit 1; }

docker cp "$SEED" mavis-mysql:/tmp/seed.sql
docker exec mavis-mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -u"$MYSQL_USER" "$MYSQL_DATABASE" < /tmp/seed.sql'
echo "Restored $SEED into mavis-mysql."

#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
echo "STF POC / HeraclitusDB - http://127.0.0.1:8787"
exec python3 server.py --host 127.0.0.1 --port 8787

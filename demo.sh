#!/usr/bin/env bash
# axiom-lsm first proof: a real process denied, then granted, on camera.
# Run: sudo bash demo.sh
set -u
cd "$(dirname "$0")"

make || exit 1
./axiom-lsm detach 2>/dev/null
./axiom-lsm attach || exit 1

./axiom-lsm audit > /tmp/axiom-audit.log 2>&1 &
AUDIT=$!
sleep 1

echo "=== petition without rights (expect PermissionError + DENY) ==="
python3 -c 'import socket; socket.socket()'
echo "  -> exit $?"

echo "=== same petition with Rights::NET (expect connect) ==="
./axiom-lsm run 0x10000 python3 -c 'import socket; s=socket.socket(); print("  -> socket() ok:", s.fileno())'

echo "=== audit events ==="
cat /tmp/axiom-audit.log

kill $AUDIT 2>/dev/null
./axiom-lsm detach
echo "=== done ==="

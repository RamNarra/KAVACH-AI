#!/bin/bash
# Script to configure local Git hooks for KAVACH AI

HOOK_DIR=".git/hooks"
PRE_PUSH_HOOK="$HOOK_DIR/pre-push"

if [ ! -d "$HOOK_DIR" ]; then
    echo "[-] Error: .git directory not found. Please run this script from the repository root."
    exit 1
fi

echo "[+] Writing pre-push hook to $PRE_PUSH_HOOK..."

cat << 'EOF' > "$PRE_PUSH_HOOK"
#!/bin/bash
# Pre-push hook to verify code before uploading to remote

echo "==============================================="
echo "Running Pre-Push Verification Check..."
echo "==============================================="

./scripts/verify_all.sh
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "[-] Verification failed! Git push aborted."
    exit 1
fi

echo "[+] Verification passed. Proceeding with push."
exit 0
EOF

chmod +x "$PRE_PUSH_HOOK"
echo "[+] Pre-push hook successfully configured and made executable!"
exit 0

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
mkdir -p "$TOOLS"

if [[ ! -x "$TOOLS/jadx/bin/jadx" ]]; then
  echo "[install] downloading jadx 1.5.0..."
  tmp="$(mktemp)"
  wget -q -O "$tmp" https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
  rm -rf "$TOOLS/jadx"
  unzip -qo "$tmp" -d "$TOOLS/jadx"
  chmod +x "$TOOLS/jadx/bin/jadx"
  rm -f "$tmp"
fi

if [[ ! -f "$TOOLS/apktool.jar" ]]; then
  echo "[install] downloading apktool 2.9.3..."
  wget -q -O "$TOOLS/apktool.jar" https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
fi

cat > "$TOOLS/apktool" <<'EOF'
#!/usr/bin/env bash
exec java -jar "$(dirname "$0")/apktool.jar" "$@"
EOF
chmod +x "$TOOLS/apktool"

echo "[install] jadx: $($TOOLS/jadx/bin/jadx --version)"
echo "[install] apktool: $($TOOLS/apktool --version)"

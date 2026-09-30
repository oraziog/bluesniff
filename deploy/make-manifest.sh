#!/usr/bin/env bash
# Genera il manifest di deploy per la macchina di test.
#
# Produce dist/manifest.json con l'hash reale della build in dist/, cosi'
# l'hash non va ricopiato a mano (ed è esattamente l'errore che l'agente è
# pensato per intercettare). Avvia anche un server HTTP per il download.
#
# Uso:
#   ./deploy/make-manifest.sh [url_base] [porta]
#
# Esempio, se la macchina di test raggiunge questa via http://REPLACE_ME:8899:
#   ./deploy/make-manifest.sh http://REPLACE_ME:8899

set -euo pipefail

cd "$(dirname "$0")/.."

URL_BASE="${1:-http://127.0.0.1:8899}"
PORT="${2:-8899}"
BIN="dist/bluesniff.exe"
MANIFEST="dist/manifest.json"

if [[ ! -f "$BIN" ]]; then
  echo "Errore: $BIN non esiste. Build prima con: cargo build --release" >&2
  exit 1
fi

# L'hash va calcolato sul file che verrà scaricato, non su un'altra copia.
HASH=$(sha256sum "$BIN" | cut -d' ' -f1)
SIZE=$(stat -c%s "$BIN" 2>/dev/null || stat -f%z "$BIN")

cat > "$MANIFEST" <<EOF
{
  "_commento": [
    "Generato da deploy/make-manifest.sh il $(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "L'hash e' calcolato sul file in dist/: non va modificato a mano."
  ],
  "url": "${URL_BASE}/bluesniff.exe",
  "sha256": "${HASH}",
  "args": ["--listen", "--dashboard"],
  "_size_bytes": ${SIZE}
}
EOF

echo "Manifest scritto: $MANIFEST"
echo "  url:   ${URL_BASE}/bluesniff.exe"
echo "  sha256: ${HASH}"
echo "  size:  ${SIZE} byte"
echo
echo "Per il download dalla macchina di test, servire il file da questa macchina:"
echo "  cd dist && python -m http.server ${PORT}"
echo
echo "Poi copiare il manifest sulla macchina di test e lanciare:"
echo "  powershell -NoProfile -ExecutionPolicy Bypass -File bluesniff-agent.ps1 -Root C:\\bluesniff-agent -Port 9100"

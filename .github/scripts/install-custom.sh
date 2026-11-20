#!/usr/bin/env bash
# Install or update the custom arm64 Tracexy build from GitHub Releases.
# Using curl avoids macOS browser com.apple.quarantine attributes on first install.
set -euo pipefail

REPO="${TRACEXY_REPO:-ymqy/Tracexy}"
INSTALL_DIR="${TRACEXY_INSTALL_DIR:-/Applications}"
APP_NAME="Tracexy.app"
DEST_APP="${INSTALL_DIR}/${APP_NAME}"
TAG=""
NO_LAUNCH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --no-launch)
      NO_LAUNCH=1
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: install-custom.sh [--tag vX.Y.Z] [--no-launch]

Installs the latest custom arm64 Tracexy release from GitHub Releases
into /Applications/Tracexy.app without browser quarantine attributes.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

ARCH="$(uname -m)"
if [ "$ARCH" != "arm64" ]; then
  echo "Error: This custom release is built for Apple Silicon (arm64) only (detected: ${ARCH})." >&2
  exit 1
fi

if [ -n "$TAG" ]; then
  API_URL="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
else
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
fi

echo "==> Querying release metadata from ${API_URL} ..."
RELEASE_JSON="$(curl -fsSL -H "Accept: application/vnd.github+json" "$API_URL")"

read -r RELEASE_TAG ZIP_NAME ZIP_URL SHA_URL < <(
  python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
tag = data.get("tag_name", "")
zip_asset = None
sha_asset = None
for a in data.get("assets", []):
    name = a.get("name", "")
    if name.endswith("-arm64.zip") and name.startswith("Tracexy-"):
        zip_asset = a
    elif name == "SHA256SUMS.txt":
        sha_asset = a
if not zip_asset:
    sys.stderr.write("Error: no Tracexy-*-arm64.zip asset found in release.\n")
    sys.exit(1)
print(tag, zip_asset["name"], zip_asset["browser_download_url"], sha_asset["browser_download_url"] if sha_asset else "-")
' <<< "$RELEASE_JSON"
)

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_PATH="${TMP_DIR}/${ZIP_NAME}"
echo "==> Downloading ${ZIP_NAME} (${RELEASE_TAG}) ..."
curl -fL --progress-bar "$ZIP_URL" -o "$ZIP_PATH"

if [ "$SHA_URL" != "-" ]; then
  echo "==> Verifying SHA-256 checksum ..."
  curl -fsSL "$SHA_URL" -o "${TMP_DIR}/SHA256SUMS.txt"
  (cd "$TMP_DIR" && shasum -a 256 -c SHA256SUMS.txt)
fi

EXTRACT_DIR="${TMP_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"
echo "==> Extracting ${ZIP_NAME} ..."
ditto -x -k "$ZIP_PATH" "$EXTRACT_DIR"

NEW_APP="${EXTRACT_DIR}/${APP_NAME}"
if [ ! -d "$NEW_APP" ]; then
  echo "Error: ${APP_NAME} not found inside archive." >&2
  exit 1
fi

echo "==> Verifying code signature ..."
codesign --verify --deep --strict "$NEW_APP"

if pgrep -x Tracexy >/dev/null 2>&1; then
  echo "==> Quitting running Tracexy ..."
  osascript -e 'tell application "Tracexy" to quit' >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -x Tracexy >/dev/null 2>&1 || break
    sleep 0.3
  done
  if pgrep -x Tracexy >/dev/null 2>&1; then
    pkill -x Tracexy >/dev/null 2>&1 || true
    sleep 0.5
  fi
fi

echo "==> Installing to ${DEST_APP} ..."
if [ -w "$INSTALL_DIR" ]; then
  rm -rf "$DEST_APP"
  ditto "$NEW_APP" "$DEST_APP"
  xattr -cr "$DEST_APP" 2>/dev/null || true
else
  sudo rm -rf "$DEST_APP"
  sudo ditto "$NEW_APP" "$DEST_APP"
  sudo xattr -cr "$DEST_APP" 2>/dev/null || true
fi

INSTALLED_VER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${DEST_APP}/Contents/Info.plist" 2>/dev/null || echo "unknown")"
INSTALLED_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "${DEST_APP}/Contents/Info.plist" 2>/dev/null || echo "?")"
echo "==> Installed Tracexy ${INSTALLED_VER} (build ${INSTALLED_BUILD}) to ${DEST_APP}."

if [ "$NO_LAUNCH" -eq 0 ]; then
  echo "==> Launching Tracexy ..."
  open "$DEST_APP"
fi

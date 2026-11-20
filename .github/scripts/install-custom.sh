#!/usr/bin/env bash
# Install or update the custom arm64 Tracexy build from GitHub Releases.
# Reads appcast.xml from github.com directly (avoids api.github.com rate limits)
# and downloads with curl (avoids browser com.apple.quarantine attributes).
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
  BASE_DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}"
else
  BASE_DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download"
fi

APPCAST_URL="${BASE_DOWNLOAD_URL}/appcast.xml"
echo "==> Reading release metadata from ${APPCAST_URL} ..."
APPCAST_XML="$(curl -fsSL "$APPCAST_URL")"

read -r VERSION BUILD ZIP_NAME ZIP_URL < <(
  python3 -c '
import os, sys, xml.etree.ElementTree as ET
from urllib.parse import urlparse

NS = {"sparkle": "http://www.andymatuschak.org/xml-namespaces/sparkle"}
root = ET.fromstring(sys.stdin.read())
item = root.find("./channel/item")
if item is None:
    sys.stderr.write("Error: no <item> found in appcast.xml.\n")
    sys.exit(1)
enclosure = item.find("enclosure")
if enclosure is None or not enclosure.get("url"):
    sys.stderr.write("Error: no enclosure download URL found in appcast.xml.\n")
    sys.exit(1)
url = enclosure.get("url")
zip_name = os.path.basename(urlparse(url).path)
version = (
    enclosure.get("{http://www.andymatuschak.org/xml-namespaces/sparkle}shortVersionString")
    or item.findtext("sparkle:shortVersionString", default="", namespaces=NS)
    or item.findtext("title", default="unknown")
).strip()
build = (
    enclosure.get("{http://www.andymatuschak.org/xml-namespaces/sparkle}version")
    or item.findtext("sparkle:version", default="?", namespaces=NS)
).strip()
print(version, build, zip_name, url)
' <<< "$APPCAST_XML"
)

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_PATH="${TMP_DIR}/${ZIP_NAME}"
echo "==> Downloading ${ZIP_NAME} (v${VERSION}, build ${BUILD}) ..."
curl -fL --progress-bar "$ZIP_URL" -o "$ZIP_PATH"

SHA_URL="${ZIP_URL%/*}/SHA256SUMS.txt"
if curl -fsSL "$SHA_URL" -o "${TMP_DIR}/SHA256SUMS.txt" 2>/dev/null; then
  echo "==> Verifying SHA-256 checksum ..."
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

#!/usr/bin/env sh
set -eu

APP_DIR="/www"
APP_FILE="img_url_probe.py"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Replace this with your GitHub raw direct URL before uploading the script.
# Example: https://raw.githubusercontent.com/user/repo/main/img_url_probe.py
DEFAULT_DOWNLOAD_URL="https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/img_url_probe.py"
DOWNLOAD_URL="${IMG_URL_PROBE_URL:-$DEFAULT_DOWNLOAD_URL}"

usage() {
  printf '%s\n' "Usage: sh install_img_url_probe.sh"
  printf '%s\n' "   or: IMG_URL_PROBE_URL=<url> sh install_img_url_probe.sh"
  printf '%s\n' "   or: sh install_img_url_probe.sh <img_url_probe.py_download_url>"
  printf '%s\n' ""
  printf '%s\n' "Example:"
  printf '%s\n' "  sh install_img_url_probe.sh https://raw.githubusercontent.com/user/repo/main/img_url_probe.py"
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "This script must be run as root. Try: sudo sh install_img_url_probe.sh <url>" >&2
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' "apt"
  elif command -v dnf >/dev/null 2>&1; then
    printf '%s\n' "dnf"
  elif command -v yum >/dev/null 2>&1; then
    printf '%s\n' "yum"
  elif command -v apk >/dev/null 2>&1; then
    printf '%s\n' "apk"
  else
    printf '%s\n' "unknown"
  fi
}

install_python() {
  if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    "$PYTHON_BIN" --version
    return
  fi

  pkg_manager="$(detect_pkg_manager)"
  case "$pkg_manager" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip ca-certificates curl
      ;;
    dnf)
      dnf install -y python3 python3-pip ca-certificates curl
      ;;
    yum)
      yum install -y python3 python3-pip ca-certificates curl
      ;;
    apk)
      apk add --no-cache python3 py3-pip ca-certificates curl
      ;;
    *)
      printf '%s\n' "Unsupported Linux distribution: package manager not found." >&2
      exit 1
      ;;
  esac
}

download_file() {
  url="$1"
  target="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fL "$url" -o "$target"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$target" "$url"
  else
    printf '%s\n' "curl/wget not found after dependency installation." >&2
    exit 1
  fi
}

validate_download_url() {
  if [ "$DOWNLOAD_URL" = "$DEFAULT_DOWNLOAD_URL" ]; then
    printf '%s\n' "Error: please replace DEFAULT_DOWNLOAD_URL with your GitHub raw URL." >&2
    exit 1
  fi

  if [ "$DOWNLOAD_URL" = "" ]; then
    usage >&2
    printf '%s\n' "Error: missing img_url_probe.py download URL." >&2
    exit 1
  fi
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  if [ "${1:-}" != "" ]; then
    DOWNLOAD_URL="$1"
  fi

  validate_download_url

  need_root
  mkdir -p "$APP_DIR"
  install_python
  download_file "$DOWNLOAD_URL" "$APP_DIR/$APP_FILE"
  chmod 0644 "$APP_DIR/$APP_FILE"

  printf '%s\n' "Installed: $APP_DIR/$APP_FILE"
  "$PYTHON_BIN" "$APP_DIR/$APP_FILE" --help >/dev/null 2>&1 || true
}

main "$@"

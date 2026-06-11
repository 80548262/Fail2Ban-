#!/usr/bin/env sh
set -eu

APP_DIR="/www"
APP_FILE="img_url_probe.py"
PYTHON_BIN="python3"

DOWNLOAD_URL="https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/img_url_probe.py"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "This script must be run as root. Try: sudo sh install_img_url_probe.sh" >&2
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
  if command -v curl >/dev/null 2>&1; then
    curl -fL "$DOWNLOAD_URL" -o "$APP_DIR/$APP_FILE"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$APP_DIR/$APP_FILE" "$DOWNLOAD_URL"
  else
    printf '%s\n' "curl/wget not found after dependency installation." >&2
    exit 1
  fi
}

main() {
  need_root
  mkdir -p "$APP_DIR"
  install_python
  download_file
  chmod 0644 "$APP_DIR/$APP_FILE"

  printf '%s\n' "Installed: $APP_DIR/$APP_FILE"
}

main

#!/usr/bin/env bash
has_command() {
  command -v "$1" >/dev/null 2>&1
}

sys_user() {
  local target_user
  target_user="${SUDO_USER:-$USER}"
  local target_uid
  target_uid=$(id -u "$target_user")
  if [ "$target_user" = "$USER" ]; then
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$target_uid}" systemctl --user "$@"
  else
    sudo -u "$target_user" env XDG_RUNTIME_DIR="/run/user/$target_uid" systemctl --user "$@"
  fi
}

hash_file() {
  local file="$1"
  if has_command sha256sum; then
    sha256sum "$file" | awk '{print $1}'
  elif has_command openssl; then
    openssl dgst -sha256 "$file" | awk '{print $2}'
  else
    echo ""
    return 1
  fi
}

check_immutable() {
  local file="$1"
  if ! has_command lsattr; then
    echo "unknown"
    return
  fi
  if lsattr -d "$file" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
    echo "yes"
  else
    echo "no"
  fi
}

extract_hash_from_json() {
  local json_file="$1"
  local key="$2"
  if [[ -f "$json_file" ]]; then
    sed -n "s/.*\"${key}\"\s*:\s*\"\([a-fA-F0-9]\{64\}\)\".*/\1/p" "$json_file" | head -n1
  else
    echo ""
  fi
}

#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

echo "[secrets-actions] Uninstalling user components (fail-first)..."
echo "[secrets-actions] Some cleanup steps require sudo."

SUDO="$(command -v sudo || true)"
SYSTEMCTL_BIN="$(command -v systemctl || true)"
SERVICE_BIN="$(command -v service || true)"
APPARMOR_PARSER_BIN="$(command -v apparmor_parser || true)"
CHATTR_BIN="$(command -v chattr || true)"

if has_command systemctl; then
  sys_user disable --now secrets-tray.service || echo "[secrets-actions] secrets-tray.service not present (ok)"
  sys_user disable --now secrets-pin-hashes.path || echo "[secrets-actions] secrets-pin-hashes.path not present (ok)"
  sys_user disable --now secrets-pin-hashes.timer || echo "[secrets-actions] secrets-pin-hashes.timer not present (ok)"
  rm -f "$HOME/.config/systemd/user/secrets-tray.service"
  rm -f "$HOME/.config/systemd/user/secrets-pin-hashes.service"
  rm -f "$HOME/.config/systemd/user/secrets-pin-hashes.path"
  rm -f "$HOME/.config/systemd/user/secrets-pin-hashes.timer"
  sys_user daemon-reload
fi

if [ -f "$HOME/.local/share/secrets-actions/pinned.json" ]; then
  PIN_FILE="$HOME/.local/share/secrets-actions/pinned.json"
  is_immutable=$(check_immutable "$PIN_FILE")

  if [ "$is_immutable" = "yes" ]; then
    if ! has_command chattr; then
      echo "[secrets-actions][WARN] pinned.json has immutable bit set, but chattr not found; deletion may fail."
    elif ! has_command sudo; then
      echo "[secrets-actions][WARN] pinned.json has immutable bit set, but sudo not found; deletion may fail."
    else
      echo "[secrets-actions] Removing immutability from pinned.json (requires sudo)"
      if ! PATH=/usr/bin:/bin "${SUDO:-sudo}" "${CHATTR_BIN:-/usr/bin/chattr}" -i "$PIN_FILE"; then
        echo "[secrets-actions][WARN] Failed to remove immutable bit; will attempt to delete anyway."
      fi
    fi
  elif [ "$is_immutable" = "no" ]; then
    echo "[secrets-actions] pinned.json immutable bit not set (ok)"
  else
    if has_command chattr && has_command sudo; then
      PATH=/usr/bin:/bin "${SUDO:-sudo}" "${CHATTR_BIN:-/usr/bin/chattr}" -i "$PIN_FILE" >/dev/null 2>&1 || true
    fi
  fi

  if ! rm -f "$PIN_FILE" 2>/dev/null; then
    echo "[secrets-actions][WARN] Failed to remove pinned.json (may still be immutable)."
    echo "[secrets-actions] Try manually: sudo chattr -i \"$PIN_FILE\" && rm -f \"$PIN_FILE\""
  else
    echo "[secrets-actions] pinned.json removed successfully"
  fi
fi

rm -f "$HOME/.local/bin/secrets-tray"
rm -rf "$HOME/.local/share/secrets-actions"
rm -rf "$HOME/.local/libexec/secrets-actions"
rm -f "$HOME/.local/state/secrets-actions.log" "$HOME/.local/state/secrets-actions.log.1" "$HOME/.local/state/secrets-actions.log.2"

if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
  rm -f "$XDG_RUNTIME_DIR/secrets-unlock.stamp"
  rm -f "$XDG_RUNTIME_DIR/secrets-tray.lock"
fi

APP_PROFILE_NAME="home.${USER}.local.bin.secrets-tray"
APP_PROFILE_PATH="/etc/apparmor.d/${APP_PROFILE_NAME}"
if [ -f "$APP_PROFILE_PATH" ]; then
  if ! has_command sudo; then
    echo "[secrets-actions][WARN] sudo not available; skipping AppArmor profile removal (${APP_PROFILE_PATH})."
  else
    if ! has_command apparmor_parser; then
      echo "[secrets-actions][WARN] apparmor_parser not found; removing file only (profile may remain loaded until reboot)."
    else
      echo "[secrets-actions] Removing AppArmor profile: ${APP_PROFILE_PATH}"
      ${SUDO:-sudo} ${APPARMOR_PARSER_BIN:-/sbin/apparmor_parser} -R "$APP_PROFILE_PATH" \
        || echo "[secrets-actions][WARN] Failed to unload AppArmor profile; continuing."
    fi
    ${SUDO:-sudo} /bin/rm -f "$APP_PROFILE_PATH" \
      || echo "[secrets-actions][WARN] Failed to delete AppArmor profile file; remove manually if needed."
    if has_command systemctl; then
      ${SUDO:-sudo} ${SYSTEMCTL_BIN:-/bin/systemctl} reload apparmor \
        || echo "[secrets-actions][WARN] Failed to reload AppArmor; profile changes may require reboot."
    else
      ${SUDO:-sudo} ${SERVICE_BIN:-/sbin/service} apparmor reload \
        || echo "[secrets-actions][WARN] Failed to reload AppArmor via service; profile changes may require reboot."
    fi
  fi
fi

echo "[secrets-actions] Uninstall complete. The repo folder remains."

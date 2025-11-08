#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

SUDO="$(command -v sudo || true)"
SYSTEMCTL_BIN="$(command -v systemctl || true)"
SERVICE_BIN="$(command -v service || true)"
APPARMOR_PARSER_BIN="$(command -v apparmor_parser || true)"
CHATTR_BIN="$(command -v chattr || true)"

cd "$ROOT_DIR"
cd build
cmake --install . --prefix "$HOME/.local"
echo "Installed to $HOME/.local."
echo "[secrets-actions] Auto-mode enabled: immutable(+i) is disabled; oneshot handles updates."

mkdir -p "$HOME/.local/share/secrets-actions"
GBIN="/usr/bin/gocryptfs"
FBIN="/usr/bin/fusermount3"
GHASH=$(hash_file "$GBIN")
FHASH=$(hash_file "$FBIN")
if [ -z "$GHASH" ] || [ -z "$FHASH" ]; then
  echo "[secrets-actions][FATAL] No hashing tool found (sha256sum or openssl). Cannot create pinned.json" >&2
  exit 1
fi
PIN_FILE="$HOME/.local/share/secrets-actions/pinned.json"

old_g=$(extract_hash_from_json "$PIN_FILE" "gocryptfs")
old_f=$(extract_hash_from_json "$PIN_FILE" "fusermount3")

if [[ "$GHASH" == "$old_g" && "$FHASH" == "$old_f" && -n "$old_g" && -n "$old_f" ]]; then
  echo "[secrets-actions] pinned.json already up to date"
else
  if [[ -f "$PIN_FILE" ]]; then
    is_immutable=$(check_immutable "$PIN_FILE")
    if [[ "$is_immutable" == "yes" ]]; then
      if [[ -n "$CHATTR_BIN" && -n "$SUDO" ]]; then
        echo "[secrets-actions] pinned.json is immutable; temporarily removing +i to update (requires sudo)"
        PATH=/usr/bin:/bin "$SUDO" "$CHATTR_BIN" -i "$PIN_FILE" || echo "[secrets-actions][WARN] Failed to remove immutable bit; update may fail."
      else
        echo "[secrets-actions][WARN] pinned.json is immutable and chattr/sudo not available; keeping existing file as-is."
        GHASH="$old_g"; FHASH="$old_f"
      fi
    fi
  fi

  if [[ "$GHASH" != "$old_g" || "$FHASH" != "$old_f" ]]; then
    tmpfile=$(mktemp)
    cat > "$tmpfile" <<EOF
{
  "schema": 1,
  "gocryptfs": "$GHASH",
  "fusermount3": "$FHASH"
}
EOF
    if [[ -L "$PIN_FILE" ]]; then
      echo "[secrets-actions][FATAL] pinned.json is a symlink; refusing to overwrite" >&2
      rm -f "$tmpfile"
      exit 1
    fi
    mv -f "$tmpfile" "$PIN_FILE" && chmod 600 "$PIN_FILE" || echo "[secrets-actions][WARN] Failed to write pinned.json"
    rm -f "$tmpfile"
    echo "Pinned hashes saved to ~/.local/share/secrets-actions/pinned.json"
  else
    echo "[secrets-actions] pinned.json left unchanged"
  fi
fi

LIBEXEC_DIR="$HOME/.local/libexec/secrets-actions"
mkdir -p "$LIBEXEC_DIR"

install -m 0644 "$SCRIPT_DIR/common.sh" "$LIBEXEC_DIR/common.sh"

cat >"$LIBEXEC_DIR/refresh_hashes.sh" <<'REFRESH_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"

PIN_FILE="$HOME/.local/share/secrets-actions/pinned.json"
GBIN="$(realpath -e /usr/bin/gocryptfs || true)"
FBIN="$(realpath -e /usr/bin/fusermount3 || true)"

mkdir -p "$(dirname "$PIN_FILE")"

if [[ -z "$GBIN" || -z "$FBIN" ]]; then
  echo "[secrets-actions][WARN] Binaries missing; skipping"
  exit 0
fi

check_bin() {
  local b="$1"
  local own ids mode
  own="$(stat -c '%U:%G' "$b")" || return 1
  ids="$(stat -c '%u:%g' "$b")" || return 1
  mode="$(stat -c '%a' "$b")" || return 1
  # Require strict root ownership (reject 65534:65534)
  if [[ "$own" != "root:root" || "$ids" != "0:0" ]]; then return 1; fi
  if [[ "$mode" != "755" && "$mode" != "4755" ]]; then return 1; fi
  return 0
}

if ! check_bin "$GBIN" || ! check_bin "$FBIN"; then
  echo "[secrets-actions][WARN] Unexpected ownership/mode on binaries; not updating pinned.json"
  echo "[secrets-actions][WARN] gocryptfs: own=$(stat -c '%U:%G' "$GBIN" 2>/dev/null || true) ids=$(stat -c '%u:%g' "$GBIN" 2>/dev/null || true) mode=$(stat -c '%a' "$GBIN" 2>/dev/null || true)"
  echo "[secrets-actions][WARN] fusermount3: own=$(stat -c '%U:%G' "$FBIN" 2>/dev/null || true) ids=$(stat -c '%u:%g' "$FBIN" 2>/dev/null || true) mode=$(stat -c '%a' "$FBIN" 2>/dev/null || true)"
  exit 0
fi

new_g="$(hash_file "$GBIN")"
new_f="$(hash_file "$FBIN")"
if [[ -z "$new_g" || -z "$new_f" ]]; then
  echo "[secrets-actions][WARN] Cannot compute hashes"
  exit 0
fi

old_g="$(extract_hash_from_json "$PIN_FILE" "gocryptfs")"
old_f="$(extract_hash_from_json "$PIN_FILE" "fusermount3")"

if [[ "$new_g" == "$old_g" && "$new_f" == "$old_f" ]]; then
  echo "[secrets-actions] pinned.json already up to date"
  exit 0
fi

echo "[secrets-actions] Updating pinned.json: gocryptfs $old_g -> $new_g; fusermount3 $old_f -> $new_f"
tmp="$(mktemp)"
cat >"$tmp" <<EOF
{
  "schema": 1,
  "gocryptfs": "$new_g",
  "fusermount3": "$new_f"
}
EOF
if [[ -L "$PIN_FILE" ]]; then
  echo "[secrets-actions][FATAL] pinned.json is a symlink; refusing to overwrite" >&2
  rm -f "$tmp"
  exit 1
fi
mv -f "$tmp" "$PIN_FILE"
chmod 600 "$PIN_FILE"
rm -f "$tmp"
echo "[secrets-actions] Updated pinned hashes"
REFRESH_SCRIPT

chmod 700 "$LIBEXEC_DIR/refresh_hashes.sh"

unit_dir="$HOME/.config/systemd/user"
mkdir -p "$unit_dir"
cat >"$unit_dir/secrets-tray.service" <<'UNIT'
[Unit]
Description=Secrets Tray
ConditionUser=!root
ConditionPathExists=/usr/bin/gocryptfs
ConditionPathExists=/usr/bin/fusermount3
Wants=secrets-pin-hashes.service
After=graphical-session.target secrets-pin-hashes.service

[Service]
Type=simple
ExecStart=%h/.local/bin/secrets-tray
# PrivateTmp=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# LockPersonality=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# RestrictRealtime=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
Environment=HOME=%h
Environment=LD_PRELOAD=
Environment=LD_LIBRARY_PATH=
Environment=PATH=/usr/bin:/bin
Environment=LANG=C
Environment=TMPDIR=%t
Environment=LC_ALL=C
PrivateMounts=no
# MemoryDenyWriteExecute=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# SystemCallArchitectures=native # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# RestrictAddressFamilies=AF_UNIX AF_NETLINK # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
IPAddressDeny=any
ProtectProc=invisible
ProcSubset=pid
# ProtectSystem=full # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# ProtectHome=read-only # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# ProtectClock=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# ProtectHostname=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# ProtectKernelLogs=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# KeyringMode=private # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# NoNewPrivileges=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
UMask=0077
LimitCORE=0
LimitMEMLOCK=infinity
WorkingDirectory=%h
RestartSec=3
StandardOutput=journal
StandardError=journal
# ReadOnlyPaths=%h/.local/share/secrets-actions/pinned.json # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# RestrictNamespaces=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
# RestrictSUIDSGID=yes # COMMENTED OUT DUE TO ISSUES WITH KDE TRAY
Restart=on-failure

[Install]
WantedBy=default.target
UNIT

cat >"$unit_dir/secrets-pin-hashes.service" <<UNIT
[Unit]
Description=Refresh pinned hashes for gocryptfs/fusermount3

[Service]
Type=oneshot
ExecStart=%h/.local/libexec/secrets-actions/refresh_hashes.sh
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/secrets-actions
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
PrivateUsers=yes
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
ProtectProc=invisible
ProcSubset=pid
SystemCallArchitectures=native
SystemCallFilter=@system-service
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RemoveIPC=yes
IPAddressDeny=any
RestrictSUIDSGID=yes
TasksMax=64
StandardOutput=journal
StandardError=journal
UNIT

cat >"$unit_dir/secrets-pin-hashes.path" <<UNIT
[Unit]
Description=Watch gocryptfs/fusermount3 for changes

[Path]
Unit=secrets-pin-hashes.service
PathChanged=/usr/bin/gocryptfs
PathModified=/usr/bin/gocryptfs
PathChanged=/usr/bin/fusermount3
PathModified=/usr/bin/fusermount3

[Install]
WantedBy=default.target
UNIT

cat >"$unit_dir/secrets-pin-hashes.timer" <<UNIT
[Unit]
Description=Daily hash refresh for gocryptfs/fusermount3

[Timer]
OnBootSec=30
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
UNIT

if has_command systemctl; then
  sys_user daemon-reload || echo "[secrets-actions][WARN] systemd --user daemon-reload failed; continuing"
  sys_user enable --now secrets-pin-hashes.path || echo "[secrets-actions] secrets-pin-hashes.path already enabled or unavailable (ok)"
  sys_user enable --now secrets-pin-hashes.timer || echo "[secrets-actions] secrets-pin-hashes.timer already enabled or unavailable (ok)"
  sys_user start secrets-pin-hashes.service || echo "[secrets-actions] secrets-pin-hashes.service start skipped/failed (ok)"
  sys_user enable --now secrets-tray.service || echo "[secrets-actions] secrets-tray.service already enabled or unavailable (ok)"
  sys_user restart secrets-tray.service || echo "[secrets-actions] secrets-tray.service restart failed (ok)"
  echo "Enabled systemd services:"
  echo "  - secrets-pin-hashes.service (one-shot refresh now)"
  echo "  - secrets-pin-hashes.path (auto-refresh on binary change)"
  echo "  - secrets-pin-hashes.timer (daily refresh)"
  echo "  - secrets-tray.service (tray app)"
else
  echo "[secrets-actions][WARN] systemctl not found; skipping user service enablement (manual start required)."
fi

APP_PROFILE_NAME="home.${USER}.local.bin.secrets-tray"
APP_PROFILE_PATH="/etc/apparmor.d/${APP_PROFILE_NAME}"
APP_BIN="$HOME/.local/bin/secrets-tray"
if has_command sudo; then
  if [ -f "$APP_BIN" ]; then
    echo "[secrets-actions] Installing AppArmor profile: ${APP_PROFILE_PATH}"
    ${SUDO:-sudo} /bin/mkdir -p /etc/apparmor.d
    ${SUDO:-sudo} /usr/bin/tee "$APP_PROFILE_PATH" >/dev/null <<EOF
#include <tunables/global>

$APP_BIN {
  #include <abstractions/base>
  #include <abstractions/kde>
  #include <abstractions/dbus-session-strict>

  /usr/bin/gocryptfs ix,
  /usr/bin/fusermount3 ix,

  deny owner @{HOME}/.local/share/secrets-actions/pinned.json w,
  owner @{HOME}/.local/share/secrets-actions/** rw,
  owner @{HOME}/.local/state/* rw,
  owner @{HOME}/.secrets-encrypted/ r,
  owner @{HOME}/.secrets-encrypted/** rw,
  owner @{HOME}/Secrets/ rw,

  /proc/self/mountinfo r,
  /proc/self/mounts r,
  /sys/devices/** r,

  deny /home/** w,
  deny network inet,
  deny network inet6,
}
EOF
    if has_command apparmor_parser; then
      ${SUDO:-sudo} ${APPARMOR_PARSER_BIN:-/sbin/apparmor_parser} -r "$APP_PROFILE_PATH" \
        || echo "[secrets-actions][WARN] Failed to (re)load AppArmor profile; it may take effect after reboot or manual load."
      if has_command systemctl; then
        ${SUDO:-sudo} ${SYSTEMCTL_BIN:-/bin/systemctl} reload apparmor \
          || echo "[secrets-actions][WARN] Failed to reload AppArmor daemon; profile may require reboot."
      else
        ${SUDO:-sudo} ${SERVICE_BIN:-/sbin/service} apparmor reload \
          || echo "[secrets-actions][WARN] Failed to reload AppArmor via service; profile may require reboot."
      fi
      echo "[secrets-actions] AppArmor profile installed."
    else
      echo "[secrets-actions][WARN] apparmor_parser not found; profile file placed but not loaded (install apparmor-utils and reload)."
    fi
  fi
else
  echo "[secrets-actions][WARN] sudo not available; skipping AppArmor profile installation."
fi

echo "[secrets-actions] Installation complete. secrets-tray should now be running."

# Secrets Tray

Secure system tray application for managing encrypted secrets using gocryptfs with hardened runtime security.

## Features

* Encrypted storage via gocryptfs integration
* Auto-lock with configurable idle timeout
* Rate-limited authentication with exponential backoff
* Binary hash pinning for trusted executables
* Memory-locked password handling with secure erasure
* TOCTOU-resistant mountpoint validation
* AppArmor MAC enforcement
* Systemd service hardening
* Screen lock and suspend integration

## Security Overview

| Component             | Category                     | Security Measures                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **secrets-tray**      | Compile-time hardening       | Stack protector (`-fstack-protector-strong`), `_FORTIFY_SOURCE=3` (with safe fallback), stack clash protection, control-flow enforcement (CET / `-fcf-protection=full`), format string hardening (`-Wformat=2`, `-Wformat-security`, `-Werror=format-security`), bounds checking, auto-var zero-init (`-ftrivial-auto-var-init=zero`), strict flex arrays (`-fstrict-flex-arrays=3`), position-independent code (PIE / `-fPIE`). |
|                       | Integer & UB safety          | Defensive integer behavior (`-fno-strict-overflow`, `-fwrapv`), null-pointer checks preserved (`-fno-delete-null-pointer-checks`), conservative use of signed arithmetic, avoids relying on undefined behavior so the compiler cannot optimize away safety checks. |
|                       | Warnings & static checks     | Wide warning sets (`-Wall`, `-Wextra`, `-Wconversion`) plus GCC/Clang-specific warnings (`-Wtrampolines`, `-Wlogical-op`, `-Wduplicated-cond`, `-Wduplicated-branches`, `-Wthread-safety`, etc.) to catch logic bugs early and enforce a "warnings as errors" policy for format-string issues. |
|                       | Link-time hardening          | Full RELRO (`-Wl,-z,relro`), immediate binding (`-Wl,-z,now`), non-executable stack (`-Wl,-z,noexecstack`), ASLR-ready PIE binary (`-pie`), restricted dynamic loading (`-Wl,-z,nodlopen`), no unnecessary DT_NEEDED entries (`-Wl,--as-needed`), link-time / interprocedural optimization (LTO/IPO) to strip dead code and reduce attack surface. |
|                       | Debug & sanitizer builds     | Dedicated debug configuration enabling AddressSanitizer and UndefinedBehaviorSanitizer (and leak detection) to find memory and UB bugs during development; clearly documented interaction with systemd hardening (e.g., `MemoryDenyWriteExecute=yes`) so debug runs stay outside the strict sandbox. |
|                       | Runtime hardening            | Global memory locking via `mlockall(MCL_CURRENT \| MCL_FUTURE)` to prevent swapping sensitive data, core dumps disabled (`RLIMIT_CORE=0`), dumpable flag cleared (`prctl(PR_SET_DUMPABLE, 0)`), explicit secret wiping (`explicit_bzero` or volatile fallback), password buffers individually `mlock()`-ed and cleared immediately after use. |
|                       | Authentication security      | Exponential backoff rate limiting (e.g. 1s → 5m → 30m → 4h → permanent lockout), persistent lockout state stored in `~/.local/state/secrets-lockout.json` (0600, non-symlink), constant-time hash comparison for password verification, atomic dialog locking to allow only one auth attempt at a time. |
|                       | Hash pinning store           | Pinned hashes in `pinned.json` with explicit schema versioning; file opened with `O_NOFOLLOW`, validated as regular file (not symlink), 0600 permissions and correct ownership, bounded size (≤1 MB) to prevent DoS, parsed with schema checks, binary hashed via file descriptor to avoid TOCTOU, constant-time comparison of expected vs actual hash. |
|                       | Binary trust verification    | Existence + executability checks, symlink rejection via `lstat`, canonical path resolution, trusted-path whitelist (`/usr/`, `/bin/`, `/sbin/`, `/usr/local/`), open with `O_NOFOLLOW \| O_CLOEXEC`, `fstat` verification of the opened fd, root ownership with user-namespace awareness (UID 0 or overflow 65534), rejection of group/world-writable binaries, hash pinning enforced before execution. |
|                       | Filesystem security          | All security-critical directories (runtime, encrypted, secrets) validated via `lstat` and `fstat`; owner must be current UID, strict permissions (0700 for dirs, 0600 for files), rejection of group/world-readable or writable paths, symlink attack prevention (`O_NOFOLLOW`), TOCTOU protection using fd-based double validation, empty-directory checks and mountpoint detection via `/proc/self/mounts` / `/proc/self/mountinfo`. |
|                       | TOCTOU & mount handling      | `openNoFollowDirFd()` + `fstat` used to keep stable directory fds across operations, re-validated just before critical use; careful parsing of mount tables (including octal-escaped paths) to detect active mountpoints, avoid double-mounts and ensure clean unmounts. |
|                       | Process isolation            | Minimal, sanitized environment for child processes; dangerous env vars removed (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`, `PYTHONPATH`, `DYLD_INSERT_LIBRARIES`, etc.), safe PATH (`/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin`), locale forced to `C`, strict spawn timeouts (5s startup, 30s runtime) with kill-on-timeout, separated stdout/stderr channels, exit status and abnormal terminations checked and logged. |
|                       | UI security                  | Password masking with no clipboard support, input method and context menu disabled for password fields, secure internal buffers with immediate clearing on dialog close, atomic dialog lock (`ScopedDialogLock`) to prevent multiple overlapping authentication prompts. |
|                       | Auto-lock & session security | Configurable idle timeout tracked via monotonic timer; automatic unmount of secrets directory on timeout; integration with screen lock and suspend events (via D-Bus `PrepareForSleep` and screensaver interfaces) to lock immediately on session lock/suspend; state updated on each unlock to minimize exposure window. |
|                       | Logging & audit              | Security-relevant events written to `~/.local/state/secrets-actions.log` with size-bounded rotation (1 MB, 2 backups); logs include timestamps and event types for auditability; optional debug mode via `SECRETS_LOG_DEBUG` for development while keeping production logs minimal; failures in critical paths recorded for later forensics. |
|                       | Desktop integration          | D-Bus sender validation (org.freedesktop.ScreenSaver, org.kde.screensaver, org.freedesktop.login1) to reject spoofed lock/unlock events, KDE integration for tray icon behavior, automatic exclusion of secrets directory from Baloo and media indexers (including `.nomedia` marker) to prevent accidental indexing of sensitive content. |
|                       | Systemd sandboxing           | `secrets-tray.service` runs as non-root (`ConditionUser=!root`), with path existence guards, environment sanitization (clears LD preload vars), full network isolation (`IPAddressDeny=any`), process hiding (`ProtectProc=invisible`, `ProcSubset=pid`), strict umask (0077), core dumps disabled (`LimitCORE=0`), unlimited memlock (`LimitMEMLOCK=infinity`). *Note: Some additional hardening options (ProtectSystem, ProtectHome, MemoryDenyWriteExecute, NoNewPrivileges, etc.) are currently disabled due to compatibility issues with KDE tray integration.* |
|                       | AppArmor confinement         | AppArmor profile denies network (inet/inet6), restricts writes in `$HOME` to secrets-related locations, treats `pinned.json` as read-only, allows only specific helper binaries (gocryptfs, fusermount3) via `ix` execution, grants only the minimal filesystem access needed for mounts, allows required D-Bus session interfaces and KDE abstractions, and permits access to `/proc/self/mountinfo`, `/proc/self/mounts`, and relevant `/sys` paths for mount and device inspection. |
| **install.sh**        | Input validation             | Verifies hashes of installed binaries using `sha256sum` with `openssl` fallback; validates schema versions before updating `pinned.json`; rejects symlinks for all security-critical paths; checks and, when necessary, temporarily drops immutability bits (`chattr -i` via sudo) before file updates. |
|                       | Safe file operations         | Uses `mktemp` for secure temp files, writes through temporary files and atomically renames with `mv` to avoid partial updates, enforces restrictive permissions (0600 for files, 0700 for scripts and dirs), validates ownership and type before modifying or replacing files. |
|                       | Systemd service deployment   | Creates systemd user units for `secrets-tray` and hash refresh: user service isolation, oneshot hash refresh service, `.path` unit to monitor binary changes, timer for daily refresh and post-boot runs; hash-refresh service runs in a tightly sandboxed environment (e.g. `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`, `PrivateUsers`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, AF_UNIX-only networking, empty capability set, syscall filter `@system-service`, restricted namespaces, protected kernel/cgroup/clock/hostname, `RestrictSUIDSGID`, `TasksMax` limit). |
|                       | AppArmor profile creation    | Generates AppArmor profile from template, validates it with `apparmor_parser`, installs via sudo, reloads AppArmor and systemd daemons to apply changes; fails early if tools are missing or if profile load fails. |
| **uninstall.sh**      | Cleanup verification         | Safely removes immutability (via `chattr -i` with sudo) before deleting files, disables and stops systemd units (`--now`) before removal, reloads systemd to ensure a clean state, unloads AppArmor profile with `apparmor_parser -R` before deleting it. |
|                       | Safe removal                 | Uses `set -euo pipefail` to fail on any unexpected condition, checks for sudo availability and degrades gracefully when some optional tools are missing, avoids blind `rm -rf` on unvalidated paths. |
| **build.sh**          | Build safety                 | Requires explicit `BUILD_TYPE` (no unsafe defaults), validates build directory is not a symlink before `rm -rf`, uses `nproc`-based parallel builds while avoiding shell injection, separates build artifacts from source tree. |
|                       | Validation                   | Verifies presence of required tools (cmake, nproc) before building, whitelists `BUILD_TYPE` (Release / Debug / RelWithDebInfo / MinSizeRel), emits clear guidance on when to use which build type and how sanitizers interact with systemd hardening. |
| **common.sh**         | Utility functions            | `hash_file()` wrapper that picks `sha256sum` or `openssl` safely, `check_immutable()` via `lsattr` to detect immutable files, JSON parsing helpers implemented with standard POSIX tools (grep/sed) to avoid extra dependencies, `sys_user()` helper to correctly invoke `systemd --user` with proper `XDG_RUNTIME_DIR`. |
| **refresh_hashes.sh** | Binary verification          | Strict validation of target binaries: `realpath -e` resolution, rejection of symlinks, enforced ownership `root:root` (UID 0: GID 0, rejecting 65534 namespace UIDs), permission whitelist (0755 or 04755), aborts if any invariant is violated before hashing. |
|                       | Update safety                | Computes new hashes to a temp file (`mktemp`) and atomically replaces `pinned.json` with `mv`, enforces restrictive permissions on updated files, validates schema before writing, avoids unnecessary updates when hashes are unchanged, logs operations for traceability and troubleshooting. |

## Installation

```bash
BUILD_TYPE=Release ./scripts/build.sh
./scripts/install.sh
```

## Build

```bash
BUILD_TYPE=Release ./scripts/build.sh
BUILD_TYPE=Debug ./scripts/build.sh
```

## Uninstall

```bash
./scripts/uninstall.sh
```

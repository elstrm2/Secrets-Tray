# Secrets Tray

Secure system tray application for managing encrypted secrets using gocryptfs with hardened runtime security.

## Features

- Encrypted storage via gocryptfs integration
- Auto-lock with configurable idle timeout
- Rate-limited authentication with exponential backoff
- Binary hash pinning for trusted executables
- Memory-locked password handling with secure erasure
- TOCTOU-resistant mountpoint validation
- AppArmor MAC enforcement
- Systemd service hardening
- Screen lock and suspend integration

## Security Overview

| Component | Category | Security Measures |
|-----------|----------|-------------------|
| **secrets-tray** | Compile-time hardening | Stack protector, FORTIFY_SOURCE=3, stack clash protection, control flow integrity (CET), format string hardening, bounds checking, auto-var initialization, strict flex arrays, position-independent code (PIE) |
| | Link-time hardening | Full RELRO, immediate binding (BIND_NOW), non-executable stack, no DT_NEEDED copy, restricted dynamic loading, LTO/IPO optimization |
| | Runtime hardening | Memory locking (mlockall), core dumps disabled (RLIMIT_CORE=0), dumpable flag cleared (PR_SET_DUMPABLE), secure password erasure (explicit_bzero), mlock for password buffers |
| | Authentication security | Exponential backoff rate limiting (1s → 5m → 30m → 4h → permanent), persistent lockout state across restarts, cryptographic hash verification (SHA-256), constant-time hash comparison, atomic dialog locking |
| | Binary trust verification | Root ownership validation, user namespace awareness (uid 0 or overflow UID 65534), trusted path whitelist (/usr/, /bin/, /sbin/), no symlink following (O_NOFOLLOW), hash pinning with schema versioning, permission checks (no group/world write) |
| | Filesystem security | Owner validation (getuid), permission enforcement (0700 dirs, 0600 files), symlink attack prevention (lstat + O_NOFOLLOW), TOCTOU protection (double validation via fd), empty directory verification, mountpoint detection via /proc |
| | Process isolation | Minimal environment variables, dangerous env vars cleared (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, etc), safe PATH, clean locale (LANG=C, LC_ALL=C), timeout enforcement (5s startup, 30s execution), separate channels for stdout/stderr |
| | UI security | Password masking, clipboard disabled, input method disabled, context menu disabled, secure buffer management, immediate memory clearing on dialog close |
| | Systemd sandboxing | Network isolation (IPAddressDeny=any), process hiding (ProtectProc=invisible, ProcSubset=pid), private mounts isolation, umask 0077, core dumps limited, memory locking allowed (LimitMEMLOCK=infinity) |
| | AppArmor confinement | Network deny (inet/inet6), write restrictions on home directory, read-only pinned.json enforcement, gocryptfs/fusermount3 execution via inherit (ix), limited filesystem access |
| | Desktop integration | D-Bus sender validation, screensaver lock integration (org.freedesktop.ScreenSaver), suspend handling (PrepareForSleep), KDE integration, Baloo indexing exclusion |
| **install.sh** | Input validation | Hash verification for binaries (sha256sum/openssl fallback), symlink detection and rejection, immutability handling (chattr -i with sudo), schema version checking |
| | Safe file operations | Atomic writes via temporary files, permission enforcement (chmod 600/700), ownership validation, mktemp for secure temp files |
| | Systemd service deployment | User service isolation, oneshot hash refresh service, path-based monitoring (.path unit), timer-based daily refresh, strict sandboxing for pin-hashes service |
| | AppArmor profile creation | Profile generation, parser validation, daemon reload, sudo-based installation |
| **uninstall.sh** | Cleanup verification | Immutability removal before deletion, service disablement (disable --now), daemon reload, AppArmor profile unload and removal |
| | Safe removal | Fail-first approach (set -euo pipefail), sudo availability checks, graceful degradation on missing tools |
| **build.sh** | Build safety | Mandatory BUILD_TYPE enforcement, symlink detection on build directory, safe rm -rf with validation, parallel build with nproc |
| | Validation | Required command checks (cmake, nproc), BUILD_TYPE whitelist (Release/Debug/RelWithDebInfo/MinSizeRel) |
| **common.sh** | Utility functions | Secure hash computation (sha256sum/openssl), immutability checking (lsattr), JSON parsing without external dependencies, systemd --user helper with proper XDG_RUNTIME_DIR handling |
| **refresh_hashes.sh** | Binary verification | Strict ownership checks (root:root, uid=0:gid=0), permission validation (755/4755), realpath resolution, hash comparison, symlink rejection |
| | Update safety | Temporary file creation with mktemp, atomic mv, permission enforcement, schema validation |

## Detailed Security Analysis

### Compile-time Security (CMakeLists.txt)

**Stack Protection:**
Stack buffer overflow protection is enforced through multiple mechanisms. The `-fstack-protector-strong` flag enables stack canaries for all functions with local buffers or references, providing runtime detection of stack smashing attacks. Additionally, `-fstack-clash-protection` mitigates stack clash attacks by ensuring the stack grows incrementally with guard pages. These mechanisms work together to detect both traditional stack buffer overflows and large stack allocation exploits.

**Memory Safety:**
Memory corruption vulnerabilities are mitigated through several compile-time features. `_FORTIFY_SOURCE=3` (with fallback to level 2) enables compile-time and runtime checks for dangerous functions like `strcpy`, `memcpy`, and `sprintf`, detecting buffer overflows before they occur. The `-ftrivial-auto-var-init=zero` flag ensures all automatic variables are zero-initialized, eliminating use-of-uninitialized-memory vulnerabilities. Strict flex arrays (`-fstrict-flex-arrays=3`) enforce proper bounds checking on flexible array members, preventing out-of-bounds access.

**Control Flow Integrity:**
Control flow hijacking attacks are prevented through hardware and software mechanisms. The `-fcf-protection=full` flag enables Intel CET (Control-flow Enforcement Technology) on supported CPUs, implementing shadow stacks and indirect branch tracking to detect ROP/JOP attacks. Format string vulnerabilities are caught at compile-time with `-Wformat=2`, `-Wformat-security`, and `-Werror=format-security`, treating any format string issue as a fatal error.

**Integer Safety:**
Integer overflow vulnerabilities are handled conservatively. The `-fno-strict-overflow` and `-fwrapv` flags ensure signed integer overflow produces well-defined wraparound behavior rather than undefined behavior that compilers might exploit. The `-fno-delete-null-pointer-checks` flag prevents optimizations that assume null pointer dereferences are impossible, maintaining defensive checks.

**Compiler Warnings:**
Comprehensive warning coverage catches potential bugs early. `-Wall`, `-Wextra`, and `-Wconversion` enable broad error detection. GCC-specific warnings (`-Wtrampolines`, `-Wlogical-op`, `-Wduplicated-cond`, `-Wduplicated-branches`) catch subtle logic errors and code duplication. Clang-specific warnings (`-Wthread-safety`, `-Wunused-exception-parameter`) improve concurrency safety and exception handling.

**Link-time Security:**
The linker applies multiple hardening flags. Full RELRO (`-Wl,-z,relro`) marks the GOT (Global Offset Table) as read-only after relocation, preventing GOT overwrite attacks. Immediate binding (`-Wl,-z,now`) resolves all symbols at program startup, eliminating lazy binding vulnerabilities. Non-executable stack (`-Wl,-z,noexecstack`) prevents code execution from the stack. The `-pie` flag creates a position-independent executable, enabling ASLR (Address Space Layout Randomization). The `-Wl,--as-needed` flag removes unnecessary library dependencies, reducing attack surface. The `-Wl,-z,nodlopen` flag prevents runtime dynamic library loading via dlopen, enforcing a fixed set of trusted libraries.

**Link-time Optimization:**
LTO/IPO (Link-Time Optimization / Interprocedural Optimization) enables whole-program optimization, allowing the compiler to inline and optimize across translation units, reducing code size and eliminating dead code that could harbor vulnerabilities.

**Position Independence:**
`CMAKE_POSITION_INDEPENDENT_CODE` and explicit `-fPIE` flags ensure the binary can be loaded at random addresses, working with kernel ASLR to make exploit development significantly harder by randomizing code and data locations.

**Debug Mode:**
Debug builds include AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) for detecting memory errors (use-after-free, buffer overflows, memory leaks) and undefined behavior (signed overflow, null pointer dereference) at runtime. A build-time informational message notes that these sanitizers are incompatible with systemd `MemoryDenyWriteExecute=yes`, so debug builds must run outside sandboxed services. The message is shown as a status notification rather than a warning to avoid noise during normal development.

### Runtime Security (main.cpp)

**Memory Locking:**
The `mlockall(MCL_CURRENT | MCL_FUTURE)` call prevents all current and future pages from being swapped to disk, ensuring sensitive data (passwords, encryption keys) never reaches persistent storage where it could be recovered. This is critical for maintaining confidentiality even if the system is physically compromised after shutdown.

**Core Dump Prevention:**
`setrlimit(RLIMIT_CORE, {0,0})` prevents core dumps from being generated on crashes. Core dumps could contain sensitive data in memory, including passwords and decrypted file contents. `prctl(PR_SET_DUMPABLE, 0)` additionally prevents ptrace attachment and /proc/self/mem access, blocking debugger-based memory inspection by unauthorized processes.

**Rate Limiting:**
Failed authentication attempts trigger exponential backoff: 3 failures = 1s delay, 6 failures = 5m, 9 failures = 30m, 12 failures = 4h, 15+ failures = permanent lockout. The lockout state is persisted to `~/.local/state/secrets-lockout.json` with 0600 permissions, surviving restarts and preventing brute-force attacks. Successful authentication clears the failure count, balancing security with usability.

**Password Handling:**
Passwords are stored in memory-locked buffers allocated via `mlock()`, preventing them from being swapped to disk. After use, passwords are erased using `explicit_bzero()` (glibc) or a volatile memory write loop (portable fallback), ensuring the compiler cannot optimize away the erasure. This prevents password recovery from memory dumps or freed heap blocks. The `SecurePasswordDialog` uses a custom `QVector<char>` buffer that is immediately cleared on dialog close.

**Binary Trust Verification:**
Before executing external binaries (gocryptfs, fusermount3, dolphin), the application performs multi-layered trust verification:

1. Existence and executability checks via `QFileInfo`
2. Symlink rejection using `lstat` to prevent symlink attacks
3. Canonicalization to resolve any path traversal or relative paths
4. Trusted path whitelist enforcement (only /usr/, /bin/, /sbin/, /usr/local/)
5. Open via `O_NOFOLLOW | O_CLOEXEC` to prevent race conditions and FD leaks
6. `fstat` validation to ensure the opened file matches expectations
7. Root ownership verification, with user namespace awareness (UID 0 or overflow UID 65534)
8. Permission checks to reject group/world-writable binaries
9. SHA-256 hash pinning with constant-time comparison to prevent timing attacks

**Hash Pinning:**
The `pinned.json` file stores SHA-256 hashes of trusted binaries with schema versioning. On verification, the pinned file itself is validated (0600 permissions, owned by user, not a symlink), opened via `O_NOFOLLOW`, read with size limits (1MB max) to prevent DoS, and parsed with schema version checking. The actual binary is hashed via file descriptor to prevent TOCTOU attacks, and the hash is compared using constant-time XOR accumulation to prevent timing side-channels that could leak hash information.

**Filesystem Security:**
All security-critical directories (runtime dir, encrypted dir, secrets dir) are validated:

1. `lstat` to detect symlinks
2. Owner verification (must be current UID)
3. Permission enforcement (0700 for directories, 0600 for files)
4. Rejection of group/world-readable or writable paths
5. File descriptor-based validation to prevent TOCTOU (Time-Of-Check-Time-Of-Use) attacks

**TOCTOU Protection:**
Mountpoint operations use double validation: first validation before user input, second validation immediately before mount using the same file descriptor. This prevents attackers from modifying the mountpoint between validation and use. The `openNoFollowDirFd()` function returns a file descriptor that is subsequently validated via `fstat`, ensuring the directory cannot be replaced with a symlink or modified during the operation.

**Mountpoint Detection:**
The application parses `/proc/self/mounts` and `/proc/self/mountinfo` to detect active mountpoints, handling octal-encoded paths (\040 for spaces) and decoding them correctly. This prevents accidental double-mounting and ensures clean unmounts.

**Process Environment Sanitization:**
Before executing external binaries, the environment is sanitized to prevent LD_PRELOAD attacks and other injection techniques. Dangerous variables are explicitly removed: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_ASSUME_KERNEL`, `GCONV_PATH`, `HOSTALIASES`, `PYTHONPATH`, `RUBYLIB`, `NODE_PATH`, `PERL5LIB`, `DYLD_INSERT_LIBRARIES`, `QT_PLUGIN_PATH`, `QT_QPA_PLATFORMTHEME`. The PATH is set to a safe default (`/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin`), and locale is set to C to avoid locale-based attacks.

**Process Execution:**
External processes are executed with strict timeouts: 5 seconds for startup, 30 seconds for completion. Processes that exceed these limits are killed to prevent DoS. Process channels are separated (stdout/stderr) to avoid output confusion attacks. Exit status is checked, and abnormal exits (crashes) are detected and logged.

**Atomic Dialog Locking:**
The `ScopedDialogLock` uses atomic compare-and-exchange (`std::atomic_bool::compare_exchange_strong`) to ensure only one password dialog is open at a time, preventing multiple concurrent authentication attempts and associated race conditions. Menu actions are disabled while dialogs are open.

**Auto-lock:**
The application tracks an autolock deadline using a monotonic timer (`QElapsedTimer`). When the deadline expires, the encrypted filesystem is automatically unmounted. The deadline is refreshed on unlock and can be configured per-user. Integration with screen savers and suspend events triggers immediate lock via D-Bus message validation.

**D-Bus Security:**
D-Bus messages for screen lock and suspend are validated by checking the sender against known service owners (org.freedesktop.ScreenSaver, org.kde.screensaver, org.freedesktop.login1). Messages from unknown senders are rejected and logged, preventing spoofed lock/unlock events.

**Logging:**
Security events are logged to `~/.local/state/secrets-actions.log` with automatic rotation (1MB max size, 2 backup files). Logs include timestamps, event types, and diagnostic information. Debug logging can be enabled via `SECRETS_LOG_DEBUG` environment variable for troubleshooting.

**Baloo Exclusion:**
The Secrets directory is automatically added to KDE Baloo's exclusion list to prevent indexing of sensitive files. A `.nomedia` file is created in the mounted directory as a secondary signal to media scanners.

### Script Security

**install.sh:**

- Validates binary hashes before pinning using sha256sum or openssl fallback
- Detects and handles immutable files (chattr -i) for updates
- Rejects symlinks to prevent symlink attack during pinned.json creation
- Creates systemd user services with maximum sandboxing for the hash refresh service
- Installs AppArmor profile with network deny and filesystem restrictions
- Uses atomic file operations (temporary file + mv) for safe updates
- Enforces strict permissions (0600 for files, 0700 for scripts)
- Generates oneshot service, path watcher, and timer for automated hash updates

**uninstall.sh:**

- Removes immutability bit before deletion (chattr -i with sudo)
- Disables systemd services before removal (--now flag for immediate stop)
- Unloads AppArmor profile via apparmor_parser -R
- Performs daemon reloads to ensure clean state
- Uses fail-first approach (set -euo pipefail) for error detection

**build.sh:**

- Enforces BUILD_TYPE environment variable (no default to prevent accidents)
- Validates BUILD_TYPE against whitelist (Release, Debug, RelWithDebInfo, MinSizeRel)
- Detects symlink attacks on build directory before rm -rf
- Checks for required commands (cmake, nproc) before proceeding
- Provides clear guidance for production vs debug builds
- Warns about sanitizer incompatibility with systemd hardening

**common.sh:**

- Provides hash_file() with automatic tool detection (sha256sum/openssl)
- Implements check_immutable() using lsattr for immutability detection
- Provides extract_hash_from_json() without external dependencies (pure sed/grep)
- Implements sys_user() for correct systemd --user invocation with XDG_RUNTIME_DIR

**refresh_hashes.sh:**

- Validates binary ownership and permissions before hashing
- Uses realpath -e for symlink resolution and existence verification
- Requires strict root:root ownership (rejects 65534:65534 from user namespaces)
- Enforces permission whitelist (755 or 4755 for setuid)
- Compares old and new hashes to avoid unnecessary updates
- Uses atomic file operations (mktemp + mv) for safe updates
- Logs all operations for audit trail

### Systemd Hardening

**secrets-tray.service:**

- `ConditionUser=!root` prevents running as root
- `ConditionPathExists` ensures dependencies are present before start
- `Environment` sanitization clears LD_PRELOAD and LD_LIBRARY_PATH
- `IPAddressDeny=any` blocks all network access
- `ProtectProc=invisible` hides other users' processes
- `ProcSubset=pid` restricts /proc access to PID information only
- `UMask=0077` ensures all created files are user-private
- `LimitCORE=0` prevents core dumps
- `LimitMEMLOCK=infinity` allows mlockall for password protection
- Many protections commented out due to KDE tray integration issues

**secrets-pin-hashes.service:**

- `Type=oneshot` for one-time execution
- `ProtectSystem=strict` makes entire filesystem read-only except allowed paths
- `ProtectHome=read-only` prevents home directory modification except allowed paths
- `ReadWritePaths` explicitly allows only pinned.json updates
- `PrivateTmp=yes`, `PrivateDevices=yes` isolate /tmp and /dev
- `PrivateUsers=yes` isolates user namespace
- `NoNewPrivileges=yes` prevents privilege escalation
- `MemoryDenyWriteExecute=yes` prevents JIT attacks
- `RestrictAddressFamilies=AF_UNIX` allows only local IPC
- `CapabilityBoundingSet=` drops all capabilities
- `SystemCallFilter=@system-service` whitelists only safe syscalls
- `ProtectControlGroups`, `ProtectKernelModules`, `ProtectKernelTunables` protect kernel interfaces
- `ProtectClock`, `ProtectHostname` prevent time/hostname changes
- `LockPersonality` prevents personality syscall abuse
- `RestrictRealtime`, `RestrictNamespaces` prevent advanced attacks
- `RestrictSUIDSGID` prevents setuid/setgid file creation
- `TasksMax=64` limits process creation for DoS prevention

**secrets-pin-hashes.path:**

- Monitors /usr/bin/gocryptfs and /usr/bin/fusermount3 for changes
- Triggers hash refresh service on modification
- Provides real-time protection against binary replacement attacks

**secrets-pin-hashes.timer:**

- Runs hash refresh 30 seconds after boot
- Re-runs daily (OnUnitActiveSec=1d)
- Persistent=true ensures missed runs execute on next boot
- Provides defense-in-depth against stale hash detection

### AppArmor Confinement

The AppArmor profile restricts secrets-tray to:

- Execute gocryptfs and fusermount3 with profile inheritance (ix)
- Read/write secrets-related directories only
- Deny writes to pinned.json (read-only enforcement)
- Deny network access (inet/inet6)
- Deny writes to home directory outside allowed paths
- Allow KDE abstractions for tray integration
- Allow D-Bus session for desktop integration
- Allow /proc/self/mountinfo and /proc/self/mounts for mountpoint detection
- Allow /sys/devices for device enumeration

## Installation

```bash
BUILD_TYPE=Release ./scripts/build.sh
./scripts/install.sh
```

## Build

```bash
# Production build
BUILD_TYPE=Release ./scripts/build.sh

# Debug build with sanitizers
BUILD_TYPE=Debug ./scripts/build.sh
```

## Uninstall

```bash
./scripts/uninstall.sh
```

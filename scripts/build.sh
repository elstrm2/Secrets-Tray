#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in cmake nproc; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "[build.sh][FATAL] Missing required command: $cmd" >&2
		exit 1
	fi
done

if [[ -z "${BUILD_TYPE:-}" ]]; then
	cat >&2 <<-'EOF'
	[build.sh][FATAL] BUILD_TYPE environment variable not set.
	
	Usage:
	  BUILD_TYPE=Release ./scripts/build.sh    # Production build (recommended)
	  BUILD_TYPE=Debug ./scripts/build.sh      # Debug build with sanitizers
	
	Example:
	  BUILD_TYPE=Release ./scripts/build.sh
	EOF
	exit 1
fi

case "$BUILD_TYPE" in
	Release|Debug|RelWithDebInfo|MinSizeRel)
		;;
	*)
		echo "[build.sh][FATAL] Invalid BUILD_TYPE='$BUILD_TYPE'" >&2
		echo "[build.sh] Allowed: Release, Debug, RelWithDebInfo, MinSizeRel" >&2
		exit 1
		;;
esac

echo "[build.sh] Build type: $BUILD_TYPE"

if [[ -L build ]]; then
	echo "[build.sh][FATAL] 'build' is a symlink; aborting to avoid unsafe rm -rf" >&2
	exit 1
fi

rm -rf build
mkdir -p build
cd build

echo "[build.sh] Configuring..."
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..

echo "[build.sh] Building..."
if cmake --build . -j"${NPROC:-$(nproc)}"; then
	echo "[build.sh] ✓ Build complete"
	echo "[build.sh] Binary: $ROOT_DIR/build/secrets-tray"
	if [[ "$BUILD_TYPE" == "Release" ]]; then
		echo "[build.sh] Production build ready. Install with:"
		echo "[build.sh]   ./scripts/install.sh"
	elif [[ "$BUILD_TYPE" == "Debug" ]]; then
		echo "[build.sh] WARNING: Debug build includes sanitizers."
		echo "[build.sh] Do NOT run under systemd with MemoryDenyWriteExecute=yes"
	fi
else
	echo "[build.sh][FATAL] Build failed" >&2
	exit 1
fi
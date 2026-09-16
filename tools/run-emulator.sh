#!/usr/bin/env bash
#
# Stage CMake build artifacts for the Vela emulator, then invoke the upstream
# emulator.sh. Intended for out-of-tree (--cmake) builds whose outputs live
# under cmake_out/vela_<config>/ instead of nuttx/.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
TOP_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BOARD="vela"
CONFIG="goldfish-arm64-v8a-ap"

usage() {
  cat <<EOF
Usage: $(basename "$0") [config] [emulator options...]

Stage cmake_out/vela_<config>/ artifacts into nuttx/, then run emulator.sh.

Examples:
  $(basename "$0")
  $(basename "$0") -no-window
  $(basename "$0") goldfish-arm64-v8a-ap -no-window
  $(basename "$0") goldfish-armeabi-v7a-ap -keep my-dev -no-window

Build first:
  ./build.sh vendor/openvela/boards/vela/configs/<config>/ --cmake -j\$(nproc)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 0 && "${1}" != -* ]]; then
  CONFIG="$1"
  shift
fi

OUT="${TOP_DIR}/cmake_out/vela_${CONFIG}"
NUTTX_DIR="${TOP_DIR}/nuttx"
ARTIFACTS=(nuttx nuttx.bin vela_data.bin vela_system.bin)

if [[ ! -d "${OUT}" ]]; then
  echo "Build output not found: ${OUT}" >&2
  echo "Build with:" >&2
  echo "  ./build.sh vendor/openvela/boards/vela/configs/${CONFIG}/ --cmake -j\$(nproc)" >&2
  exit 1
fi

missing=()
for artifact in "${ARTIFACTS[@]}"; do
  if [[ ! -e "${OUT}/${artifact}" ]]; then
    missing+=("${artifact}")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing artifacts in ${OUT}: ${missing[*]}" >&2
  exit 1
fi

mkdir -p "${NUTTX_DIR}"
for artifact in "${ARTIFACTS[@]}"; do
  ln -sf "../cmake_out/vela_${CONFIG}/${artifact}" "${NUTTX_DIR}/${artifact}"
done

echo "Staged emulator artifacts from cmake_out/vela_${CONFIG}/"
exec "${TOP_DIR}/emulator.sh" "${BOARD}" "$@"

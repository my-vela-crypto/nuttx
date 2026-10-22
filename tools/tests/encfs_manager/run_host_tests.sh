#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
nuttx_dir=$(cd -- "$test_dir/../../.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/encfs-manager.XXXXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT

host_cc=${HOSTCC:-cc}
flags=(-std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -g -pthread)
if [[ ${ENCFS_MANAGER_SANITIZERS:-address,undefined} != none ]]; then
  flags+=("-fsanitize=${ENCFS_MANAGER_SANITIZERS:-address,undefined}")
fi

# -idirafter keeps the host standard headers ahead of NuttX libc headers.
# The shims substitute only the external board/VFS/driver dependencies.
"$host_cc" "${flags[@]}" -I"$test_dir/shim" -idirafter "$nuttx_dir/include" \
  "$test_dir/test_manager.c" \
  "$nuttx_dir/fs/encfs/encfs_manager.c" \
  "$nuttx_dir/fs/encfs/encfs_key.c" \
  "$nuttx_dir/fs/encfs/encfs_block_port.c" \
  -o "$build_dir/test_manager"

# LeakSanitizer cannot run under ptrace-based sandboxes. There is no dynamic
# allocation in this test. Users can override ASAN_OPTIONS in a normal shell.
ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0} \
UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1} \
  "$build_dir/test_manager"

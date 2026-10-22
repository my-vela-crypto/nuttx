# EncFS manager lifecycle tests

From any working directory on a POSIX host with a C compiler and pthreads:

```sh
nuttx/tools/tests/encfs_manager/run_host_tests.sh
```

The runner compiles the production `encfs_manager.c`, `encfs_key.c`, and
`encfs_block_port.c` with warnings treated as errors, AddressSanitizer, and
UndefinedBehaviorSanitizer. It reads the real public API headers. The checked-in
shims provide a host configuration and replace external board, block-device,
key-slot, and VFS dependencies with an observable model. HKDF itself is stubbed
to check the exact 32-byte input/output lengths, ASCII salts without their NUL,
and empty info. This suite tests orchestration and rollback, not cryptographic
correctness or real filesystem I/O; `../encfs_crypto` and the Guest acceptance
program cover those separately.

The cases exercise absent and invalid keys; every one-shot startup failpoint;
retry after failure; repeated start and stop; runtime key replacement refusal;
busy file/directory unmount behavior; failed upper authentication; the VFS path
where bind succeeds but publication fails; lower-unmount and block-unregister
cleanup errors; retrying cleanup without reporting false STOPPED; and explicit
provisioning versus a normal start on an unformatted volume. Upper target
reservation is checked for allocation failure and an existing foreign mount.

The test creates only a temporary host executable and never accesses a real
block device. It has no network dependencies. `HOSTCC` selects a host compiler.
`ENCFS_MANAGER_SANITIZERS=undefined` selects UBSan only, and
`ENCFS_MANAGER_SANITIZERS=none` disables sanitizers. Leak detection is disabled
by default because ptrace-based sandboxes cannot run LeakSanitizer; the test
performs no dynamic allocations. Set `ASAN_OPTIONS=detect_leaks=1` to override
that default outside such a sandbox.

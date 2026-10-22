# EncFS cryptographic primitive tests

Run from any directory with Python 3.9+ and a host C compiler:

```sh
python3 nuttx/tools/tests/encfs_crypto/test_crypto.py
```

The runner compiles the production `aes_siv.c`, `hkdf.c`, AES, CMAC, HMAC,
SHA-256, SHA-1, and MD5 sources into a temporary library. The temporary
headers only supply NuttX configuration, `FAR`, and endian helpers needed
to use the host C library. It does not substitute the primitives under test.
Compiler warnings are errors (except a pre-existing declaration ordering
warning in `sha2.c`), and UndefinedBehaviorSanitizer is enabled.

The tests cover:

- RFC 5297 appendix A.1 encrypt and decrypt.
- RFC 5869 appendix A.1, A.2, and A.3 for SHA-256.
- 675 plaintext/AD length combinations, including empty messages, AES block
  boundaries, a 140-byte filename, and long multi-block inputs.
- Independent differential comparisons with OpenSSL 3 AES-128-SIV, when the
  host provides it. OpenSSL rejects empty messages; a fixed independently
  generated CMAC reference checks the empty-message case.
- Determinism, wrong keys, wrong AD, tag/ciphertext tampering, plaintext
  clearing on failed authentication, and overlapping text buffers.
- Invalid pointers, short ciphertext, output size overflow, NULL empty
  inputs, and HKDF output lengths up to the RFC limit of 8160 bytes.

The AES-SIV public interface deliberately accepts exactly one AD string,
including a zero-length AD. RFC 5297 A.2 uses three AD strings, so it is
outside that public interface. OpenSSL differential tests cover both S2V
branches and multi-block CTR through the actual single-AD interface.

`ENCFS_CRYPTO_SANITIZERS=address,undefined` additionally enables ASan; its
runtime must be loaded before Python (for example with `LD_PRELOAD` pointing
to the compiler's `libasan.so`). Disable leak detection for that run because
the process includes the uninstrumented Python interpreter and OpenSSL.
The runner creates no persistent build files and requires no network access.

## Block driver lifecycle tests

```sh
python3 nuttx/tools/tests/encfs_crypto/test_blkcrypt.py
```

This separate runner compiles the production block driver, unchanged XTS
algorithm, and AES implementation with ASan and UBSan. Its host shim supplies
an inode namespace with a reader/writer lock, real pthread mutexes, a small
memory disk, fault injection, and heap/reference accounting.

It verifies busy key replacement through both public and ioctl interfaces,
busy unlink and unregister, preservation of an existing key after invalid
input or allocation failure, failed parent opens/closes, first-key ioctl,
idle unlink, and exact release of driver memory and parent references.
Two worker threads perform 10000 open/read/close cycles while another thread
attempts 2000 unregister/re-register cycles. Busy unregister must keep the
namespace visible; successful unregister must release it exactly once.

LeakSanitizer is disabled because it cannot inspect threads under the desktop
sandbox's process monitor. Explicit checks assert that no driver allocation
or inode reference remains. Full Guest filesystem tests are still necessary
to validate the real VFS integration.

## VFS publication and FatFs failure tests

```sh
python3 nuttx/tools/tests/encfs_crypto/test_vfs_lifecycle.py
```

This runner extracts the current production function bodies verbatim and
compiles them with ASan and UBSan against small OS/backend fault stubs. It
checks `nx_mount` publication after a target was removed, replaced, or
claimed during bind; normal and failed bind; and separate release of the
lookup and filesystem-owned block references during rollback.

FatFs checks cover FIL synchronization, window/bitmap/FSInfo dirty flags,
directory open/close accounting and failed-close retry, busy files and
directories, inode references held by callbacks, device flush errors,
unmount failure, retained resource state, and successful cleanup retry.
The tests isolate these wrapper contracts; the full Guest build remains
the test of actual VFS, FatFs, and block driver integration.

The wrapper cannot safely flush a dirty volume window or allocation bitmap
left by a failed directory operation because the third-party FatFs core's
volume synchronization routine is private. If FIL synchronization leaves
such state dirty, `syncfs` and unmount return `-EIO` and retain the mount.
This deliberately reports the unsynchronized state instead of returning
success after only flushing the block device. No third-party core files
are changed by this behavior.

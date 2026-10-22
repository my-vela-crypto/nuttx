# encpathfs host checks

Run from the workspace root with a host C compiler and Python 3.10 or later:

```sh
python3 nuttx/tools/tests/encpathfs/test_encpathfs.py
```

The test compiles the actual `encpathfs_codec.c`, `encpathfs_path.c`, AES-SIV,
AES and CMAC sources into a temporary shared library. It uses undefined
behavior sanitization by default and treats compiler warnings as errors.
`CC` selects the compiler; `ENCPATHFS_SANITIZERS` selects sanitizers supported
by that compiler and the Python process loading the shared library.

There are 6,073 deterministic assertions:

- 512 randomized authenticated name round trips covering every logical
  length from 1 through 128 bytes.
- Exact physical length and uppercase unpadded Base32hex checks.
- Tag and ciphertext changes, incorrect keys, invalid characters, lowercase
  encoding, and noncanonical unused trailing bits.
- Input/output limits, including 128 logical bytes becoming 234 physical
  bytes, rejection of 129-byte names, and capacity reserved for the NUL.
- Root, repeated slash and dot handling; rejection of root escape and
  missing/non-directory components before `..`; physical path expansion.

Only allocation and the inode/stat boundary are replaced for the path
tests. The stat stub reports names `missing` and `file` as a missing entry
and a regular file, respectively; other valid paths are directories. These
checks do not replace NuttX compilation or Guest filesystem tests and do
not exercise lower inode ownership, actual FAT directory entries, I/O
failure recovery, or concurrency. AES-SIV algorithm/reference tests live
in the separate `tools/tests/encfs_crypto` runner.

Expected result:

```text
PASS codec: 6052 assertions; 512 random round trips, lengths 1..128,
     authentication, canonical encoding and buffer boundaries
PASS paths: 21 assertions; dot/dotdot, missing/non-directory paths,
     root escape, repeated slashes and encrypted path expansion
PASS encpathfs: 6073 assertions, sanitizers clean
```

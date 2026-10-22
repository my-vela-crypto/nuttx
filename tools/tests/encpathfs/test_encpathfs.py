#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host checks of the actual encrypted-name codec and path implementation."""

import base64
import ctypes as C
import errno
import os
from pathlib import Path
import random
import subprocess
import tempfile


NUTTX = Path(__file__).resolve().parents[3]
CHECKS = 0


def check(condition, description):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(description)


def compile_library(directory):
    inc = directory / "include"
    (inc / "nuttx/fs").mkdir(parents=True)
    (inc / "nuttx/config.h").write_text("#define CONFIG_CRYPTO 1\n")
    (inc / "nuttx/compiler.h").write_text("#define FAR\n")
    (inc / "nuttx/crypto").symlink_to(NUTTX / "include/nuttx/crypto")
    (inc / "crypto").symlink_to(NUTTX / "include/crypto")
    (inc / "nuttx/fs/encpathfs.h").symlink_to(
        NUTTX / "include/nuttx/fs/encpathfs.h")

    # Only the inode/stat boundary and allocator are substituted for the
    # host.  Codec, path, AES-SIV, AES and CMAC are compiled from real sources.
    # The 1024-byte path limit matches the dedicated demonstration config.
    host = directory / "host.h"
    host.write_text("""#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <nuttx/fs/encpathfs.h>
#undef PATH_MAX
#define PATH_MAX 1024
#define swap32 __builtin_bswap32
#define swap64 __builtin_bswap64
#define __FS_ENCPATHFS_ENCPATHFS_H
#define ENCPATHFS_ROOT ".p"
#define fs_heap_malloc malloc
#define fs_heap_free free
struct inode;
struct mountpt_operations
{
  int (*stat)(struct inode *, const char *, struct stat *);
};
struct inode
{
  union { const struct mountpt_operations *i_mops; } u;
};
struct encpathfs_mount_s
{
  struct inode *lower;
  uint8_t key[32];
};
void encpathfs_erase(void *, size_t);
int encpathfs_path(struct encpathfs_mount_s *, const char *, char **, char **);
""")

    harness = directory / "harness.c"
    harness.write_text("""#include <string.h>
#include <errno.h>

static uint8_t g_key[32];

static int fake_stat(struct inode *node, const char *path, struct stat *st)
{
  const char *p = path;
  char component[235];
  char name[129];
  size_t length;

  (void)node;
  memset(st, 0, sizeof(*st));
  st->st_mode = S_IFDIR | 0700;
  if (strncmp(p, ".p", 2))
    {
      return -EINVAL;
    }

  p += 2;
  while (*p)
    {
      if (*p++ != '/')
        {
          return -EINVAL;
        }

      length = strcspn(p, "/");
      if (length > 234)
        {
          return -ENAMETOOLONG;
        }

      memcpy(component, p, length);
      component[length] = 0;
      if (encpathfs_decode_name(g_key, component, name, sizeof(name)))
        {
          return -EBADMSG;
        }

      if (!strcmp(name, "missing"))
        {
          return -ENOENT;
        }

      if (!strcmp(name, "file"))
        {
          if (p[length])
            {
              return -ENOTDIR;
            }

          st->st_mode = S_IFREG | 0600;
        }

      p += length;
    }

  return 0;
}

int harness_path(const uint8_t *key, const char *input,
                 char *physical, char *logical)
{
  struct mountpt_operations ops = {fake_stat};
  struct inode node = {.u.i_mops = &ops};
  struct encpathfs_mount_s mount = {.lower = &node};
  char *path = NULL;
  char *normal = NULL;
  int ret;

  memcpy(mount.key, key, 32);
  memcpy(g_key, key, 32);
  ret = encpathfs_path(&mount, input, &path, &normal);
  if (ret == 0)
    {
      strcpy(physical, path);
      strcpy(logical, normal);
    }

  free(path);
  free(normal);
  return ret;
}
""")

    output = directory / "encpathfs.so"
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-g", "-shared",
        "-fPIC", "-Wall", "-Wextra", "-Werror", "-Wno-old-style-declaration",
        "-fsanitize=" + os.environ.get("ENCPATHFS_SANITIZERS", "undefined"),
        "-fno-sanitize-recover=all", "-include", str(host), "-I", str(inc),
        "-o", str(output),
        *[str(NUTTX / "crypto" / source) for source in
          ("aes_siv.c", "aes.c", "cmac.c")],
        str(NUTTX / "fs/encpathfs/encpathfs_codec.c"),
        str(NUTTX / "fs/encpathfs/encpathfs_path.c"), str(harness),
    ], check=True)

    library = C.CDLL(str(output))
    for name in ("encpathfs_encode_name", "encpathfs_decode_name"):
        function = getattr(library, name)
        function.argtypes = [C.c_void_p, C.c_char_p, C.c_void_p, C.c_size_t]
        function.restype = C.c_int
    library.harness_path.argtypes = [C.c_void_p, C.c_char_p,
                                    C.c_void_p, C.c_void_p]
    library.harness_path.restype = C.c_int
    return library


def codec_tests(library):
    rng = random.Random(81259)
    alphabet = bytes(value for value in range(32, 127) if value != 47)
    base32 = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"

    for length in range(1, 129):
        for _ in range(4):
            key = rng.randbytes(32)
            name = bytes(rng.choice(alphabet) for _ in range(length))
            if name in (b".", b".."):
                name = b"X" * length
            output = C.create_string_buffer(235)
            decoded = C.create_string_buffer(129)
            check(library.encpathfs_encode_name(key, name, output, 235) == 0,
                  "encode success")
            encoded = output.value
            check(len(encoded) == 3 + ((length + 16) * 8 + 4) // 5,
                  "physical component length")
            check(encoded.startswith(b"E1_") and
                  all(value in base32 for value in encoded[3:]),
                  "uppercase Base32hex alphabet")
            check(library.encpathfs_decode_name(key, encoded, decoded, 129)
                  == 0 and decoded.value == name, "authenticated round trip")
            check(library.encpathfs_encode_name(key, name, output,
                                                len(encoded)) ==
                  -errno.ENAMETOOLONG, "encode capacity includes NUL")
            check(library.encpathfs_decode_name(key, encoded, decoded,
                                                length) ==
                  -errno.ENAMETOOLONG, "decode capacity includes NUL")
            wrong_key = bytes(value ^ 0x80 for value in key)
            check(library.encpathfs_decode_name(wrong_key, encoded, decoded,
                                                129) == -errno.EBADMSG and
                  decoded.value == b"", "wrong key exposes no plaintext")

            raw = bytearray(base64.b32hexdecode(
                encoded[3:] + b"=" * ((-(len(encoded) - 3)) % 8)))
            for index in (0, 15, len(raw) - 1):
                changed = raw.copy()
                changed[index] ^= 1
                tampered = b"E1_" + base64.b32hexencode(changed).rstrip(b"=")
                check(library.encpathfs_decode_name(key, tampered, decoded,
                                                    129) == -errno.EBADMSG
                      and decoded.value == b"", "tag/ciphertext corruption")
            check(library.encpathfs_decode_name(key, encoded.lower(),
                                                decoded, 129) ==
                  -errno.EBADMSG, "lowercase encoding rejected")
            if ((length + 16) * 8) % 5:
                value = base32.index(encoded[-1])
                malformed = encoded[:-1] + bytes([base32[value | 1]])
                check(library.encpathfs_decode_name(key, malformed, decoded,
                                                    129) == -errno.EBADMSG,
                      "nonzero unused trailing bits rejected")

    key = bytes(32)
    output = C.create_string_buffer(235)
    for name in (b"", b".", b"..", b"a/b", b"\x01", b"\xff"):
        check(library.encpathfs_encode_name(key, name, output, 235) ==
              -errno.EINVAL, "invalid/unsupported logical name rejected")
    check(library.encpathfs_encode_name(key, b"a" * 129, output, 235) ==
          -errno.ENAMETOOLONG, "129-byte logical name rejected")
    check(library.encpathfs_encode_name(key, b"a" * 128, output, 235) == 0
          and len(output.value) == 234, "128-byte boundary maps to 234 bytes")
    print("PASS codec: 6052 assertions; 512 random round trips, lengths 1..128,")
    print("     authentication, canonical encoding and buffer boundaries")


def path_tests(library):
    def path_check(path, expected, normal=None):
        physical = C.create_string_buffer(1024)
        logical = C.create_string_buffer(1024)
        result = library.harness_path(bytes(32), path, physical, logical)
        check(result == expected and (normal is None or logical.value == normal),
              "path result: " + repr(path))

    for path in (b"", b"/", b".", b"./", b"////"):
        path_check(path, 0, b"")
    for path in (b"..", b"../file", b"dir/../../file", b"//../dir"):
        path_check(path, -errno.EPERM)
    path_check(b"dir//child", 0, b"dir/child")
    path_check(b"dir/./child", 0, b"dir/child")
    path_check(b"dir/../child", 0, b"child")
    path_check(b"missing/../child", -errno.ENOENT)
    path_check(b"file/../child", -errno.ENOTDIR)
    path_check(b"file/./child", -errno.ENOTDIR)
    path_check(b"file/", -errno.ENOTDIR)
    path_check(b"dir/", 0, b"dir")
    path_check(b"file/.", -errno.ENOTDIR)
    path_check(b"a" * 129, -errno.ENAMETOOLONG)
    path_check(b"/".join([b"a" * 128] * 5), -errno.ENAMETOOLONG)
    normal = b"/".join([b"a" * 128] * 4)
    path_check(normal, 0, normal)
    print("PASS paths: 21 assertions; dot/dotdot, missing/non-directory paths,")
    print("     root escape, repeated slashes and encrypted path expansion")


def main():
    with tempfile.TemporaryDirectory(prefix="encpathfs-test-") as temporary:
        library = compile_library(Path(temporary))
        codec_tests(library)
        path_tests(library)
    print("PASS encpathfs: " + str(CHECKS) + " assertions, sanitizers clean")


if __name__ == "__main__":
    main()

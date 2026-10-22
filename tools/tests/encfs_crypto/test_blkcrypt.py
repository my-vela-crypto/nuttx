#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise production blkcrypt lifecycle with a host inode-tree shim."""

import os
from pathlib import Path
import subprocess
import tempfile


NUTTX = Path(__file__).resolve().parents[3]
TESTDIR = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix="blkcrypt-lifecycle-") as tmp:
        root = Path(tmp)
        inc = root / "include"
        (inc / "nuttx/fs").mkdir(parents=True)
        (inc / "crypto").symlink_to(NUTTX / "include/crypto")
        (inc / "nuttx/crypto").symlink_to(NUTTX / "include/nuttx/crypto")
        (inc / "nuttx/config.h").write_text(
            "#define CONFIG_CRYPTO_SW_AES 1\n#define CONFIG_FS_NOTIFY 1\n")
        (inc / "nuttx/compiler.h").write_text("#define FAR\n")
        (inc / "debug.h").write_text("#define ferr(...) ((void)0)\n")
        (inc / "nuttx/atomic.h").write_text(
            "#define atomic_read(p) __atomic_load_n(p, __ATOMIC_RELAXED)\n")
        (inc / "nuttx/mutex.h").write_text(
            "#include <pthread.h>\ntypedef pthread_mutex_t mutex_t;\n"
            "static inline int nxmutex_init(mutex_t *p) "
            "{return -pthread_mutex_init(p, NULL);}\n"
            "static inline int nxmutex_destroy(mutex_t *p) "
            "{return -pthread_mutex_destroy(p);}\n"
            "static inline int nxmutex_lock(mutex_t *p) "
            "{return -pthread_mutex_lock(p);}\n"
            "static inline int nxmutex_unlock(mutex_t *p) "
            "{return -pthread_mutex_unlock(p);}\n")
        (inc / "nuttx/kmalloc.h").write_text(
            "#include <stddef.h>\nvoid *test_zalloc(size_t);\n"
            "void *test_memalign(size_t, size_t);\nvoid test_free(void *);\n"
            "#define kmm_zalloc test_zalloc\n#define kmm_memalign test_memalign\n"
            "#define kmm_free test_free\n")
        (inc / "nuttx/fs/ioctl.h").write_text(
            "#define DIOC_SETKEY 1\n#define BIOC_XIPBASE 2\n")
        (inc / "nuttx/fs/fs.h").write_text("""
#ifndef HOST_FS_H
#define HOST_FS_H
#include <stdbool.h>
#include <sys/types.h>
struct inode;
struct geometry
{
  bool geo_available;
  unsigned int geo_sectorsize;
  blkcnt_t geo_nsectors;
};
struct block_operations
{
  int (*open)(struct inode *);
  int (*close)(struct inode *);
  ssize_t (*read)(struct inode *, unsigned char *, blkcnt_t, unsigned int);
  ssize_t (*write)(struct inode *, const unsigned char *, blkcnt_t,
                   unsigned int);
  int (*geometry)(struct inode *, struct geometry *);
  int (*ioctl)(struct inode *, int, unsigned long);
  int (*unlink)(struct inode *);
};
struct inode
{
  union {const struct block_operations *i_bops;} u;
  void *i_private;
  int i_crefs;
};
int find_blockdriver(const char *, int, struct inode **);
int register_blockdriver(const char *, const struct block_operations *,
                          mode_t, void *);
#endif
""")
        prelude = root / "host.h"
        prelude.write_text("#include <stdint.h>\n#define FAR\n#define OK 0\n")
        binary = root / "test_blkcrypt"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-pthread",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-include", str(prelude), "-I", str(inc),
            '-DTEST_BLKCRYPT_SOURCE="' + str(NUTTX / "drivers/crypto/blkcrypt.c")
            + '"', "-o", str(binary), str(TESTDIR / "test_blkcrypt.c"),
            str(NUTTX / "drivers/crypto/blkcrypt_xts.c"),
            str(NUTTX / "crypto/aes.c"),
        ], check=True)
        env = os.environ.copy()
        # LeakSanitizer cannot inspect threads under the desktop sandbox's
        # ptrace monitor. The harness separately asserts zero driver heap
        # allocations and exact final inode reference counts.
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        subprocess.run([str(binary)], check=True, env=env)


if __name__ == "__main__":
    main()

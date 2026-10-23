#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual VFS directory read/seek bodies under ASan and UBSan.

Only surrounding inode/directory types and backend callbacks are replaced.
The authenticated backend model consumes a physical entry before rejecting it,
as encpathfs does when a filename's authentication fails.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def function(source, name):
    match = re.search(
        r"static (?:off_t|ssize_t) " + name + r"\([^;]*?\)\s*\{", source)
    if match is None:
        raise AssertionError("production function not found: " + name)
    begin, pos = match.start(), match.end()
    depth = 1
    while depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    return source[begin:pos] + "\n"


PRELUDE = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define FAR
#define INODE_IS_MOUNTPT(node) ((node)->mountpoint)

struct dirent {char d_name[32];};
struct inode;
struct fs_dirent_s {struct inode *fd_root;};
struct mountpt_operations
{
  int (*rewinddir)(struct inode *, struct fs_dirent_s *);
  int (*readdir)(struct inode *, struct fs_dirent_s *, struct dirent *);
};
struct inode
{
  bool mountpoint;
  union {struct mountpt_operations *i_mops;} u;
};
struct file {void *f_priv; off_t f_pos;};

/* The tests exercise mounted directories only.  These unrelated pseudo-FS
 * backends make an unexpected dispatch fail immediately.
 */

static int read_pseudodir(struct fs_dirent_s *dir, struct dirent *entry)
{
  (void)dir; (void)entry; assert(false); return -ENOSYS;
}

static off_t seek_pseudodir(struct file *filep, off_t offset)
{
  (void)filep; (void)offset; assert(false); return -ENOSYS;
}

static int g_records[8];
static unsigned int g_length;
static unsigned int g_physical;
static unsigned int g_reads;
static unsigned int g_rewinds;
static unsigned int g_pass;
static unsigned int g_fail;
static int g_rewind_error;
static struct mountpt_operations g_ops;
static struct inode g_inode;
static struct fs_dirent_s g_dir;
static struct file g_file;

static int backend_readdir(struct inode *inode, struct fs_dirent_s *dir,
                           struct dirent *entry)
{
  int ret;

  assert(inode == &g_inode && dir == &g_dir);
  ++g_reads;
  if (g_physical == g_length)
    {
      return -ENOENT;
    }

  ret = g_records[g_physical++];
  if (ret < 0)
    {
      return ret;
    }

  snprintf(entry->d_name, sizeof(entry->d_name), "entry-%u", g_physical);
  return 0;
}

static int backend_rewinddir(struct inode *inode, struct fs_dirent_s *dir)
{
  assert(inode == &g_inode && dir == &g_dir);
  ++g_rewinds;
  if (g_rewind_error < 0)
    {
      return g_rewind_error;
    }

  g_physical = 0;
  return 0;
}

static void reset(unsigned int length)
{
  assert(length <= sizeof(g_records) / sizeof(g_records[0]));
  memset(g_records, 0, sizeof(g_records));
  g_length = length;
  g_physical = g_reads = g_rewinds = 0;
  g_rewind_error = 0;
  g_ops.readdir = backend_readdir;
  g_ops.rewinddir = backend_rewinddir;
  g_inode.mountpoint = true;
  g_inode.u.i_mops = &g_ops;
  g_dir.fd_root = &g_inode;
  g_file.f_priv = &g_dir;
  g_file.f_pos = 0;
}

#define CHECK(label, expression) do \
  { \
    if (expression) \
      { \
        ++g_pass; \
        printf("[PASS] %s\n", label); \
      } \
    else \
      { \
        ++g_fail; \
        printf("[FAIL] %s\n", label); \
      } \
  } while (0)
"""


TEST = r"""
int main(void)
{
  struct dirent entry;
  ssize_t count;
  off_t position;

  setvbuf(stdout, NULL, _IONBF, 0);

  reset(1);
  g_records[0] = -EBADMSG;
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("authentication error consumes backend entry at logical zero",
        count == -EBADMSG && g_physical == 1 && g_file.f_pos == 0);
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("rewind at logical zero reaches the backend",
        position == 0 && g_rewinds == 1 && g_physical == 0);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("rewound authenticated entry is rejected again",
        count == -EBADMSG && g_physical == 1 && g_file.f_pos == 0);

  reset(0);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("empty directory EOF leaves logical zero",
        count == 0 && g_file.f_pos == 0);
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("rewind after zero-position EOF reaches the backend",
        position == 0 && g_rewinds == 1);

  reset(2);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("first valid entry advances logical position",
        count == sizeof(entry) && g_file.f_pos == 1 && g_physical == 1);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("second valid entry advances logical position",
        count == sizeof(entry) && g_file.f_pos == 2 && g_physical == 2);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("nonempty directory EOF preserves logical position",
        count == 0 && g_file.f_pos == 2);
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("rewind after nonempty EOF resets both positions",
        position == 0 && g_file.f_pos == 0 && g_physical == 0 &&
        g_rewinds == 1);
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("entry is readable again after EOF rewind",
        count == sizeof(entry) && strcmp(entry.d_name, "entry-1") == 0);

  reset(5);
  position = dir_seek(&g_file, 3, SEEK_SET);
  CHECK("ordinary forward seek reads entries without rewind",
        position == 3 && g_file.f_pos == 3 && g_physical == 3 &&
        g_reads == 3 && g_rewinds == 0);
  position = dir_seek(&g_file, 1, SEEK_SET);
  CHECK("ordinary backward seek rewinds and scans to target",
        position == 1 && g_file.f_pos == 1 && g_physical == 1 &&
        g_reads == 4 && g_rewinds == 1);
  position = dir_seek(&g_file, 1, SEEK_SET);
  CHECK("same nonzero seek preserves backend position",
        position == 1 && g_physical == 1 && g_reads == 4 && g_rewinds == 1);
  position = dir_seek(&g_file, 4, SEEK_SET);
  CHECK("subsequent forward seek continues from current position",
        position == 4 && g_file.f_pos == 4 && g_physical == 4 &&
        g_reads == 7 && g_rewinds == 1);
  position = dir_seek(&g_file, 0, SEEK_CUR);
  CHECK("SEEK_CUR reports logical position without moving backend",
        position == 4 && g_file.f_pos == 4 && g_physical == 4 &&
        g_reads == 7 && g_rewinds == 1);

  reset(2);
  g_records[0] = -EBADMSG;
  count = dir_read(&g_file, (char *)&entry, sizeof(entry));
  CHECK("prepare failed first read for rewind fault",
        count == -EBADMSG && g_file.f_pos == 0 && g_physical == 1);
  g_rewind_error = -EIO;
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("zero-position rewind propagates backend error",
        position == -EIO && g_file.f_pos == 0 && g_physical == 1 &&
        g_rewinds == 1 && g_reads == 1);
  g_rewind_error = 0;
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("zero-position rewind can retry after backend error",
        position == 0 && g_file.f_pos == 0 && g_physical == 0 &&
        g_rewinds == 2);

  reset(3);
  position = dir_seek(&g_file, 2, SEEK_SET);
  CHECK("prepare nonzero position for rewind fault", position == 2);
  g_rewind_error = -EIO;
  position = dir_seek(&g_file, 1, SEEK_SET);
  CHECK("backward rewind error preserves positions and skips no entries",
        position == -EIO && g_file.f_pos == 2 && g_physical == 2 &&
        g_rewinds == 1 && g_reads == 2);

  reset(1);
  g_ops.rewinddir = NULL;
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("missing rewind backend at zero returns ENOTSUP",
        position == -ENOTSUP && g_file.f_pos == 0 && g_reads == 0);
  position = dir_seek(&g_file, 1, SEEK_SET);
  CHECK("missing rewind backend permits a forward scan",
        position == 1 && g_file.f_pos == 1 && g_physical == 1);
  position = dir_seek(&g_file, 0, SEEK_SET);
  CHECK("missing rewind backend for backward seek returns ENOTSUP",
        position == -ENOTSUP && g_file.f_pos == 1 && g_physical == 1);

  printf("DIRECTORY_REWIND_RESULT pass=%u fail=%u\n", g_pass, g_fail);
  return g_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
"""


def main():
    source = (ROOT / "fs/vfs/fs_dir.c").read_text()
    functions = "\n".join(function(source, name) for name in [
        "seek_mountptdir", "dir_read", "dir_seek",
    ])
    with tempfile.TemporaryDirectory(prefix="encfs-directory-rewind-") as tmp:
        cfile = Path(tmp) / "directory_rewind.c"
        binary = Path(tmp) / "directory_rewind"
        cfile.write_text(PRELUDE + functions + TEST)
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-fno-pie", "-no-pie", str(cfile), "-o", str(binary),
        ], check=True)
        env = os.environ.copy()
        # LeakSanitizer cannot inspect this sandbox's process monitor.  The
        # harness is allocation-free; ASan bounds and UBSan remain enabled.
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        subprocess.run([str(binary)], check=True, env=env)


if __name__ == "__main__":
    main()

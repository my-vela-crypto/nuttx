#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check current VFS publication and FatFs lifecycle function bodies.

Extract the production functions verbatim; supply only their surrounding
OS/backend types and fault-injection stubs in a small host harness.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def function(path, name):
    source = path.read_text()
    match = re.search(r"(?:static )?int " + name + r"\([^;]*?\)\s*\{", source)
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


COMMON = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define FAR
#define OK 0
#define DEBUGASSERT assert
#define ferr(...) ((void)0)
#define finfo(...) ((void)0)
"""


MOUNT_PRELUDE = COMMON + r"""
#define BDFS_SUPPORT 1
#define NODFS_SUPPORT
struct inode;
struct mountpt_operations
{
  int (*bind)(struct inode *, const void *, void **);
  int (*unbind)(void *, struct inode **, unsigned int);
};
struct inode
{
  int refs;
  int type;
  union {const struct mountpt_operations *i_mops;} u;
  void *i_private;
};
struct inode_search_s {struct inode *node; const char *relpath;};
struct fsmap_t {int dummy;};
static struct fsmap_t g_bdfsmap[1], g_nonbdfsmap[1];
static struct inode g_driver = {.refs = 1};
static struct inode g_target, g_other;
static struct inode *g_visible;
static struct inode *g_bound_driver;
static bool g_locked;
static int g_mode, g_bind_calls, g_unbind_calls;
static int g_private;
#define SETUP_SEARCH(d,p,n) memset(d,0,sizeof(*(d)))
#define RELEASE_SEARCH(d) ((void)0)
#define INODE_IS_PSEUDODIR(i) ((i)->type == 0)
#define INODE_SET_MOUNTPT(i) ((i)->type = 1)
#define atomic_add(p,n) (*(p) += (n))
#define atomic_sub(p,n) (*(p) -= (n))
#define i_crefs refs
static void inode_lock(void) {assert(!g_locked); g_locked=true;}
static void inode_unlock(void) {assert(g_locked); g_locked=false;}
static void inode_release(struct inode *n) {assert(n->refs>0); --n->refs;}
static int inode_find(struct inode_search_s *d)
{
  assert(g_locked);
  if (!g_visible) return -ENOENT;
  d->node=g_visible; d->relpath=""; ++g_visible->refs; return 0;
}
static int inode_search(struct inode_search_s *d)
{
  assert(g_locked);
  if (!g_visible) return -ENOENT;
  d->node=g_visible; d->relpath=""; return 0;
}
static int inode_reserve_path(const char *p, int mode, struct inode **n)
{
  (void)p; (void)mode; assert(g_locked);
  if (g_visible) return -EEXIST;
  g_target.refs=1; g_target.type=0; g_visible=&g_target; *n=&g_target;
  return 0;
}
static int find_blockdriver(const char *p, unsigned long f, struct inode **n)
{
  (void)p; (void)f; *n=&g_driver; ++g_driver.refs; return 0;
}
static int find_mtddriver(const char *p, struct inode **n)
{(void)p; (void)n; return -ENOENT;}
static int test_bind(struct inode *d, const void *data, void **out)
{
  (void)data; assert(!g_locked); ++g_bind_calls;
  if (g_mode==4) return -EIO;
  g_bound_driver=d; *out=&g_private;
  if (g_mode==1) {--g_target.refs; g_visible=NULL;}
  if (g_mode==2) {--g_target.refs; g_visible=&g_other;}
  if (g_mode==3) {g_target.type=1; g_target.i_private=&g_other;}
  return 0;
}
static int test_unbind(void *h, struct inode **d, unsigned int f)
{
  (void)f; assert(g_locked); assert(h==&g_private); ++g_unbind_calls;
  *d=g_bound_driver; g_bound_driver=NULL; return 0;
}
static const struct mountpt_operations g_ops={test_bind,test_unbind};
static const struct mountpt_operations *mount_findfs(struct fsmap_t *m,
                                                     const char *name)
{(void)m; (void)name; return &g_ops;}
"""


MOUNT_TEST = r"""
int main(void)
{
  int mode;
  for (mode=0; mode<=4; ++mode)
    {
      g_mode=mode; g_bind_calls=g_unbind_calls=0;
      memset(&g_target,0,sizeof(g_target)); g_target.refs=1;
      memset(&g_other,0,sizeof(g_other)); g_other.refs=1;
      g_visible=&g_target; g_driver.refs=1;
      int ret=nx_mount("/dev/test","/target","testfs",0,NULL);
      assert(!g_locked && g_bind_calls==1);
      if (mode==0)
        {
          assert(ret==0 && g_target.refs==1 && g_driver.refs==2);
          assert(g_target.i_private==&g_private && g_unbind_calls==0);
        }
      else if (mode==4)
        {
          assert(ret==-EIO && g_unbind_calls==0);
          assert(g_target.refs==1 && g_driver.refs==1);
        }
      else
        {
          assert(ret==(mode==1?-ENOENT:-EBUSY));
          assert(g_unbind_calls==1 && g_driver.refs==1);
          if (mode==3)
            assert(g_target.refs==1 && g_target.i_private==&g_other);
          else
            assert(g_target.refs==0);
          if (mode==2) assert(g_visible==&g_other && g_other.refs==1);
        }
    }
  puts("PASS production nx_mount: normal/failed bind, deleted/replaced/claimed");
  puts("     target, and exact lookup/bound-driver rollback reference release");
  return 0;
}
"""


FAT_PRELUDE = COMMON + r"""
#define FF_FS_EXFAT 1
#define FS_FAT32 3
#define CTRL_SYNC 0
#define RES_OK 0
typedef int mutex_t;
struct fs_dirent_s {int reserved;};
struct fatfs_dir_s {struct fs_dirent_s base; int dir;};
struct fatfs_file_s {struct fatfs_file_s *next; int f;};
struct fatfs_mountpt_s
{
  struct {int wflag,fs_type,fsi_flag,bitdirty;} fat;
  int pdrv,lock,nb;
  struct fatfs_file_s *files;
  unsigned int dirs;
};
struct mountpt_operations;
struct inode;
struct block_operations {int (*close)(struct inode *);};
struct inode
{
  int i_crefs,type;
  union {const struct mountpt_operations *i_mops;
         const struct block_operations *i_bops;} u;
  void *i_private;
};
struct mountpt_operations {int dummy;};
static const struct mountpt_operations g_fatfs_operations={0};
static struct inode g_inode,g_driver;
static int g_fsync_result,g_device_result,g_unmount_result;
static int g_unmount_calls,g_device_calls,g_fsync_calls,g_close_calls;
static int g_free_slot_calls,g_frees,g_foreach_error;
static int g_opendir_result,g_closedir_result,g_dir_frees;
static bool g_is_published;
static struct fatfs_mountpt_s *g_fs;
#define INODE_IS_MOUNTPT(i) ((i)->type==1)
#define atomic_read(p) (*(p))
static int nxmutex_lock(mutex_t *p) {assert(*p==0); *p=1; return 0;}
static int nxmutex_unlock(mutex_t *p) {assert(*p==1); *p=0; return 0;}
static void nxmutex_destroy(mutex_t *p) {assert(*p==0);}
static int f_sync(int *f)
{(void)f; assert(g_fs->lock); ++g_fsync_calls; return g_fsync_result;}
static int fatfs_convert_result(int r) {return r;}
static int disk_ioctl(int d,int c,void *p)
{(void)d;(void)c;(void)p;assert(g_fs->lock);++g_device_calls;
 return g_device_result;}
static int f_unmount(const char *p)
{(void)p;assert(g_fs->lock);++g_unmount_calls;return g_unmount_result;}
static struct inode *fatfs_free_slot(int d)
{(void)d;++g_free_slot_calls;return &g_driver;}
static void unregister_reboot_notifier(int *n) {(void)n;}
static void *fs_heap_malloc(size_t s) {void *p=malloc(s);assert(p);return p;}
static void fs_heap_free(void *p)
{if(p==g_fs)++g_frees;else{++g_dir_frees;free(p);}}
static int f_opendir(int *d,const char *p)
{(void)d;(void)p;assert(g_fs->lock);return g_opendir_result;}
static int f_closedir(int *d)
{(void)d;assert(g_fs->lock);return g_closedir_result;}
static int test_close(struct inode *d) {(void)d;++g_close_calls;return 0;}
static const struct block_operations g_bops={test_close};
static int foreach_inode(int (*f)(struct inode *,char *,void *),void *arg)
{
  if (g_foreach_error) return g_foreach_error;
  return g_is_published?f(&g_inode,NULL,arg):0;
}
"""


FAT_TEST = r"""
int main(void)
{
  struct fatfs_mountpt_s fs={0};
  struct fatfs_file_s fil={0};
  struct fs_dirent_s *dir=NULL;
  struct inode *driver=NULL;
  g_fs=&fs; g_inode.i_private=&fs; g_inode.type=1; g_inode.i_crefs=2;
  g_inode.u.i_mops=&g_fatfs_operations; g_driver.u.i_bops=&g_bops;
  g_is_published=true;
  g_opendir_result=-EIO;
  assert(fatfs_opendir(&g_inode,"",&dir)==-EIO && fs.dirs==0);
  assert(g_dir_frees==1);
  g_opendir_result=0;
  assert(fatfs_opendir(&g_inode,"",&dir)==0 && fs.dirs==1);
  g_closedir_result=-EIO;
  assert(fatfs_closedir(&g_inode,dir)==-EIO && fs.dirs==1);
  assert(g_dir_frees==1);
  assert(fatfs_unbind(&fs,&driver,0)==-EBUSY);
  g_closedir_result=0;
  assert(fatfs_closedir(&g_inode,dir)==0 && fs.dirs==0);
  assert(g_dir_frees==2);
  assert(fatfs_syncfs(&g_inode)==0 && g_device_calls==1);
  fs.files=&fil;
  assert(fatfs_syncfs(&g_inode)==0 && g_fsync_calls==1);
  g_fsync_result=-EIO;
  assert(fatfs_syncfs(&g_inode)==-EIO && fs.lock==0);
  g_fsync_result=0; fs.files=NULL;
  fs.fat.wflag=1;
  assert(fatfs_syncfs(&g_inode)==-EIO);
  assert(fatfs_unbind(&fs,&driver,0)==-EIO && g_unmount_calls==0);
  fs.fat.wflag=0;fs.fat.bitdirty=1;
  assert(fatfs_syncfs(&g_inode)==-EIO);
  fs.fat.bitdirty=0;fs.fat.fs_type=FS_FAT32;fs.fat.fsi_flag=1;
  assert(fatfs_syncfs(&g_inode)==-EIO);
  fs.fat.fsi_flag=0x81;
  assert(fatfs_syncfs(&g_inode)==0);
  fs.fat.fs_type=4;fs.fat.fsi_flag=1;
  assert(fatfs_syncfs(&g_inode)==0);
  fs.files=&fil;
  assert(fatfs_unbind(&fs,&driver,0)==-EBUSY && g_unmount_calls==0);
  fs.files=NULL;fs.dirs=1;
  assert(fatfs_unbind(&fs,&driver,0)==-EBUSY && g_unmount_calls==0);
  fs.dirs=0;g_inode.i_crefs=3;
  assert(fatfs_unbind(&fs,&driver,0)==-EBUSY && g_unmount_calls==0);
  g_inode.i_crefs=2;g_foreach_error=-ENOMEM;
  assert(fatfs_unbind(&fs,&driver,0)==-ENOMEM && g_unmount_calls==0);
  g_foreach_error=0;g_device_result=1;
  assert(fatfs_unbind(&fs,&driver,0)==-EIO && g_unmount_calls==0);
  g_device_result=0;g_unmount_result=-EIO;
  assert(fatfs_unbind(&fs,&driver,0)==-EIO && g_frees==0);
  assert(driver==NULL && g_free_slot_calls==0 && fs.lock==0);
  g_unmount_result=0;
  assert(fatfs_unbind(&fs,&driver,0)==0);
  assert(driver==&g_driver && g_free_slot_calls==1 && g_frees==1);
  assert(g_close_calls==1 && fs.lock==0);
  puts("PASS production FatFs syncfs/unbind: FIL sync, dirty window/bitmap/FSInfo,");
  puts("     busy files/directories/in-flight refs, failed flush/unmount, retry");
  return 0;
}
"""


def main():
    mount = function(ROOT / "fs/mount/fs_mount.c", "nx_mount")
    fatpath = ROOT / "fs/fatfs/fatfs_vfs.c"
    fat = "\n".join(function(fatpath, name) for name in [
        "fatfs_syncfs_locked", "fatfs_syncfs", "fatfs_opendir", "fatfs_closedir",
        "fatfs_check_refs", "fatfs_unbind",
    ])
    with tempfile.TemporaryDirectory(prefix="encfs-vfs-tests-") as tmp:
        for name, source in [
            ("mount", MOUNT_PRELUDE + mount + MOUNT_TEST),
            ("fatfs", FAT_PRELUDE + fat + FAT_TEST),
        ]:
            cfile = Path(tmp) / (name + ".c")
            binary = Path(tmp) / name
            cfile.write_text(source)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11",
                            "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter", "-O1", "-g",
                            "-fsanitize=address,undefined",
                            "-fno-sanitize-recover=all", str(cfile),
                            "-o", str(binary)], check=True)
            env = os.environ.copy()
            env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
            subprocess.run([str(binary)], check=True, env=env)


if __name__ == "__main__":
    main()

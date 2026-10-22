/****************************************************************************
 * fs/encpathfs/encpathfs.h
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef __FS_ENCPATHFS_ENCPATHFS_H
#define __FS_ENCPATHFS_ENCPATHFS_H

#include <nuttx/config.h>
#include <nuttx/fs/fs.h>
#include <nuttx/fs/encpathfs.h>
#include <nuttx/mutex.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <stdbool.h>
#include <limits.h>

#include "fs_heap.h"

#define ENCPATHFS_ROOT ".p"
#define ENCPATHFS_META ".encfs.meta"

struct encpathfs_file_s;
struct encpathfs_dir_s;

/* All lower operations run under this lock.  Lower file/dir objects are
 * constructed directly and never exposed to the public inode namespace.
 */

struct encpathfs_mount_s
{
  FAR struct inode *lower;
  mutex_t lock;
  unsigned int files;
  unsigned int dirs;
  uint8_t key[ENCPATHFS_KEY_SIZE];
  FAR struct encpathfs_file_s *head;
  FAR struct encpathfs_dir_s *dhead;
};

struct encpathfs_file_s
{
  struct file lower;
  FAR struct encpathfs_mount_s *mount;
  FAR char *logical;
  FAR struct encpathfs_file_s *next;
  FAR struct inode *orphan_inode;
};

struct encpathfs_dir_s
{
  struct fs_dirent_s base;
  FAR struct fs_dirent_s *lower;
  FAR struct encpathfs_dir_s *next;
  bool orphan;
};

void encpathfs_erase(FAR void *memory, size_t length);
int encpathfs_path(FAR struct encpathfs_mount_s *mount,
                  FAR const char *relative, FAR char **physical,
                  FAR char **logical);
int encpathfs_flush(FAR struct encpathfs_mount_s *mount);
int encpathfs_bind(FAR struct inode *blkdriver, FAR const void *data,
                  FAR void **handle);
int encpathfs_unbind(FAR void *handle, FAR struct inode **blkdriver,
                    unsigned int flags);
int encpathfs_statfs(FAR struct inode *inode, FAR struct statfs *buf);
int encpathfs_syncfs(FAR struct inode *inode);

int encpathfs_open(FAR struct file *filep, FAR const char *path,
                  int oflags, mode_t mode);
int encpathfs_close(FAR struct file *filep);
ssize_t encpathfs_read(FAR struct file *filep, FAR char *buffer,
                      size_t length);
ssize_t encpathfs_write(FAR struct file *filep, FAR const char *buffer,
                       size_t length);
off_t encpathfs_seek(FAR struct file *filep, off_t offset, int whence);
int encpathfs_ioctl(FAR struct file *filep, int cmd, unsigned long arg);
int encpathfs_sync(FAR struct file *filep);
int encpathfs_dup(FAR const struct file *oldp, FAR struct file *newp);
int encpathfs_fstat(FAR const struct file *filep, FAR struct stat *buf);
int encpathfs_fchstat(FAR const struct file *filep,
                     FAR const struct stat *buf, int flags);
int encpathfs_truncate(FAR struct file *filep, off_t length);

int encpathfs_opendir(FAR struct inode *inode, FAR const char *path,
                     FAR struct fs_dirent_s **dir);
int encpathfs_closedir(FAR struct inode *inode, FAR struct fs_dirent_s *dir);
int encpathfs_readdir(FAR struct inode *inode, FAR struct fs_dirent_s *dir,
                     FAR struct dirent *entry);
int encpathfs_rewinddir(FAR struct inode *inode, FAR struct fs_dirent_s *dir);
int encpathfs_unlink(FAR struct inode *inode, FAR const char *path);
int encpathfs_mkdir(FAR struct inode *inode, FAR const char *path,
                   mode_t mode);
int encpathfs_rmdir(FAR struct inode *inode, FAR const char *path);
int encpathfs_rename(FAR struct inode *inode, FAR const char *oldpath,
                    FAR const char *newpath);
int encpathfs_stat(FAR struct inode *inode, FAR const char *path,
                  FAR struct stat *buf);
int encpathfs_chstat(FAR struct inode *inode, FAR const char *path,
                    FAR const struct stat *buf, int flags);

#endif /* __FS_ENCPATHFS_ENCPATHFS_H */

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __ENCFS_TEST_FS_H
#define __ENCFS_TEST_FS_H
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
struct mountpt_operations
{
  int unused;
};
struct inode
{
  bool pseudo;
  bool mounted;
  ino_t i_ino;
  union
  {
    const struct mountpt_operations *i_mops;
  } u;
  void *i_private;
};
#define INODE_IS_PSEUDODIR(inode) ((inode)->pseudo)
#define INODE_IS_MOUNTPT(inode) ((inode)->mounted)
int nx_mount(const char *source, const char *target, const char *filesystem,
             unsigned long flags, const void *data);
int nx_umount2(const char *target, unsigned int flags);
int nx_stat(const char *path, struct stat *st, int resolve);
#endif

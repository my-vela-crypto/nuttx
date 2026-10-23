/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __ENCFS_TEST_INODE_H
#define __ENCFS_TEST_INODE_H
#include <nuttx/fs/fs.h>
struct inode_search_s
{
  struct inode *node;
  const char *path;
  const char *relpath;
};
#define SETUP_SEARCH(desc, p, follow) \
  do \
    { \
      (desc)->node = NULL; \
      (desc)->path = (p); \
      (desc)->relpath = ""; \
    } \
  while (0)
#define RELEASE_SEARCH(desc) ((void)(desc))
void inode_lock(void);
void inode_unlock(void);
int inode_find(struct inode_search_s *desc);
int inode_search(struct inode_search_s *desc);
void inode_release(struct inode *inode);
int inode_reserve_path(const char *path, mode_t mode, struct inode **inode);
#endif

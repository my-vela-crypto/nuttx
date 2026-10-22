/****************************************************************************
 * fs/encpathfs/encpathfs_dir.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <nuttx/config.h>
#include <errno.h>
#include <string.h>
#include "encpathfs.h"

int encpathfs_opendir(FAR struct inode *inode, FAR const char *path,
                     FAR struct fs_dirent_s **dir)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR struct encpathfs_dir_s *priv;
  FAR char *physical = NULL;
  int ret;

  priv = fs_heap_zalloc(sizeof(*priv));
  if (priv == NULL)
    {
      return -ENOMEM;
    }

  ret = nxmutex_lock(&mount->lock);
  if (ret >= 0)
    {
      ret = encpathfs_path(mount, path, &physical, NULL);
      if (ret >= 0)
        {
          ret = mount->lower->u.i_mops->opendir(mount->lower, physical,
                                               &priv->lower);
        }

      if (ret >= 0)
        {
          priv->next = mount->dhead;
          mount->dhead = priv;
          mount->dirs++;
          *dir = &priv->base;
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  if (ret < 0)
    {
      fs_heap_free(priv);
    }

  return ret;
}

int encpathfs_closedir(FAR struct inode *inode, FAR struct fs_dirent_s *dir)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR struct encpathfs_dir_s *priv = (FAR struct encpathfs_dir_s *)dir;
  FAR struct encpathfs_dir_s **link;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->closedir(mount->lower, priv->lower);
      mount->dirs--;
      if (ret < 0)
        {
          /* VFS releases its directory wrapper and inode reference even
           * when the lower close fails.  Preserve the lower object until
           * syncfs or unbind can finish closing it.
           */

          priv->orphan = true;
          nxmutex_unlock(&mount->lock);
          return ret;
        }

      for (link = &mount->dhead; *link != priv; link = &(*link)->next)
        {
        }

      *link = priv->next;
      nxmutex_unlock(&mount->lock);
      fs_heap_free(priv);
    }

  return ret;
}

int encpathfs_readdir(FAR struct inode *inode, FAR struct fs_dirent_s *dir,
                     FAR struct dirent *entry)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR struct encpathfs_dir_s *priv = (FAR struct encpathfs_dir_s *)dir;
  struct dirent lower_entry;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      do
        {
          memset(&lower_entry, 0, sizeof(lower_entry));
          ret = mount->lower->u.i_mops->readdir(mount->lower, priv->lower,
                                               &lower_entry);
        }
      while (ret >= 0 && (!strcmp(lower_entry.d_name, ".") ||
                          !strcmp(lower_entry.d_name, "..")));

      if (ret >= 0)
        {
          ret = encpathfs_decode_name(mount->key, lower_entry.d_name,
                                      entry->d_name, sizeof(entry->d_name));
          if (ret >= 0)
            {
              entry->d_type = lower_entry.d_type;
            }
        }

      nxmutex_unlock(&mount->lock);
    }

  if (ret < 0)
    {
      entry->d_name[0] = '\0';
    }

  return ret;
}

int encpathfs_rewinddir(FAR struct inode *inode, FAR struct fs_dirent_s *dir)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR struct encpathfs_dir_s *priv = (FAR struct encpathfs_dir_s *)dir;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->rewinddir(mount->lower, priv->lower);
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_unlink(FAR struct inode *inode, FAR const char *path)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *physical = NULL;
  struct stat st;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_path(mount, path, &physical, NULL);
      if (ret >= 0)
        {
          if (!strcmp(physical, ENCPATHFS_ROOT))
            {
              ret = -EBUSY;
            }
          else
            {
              ret = mount->lower->u.i_mops->stat(mount->lower, physical, &st);
              if (ret >= 0)
                {
                  ret = S_ISDIR(st.st_mode) ? -EISDIR :
                        mount->lower->u.i_mops->unlink(mount->lower,
                                                        physical);
                }
            }
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  return ret;
}

int encpathfs_mkdir(FAR struct inode *inode, FAR const char *path, mode_t mode)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *physical = NULL;
  FAR char *trimmed;
  size_t length;
  int ret;

  if (path == NULL)
    {
      return -EINVAL;
    }

  length = strnlen(path, PATH_MAX);
  if (length == PATH_MAX)
    {
      return -ENAMETOOLONG;
    }

  while (length > 0 && path[length - 1] == '/')
    {
      length--;
    }

  /* A trailing slash is legal when creating a new directory; the shared
   * path helper requires existing directories for other trailing slashes.
   */

  trimmed = fs_heap_strndup(path, length);
  if (trimmed == NULL)
    {
      return -ENOMEM;
    }

  ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_path(mount, trimmed, &physical, NULL);
      if (ret >= 0)
        {
          ret = !strcmp(physical, ENCPATHFS_ROOT) ? -EEXIST :
                mount->lower->u.i_mops->mkdir(mount->lower, physical, mode);
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  fs_heap_free(trimmed);
  return ret;
}

int encpathfs_rmdir(FAR struct inode *inode, FAR const char *path)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *physical = NULL;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_path(mount, path, &physical, NULL);
      if (ret >= 0)
        {
          ret = !strcmp(physical, ENCPATHFS_ROOT) ? -EBUSY :
                mount->lower->u.i_mops->rmdir(mount->lower, physical);
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  return ret;
}

int encpathfs_rename(FAR struct inode *inode, FAR const char *oldpath,
                    FAR const char *newpath)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *oldphysical = NULL;
  FAR char *newphysical = NULL;
  struct stat st;
  int ret = nxmutex_lock(&mount->lock);

  if (ret < 0)
    {
      return ret;
    }

  ret = encpathfs_path(mount, oldpath, &oldphysical, NULL);
  if (ret >= 0)
    {
      ret = encpathfs_path(mount, newpath, &newphysical, NULL);
    }

  if (ret < 0)
    {
      goto out;
    }

  if (!strcmp(oldphysical, ENCPATHFS_ROOT) ||
      !strcmp(newphysical, ENCPATHFS_ROOT))
    {
      ret = -EBUSY;
      goto out;
    }

  /* FAT does not implement POSIX replacement.  Serialize the existence
   * check with all other upper mutations and explicitly reject it.
   */

  ret = mount->lower->u.i_mops->stat(mount->lower, newphysical, &st);
  if (ret >= 0)
    {
      ret = -EEXIST;
    }
  else if (ret == -ENOENT)
    {
      ret = mount->lower->u.i_mops->rename(mount->lower, oldphysical,
                                          newphysical);
    }

out:
  nxmutex_unlock(&mount->lock);
  fs_heap_free(oldphysical);
  fs_heap_free(newphysical);
  return ret;
}

int encpathfs_stat(FAR struct inode *inode, FAR const char *path,
                  FAR struct stat *buf)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *physical = NULL;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_path(mount, path, &physical, NULL);
      if (ret >= 0)
        {
          ret = mount->lower->u.i_mops->stat(mount->lower, physical, buf);
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  return ret;
}

int encpathfs_chstat(FAR struct inode *inode, FAR const char *path,
                    FAR const struct stat *buf, int flags)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  FAR char *physical = NULL;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_path(mount, path, &physical, NULL);
      if (ret >= 0)
        {
          ret = mount->lower->u.i_mops->chstat == NULL ? -ENOSYS :
                mount->lower->u.i_mops->chstat(mount->lower, physical,
                                               buf, flags);
        }

      nxmutex_unlock(&mount->lock);
    }

  fs_heap_free(physical);
  return ret;
}

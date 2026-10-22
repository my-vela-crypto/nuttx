/****************************************************************************
 * fs/encpathfs/encpathfs_file.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/fs/ioctl.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "inode/inode.h"
#include "encpathfs.h"

int encpathfs_open(FAR struct file *filep, FAR const char *path,
                  int oflags, mode_t mode)
{
  FAR struct encpathfs_mount_s *mount = filep->f_inode->i_private;
  FAR struct encpathfs_file_s *priv;
  FAR char *physical = NULL;
  struct stat st;
  int ret;

  priv = fs_heap_zalloc(sizeof(*priv));
  if (priv == NULL)
    {
      return -ENOMEM;
    }

  ret = nxmutex_lock(&mount->lock);
  if (ret < 0)
    {
      fs_heap_free(priv);
      return ret;
    }

  ret = encpathfs_path(mount, path, &physical, &priv->logical);
  if (ret < 0)
    {
      goto out;
    }

  ret = mount->lower->u.i_mops->stat(mount->lower, physical, &st);
  if (ret >= 0 && S_ISDIR(st.st_mode))
    {
      ret = -EISDIR;
      goto out;
    }

  if (ret < 0 && ret != -ENOENT)
    {
      goto out;
    }

  priv->lower.f_inode = mount->lower;
  priv->lower.f_oflags = oflags;
  ret = mount->lower->u.i_mops->open(&priv->lower, physical, oflags, mode);
  if (ret >= 0)
    {
      priv->mount = mount;
      priv->next = mount->head;
      mount->head = priv;
      mount->files++;
      filep->f_priv = priv;
      filep->f_pos = priv->lower.f_pos;
    }

out:
  fs_heap_free(physical);
  nxmutex_unlock(&mount->lock);
  if (ret < 0)
    {
      fs_heap_free(priv->logical);
      fs_heap_free(priv);
    }

  return ret;
}

int encpathfs_close(FAR struct file *filep)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  FAR struct encpathfs_file_s **link;
  int ret;

  ret = nxmutex_lock(&mount->lock);
  if (ret < 0)
    {
      return ret;
    }

  ret = mount->lower->u.i_mops->close(&priv->lower);
  mount->files--;
  if (ret < 0)
    {
      /* VFS consumes the file object even on close failure, but retains
       * its inode reference.  Keep both that reference and the lower
       * handle for a subsequent syncfs/unbind retry.
       */

      priv->orphan_inode = filep->f_inode;
      filep->f_priv = NULL;
      nxmutex_unlock(&mount->lock);
      return ret;
    }

  for (link = &mount->head; *link != priv; link = &(*link)->next)
    {
    }

  *link = priv->next;
  nxmutex_unlock(&mount->lock);
  fs_heap_free(priv->logical);
  fs_heap_free(priv);
  filep->f_priv = NULL;
  return ret;
}

ssize_t encpathfs_read(FAR struct file *filep, FAR char *buffer,
                      size_t length)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  ssize_t ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->read(&priv->lower, buffer, length);
      filep->f_pos = priv->lower.f_pos;
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

ssize_t encpathfs_write(FAR struct file *filep, FAR const char *buffer,
                       size_t length)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  ssize_t ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->write(&priv->lower, buffer, length);
      filep->f_pos = priv->lower.f_pos;
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

off_t encpathfs_seek(FAR struct file *filep, off_t offset, int whence)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  off_t ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      if (mount->lower->u.i_mops->seek == NULL)
        {
          ret = -ENOSYS;
        }
      else
        {
          ret = mount->lower->u.i_mops->seek(&priv->lower, offset, whence);
          filep->f_pos = priv->lower.f_pos;
        }

      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR char *buffer = (FAR char *)(uintptr_t)arg;
  size_t length;
  size_t plen;
  int ret;

  if (cmd != FIOC_FILEPATH)
    {
      return -ENOTTY;
    }

  if (buffer == NULL)
    {
      return -EINVAL;
    }

  /* Return the upper path only.  The lower FILEPATH ioctl would expose the
   * hidden namespace, and other lower ioctls could alter the block device.
   */

  ret = inode_getpath(filep->f_inode, buffer, PATH_MAX);
  if (ret < 0)
    {
      return ret;
    }

  length = strlen(buffer);
  plen = strlen(priv->logical);
  if (length + (length == 0 || buffer[length - 1] != '/') + plen >= PATH_MAX)
    {
      return -ENAMETOOLONG;
    }

  if (length == 0 || buffer[length - 1] != '/')
    {
      buffer[length++] = '/';
    }
  memcpy(buffer + length, priv->logical, plen + 1);
  return 0;
}

int encpathfs_sync(FAR struct file *filep)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->sync(&priv->lower);
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_dup(FAR const struct file *oldp, FAR struct file *newp)
{
  FAR struct encpathfs_file_s *oldpriv = oldp->f_priv;
  FAR struct encpathfs_mount_s *mount = oldpriv->mount;
  FAR struct encpathfs_file_s *priv;
  int ret;

  if (mount->lower->u.i_mops->dup == NULL)
    {
      return -ENOSYS;
    }

  priv = fs_heap_zalloc(sizeof(*priv));
  if (priv == NULL)
    {
      return -ENOMEM;
    }

  priv->logical = fs_heap_strdup(oldpriv->logical);
  if (priv->logical == NULL)
    {
      fs_heap_free(priv);
      return -ENOMEM;
    }

  ret = nxmutex_lock(&mount->lock);
  if (ret >= 0)
    {
      priv->lower.f_inode = mount->lower;
      priv->lower.f_oflags = newp->f_oflags;
      priv->lower.f_pos = oldpriv->lower.f_pos;
      ret = mount->lower->u.i_mops->dup(&oldpriv->lower, &priv->lower);
      if (ret >= 0)
        {
          priv->mount = mount;
          priv->next = mount->head;
          mount->head = priv;
          mount->files++;
          newp->f_priv = priv;
          newp->f_pos = priv->lower.f_pos;
        }

      nxmutex_unlock(&mount->lock);
    }

  if (ret < 0)
    {
      fs_heap_free(priv->logical);
      fs_heap_free(priv);
    }

  return ret;
}

int encpathfs_fstat(FAR const struct file *filep, FAR struct stat *buf)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->fstat == NULL ? -ENOSYS :
            mount->lower->u.i_mops->fstat(&priv->lower, buf);
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_fchstat(FAR const struct file *filep,
                     FAR const struct stat *buf, int flags)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->fchstat == NULL ? -ENOSYS :
            mount->lower->u.i_mops->fchstat(&priv->lower, buf, flags);
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_truncate(FAR struct file *filep, off_t length)
{
  FAR struct encpathfs_file_s *priv = filep->f_priv;
  FAR struct encpathfs_mount_s *mount = priv->mount;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      if (length < 0)
        {
          ret = -EINVAL;
        }
      else
        {
          ret = mount->lower->u.i_mops->truncate == NULL ? -ENOSYS :
                mount->lower->u.i_mops->truncate(&priv->lower, length);
          filep->f_pos = priv->lower.f_pos;
        }

      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

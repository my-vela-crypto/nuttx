/****************************************************************************
 * fs/encpathfs/encpathfs_mount.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/atomic.h>
#include <nuttx/crypto/aes_siv.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "inode/inode.h"
#include "vfs/vfs.h"
#include "encpathfs.h"

static mutex_t g_keylock = NXMUTEX_INITIALIZER;
static uint8_t g_key[ENCPATHFS_KEY_SIZE];
static bool g_keyvalid;
static bool g_busy;

struct encpathfs_pending_s
{
  struct file filep;
  FAR struct fs_dirent_s *dir;
  bool closed;
  bool remove_meta;
  bool remove_root;
};

static FAR struct encpathfs_pending_s *g_pending;
static bool g_pending_ready;

#ifdef CONFIG_FS_FATFS
extern const struct mountpt_operations g_fatfs_operations;
#endif

static const uint8_t g_header[16] =
{
  'E', 'N', 'C', 'P', 'F', 'S', '0', '1',
  1, 0, 1, 0, ENCPATHFS_NAME_MAX, 0, 0, 0
};

static const uint8_t g_volume_ad[] = "encpathfs:volume:v1";
static const uint8_t g_check[] = "encpathfs-volume-v1";

#define META_SIZE (sizeof(g_header) + 16 + sizeof(g_check) - 1)

static int encpathfs_mmap(FAR struct file *filep,
                         FAR struct mm_map_entry_s *entry)
{
  /* NULL or -ENOTTY would allow VFS to fall back to a RAM mapping in
   * configurations enabling RAMMAP.  Version one explicitly rejects it.
   */

  return -ENOSYS;
}

const struct mountpt_operations g_encpathfs_operations =
{
  .open      = encpathfs_open,
  .close     = encpathfs_close,
  .read      = encpathfs_read,
  .write     = encpathfs_write,
  .seek      = encpathfs_seek,
  .ioctl     = encpathfs_ioctl,
  .mmap      = encpathfs_mmap,
  .truncate  = encpathfs_truncate,
  .sync      = encpathfs_sync,
  .dup       = encpathfs_dup,
  .fstat     = encpathfs_fstat,
  .fchstat   = encpathfs_fchstat,
  .opendir   = encpathfs_opendir,
  .closedir  = encpathfs_closedir,
  .readdir   = encpathfs_readdir,
  .rewinddir = encpathfs_rewinddir,
  .bind      = encpathfs_bind,
  .unbind    = encpathfs_unbind,
  .statfs    = encpathfs_statfs,
  .unlink    = encpathfs_unlink,
  .mkdir     = encpathfs_mkdir,
  .rmdir     = encpathfs_rmdir,
  .rename    = encpathfs_rename,
  .stat      = encpathfs_stat,
  .chstat    = encpathfs_chstat,
  .syncfs    = encpathfs_syncfs,
  .flags     = MOUNTPT_RENAME_OWN_TARGET
};

static void encpathfs_idle(void)
{
  nxmutex_lock(&g_keylock);
  /* An operation that failed to close its temporary metadata handle still
   * owns a lower reference.  Only recover may release that state.
   */

  g_busy = g_pending != NULL;
  g_pending_ready = g_pending != NULL;
  nxmutex_unlock(&g_keylock);
}

int encpathfs_setkey(unsigned int slot, FAR const uint8_t *key,
                    size_t keylen)
{
  int ret;

  if (slot != 0 || key == NULL || keylen != ENCPATHFS_KEY_SIZE)
    {
      return -EINVAL;
    }

  ret = nxmutex_lock(&g_keylock);
  if (ret < 0)
    {
      return ret;
    }

  if (g_busy)
    {
      ret = -EBUSY;
    }
  else
    {
      encpathfs_erase(g_key, sizeof(g_key));
      memcpy(g_key, key, sizeof(g_key));
      g_keyvalid = true;
      ret = 0;
    }

  nxmutex_unlock(&g_keylock);
  return ret;
}

int encpathfs_clearkey(unsigned int slot)
{
  int ret;

  if (slot != 0)
    {
      return -EINVAL;
    }

  ret = nxmutex_lock(&g_keylock);
  if (ret < 0)
    {
      return ret;
    }

  if (g_busy)
    {
      ret = -EBUSY;
    }
  else
    {
      encpathfs_erase(g_key, sizeof(g_key));
      g_keyvalid = false;
      ret = 0;
    }

  nxmutex_unlock(&g_keylock);
  return ret;
}

/* Called with the inode tree locked.  A mounted lower has one namespace
 * reference.  Reject pre-existing lower handles before taking ownership.
 */

static int encpathfs_getlower(FAR const char *path,
                             FAR struct inode **result)
{
  struct inode_search_s search;
  FAR const struct mountpt_operations *ops;
  FAR struct inode *node;
  int ret;

  /* Do not resolve a terminal soft link: inode_remove uses nofollow for
   * its terminal component too.  Verifying one inode and detaching an
   * alias would otherwise leave the verified lower publicly accessible.
   */

  SETUP_SEARCH(&search, path, true);
  ret = inode_search(&search);
  if (ret < 0)
    {
      RELEASE_SEARCH(&search);
      return ret;
    }

  node = search.node;
  if (!INODE_IS_MOUNTPT(node) || search.relpath[0] != '\0' ||
      node->i_child != NULL)
    {
      ret = -EINVAL;
      goto out;
    }

  if (atomic_read(&node->i_crefs) != 1 || INODE_IS_PATHCACHE(node))
    {
      ret = -EBUSY;
      goto out;
    }

  ops = node->u.i_mops;
#ifdef CONFIG_FS_FATFS
  /* Version one is a FAT proxy.  In particular, lower symlinks must not
   * redirect encoded components out of the authenticated .p directory.
   */

  if (ops != &g_fatfs_operations)
    {
      ret = -ENOTSUP;
      goto out;
    }
#else
  ret = -ENOTSUP;
  goto out;
#endif

  if (ops == &g_encpathfs_operations || ops->open == NULL ||
      ops->close == NULL || ops->read == NULL || ops->write == NULL ||
      ops->sync == NULL || ops->syncfs == NULL || ops->stat == NULL ||
      ops->opendir == NULL || ops->closedir == NULL ||
      ops->readdir == NULL || ops->rewinddir == NULL ||
      ops->mkdir == NULL || ops->rmdir == NULL || ops->unlink == NULL ||
      ops->rename == NULL || ops->unbind == NULL || ops->statfs == NULL)
    {
      ret = -ENOTSUP;
      goto out;
    }

  inode_addref(node);
  *result = node;
  ret = 0;
out:
  RELEASE_SEARCH(&search);
  return ret;
}

static int encpathfs_meta(FAR struct inode *lower, FAR const uint8_t *key,
                         bool create)
{
  FAR const struct mountpt_operations *ops = lower->u.i_mops;
  FAR struct encpathfs_pending_s *pending;
  FAR struct file *filep;
  uint8_t record[META_SIZE];
  uint8_t ad[sizeof(g_volume_ad) - 1 + sizeof(g_header)];
  uint8_t plain[sizeof(g_check) - 1];
  struct stat st;
  size_t offset;
  ssize_t count;
  int close_ret;
  int ret;

  pending = fs_heap_zalloc(sizeof(*pending));
  if (pending == NULL)
    {
      return -ENOMEM;
    }

  filep = &pending->filep;
  memset(record, 0, sizeof(record));
  memcpy(ad, g_volume_ad, sizeof(g_volume_ad) - 1);
  memcpy(ad + sizeof(g_volume_ad) - 1, g_header, sizeof(g_header));
  filep->f_inode = lower;
  filep->f_oflags = create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY;
  if (!create)
    {
      ret = ops->stat(lower, ENCPATHFS_META, &st);
      if (ret < 0)
        {
          goto out;
        }

      if (!S_ISREG(st.st_mode) || st.st_size != META_SIZE)
        {
          ret = -EINVAL;
          goto out;
        }
    }
  else
    {
      memcpy(record, g_header, sizeof(g_header));
      ret = aes_siv_encrypt(key, ad, sizeof(ad), g_check,
                            sizeof(g_check) - 1,
                            record + sizeof(g_header));
      if (ret < 0)
        {
          goto out;
        }
    }

  ret = ops->open(filep, ENCPATHFS_META, filep->f_oflags, 0600);
  if (ret < 0)
    {
      goto out;
    }

  for (offset = 0; offset < sizeof(record); offset += count)
    {
      if (create)
        {
          count = ops->write(filep, (FAR const char *)record + offset,
                             sizeof(record) - offset);
        }
      else
        {
          count = ops->read(filep, (FAR char *)record + offset,
                            sizeof(record) - offset);
        }

      if (count <= 0 || count > sizeof(record) - offset)
        {
          ret = count < 0 ? (int)count : -EIO;
          goto close;
        }
    }

  if (create)
    {
      ret = ops->sync(filep);
    }
  else if (memcmp(record, g_header, sizeof(g_header)) != 0)
    {
      ret = -EPROTONOSUPPORT;
    }
  else
    {
      ret = aes_siv_decrypt(key, ad, sizeof(ad),
                            record + sizeof(g_header),
                            sizeof(record) - sizeof(g_header), plain);
      if (ret >= 0 && memcmp(plain, g_check, sizeof(plain)) != 0)
        {
          ret = -EBADMSG;
        }
    }

close:
  close_ret = ops->close(filep);
  if (close_ret < 0)
    {
      /* FatFs retains FIL when close fails.  Do not lose the handle or
       * its mount reference: the manager retries recover before lower
       * unmount and keeps its block resource flags if cleanup still fails.
       */

      pending->remove_meta = create;
      inode_addref(lower);
      nxmutex_lock(&g_keylock);
      g_pending = pending;
      g_pending_ready = false;
      nxmutex_unlock(&g_keylock);
      pending = NULL;
    }

  if (ret >= 0)
    {
      ret = close_ret;
    }

out:
  fs_heap_free(pending);
  encpathfs_erase(record, sizeof(record));
  encpathfs_erase(ad, sizeof(ad));
  encpathfs_erase(plain, sizeof(plain));
  return ret;
}

int encpathfs_recover(void)
{
  FAR struct encpathfs_pending_s *pending;
  FAR struct inode *lower;
  FAR const struct mountpt_operations *ops;
  int ret = nxmutex_lock(&g_keylock);

  if (ret < 0)
    {
      return ret;
    }

  pending = g_pending;
  if (pending == NULL || !g_pending_ready)
    {
      ret = pending == NULL ? 0 : -EBUSY;
      nxmutex_unlock(&g_keylock);
      return ret;
    }

  g_pending_ready = false;
  nxmutex_unlock(&g_keylock);
  lower = pending->filep.f_inode;
  ops = lower->u.i_mops;
  inode_lock();
  ret = 0;
  if (!pending->closed)
    {
      if (pending->dir != NULL)
        {
          ret = ops->closedir(lower, pending->dir);
        }
      else
        {
          ret = ops->close(&pending->filep);
        }

      if (ret >= 0)
        {
          pending->closed = true;
        }
    }

  if (ret >= 0 && pending->remove_meta)
    {
      ret = ops->unlink(lower, ENCPATHFS_META);
      if (ret == -ENOENT)
        {
          ret = 0;
        }

      if (ret >= 0)
        {
          pending->remove_meta = false;
        }
    }

  if (ret >= 0 && pending->remove_root)
    {
      ret = ops->rmdir(lower, ENCPATHFS_ROOT);
      if (ret == -ENOENT)
        {
          ret = 0;
        }

      if (ret >= 0)
        {
          pending->remove_root = false;
        }
    }

  if (ret >= 0)
    {
      ret = ops->syncfs(lower);
    }

  if (ret >= 0)
    {
      inode_release(lower);
    }

  inode_unlock();
  nxmutex_lock(&g_keylock);
  if (ret >= 0)
    {
      g_pending = NULL;
      g_busy = false;
      fs_heap_free(pending);
    }
  else
    {
      g_pending_ready = true;
    }

  nxmutex_unlock(&g_keylock);
  return ret;
}

int encpathfs_initialize(FAR const char *path, FAR const uint8_t *key,
                        size_t keylen)
{
  FAR struct inode *lower = NULL;
  FAR struct encpathfs_pending_s *pending_dir = NULL;
  FAR struct fs_dirent_s *dir;
  FAR const struct mountpt_operations *ops;
  struct dirent entry;
  bool root_created = false;
  bool meta_created = false;
  int tmp;
  int ret;

  if (path == NULL || path[0] != '/' || key == NULL ||
      keylen != ENCPATHFS_KEY_SIZE)
    {
      return -EINVAL;
    }

  ret = nxmutex_lock(&g_keylock);
  if (ret < 0)
    {
      return ret;
    }

  if (g_busy)
    {
      nxmutex_unlock(&g_keylock);
      return -EBUSY;
    }

  g_busy = true;
  nxmutex_unlock(&g_keylock);
  inode_lock();
  ret = encpathfs_getlower(path, &lower);
  if (ret < 0)
    {
      goto out;
    }

  ops = lower->u.i_mops;
  pending_dir = fs_heap_zalloc(sizeof(*pending_dir));
  if (pending_dir == NULL)
    {
      ret = -ENOMEM;
      goto out;
    }

  ret = ops->opendir(lower, "", &dir);
  if (ret < 0)
    {
      goto out;
    }

  /* Provisioning only accepts an empty volume.  Existing data, including an
   * incomplete or corrupt previous header, is never silently overwritten.
   */

  do
    {
      ret = ops->readdir(lower, dir, &entry);
    }
  while (ret >= 0 && (!strcmp(entry.d_name, ".") ||
                      !strcmp(entry.d_name, "..")));

  tmp = ops->closedir(lower, dir);
  if (tmp < 0)
    {
      /* The initialization scan owns a DIR too.  A failed closedir must
       * be recoverable just like a failed metadata FIL close.
       */

      pending_dir->filep.f_inode = lower;
      pending_dir->dir = dir;
      inode_addref(lower);
      nxmutex_lock(&g_keylock);
      g_pending = pending_dir;
      g_pending_ready = false;
      nxmutex_unlock(&g_keylock);
      pending_dir = NULL;
    }

  if (ret >= 0)
    {
      ret = -EEXIST;
      goto out;
    }

  if (ret != -ENOENT || tmp < 0)
    {
      ret = tmp < 0 ? tmp : ret;
      goto out;
    }

  ret = ops->mkdir(lower, ENCPATHFS_ROOT, 0700);
  if (ret < 0)
    {
      goto out;
    }

  root_created = true;
  ret = encpathfs_meta(lower, key, true);
  if (ret < 0)
    {
      /* Since the volume was empty under the inode lock, any header now
       * present belongs to this failed initialization attempt.
       */

      if (g_pending == NULL)
        {
          ops->unlink(lower, ENCPATHFS_META);
        }
      goto out;
    }

  meta_created = true;
  ret = ops->syncfs(lower);
  if (ret >= 0)
    {
      ret = encpathfs_meta(lower, key, false);
    }

out:
  fs_heap_free(pending_dir);
  if (ret < 0 && lower != NULL)
    {
      if (g_pending != NULL)
        {
          /* Keep newly created entries until the pending FIL can close.
           * Removing an open FAT entry would invalidate recovery state.
           */

          g_pending->remove_meta = root_created;
          g_pending->remove_root = root_created;
        }
      else if (meta_created)
        {
          lower->u.i_mops->unlink(lower, ENCPATHFS_META);
        }

      if (root_created && g_pending == NULL)
        {
          lower->u.i_mops->rmdir(lower, ENCPATHFS_ROOT);
        }

      lower->u.i_mops->syncfs(lower);
    }

  if (lower != NULL)
    {
      inode_release(lower);
    }

  inode_unlock();
  encpathfs_idle();
  return ret;
}

int encpathfs_bind(FAR struct inode *blkdriver, FAR const void *data,
                  FAR void **handle)
{
  FAR struct encpathfs_mount_s *mount;
  FAR const char *options = data;
  FAR const char *suffix;
  FAR char *path = NULL;
  struct stat st;
  struct statfs statfs;
  size_t length;
  int ret;

  mount = fs_heap_zalloc(sizeof(*mount));
  if (mount == NULL)
    {
      encpathfs_clearkey(0);
      return -ENOMEM;
    }

  ret = nxmutex_lock(&g_keylock);
  if (ret < 0)
    {
      fs_heap_free(mount);
      return ret;
    }

  if (g_busy || !g_keyvalid)
    {
      ret = g_busy ? -EBUSY : -ENOKEY;
      nxmutex_unlock(&g_keylock);
      fs_heap_free(mount);
      return ret;
    }

  memcpy(mount->key, g_key, sizeof(g_key));
  encpathfs_erase(g_key, sizeof(g_key));
  g_keyvalid = false;
  g_busy = true;
  nxmutex_unlock(&g_keylock);
  nxmutex_init(&mount->lock);

  if (blkdriver != NULL || options == NULL || handle == NULL ||
      strnlen(options, PATH_MAX + 32) >= PATH_MAX + 32 ||
      strncmp(options, "lower=/", 7) != 0)
    {
      ret = -EINVAL;
      goto fail;
    }

  suffix = strchr(options + 6, ',');
  if (suffix == NULL || strcmp(suffix, ",root=.p,slot=0") != 0)
    {
      ret = -EINVAL;
      goto fail;
    }

  length = suffix - (options + 6);
  if (length < 2 || length >= PATH_MAX)
    {
      ret = -EINVAL;
      goto fail;
    }

  path = fs_heap_strndup(options + 6, length);
  if (path == NULL)
    {
      ret = -ENOMEM;
      goto fail;
    }

  inode_lock();
  ret = encpathfs_getlower(path, &mount->lower);
  if (ret < 0)
    {
      goto unlock;
    }

  ret = mount->lower->u.i_mops->statfs(mount->lower, &statfs);
  if (ret >= 0 && statfs.f_namelen < ENCPATHFS_ENCODED_MAX)
    {
      ret = -ENAMETOOLONG;
    }

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->stat(mount->lower,
                                        ENCPATHFS_ROOT, &st);
    }

  if (ret >= 0 && !S_ISDIR(st.st_mode))
    {
      ret = -ENOTDIR;
    }

  if (ret >= 0)
    {
      ret = encpathfs_meta(mount->lower, mount->key, false);
    }

  if (ret >= 0)
    {
      /* inode_remove returns -EBUSY on successful detach because the
       * reference obtained above intentionally keeps the inode alive.
       */

      ret = inode_remove(path);
      if (ret == -EBUSY)
        {
          ret = 0;
        }
    }

unlock:
  inode_unlock();
  fs_heap_free(path);
  path = NULL;
  if (ret >= 0)
    {
      *handle = mount;
      return 0;
    }

fail:
  fs_heap_free(path);
  if (mount->lower != NULL)
    {
      inode_release(mount->lower);
    }

  nxmutex_destroy(&mount->lock);
  encpathfs_erase(mount->key, sizeof(mount->key));
  fs_heap_free(mount);
  encpathfs_idle();
  return ret;
}

int encpathfs_flush(FAR struct encpathfs_mount_s *mount)
{
  FAR struct encpathfs_file_s **flink = &mount->head;
  FAR struct encpathfs_dir_s **dlink = &mount->dhead;
  FAR struct encpathfs_file_s *filep;
  FAR struct encpathfs_dir_s *dir;
  int ret;

  while ((filep = *flink) != NULL)
    {
      if (filep->orphan_inode != NULL)
        {
          ret = mount->lower->u.i_mops->close(&filep->lower);
        }
      else
        {
          ret = mount->lower->u.i_mops->sync(&filep->lower);
        }

      if (ret < 0)
        {
          return ret;
        }

      if (filep->orphan_inode != NULL)
        {
          *flink = filep->next;
          inode_release(filep->orphan_inode);
          fs_heap_free(filep->logical);
          fs_heap_free(filep);
        }
      else
        {
          flink = &filep->next;
        }
    }

  while ((dir = *dlink) != NULL)
    {
      if (dir->orphan)
        {
          ret = mount->lower->u.i_mops->closedir(mount->lower, dir->lower);
          if (ret < 0)
            {
              return ret;
            }

          *dlink = dir->next;
          fs_heap_free(dir);
        }
      else
        {
          dlink = &dir->next;
        }
    }

  return mount->lower->u.i_mops->syncfs(mount->lower);
}

struct encpathfs_upper_s
{
  FAR struct encpathfs_mount_s *mount;
  FAR struct inode *inode;
};

static int encpathfs_findupper(FAR struct inode *inode,
                              FAR char *path, FAR void *arg)
{
  FAR struct encpathfs_upper_s *upper = arg;

  if (INODE_IS_MOUNTPT(inode) &&
      inode->u.i_mops == &g_encpathfs_operations &&
      inode->i_private == upper->mount)
    {
      upper->inode = inode;
      return 1;
    }

  return 0;
}

int encpathfs_unbind(FAR void *handle, FAR struct inode **blkdriver,
                    unsigned int flags)
{
  FAR struct encpathfs_mount_s *mount = handle;
  FAR struct inode *driver = NULL;
  struct encpathfs_upper_s upper = { mount, NULL };
  int ret = nxmutex_lock(&mount->lock);

  if (ret < 0)
    {
      return ret;
    }

  /* Forced detach is intentionally unsupported: no caller can revoke
   * live file objects or their encryption keys.
   */

  if (mount->files != 0 || mount->dirs != 0)
    {
      nxmutex_unlock(&mount->lock);
      return -EBUSY;
    }

  ret = encpathfs_flush(mount);
  if (ret >= 0)
    {
      /* VFS holds the inode tree write lock during unbind.  In addition
       * to completed opens, protect operations which found the upper inode
       * but have not entered a callback yet.  A published mount has one
       * namespace reference and nx_umount2 holds one lookup reference.
       * No upper exists when VFS is rolling back an unpublished bind.
       */

      ret = foreach_inode(encpathfs_findupper, &upper);
      if (ret > 0)
        {
          ret = 0;
        }

      if (ret >= 0 && upper.inode != NULL &&
          atomic_read(&upper.inode->i_crefs) > 2)
        {
          ret = -EBUSY;
        }
    }

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->unbind(mount->lower->i_private,
                                           &driver, 0);
    }

  if (ret != 0)
    {
      nxmutex_unlock(&mount->lock);
      return ret > 0 ? -EBUSY : ret;
    }

  mount->lower->i_private = NULL;
  inode_release(mount->lower);
  if (blkdriver != NULL)
    {
      *blkdriver = driver;
    }
  else if (driver != NULL)
    {
      inode_release(driver);
    }

  encpathfs_erase(mount->key, sizeof(mount->key));
  nxmutex_unlock(&mount->lock);
  nxmutex_destroy(&mount->lock);
  fs_heap_free(mount);
  encpathfs_idle();
  return 0;
}

int encpathfs_statfs(FAR struct inode *inode, FAR struct statfs *buf)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = mount->lower->u.i_mops->statfs(mount->lower, buf);
      if (ret >= 0)
        {
          buf->f_namelen = ENCPATHFS_NAME_MAX;
        }

      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

int encpathfs_syncfs(FAR struct inode *inode)
{
  FAR struct encpathfs_mount_s *mount = inode->i_private;
  int ret = nxmutex_lock(&mount->lock);

  if (ret >= 0)
    {
      ret = encpathfs_flush(mount);
      nxmutex_unlock(&mount->lock);
    }

  return ret;
}

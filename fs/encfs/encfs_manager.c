/****************************************************************************
 * fs/encfs/encfs_manager.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/stat.h>
#include <errno.h>

#include <nuttx/fs/encpathfs.h>
#include <nuttx/fs/fs.h>
#include <nuttx/mutex.h>

#include "inode/inode.h"
#include "encfs.h"

/****************************************************************************
 * Private Data
 ****************************************************************************/

static mutex_t g_lock = NXMUTEX_INITIALIZER;
static struct encfs_status_s g_status;

#ifdef CONFIG_ENCFS_TESTING
static enum encfs_test_failpoint_e g_failpoint;
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/* All state and test-provider access is serialized by g_lock.
 * No key material is stored in status or in the mount option string.
 */

static bool encfs_has_resources(void)
{
  return g_status.block_registered || g_status.lower_visible ||
         g_status.upper_mounted || g_status.path_key_staged;
}

static void encfs_update_state(void)
{
  if (g_status.upper_mounted)
    {
      g_status.state = ENCFS_READY;
    }
  else if (g_status.lower_visible)
    {
      g_status.state = ENCFS_LOWER_MOUNTED;
    }
  else if (g_status.block_keyed)
    {
      g_status.state = ENCFS_BLOCK_KEYED;
    }
  else if (g_status.block_registered)
    {
      g_status.state = ENCFS_BLOCK_REGISTERED;
    }
  else
    {
      g_status.state = ENCFS_STOPPED;
    }
}

static void encfs_clear_error(void)
{
  g_status.error = 0;
  g_status.stage = ENCFS_STAGE_NONE;
  g_status.cleanup_error = 0;
  g_status.cleanup_stage = ENCFS_STAGE_NONE;
}

/* Reserve the upper pseudo directory before bind can take ownership of the
 * lower mount.  With an existing target, nx_mount has no allocating/failing
 * publication step after bind.  This avoids a VFS error path that ignores an
 * unbind error and would otherwise strand an invisible lower mount.
 */

static int encfs_prepare_upper(void)
{
  struct inode_search_s desc;
  FAR struct inode *inode;
  int ret;

  SETUP_SEARCH(&desc, ENCFS_UPPER_PATH, false);
  inode_lock();
  ret = inode_find(&desc);
  if (ret >= 0)
    {
      ret = INODE_IS_PSEUDODIR(desc.node) && desc.relpath[0] == '\0' ?
            0 : -EBUSY;
      inode_release(desc.node);
    }
  else if (ret == -ENOENT)
    {
      ret = inode_reserve_path(ENCFS_UPPER_PATH, 0777, &inode);
    }

  inode_unlock();
  RELEASE_SEARCH(&desc);
  return ret;
}

static int encfs_inject(enum encfs_stage_e stage)
{
#ifdef CONFIG_ENCFS_TESTING
  enum encfs_test_failpoint_e point = ENCFS_TEST_FAIL_NONE;

  switch (stage)
    {
      case ENCFS_STAGE_REGISTER:
        point = ENCFS_TEST_FAIL_REGISTER;
        break;
      case ENCFS_STAGE_BLOCK_KEY:
        point = ENCFS_TEST_FAIL_KEY;
        break;
      case ENCFS_STAGE_LOWER_MOUNT:
      case ENCFS_STAGE_FORMAT:
        point = ENCFS_TEST_FAIL_LOWER;
        break;
      case ENCFS_STAGE_UPPER_MOUNT:
        point = ENCFS_TEST_FAIL_UPPER;
        break;
      default:
        break;
    }

  if (point != ENCFS_TEST_FAIL_NONE && g_failpoint == point)
    {
      g_failpoint = ENCFS_TEST_FAIL_NONE;
      return -EIO;
    }
#else
  (void)stage;
#endif

  return 0;
}

static int encfs_release_error(enum encfs_stage_e stage, int ret,
                                bool rollback)
{
  if (rollback)
    {
      g_status.cleanup_stage = stage;
      g_status.cleanup_error = ret;
    }
  else
    {
      g_status.stage = stage;
      g_status.error = ret;
    }

  encfs_update_state();
  return ret;
}

/* Release strictly in reverse ownership order.  A failed unmount must leave
 * its dependent resources alive.  In particular, -EBUSY at /data preserves
 * the complete running chain and the caller may retry after closing handles.
 */

static int encfs_release(bool rollback)
{
  int ret;

  if (g_status.upper_mounted)
    {
      ret = nx_umount2(ENCFS_UPPER_PATH, 0);
      if (ret < 0)
        {
          return encfs_release_error(ENCFS_STAGE_UPPER_UMOUNT, ret,
                                     rollback);
        }

      /* encpathfs unbind also closes and releases the hidden FatFs mount. */

      g_status.upper_mounted = false;
      g_status.lower_visible = false;
    }

  if (g_status.lower_visible)
    {
      /* A failed metadata close may still own a temporary lower file.
       * Retry it before releasing the key slot or unmounting its lower.
       */

      ret = encpathfs_recover();
      if (ret < 0)
        {
          return encfs_release_error(ENCFS_STAGE_LOWER_UMOUNT, ret,
                                     rollback);
        }
    }

  if (g_status.path_key_staged)
    {
      ret = encpathfs_clearkey(ENCFS_KEY_SLOT);
      if (ret < 0)
        {
          return encfs_release_error(ENCFS_STAGE_PATH_KEY, ret, rollback);
        }

      g_status.path_key_staged = false;
    }

  if (g_status.lower_visible)
    {
      ret = nx_umount2(ENCFS_LOWER_PATH, 0);
      if (ret < 0)
        {
          return encfs_release_error(ENCFS_STAGE_LOWER_UMOUNT, ret,
                                     rollback);
        }

      g_status.lower_visible = false;
    }

  if (g_status.block_registered)
    {
      ret = encfs_block_unregister();
      if (ret < 0)
        {
          return encfs_release_error(ENCFS_STAGE_UNREGISTER, ret, rollback);
        }

      g_status.block_registered = false;
      g_status.block_keyed = false;
    }

  encfs_update_state();
  return 0;
}

/* Start and provision share block/key acquisition, but only provision passes
 * forceformat.  Plain start must never pass autoformat or create metadata.
 */

static int encfs_acquire(bool provision)
{
  struct encfs_keys_s keys;
  struct stat st;
  int clearret;
  int ret;

  encfs_clear_error();
  if (!provision)
    {
      g_status.stage = ENCFS_STAGE_PREPARE_UPPER;
      ret = encfs_prepare_upper();
      if (ret < 0)
        {
          goto fail;
        }
    }

  g_status.stage = ENCFS_STAGE_REGISTER;
  ret = encfs_inject(g_status.stage);
  if (ret < 0)
    {
      goto fail;
    }

  ret = encfs_block_register();
  if (ret < 0)
    {
      goto fail;
    }

  g_status.block_registered = true;
  ret = encfs_derive_keys(&keys, &g_status.stage);
  if (ret < 0)
    {
      goto fail;
    }

  g_status.stage = ENCFS_STAGE_BLOCK_KEY;
  ret = encfs_inject(g_status.stage);
  if (ret < 0)
    {
      goto fail;
    }

  ret = encfs_block_set_key(keys.block);
  encfs_erase(keys.block, sizeof(keys.block));
  if (ret < 0)
    {
      goto fail;
    }

  g_status.block_keyed = true;
  g_status.stage = provision ? ENCFS_STAGE_FORMAT : ENCFS_STAGE_LOWER_MOUNT;
  ret = encfs_inject(g_status.stage);
  if (ret < 0)
    {
      goto fail;
    }

  ret = nx_mount(ENCFS_BLOCK_DEVICE, ENCFS_LOWER_PATH, "fatfs", 0,
                 provision ? "forceformat" : NULL);
  if (ret < 0)
    {
      goto fail;
    }

  g_status.lower_visible = true;
  if (provision)
    {
      g_status.stage = ENCFS_STAGE_INITIALIZE;
      ret = encpathfs_initialize(ENCFS_LOWER_PATH, keys.path,
                                sizeof(keys.path));
      encfs_erase(&keys, sizeof(keys));
      if (ret < 0)
        {
          goto fail;
        }

      encfs_clear_error();
      return encfs_release(false);
    }

  g_status.stage = ENCFS_STAGE_PATH_KEY;
  ret = encpathfs_setkey(ENCFS_KEY_SLOT, keys.path, sizeof(keys.path));
  encfs_erase(&keys, sizeof(keys));
  if (ret < 0)
    {
      goto fail;
    }

  g_status.path_key_staged = true;
  g_status.stage = ENCFS_STAGE_UPPER_MOUNT;
  ret = encfs_inject(g_status.stage);
  if (ret < 0)
    {
      goto fail;
    }

  ret = nx_mount(NULL, ENCFS_UPPER_PATH, "encpathfs", 0,
                 "lower=" ENCFS_LOWER_PATH ",root=.p,slot=0");
  if (ret >= 0)
    {
      g_status.upper_mounted = true;
      g_status.lower_visible = false;
    }
  else
    {
      /* bind consumes the lower mount on success; VFS also invokes unbind
       * if publishing /data subsequently fails.  In that case /datap has
       * disappeared and its resources have already been released.  Earlier
       * bind failures leave /datap visible for our rollback.
       */

      if (nx_stat(ENCFS_LOWER_PATH, &st, 0) == -ENOENT)
        {
          g_status.lower_visible = false;
        }
    }

  /* bind consumes its key slot on all paths.  A failure before bind (e.g. an
   * existing /data mount) does not, so explicitly clear that case as well.
   * A successful mount returns -EBUSY here because its key context is
   * active;
   * the temporary slot has nevertheless been erased by bind.
   */

  clearret = encpathfs_clearkey(ENCFS_KEY_SLOT);
  if (clearret >= 0 || (clearret == -EBUSY && g_status.upper_mounted))
    {
      g_status.path_key_staged = false;
    }

  if (ret < 0)
    {
      goto fail;
    }

  if (clearret < 0 && g_status.path_key_staged)
    {
      g_status.stage = ENCFS_STAGE_PATH_KEY;
      ret = clearret;
      goto fail;
    }

  encfs_clear_error();
  encfs_update_state();
  return 0;

fail:
  encfs_erase(&keys, sizeof(keys));
  g_status.error = ret;
  encfs_release(true);
  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int encfs_start(void)
{
  int ret = nxmutex_lock(&g_lock);

  if (ret < 0)
    {
      return ret;
    }

  if (g_status.upper_mounted)
    {
      ret = 0;
    }
  else if (encfs_has_resources())
    {
      ret = -EBUSY;
    }
  else
    {
      ret = encfs_acquire(false);
    }

  nxmutex_unlock(&g_lock);
  return ret;
}

int encfs_stop(void)
{
  int ret = nxmutex_lock(&g_lock);

  if (ret < 0)
    {
      return ret;
    }

  encfs_clear_error();
  ret = encfs_release(false);
  nxmutex_unlock(&g_lock);
  return ret;
}

int encfs_provision(void)
{
  int ret = nxmutex_lock(&g_lock);

  if (ret < 0)
    {
      return ret;
    }

  if (encfs_has_resources())
    {
      ret = -EBUSY;
    }
  else
    {
      ret = encfs_acquire(true);
    }

  nxmutex_unlock(&g_lock);
  return ret;
}

int encfs_get_status(FAR struct encfs_status_s *status)
{
  int ret;

  if (status == NULL)
    {
      return -EINVAL;
    }

  ret = nxmutex_lock(&g_lock);
  if (ret < 0)
    {
      return ret;
    }

  *status = g_status;
  nxmutex_unlock(&g_lock);
  return 0;
}

#ifdef CONFIG_ENCFS_TESTING
int encfs_test_set_master(FAR const uint8_t *key, size_t keylen)
{
  int ret = nxmutex_lock(&g_lock);

  if (ret < 0)
    {
      return ret;
    }

  ret = encfs_has_resources() ? -EBUSY :
        encfs_key_set_test_master(key, keylen);
  nxmutex_unlock(&g_lock);
  return ret;
}

int encfs_test_use_board_key(void)
{
  int ret = nxmutex_lock(&g_lock);

  if (ret < 0)
    {
      return ret;
    }

  if (encfs_has_resources())
    {
      ret = -EBUSY;
    }
  else
    {
      encfs_key_use_board();
      ret = 0;
    }

  nxmutex_unlock(&g_lock);
  return ret;
}

int encfs_test_set_failpoint(enum encfs_test_failpoint_e failpoint)
{
  int ret;

  if (failpoint < ENCFS_TEST_FAIL_NONE || failpoint > ENCFS_TEST_FAIL_UPPER)
    {
      return -EINVAL;
    }

  ret = nxmutex_lock(&g_lock);
  if (ret < 0)
    {
      return ret;
    }

  if (encfs_has_resources())
    {
      ret = -EBUSY;
    }
  else
    {
      g_failpoint = failpoint;
      ret = 0;
    }

  nxmutex_unlock(&g_lock);
  return ret;
}
#endif

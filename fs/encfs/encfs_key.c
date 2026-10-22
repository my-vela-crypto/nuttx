/****************************************************************************
 * fs/encfs/encfs_key.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <string.h>

#include <nuttx/board.h>
#include <nuttx/crypto/hkdf.h>

#include "encfs.h"

#if CONFIG_BOARDCTL_UNIQUEKEY_SIZE != ENCFS_MASTER_KEY_SIZE
#  error "ENCFSMGR requires a 32-byte board unique key"
#endif

/****************************************************************************
 * Private Data
 ****************************************************************************/

#ifdef CONFIG_ENCFS_TESTING
static uint8_t g_test_master[ENCFS_MASTER_KEY_SIZE];
static bool g_test_provider;
static bool g_test_missing;
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* A volatile store prevents dead-store elimination of temporary secrets. */

void encfs_erase(FAR void *memory, size_t length)
{
  FAR volatile uint8_t *p = memory;

  while (length-- > 0)
    {
      *p++ = 0;
    }
}

static int encfs_read_master(FAR uint8_t *master)
{
#ifdef CONFIG_ENCFS_TESTING
  if (g_test_provider)
    {
      if (g_test_missing)
        {
          return -ENOKEY;
        }

      memcpy(master, g_test_master, ENCFS_MASTER_KEY_SIZE);
      return 0;
    }
#endif

  return board_uniquekey(master);
}

int encfs_derive_keys(FAR struct encfs_keys_s *keys,
                      FAR enum encfs_stage_e *stage)
{
  static const uint8_t blocksalt[] = "blkcrypt";
  static const uint8_t pathsalt[] = "encpathfs";
  uint8_t master[ENCFS_MASTER_KEY_SIZE];
  int ret;

  memset(keys, 0, sizeof(*keys));
  *stage = ENCFS_STAGE_MASTER;
  ret = encfs_read_master(master);
  if (ret < 0)
    {
      goto out;
    }

  *stage = ENCFS_STAGE_DERIVE;
  ret = hkdf_sha256(master, sizeof(master), blocksalt,
                    sizeof(blocksalt) - 1, NULL, 0,
                    keys->block, sizeof(keys->block));
  if (ret < 0)
    {
      goto out;
    }

  ret = hkdf_sha256(master, sizeof(master), pathsalt,
                    sizeof(pathsalt) - 1, NULL, 0,
                    keys->path, sizeof(keys->path));
out:
  encfs_erase(master, sizeof(master));
  if (ret < 0)
    {
      encfs_erase(keys, sizeof(*keys));
    }

  return ret;
}

#ifdef CONFIG_ENCFS_TESTING
int encfs_key_set_test_master(FAR const uint8_t *key, size_t keylen)
{
  if ((key == NULL && keylen != 0) ||
      (key != NULL && keylen != ENCFS_MASTER_KEY_SIZE))
    {
      return -EINVAL;
    }

  encfs_erase(g_test_master, sizeof(g_test_master));
  g_test_provider = true;
  g_test_missing = key == NULL;
  if (key != NULL)
    {
      memcpy(g_test_master, key, sizeof(g_test_master));
    }

  return 0;
}

void encfs_key_use_board(void)
{
  encfs_erase(g_test_master, sizeof(g_test_master));
  g_test_provider = false;
  g_test_missing = false;
}
#endif

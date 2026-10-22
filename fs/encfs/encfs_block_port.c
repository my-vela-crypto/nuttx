/****************************************************************************
 * fs/encfs/encfs_block_port.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>

#include <nuttx/compiler.h>
#include <nuttx/crypto/blkcrypt.h>

#include "encfs.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int encfs_block_register(void)
{
  return blkcrypt_register(ENCFS_BLOCK_DEVICE, ENCFS_PARENT_DEVICE);
}

int encfs_block_set_key(FAR const uint8_t *key)
{
  return blkcrypt_set_key(ENCFS_BLOCK_DEVICE, key, ENCFS_KEY_SIZE);
}

int encfs_block_unregister(void)
{
  return blkcrypt_unregister(ENCFS_BLOCK_DEVICE);
}

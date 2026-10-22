/****************************************************************************
 * fs/encfs/encfs.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

#ifndef __FS_ENCFS_ENCFS_H
#define __FS_ENCFS_ENCFS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <stddef.h>
#include <stdint.h>
#include <nuttx/fs/encfs.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define ENCFS_KEY_SIZE 32
#define ENCFS_KEY_SLOT 0

/****************************************************************************
 * Public Types
 ****************************************************************************/

struct encfs_keys_s
{
  uint8_t block[ENCFS_KEY_SIZE];
  uint8_t path[ENCFS_KEY_SIZE];
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

void encfs_erase(FAR void *memory, size_t length);
int encfs_derive_keys(FAR struct encfs_keys_s *keys,
                      FAR enum encfs_stage_e *stage);
int encfs_block_register(void);
int encfs_block_set_key(FAR const uint8_t *key);
int encfs_block_unregister(void);

#ifdef CONFIG_ENCFS_TESTING
/* These private providers are called with the manager lock held. */

int encfs_key_set_test_master(FAR const uint8_t *key, size_t keylen);
void encfs_key_use_board(void);
#endif

#endif /* __FS_ENCFS_ENCFS_H */

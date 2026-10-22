/****************************************************************************
 * include/nuttx/fs/encfs.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_FS_ENCFS_H
#define __INCLUDE_NUTTX_FS_ENCFS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define ENCFS_MASTER_KEY_SIZE 32
#define ENCFS_BLOCK_DEVICE    "/dev/encdata0"
#define ENCFS_PARENT_DEVICE   "/dev/virtblk1"
#define ENCFS_LOWER_PATH      "/datap"
#define ENCFS_UPPER_PATH      "/data"

/****************************************************************************
 * Public Types
 ****************************************************************************/

enum encfs_state_e
{
  ENCFS_STOPPED = 0,
  ENCFS_BLOCK_REGISTERED,
  ENCFS_BLOCK_KEYED,
  ENCFS_LOWER_MOUNTED,
  ENCFS_READY
};

enum encfs_stage_e
{
  ENCFS_STAGE_NONE = 0,
  ENCFS_STAGE_REGISTER,
  ENCFS_STAGE_MASTER,
  ENCFS_STAGE_DERIVE,
  ENCFS_STAGE_BLOCK_KEY,
  ENCFS_STAGE_LOWER_MOUNT,
  ENCFS_STAGE_FORMAT,
  ENCFS_STAGE_PATH_KEY,
  ENCFS_STAGE_UPPER_MOUNT,
  ENCFS_STAGE_INITIALIZE,
  ENCFS_STAGE_UPPER_UMOUNT,
  ENCFS_STAGE_LOWER_UMOUNT,
  ENCFS_STAGE_UNREGISTER,
  ENCFS_STAGE_PREPARE_UPPER
};

/* The resource fields describe what is still owned after an error.  error
 * and stage retain the original failure; cleanup_error and cleanup_stage
 * describe a subsequent rollback failure.  A busy stop leaves READY intact.
 */

struct encfs_status_s
{
  enum encfs_state_e state;
  enum encfs_stage_e stage;
  int error;
  enum encfs_stage_e cleanup_stage;
  int cleanup_error;
  bool block_registered;
  bool block_keyed;
  bool lower_visible;
  bool upper_mounted;
  bool path_key_staged;
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifdef __cplusplus
extern "C"
{
#endif

/* All interfaces return zero or a negated errno.  start is idempotent when
 * READY, never formats, and authenticates existing path metadata.  stop is
 * idempotent when STOPPED and returns -EBUSY while handles remain open.
 *
 * DESTRUCTIVE: provision formats the entire encrypted data volume as exFAT
 * and initializes its authenticated path metadata.  Invoke only after an
 * explicit user request to erase the data disk.  It leaves the volume
 * stopped.
 */

int encfs_start(void);
int encfs_stop(void);
int encfs_provision(void);
int encfs_get_status(FAR struct encfs_status_s *status);

#ifdef CONFIG_ENCFS_TESTING
/* Test interfaces are excluded from production builds.  Key changes require
 * STOPPED with no resources left over.  NULL/0 selects a missing key
 * provider;
 * a non-NULL key must have exactly ENCFS_MASTER_KEY_SIZE bytes.
 * use_board_key
 * erases the test key and restores the board provider.
 */

enum encfs_test_failpoint_e
{
  ENCFS_TEST_FAIL_NONE = 0,
  ENCFS_TEST_FAIL_REGISTER,
  ENCFS_TEST_FAIL_KEY,
  ENCFS_TEST_FAIL_LOWER,
  ENCFS_TEST_FAIL_UPPER
};

int encfs_test_set_master(FAR const uint8_t *key, size_t keylen);
int encfs_test_use_board_key(void);

/* Failpoints fail once with -EIO immediately before the selected operation.
 * A subsequent start can retry without resetting the failpoint.
 */

int encfs_test_set_failpoint(enum encfs_test_failpoint_e failpoint);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_NUTTX_FS_ENCFS_H */

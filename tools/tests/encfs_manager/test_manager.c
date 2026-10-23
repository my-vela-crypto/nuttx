/****************************************************************************
 * tools/tests/encfs_manager/test_manager.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <nuttx/fs/encfs.h>
#include <nuttx/fs/encpathfs.h>
#include <nuttx/crypto/blkcrypt.h>
#include <nuttx/crypto/hkdf.h>
#include "inode/inode.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define CHECK(condition) \
  do \
    { \
      g_checks++; \
      if (!(condition)) \
        { \
          fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
          exit(EXIT_FAILURE); \
        } \
    } \
  while (0)

/****************************************************************************
 * Private Data
 ****************************************************************************/

static bool g_block;
static bool g_keyed;
static bool g_lower;
static bool g_upper;
static bool g_staged;
static bool g_formatted = true;
static bool g_busy;
static bool g_lower_cleanup_error;
static bool g_metadata_close_error;
static bool g_block_cleanup_error;
static bool g_target_reserved;
static bool g_target_foreign;
static bool g_lower_foreign;
static bool g_target_allocation_error;
static int g_upper_fail;
static int g_formats;
static int g_initializations;
static int g_hkdf_calls;
static unsigned int g_checks;
static struct inode g_target_inode;
static struct inode g_lower_inode;
static ino_t g_inode_serial;
static uintptr_t g_mount_serial;
static const struct mountpt_operations g_upper_operations;
static const struct mountpt_operations g_lower_operations;
static const struct mountpt_operations g_foreign_operations;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static struct encfs_status_s status(void)
{
  struct encfs_status_s s;

  CHECK(encfs_get_status(&s) == 0);
  return s;
}

static void check_stopped(void)
{
  struct encfs_status_s s = status();

  CHECK(s.state == ENCFS_STOPPED && !s.block_registered && !s.block_keyed &&
        !s.lower_visible && !s.upper_mounted && !s.path_key_staged);
  CHECK(!g_block && !g_keyed && !g_lower && !g_upper && !g_staged);
}

static void test_missing_master(void)
{
  uint8_t key[ENCFS_MASTER_KEY_SIZE];

  memset(key, 0x69, sizeof(key));
  CHECK(encfs_get_status(NULL) == -EINVAL);
  CHECK(encfs_stop() == 0);
  check_stopped();
  CHECK(encfs_test_set_master(key, sizeof(key) - 1) == -EINVAL);
  CHECK(encfs_test_set_master(NULL, 1) == -EINVAL);
  CHECK(encfs_test_set_master(NULL, 0) == 0);
  CHECK(encfs_start() == -ENOKEY);
  CHECK(status().stage == ENCFS_STAGE_MASTER);
  check_stopped();
  CHECK(encfs_test_set_master(key, sizeof(key)) == 0);
}

static void test_target_reservation(void)
{
  g_target_reserved = false;
  g_target_allocation_error = true;
  CHECK(encfs_start() == -ENOMEM);
  CHECK(status().stage == ENCFS_STAGE_PREPARE_UPPER);
  check_stopped();
  g_target_allocation_error = false;
  g_target_foreign = true;
  CHECK(encfs_start() == -EBUSY);
  CHECK(status().stage == ENCFS_STAGE_PREPARE_UPPER);
  check_stopped();
  g_target_foreign = false;
}

static void test_failpoints(void)
{
  int point;

  for (point = ENCFS_TEST_FAIL_REGISTER;
       point <= ENCFS_TEST_FAIL_UPPER; point++)
    {
      CHECK(encfs_test_set_failpoint(point) == 0);
      CHECK(encfs_start() == -EIO);
      CHECK(status().error == -EIO);
      check_stopped();
      CHECK(encfs_start() == 0);
      CHECK(status().state == ENCFS_READY);
      CHECK(encfs_stop() == 0);
      check_stopped();
    }
}

static void test_busy_stop(void)
{
  uint8_t key[ENCFS_MASTER_KEY_SIZE];

  memset(key, 0xa6, sizeof(key));
  CHECK(encfs_start() == 0);
  CHECK(encfs_start() == 0);
  CHECK(encfs_provision() == -EBUSY);
  CHECK(encfs_test_set_master(key, sizeof(key)) == -EBUSY);
  CHECK(encfs_test_use_board_key() == -EBUSY);
  CHECK(encfs_test_set_failpoint(ENCFS_TEST_FAIL_KEY) == -EBUSY);
  g_busy = true;
  CHECK(encfs_stop() == -EBUSY);
  CHECK(status().state == ENCFS_READY && status().upper_mounted &&
        status().block_keyed);
  CHECK(encfs_start() == 0);
  g_busy = false;
  CHECK(encfs_stop() == 0);
  check_stopped();
}

static void test_upper_failures(void)
{
  g_upper_fail = 1;
  CHECK(encfs_start() == -EKEYREJECTED);
  CHECK(status().stage == ENCFS_STAGE_UPPER_MOUNT);
  check_stopped();
  g_upper_fail = 2;
  CHECK(encfs_start() == -ENOMEM);
  check_stopped();
  g_upper_fail = 0;
}

static void test_cleanup_failures(void)
{
  g_upper_fail = 1;
  g_lower_cleanup_error = true;
  CHECK(encfs_start() == -EKEYREJECTED);
  CHECK(status().state == ENCFS_LOWER_MOUNTED);
  CHECK(status().error == -EKEYREJECTED);
  CHECK(status().cleanup_error == -EIO);
  CHECK(status().cleanup_stage == ENCFS_STAGE_LOWER_UMOUNT);
  CHECK(encfs_start() == -EBUSY);
  CHECK(encfs_test_set_master(NULL, 0) == -EBUSY);
  g_lower_cleanup_error = false;
  CHECK(encfs_stop() == 0);
  check_stopped();
  g_upper_fail = 1;
  g_metadata_close_error = true;
  CHECK(encfs_start() == -EKEYREJECTED);
  CHECK(status().lower_visible && status().block_registered);
  CHECK(status().cleanup_error == -EIO);
  CHECK(encfs_stop() == -EIO);
  g_metadata_close_error = false;
  CHECK(encfs_stop() == 0);
  check_stopped();
  g_upper_fail = 0;
  g_block_cleanup_error = true;
  CHECK(encfs_start() == 0);
  CHECK(encfs_stop() == -EBUSY);
  CHECK(status().state == ENCFS_BLOCK_KEYED && status().block_registered &&
        !status().upper_mounted);
  g_block_cleanup_error = false;
  CHECK(encfs_stop() == 0);
  check_stopped();
}

static void test_provision(void)
{
  int before = g_formats;

  g_formatted = false;
  CHECK(encfs_start() == -EINVAL);
  CHECK(g_formats == before);
  check_stopped();
  CHECK(encfs_provision() == 0);
  CHECK(g_formats == before + 1 && g_initializations == 1);
  check_stopped();
  CHECK(encfs_test_use_board_key() == 0);
  CHECK(encfs_start() == 0);
  CHECK(encfs_stop() == 0);
  check_stopped();
  CHECK(g_hkdf_calls > 0);
}

static void test_external_upper_unmount(void)
{
  CHECK(encfs_start() == 0);
  CHECK(nx_umount2(ENCFS_UPPER_PATH, 0) == 0);
  CHECK(status().state == ENCFS_BLOCK_KEYED && !status().upper_mounted);
  CHECK(encfs_start() == -EBUSY);
  CHECK(encfs_stop() == 0);
  check_stopped();
  CHECK(encfs_start() == 0);
  CHECK(encfs_stop() == 0);
  check_stopped();

  CHECK(encfs_start() == 0);
  CHECK(nx_umount2(ENCFS_UPPER_PATH, 0) == 0);
  g_target_reserved = false;
  CHECK(encfs_start() == -EBUSY);
  CHECK(status().state == ENCFS_BLOCK_KEYED);
  CHECK(encfs_stop() == 0);
  check_stopped();
}

static void test_foreign_upper_preserved(void)
{
  void *previous_handle;

  CHECK(encfs_start() == 0);
  CHECK(nx_umount2(ENCFS_UPPER_PATH, 0) == 0);
  g_target_foreign = true;
  g_target_inode.i_ino = ++g_inode_serial;
  g_target_inode.u.i_mops = &g_foreign_operations;
  g_target_inode.i_private = (void *)++g_mount_serial;
  CHECK(encfs_stop() == 0);
  CHECK(g_target_foreign);
  check_stopped();
  CHECK(encfs_start() == -EBUSY);
  g_target_foreign = false;
  g_target_reserved = false;
  CHECK(encfs_start() == 0);
  CHECK(encfs_stop() == 0);
  check_stopped();

  /* Reuse both addresses/ops for a different inode serial.  A pointer-only
   * identity check must not mistake the foreign mount for the old owner.
   */

  CHECK(encfs_start() == 0);
  previous_handle = g_target_inode.i_private;
  CHECK(nx_umount2(ENCFS_UPPER_PATH, 0) == 0);
  g_target_foreign = true;
  g_target_inode.i_ino = ++g_inode_serial;
  g_target_inode.u.i_mops = &g_upper_operations;
  g_target_inode.i_private = previous_handle;
  CHECK(encfs_stop() == 0);
  CHECK(g_target_foreign);
  check_stopped();
  g_target_foreign = false;
  g_target_reserved = false;
}

static void test_external_lower_unmount(void)
{
  g_upper_fail = 1;
  g_lower_cleanup_error = true;
  CHECK(encfs_start() == -EKEYREJECTED);
  CHECK(status().state == ENCFS_LOWER_MOUNTED);
  g_lower_cleanup_error = false;
  g_upper_fail = 0;
  CHECK(nx_umount2(ENCFS_LOWER_PATH, 0) == 0);
  CHECK(status().state == ENCFS_BLOCK_KEYED && !status().lower_visible);
  g_lower_foreign = true;
  g_lower_inode.i_ino = ++g_inode_serial;
  g_lower_inode.u.i_mops = &g_foreign_operations;
  g_lower_inode.i_private = (void *)++g_mount_serial;
  CHECK(encfs_stop() == 0);
  CHECK(g_lower_foreign);
  check_stopped();
  g_lower_foreign = false;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* External dependency model.  These callbacks assert acquisition order and
 * expose failure modes that are difficult to trigger in a real simulator.
 */

void inode_lock(void)
{
}

void inode_unlock(void)
{
}

int inode_find(struct inode_search_s *desc)
{
  return inode_search(desc);
}

int inode_search(struct inode_search_s *desc)
{
  if (!strcmp(desc->path, ENCFS_LOWER_PATH))
    {
      if (!g_lower && !g_lower_foreign)
        {
          return -ENOENT;
        }

      g_lower_inode.pseudo = false;
      g_lower_inode.mounted = true;
      desc->node = &g_lower_inode;
      desc->relpath = "";
      return 0;
    }

  CHECK(!strcmp(desc->path, ENCFS_UPPER_PATH));
  if (!g_target_reserved && !g_target_foreign)
    {
      return -ENOENT;
    }

  g_target_inode.pseudo = !g_target_foreign && !g_upper;
  g_target_inode.mounted = g_target_foreign || g_upper;
  desc->node = &g_target_inode;
  desc->relpath = "";
  return 0;
}

void inode_release(struct inode *inode)
{
  CHECK(inode == &g_target_inode || inode == &g_lower_inode);
}

int inode_reserve_path(const char *path, mode_t mode, struct inode **inode)
{
  CHECK(!strcmp(path, ENCFS_UPPER_PATH) && mode == 0777);
  if (g_target_allocation_error)
    {
      return -ENOMEM;
    }

  g_target_reserved = true;
  g_target_inode.i_ino = ++g_inode_serial;
  *inode = &g_target_inode;
  return 0;
}

int board_uniquekey(uint8_t *key)
{
  memset(key, 0x4a, ENCFS_MASTER_KEY_SIZE);
  return 0;
}

int hkdf_sha256(const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
                size_t saltlen, const uint8_t *info, size_t infolen,
                uint8_t *out, size_t outlen)
{
  CHECK(ikm && ikmlen == 32 && outlen == 32 && !info && !infolen);
  CHECK((saltlen == 8 && !memcmp(salt, "blkcrypt", 8)) ||
        (saltlen == 9 && !memcmp(salt, "encpathfs", 9)));
  memset(out, ikm[0] ^ salt[0], outlen);
  g_hkdf_calls++;
  return 0;
}

int blkcrypt_register(const char *dev, const char *parent)
{
  CHECK(!strcmp(dev, ENCFS_BLOCK_DEVICE) &&
        !strcmp(parent, ENCFS_PARENT_DEVICE));
  if (g_block)
    {
      return -EEXIST;
    }

  g_block = true;
  return 0;
}

int blkcrypt_set_key(const char *dev, const uint8_t *key, size_t len)
{
  CHECK(g_block && key && len == 32 && !strcmp(dev, ENCFS_BLOCK_DEVICE));
  g_keyed = true;
  return 0;
}

int blkcrypt_unregister(const char *dev)
{
  CHECK(g_block && !g_lower && !g_upper &&
        !strcmp(dev, ENCFS_BLOCK_DEVICE));
  if (g_block_cleanup_error)
    {
      return -EBUSY;
    }

  g_block = false;
  g_keyed = false;
  return 0;
}

int encpathfs_setkey(unsigned int slot, const uint8_t *key, size_t len)
{
  CHECK(slot == 0 && key && len == 32 && !g_upper);
  g_staged = true;
  return 0;
}

int encpathfs_recover(void)
{
  return g_metadata_close_error ? -EIO : 0;
}

int encpathfs_clearkey(unsigned int slot)
{
  CHECK(slot == 0);
  if (g_upper)
    {
      return -EBUSY;
    }

  g_staged = false;
  return 0;
}

int encpathfs_initialize(const char *path, const uint8_t *key, size_t len)
{
  CHECK(g_lower && !strcmp(path, ENCFS_LOWER_PATH) && key && len == 32);
  g_initializations++;
  return 0;
}

int nx_mount(const char *source, const char *target, const char *filesystem,
             unsigned long flags, const void *data)
{
  CHECK(!flags);
  if (!strcmp(filesystem, "fatfs"))
    {
      CHECK(g_block && g_keyed && !g_lower && !g_upper &&
            !strcmp(source, ENCFS_BLOCK_DEVICE) &&
            !strcmp(target, ENCFS_LOWER_PATH));
      if (data)
        {
          CHECK(!strcmp(data, "forceformat"));
          g_formats++;
          g_formatted = true;
        }

      if (!g_formatted)
        {
          return -EINVAL;
        }

      g_lower = true;
      g_lower_inode.i_ino = ++g_inode_serial;
      g_lower_inode.u.i_mops = &g_lower_operations;
      g_lower_inode.i_private = (void *)++g_mount_serial;
      return 0;
    }

  CHECK(!source && g_lower && g_staged && g_target_reserved &&
        !strcmp(filesystem, "encpathfs") &&
        !strcmp(target, ENCFS_UPPER_PATH) &&
        !strcmp(data, "lower=/datap,root=.p,slot=0"));
  g_staged = false;
  if (g_upper_fail == 1)
    {
      return -EKEYREJECTED;
    }

  g_lower = false;
  if (g_upper_fail == 2)
    {
      /* A simulated failure after bind consumed and released the lower. */

      return -ENOMEM;
    }

  g_upper = true;
  g_target_inode.u.i_mops = &g_upper_operations;
  g_target_inode.i_private = (void *)++g_mount_serial;
  return 0;
}

int nx_umount2(const char *target, unsigned int flags)
{
  CHECK(!flags);
  if (!strcmp(target, ENCFS_UPPER_PATH))
    {
      CHECK(g_upper);
      if (g_busy)
        {
          return -EBUSY;
        }

      g_upper = false;
      return 0;
    }

  CHECK(!strcmp(target, ENCFS_LOWER_PATH) && g_lower);
  if (g_lower_cleanup_error)
    {
      return -EIO;
    }

  g_lower = false;
  return 0;
}

int nx_stat(const char *path, struct stat *st, int resolve)
{
  CHECK(!strcmp(path, ENCFS_LOWER_PATH));
  return g_lower ? 0 : -ENOENT;
}

int main(void)
{
  test_missing_master();
  test_target_reservation();
  test_failpoints();
  test_busy_stop();
  test_upper_failures();
  test_cleanup_failures();
  test_provision();
  test_external_upper_unmount();
  test_foreign_upper_preserved();
  test_external_lower_unmount();
  printf("encfs manager lifecycle: PASS (%u assertions)\n", g_checks);
  return EXIT_SUCCESS;
}

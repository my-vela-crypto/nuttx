/****************************************************************************
 * tools/tests/encfs_crypto/test_blkcrypt.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

/* Include the production source to reach its registered block operations.
 * AES and XTS are linked from their unchanged production source files.
 */

#include TEST_BLKCRYPT_SOURCE

/****************************************************************************
 * Private Data
 ****************************************************************************/

static pthread_rwlock_t g_tree = PTHREAD_RWLOCK_INITIALIZER;
static _Thread_local bool g_tree_owned;
static struct inode g_parent =
{
  .i_crefs = 1
};
static struct inode *g_node;
static atomic_int g_allocations;
static atomic_int g_fail_alloc;
static atomic_int g_fail_open;
static atomic_int g_fail_close;
static atomic_int g_notifications;
static atomic_int g_busy;
static atomic_int g_removed;
static uint8_t g_disk[4 * 512];
static uint8_t g_key[BLKCRYPT_KEY_SIZE];

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void *test_zalloc(size_t size)
{
  void *p;

  if (atomic_exchange(&g_fail_alloc, 0))
    {
      return NULL;
    }

  p = calloc(1, size);
  assert(p != NULL);
  atomic_fetch_add(&g_allocations, 1);
  return p;
}

void *test_memalign(size_t align, size_t size)
{
  void *p;

  assert(posix_memalign(&p, align, size) == 0);
  atomic_fetch_add(&g_allocations, 1);
  return p;
}

void test_free(void *p)
{
  if (p != NULL)
    {
      atomic_fetch_sub(&g_allocations, 1);
      free(p);
    }
}

void inode_lock(void)
{
  assert(!g_tree_owned);
  assert(pthread_rwlock_wrlock(&g_tree) == 0);
  g_tree_owned = true;
}

void inode_unlock(void)
{
  assert(g_tree_owned);
  g_tree_owned = false;
  assert(pthread_rwlock_unlock(&g_tree) == 0);
}

void inode_addref(struct inode *inode)
{
  assert(__atomic_fetch_add(&inode->i_crefs, 1, __ATOMIC_SEQ_CST) > 0);
}

void inode_release(struct inode *inode)
{
  int old = __atomic_fetch_sub(&inode->i_crefs, 1, __ATOMIC_SEQ_CST);

  assert(old > 0);
  if (old == 1)
    {
      assert(inode != &g_parent);
      assert(inode->i_private == NULL);
      free(inode);
    }
}

int find_blockdriver(const char *path, int flags, struct inode **result)
{
  struct inode *node;

  (void)flags;
  assert(!g_tree_owned);
  assert(pthread_rwlock_rdlock(&g_tree) == 0);
  node = strcmp(path, BLKCRYPT_PARENT_DEFAULT) == 0 ? &g_parent : g_node;
  if (node != NULL)
    {
      inode_addref(node);
      *result = node;
    }

  assert(pthread_rwlock_unlock(&g_tree) == 0);
  return node == NULL ? -ENOENT : 0;
}

int register_blockdriver(const char *path,
                         const struct block_operations *ops,
                         mode_t mode, void *priv)
{
  (void)path;
  (void)mode;
  inode_lock();
  if (g_node != NULL)
    {
      inode_unlock();
      return -EEXIST;
    }

  g_node = calloc(1, sizeof(*g_node));
  assert(g_node != NULL);
  g_node->i_crefs = 1;
  g_node->i_private = priv;
  g_node->u.i_bops = ops;
  inode_unlock();
  return 0;
}

int inode_remove(const char *path)
{
  struct inode *node = g_node;

  (void)path;
  assert(g_tree_owned);
  if (node == NULL)
    {
      return -ENOENT;
    }

  g_node = NULL;
  assert(__atomic_fetch_sub(&node->i_crefs, 1, __ATOMIC_SEQ_CST) >= 2);
  return -EBUSY;
}

void notify_unlink(const char *path)
{
  (void)path;
  atomic_fetch_add(&g_notifications, 1);
}

static int parent_open(struct inode *inode)
{
  (void)inode;
  return atomic_exchange(&g_fail_open, 0) ? -EIO : 0;
}

static int parent_close(struct inode *inode)
{
  (void)inode;
  return atomic_exchange(&g_fail_close, 0) ? -EIO : 0;
}

static int parent_geometry(struct inode *inode, struct geometry *geo)
{
  (void)inode;
  geo->geo_available = true;
  geo->geo_nsectors = 4;
  geo->geo_sectorsize = 512;
  return 0;
}

static ssize_t parent_read(struct inode *inode, unsigned char *buffer,
                            blkcnt_t sector, unsigned int count)
{
  (void)inode;
  assert(sector >= 0 && sector + count <= 4);
  memcpy(buffer, g_disk + sector * 512, count * 512);
  return count;
}

static ssize_t parent_write(struct inode *inode, const unsigned char *buffer,
                             blkcnt_t sector, unsigned int count)
{
  (void)inode;
  assert(sector >= 0 && sector + count <= 4);
  memcpy(g_disk + sector * 512, buffer, count * 512);
  return count;
}

static const struct block_operations g_parent_ops =
{
  .open = parent_open,
  .close = parent_close,
  .read = parent_read,
  .write = parent_write,
  .geometry = parent_geometry
};

static void verify_read(const uint8_t *expected)
{
  struct inode *node;
  uint8_t output[512];

  assert(find_blockdriver(BLKCRYPT_DEV_DEFAULT, 0, &node) == 0);
  assert(node->u.i_bops->open(node) == 0);
  assert(node->u.i_bops->read(node, output, 0, 1) == 1);
  assert(memcmp(output, expected, sizeof(output)) == 0);
  assert(node->u.i_bops->close(node) == 0);
  inode_release(node);
}

static void *open_worker(void *arg)
{
  struct inode *node;
  uint8_t output[512];
  int i;
  int ret;

  (void)arg;
  for (i = 0; i < 5000; i++)
    {
      ret = find_blockdriver(BLKCRYPT_DEV_DEFAULT, 0, &node);
      if (ret == -ENOENT)
        {
          continue;
        }

      assert(ret == 0);
      assert(node->u.i_bops->open(node) == 0);
      ret = node->u.i_bops->read(node, output, 0, 1);
      assert(ret == 1 || ret == -EACCES);
      assert(node->u.i_bops->close(node) == 0);
      inode_release(node);
    }

  return NULL;
}

int main(void)
{
  struct inode *node;
  struct blkcrypt_priv_s *dev;
  pthread_t workers[2];
  uint8_t plain[512];
  uint8_t samehalves[BLKCRYPT_KEY_SIZE];
  int ret;
  int i;

  g_parent.u.i_bops = &g_parent_ops;
  for (i = 0; i < BLKCRYPT_KEY_SIZE; i++)
    {
      g_key[i] = i;
    }

  memset(plain, 0x47, sizeof(plain));
  memset(samehalves, 0x77, sizeof(samehalves));
  assert(blkcrypt_register(BLKCRYPT_DEV_DEFAULT,
                            BLKCRYPT_PARENT_DEFAULT) == 0);
  assert(blkcrypt_register(BLKCRYPT_DEV_DEFAULT,
                            BLKCRYPT_PARENT_DEFAULT) == -EEXIST);
  assert(atomic_load(&g_allocations) == 2);
  assert(atomic_read(&g_parent.i_crefs) == 2);
  assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, g_key, sizeof(g_key)) == 0);
  assert(find_blockdriver(BLKCRYPT_DEV_DEFAULT, 0, &node) == 0);
  atomic_store(&g_fail_open, 1);
  assert(node->u.i_bops->open(node) == -EIO);
  dev = node->i_private;
  assert(dev->opens == 0);
  assert(node->u.i_bops->open(node) == 0);
  assert(node->u.i_bops->write(node, plain, 0, 1) == 1);
  assert(memcmp(g_disk, plain, sizeof(plain)) != 0);
  assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, samehalves,
                           sizeof(samehalves)) == -EBUSY);
  assert(node->u.i_bops->ioctl(node, DIOC_SETKEY,
                              (unsigned long)g_key) == -EBUSY);
  assert(blkcrypt_unregister(BLKCRYPT_DEV_DEFAULT) == -EBUSY);
  inode_addref(node); /* nx_unlink's lookup, in addition to the open handle */
  assert(node->u.i_bops->unlink(node) == -EBUSY);
  inode_release(node);
  assert(g_node == node && node->i_private == dev);
  atomic_store(&g_fail_close, 1);
  assert(node->u.i_bops->close(node) == -EIO);
  assert(dev->opens == 0);
  inode_release(node);
  assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, g_key, 31) == -EINVAL);
  assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, samehalves,
                           sizeof(samehalves)) == -EINVAL);
  atomic_store(&g_fail_alloc, 1);
  assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, g_key,
                           sizeof(g_key)) == -ENOMEM);
  verify_read(plain);
  assert(blkcrypt_unregister(BLKCRYPT_DEV_DEFAULT) == 0);
  assert(g_node == NULL);
  assert(atomic_load(&g_allocations) == 0);
  assert(atomic_read(&g_parent.i_crefs) == 1);
  assert(blkcrypt_unregister(BLKCRYPT_DEV_DEFAULT) == -ENOENT);
  puts("PASS busy key replacement/ioctl/unlink/unregister; invalid-key and");
  puts("     allocation failure preserves keys; parent open/close errors");

  /* A raw ioctl may install the first key before the device has any data. */

  assert(blkcrypt_register(BLKCRYPT_DEV_DEFAULT,
                            BLKCRYPT_PARENT_DEFAULT) == 0);
  assert(find_blockdriver(BLKCRYPT_DEV_DEFAULT, 0, &node) == 0);
  assert(node->u.i_bops->open(node) == 0);
  assert(node->u.i_bops->ioctl(node, DIOC_SETKEY,
                              (unsigned long)g_key) == 0);
  assert(node->u.i_bops->close(node) == 0);
  assert(node->u.i_bops->unlink(node) == 0);
  assert(node->i_private == NULL);
  inode_lock();
  assert(inode_remove(BLKCRYPT_DEV_DEFAULT) == -EBUSY);
  inode_unlock();
  inode_release(node);
  assert(atomic_load(&g_allocations) == 0);
  assert(atomic_read(&g_parent.i_crefs) == 1);
  puts("PASS first-key ioctl, safe idle unlink, exact resource release");

  assert(blkcrypt_register(BLKCRYPT_DEV_DEFAULT,
                            BLKCRYPT_PARENT_DEFAULT) == 0);
  assert(pthread_create(&workers[0], NULL, open_worker, NULL) == 0);
  assert(pthread_create(&workers[1], NULL, open_worker, NULL) == 0);
  for (i = 0; i < 2000; i++)
    {
      ret = blkcrypt_unregister(BLKCRYPT_DEV_DEFAULT);
      if (ret == -EBUSY)
        {
          atomic_fetch_add(&g_busy, 1);
          assert(g_node != NULL);
        }
      else
        {
          assert(ret == 0);
          atomic_fetch_add(&g_removed, 1);
          assert(blkcrypt_register(BLKCRYPT_DEV_DEFAULT,
                                    BLKCRYPT_PARENT_DEFAULT) == 0);
          assert(blkcrypt_set_key(BLKCRYPT_DEV_DEFAULT, g_key,
                                   sizeof(g_key)) == 0);
        }
    }

  assert(pthread_join(workers[0], NULL) == 0);
  assert(pthread_join(workers[1], NULL) == 0);
  assert(blkcrypt_unregister(BLKCRYPT_DEV_DEFAULT) == 0);
  assert(g_node == NULL);
  assert(atomic_load(&g_allocations) == 0);
  assert(atomic_read(&g_parent.i_crefs) == 1);
  assert(atomic_load(&g_notifications) == atomic_load(&g_removed) + 2);
  printf("PASS 10000 concurrent open/read/close cycles vs 2000 unregister");
  printf(" attempts (%d busy, %d safely removed), ASan+UBSan\n",
         atomic_load(&g_busy), atomic_load(&g_removed));
  return 0;
}

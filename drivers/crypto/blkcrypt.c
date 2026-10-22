/****************************************************************************
 * drivers/crypto/blkcrypt.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * 块加密驱动。
 *
 * 它在 FAT 和真实磁盘中间加了一扇门：
 *   - FAT 说“把第 N 格原文给我”，这里先从底下读出密文，再解密。
 *   - FAT 说“把这块原文写进第 N 格”，这里先抄到自己的草稿纸上加密，
 *     再把草稿纸交给底下的盘。FAT 手里的原文不会被改掉。
 *   - 格子有多少、每格多大，都原样沿用底下的盘，所以 FAT 不用改。
 *
 * 写法模仿 fs/driver/fs_blockpartition.c：自己不存盘，只拿着底下那块盘
 * 的登记卡（inode），把读和写转交给它。
 *
 * 给上层的接口只有头文件里的三个函数。路径加密不调用它们。
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <debug.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <nuttx/atomic.h>
#include <nuttx/fs/fs.h>
#include <nuttx/fs/ioctl.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mutex.h>
#include <nuttx/crypto/blkcrypt.h>

#include "blkcrypt_xts.h"

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* 每一块加密盘一份笔记。两块盘就可以用两把不同的钥匙。 */

struct blkcrypt_priv_s
{
  FAR struct inode *parent;   /* 底下那块盘的登记卡，本设备长期拿着一份 */
  blkcnt_t          nsectors; /* 一共有多少格，和底下的盘相同 */
  blksize_t         sectorsize; /* 一格多少字节，也是一次加密的长度 */
  mutex_t           lock;     /* 同一时刻只允许一个人使用钥匙和草稿纸 */
  bool              key_set;  /* 钥匙装好了才允许读和写 */

  AES_CTX           key1;     /* K1 的计算表：加密、解密格子内容 */
  AES_CTX           key2;     /* K2 的计算表：只加密格子号 */

  FAR uint8_t      *bounce;   /* 写盘用的草稿纸，长度等于一格 */
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/* 登记卡的“使用人数”增减。公开头文件没有声明它们，
 * 分区驱动在文件系统内部直接调用。这里是驱动目录，所以自己声明一次。
 * 链接时和文件系统里的实现接在一起。
 */

void inode_addref(FAR struct inode *inode);
void inode_release(FAR struct inode *inode);

static int     blkcrypt_open(FAR struct inode *inode);
static int     blkcrypt_close(FAR struct inode *inode);
static ssize_t blkcrypt_read(FAR struct inode *inode,
                             FAR unsigned char *buffer,
                             blkcnt_t start_sector, unsigned int nsectors);
static ssize_t blkcrypt_write(FAR struct inode *inode,
                              FAR const unsigned char *buffer,
                              blkcnt_t start_sector, unsigned int nsectors);
static int     blkcrypt_geometry(FAR struct inode *inode,
                                 FAR struct geometry *geometry);
static int     blkcrypt_ioctl(FAR struct inode *inode, int cmd,
                              unsigned long arg);
#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
static int     blkcrypt_unlink(FAR struct inode *inode);
#endif

static int  blkcrypt_install_key(FAR struct blkcrypt_priv_s *dev,
                                 FAR const uint8_t *key, size_t keylen);
static void blkcrypt_destroy(FAR struct blkcrypt_priv_s *dev);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* 系统不关心函数名字，只按这张表的位置来叫：
 * 打开、关闭、读、写、查询大小、特殊命令。
 */

static const struct block_operations g_blkcrypt_bops =
{
  blkcrypt_open,
  blkcrypt_close,
  blkcrypt_read,
  blkcrypt_write,
  blkcrypt_geometry,
  blkcrypt_ioctl
#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
  , blkcrypt_unlink
#endif
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: blkcrypt_install_key
 *
 * Description:
 *   在已经拿着门锁的前提下装钥匙。
 *   装失败时把“可以读写”关掉，并擦掉算了一半的表，避免留下半把旧钥匙。
 *
 ****************************************************************************/

static int blkcrypt_install_key(FAR struct blkcrypt_priv_s *dev,
                                FAR const uint8_t *key, size_t keylen)
{
  int ret;

  ret = blkcrypt_xts_setkey(&dev->key1, &dev->key2, key, keylen);
  if (ret < 0)
    {
      explicit_bzero(&dev->key1, sizeof(dev->key1));
      explicit_bzero(&dev->key2, sizeof(dev->key2));
      dev->key_set = false;
      return ret;
    }

  dev->key_set = true;
  return OK;
}

/****************************************************************************
 * Name: blkcrypt_destroy
 *
 * Description:
 *   擦掉钥匙和草稿纸，放开底下那块盘，再释放这份笔记。
 *   只在设备已经从名单上摘掉、没有人正在读写时调用。
 *
 ****************************************************************************/

static void blkcrypt_destroy(FAR struct blkcrypt_priv_s *dev)
{
  if (dev == NULL)
    {
      return;
    }

  explicit_bzero(&dev->key1, sizeof(dev->key1));
  explicit_bzero(&dev->key2, sizeof(dev->key2));
  dev->key_set = false;

  if (dev->bounce != NULL)
    {
      explicit_bzero(dev->bounce, dev->sectorsize);
      kmm_free(dev->bounce);
      dev->bounce = NULL;
    }

  if (dev->parent != NULL)
    {
      inode_release(dev->parent);
      dev->parent = NULL;
    }

  nxmutex_destroy(&dev->lock);
  explicit_bzero(dev, sizeof(*dev));
  kmm_free(dev);
}

/****************************************************************************
 * Name: blkcrypt_check_range
 *
 * Description:
 *   检查 FAT 要的格子有没有超出这块盘。
 *   要 0 格是合法的，调用者看到 0 就直接返回，不去碰磁盘。
 *   超出范围返回 -EINVAL，不悄悄少读几格。
 *
 ****************************************************************************/

static int blkcrypt_check_range(FAR struct blkcrypt_priv_s *dev,
                                blkcnt_t start_sector,
                                unsigned int nsectors)
{
  if (nsectors == 0)
    {
      return OK;
    }

  if (start_sector >= dev->nsectors ||
      (blkcnt_t)nsectors > (dev->nsectors - start_sector))
    {
      return -EINVAL;
    }

  return OK;
}

/****************************************************************************
 * Name: blkcrypt_open / blkcrypt_close
 *
 * Description:
 *   FAT 挂载时会先打开这块盘，卸载时关闭。
 *   这里把打开和关闭原样转告底下的盘。虚拟硬盘的打开目前直接表示成功。
 *   这一步不检查钥匙：查询大小在装钥匙之前也要能用。
 *
 ****************************************************************************/

static int blkcrypt_open(FAR struct inode *inode)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;

  if (inode == NULL || inode->i_private == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  parent = dev->parent;

  if (parent != NULL && parent->u.i_bops != NULL &&
      parent->u.i_bops->open != NULL)
    {
      return parent->u.i_bops->open(parent);
    }

  return OK;
}

static int blkcrypt_close(FAR struct inode *inode)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;

  if (inode == NULL || inode->i_private == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  parent = dev->parent;

  if (parent != NULL && parent->u.i_bops != NULL &&
      parent->u.i_bops->close != NULL)
    {
      return parent->u.i_bops->close(parent);
    }

  return OK;
}

/****************************************************************************
 * Name: blkcrypt_read
 *
 * Description:
 *   FAT 要原文。先让底下的盘把密文读进 FAT 给的内存，再按格子号解密。
 *   成功时返回的是格子个数，不是字节数。虚拟硬盘也是这样返回的，
 *   FAT 用“返回值是不是等于我要的格子数”来判断成功。
 *
 *   还没装钥匙时直接拒绝，不去读磁盘。这样 FAT 挂载会得到明确的失败，
 *   而不是把密文当成磁盘开头的说明去猜。
 *
 ****************************************************************************/

static ssize_t blkcrypt_read(FAR struct inode *inode,
                             FAR unsigned char *buffer,
                             blkcnt_t start_sector, unsigned int nsectors)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;
  unsigned int i;
  ssize_t ret;

  if (inode == NULL || inode->i_private == NULL || buffer == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  ret = nxmutex_lock(&dev->lock);
  if (ret < 0)
    {
      return ret;
    }

  if (!dev->key_set)
    {
      ret = -EACCES;
      goto out;
    }

  ret = blkcrypt_check_range(dev, start_sector, nsectors);
  if (ret < 0 || nsectors == 0)
    {
      goto out;
    }

  parent = dev->parent;
  ret = parent->u.i_bops->read(parent, buffer, start_sector, nsectors);
  if (ret < 0)
    {
      goto out;
    }

  /* 少读了几格时，后面的内存可能是空的，不能拿去解密。 */

  if ((unsigned int)ret != nsectors)
    {
      ret = -EIO;
      goto out;
    }

  for (i = 0; i < nsectors; i++)
    {
      size_t offset = (size_t)i * (size_t)dev->sectorsize;

      ret = blkcrypt_xts_decrypt(&dev->key1, &dev->key2,
                                 buffer + offset, dev->sectorsize,
                                 start_sector + i);
      if (ret < 0)
        {
          goto out;
        }
    }

  ret = nsectors;

out:
  nxmutex_unlock(&dev->lock);
  return ret;
}

/****************************************************************************
 * Name: blkcrypt_write
 *
 * Description:
 *   FAT 交来的内存里是原文，而且它可能还要继续使用这块内存。
 *   所以先抄到自己的草稿纸上，在草稿纸上加密，再把草稿纸交给底下的盘。
 *   一次写很多格时，前面的格子可能已经写成密文，后面某一格才失败。
 *   这时返回错误，不把前面几格撤销。这和普通磁盘的行为一样。
 *
 ****************************************************************************/

static ssize_t blkcrypt_write(FAR struct inode *inode,
                              FAR const unsigned char *buffer,
                              blkcnt_t start_sector, unsigned int nsectors)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;
  unsigned int i;
  ssize_t ret;

  if (inode == NULL || inode->i_private == NULL || buffer == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  ret = nxmutex_lock(&dev->lock);
  if (ret < 0)
    {
      return ret;
    }

  if (!dev->key_set)
    {
      ret = -EACCES;
      goto out;
    }

  ret = blkcrypt_check_range(dev, start_sector, nsectors);
  if (ret < 0 || nsectors == 0)
    {
      goto out;
    }

  parent = dev->parent;

  for (i = 0; i < nsectors; i++)
    {
      size_t offset = (size_t)i * (size_t)dev->sectorsize;

      memcpy(dev->bounce, buffer + offset, dev->sectorsize);
      ret = blkcrypt_xts_encrypt(&dev->key1, &dev->key2, dev->bounce,
                                 dev->sectorsize, start_sector + i);
      if (ret < 0)
        {
          goto out_bounce;
        }

      ret = parent->u.i_bops->write(parent, dev->bounce,
                                    start_sector + i, 1);
      if (ret < 0)
        {
          goto out_bounce;
        }

      if (ret != 1)
        {
          ret = -EIO;
          goto out_bounce;
        }
    }

  ret = nsectors;

out_bounce:
  explicit_bzero(dev->bounce, dev->sectorsize);

out:
  nxmutex_unlock(&dev->lock);
  return ret;
}

/****************************************************************************
 * Name: blkcrypt_geometry
 *
 * Description:
 *   把底下那块盘的说明书原样交回去。
 *   不改格子总数，也不改每格大小。加密前后一格一样大，FAT 才能对上。
 *   没装钥匙时也允许查询，否则这块盘会像根本不存在。
 *
 ****************************************************************************/

static int blkcrypt_geometry(FAR struct inode *inode,
                             FAR struct geometry *geometry)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;

  if (inode == NULL || inode->i_private == NULL || geometry == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  parent = dev->parent;

  if (parent == NULL || parent->u.i_bops == NULL ||
      parent->u.i_bops->geometry == NULL)
    {
      return -ENOSYS;
    }

  return parent->u.i_bops->geometry(parent, geometry);
}

/****************************************************************************
 * Name: blkcrypt_ioctl
 *
 * Description:
 *   特殊命令。
 *   DIOC_SETKEY：参数指向 32 字节钥匙，本层自己装上。
 *   BIOC_XIPBASE：意思是“请让我直接看见磁盘内存”。必须拒绝，
 *   否则调用者会绕过这扇门。
 *   其余命令，底下的盘认识就转告，不认识就返回 -ENOTTY。
 *
 ****************************************************************************/

static int blkcrypt_ioctl(FAR struct inode *inode, int cmd,
                          unsigned long arg)
{
  FAR struct blkcrypt_priv_s *dev;
  FAR struct inode *parent;
  int ret;

  if (inode == NULL || inode->i_private == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;

  if (cmd == DIOC_SETKEY)
    {
      if (arg == 0)
        {
          return -EINVAL;
        }

      ret = nxmutex_lock(&dev->lock);
      if (ret < 0)
        {
          return ret;
        }

      ret = blkcrypt_install_key(dev, (FAR const uint8_t *)(uintptr_t)arg,
                                 BLKCRYPT_KEY_SIZE);
      nxmutex_unlock(&dev->lock);
      return ret;
    }

  if (cmd == BIOC_XIPBASE)
    {
      return -ENOTTY;
    }

  parent = dev->parent;
  if (parent != NULL && parent->u.i_bops != NULL &&
      parent->u.i_bops->ioctl != NULL)
    {
      return parent->u.i_bops->ioctl(parent, cmd, arg);
    }

  return -ENOTTY;
}

/****************************************************************************
 * Name: blkcrypt_unlink
 *
 * Description:
 *   有人用 unlink 摘掉 /dev/encdata0 时，系统会叫到这里。
 *   笔记在这里释放。unregister_blockdriver 那条路不会叫到这里，
 *   所以 blkcrypt_unregister 里还会再释放一次；两条路不会同时发生。
 *
 ****************************************************************************/

#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
static int blkcrypt_unlink(FAR struct inode *inode)
{
  FAR struct blkcrypt_priv_s *dev;

  if (inode == NULL)
    {
      return -EINVAL;
    }

  dev = inode->i_private;
  inode->i_private = NULL;
  blkcrypt_destroy(dev);
  return OK;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: blkcrypt_register
 *
 * Description:
 *   创建一块加密盘，例如把 "/dev/encdata0" 挂到名单上，并让它站在
 *   "/dev/virtblk1" 前面。这一步只搭架子，不装钥匙。
 *
 *   架子包括四样东西：
 *     1. 底下那块盘的登记卡。以后读、写都拿这张卡去叫虚拟硬盘。
 *     2. 一格有多大、一共有多少格。加密不改变这两个数字。
 *     3. 一张草稿纸。写盘时先在上面加密，避免改掉 FAT 手里的原文。
 *     4. 一把门锁。装钥匙和读写不能同时进行。
 *
 *   登记卡上有“使用人数”。人数减到 0，系统就会把这张卡扔掉。
 *   查找底下的盘时，系统会临时把人数加 1。加密盘要长期拿着这张卡，
 *   所以这里再加 1。函数成功返回前，把查找时加的那 1 还掉，
 *   长期的那 1 留在 dev->parent 里，等拆除加密盘时再还。
 *
 *   中途任何一步失败，都要按“加过几次就还几次”把人数还回去，
 *   已经申请的草稿纸和笔记也要释放，否则这块盘没创建成功也会占着资源。
 *
 ****************************************************************************/

int blkcrypt_register(FAR const char *encdev, FAR const char *parent)
{
  FAR struct inode *parent_inode = NULL;
  FAR struct blkcrypt_priv_s *dev = NULL;
  struct geometry geo;
  bool extra_ref = false;
  bool lock_ready = false;
  int ret;

  /* 两个名字都必须是非空字符串。空指针或 "" 无法到 /dev 里查找。 */

  if (encdev == NULL || parent == NULL ||
      encdev[0] == '\0' || parent[0] == '\0')
    {
      return -EINVAL;
    }

  /* 按名字找到底下的盘，例如 "/dev/virtblk1"。
   * 第二个参数 0 表示：这块盘必须能写。只读盘不能当加密盘的下层，
   * 因为 FAT 格式化和写文件都要往下写。
   * 找到时 parent_inode 就是那张登记卡，并且使用人数已经被加了 1。
   * 找不到会得到负数：盘还不存在是 -ENOENT，路径不是磁盘是 -ENOTBLK。
   * 这条失败路径还没拿到卡，所以不用还人数，直接返回。
   */

  ret = find_blockdriver(parent, 0, &parent_inode);
  if (ret < 0)
    {
      ferr("blkcrypt: 找不到底下的盘 %s: %d\n", parent, ret);
      return ret;
    }

  /* 申请这份加密盘自己的笔记，并清成 0。
   * 清零后 key_set 是假，表示还没装钥匙；bounce 是空，表示草稿纸还没申请。
   * 申请失败时，查找加的那 1 个人数还没还，要跳到 errout_parent 还掉。
   */

  dev = kmm_zalloc(sizeof(*dev));
  if (dev == NULL)
    {
      ret = -ENOMEM;
      goto errout_parent;
    }

  /* 再把使用人数加 1，这份算加密盘长期持有的。
   * dev->parent 和 parent_inode 指向同一张卡。
   * extra_ref 用来记住“长期的这一份已经加上了”。
   * 失败清理时要把它单独还掉；成功时则留着，不在函数末尾还。
   */

  inode_addref(parent_inode);
  extra_ref = true;
  dev->parent = parent_inode;

  /* 值班表必须能查询大小、读、写。
   * 少任何一项，这块盘就没法被 FAT 当成普通磁盘来用。
   * -ENOSYS 表示“这个设备没有我们需要的功能”。
   */

  if (parent_inode->u.i_bops == NULL ||
      parent_inode->u.i_bops->geometry == NULL ||
      parent_inode->u.i_bops->read == NULL ||
      parent_inode->u.i_bops->write == NULL)
    {
      ret = -ENOSYS;
      goto errout_dev;
    }

  /* 向底下的盘要说明书：现在能不能用、一格多少字节、一共多少格。
   * 这些数字原样记进笔记。加密不把一格变大，也不把盘变小，
   * 这样 FAT 不用知道自己前面多了一层加密。
   */

  ret = parent_inode->u.i_bops->geometry(parent_inode, &geo);
  if (ret < 0)
    {
      goto errout_dev;
    }

  /* 拒绝三种不能加密的盘：
   *   - 介质不在（geo_available 为假），后面的读写没有意义。
   *   - 一格不到 16 字节，或者不能被 16 整除。XTS 按 16 字节一小块来切，
   *     切不完就没有实现“最后一小块不足 16 字节”的拼接。
   *     goldfish 的虚拟硬盘通常是 512，512 / 16 = 32，正好切完。
   *   - 总格数是 0，等于没有磁盘。
   */

  if (!geo.geo_available || geo.geo_sectorsize < BLKCRYPT_AES_BLOCK ||
      (geo.geo_sectorsize % BLKCRYPT_AES_BLOCK) != 0 ||
      geo.geo_nsectors == 0)
    {
      ferr("blkcrypt: 格子大小 %u 不能加密\n",
           (unsigned int)geo.geo_sectorsize);
      ret = -EINVAL;
      goto errout_dev;
    }

  dev->sectorsize = geo.geo_sectorsize;
  dev->nsectors = geo.geo_nsectors;

  /* 申请一张和“一格”一样大的草稿纸，地址对齐到 64 字节。
   * 写盘时虚拟硬盘会把这块内存直接放进传输队列，队列希望地址是整齐的。
   * 现在就申请，是为了以后每一次写盘都用同一张纸。
   * 如果拖到写盘时再申请，那一次写可能因为内存不够而失败。
   * kmm_zalloc 把 bounce 清成了空，所以申请失败时它仍是 NULL，清理时不会误释放。
   */

  dev->bounce = kmm_memalign(64, dev->sectorsize);
  if (dev->bounce == NULL)
    {
      ret = -ENOMEM;
      goto errout_dev;
    }

  /* 准备门锁。同一块加密盘的装钥匙、读、写都要先拿到它，
   * 避免换钥匙发生在某一格加密到一半的时候，也避免两个人同时写同一张草稿纸。
   * lock_ready 记住门锁是否已经初始化。没初始化成功就去销毁，会碰到无效的锁。
   */

  ret = nxmutex_init(&dev->lock);
  if (ret < 0)
    {
      goto errout_dev;
    }

  lock_ready = true;

  /* 把名字挂到 /dev 下面。0660 表示拥有者和同组可以读写。
   * 第三个参数是值班表：系统以后对这个名字做读、写、查询大小时，
   * 会叫到本文件里的 blkcrypt_read 等函数。
   * 第四个参数 dev 放进登记卡的抽屉 i_private，那些函数靠它找到笔记。
   * 名字已经存在时，这里返回 -EEXIST。
   */

  ret = register_blockdriver(encdev, &g_blkcrypt_bops, 0660, dev);
  if (ret < 0)
    {
      ferr("blkcrypt: 创建 %s 失败: %d\n", encdev, ret);
      goto errout_dev;
    }

  /* 成功。查找时加的那 1 个人数在这里还掉。
   * dev->parent 里还留着后面加的那 1，加密盘存在期间一直拿着底下那块盘。
   * 注意还掉的是“人数”，指针本身仍然有效，因为另一份人数还在。
   */

  inode_release(parent_inode);
  return OK;

  /* 创建失败：笔记、草稿纸、门锁、长期人数都可能只完成了一部分。
   * 下面按“后申请的先释放”收拾。收拾完再落到 errout_parent，
   * 把查找时加的那 1 个人数还掉。
   */

errout_dev:
  if (lock_ready)
    {
      nxmutex_destroy(&dev->lock);
    }

  /* 草稿纸里还没有用户数据，这里仍擦一遍再释放，和拆除设备时的做法一致。 */

  if (dev->bounce != NULL)
    {
      explicit_bzero(dev->bounce, dev->sectorsize);
      kmm_free(dev->bounce);
    }

  /* 只有已经执行过 inode_addref 才还这一份。
   * 和下面 errout_parent 的那一次是两笔不同的账：一笔是长期持有，一笔是查找。
   */

  if (extra_ref)
    {
      inode_release(dev->parent);
    }

  explicit_bzero(dev, sizeof(*dev));
  kmm_free(dev);

errout_parent:

  /* 还掉 find_blockdriver 加上的那 1 个人数。
   * 走到这里时，加密盘的名字没有挂上，调用者不会再看到 dev。
   */

  inode_release(parent_inode);
  return ret;
}

/****************************************************************************
 * Name: blkcrypt_set_key
 ****************************************************************************/

int blkcrypt_set_key(FAR const char *encdev, FAR const uint8_t *key,
                     size_t keylen)
{
  FAR struct inode *inode;
  FAR struct blkcrypt_priv_s *dev;
  int ret;

  if (encdev == NULL || key == NULL)
    {
      return -EINVAL;
    }

  ret = find_blockdriver(encdev, 0, &inode);
  if (ret < 0)
    {
      return ret;
    }

  /* 确认这张登记卡确实是本驱动的，避免把钥匙写进虚拟硬盘。 */

  if (inode->u.i_bops != &g_blkcrypt_bops || inode->i_private == NULL)
    {
      inode_release(inode);
      return -EINVAL;
    }

  dev = inode->i_private;
  ret = nxmutex_lock(&dev->lock);
  if (ret < 0)
    {
      inode_release(inode);
      return ret;
    }

  ret = blkcrypt_install_key(dev, key, keylen);
  nxmutex_unlock(&dev->lock);
  inode_release(inode);
  return ret;
}

/****************************************************************************
 * Name: blkcrypt_unregister
 ****************************************************************************/

int blkcrypt_unregister(FAR const char *encdev)
{
  FAR struct inode *inode;
  FAR struct blkcrypt_priv_s *dev;
  int ret;

  if (encdev == NULL)
    {
      return -EINVAL;
    }

  ret = find_blockdriver(encdev, 0, &inode);
  if (ret < 0)
    {
      return ret;
    }

  if (inode->u.i_bops != &g_blkcrypt_bops || inode->i_private == NULL)
    {
      inode_release(inode);
      return -EINVAL;
    }

  dev = inode->i_private;

  /* 登记卡刚创建时使用人数是 1（表示它还挂在名单上）。
   * find_blockdriver 又加了 1，所以现在没人使用时人数是 2。
   * 大于 2 说明 FAT 还挂在上面，或者还有别人打开着它。
   * 这时不能摘掉名字：摘掉之后最后一个人离开时，系统不会再来叫
   * unlink，钥匙和草稿纸就释放不掉了。
   */

  if (atomic_read(&inode->i_crefs) > 2)
    {
      inode_release(inode);
      return -EBUSY;
    }

  inode_release(inode);

  ret = unregister_blockdriver(encdev);
  if (ret < 0)
    {
      return ret;
    }

  /* unregister 只摘掉登记卡，不会主动释放 i_private，所以在这里释放。 */

  blkcrypt_destroy(dev);
  return OK;
}

/****************************************************************************
 * fs/driver/fs_registerblockdriver.c
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
 * 包含的头文件
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <errno.h>

#include <nuttx/fs/fs.h>

#include "inode/inode.h"
#include "vfs/vfs.h"

#ifndef CONFIG_DISABLE_MOUNTPOINT

/****************************************************************************
 * 对外提供的函数
 ****************************************************************************/

/****************************************************************************
 * Name: register_blockdriver
 *
 * 说明:
 *   在伪文件系统里登记一个块设备的 inode，
 *   也就是在设备名单上新建一张登记卡。
 *
 * 参数:
 *   path - 要创建的登记卡路径
 *   bops - 块设备的值班表
 *   mode - 访问权限
 *   priv - 要挂在这张登记卡上的私人数据
 *
 * 返回值:
 *   成功返回 0。失败返回负数，这些错误都来自内部的 inode_reserve：
 *
 *   EINVAL - 这个 path 不能用于本次操作
 *   EEXIST - 这个路径上已经有登记卡
 *   ENOMEM - 内存不够，登记卡分配失败
 *
 ****************************************************************************/

int register_blockdriver(FAR const char *path,
                         FAR const struct block_operations *bops,
                         mode_t mode, FAR void *priv)
{
  FAR struct inode *node;
  int ret;

  /* 为这个设备插入一张登记卡。
   * 插入期间先锁住整棵登记卡树，避免别人同时来查。
   * 卡刚放进去、值班表和私人数据还没填上时，这张卡是不完整的。
   */

  inode_lock();
  ret = inode_reserve_path(path, mode, &node);
  if (ret >= 0)
    {
      /* 卡已经拿到了，现在填上块设备专有的信息。
       * inode_reserve 会把使用人数设成 1，表示这张卡还挂在名单上。
       */

      INODE_SET_BLOCK(node);

      node->u.i_bops  = bops;
      node->i_private = priv;
      inode_unlock();
#ifdef CONFIG_FS_NOTIFY
      notify_create(path);
#endif
      return OK;
    }

  inode_unlock();
  return ret;
}

#endif /* 只有允许挂载磁盘时才编译这个函数 */

/****************************************************************************
 * include/nuttx/crypto/blkcrypt.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * 块加密层对上层暴露的接口。
 *
 * 路径加密层不要调用这里的函数，也不要直接打开 /dev/virtblk1。
 * 它只挂在 FAT 上面。FAT 再挂在本层创建的 /dev/encdata0 上。
 * 对 FAT 和路径加密来说，/dev/encdata0 就是一块普通磁盘：
 * 格子数量、每格大小都和底下的虚拟硬盘一样，读出来的是原文。
 *
 * 真正要调用下面三个函数的，是负责开机顺序的集成代码：
 *   1. blkcrypt_register  创建加密盘
 *   2. blkcrypt_set_key   装上 32 字节密钥
 *   3. 然后才能 mkfs.fat / mount fatfs
 * 文件系统卸载之后，再用 blkcrypt_unregister 拆除。
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_CRYPTO_BLKCRYPT_H
#define __INCLUDE_NUTTX_CRYPTO_BLKCRYPT_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* 密钥总长度：前 16 字节是 K1（加密格子里的内容），
 * 后 16 字节是 K2（只用来把格子号变成调料）。
 * 这是 XTS-AES-128，不是 32 字节的 AES-256。
 */

#define BLKCRYPT_KEY_SIZE        32

/* 双方约定的默认名字。集成代码可以直接使用这两个字符串。 */

#define BLKCRYPT_DEV_DEFAULT     "/dev/encdata0"
#define BLKCRYPT_PARENT_DEFAULT  "/dev/virtblk1"

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#undef EXTERN
#if defined(__cplusplus)
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/****************************************************************************
 * Name: blkcrypt_register
 *
 * Description:
 *   在 /dev 里挂出一块加密盘。它自己不保存文件，只是站在另一块盘前面，
 *   负责把每一格加密后再交给底下的盘。
 *
 *   调用时底下的盘必须已经出现。goldfish 上通常是 /dev/virtblk1。
 *   这一步还不装钥匙。没装钥匙之前，读和写会被拒绝，FAT 挂不上去。
 *
 * Input Parameters:
 *   encdev - 加密盘的名字，例如 "/dev/encdata0"
 *   parent - 底下那块真实盘的名字，例如 "/dev/virtblk1"
 *
 * Returned Value:
 *   成功返回 0。失败返回负数：
 *   -EINVAL  参数是空的，或底下那块盘的格子大小不是 16 的倍数
 *   -ENOENT  底下的盘还不存在
 *   -ENOTBLK 给出的路径不是按格子读写的设备
 *   -EEXIST  这个名字已经有人用了
 *   -ENOMEM  内存不够
 *
 ****************************************************************************/

int blkcrypt_register(FAR const char *encdev, FAR const char *parent);

/****************************************************************************
 * Name: blkcrypt_set_key
 *
 * Description:
 *   给一块已经创建好的加密盘装钥匙。装好之后，FAT 才能格式化和挂载。
 *
 *   key 必须指向 32 字节。前 16 字节和后 16 字节不能完全相同。
 *   函数返回后，调用者可以擦掉自己手里的那 32 字节，驱动只保留算好的表。
 *
 * Input Parameters:
 *   encdev - 加密盘名字，必须是 blkcrypt_register 创建的那一块
 *   key    - 32 字节密钥
 *   keylen - 必须是 BLKCRYPT_KEY_SIZE（32）
 *
 * Returned Value:
 *   成功返回 0。失败返回负数：
 *   -EINVAL  长度不是 32，两半钥匙相同，或这个设备不是 blkcrypt
 *   -ENOENT  加密盘还没创建
 *
 ****************************************************************************/

int blkcrypt_set_key(FAR const char *encdev, FAR const uint8_t *key,
                     size_t keylen);

/****************************************************************************
 * Name: blkcrypt_unregister
 *
 * Description:
 *   拆除加密盘，擦掉钥匙，放开底下那块盘。
 *   调用前必须先卸载挂在上面的文件系统，否则返回 -EBUSY。
 *
 * Returned Value:
 *   成功返回 0。设备不存在返回 -ENOENT。仍被占用返回 -EBUSY。
 *
 ****************************************************************************/

int blkcrypt_unregister(FAR const char *encdev);

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif /* __INCLUDE_NUTTX_CRYPTO_BLKCRYPT_H */

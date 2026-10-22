/****************************************************************************
 * drivers/crypto/blkcrypt_xts.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * 只给 blkcrypt.c 使用的加密步骤声明。
 * 路径加密层和应用程序不要包含这个文件。
 ****************************************************************************/

#ifndef __DRIVERS_CRYPTO_BLKCRYPT_XTS_H
#define __DRIVERS_CRYPTO_BLKCRYPT_XTS_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/compiler.h>
#include <sys/types.h>

#include <crypto/aes.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* AES 一次搅拌 16 字节。512 字节的一格正好是 32 次。 */

#define BLKCRYPT_AES_BLOCK 16

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Name: blkcrypt_xts_setkey
 *
 * Description:
 *   把 32 字节拆成两把 16 字节的钥匙，分别装进 key1 和 key2。
 *   key1 用来加密格子里的内容，key2 只用来加密格子号。
 *   失败时两张表都会被擦成 0。
 *
 ****************************************************************************/

int blkcrypt_xts_setkey(FAR AES_CTX *key1, FAR AES_CTX *key2,
                        FAR const uint8_t *key, size_t keylen);

/****************************************************************************
 * Name: blkcrypt_xts_encrypt / blkcrypt_xts_decrypt
 *
 * Description:
 *   就地加密或解密一整格。data 的长度必须是 16 的倍数。
 *   sector 是这一格的编号，从 0 开始。同样的内容放到不同编号里，
 *   得到的密文不同。
 *
 ****************************************************************************/

int blkcrypt_xts_encrypt(FAR AES_CTX *key1, FAR AES_CTX *key2,
                         FAR uint8_t *data, size_t len, blkcnt_t sector);

int blkcrypt_xts_decrypt(FAR AES_CTX *key1, FAR AES_CTX *key2,
                         FAR uint8_t *data, size_t len, blkcnt_t sector);

#endif /* __DRIVERS_CRYPTO_BLKCRYPT_XTS_H */

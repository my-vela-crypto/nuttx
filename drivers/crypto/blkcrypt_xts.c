/****************************************************************************
 * drivers/crypto/blkcrypt_xts.c
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
 * 这一文件只做“把一整格原文变成密文”，不认识磁盘，也不认识文件名。
 *
 * 生活里的对应关系：
 *   - 一格磁盘（通常 512 字节）被切成许多 16 字节的小块。
 *   - K1 是搅拌内容的钥匙。
 *   - K2 是搅拌格子号的钥匙。搅拌结果叫调料（tweak）。
 *   - 每一小块都先和调料混合，再送进 AES，出来后再和同一份调料混合一次。
 *   - 下一小块使用“按固定规则变过”的调料，所以同一格里的小块调料各不相同。
 *   - 每一格都从自己的格子号重新做调料，不能接着用上一格留下的调料。
 *
 * 底下调用的是 crypto/aes.c 里的 aes_setkey、aes_encrypt、aes_decrypt。
 * 这三个函数一次只处理 16 字节。它们由 CONFIG_CRYPTO_SW_AES 编进内核。
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <nuttx/crypto/blkcrypt.h>

#include "blkcrypt_xts.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: blkcrypt_xts_mul_alpha
 *
 * Description:
 *   把调料当成一个 128 位的数乘以 2。
 *   每个字节左移一位，最高位进到下一个字节。
 *   如果最后还有一位溢出来，就在最低字节上异或 0x87。
 *   0x87 来自标准里的常数 AES_XTS_ALPHA，和仓库 xform.c 里的步进一致。
 *   低位字节放在数组前面（小端）。
 *
 ****************************************************************************/

static void blkcrypt_xts_mul_alpha(FAR uint8_t tweak[BLKCRYPT_AES_BLOCK])
{
  uint8_t carry_in = 0;
  int i;

  for (i = 0; i < BLKCRYPT_AES_BLOCK; i++)
    {
      uint8_t carry_out = tweak[i] & 0x80;

      tweak[i] = (uint8_t)((tweak[i] << 1) | carry_in);
      carry_in = carry_out >> 7;
    }

  /* carry_in 为 1 表示乘 2 之后还有一位溢出来，需要按多项式折回。 */

  if (carry_in != 0)
    {
      tweak[0] ^= 0x87;
    }
}

/****************************************************************************
 * Name: blkcrypt_xts_load_tweak
 *
 * Description:
 *   用格子号做出这一格的起始调料。
 *   格子号按小端写成 16 字节（低位放在 tweak[0]），其余填 0，
 *   再用 K2 加密一次。格子号本身不会被写进磁盘。
 *
 ****************************************************************************/

static void blkcrypt_xts_load_tweak(FAR AES_CTX *key2,
                                    FAR uint8_t tweak[BLKCRYPT_AES_BLOCK],
                                    blkcnt_t sector)
{
  uint8_t plain[BLKCRYPT_AES_BLOCK];
  uint64_t value = (uint64_t)sector;
  size_t i;

  memset(plain, 0, sizeof(plain));

  /* 按字节拆开，避免依赖 CPU 把多字节整数放在内存里的方向。 */

  for (i = 0; i < sizeof(value) && i < BLKCRYPT_AES_BLOCK; i++)
    {
      plain[i] = (uint8_t)((value >> (8 * i)) & 0xff);
    }

  aes_encrypt(key2, plain, tweak);
  explicit_bzero(plain, sizeof(plain));
}

/****************************************************************************
 * Name: blkcrypt_xts_crypt
 *
 * Description:
 *   处理一整格。encrypt 为真时加密，为假时解密。
 *   解密只是把中间那一步从 aes_encrypt 换成 aes_decrypt，
 *   前后两次“和调料混合”不变。混合用的是异或：
 *   两位相同得 0，不同得 1；对同一份调料再异或一次就回到原样。
 *
 ****************************************************************************/

static int blkcrypt_xts_crypt(FAR AES_CTX *key1, FAR AES_CTX *key2,
                              FAR uint8_t *data, size_t len,
                              blkcnt_t sector, bool encrypt)
{
  uint8_t tweak[BLKCRYPT_AES_BLOCK];
  size_t offset;

  if (key1 == NULL || key2 == NULL || data == NULL ||
      len == 0 || (len % BLKCRYPT_AES_BLOCK) != 0)
    {
      return -EINVAL;
    }

  blkcrypt_xts_load_tweak(key2, tweak, sector);

  for (offset = 0; offset < len; offset += BLKCRYPT_AES_BLOCK)
    {
      uint8_t mixed[BLKCRYPT_AES_BLOCK];
      FAR uint8_t *block = data + offset;
      int i;

      for (i = 0; i < BLKCRYPT_AES_BLOCK; i++)
        {
          mixed[i] = block[i] ^ tweak[i];
        }

      if (encrypt)
        {
          aes_encrypt(key1, mixed, block);
        }
      else
        {
          aes_decrypt(key1, mixed, block);
        }

      for (i = 0; i < BLKCRYPT_AES_BLOCK; i++)
        {
          block[i] ^= tweak[i];
        }

      /* 这一小块用完了，调料变一下，留给同一格里的下一块。 */

      blkcrypt_xts_mul_alpha(tweak);
      explicit_bzero(mixed, sizeof(mixed));
    }

  explicit_bzero(tweak, sizeof(tweak));
  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: blkcrypt_xts_setkey
 ****************************************************************************/

int blkcrypt_xts_setkey(FAR AES_CTX *key1, FAR AES_CTX *key2,
                        FAR const uint8_t *key, size_t keylen)
{
  const size_t half = BLKCRYPT_KEY_SIZE / 2;

  if (key1 == NULL || key2 == NULL || key == NULL ||
      keylen != BLKCRYPT_KEY_SIZE)
    {
      return -EINVAL;
    }

  /* 标准不允许两把子钥匙相同，否则内容和调料用了同一把钥匙。 */

  if (memcmp(key, key + half, half) == 0)
    {
      return -EINVAL;
    }

  explicit_bzero(key1, sizeof(*key1));
  explicit_bzero(key2, sizeof(*key2));

  /* aes_setkey 的长度单位是字节。16 表示 AES-128。失败时它返回 -1。 */

  if (aes_setkey(key1, key, (int)half) != 0)
    {
      explicit_bzero(key1, sizeof(*key1));
      return -EINVAL;
    }

  if (aes_setkey(key2, key + half, (int)half) != 0)
    {
      explicit_bzero(key1, sizeof(*key1));
      explicit_bzero(key2, sizeof(*key2));
      return -EINVAL;
    }

  return OK;
}

/****************************************************************************
 * Name: blkcrypt_xts_encrypt
 ****************************************************************************/

int blkcrypt_xts_encrypt(FAR AES_CTX *key1, FAR AES_CTX *key2,
                         FAR uint8_t *data, size_t len, blkcnt_t sector)
{
  return blkcrypt_xts_crypt(key1, key2, data, len, sector, true);
}

/****************************************************************************
 * Name: blkcrypt_xts_decrypt
 ****************************************************************************/

int blkcrypt_xts_decrypt(FAR AES_CTX *key1, FAR AES_CTX *key2,
                         FAR uint8_t *data, size_t len, blkcnt_t sector)
{
  return blkcrypt_xts_crypt(key1, key2, data, len, sector, false);
}

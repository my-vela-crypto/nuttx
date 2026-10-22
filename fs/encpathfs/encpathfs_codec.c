/****************************************************************************
 * fs/encpathfs/encpathfs_codec.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/crypto/aes_siv.h>
#include <nuttx/fs/encpathfs.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t g_name_ad[] = "encpathfs:name:v1";
static const char g_alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

void encpathfs_erase(FAR void *memory, size_t length)
{
  FAR volatile uint8_t *p = memory;
  while (length-- > 0)
    {
      *p++ = 0;
    }
}

static bool encpathfs_valid_name(FAR const char *name, size_t length)
{
  size_t i;

  if (length == 0 || length > ENCPATHFS_NAME_MAX ||
      (length == 1 && name[0] == '.') ||
      (length == 2 && name[0] == '.' && name[1] == '.'))
    {
      return false;
    }

  for (i = 0; i < length; i++)
    {
      if ((uint8_t)name[i] < 0x20 || (uint8_t)name[i] > 0x7e ||
          name[i] == '/')
        {
          return false;
        }
    }

  return true;
}

int encpathfs_encode_name(FAR const uint8_t *key, FAR const char *name,
                         FAR char *encoded, size_t capacity)
{
  uint8_t sealed[16 + ENCPATHFS_NAME_MAX];
  uint32_t bits = 0;
  unsigned int count = 0;
  size_t length;
  size_t out = 3;
  size_t i;
  int ret;

  if (key == NULL || name == NULL || encoded == NULL)
    {
      return -EINVAL;
    }

  length = strnlen(name, ENCPATHFS_NAME_MAX + 1);
  if (length > ENCPATHFS_NAME_MAX)
    {
      return -ENAMETOOLONG;
    }

  if (!encpathfs_valid_name(name, length))
    {
      return -EINVAL;
    }

  if (capacity <= 3 + ((length + 16) * 8 + 4) / 5)
    {
      return -ENAMETOOLONG;
    }

  ret = aes_siv_encrypt(key, g_name_ad, sizeof(g_name_ad) - 1,
                        (FAR const uint8_t *)name, length, sealed);
  if (ret < 0)
    {
      encpathfs_erase(sealed, sizeof(sealed));
      return ret;
    }

  memcpy(encoded, "E1_", 3);
  for (i = 0; i < length + 16; i++)
    {
      bits = (bits << 8) | sealed[i];
      count += 8;
      while (count >= 5)
        {
          count -= 5;
          encoded[out++] = g_alphabet[(bits >> count) & 31];
        }
    }

  if (count != 0)
    {
      encoded[out++] = g_alphabet[(bits << (5 - count)) & 31];
    }

  encoded[out] = '\0';
  encpathfs_erase(sealed, sizeof(sealed));
  return 0;
}

int encpathfs_decode_name(FAR const uint8_t *key, FAR const char *encoded,
                         FAR char *name, size_t capacity)
{
  uint8_t sealed[16 + ENCPATHFS_NAME_MAX];
  char plain[ENCPATHFS_NAME_MAX + 1];
  uint32_t bits = 0;
  unsigned int count = 0;
  size_t length;
  size_t nsealed = 0;
  size_t i;
  int value;
  int ret = -EBADMSG;

  if (key == NULL || encoded == NULL || name == NULL)
    {
      return -EINVAL;
    }

  if (capacity > 0)
    {
      name[0] = '\0';
    }

  length = strnlen(encoded, ENCPATHFS_ENCODED_MAX + 1);
  if (length < 31 || length > ENCPATHFS_ENCODED_MAX ||
      memcmp(encoded, "E1_", 3) != 0)
    {
      return -EBADMSG;
    }

  for (i = 3; i < length; i++)
    {
      if (encoded[i] >= '0' && encoded[i] <= '9')
        {
          value = encoded[i] - '0';
        }
      else if (encoded[i] >= 'A' && encoded[i] <= 'V')
        {
          value = encoded[i] - 'A' + 10;
        }
      else
        {
          goto out;
        }

      bits = (bits << 5) | value;
      count += 5;
      if (count >= 8)
        {
          count -= 8;
          if (nsealed == sizeof(sealed))
            {
              goto out;
            }

          sealed[nsealed++] = (bits >> count) & 255;
        }
    }

  /* Reject non-canonical lengths and nonzero unused trailing bits. */

  if (nsealed <= 16 || (nsealed * 8 + 4) / 5 != length - 3 ||
      (bits & ((1u << count) - 1)) != 0)
    {
      goto out;
    }

  ret = aes_siv_decrypt(key, g_name_ad, sizeof(g_name_ad) - 1,
                        sealed, nsealed, (FAR uint8_t *)plain);
  if (ret < 0)
    {
      goto out;
    }

  if (!encpathfs_valid_name(plain, nsealed - 16))
    {
      ret = -EBADMSG;
      goto out;
    }

  if (capacity <= nsealed - 16)
    {
      ret = -ENAMETOOLONG;
      goto out;
    }

  memcpy(name, plain, nsealed - 16);
  name[nsealed - 16] = '\0';
  ret = 0;
out:
  encpathfs_erase(plain, sizeof(plain));
  encpathfs_erase(sealed, sizeof(sealed));
  return ret;
}

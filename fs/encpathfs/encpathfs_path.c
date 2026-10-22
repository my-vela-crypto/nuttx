/****************************************************************************
 * fs/encpathfs/encpathfs_path.c
 *
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#include <nuttx/config.h>
#include <errno.h>
#include <string.h>
#include "encpathfs.h"

int encpathfs_path(FAR struct encpathfs_mount_s *mount,
                  FAR const char *relative, FAR char **physical,
                  FAR char **logical)
{
  FAR char *path;
  FAR char *normal;
  FAR const char *start;
  FAR const char *p;
  FAR char *last;
  char component[ENCPATHFS_NAME_MAX + 1];
  char encoded[ENCPATHFS_ENCODED_MAX + 1];
  struct stat st;
  size_t used = sizeof(ENCPATHFS_ROOT) - 1;
  size_t nused = 0;
  size_t length;
  size_t elength;
  int ret = 0;

  if (relative == NULL || physical == NULL)
    {
      return -EINVAL;
    }

  if (strnlen(relative, PATH_MAX) == PATH_MAX)
    {
      return -ENAMETOOLONG;
    }

  path = fs_heap_malloc(PATH_MAX);
  normal = fs_heap_malloc(PATH_MAX);
  if (path == NULL || normal == NULL)
    {
      ret = -ENOMEM;
      goto out;
    }

  memcpy(path, ENCPATHFS_ROOT, used + 1);
  normal[0] = '\0';
  p = relative;
  while (*p != '\0')
    {
      if (*p == '/')
        {
          p++;
          continue;
        }

      start = p;
      while (*p != '\0' && *p != '/')
        {
          p++;
        }

      length = p - start;
      if ((length == 1 && start[0] == '.') ||
          (length == 2 && start[0] == '.' && start[1] == '.'))
        {
          /* Verify the traversed directory before removing a component:
           * missing/../name must not bypass a missing intermediate path.
           */

          ret = mount->lower->u.i_mops->stat(mount->lower, path, &st);
          if (ret < 0)
            {
              goto out;
            }

          if (!S_ISDIR(st.st_mode))
            {
              ret = -ENOTDIR;
              goto out;
            }

          if (length == 2)
            {
              if (nused == 0)
                {
                  ret = -EPERM;
                  goto out;
                }

              last = strrchr(path, '/');
              *last = '\0';
              used = last - path;
              last = strrchr(normal, '/');
              nused = last == NULL ? 0 : (size_t)(last - normal);
              normal[nused] = '\0';
            }

          continue;
        }

      if (length > ENCPATHFS_NAME_MAX)
        {
          ret = -ENAMETOOLONG;
          goto out;
        }

      memcpy(component, start, length);
      component[length] = '\0';
      ret = encpathfs_encode_name(mount->key, component,
                                  encoded, sizeof(encoded));
      if (ret < 0)
        {
          goto out;
        }

      elength = strlen(encoded);
      if (used + 1 + elength >= PATH_MAX ||
          nused + (nused != 0) + length >= PATH_MAX)
        {
          ret = -ENAMETOOLONG;
          goto out;
        }

      path[used++] = '/';
      memcpy(path + used, encoded, elength + 1);
      used += elength;
      if (nused != 0)
        {
          normal[nused++] = '/';
        }

      memcpy(normal + nused, component, length + 1);
      nused += length;
    }

  /* A trailing slash imposes directory semantics even for file operations. */

  length = strlen(relative);
  if (length > 0 && relative[length - 1] == '/' && nused != 0)
    {
      ret = mount->lower->u.i_mops->stat(mount->lower, path, &st);
      if (ret < 0)
        {
          goto out;
        }

      if (!S_ISDIR(st.st_mode))
        {
          ret = -ENOTDIR;
          goto out;
        }
    }

  *physical = path;
  path = NULL;
  if (logical != NULL)
    {
      *logical = normal;
      normal = NULL;
    }

out:
  encpathfs_erase(component, sizeof(component));
  fs_heap_free(path);
  fs_heap_free(normal);
  return ret;
}

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __ENCFS_TEST_MUTEX_H
#define __ENCFS_TEST_MUTEX_H
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
#define NXMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
static inline int nxmutex_lock(mutex_t *mutex)
{
  return -pthread_mutex_lock(mutex);
}
static inline int nxmutex_unlock(mutex_t *mutex)
{
  return -pthread_mutex_unlock(mutex);
}
#endif

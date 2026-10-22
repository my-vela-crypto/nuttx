# SPDX-License-Identifier: Apache-2.0

if(CONFIG_ENCFSMGR)
  target_sources(fs PRIVATE encfs_manager.c encfs_key.c encfs_block_port.c)
endif()

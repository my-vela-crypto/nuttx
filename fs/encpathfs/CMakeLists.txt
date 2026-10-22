# SPDX-License-Identifier: Apache-2.0

if(CONFIG_FS_ENCPATHFS)
  target_sources(fs PRIVATE encpathfs_mount.c encpathfs_file.c encpathfs_dir.c
                            encpathfs_path.c encpathfs_codec.c)
endif()

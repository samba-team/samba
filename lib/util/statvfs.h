/*
 * Unix SMB/CIFS implementation.
 * VFS API's statvfs abstraction
 * Copyright (C) Alexander Bokovoy			2005
 * Copyright (C) Steve French				2005
 * Copyright (C) James Peach				2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SMBD_STATVFS_H__
#define __SMBD_STATVFS_H__

struct vfs_statvfs_struct {
	/* For undefined recommended transfer size return -1 in that field */
	uint32_t OptimalTransferSize; /* bsize on some os, iosize on
				       * other os */
	uint32_t BlockSize;

	/*
	 The next three fields are in terms of the block size.
	 (above). If block size is unknown, 4096 would be a
	 reasonable block size for a server to report.
	 Note that returning the blocks/blocksavail removes need
	 to make a second call (to QFSInfo level 0x103 to get this info.
	 UserBlockAvail is typically less than or equal to BlocksAvail,
	 if no distinction is made return the same value in each.
	*/

	uint64_t TotalBlocks;
	uint64_t BlocksAvail;	  /* bfree */
	uint64_t UserBlocksAvail; /* bavail */

	/* For undefined Node fields or FSID return -1 */
	uint64_t TotalFileNodes;
	uint64_t FreeFileNodes;
	uint64_t FsIdentifier; /* fsid */
	/* NB Namelen comes from FILE_SYSTEM_ATTRIBUTE_INFO call */
	/* NB flags can come from FILE_SYSTEM_DEVICE_INFO call   */

	int FsCapabilities;
};

int sys_statvfs(const char *path, struct vfs_statvfs_struct *statbuf);
int sys_fstatvfs(int fd, struct vfs_statvfs_struct *statbuf);

#endif

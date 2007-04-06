/*
 * Copyright (c) Jeremy Allison 2007.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#if !defined(HAVE_LINUX_READAHEAD) && !defined(HAVE_POSIX_FADVISE)
static BOOL didmsg;
#endif

/* 
 * This module copes with Vista AIO read requests on Linux
 * by detecting the initial 0x80000 boundary reads and causing
 * the buffer cache to be filled in advance.
 */

static unsigned long get_offset_boundary(struct vfs_handle_struct *handle)
{
	SMB_OFF_T off_bound = conv_str_size(lp_parm_const_string(SNUM(handle->conn),
						"readahead",
						"offset",
						NULL));
	if (off_bound == 0) {
		off_bound = 0x80000;
	}
	return (unsigned long)off_bound;
}

static unsigned long get_offset_length(struct vfs_handle_struct *handle, unsigned long def_val)
{
	SMB_OFF_T len = conv_str_size(lp_parm_const_string(SNUM(handle->conn),
						"readahead",
						"length",
						NULL));
	if (len == 0) {
		len = def_val;
	}
	return (unsigned long)len;
}

static ssize_t readahead_sendfile(struct vfs_handle_struct *handle,
					int tofd,
					files_struct *fsp,
					int fromfd,
					const DATA_BLOB *header,
					SMB_OFF_T offset,
					size_t count)
{
	unsigned long off_bound = get_offset_boundary(handle);
	if ( offset % off_bound == 0) {
		unsigned long len = get_offset_length(handle, off_bound);
#if defined(HAVE_LINUX_READAHEAD)
		int err = readahead(fromfd, offset, (size_t)len);
		DEBUG(10,("readahead_sendfile: readahead on fd %u, offset %llu, len %u returned %d\n",
			(unsigned int)fromfd,
			(unsigned long long)offset,
			(unsigned int)len,
		        err ));
#elif defined(HAVE_POSIX_FADVISE)
		int err = posix_fadvise(fromfd, offset, (off_t)len, POSIX_FADV_WILLNEED);
		DEBUG(10,("readahead_sendfile: posix_fadvise on fd %u, offset %llu, len %u returned %d\n",
			(unsigned int)fromfd,
			(unsigned long long)offset,
			(unsigned int)len,
			err ));
#else
		if (!didmsg) {
			DEBUG(0,("readahead_sendfile: no readahead on this platform\n"));
			didmsg = True;
		}
#endif
	}
	return SMB_VFS_NEXT_SENDFILE(handle,
					tofd,
					fsp,
					fromfd,
					header,
					offset,
					count);
}

static ssize_t readahead_pread(vfs_handle_struct *handle,
				files_struct *fsp,
				int fd,
				void *data,
				size_t count,
				SMB_OFF_T offset)
{
	unsigned long off_bound = get_offset_boundary(handle);
	if ( offset % off_bound == 0) {
		unsigned long len = get_offset_length(handle, off_bound);
#if defined(HAVE_LINUX_READAHEAD)
		int err = readahead(fd, offset, (size_t)len);
		DEBUG(10,("readahead_pread: readahead on fd %u, offset %llu, len %u returned %d\n",
			(unsigned int)fd,
			(unsigned long long)offset,
			(unsigned int)len,
			err ));
#elif defined(HAVE_POSIX_FADVISE)
		int err = posix_fadvise(fromfd, offset, (off_t)len, POSIX_FADV_WILLNEED);
		DEBUG(10,("readahead_pread: posix_fadvise on fd %u, offset %llu, len %u returned %d\n",
			(unsigned int)fd,
			(unsigned long long)offset,
			(unsigned int)len,
			(err ));
#else
		if (!didmsg) {
			DEBUG(0,("readahead_pread: no readahead on this platform\n"));
			didmsg = True;
		}
#endif
        }
        return SMB_VFS_NEXT_PREAD(handle, fsp, fd, data, count, offset);
}

static vfs_op_tuple readahead_ops [] =
{
	{SMB_VFS_OP(readahead_sendfile), SMB_VFS_OP_SENDFILE, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(readahead_pread), SMB_VFS_OP_PREAD, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_readahead_init(void);
NTSTATUS vfs_readahead_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "readahead", readahead_ops);
}

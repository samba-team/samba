/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - write

   Copyright (C) Andrew Tridgell 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "include/includes.h"
#include "vfs_posix.h"


/*
  write to a file
*/
NTSTATUS pvfs_write(struct smbsrv_request *req, union smb_write *wr)
{
	NTVFS_GET_PRIVATE(pvfs_state, pvfs, req);
	ssize_t ret;
	struct pvfs_file *f;

	switch (wr->generic.level) {
	case RAW_WRITE_WRITEX:
		f = pvfs_find_fd(pvfs, wr->writex.in.fnum);
		if (!f) {
			return NT_STATUS_INVALID_HANDLE;
		}
		ret = pwrite(f->fd, 
			     wr->writex.in.data, 
			     wr->writex.in.count,
			     wr->writex.in.offset);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
		
		wr->writex.out.nwritten = ret;
		wr->writex.out.remaining = 0; /* should fill this in? */

		return NT_STATUS_OK;

	case RAW_WRITE_WRITE:
		f = pvfs_find_fd(pvfs, wr->write.in.fnum);
		if (!f) {
			return NT_STATUS_INVALID_HANDLE;
		}
		if (wr->write.in.count == 0) {
			/* a truncate! */
			ret = ftruncate(f->fd, wr->write.in.offset);
		} else {
			ret = pwrite(f->fd,
				     wr->write.in.data, 
				     wr->write.in.count,
				     wr->write.in.offset);
		}
		if (ret == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
		
		wr->write.out.nwritten = ret;

		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

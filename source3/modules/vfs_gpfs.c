/*
   Unix SMB/CIFS implementation.
   Wrap gpfs calls in vfs functions.
 
   Copyright (C) Christian Ambach <cambach1@de.ibm.com> 2006
   
   Major code contributions by Chetan Shringarpure <chetan.sh@in.ibm.com>
   
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

#include "includes.h"


static int vfs_gpfs_kernel_flock(vfs_handle_struct *handle, files_struct *fsp, 
				 int fd, uint32 share_mode)
{

	START_PROFILE(syscall_kernel_flock);

	kernel_flock(fsp->fh->fd, share_mode);

	if (!set_gpfs_sharemode(fsp, fsp->access_mask, fsp->share_access)) {

		return -1;

	}

	END_PROFILE(syscall_kernel_flock);

	return 0;
}


static vfs_op_tuple gpfs_op_tuples[] = {

	{SMB_VFS_OP(vfs_gpfs_kernel_flock),
	 SMB_VFS_OP_KERNEL_FLOCK,
	 SMB_VFS_LAYER_OPAQUE},

	{SMB_VFS_OP(NULL),
	 SMB_VFS_OP_NOOP,
	 SMB_VFS_LAYER_NOOP}

};


NTSTATUS vfs_gpfs_init(void)
{
	init_gpfs();
	
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gpfs",
				gpfs_op_tuples);
}

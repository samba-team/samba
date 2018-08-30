/*
 *  Unix SMB/CIFS implementation.
 *  Samba VFS module for delay injection in VFS calls
 *  Copyright (C) Ralph Boehme 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static void inject_delay(const char *vfs_func, vfs_handle_struct *handle)
{
	int delay;

	delay = lp_parm_int(SNUM(handle->conn), "delay_inject", vfs_func, 0);
	if (delay == 0) {
		return;
	}

	DBG_DEBUG("Injected delay for [%s] of [%d] ms\n", vfs_func, delay);

	smb_msleep(delay);
}

static int vfs_delay_inject_ntimes(vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   struct smb_file_time *ft)
{
	inject_delay("ntimes", handle);

	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static struct vfs_fn_pointers vfs_delay_inject_fns = {
	.ntimes_fn = vfs_delay_inject_ntimes,
};

static_decl_vfs;
NTSTATUS vfs_delay_inject_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "delay_inject",
				&vfs_delay_inject_fns);
}

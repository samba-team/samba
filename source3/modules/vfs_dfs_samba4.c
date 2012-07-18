/*
 * VFS module to alter the algorithm to calculate
 * the struct file_id used as key for the share mode
 * and byte range locking db's.
 *
 * Copyright (C) 2007, Stefan Metzmacher
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "source3/include/msdfs.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "source4/lib/events/events.h"
#include "source4/auth/session.h"
#include "lib/param/param.h"
#include "source4/dsdb/samdb/samdb.h"
#include "dfs_server/dfs_server_ad.h"

static int vfs_dfs_samba4_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_dfs_samba4_debug_level

struct dfs_samba4_handle_data {
	struct tevent_context *ev;
	struct loadparm_context *lp_ctx;
	struct ldb_context *sam_ctx;
};

static int dfs_samba4_connect(struct vfs_handle_struct *handle,
			      const char *service, const char *user)
{
	struct dfs_samba4_handle_data *data;
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	data = talloc_zero(handle->conn, struct dfs_samba4_handle_data);
	if (!data) {
		DEBUG(0, ("talloc_zero() failed\n"));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	data->ev = s4_event_context_init(data);
	if (!data->ev) {
		DEBUG(0, ("s4_event_context_init failed\n"));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	data->lp_ctx = loadparm_init_s3(data, loadparm_s3_helpers());
	if (data->lp_ctx == NULL) {
		DEBUG(0, ("loadparm_init_s3 failed\n"));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	data->sam_ctx = samdb_connect(data,
				      data->ev,
				      data->lp_ctx,
				      system_session(data->lp_ctx), 0);
	if (!data->sam_ctx) {
		DEBUG(0, ("samdb_connect failed\n"));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, data, NULL,
				struct dfs_samba4_handle_data,
				return -1);

	DEBUG(10,("dfs_samba4: connect to service[%s]\n",
		  service));

	return 0;
}

static void dfs_samba4_disconnect(struct vfs_handle_struct *handle)
{
	DEBUG(10,("dfs_samba4_disconnect() connect to service[%s].\n",
		  lp_servicename(talloc_tos(), SNUM(handle->conn))));

	SMB_VFS_NEXT_DISCONNECT(handle);
}

static NTSTATUS dfs_samba4_get_referrals(struct vfs_handle_struct *handle,
					 struct dfs_GetDFSReferral *r)
{
	struct dfs_samba4_handle_data *data;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, data,
				struct dfs_samba4_handle_data,
				return NT_STATUS_INTERNAL_ERROR);

	DEBUG(8, ("dfs_samba4: Requested DFS name: %s utf16-length: %u\n",
		   r->in.req.servername,
		   (unsigned int)strlen_m(r->in.req.servername)*2));

	status = dfs_server_ad_get_referrals(data->lp_ctx,
					     data->sam_ctx,
					     handle->conn->sconn->remote_address,
					     r);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		return SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static struct vfs_fn_pointers vfs_dfs_samba4_fns = {
	.connect_fn = dfs_samba4_connect,
	.disconnect_fn = dfs_samba4_disconnect,
	.get_dfs_referrals_fn = dfs_samba4_get_referrals,
};

NTSTATUS vfs_dfs_samba4_init(void);
NTSTATUS vfs_dfs_samba4_init(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "dfs_samba4",
			       &vfs_dfs_samba4_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_dfs_samba4_debug_level = debug_add_class("dfs_samba4");
	if (vfs_dfs_samba4_debug_level == -1) {
		vfs_dfs_samba4_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_dfs_samba4: Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("vfs_dfs_samba4: Debug class number of 'fileid': %d\n",
		      vfs_dfs_samba4_debug_level));
	}

	return ret;
}

/*
   Unix SMB/CIFS implementation.

   Copyright (C) Ralph Boehme 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/security/security.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "dbwrap/dbwrap_open.h"
#include "../lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "librpc/gen_ndr/ioctl.h"
#include "offload_token.h"

struct vfs_offload_ctx {
	bool initialized;
	struct db_context *db_ctx;
};

NTSTATUS vfs_offload_token_ctx_init(TALLOC_CTX *mem_ctx,
				    struct vfs_offload_ctx **_ctx)
{
	struct vfs_offload_ctx *ctx = *_ctx;

	if (ctx != NULL) {
		if (!ctx->initialized) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		return NT_STATUS_OK;
	}

	ctx = talloc_zero(mem_ctx, struct vfs_offload_ctx);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ctx->db_ctx = db_open_rbt(mem_ctx);
	if (ctx->db_ctx == NULL) {
		TALLOC_FREE(ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ctx->initialized = true;
	*_ctx = ctx;
	return NT_STATUS_OK;
}

struct fsp_token_link {
	struct vfs_offload_ctx *ctx;
	DATA_BLOB token_blob;
};

static int fsp_token_link_destructor(struct fsp_token_link *link)
{
	DATA_BLOB token_blob = link->token_blob;
	TDB_DATA key = make_tdb_data(token_blob.data, token_blob.length);
	NTSTATUS status;

	status = dbwrap_delete(link->ctx->db_ctx, key);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_delete failed: %s. Token:\n", nt_errstr(status));
		dump_data(0, token_blob.data, token_blob.length);
		return -1;
	}

	return 0;
}

struct vfs_offload_token_db_store_fsp_state {
	const struct files_struct *fsp;
	const DATA_BLOB *token_blob;
	NTSTATUS status;
};

static void vfs_offload_token_db_store_fsp_fn(
	struct db_record *rec, TDB_DATA value, void *private_data)
{
	struct vfs_offload_token_db_store_fsp_state *state = private_data;
	const struct files_struct *fsp = state->fsp;
	const DATA_BLOB *token_blob = state->token_blob;
	files_struct *token_db_fsp = NULL;
	void *ptr = NULL;

	if (value.dsize == 0) {
		value = make_tdb_data((uint8_t *)&fsp, sizeof(files_struct *));
		state->status = dbwrap_record_store(rec, value, 0);
		return;
	}

	if (value.dsize != sizeof(ptr)) {
		DBG_ERR("Bad db entry for token:\n");
		dump_data(1, token_blob->data, token_blob->length);
		state->status = NT_STATUS_INTERNAL_ERROR;
		return;
	}
	memcpy(&ptr, value.dptr, value.dsize);

	token_db_fsp = talloc_get_type_abort(ptr, struct files_struct);
	if (token_db_fsp != fsp) {
		DBG_ERR("token for fsp [%s] matches already known "
			"but different fsp [%s]:\n",
			fsp_str_dbg(fsp),
			fsp_str_dbg(token_db_fsp));
		dump_data(1, token_blob->data, token_blob->length);
		state->status = NT_STATUS_INTERNAL_ERROR;
		return;
	}
}

NTSTATUS vfs_offload_token_db_store_fsp(struct vfs_offload_ctx *ctx,
					const files_struct *fsp,
					const DATA_BLOB *token_blob)
{
	struct vfs_offload_token_db_store_fsp_state state = {
		.fsp = fsp, .token_blob = token_blob,
	};
	struct fsp_token_link *link = NULL;
	TDB_DATA key = make_tdb_data(token_blob->data, token_blob->length);
	NTSTATUS status;

	link = talloc(fsp, struct fsp_token_link);
	if (link == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*link = (struct fsp_token_link) {
		.ctx = ctx,
		.token_blob = data_blob_dup_talloc(link, *token_blob),
	};
	if (link->token_blob.data == NULL) {
		TALLOC_FREE(link);
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_do_locked(
		ctx->db_ctx,
		key,
		vfs_offload_token_db_store_fsp_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(link);
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("vfs_offload_token_db_store_fsp_fn failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(link);
		return status;
	}

	talloc_set_destructor(link, fsp_token_link_destructor);
	return NT_STATUS_OK;
}

struct vfs_offload_token_db_fetch_fsp_state {
	struct files_struct **fsp;
	NTSTATUS status;
};

static void vfs_offload_token_db_fetch_fsp_fn(
	TDB_DATA key, TDB_DATA value, void *private_data)
{
	struct vfs_offload_token_db_fetch_fsp_state *state = private_data;
	void *ptr;

	if (value.dsize != sizeof(ptr)) {
		DBG_ERR("Bad db entry for token:\n");
		dump_data(1, key.dptr, key.dsize);
		state->status = NT_STATUS_INTERNAL_ERROR;
		return;
	}

	memcpy(&ptr, value.dptr, value.dsize);
	*state->fsp = talloc_get_type_abort(ptr, struct files_struct);
}

NTSTATUS vfs_offload_token_db_fetch_fsp(struct vfs_offload_ctx *ctx,
					const DATA_BLOB *token_blob,
					files_struct **fsp)
{
	struct vfs_offload_token_db_fetch_fsp_state state = { .fsp = fsp };
	TDB_DATA key = make_tdb_data(token_blob->data, token_blob->length);
	NTSTATUS status;

	status = dbwrap_parse_record(
		ctx->db_ctx,
		key,
		vfs_offload_token_db_fetch_fsp_fn,
		&state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Unknown token:\n");
		dump_data(10, token_blob->data, token_blob->length);
		return status;
	}
	return state.status;
}

NTSTATUS vfs_offload_token_create_blob(TALLOC_CTX *mem_ctx,
				       const files_struct *fsp,
				       uint32_t fsctl,
				       DATA_BLOB *token_blob)
{
	size_t len;

	switch (fsctl) {
	case FSCTL_DUP_EXTENTS_TO_FILE:
		len = 20;
		break;
	case FSCTL_SRV_REQUEST_RESUME_KEY:
		len = 24;
		break;
	default:
		DBG_ERR("Invalid fsctl [%" PRIu32 "]\n", fsctl);
		return NT_STATUS_NOT_SUPPORTED;
	}

	*token_blob = data_blob_talloc_zero(mem_ctx, len);
	if (token_blob->length == 0) {
		return NT_STATUS_NO_MEMORY;
	}

	/* combine persistent and volatile handles for the resume key */
	SBVAL(token_blob->data,  0, fsp->op->global->open_persistent_id);
	SBVAL(token_blob->data,  8, fsp->op->global->open_volatile_id);
	SIVAL(token_blob->data, 16, fsctl);

	return NT_STATUS_OK;
}


NTSTATUS vfs_offload_token_check_handles(uint32_t fsctl,
					 files_struct *src_fsp,
					 files_struct *dst_fsp)
{
	if (src_fsp->vuid != dst_fsp->vuid) {
		DBG_INFO("copy chunk handles not in the same session.\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!NT_STATUS_IS_OK(src_fsp->op->status)) {
		DBG_INFO("copy chunk source handle invalid: %s\n",
			 nt_errstr(src_fsp->op->status));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!NT_STATUS_IS_OK(dst_fsp->op->status)) {
		DBG_INFO("copy chunk destination handle invalid: %s\n",
			 nt_errstr(dst_fsp->op->status));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (src_fsp->fsp_flags.closing) {
		DBG_INFO("copy chunk src handle with closing in progress.\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dst_fsp->fsp_flags.closing) {
		DBG_INFO("copy chunk dst handle with closing in progress.\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (src_fsp->fsp_flags.is_directory) {
		DBG_INFO("copy chunk no read on src directory handle (%s).\n",
			 smb_fname_str_dbg(src_fsp->fsp_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dst_fsp->fsp_flags.is_directory) {
		DBG_INFO("copy chunk no read on dst directory handle (%s).\n",
			 smb_fname_str_dbg(dst_fsp->fsp_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (IS_IPC(src_fsp->conn) || IS_IPC(dst_fsp->conn)) {
		DBG_INFO("copy chunk no access on IPC$ handle.\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (IS_PRINT(src_fsp->conn) || IS_PRINT(dst_fsp->conn)) {
		DBG_INFO("copy chunk no access on PRINT handle.\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 * The server MUST fail the request with STATUS_ACCESS_DENIED if any of
	 * the following are true:
	 * - The Open.GrantedAccess of the destination file does not include
	 *   FILE_WRITE_DATA or FILE_APPEND_DATA.
	 *
	 * A non writable dst handle also doesn't make sense for other fsctls.
	 */
	if (!CHECK_WRITE(dst_fsp)) {
		DBG_INFO("dest handle not writable (%s).\n",
			smb_fname_str_dbg(dst_fsp->fsp_name));
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the destination file does not include
	 *   FILE_READ_DATA, and the CtlCode is FSCTL_SRV_COPYCHUNK.
	 */
	if ((fsctl == FSCTL_SRV_COPYCHUNK) && !CHECK_READ_IOCTL(dst_fsp)) {
		DBG_INFO("copy chunk no read on dest handle (%s).\n",
			 smb_fname_str_dbg(dst_fsp->fsp_name));
		return NT_STATUS_ACCESS_DENIED;
	}
	/*
	 * - The Open.GrantedAccess of the source file does not include
	 *   FILE_READ_DATA access.
	 */
	if (!CHECK_READ_SMB2(src_fsp)) {
		DBG_INFO("src handle not readable (%s).\n",
			 smb_fname_str_dbg(src_fsp->fsp_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

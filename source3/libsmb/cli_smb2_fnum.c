/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Jeremy Allison 2013
   Copyright (C) Volker Lendecke 2013
   Copyright (C) Stefan Metzmacher 2013

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

/*
 This code is a thin wrapper around the existing
 cli_smb2_XXXX() functions in libcli/smb/smb2cli_XXXXX.c,
 but allows the handles to be mapped to uint16_t fnums,
 which are easier for smbclient to use.
*/

#include "includes.h"
#include "client.h"
#include "async_smb.h"
#include "../libcli/smb/smbXcli_base.h"
#include "cli_smb2_fnum.h"
#include "trans2.h"
#include "clirap.h"
#include "../libcli/smb/smb2_create_blob.h"
#include "libsmb/proto.h"
#include "lib/util/tevent_ntstatus.h"
#include "../libcli/security/security.h"
#include "lib/util_ea.h"

struct smb2_hnd {
	uint64_t fid_persistent;
	uint64_t fid_volatile;
};

/*
 * Handle mapping code.
 */

/***************************************************************
 Allocate a new fnum between 1 and 0xFFFE from an smb2_hnd.
 Ensures handle is owned by cli struct.
***************************************************************/

static NTSTATUS map_smb2_handle_to_fnum(struct cli_state *cli,
				const struct smb2_hnd *ph,	/* In */
				uint16_t *pfnum)		/* Out */
{
	int ret;
	struct idr_context *idp = cli->smb2.open_handles;
	struct smb2_hnd *owned_h = talloc_memdup(cli,
						ph,
						sizeof(struct smb2_hnd));

	if (owned_h == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (idp == NULL) {
		/* Lazy init */
		cli->smb2.open_handles = idr_init(cli);
		if (cli->smb2.open_handles == NULL) {
			TALLOC_FREE(owned_h);
			return NT_STATUS_NO_MEMORY;
		}
		idp = cli->smb2.open_handles;
	}

	ret = idr_get_new_above(idp, owned_h, 1, 0xFFFE);
	if (ret == -1) {
		TALLOC_FREE(owned_h);
		return NT_STATUS_NO_MEMORY;
	}

	*pfnum = (uint16_t)ret;
	return NT_STATUS_OK;
}

/***************************************************************
 Return the smb2_hnd pointer associated with the given fnum.
***************************************************************/

static NTSTATUS map_fnum_to_smb2_handle(struct cli_state *cli,
				uint16_t fnum,		/* In */
				struct smb2_hnd **pph)	/* Out */
{
	struct idr_context *idp = cli->smb2.open_handles;

	if (idp == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*pph = (struct smb2_hnd *)idr_find(idp, fnum);
	if (*pph == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}
	return NT_STATUS_OK;
}

/***************************************************************
 Delete the fnum to smb2_hnd mapping. Zeros out handle on
 successful return.
***************************************************************/

static NTSTATUS delete_smb2_handle_mapping(struct cli_state *cli,
				struct smb2_hnd **pph,	/* In */
				uint16_t fnum)			/* In */
{
	struct idr_context *idp = cli->smb2.open_handles;
	struct smb2_hnd *ph;

	if (idp == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ph = (struct smb2_hnd *)idr_find(idp, fnum);
	if (ph != *pph) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	idr_remove(idp, fnum);
	TALLOC_FREE(*pph);
	return NT_STATUS_OK;
}

/***************************************************************
 Oplock mapping code.
***************************************************************/

static uint8_t flags_to_smb2_oplock(uint32_t create_flags)
{
	if (create_flags & REQUEST_BATCH_OPLOCK) {
		return SMB2_OPLOCK_LEVEL_BATCH;
	} else if (create_flags & REQUEST_OPLOCK) {
		return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	}

	/* create_flags doesn't do a level2 request. */
	return SMB2_OPLOCK_LEVEL_NONE;
}

/***************************************************************
 Small wrapper that allows SMB2 create to return a uint16_t fnum.
***************************************************************/

struct cli_smb2_create_fnum_state {
	struct cli_state *cli;
	struct smb_create_returns cr;
	uint16_t fnum;
	struct tevent_req *subreq;
};

static void cli_smb2_create_fnum_done(struct tevent_req *subreq);
static bool cli_smb2_create_fnum_cancel(struct tevent_req *req);

struct tevent_req *cli_smb2_create_fnum_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli,
					     const char *fname,
					     uint32_t create_flags,
					     uint32_t desired_access,
					     uint32_t file_attributes,
					     uint32_t share_access,
					     uint32_t create_disposition,
					     uint32_t create_options)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_create_fnum_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_create_fnum_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	if (cli->backup_intent) {
		create_options |= FILE_OPEN_FOR_BACKUP_INTENT;
	}

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   start in a '\' */
	if (*fname == '\\') {
		fname++;
	}

	subreq = smb2cli_create_send(state, ev,
				     cli->conn,
				     cli->timeout,
				     cli->smb2.session,
				     cli->smb2.tcon,
				     fname,
				     flags_to_smb2_oplock(create_flags),
				     SMB2_IMPERSONATION_IMPERSONATION,
				     desired_access,
				     file_attributes,
				     share_access,
				     create_disposition,
				     create_options,
				     NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_create_fnum_done, req);

	state->subreq = subreq;
	tevent_req_set_cancel_fn(req, cli_smb2_create_fnum_cancel);

	return req;
}

static void cli_smb2_create_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_create_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_create_fnum_state);
	struct smb2_hnd h;
	NTSTATUS status;

	status = smb2cli_create_recv(subreq, &h.fid_persistent,
				     &h.fid_volatile, &state->cr, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = map_smb2_handle_to_fnum(state->cli, &h, &state->fnum);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static bool cli_smb2_create_fnum_cancel(struct tevent_req *req)
{
	struct cli_smb2_create_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_create_fnum_state);
	return tevent_req_cancel(state->subreq);
}

NTSTATUS cli_smb2_create_fnum_recv(struct tevent_req *req, uint16_t *pfnum,
				   struct smb_create_returns *cr)
{
	struct cli_smb2_create_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_create_fnum_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pfnum != NULL) {
		*pfnum = state->fnum;
	}
	if (cr != NULL) {
		*cr = state->cr;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_create_fnum(struct cli_state *cli,
			const char *fname,
			uint32_t create_flags,
			uint32_t desired_access,
			uint32_t file_attributes,
			uint32_t share_access,
			uint32_t create_disposition,
			uint32_t create_options,
			uint16_t *pfid,
			struct smb_create_returns *cr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_smb2_create_fnum_send(frame, ev, cli, fname, create_flags,
					desired_access, file_attributes,
					share_access, create_disposition,
					create_options);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_create_fnum_recv(req, pfid, cr);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Small wrapper that allows SMB2 close to use a uint16_t fnum.
***************************************************************/

struct cli_smb2_close_fnum_state {
	struct cli_state *cli;
	uint16_t fnum;
	struct smb2_hnd *ph;
};

static void cli_smb2_close_fnum_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_close_fnum_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    uint16_t fnum)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_close_fnum_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_close_fnum_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->fnum = fnum;

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = map_fnum_to_smb2_handle(cli, fnum, &state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_close_send(state, ev, cli->conn, cli->timeout,
				    cli->smb2.session, cli->smb2.tcon,
				    0, state->ph->fid_persistent,
				    state->ph->fid_volatile);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_close_fnum_done, req);
	return req;
}

static void cli_smb2_close_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_close_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_close_fnum_state);
	NTSTATUS status;

	status = smb2cli_close_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* Delete the fnum -> handle mapping. */
	status = delete_smb2_handle_mapping(state->cli, &state->ph,
					    state->fnum);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_smb2_close_fnum_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_smb2_close_fnum(struct cli_state *cli, uint16_t fnum)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_smb2_close_fnum_send(frame, ev, cli, fnum);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_close_fnum_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Small wrapper that allows SMB2 to create a directory
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_mkdir(struct cli_state *cli, const char *dname)
{
	NTSTATUS status;
	uint16_t fnum;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = cli_smb2_create_fnum(cli,
			dname,
			0,			/* create_flags */
			FILE_READ_ATTRIBUTES,	/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE, /* share_access */
			FILE_CREATE,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			&fnum,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return cli_smb2_close_fnum(cli, fnum);
}

/***************************************************************
 Small wrapper that allows SMB2 to delete a directory
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_rmdir(struct cli_state *cli, const char *dname)
{
	NTSTATUS status;
	uint16_t fnum;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = cli_smb2_create_fnum(cli,
			dname,
			0,			/* create_flags */
			DELETE_ACCESS,		/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE|FILE_DELETE_ON_CLOSE,	/* create_options */
			&fnum,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return cli_smb2_close_fnum(cli, fnum);
}

/***************************************************************
 Small wrapper that allows SMB2 to unlink a pathname.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_unlink(struct cli_state *cli, const char *fname)
{
	NTSTATUS status;
	uint16_t fnum;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = cli_smb2_create_fnum(cli,
			fname,
			0,			/* create_flags */
			DELETE_ACCESS,		/* desired_access */
			FILE_ATTRIBUTE_NORMAL, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DELETE_ON_CLOSE,	/* create_options */
			&fnum,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return cli_smb2_close_fnum(cli, fnum);
}

/***************************************************************
 Utility function to parse a SMB2_FIND_ID_BOTH_DIRECTORY_INFO reply.
***************************************************************/

static NTSTATUS parse_finfo_id_both_directory_info(uint8_t *dir_data,
				uint32_t dir_data_length,
				struct file_info *finfo,
				uint32_t *next_offset)
{
	size_t namelen = 0;
	size_t slen = 0;
	size_t ret = 0;

	if (dir_data_length < 4) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	*next_offset = IVAL(dir_data, 0);

	if (*next_offset > dir_data_length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	if (*next_offset != 0) {
		/* Ensure we only read what in this record. */
		dir_data_length = *next_offset;
	}

	if (dir_data_length < 105) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	finfo->atime_ts = interpret_long_date((const char *)dir_data + 16);
	finfo->mtime_ts = interpret_long_date((const char *)dir_data + 24);
	finfo->ctime_ts = interpret_long_date((const char *)dir_data + 32);
	finfo->size = IVAL2_TO_SMB_BIG_UINT(dir_data + 40, 0);
	finfo->mode = CVAL(dir_data + 56, 0);
	namelen = IVAL(dir_data + 60,0);
	if (namelen > (dir_data_length - 104)) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	slen = CVAL(dir_data + 68, 0);
	if (slen > 24) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	ret = pull_string_talloc(finfo,
				dir_data,
				FLAGS2_UNICODE_STRINGS,
				&finfo->short_name,
				dir_data + 70,
				slen,
				STR_UNICODE);
	if (ret == (size_t)-1) {
		/* Bad conversion. */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	ret = pull_string_talloc(finfo,
				dir_data,
				FLAGS2_UNICODE_STRINGS,
				&finfo->name,
				dir_data + 104,
				namelen,
				STR_UNICODE);
	if (ret == (size_t)-1) {
		/* Bad conversion. */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Given a filename - get its directory name
********************************************************************/

static bool windows_parent_dirname(TALLOC_CTX *mem_ctx,
				const char *dir,
				char **parent,
				const char **name)
{
	char *p;
	ptrdiff_t len;

	p = strrchr_m(dir, '\\'); /* Find final '\\', if any */

	if (p == NULL) {
		if (!(*parent = talloc_strdup(mem_ctx, "\\"))) {
			return false;
		}
		if (name) {
			*name = dir;
		}
		return true;
	}

	len = p-dir;

	if (!(*parent = (char *)talloc_memdup(mem_ctx, dir, len+1))) {
		return false;
	}
	(*parent)[len] = '\0';

	if (name) {
		*name = p+1;
	}
	return true;
}

/***************************************************************
 Wrapper that allows SMB2 to list a directory.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_list(struct cli_state *cli,
			const char *pathname,
			uint16_t attribute,
			NTSTATUS (*fn)(const char *,
				struct file_info *,
				const char *,
				void *),
			void *state)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	char *parent_dir = NULL;
	const char *mask = NULL;
	struct smb2_hnd *ph = NULL;
	bool processed_file = false;
	TALLOC_CTX *frame = talloc_stackframe();
	TALLOC_CTX *subframe = NULL;
	bool mask_has_wild;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	/* Get the directory name. */
	if (!windows_parent_dirname(frame,
				pathname,
				&parent_dir,
				&mask)) {
                status = NT_STATUS_NO_MEMORY;
		goto fail;
        }

	mask_has_wild = ms_has_wild(mask);

	status = cli_smb2_create_fnum(cli,
			parent_dir,
			0,			/* create_flags */
			SEC_DIR_LIST|SEC_DIR_READ_ATTRIBUTE,/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			&fnum,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	do {
		uint8_t *dir_data = NULL;
		uint32_t dir_data_length = 0;
		uint32_t next_offset = 0;
		subframe = talloc_stackframe();

		status = smb2cli_query_directory(cli->conn,
					cli->timeout,
					cli->smb2.session,
					cli->smb2.tcon,
					SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
					0,	/* flags */
					0,	/* file_index */
					ph->fid_persistent,
					ph->fid_volatile,
					mask,
					0xffff,
					subframe,
					&dir_data,
					&dir_data_length);

		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
				break;
			}
			goto fail;
		}

		do {
			struct file_info *finfo = talloc_zero(subframe,
							struct file_info);

			if (finfo == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto fail;
			}

			status = parse_finfo_id_both_directory_info(dir_data,
						dir_data_length,
						finfo,
						&next_offset);

			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			if (dir_check_ftype((uint32_t)finfo->mode,
					(uint32_t)attribute)) {
				/*
				 * Only process if attributes match.
				 * On SMB1 server does this, so on
				 * SMB2 we need to emulate in the
				 * client.
				 *
				 * https://bugzilla.samba.org/show_bug.cgi?id=10260
				 */
				processed_file = true;

				status = fn(cli->dfs_mountpoint,
					finfo,
					pathname,
					state);

				if (!NT_STATUS_IS_OK(status)) {
					break;
				}
			}

			TALLOC_FREE(finfo);

			/* Move to next entry. */
			if (next_offset) {
				dir_data += next_offset;
				dir_data_length -= next_offset;
			}
		} while (next_offset != 0);

		TALLOC_FREE(subframe);

		if (!mask_has_wild) {
			/*
			 * MacOSX 10 doesn't set STATUS_NO_MORE_FILES
			 * when handed a non-wildcard path. Do it
			 * for the server (with a non-wildcard path
			 * there should only ever be one file returned.
			 */
			status = STATUS_NO_MORE_FILES;
			break;
		}

	} while (NT_STATUS_IS_OK(status));

	if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
		status = NT_STATUS_OK;
	}

	if (NT_STATUS_IS_OK(status) && !processed_file) {
		/*
		 * In SMB1 findfirst returns NT_STATUS_NO_SUCH_FILE
		 * if no files match. Emulate this in the client.
		 */
		status = NT_STATUS_NO_SUCH_FILE;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}
	TALLOC_FREE(subframe);
	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a path info (basic level).
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qpathinfo_basic(struct cli_state *cli,
				const char *name,
				SMB_STRUCT_STAT *sbuf,
				uint32_t *attributes)
{
	NTSTATUS status;
	struct smb_create_returns cr;
	uint16_t fnum = 0xffff;
	size_t namelen = strlen(name);

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   end in a '\' */
	if (namelen > 0 && name[namelen-1] == '\\') {
		char *modname = talloc_strdup(talloc_tos(), name);
		modname[namelen-1] = '\0';
		name = modname;
	}

	/* This is commonly used as a 'cd'. Try qpathinfo on
	   a directory handle first. */

	status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			FILE_READ_ATTRIBUTES,	/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			&fnum,
			&cr);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_DIRECTORY)) {
		/* Maybe a file ? */
		status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			FILE_READ_ATTRIBUTES,		/* desired_access */
			0, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			0,	/* create_options */
			&fnum,
			&cr);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	cli_smb2_close_fnum(cli, fnum);

	ZERO_STRUCTP(sbuf);

	sbuf->st_ex_atime = nt_time_to_unix_timespec(cr.last_access_time);
	sbuf->st_ex_mtime = nt_time_to_unix_timespec(cr.last_write_time);
	sbuf->st_ex_ctime = nt_time_to_unix_timespec(cr.change_time);
	sbuf->st_ex_size = cr.end_of_file;
	*attributes = cr.file_attributes;

	return NT_STATUS_OK;
}

/***************************************************************
 Helper function for pathname operations.
***************************************************************/

static NTSTATUS get_fnum_from_path(struct cli_state *cli,
				const char *name,
				uint32_t desired_access,
				uint16_t *pfnum)
{
	NTSTATUS status;
	size_t namelen = strlen(name);
	TALLOC_CTX *frame = talloc_stackframe();

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   end in a '\' */
	if (namelen > 0 && name[namelen-1] == '\\') {
		char *modname = talloc_strdup(frame, name);
		if (modname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		modname[namelen-1] = '\0';
		name = modname;
	}

	/* Try to open a file handle first. */
	status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			desired_access,
			0, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			0,	/* create_options */
			pfnum,
			NULL);

	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_IS_A_DIRECTORY)) {
		status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			desired_access,
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			pfnum,
			NULL);
	}

  fail:

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a path info (ALTNAME level).
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qpathinfo_alt_name(struct cli_state *cli,
				const char *name,
				fstring alt_name)
{
	NTSTATUS status;
	DATA_BLOB outbuf = data_blob_null;
	uint16_t fnum = 0xffff;
	struct smb2_hnd *ph = NULL;
	uint32_t altnamelen = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_READ_ATTRIBUTES,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level SMB_FILE_ALTERNATE_NAME_INFORMATION (1021) == SMB2 21 */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				(SMB_FILE_ALTERNATE_NAME_INFORMATION - 1000), /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				0, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	if (outbuf.length < 4) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	altnamelen = IVAL(outbuf.data, 0);
	if (altnamelen > outbuf.length - 4) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	if (altnamelen > 0) {
		size_t ret = 0;
		char *short_name = NULL;
		ret = pull_string_talloc(frame,
				outbuf.data,
				FLAGS2_UNICODE_STRINGS,
				&short_name,
				outbuf.data + 4,
				altnamelen,
				STR_UNICODE);
		if (ret == (size_t)-1) {
			/* Bad conversion. */
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			goto fail;
		}

	        fstrcpy(alt_name, short_name);
	} else {
		alt_name[0] = '\0';
	}

	status = NT_STATUS_OK;

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}
	TALLOC_FREE(frame);
	return status;
}


/***************************************************************
 Wrapper that allows SMB2 to query a fnum info (basic level).
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qfileinfo_basic(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *mode,
			off_t *size,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			SMB_INO_T *ino)
{
	NTSTATUS status;
	DATA_BLOB outbuf = data_blob_null;
	struct smb2_hnd *ph = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level 0x12 (SMB2_FILE_ALL_INFORMATION). */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				(SMB_FILE_ALL_INFORMATION - 1000), /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				0, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	if (outbuf.length < 0x60) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	if (create_time) {
		*create_time = interpret_long_date((const char *)outbuf.data + 0x0);
	}
	if (access_time) {
		*access_time = interpret_long_date((const char *)outbuf.data + 0x8);
	}
	if (write_time) {
		*write_time = interpret_long_date((const char *)outbuf.data + 0x10);
	}
	if (change_time) {
		*change_time = interpret_long_date((const char *)outbuf.data + 0x18);
	}
	if (mode) {
		uint32_t attr = IVAL(outbuf.data, 0x20);
		*mode = (uint16_t)attr;
	}
	if (size) {
		uint64_t file_size = BVAL(outbuf.data, 0x30);
		*size = (off_t)file_size;
	}
	if (ino) {
		uint64_t file_index = BVAL(outbuf.data, 0x40);
		*ino = (SMB_INO_T)file_index;
	}

  fail:

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query an fnum.
 Implement on top of cli_smb2_qfileinfo_basic().
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_getattrE(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *attr,
			off_t *size,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time)
{
	struct timespec access_time_ts;
	struct timespec write_time_ts;
	struct timespec change_time_ts;
	NTSTATUS status = cli_smb2_qfileinfo_basic(cli,
					fnum,
					attr,
					size,
					NULL,
					&access_time_ts,
					&write_time_ts,
					&change_time_ts,
                                        NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (change_time) {
		*change_time = change_time_ts.tv_sec;
	}
	if (access_time) {
		*access_time = access_time_ts.tv_sec;
	}
	if (write_time) {
		*write_time = write_time_ts.tv_sec;
	}
	return NT_STATUS_OK;
}

/***************************************************************
 Wrapper that allows SMB2 to get pathname attributes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_getatr(struct cli_state *cli,
			const char *name,
			uint16_t *attr,
			off_t *size,
			time_t *write_time)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	struct smb2_hnd *ph = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_READ_ATTRIBUTES,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	status = cli_smb2_getattrE(cli,
				fnum,
				attr,
				size,
				NULL,
				NULL,
				write_time);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a pathname info (basic level).
 Implement on top of cli_smb2_qfileinfo_basic().
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qpathinfo2(struct cli_state *cli,
			const char *name,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size,
			uint16_t *mode,
			SMB_INO_T *ino)
{
	NTSTATUS status;
	struct smb2_hnd *ph = NULL;
	uint16_t fnum = 0xffff;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
					name,
					FILE_READ_ATTRIBUTES,
					&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = cli_smb2_qfileinfo_basic(cli,
					fnum,
					mode,
					size,
					create_time,
					access_time,
					write_time,
					change_time,
					ino);

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query pathname streams.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qpathinfo_streams(struct cli_state *cli,
				const char *name,
				TALLOC_CTX *mem_ctx,
				unsigned int *pnum_streams,
				struct stream_struct **pstreams)
{
	NTSTATUS status;
	struct smb2_hnd *ph = NULL;
	uint16_t fnum = 0xffff;
	DATA_BLOB outbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_READ_ATTRIBUTES,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level 22 (SMB2_FILE_STREAM_INFORMATION). */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				(SMB_FILE_STREAM_INFORMATION - 1000), /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				0, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	if (!parse_streams_blob(mem_ctx,
				outbuf.data,
				outbuf.length,
				pnum_streams,
				pstreams)) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set pathname attributes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_setatr(struct cli_state *cli,
			const char *name,
			uint16_t attr,
			time_t mtime)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	struct smb2_hnd *ph = NULL;
	uint8_t inbuf_store[40];
	DATA_BLOB inbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_WRITE_ATTRIBUTES,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	   level 4 (SMB_FILE_BASIC_INFORMATION - 1000). */

	inbuf.data = inbuf_store;
	inbuf.length = sizeof(inbuf_store);
	data_blob_clear(&inbuf);

	SSVAL(inbuf.data, 32, attr);
	if (mtime != 0) {
		put_long_date((char *)inbuf.data + 16,mtime);
	}
	/* Set all the other times to -1. */
	SBVAL(inbuf.data, 0, 0xFFFFFFFFFFFFFFFFLL);
	SBVAL(inbuf.data, 8, 0xFFFFFFFFFFFFFFFFLL);
	SBVAL(inbuf.data, 24, 0xFFFFFFFFFFFFFFFFLL);

	status = smb2cli_set_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				SMB_FILE_BASIC_INFORMATION - 1000, /* in_file_info_class */
				&inbuf, /* in_input_buffer */
				0, /* in_additional_info */
				ph->fid_persistent,
				ph->fid_volatile);
  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set file handle times.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_setattrE(struct cli_state *cli,
			uint16_t fnum,
			time_t change_time,
			time_t access_time,
			time_t write_time)
{
	NTSTATUS status;
	struct smb2_hnd *ph = NULL;
	uint8_t inbuf_store[40];
	DATA_BLOB inbuf = data_blob_null;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	   level 4 (SMB_FILE_BASIC_INFORMATION - 1000). */

	inbuf.data = inbuf_store;
	inbuf.length = sizeof(inbuf_store);
	data_blob_clear(&inbuf);

	SBVAL(inbuf.data, 0, 0xFFFFFFFFFFFFFFFFLL);
	if (change_time != 0) {
		put_long_date((char *)inbuf.data + 24, change_time);
	}
	if (access_time != 0) {
		put_long_date((char *)inbuf.data + 8, access_time);
	}
	if (write_time != 0) {
		put_long_date((char *)inbuf.data + 16, write_time);
	}

	return smb2cli_set_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				SMB_FILE_BASIC_INFORMATION - 1000, /* in_file_info_class */
				&inbuf, /* in_input_buffer */
				0, /* in_additional_info */
				ph->fid_persistent,
				ph->fid_volatile);
}

/***************************************************************
 Wrapper that allows SMB2 to query disk attributes (size).
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_dskattr(struct cli_state *cli, uint64_t *bsize, uint64_t *total, uint64_t *avail)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	DATA_BLOB outbuf = data_blob_null;
	struct smb2_hnd *ph = NULL;
	uint32_t sectors_per_unit = 0;
	uint32_t bytes_per_sector = 0;
	uint64_t total_size = 0;
	uint64_t size_free = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	/* First open the top level directory. */
	status = cli_smb2_create_fnum(cli,
			"",
			0,			/* create_flags */
			FILE_READ_ATTRIBUTES,	/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			&fnum,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the returned handle with info_type SMB2_GETINFO_FS (2),
	   level 3 (SMB_FS_SIZE_INFORMATION). */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				2, /* in_info_type */
				3, /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				0, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	if (outbuf.length != 24) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	total_size = BVAL(outbuf.data, 0);
	size_free = BVAL(outbuf.data, 8);
	sectors_per_unit = IVAL(outbuf.data, 16);
	bytes_per_sector = IVAL(outbuf.data, 20);

	if (bsize) {
		*bsize = (uint64_t)sectors_per_unit * (uint64_t)bytes_per_sector;
	}
	if (total) {
		*total = total_size;
	}
	if (avail) {
		*avail = size_free;
	}

	status = NT_STATUS_OK;

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a security descriptor.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_query_security_descriptor(struct cli_state *cli,
					uint16_t fnum,
					uint32_t sec_info,
					TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppsd)
{
	NTSTATUS status;
	DATA_BLOB outbuf = data_blob_null;
	struct smb2_hnd *ph = NULL;
	struct security_descriptor *lsd = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the returned handle with info_type SMB2_GETINFO_SEC (3) */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				3, /* in_info_type */
				0, /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				sec_info, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	status = unmarshall_sec_desc(mem_ctx,
				outbuf.data,
				outbuf.length,
				&lsd);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (ppsd != NULL) {
		*ppsd = lsd;
	} else {
		TALLOC_FREE(lsd);
	}

  fail:

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set a security descriptor.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_set_security_descriptor(struct cli_state *cli,
					uint16_t fnum,
					uint32_t sec_info,
					const struct security_descriptor *sd)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	struct smb2_hnd *ph = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = marshall_sec_desc(frame,
				sd,
				&inbuf.data,
				&inbuf.length);

        if (!NT_STATUS_IS_OK(status)) {
		goto fail;
        }

	/* setinfo on the returned handle with info_type SMB2_SETINFO_SEC (3) */

	status = smb2cli_set_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				3, /* in_info_type */
				0, /* in_file_info_class */
				&inbuf, /* in_input_buffer */
				sec_info, /* in_additional_info */
				ph->fid_persistent,
				ph->fid_volatile);

  fail:

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to rename a file.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_rename(struct cli_state *cli,
			const char *fname_src,
			const char *fname_dst)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	uint16_t fnum = 0xffff;
	struct smb2_hnd *ph = NULL;
	smb_ucs2_t *converted_str = NULL;
	size_t converted_size_bytes = 0;
	size_t namelen = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				fname_src,
				DELETE_ACCESS,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   start in a '\' */
	if (*fname_dst == '\\') {
		fname_dst++;
	}

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   end in a '\' */
	namelen = strlen(fname_dst);
	if (namelen > 0 && fname_dst[namelen-1] == '\\') {
		char *modname = talloc_strdup(frame, fname_dst);
		modname[namelen-1] = '\0';
		fname_dst = modname;
	}

	if (!push_ucs2_talloc(frame,
				&converted_str,
				fname_dst,
				&converted_size_bytes)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	/* W2K8 insists the dest name is not null
	   terminated. Remove the last 2 zero bytes
	   and reduce the name length. */

	if (converted_size_bytes < 2) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	converted_size_bytes -= 2;

	inbuf = data_blob_talloc_zero(frame,
				20 + converted_size_bytes);
	if (inbuf.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	SIVAL(inbuf.data, 16, converted_size_bytes);
	memcpy(inbuf.data + 20, converted_str, converted_size_bytes);

	/* setinfo on the returned handle with info_type SMB2_GETINFO_FILE (1),
	   level SMB2_FILE_RENAME_INFORMATION (SMB_FILE_RENAME_INFORMATION - 1000) */

	status = smb2cli_set_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				SMB_FILE_RENAME_INFORMATION - 1000, /* in_file_info_class */
				&inbuf, /* in_input_buffer */
				0, /* in_additional_info */
				ph->fid_persistent,
				ph->fid_volatile);

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set an EA on a fnum.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_set_ea_fnum(struct cli_state *cli,
			uint16_t fnum,
			const char *ea_name,
			const char *ea_val,
			size_t ea_len)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	size_t bloblen = 0;
	char *ea_name_ascii = NULL;
	size_t namelen = 0;
	struct smb2_hnd *ph = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Marshall the SMB2 EA data. */
	if (ea_len > 0xFFFF) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (!push_ascii_talloc(frame,
				&ea_name_ascii,
				ea_name,
				&namelen)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (namelen < 2 || namelen > 0xFF) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	bloblen = 8 + ea_len + namelen;
	/* Round up to a 4 byte boundary. */
	bloblen = ((bloblen + 3)&~3);

	inbuf = data_blob_talloc_zero(frame, bloblen);
	if (inbuf.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	/* namelen doesn't include the NULL byte. */
	SCVAL(inbuf.data, 5, namelen - 1);
	SSVAL(inbuf.data, 6, ea_len);
	memcpy(inbuf.data + 8, ea_name_ascii, namelen);
	memcpy(inbuf.data + 8 + namelen, ea_val, ea_len);

	/* setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	   level 15 (SMB_FILE_FULL_EA_INFORMATION - 1000). */

	status = smb2cli_set_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				SMB_FILE_FULL_EA_INFORMATION - 1000, /* in_file_info_class */
				&inbuf, /* in_input_buffer */
				0, /* in_additional_info */
				ph->fid_persistent,
				ph->fid_volatile);

  fail:

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set an EA on a pathname.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_set_ea_path(struct cli_state *cli,
			const char *name,
			const char *ea_name,
			const char *ea_val,
			size_t ea_len)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_WRITE_EA,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = cli_set_ea_fnum(cli,
				fnum,
				ea_name,
				ea_val,
				ea_len);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to get an EA list on a pathname.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_ea_list_path(struct cli_state *cli,
				const char *name,
				TALLOC_CTX *ctx,
				size_t *pnum_eas,
				struct ea_struct **pea_array)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	DATA_BLOB outbuf = data_blob_null;
	struct smb2_hnd *ph = NULL;
	struct ea_list *ea_list = NULL;
	struct ea_list *eal = NULL;
	size_t ea_count = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	*pnum_eas = 0;
	*pea_array = NULL;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	status = get_fnum_from_path(cli,
				name,
				FILE_READ_EA,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&ph);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level 15 (SMB_FILE_FULL_EA_INFORMATION - 1000). */

	status = smb2cli_query_info(cli->conn,
				cli->timeout,
				cli->smb2.session,
				cli->smb2.tcon,
				1, /* in_info_type */
				SMB_FILE_FULL_EA_INFORMATION - 1000, /* in_file_info_class */
				0xFFFF, /* in_max_output_length */
				NULL, /* in_input_buffer */
				0, /* in_additional_info */
				0, /* in_flags */
				ph->fid_persistent,
				ph->fid_volatile,
				frame,
				&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Parse the reply. */
	ea_list = read_nttrans_ea_list(ctx,
				(const char *)outbuf.data,
				outbuf.length);
	if (ea_list == NULL) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	/* Convert to an array. */
	for (eal = ea_list; eal; eal = eal->next) {
		ea_count++;
	}

	if (ea_count) {
		*pea_array = talloc_array(ctx, struct ea_struct, ea_count);
		if (*pea_array == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		ea_count = 0;
		for (eal = ea_list; eal; eal = eal->next) {
			(*pea_array)[ea_count++] = ea_list->ea;
		}
		*pnum_eas = ea_count;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	TALLOC_FREE(frame);
	return status;
}

struct cli_smb2_read_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct smb2_hnd *ph;
	uint64_t start_offset;
	uint32_t size;
	uint32_t received;
	uint8_t *buf;
};

static void cli_smb2_read_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_read_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				off_t offset,
				size_t size)
{
	NTSTATUS status;
	struct tevent_req *req, *subreq;
	struct cli_smb2_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->start_offset = (uint64_t)offset;
	state->size = (uint32_t)size;
	state->received = 0;
	state->buf = NULL;

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_read_send(state,
				state->ev,
				state->cli->conn,
				state->cli->timeout,
				state->cli->smb2.session,
				state->cli->smb2.tcon,
				state->size,
				state->start_offset,
				state->ph->fid_persistent,
				state->ph->fid_volatile,
				0, /* minimum_count */
				0); /* remaining_bytes */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_read_done, req);
	return req;
}

static void cli_smb2_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_read_state *state = tevent_req_data(
		req, struct cli_smb2_read_state);
	NTSTATUS status;

	status = smb2cli_read_recv(subreq, state,
				   &state->buf, &state->received);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->received > state->size) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS cli_smb2_read_recv(struct tevent_req *req,
				ssize_t *received,
				uint8_t **rcvbuf)
{
	NTSTATUS status;
	struct cli_smb2_read_state *state = tevent_req_data(
				req, struct cli_smb2_read_state);

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	/*
	 * As in cli_read_andx_recv() rcvbuf is talloced from the request, so
	 * better make sure that you copy it away before you talloc_free(req).
	 * "rcvbuf" is NOT a talloc_ctx of its own, so do not talloc_move it!
	 */
	*received = (ssize_t)state->received;
	*rcvbuf = state->buf;
	return NT_STATUS_OK;
}

struct cli_smb2_write_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct smb2_hnd *ph;
	uint32_t flags;
	const uint8_t *buf;
	uint64_t offset;
	uint32_t size;
	uint32_t written;
};

static void cli_smb2_write_written(struct tevent_req *req);

struct tevent_req *cli_smb2_write_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					uint16_t mode,
					const uint8_t *buf,
					off_t offset,
					size_t size)
{
	NTSTATUS status;
	struct tevent_req *req, *subreq = NULL;
	struct cli_smb2_write_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_write_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	/* Both SMB1 and SMB2 use 1 in the following meaning write-through. */
	state->flags = (uint32_t)mode;
	state->buf = buf;
	state->offset = (uint64_t)offset;
	state->size = (uint32_t)size;
	state->written = 0;

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_write_send(state,
				state->ev,
				state->cli->conn,
				state->cli->timeout,
				state->cli->smb2.session,
				state->cli->smb2.tcon,
				state->size,
				state->offset,
				state->ph->fid_persistent,
				state->ph->fid_volatile,
				0, /* remaining_bytes */
				state->flags, /* flags */
				state->buf);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_write_written, req);
	return req;
}

static void cli_smb2_write_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_write_state *state = tevent_req_data(
		req, struct cli_smb2_write_state);
        NTSTATUS status;
	uint32_t written;

	status = smb2cli_write_recv(subreq, &written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->written = written;

	tevent_req_done(req);
}

NTSTATUS cli_smb2_write_recv(struct tevent_req *req,
			     size_t *pwritten)
{
	struct cli_smb2_write_state *state = tevent_req_data(
		req, struct cli_smb2_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	if (pwritten != NULL) {
		*pwritten = (size_t)state->written;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/***************************************************************
 Wrapper that allows SMB2 async write using an fnum.
 This is mostly cut-and-paste from Volker's code inside
 source3/libsmb/clireadwrite.c, adapted for SMB2.

 Done this way so I can reuse all the logic inside cli_push()
 for free :-).
***************************************************************/

struct cli_smb2_writeall_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct smb2_hnd *ph;
	uint32_t flags;
	const uint8_t *buf;
	uint64_t offset;
	uint32_t size;
	uint32_t written;
};

static void cli_smb2_writeall_written(struct tevent_req *req);

struct tevent_req *cli_smb2_writeall_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					uint16_t mode,
					const uint8_t *buf,
					off_t offset,
					size_t size)
{
	NTSTATUS status;
	struct tevent_req *req, *subreq = NULL;
	struct cli_smb2_writeall_state *state = NULL;
	uint32_t to_write;
	uint32_t max_size;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_writeall_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	/* Both SMB1 and SMB2 use 1 in the following meaning write-through. */
	state->flags = (uint32_t)mode;
	state->buf = buf;
	state->offset = (uint64_t)offset;
	state->size = (uint32_t)size;
	state->written = 0;

	status = map_fnum_to_smb2_handle(cli,
					fnum,
					&state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	to_write = state->size;
	max_size = smb2cli_conn_max_write_size(state->cli->conn);
	to_write = MIN(max_size, to_write);
	ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
	if (ok) {
		to_write = MIN(max_size, to_write);
	}

	subreq = smb2cli_write_send(state,
				state->ev,
				state->cli->conn,
				state->cli->timeout,
				state->cli->smb2.session,
				state->cli->smb2.tcon,
				to_write,
				state->offset,
				state->ph->fid_persistent,
				state->ph->fid_volatile,
				0, /* remaining_bytes */
				state->flags, /* flags */
				state->buf + state->written);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_writeall_written, req);
	return req;
}

static void cli_smb2_writeall_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_writeall_state *state = tevent_req_data(
		req, struct cli_smb2_writeall_state);
        NTSTATUS status;
	uint32_t written, to_write;
	uint32_t max_size;
	bool ok;

	status = smb2cli_write_recv(subreq, &written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->written += written;

	if (state->written > state->size) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	to_write = state->size - state->written;

	if (to_write == 0) {
		tevent_req_done(req);
		return;
	}

	max_size = smb2cli_conn_max_write_size(state->cli->conn);
	to_write = MIN(max_size, to_write);
	ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
	if (ok) {
		to_write = MIN(max_size, to_write);
	}

	subreq = smb2cli_write_send(state,
				state->ev,
				state->cli->conn,
				state->cli->timeout,
				state->cli->smb2.session,
				state->cli->smb2.tcon,
				to_write,
				state->offset + state->written,
				state->ph->fid_persistent,
				state->ph->fid_volatile,
				0, /* remaining_bytes */
				state->flags, /* flags */
				state->buf + state->written);

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_writeall_written, req);
}

NTSTATUS cli_smb2_writeall_recv(struct tevent_req *req,
				size_t *pwritten)
{
	struct cli_smb2_writeall_state *state = tevent_req_data(
		req, struct cli_smb2_writeall_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = (size_t)state->written;
	}
	return NT_STATUS_OK;
}

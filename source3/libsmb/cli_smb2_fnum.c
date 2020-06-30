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
#include "../librpc/gen_ndr/ndr_security.h"
#include "lib/util_ea.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "ntioctl.h"
#include "librpc/gen_ndr/ndr_quota.h"

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
	struct smb2_create_blobs in_cblobs;
	struct smb2_create_blobs out_cblobs;
	struct smb_create_returns cr;
	uint16_t fnum;
	struct tevent_req *subreq;
};

static void cli_smb2_create_fnum_done(struct tevent_req *subreq);
static bool cli_smb2_create_fnum_cancel(struct tevent_req *req);

struct tevent_req *cli_smb2_create_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname,
	uint32_t create_flags,
	uint32_t impersonation_level,
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	const struct smb2_create_blobs *in_cblobs)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_create_fnum_state *state;
	size_t fname_len = 0;
	const char *startp = NULL;
	const char *endp = NULL;
	time_t tstamp = (time_t)0;
	NTSTATUS status;

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

	/* Check for @GMT- paths. Remove the @GMT and turn into TWrp if so. */
	fname_len = strlen(fname);
	if (clistr_is_previous_version_path(fname, &startp, &endp, &tstamp)) {
		size_t len_before_gmt = startp - fname;
		size_t len_after_gmt = fname + fname_len - endp;
		DATA_BLOB twrp_blob;
		NTTIME ntt;

		char *new_fname = talloc_array(state, char,
				len_before_gmt + len_after_gmt + 1);

		if (tevent_req_nomem(new_fname, req)) {
			return tevent_req_post(req, ev);
		}

		memcpy(new_fname, fname, len_before_gmt);
		memcpy(new_fname + len_before_gmt, endp, len_after_gmt + 1);
		fname = new_fname;
		fname_len = len_before_gmt + len_after_gmt;

		unix_to_nt_time(&ntt, tstamp);
		twrp_blob = data_blob_const((const void *)&ntt, 8);

		status = smb2_create_blob_add(
			state,
			&state->in_cblobs,
			SMB2_CREATE_TAG_TWRP,
			twrp_blob);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
	}

	if (in_cblobs != NULL) {
		uint32_t i;
		for (i=0; i<in_cblobs->num_blobs; i++) {
			struct smb2_create_blob *b = &in_cblobs->blobs[i];
			status = smb2_create_blob_add(
				state, &state->in_cblobs, b->tag, b->data);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}
	}

	/* SMB2 is pickier about pathnames. Ensure it doesn't
	   start in a '\' */
	if (*fname == '\\') {
		fname++;
		fname_len--;
	}

	/* Or end in a '\' */
	if (fname_len > 0 && fname[fname_len-1] == '\\') {
		char *new_fname = talloc_strdup(state, fname);
		if (tevent_req_nomem(new_fname, req)) {
			return tevent_req_post(req, ev);
		}
		new_fname[fname_len-1] = '\0';
		fname = new_fname;
	}

	subreq = smb2cli_create_send(state, ev,
				     cli->conn,
				     cli->timeout,
				     cli->smb2.session,
				     cli->smb2.tcon,
				     fname,
				     flags_to_smb2_oplock(create_flags),
				     impersonation_level,
				     desired_access,
				     file_attributes,
				     share_access,
				     create_disposition,
				     create_options,
				     &state->in_cblobs);
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

	status = smb2cli_create_recv(
		subreq,
		&h.fid_persistent,
		&h.fid_volatile, &state->cr,
		state,
		&state->out_cblobs);
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

NTSTATUS cli_smb2_create_fnum_recv(
	struct tevent_req *req,
	uint16_t *pfnum,
	struct smb_create_returns *cr,
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs *out_cblobs)
{
	struct cli_smb2_create_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_create_fnum_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		state->cli->raw_status = status;
		return status;
	}
	if (pfnum != NULL) {
		*pfnum = state->fnum;
	}
	if (cr != NULL) {
		*cr = state->cr;
	}
	if (out_cblobs != NULL) {
		*out_cblobs = (struct smb2_create_blobs) {
			.num_blobs = state->out_cblobs.num_blobs,
			.blobs = talloc_move(
				mem_ctx, &state->out_cblobs.blobs),
		};
	}
	state->cli->raw_status = NT_STATUS_OK;
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_create_fnum(
	struct cli_state *cli,
	const char *fname,
	uint32_t create_flags,
	uint32_t impersonation_level,
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	const struct smb2_create_blobs *in_cblobs,
	uint16_t *pfid,
	struct smb_create_returns *cr,
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs *out_cblobs)
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
	req = cli_smb2_create_fnum_send(
		frame,
		ev,
		cli,
		fname,
		create_flags,
		impersonation_level,
		desired_access,
		file_attributes,
		share_access,
		create_disposition,
		create_options,
		in_cblobs);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_create_fnum_recv(req, pfid, cr, mem_ctx, out_cblobs);
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
	struct cli_smb2_close_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_close_fnum_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status)) {
		state->cli->raw_status = status;
	}
	tevent_req_received(req);
	return status;
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

struct cli_smb2_set_info_fnum_state {
	uint8_t dummy;
};

static void cli_smb2_set_info_fnum_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_set_info_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_set_info_fnum_state *state = NULL;
	struct smb2_hnd *ph = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_smb2_set_info_fnum_state);
	if (req == NULL) {
		return NULL;
	}

	status = map_fnum_to_smb2_handle(cli, fnum, &ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_set_info_send(
		state,
		ev,
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		in_info_type,
		in_info_class,
		in_input_buffer,
		in_additional_info,
		ph->fid_persistent,
		ph->fid_volatile);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_set_info_fnum_done, req);
	return req;
}

static void cli_smb2_set_info_fnum_done(struct tevent_req *subreq)
{
	NTSTATUS status = smb2cli_set_info_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_set_info_fnum_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_smb2_set_info_fnum(
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

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
	req = cli_smb2_set_info_fnum_send(
		frame,
		ev,
		cli,
		fnum,
		in_info_type,
		in_info_class,
		in_input_buffer,
		in_additional_info);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = cli_smb2_set_info_fnum_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_smb2_delete_on_close_state {
	struct cli_state *cli;
	uint8_t data[1];
	DATA_BLOB inbuf;
};

static void cli_smb2_delete_on_close_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_delete_on_close_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					bool flag)
{
	struct tevent_req *req = NULL;
	struct cli_smb2_delete_on_close_state *state = NULL;
	struct tevent_req *subreq = NULL;
	uint8_t in_info_type;
	uint8_t in_file_info_class;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_delete_on_close_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	/*
	 * setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	 * level 13 (SMB_FILE_DISPOSITION_INFORMATION - 1000).
	 */
	in_info_type = 1;
	in_file_info_class = SMB_FILE_DISPOSITION_INFORMATION - 1000;
	/* Setup data array. */
	SCVAL(&state->data[0], 0, flag ? 1 : 0);
	state->inbuf.data = &state->data[0];
	state->inbuf.length = 1;

	subreq = cli_smb2_set_info_fnum_send(
		state,
		ev,
		cli,
		fnum,
		in_info_type,
		in_file_info_class,
		&state->inbuf,
		0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_smb2_delete_on_close_done,
				req);
	return req;
}

static void cli_smb2_delete_on_close_done(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_set_info_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_delete_on_close_recv(struct tevent_req *req)
{
	struct cli_smb2_delete_on_close_state *state =
		tevent_req_data(req,
		struct cli_smb2_delete_on_close_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		state->cli->raw_status = status;
		tevent_req_received(req);
		return status;
	}

	state->cli->raw_status = NT_STATUS_OK;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_delete_on_close(struct cli_state *cli, uint16_t fnum, bool flag)
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
	req = cli_smb2_delete_on_close_send(frame, ev, cli, fnum, flag);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_delete_on_close_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_smb2_mkdir_state {
	struct tevent_context *ev;
	struct cli_state *cli;
};

static void cli_smb2_mkdir_opened(struct tevent_req *subreq);
static void cli_smb2_mkdir_closed(struct tevent_req *subreq);

struct tevent_req *cli_smb2_mkdir_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *dname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_mkdir_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_smb2_mkdir_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	/* Ensure this is a directory. */
	subreq = cli_smb2_create_fnum_send(
		state,				   /* mem_ctx */
		ev,				   /* ev */
		cli,				   /* cli */
		dname,				   /* fname */
		0,				   /* create_flags */
		SMB2_IMPERSONATION_IMPERSONATION,  /* impersonation_level */
		FILE_READ_ATTRIBUTES,		   /* desired_access */
		FILE_ATTRIBUTE_DIRECTORY,	   /* file_attributes */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE,		   /* share_access */
		FILE_CREATE,			   /* create_disposition */
		FILE_DIRECTORY_FILE,		   /* create_options */
		NULL);				   /* in_cblobs */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_mkdir_opened, req);
	return req;
}

static void cli_smb2_mkdir_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_mkdir_state *state = tevent_req_data(
		req, struct cli_smb2_mkdir_state);
	NTSTATUS status;
	uint16_t fnum;

	status = cli_smb2_create_fnum_recv(subreq, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_close_fnum_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_mkdir_closed, req);
}

static void cli_smb2_mkdir_closed(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_close_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_mkdir_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct cli_smb2_rmdir_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *dname;
	const struct smb2_create_blobs *in_cblobs;
	uint16_t fnum;
	NTSTATUS status;
};

static void cli_smb2_rmdir_opened1(struct tevent_req *subreq);
static void cli_smb2_rmdir_opened2(struct tevent_req *subreq);
static void cli_smb2_rmdir_disp_set(struct tevent_req *subreq);
static void cli_smb2_rmdir_closed(struct tevent_req *subreq);

struct tevent_req *cli_smb2_rmdir_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *dname,
	const struct smb2_create_blobs *in_cblobs)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_rmdir_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_rmdir_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->dname = dname;
	state->in_cblobs = in_cblobs;

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb2_create_fnum_send(
		state,
		state->ev,
		state->cli,
		state->dname,
		0,			/* create_flags */
		SMB2_IMPERSONATION_IMPERSONATION,
		DELETE_ACCESS,		/* desired_access */
		FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
		FILE_OPEN,		/* create_disposition */
		FILE_DIRECTORY_FILE,	/* create_options */
		state->in_cblobs);	/* in_cblobs */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_rmdir_opened1, req);
	return req;
}

static void cli_smb2_rmdir_opened1(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_rmdir_state *state = tevent_req_data(
		req, struct cli_smb2_rmdir_state);
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(
		subreq, &state->fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		/*
		 * Naive option to match our SMB1 code. Assume the
		 * symlink path that tripped us up was the last
		 * component and try again. Eventually we will have to
		 * deal with the returned path unprocessed component. JRA.
		 */
		subreq = cli_smb2_create_fnum_send(
			state,
			state->ev,
			state->cli,
			state->dname,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			DELETE_ACCESS,		/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE|
			FILE_DELETE_ON_CLOSE|
			FILE_OPEN_REPARSE_POINT, /* create_options */
			state->in_cblobs);	 /* in_cblobs */
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, cli_smb2_rmdir_opened2, req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_delete_on_close_send(
		state, state->ev, state->cli, state->fnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_rmdir_disp_set, req);
}

static void cli_smb2_rmdir_opened2(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_rmdir_state *state = tevent_req_data(
		req, struct cli_smb2_rmdir_state);
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(
		subreq, &state->fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_delete_on_close_send(
		state, state->ev, state->cli, state->fnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_rmdir_disp_set, req);
}

static void cli_smb2_rmdir_disp_set(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_rmdir_state *state = tevent_req_data(
		req, struct cli_smb2_rmdir_state);

	state->status = cli_smb2_delete_on_close_recv(subreq);
	TALLOC_FREE(subreq);

	/*
	 * Close the fd even if the set_disp failed
	 */

	subreq = cli_smb2_close_fnum_send(
		state, state->ev, state->cli, state->fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_rmdir_closed, req);
}

static void cli_smb2_rmdir_closed(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_close_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_rmdir_recv(struct tevent_req *req)
{
	struct cli_smb2_rmdir_state *state = tevent_req_data(
		req, struct cli_smb2_rmdir_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return state->status;
}

/***************************************************************
 Small wrapper that allows SMB2 to unlink a pathname.
***************************************************************/

struct cli_smb2_unlink_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *fname;
	const struct smb2_create_blobs *in_cblobs;
};

static void cli_smb2_unlink_opened1(struct tevent_req *subreq);
static void cli_smb2_unlink_opened2(struct tevent_req *subreq);
static void cli_smb2_unlink_closed(struct tevent_req *subreq);

struct tevent_req *cli_smb2_unlink_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname,
	const struct smb2_create_blobs *in_cblobs)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_unlink_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_unlink_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fname = fname;
	state->in_cblobs = in_cblobs;

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb2_create_fnum_send(
		state,		/* mem_ctx */
		state->ev,	/* tevent_context */
		state->cli,	/* cli_struct */
		state->fname,	/* filename */
		0,			/* create_flags */
		SMB2_IMPERSONATION_IMPERSONATION,
		DELETE_ACCESS,		/* desired_access */
		FILE_ATTRIBUTE_NORMAL, /* file attributes */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE, /* share_access */
		FILE_OPEN,		/* create_disposition */
		FILE_DELETE_ON_CLOSE,	/* create_options */
		state->in_cblobs);	/* in_cblobs */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_unlink_opened1, req);
	return req;
}

static void cli_smb2_unlink_opened1(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_unlink_state *state = tevent_req_data(
		req, struct cli_smb2_unlink_state);
	uint16_t fnum;
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(subreq, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		/*
		 * Naive option to match our SMB1 code. Assume the
		 * symlink path that tripped us up was the last
		 * component and try again. Eventually we will have to
		 * deal with the returned path unprocessed component. JRA.
		 */
		subreq = cli_smb2_create_fnum_send(
			state,		/* mem_ctx */
			state->ev,	/* tevent_context */
			state->cli,	/* cli_struct */
			state->fname,	/* filename */
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			DELETE_ACCESS,		/* desired_access */
			FILE_ATTRIBUTE_NORMAL, /* file attributes */
			FILE_SHARE_READ|
			FILE_SHARE_WRITE|
			FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DELETE_ON_CLOSE|
			FILE_OPEN_REPARSE_POINT, /* create_options */
			state->in_cblobs);	 /* in_cblobs */
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, cli_smb2_unlink_opened2, req);
		return;
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_close_fnum_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_unlink_closed, req);
}

static void cli_smb2_unlink_opened2(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_unlink_state *state = tevent_req_data(
		req, struct cli_smb2_unlink_state);
	uint16_t fnum;
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(subreq, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_close_fnum_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_unlink_closed, req);
}

static void cli_smb2_unlink_closed(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_close_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_unlink_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/***************************************************************
 Utility function to parse a SMB2_FIND_ID_BOTH_DIRECTORY_INFO reply.
***************************************************************/

static NTSTATUS parse_finfo_id_both_directory_info(const uint8_t *dir_data,
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

	finfo->btime_ts = interpret_long_date((const char *)dir_data + 8);
	finfo->atime_ts = interpret_long_date((const char *)dir_data + 16);
	finfo->mtime_ts = interpret_long_date((const char *)dir_data + 24);
	finfo->ctime_ts = interpret_long_date((const char *)dir_data + 32);
	finfo->size = IVAL2_TO_SMB_BIG_UINT(dir_data + 40, 0);
	finfo->allocated_size = IVAL2_TO_SMB_BIG_UINT(dir_data + 48, 0);
	finfo->attr = IVAL(dir_data + 56, 0);
	finfo->ino = IVAL2_TO_SMB_BIG_UINT(dir_data + 96, 0);
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

	if (finfo->name == NULL) {
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
			uint32_t attribute,
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
	uint32_t max_trans;
	uint32_t max_avail_len;
	bool ok;

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
			SMB2_IMPERSONATION_IMPERSONATION,
			SEC_DIR_LIST|SEC_DIR_READ_ATTRIBUTE,/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			NULL,
			&fnum,
			NULL,
			NULL,
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

	/*
	 * ideally, use the max transaction size, but don't send a request
	 * bigger than we have credits available for
	 */
	max_trans = smb2cli_conn_max_trans_size(cli->conn);
	ok = smb2cli_conn_req_possible(cli->conn, &max_avail_len);
	if (ok) {
		max_trans = MIN(max_trans, max_avail_len);
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
					max_trans,
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

			/* Protect against server attack. */
			status = is_bad_finfo_name(cli, finfo);
			if (!NT_STATUS_IS_OK(status)) {
				smbXcli_conn_disconnect(cli->conn, status);
				goto fail;
			}

			if (dir_check_ftype(finfo->attr, attribute)) {
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

	cli->raw_status = status;

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
		char *modname = talloc_strndup(talloc_tos(), name, namelen-1);
		if (modname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		name = modname;
	}

	/* This is commonly used as a 'cd'. Try qpathinfo on
	   a directory handle first. */

	status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			FILE_READ_ATTRIBUTES,	/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			NULL,
			&fnum,
			&cr,
			NULL,
			NULL);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_DIRECTORY)) {
		/* Maybe a file ? */
		status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			FILE_READ_ATTRIBUTES,		/* desired_access */
			0, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			0,	/* create_options */
			NULL,
			&fnum,
			&cr,
			NULL,
			NULL);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = cli_smb2_close_fnum(cli, fnum);

	ZERO_STRUCTP(sbuf);

	sbuf->st_ex_atime = nt_time_to_unix_timespec(cr.last_access_time);
	sbuf->st_ex_mtime = nt_time_to_unix_timespec(cr.last_write_time);
	sbuf->st_ex_ctime = nt_time_to_unix_timespec(cr.change_time);
	sbuf->st_ex_size = cr.end_of_file;
	*attributes = cr.file_attributes;

	return status;
}

struct cli_smb2_chkpath_state {
	struct tevent_context *ev;
	struct cli_state *cli;
};

static void cli_smb2_chkpath_opened(struct tevent_req *subreq);
static void cli_smb2_chkpath_closed(struct tevent_req *subreq);

struct tevent_req *cli_smb2_chkpath_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *name)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_chkpath_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_smb2_chkpath_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	/* Ensure this is a directory. */
	subreq = cli_smb2_create_fnum_send(
		state,				   /* mem_ctx */
		ev,				   /* ev */
		cli,				   /* cli */
		name,				   /* fname */
		0,				   /* create_flags */
		SMB2_IMPERSONATION_IMPERSONATION,  /* impersonation_level */
		FILE_READ_ATTRIBUTES,		   /* desired_access */
		FILE_ATTRIBUTE_DIRECTORY,	   /* file_attributes */
		FILE_SHARE_READ|
		FILE_SHARE_WRITE|
		FILE_SHARE_DELETE,		   /* share_access */
		FILE_OPEN,			   /* create_disposition */
		FILE_DIRECTORY_FILE,		   /* create_options */
		NULL);				   /* in_cblobs */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_chkpath_opened, req);
	return req;
}

static void cli_smb2_chkpath_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_chkpath_state *state = tevent_req_data(
		req, struct cli_smb2_chkpath_state);
	NTSTATUS status;
	uint16_t fnum;

	status = cli_smb2_create_fnum_recv(subreq, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_smb2_close_fnum_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_chkpath_closed, req);
}

static void cli_smb2_chkpath_closed(struct tevent_req *subreq)
{
	NTSTATUS status = cli_smb2_close_fnum_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_smb2_chkpath_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct cli_smb2_query_info_fnum_state {
	DATA_BLOB outbuf;
};

static void cli_smb2_query_info_fnum_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_query_info_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	uint32_t in_max_output_length,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info,
	uint32_t in_flags)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_query_info_fnum_state *state = NULL;
	struct smb2_hnd *ph = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct cli_smb2_query_info_fnum_state);
	if (req == NULL) {
		return req;
	}

	status = map_fnum_to_smb2_handle(cli, fnum, &ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_query_info_send(
		state,
		ev,
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		in_info_type,
		in_info_class,
		in_max_output_length,
		in_input_buffer,
		in_additional_info,
		in_flags,
		ph->fid_persistent,
		ph->fid_volatile);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_query_info_fnum_done, req);
	return req;
}

static void cli_smb2_query_info_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_query_info_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_query_info_fnum_state);
	DATA_BLOB outbuf;
	NTSTATUS status;

	status = smb2cli_query_info_recv(subreq, state, &outbuf);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * We have to dup the memory here because outbuf.data is not
	 * returned as a talloc object by smb2cli_query_info_recv.
	 * It's a pointer into the received buffer.
	 */
	state->outbuf = data_blob_dup_talloc(state, outbuf);

	if ((outbuf.length != 0) &&
	    tevent_req_nomem(state->outbuf.data, req)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_smb2_query_info_fnum_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, DATA_BLOB *outbuf)
{
	struct cli_smb2_query_info_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_query_info_fnum_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*outbuf = (DATA_BLOB) {
		.data = talloc_move(mem_ctx, &state->outbuf.data),
		.length = state->outbuf.length,
	};
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_query_info_fnum(
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	uint32_t in_max_output_length,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info,
	uint32_t in_flags,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *outbuf)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

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
	req = cli_smb2_query_info_fnum_send(
		frame,
		ev,
		cli,
		fnum,
		in_info_type,
		in_info_class,
		in_max_output_length,
		in_input_buffer,
		in_additional_info,
		in_flags);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = cli_smb2_query_info_fnum_recv(req, mem_ctx, outbuf);
fail:
	TALLOC_FREE(frame);
	return status;
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
	uint32_t create_options = 0;

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
			SMB2_IMPERSONATION_IMPERSONATION,
			desired_access,
			0, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			create_options,
			NULL,
			pfnum,
			NULL,
			NULL,
			NULL);

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		/*
		 * Naive option to match our SMB1 code. Assume the
		 * symlink path that tripped us up was the last
		 * component and try again. Eventually we will have to
		 * deal with the returned path unprocessed component. JRA.
		 */
		create_options |= FILE_OPEN_REPARSE_POINT;
		status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			desired_access,
			0, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			create_options,
			NULL,
			pfnum,
			NULL,
			NULL,
			NULL);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_IS_A_DIRECTORY)) {
		create_options |= FILE_DIRECTORY_FILE;
		status = cli_smb2_create_fnum(cli,
			name,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			desired_access,
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			create_options,		/* create_options */
			NULL,
			pfnum,
			NULL,
			NULL,
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

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		1, /* in_info_type */
		(SMB_FILE_ALTERNATE_NAME_INFORMATION - 1000), /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
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

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to get pathname attributes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_getatr(struct cli_state *cli,
			const char *name,
			uint32_t *pattr,
			off_t *size,
			time_t *write_time)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	struct smb2_hnd *ph = NULL;
	struct timespec write_time_ts;
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
	status = cli_qfileinfo_basic(
		cli,
		fnum,
		pattr,
		size,
		NULL,		/* create_time */
		NULL,		/* access_time */
		&write_time_ts,
		NULL,		/* change_time */
		NULL);		/* ino */
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	if (write_time != NULL) {
		*write_time = write_time_ts.tv_sec;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a pathname info (basic level).
 Implement on top of cli_qfileinfo_basic().
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_qpathinfo2(struct cli_state *cli,
			const char *name,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size,
			uint32_t *pattr,
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

	status = cli_qfileinfo_basic(
		cli,
		fnum,
		pattr,
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

	cli->raw_status = status;

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

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level 22 (SMB2_FILE_STREAM_INFORMATION). */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		1, /* in_info_type */
		(SMB_FILE_STREAM_INFORMATION - 1000), /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
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

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set SMB_FILE_BASIC_INFORMATION on
 a pathname.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_setpathinfo(struct cli_state *cli,
			const char *name,
			uint8_t in_info_type,
			uint8_t in_file_info_class,
			const DATA_BLOB *p_in_data)
{
	NTSTATUS status;
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
				FILE_WRITE_ATTRIBUTES,
				&fnum);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		in_info_type,
		in_file_info_class,
		p_in_data,	   /* in_input_buffer */
		0);		   /* in_additional_info */
  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}


/***************************************************************
 Wrapper that allows SMB2 to set pathname attributes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_setatr(struct cli_state *cli,
			const char *name,
			uint32_t attr,
			time_t mtime)
{
	uint8_t inbuf_store[40];
	DATA_BLOB inbuf = data_blob_null;

	/* setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	   level 4 (SMB_FILE_BASIC_INFORMATION - 1000). */

	inbuf.data = inbuf_store;
	inbuf.length = sizeof(inbuf_store);
	data_blob_clear(&inbuf);

	/*
	 * SMB1 uses attr == 0 to clear all attributes
	 * on a file (end up with FILE_ATTRIBUTE_NORMAL),
	 * and attr == FILE_ATTRIBUTE_NORMAL to mean ignore
	 * request attribute change.
	 *
	 * SMB2 uses exactly the reverse. Unfortunately as the
	 * cli_setatr() ABI is exposed inside libsmbclient,
	 * we must make the SMB2 cli_smb2_setatr() call
	 * export the same ABI as the SMB1 cli_setatr()
	 * which calls it. This means reversing the sense
	 * of the requested attr argument if it's zero
	 * or FILE_ATTRIBUTE_NORMAL.
	 *
	 * See BUG: https://bugzilla.samba.org/show_bug.cgi?id=12899
	 */

	if (attr == 0) {
		attr = FILE_ATTRIBUTE_NORMAL;
	} else if (attr == FILE_ATTRIBUTE_NORMAL) {
		attr = 0;
	}

	SIVAL(inbuf.data, 32, attr);
	if (mtime != 0) {
		put_long_date((char *)inbuf.data + 16,mtime);
	}
	/* Set all the other times to -1. */
	SBVAL(inbuf.data, 0, 0xFFFFFFFFFFFFFFFFLL);
	SBVAL(inbuf.data, 8, 0xFFFFFFFFFFFFFFFFLL);
	SBVAL(inbuf.data, 24, 0xFFFFFFFFFFFFFFFFLL);

	return cli_smb2_setpathinfo(cli,
				name,
				1, /* in_info_type */
				/* in_file_info_class */
				SMB_FILE_BASIC_INFORMATION - 1000,
				&inbuf);
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

	cli->raw_status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		1,		/* in_info_type */
		SMB_FILE_BASIC_INFORMATION - 1000, /* in_file_info_class */
		&inbuf,		   /* in_input_buffer */
		0);		   /* in_additional_info */

	return cli->raw_status;
}

/***************************************************************
 Wrapper that allows SMB2 to query disk attributes (size).
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_dskattr(struct cli_state *cli, const char *path,
			  uint64_t *bsize, uint64_t *total, uint64_t *avail)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	DATA_BLOB outbuf = data_blob_null;
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
			path,
			0,			/* create_flags */
			SMB2_IMPERSONATION_IMPERSONATION,
			FILE_READ_ATTRIBUTES,	/* desired_access */
			FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, /* share_access */
			FILE_OPEN,		/* create_disposition */
			FILE_DIRECTORY_FILE,	/* create_options */
			NULL,
			&fnum,
			NULL,
			NULL,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the returned handle with info_type SMB2_GETINFO_FS (2),
	   level 3 (SMB_FS_SIZE_INFORMATION). */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		2, /* in_info_type */
		3, /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
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

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query file system sizes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_fs_full_size_info(struct cli_state *cli,
				uint64_t *total_allocation_units,
				uint64_t *caller_allocation_units,
				uint64_t *actual_allocation_units,
				uint64_t *sectors_per_allocation_unit,
				uint64_t *bytes_per_sector)
{
	NTSTATUS status;
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

	/* First open the top level directory. */
	status =
	    cli_smb2_create_fnum(cli, "", 0,		   /* create_flags */
				 SMB2_IMPERSONATION_IMPERSONATION,
				 FILE_READ_ATTRIBUTES,     /* desired_access */
				 FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
				 FILE_SHARE_READ | FILE_SHARE_WRITE |
				     FILE_SHARE_DELETE, /* share_access */
				 FILE_OPEN,		/* create_disposition */
				 FILE_DIRECTORY_FILE,   /* create_options */
				 NULL,
				 &fnum,
				 NULL,
				 NULL,
				 NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the returned handle with info_type SMB2_GETINFO_FS (2),
	   level 7 (SMB_FS_FULL_SIZE_INFORMATION). */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		SMB2_0_INFO_FILESYSTEM, /* in_info_type */
		SMB_FS_FULL_SIZE_INFORMATION - 1000, /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
		frame,
		&outbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (outbuf.length < 32) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	*total_allocation_units = BIG_UINT(outbuf.data, 0);
	*caller_allocation_units = BIG_UINT(outbuf.data, 8);
	*actual_allocation_units = BIG_UINT(outbuf.data, 16);
	*sectors_per_allocation_unit = (uint64_t)IVAL(outbuf.data, 24);
	*bytes_per_sector = (uint64_t)IVAL(outbuf.data, 28);

fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query file system attributes.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_fs_attr_info(struct cli_state *cli, uint32_t *fs_attr)
{
	NTSTATUS status;
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

	/* First open the top level directory. */
	status =
	    cli_smb2_create_fnum(cli, "", 0,		   /* create_flags */
				 SMB2_IMPERSONATION_IMPERSONATION,
				 FILE_READ_ATTRIBUTES,     /* desired_access */
				 FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
				 FILE_SHARE_READ | FILE_SHARE_WRITE |
				     FILE_SHARE_DELETE, /* share_access */
				 FILE_OPEN,		/* create_disposition */
				 FILE_DIRECTORY_FILE,   /* create_options */
				 NULL,
				 &fnum,
				 NULL,
				 NULL,
				 NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		2, /* in_info_type */
		5,		       /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL,   /* in_input_buffer */
		0,      /* in_additional_info */
		0,      /* in_flags */
		frame,
		&outbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (outbuf.length < 12) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	*fs_attr = IVAL(outbuf.data, 0);

fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query file system volume info.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_fs_volume_info(struct cli_state *cli,
                                TALLOC_CTX *mem_ctx,
                                char **_volume_name,
                                uint32_t *pserial_number,
                                time_t *pdate)
{
	NTSTATUS status;
	uint16_t fnum = 0xffff;
	DATA_BLOB outbuf = data_blob_null;
	uint32_t nlen;
	char *volume_name = NULL;
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
	status =
	    cli_smb2_create_fnum(cli, "", 0,		   /* create_flags */
				 SMB2_IMPERSONATION_IMPERSONATION,
				 FILE_READ_ATTRIBUTES,     /* desired_access */
				 FILE_ATTRIBUTE_DIRECTORY, /* file attributes */
				 FILE_SHARE_READ | FILE_SHARE_WRITE |
				     FILE_SHARE_DELETE, /* share_access */
				 FILE_OPEN,		/* create_disposition */
				 FILE_DIRECTORY_FILE,   /* create_options */
				 NULL,
				 &fnum,
				 NULL,
				 NULL,
				 NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* getinfo on the returned handle with info_type SMB2_GETINFO_FS (2),
	   level 1 (SMB_FS_VOLUME_INFORMATION). */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		SMB2_0_INFO_FILESYSTEM, /* in_info_type */
		/* in_file_info_class */
		SMB_FS_VOLUME_INFORMATION - 1000,
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
		frame,
		&outbuf);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (outbuf.length < 24) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	if (pdate) {
		struct timespec ts;
		ts = interpret_long_date((char *)outbuf.data);
		*pdate = ts.tv_sec;
	}
	if (pserial_number) {
		*pserial_number = IVAL(outbuf.data,8);
	}
	nlen = IVAL(outbuf.data,12);
	if (nlen + 18 < 18) {
		/* Integer wrap. */
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}
	/*
	 * The next check is safe as we know outbuf.length >= 24
	 * from above.
	 */
	if (nlen > (outbuf.length - 18)) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto fail;
	}

	pull_string_talloc(mem_ctx,
			   (const char *)outbuf.data,
			   0,
			   &volume_name,
			   outbuf.data + 18,
			   nlen,
			   STR_UNICODE);
	if (volume_name == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	*_volume_name = volume_name;

fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

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

	/* getinfo on the returned handle with info_type SMB2_GETINFO_SEC (3) */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		3, /* in_info_type */
		0, /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		sec_info, /* in_additional_info */
		0, /* in_flags */
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

	cli->raw_status = status;

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

	status = marshall_sec_desc(frame,
				sd,
				&inbuf.data,
				&inbuf.length);

        if (!NT_STATUS_IS_OK(status)) {
		goto fail;
        }

	/* setinfo on the returned handle with info_type SMB2_SETINFO_SEC (3) */

	status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		3,			  /* in_info_type */
		0,			  /* in_file_info_class */
		&inbuf,			  /* in_input_buffer */
		sec_info);		  /* in_additional_info */

  fail:

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to query a security descriptor.
 Synchronous only.

***************************************************************/

struct cli_smb2_mxac_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *fname;
	struct smb2_create_blobs in_cblobs;
	uint16_t fnum;
	NTSTATUS status;
	uint32_t mxac;
};

static void cli_smb2_mxac_opened(struct tevent_req *subreq);
static void cli_smb2_mxac_closed(struct tevent_req *subreq);

struct tevent_req *cli_smb2_query_mxac_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_smb2_mxac_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_mxac_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct cli_smb2_mxac_state) {
		.ev = ev,
		.cli = cli,
		.fname = fname,
	};

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = smb2_create_blob_add(state,
				      &state->in_cblobs,
				      SMB2_CREATE_TAG_MXAC,
				      data_blob(NULL, 0));
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb2_create_fnum_send(
		state,
		state->ev,
		state->cli,
		state->fname,
		0,			/* create_flags */
		SMB2_IMPERSONATION_IMPERSONATION,
		FILE_READ_ATTRIBUTES,
		0,			/* file attributes */
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,
		0,			/* create_options */
		&state->in_cblobs);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_mxac_opened, req);
	return req;
}

static void cli_smb2_mxac_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_mxac_state *state = tevent_req_data(
		req, struct cli_smb2_mxac_state);
	struct smb2_create_blobs out_cblobs = {0};
	struct smb2_create_blob *mxac_blob = NULL;
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(
		subreq, &state->fnum, NULL, state, &out_cblobs);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		return;
	}

	mxac_blob = smb2_create_blob_find(&out_cblobs, SMB2_CREATE_TAG_MXAC);
	if (mxac_blob == NULL) {
		state->status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto close;
	}
	if (mxac_blob->data.length != 8) {
		state->status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		goto close;
	}

	state->status = NT_STATUS(IVAL(mxac_blob->data.data, 0));
	state->mxac = IVAL(mxac_blob->data.data, 4);

close:
	subreq = cli_smb2_close_fnum_send(
		state, state->ev, state->cli, state->fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_mxac_closed, req);

	return;
}

static void cli_smb2_mxac_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb2_close_fnum_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS cli_smb2_query_mxac_recv(struct tevent_req *req, uint32_t *mxac)
{
	struct cli_smb2_mxac_state *state = tevent_req_data(
		req, struct cli_smb2_mxac_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (!NT_STATUS_IS_OK(state->status)) {
		return state->status;
	}

	*mxac = state->mxac;
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_query_mxac(struct cli_state *cli,
			     const char *fname,
			     uint32_t *_mxac)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_INTERNAL_ERROR;
	bool ok;

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
	req = cli_smb2_query_mxac_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = cli_smb2_query_mxac_recv(req, _mxac);

fail:
	cli->raw_status = status;
	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to rename a file.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_rename(struct cli_state *cli,
			 const char *fname_src,
			 const char *fname_dst,
			 bool replace)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	uint16_t fnum = 0xffff;
	smb_ucs2_t *converted_str = NULL;
	size_t converted_size_bytes = 0;
	size_t namelen = 0;
	size_t inbuf_size;
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

	inbuf_size = 20 + converted_size_bytes;
	if (inbuf_size < 20) {
		/* Integer wrap check. */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	/*
	 * The Windows 10 SMB2 server has a minimum length
	 * for a SMB2_FILE_RENAME_INFORMATION buffer of
	 * 24 bytes. It returns NT_STATUS_INFO_LENGTH_MISMATCH
	 * if the length is less. This isn't an alignment
	 * issue as Windows client happily 2-byte align
	 * for larget target name sizes. Also the Windows 10
	 * SMB1 server doesn't have this restriction.
	 *
	 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14403
	 */
	if (inbuf_size < 24) {
		inbuf_size = 24;
	}

	inbuf = data_blob_talloc_zero(frame, inbuf_size);
	if (inbuf.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (replace) {
		SCVAL(inbuf.data, 0, 1);
	}

	SIVAL(inbuf.data, 16, converted_size_bytes);
	memcpy(inbuf.data + 20, converted_str, converted_size_bytes);

	/* setinfo on the returned handle with info_type SMB2_GETINFO_FILE (1),
	   level SMB2_FILE_RENAME_INFORMATION (SMB_FILE_RENAME_INFORMATION - 1000) */

	status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		1,		/* in_info_type */
		SMB_FILE_RENAME_INFORMATION - 1000, /* in_file_info_class */
		&inbuf,		   /* in_input_buffer */
		0);		   /* in_additional_info */

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

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

	status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		1,		/* in_info_type */
		SMB_FILE_FULL_EA_INFORMATION - 1000, /* in_file_info_class */
		&inbuf,		/* in_input_buffer */
		0);		/* in_additional_info */

  fail:

	cli->raw_status = status;

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

	cli->raw_status = status;

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

	/* getinfo on the handle with info_type SMB2_GETINFO_FILE (1),
	   level 15 (SMB_FILE_FULL_EA_INFORMATION - 1000). */

	status = cli_smb2_query_info_fnum(
		cli,
		fnum,
		1, /* in_info_type */
		SMB_FILE_FULL_EA_INFORMATION - 1000, /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
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
			(*pea_array)[ea_count++] = eal->ea;
		}
		*pnum_eas = ea_count;
	}

  fail:

	if (fnum != 0xffff) {
		cli_smb2_close_fnum(cli, fnum);
	}

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to get user quota.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_user_quota(struct cli_state *cli,
				 int quota_fnum,
				 SMB_NTQUOTA_STRUCT *pqt)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	DATA_BLOB info_blob = data_blob_null;
	DATA_BLOB outbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned sid_len;
	unsigned int offset;
	struct smb2_query_quota_info query = {0};
	struct file_get_quota_info info = {0};
	enum ndr_err_code err;
	struct ndr_push *ndr_push = NULL;

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

	sid_len = ndr_size_dom_sid(&pqt->sid, 0);

	query.return_single = 1;

	info.next_entry_offset = 0;
	info.sid_length = sid_len;
	info.sid = pqt->sid;

	err = ndr_push_struct_blob(
			&info_blob,
			frame,
			&info,
			(ndr_push_flags_fn_t)ndr_push_file_get_quota_info);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	query.sid_list_length = info_blob.length;
	ndr_push = ndr_push_init_ctx(frame);
	if (!ndr_push) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	err = ndr_push_smb2_query_quota_info(ndr_push,
					     NDR_SCALARS | NDR_BUFFERS,
					     &query);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	err = ndr_push_array_uint8(ndr_push, NDR_SCALARS, info_blob.data,
				   info_blob.length);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}
	inbuf.data = ndr_push->data;
	inbuf.length = ndr_push->offset;

	status = cli_smb2_query_info_fnum(
		cli,
		quota_fnum,
		4, /* in_info_type */
		0,		       /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		&inbuf, /* in_input_buffer */
		0,      /* in_additional_info */
		0,      /* in_flags */
		frame,
		&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (!parse_user_quota_record(outbuf.data, outbuf.length, &offset,
				     pqt)) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DEBUG(0, ("Got invalid FILE_QUOTA_INFORMATION in reply.\n"));
	}

fail:
	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to list user quota.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_list_user_quota_step(struct cli_state *cli,
				       TALLOC_CTX *mem_ctx,
				       int quota_fnum,
				       SMB_NTQUOTA_LIST **pqt_list,
				       bool first)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	DATA_BLOB outbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb2_query_quota_info info = {0};
	enum ndr_err_code err;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	info.restart_scan = first ? 1 : 0;

	err = ndr_push_struct_blob(
			&inbuf,
			frame,
			&info,
			(ndr_push_flags_fn_t)ndr_push_smb2_query_quota_info);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto cleanup;
	}

	status = cli_smb2_query_info_fnum(
		cli,
		quota_fnum,
		4, /* in_info_type */
		0, /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		&inbuf, /* in_input_buffer */
		0,      /* in_additional_info */
		0,      /* in_flags */
		frame,
		&outbuf);

	/*
	 * safeguard against panic from calling parse_user_quota_list with
	 * NULL buffer
	 */
	if (NT_STATUS_IS_OK(status) && outbuf.length == 0) {
		status = NT_STATUS_NO_MORE_ENTRIES;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	status = parse_user_quota_list(outbuf.data, outbuf.length, mem_ctx,
				       pqt_list);

cleanup:
	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to get file system quota.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_get_fs_quota_info(struct cli_state *cli,
				    int quota_fnum,
				    SMB_NTQUOTA_STRUCT *pqt)
{
	NTSTATUS status;
	DATA_BLOB outbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	status = cli_smb2_query_info_fnum(
		cli,
		quota_fnum,
		2,				     /* in_info_type */
		SMB_FS_QUOTA_INFORMATION - 1000, /* in_file_info_class */
		0xFFFF,			     /* in_max_output_length */
		NULL,			     /* in_input_buffer */
		0,				     /* in_additional_info */
		0,				     /* in_flags */
		frame,
		&outbuf);

	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	status = parse_fs_quota_buffer(outbuf.data, outbuf.length, pqt);

cleanup:
	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to set user quota.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_set_user_quota(struct cli_state *cli,
				 int quota_fnum,
				 SMB_NTQUOTA_LIST *qtl)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	status = build_user_quota_buffer(qtl, 0, talloc_tos(), &inbuf, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	status = cli_smb2_set_info_fnum(
		cli,
		quota_fnum,
		4,			  /* in_info_type */
		0,			  /* in_file_info_class */
		&inbuf,			  /* in_input_buffer */
		0);			  /* in_additional_info */
cleanup:

	cli->raw_status = status;

	TALLOC_FREE(frame);

	return status;
}

NTSTATUS cli_smb2_set_fs_quota_info(struct cli_state *cli,
				    int quota_fnum,
				    SMB_NTQUOTA_STRUCT *pqt)
{
	NTSTATUS status;
	DATA_BLOB inbuf = data_blob_null;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	status = build_fs_quota_buffer(talloc_tos(), pqt, &inbuf, 0);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	status = cli_smb2_set_info_fnum(
		cli,
		quota_fnum,
		2,			     /* in_info_type */
		SMB_FS_QUOTA_INFORMATION - 1000, /* in_file_info_class */
		&inbuf,			     /* in_input_buffer */
		0);			     /* in_additional_info */
cleanup:
	cli->raw_status = status;

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
		state->cli->raw_status = status;
		return status;
	}
	/*
	 * As in cli_read_andx_recv() rcvbuf is talloced from the request, so
	 * better make sure that you copy it away before you talloc_free(req).
	 * "rcvbuf" is NOT a talloc_ctx of its own, so do not talloc_move it!
	 */
	*received = (ssize_t)state->received;
	*rcvbuf = state->buf;
	state->cli->raw_status = NT_STATUS_OK;
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
		state->cli->raw_status = status;
		tevent_req_received(req);
		return status;
	}

	if (pwritten != NULL) {
		*pwritten = (size_t)state->written;
	}
	state->cli->raw_status = NT_STATUS_OK;
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
		state->cli->raw_status = status;
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = (size_t)state->written;
	}
	state->cli->raw_status = NT_STATUS_OK;
	return NT_STATUS_OK;
}

struct cli_smb2_splice_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	struct smb2_hnd *src_ph;
	struct smb2_hnd *dst_ph;
	int (*splice_cb)(off_t n, void *priv);
	void *priv;
	off_t written;
	off_t size;
	off_t src_offset;
	off_t dst_offset;
	bool resized;
	struct req_resume_key_rsp resume_rsp;
	struct srv_copychunk_copy cc_copy;
};

static void cli_splice_copychunk_send(struct cli_smb2_splice_state *state,
				      struct tevent_req *req);

static void cli_splice_copychunk_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_splice_state *state =
		tevent_req_data(req,
		struct cli_smb2_splice_state);
	struct smbXcli_conn *conn = state->cli->conn;
	DATA_BLOB out_input_buffer = data_blob_null;
	DATA_BLOB out_output_buffer = data_blob_null;
	struct srv_copychunk_rsp cc_copy_rsp;
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	status = smb2cli_ioctl_recv(subreq, state,
				    &out_input_buffer,
				    &out_output_buffer);
	TALLOC_FREE(subreq);
	if ((!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER) ||
	     state->resized) && tevent_req_nterror(req, status)) {
		return;
	}

	ndr_ret = ndr_pull_struct_blob(&out_output_buffer, state, &cc_copy_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to unmarshall copy chunk rsp\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		uint32_t max_chunks = MIN(cc_copy_rsp.chunks_written,
			     cc_copy_rsp.total_bytes_written / cc_copy_rsp.chunk_bytes_written);
		if ((cc_copy_rsp.chunk_bytes_written > smb2cli_conn_cc_chunk_len(conn) ||
		     max_chunks > smb2cli_conn_cc_max_chunks(conn)) &&
		     tevent_req_nterror(req, status)) {
			return;
		}

		state->resized = true;
		smb2cli_conn_set_cc_chunk_len(conn, cc_copy_rsp.chunk_bytes_written);
		smb2cli_conn_set_cc_max_chunks(conn, max_chunks);
	} else {
		if ((state->src_offset > INT64_MAX - cc_copy_rsp.total_bytes_written) ||
		    (state->dst_offset > INT64_MAX - cc_copy_rsp.total_bytes_written) ||
		    (state->written > INT64_MAX - cc_copy_rsp.total_bytes_written)) {
			tevent_req_nterror(req, NT_STATUS_FILE_TOO_LARGE);
			return;
		}
		state->src_offset += cc_copy_rsp.total_bytes_written;
		state->dst_offset += cc_copy_rsp.total_bytes_written;
		state->written += cc_copy_rsp.total_bytes_written;
		if (!state->splice_cb(state->written, state->priv)) {
			tevent_req_nterror(req, NT_STATUS_CANCELLED);
			return;
		}
	}

	cli_splice_copychunk_send(state, req);
}

static void cli_splice_copychunk_send(struct cli_smb2_splice_state *state,
				      struct tevent_req *req)
{
	struct tevent_req *subreq;
	enum ndr_err_code ndr_ret;
	struct smbXcli_conn *conn = state->cli->conn;
	struct srv_copychunk_copy *cc_copy = &state->cc_copy;
	off_t src_offset = state->src_offset;
	off_t dst_offset = state->dst_offset;
	uint32_t req_len = MIN(smb2cli_conn_cc_chunk_len(conn) * smb2cli_conn_cc_max_chunks(conn),
			       state->size - state->written);
	DATA_BLOB in_input_buffer = data_blob_null;
	DATA_BLOB in_output_buffer = data_blob_null;

	if (state->size - state->written == 0) {
		tevent_req_done(req);
		return;
	}

	cc_copy->chunk_count = 0;
	while (req_len) {
		cc_copy->chunks[cc_copy->chunk_count].source_off = src_offset;
		cc_copy->chunks[cc_copy->chunk_count].target_off = dst_offset;
		cc_copy->chunks[cc_copy->chunk_count].length = MIN(req_len,
				                                   smb2cli_conn_cc_chunk_len(conn));
		if (req_len < cc_copy->chunks[cc_copy->chunk_count].length) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			return;
		}
		req_len -= cc_copy->chunks[cc_copy->chunk_count].length;
		if ((src_offset > INT64_MAX - cc_copy->chunks[cc_copy->chunk_count].length) ||
		    (dst_offset > INT64_MAX - cc_copy->chunks[cc_copy->chunk_count].length)) {
			tevent_req_nterror(req, NT_STATUS_FILE_TOO_LARGE);
			return;
		}
		src_offset += cc_copy->chunks[cc_copy->chunk_count].length;
		dst_offset += cc_copy->chunks[cc_copy->chunk_count].length;
		cc_copy->chunk_count++;
	}

	ndr_ret = ndr_push_struct_blob(&in_input_buffer, state, cc_copy,
				       (ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to marshall copy chunk req\n"));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = smb2cli_ioctl_send(state, state->ev, state->cli->conn,
			       state->cli->timeout,
			       state->cli->smb2.session,
			       state->cli->smb2.tcon,
			       state->dst_ph->fid_persistent, /* in_fid_persistent */
			       state->dst_ph->fid_volatile, /* in_fid_volatile */
			       FSCTL_SRV_COPYCHUNK_WRITE,
			       0, /* in_max_input_length */
			       &in_input_buffer,
			       12, /* in_max_output_length */
			       &in_output_buffer,
			       SMB2_IOCTL_FLAG_IS_FSCTL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_splice_copychunk_done,
				req);
}

static void cli_splice_key_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_splice_state *state =
		tevent_req_data(req,
		struct cli_smb2_splice_state);
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	DATA_BLOB out_input_buffer = data_blob_null;
	DATA_BLOB out_output_buffer = data_blob_null;

	status = smb2cli_ioctl_recv(subreq, state,
				    &out_input_buffer,
				    &out_output_buffer);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ndr_ret = ndr_pull_struct_blob(&out_output_buffer,
			state, &state->resume_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to unmarshall resume key rsp\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	memcpy(&state->cc_copy.source_key,
	       &state->resume_rsp.resume_key,
	       sizeof state->resume_rsp.resume_key);

	cli_splice_copychunk_send(state, req);
}

struct tevent_req *cli_smb2_splice_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t src_fnum, uint16_t dst_fnum,
				off_t size, off_t src_offset, off_t dst_offset,
				int (*splice_cb)(off_t n, void *priv),
				void *priv)
{
	struct tevent_req *req;
	struct tevent_req *subreq;
	struct cli_smb2_splice_state *state;
	NTSTATUS status;
	DATA_BLOB in_input_buffer = data_blob_null;
	DATA_BLOB in_output_buffer = data_blob_null;

	req = tevent_req_create(mem_ctx, &state, struct cli_smb2_splice_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->ev = ev;
	state->splice_cb = splice_cb;
	state->priv = priv;
	state->size = size;
	state->written = 0;
	state->src_offset = src_offset;
	state->dst_offset = dst_offset;
	state->cc_copy.chunks = talloc_array(state,
			                     struct srv_copychunk,
					     smb2cli_conn_cc_max_chunks(cli->conn));
	if (state->cc_copy.chunks == NULL) {
		return NULL;
	}

	status = map_fnum_to_smb2_handle(cli, src_fnum, &state->src_ph);
	if (tevent_req_nterror(req, status))
		return tevent_req_post(req, ev);

	status = map_fnum_to_smb2_handle(cli, dst_fnum, &state->dst_ph);
	if (tevent_req_nterror(req, status))
		return tevent_req_post(req, ev);

	subreq = smb2cli_ioctl_send(state, ev, cli->conn,
			       cli->timeout,
			       cli->smb2.session,
			       cli->smb2.tcon,
			       state->src_ph->fid_persistent, /* in_fid_persistent */
			       state->src_ph->fid_volatile, /* in_fid_volatile */
			       FSCTL_SRV_REQUEST_RESUME_KEY,
			       0, /* in_max_input_length */
			       &in_input_buffer,
			       32, /* in_max_output_length */
			       &in_output_buffer,
			       SMB2_IOCTL_FLAG_IS_FSCTL);
	if (tevent_req_nomem(subreq, req)) {
		return NULL;
	}
	tevent_req_set_callback(subreq,
				cli_splice_key_done,
				req);

	return req;
}

NTSTATUS cli_smb2_splice_recv(struct tevent_req *req, off_t *written)
{
	struct cli_smb2_splice_state *state = tevent_req_data(
		req, struct cli_smb2_splice_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		state->cli->raw_status = status;
		tevent_req_received(req);
		return status;
	}
	if (written != NULL) {
		*written = state->written;
	}
	state->cli->raw_status = NT_STATUS_OK;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/***************************************************************
 SMB2 enum shadow copy data.
***************************************************************/

struct cli_smb2_shadow_copy_data_fnum_state {
	struct cli_state *cli;
	uint16_t fnum;
	struct smb2_hnd *ph;
	DATA_BLOB out_input_buffer;
	DATA_BLOB out_output_buffer;
};

static void cli_smb2_shadow_copy_data_fnum_done(struct tevent_req *subreq);

static struct tevent_req *cli_smb2_shadow_copy_data_fnum_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					bool get_names)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_shadow_copy_data_fnum_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_shadow_copy_data_fnum_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->cli = cli;
	state->fnum = fnum;

	status = map_fnum_to_smb2_handle(cli, fnum, &state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO. Under SMB2 we should send a zero max_output_length
	 * ioctl to get the required size, then send another ioctl
	 * to get the data, but the current SMB1 implementation just
	 * does one roundtrip with a 64K buffer size. Do the same
	 * for now. JRA.
	 */

	subreq = smb2cli_ioctl_send(state, ev, state->cli->conn,
			state->cli->timeout,
			state->cli->smb2.session,
			state->cli->smb2.tcon,
			state->ph->fid_persistent, /* in_fid_persistent */
			state->ph->fid_volatile, /* in_fid_volatile */
			FSCTL_GET_SHADOW_COPY_DATA,
			0, /* in_max_input_length */
			NULL, /* in_input_buffer */
			get_names ?
				CLI_BUFFER_SIZE : 16, /* in_max_output_length */
			NULL, /* in_output_buffer */
			SMB2_IOCTL_FLAG_IS_FSCTL);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_smb2_shadow_copy_data_fnum_done,
				req);

	return req;
}

static void cli_smb2_shadow_copy_data_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_shadow_copy_data_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_shadow_copy_data_fnum_state);
	NTSTATUS status;

	status = smb2cli_ioctl_recv(subreq, state,
				&state->out_input_buffer,
				&state->out_output_buffer);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

static NTSTATUS cli_smb2_shadow_copy_data_fnum_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				bool get_names,
				char ***pnames,
				int *pnum_names)
{
	struct cli_smb2_shadow_copy_data_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_shadow_copy_data_fnum_state);
	char **names = NULL;
	uint32_t num_names = 0;
	uint32_t num_names_returned = 0;
	uint32_t dlength = 0;
	uint32_t i;
	uint8_t *endp = NULL;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (state->out_output_buffer.length < 16) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	num_names = IVAL(state->out_output_buffer.data, 0);
	num_names_returned = IVAL(state->out_output_buffer.data, 4);
	dlength = IVAL(state->out_output_buffer.data, 8);

	if (num_names > 0x7FFFFFFF) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (get_names == false) {
		*pnum_names = (int)num_names;
		return NT_STATUS_OK;
	}
	if (num_names != num_names_returned) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (dlength + 12 < 12) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	/*
	 * NB. The below is an allowable return if there are
	 * more snapshots than the buffer size we told the
	 * server we can receive. We currently don't support
	 * this.
	 */
	if (dlength + 12 > state->out_output_buffer.length) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (state->out_output_buffer.length +
			(2 * sizeof(SHADOW_COPY_LABEL)) <
				state->out_output_buffer.length) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	names = talloc_array(mem_ctx, char *, num_names_returned);
	if (names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	endp = state->out_output_buffer.data +
			state->out_output_buffer.length;

	for (i=0; i<num_names_returned; i++) {
		bool ret;
		uint8_t *src;
		size_t converted_size;

		src = state->out_output_buffer.data + 12 +
			(i * 2 * sizeof(SHADOW_COPY_LABEL));

		if (src + (2 * sizeof(SHADOW_COPY_LABEL)) > endp) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		ret = convert_string_talloc(
			names, CH_UTF16LE, CH_UNIX,
			src, 2 * sizeof(SHADOW_COPY_LABEL),
			&names[i], &converted_size);
		if (!ret) {
			TALLOC_FREE(names);
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}
	*pnum_names = num_names;
	*pnames = names;
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_shadow_copy_data(TALLOC_CTX *mem_ctx,
				struct cli_state *cli,
				uint16_t fnum,
				bool get_names,
				char ***pnames,
				int *pnum_names)
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
	req = cli_smb2_shadow_copy_data_fnum_send(frame,
					ev,
					cli,
					fnum,
					get_names);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_shadow_copy_data_fnum_recv(req,
						mem_ctx,
						get_names,
						pnames,
						pnum_names);
 fail:
	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

/***************************************************************
 Wrapper that allows SMB2 to truncate a file.
 Synchronous only.
***************************************************************/

NTSTATUS cli_smb2_ftruncate(struct cli_state *cli,
			uint16_t fnum,
			uint64_t newsize)
{
	NTSTATUS status;
	uint8_t buf[8] = {0};
	DATA_BLOB inbuf = { .data = buf, .length = sizeof(buf) };
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

	SBVAL(buf, 0, newsize);

	/* setinfo on the handle with info_type SMB2_SETINFO_FILE (1),
	   level 20 (SMB_FILE_END_OF_FILE_INFORMATION - 1000). */

	status = cli_smb2_set_info_fnum(
		cli,
		fnum,
		1, /* in_info_type */
		SMB_FILE_END_OF_FILE_INFORMATION-1000, /* in_file_info_class */
		&inbuf, /* in_input_buffer */
		0);

  fail:

	cli->raw_status = status;

	TALLOC_FREE(frame);
	return status;
}

struct cli_smb2_notify_state {
	struct tevent_req *subreq;
	struct notify_change *changes;
	size_t num_changes;
};

static void cli_smb2_notify_done(struct tevent_req *subreq);
static bool cli_smb2_notify_cancel(struct tevent_req *req);

struct tevent_req *cli_smb2_notify_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint32_t buffer_size,
	uint32_t completion_filter,
	bool recursive)
{
	struct tevent_req *req = NULL;
	struct cli_smb2_notify_state *state = NULL;
	struct smb2_hnd *ph = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_notify_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = map_fnum_to_smb2_handle(cli, fnum, &ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->subreq = smb2cli_notify_send(
		state,
		ev,
		cli->conn,
		cli->timeout,
		cli->smb2.session,
		cli->smb2.tcon,
		buffer_size,
		ph->fid_persistent,
		ph->fid_volatile,
		completion_filter,
		recursive);
	if (tevent_req_nomem(state->subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->subreq, cli_smb2_notify_done, req);
	tevent_req_set_cancel_fn(req, cli_smb2_notify_cancel);
	return req;
}

static bool cli_smb2_notify_cancel(struct tevent_req *req)
{
	struct cli_smb2_notify_state *state = tevent_req_data(
		req, struct cli_smb2_notify_state);
	bool ok;

	ok = tevent_req_cancel(state->subreq);
	return ok;
}

static void cli_smb2_notify_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_notify_state *state = tevent_req_data(
		req, struct cli_smb2_notify_state);
	uint8_t *base;
	uint32_t len;
	uint32_t ofs;
	NTSTATUS status;

	status = smb2cli_notify_recv(subreq, state, &base, &len);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		tevent_req_done(req);
		return;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ofs = 0;

	while (len - ofs >= 12) {
		struct notify_change *tmp;
		struct notify_change *c;
		uint32_t next_ofs = IVAL(base, ofs);
		uint32_t file_name_length = IVAL(base, ofs+8);
		size_t namelen;
		bool ok;

		tmp = talloc_realloc(
			state,
			state->changes,
			struct notify_change,
			state->num_changes + 1);
		if (tevent_req_nomem(tmp, req)) {
			return;
		}
		state->changes = tmp;
		c = &state->changes[state->num_changes];
		state->num_changes += 1;

		if (smb_buffer_oob(len, ofs, next_ofs) ||
		    smb_buffer_oob(len, ofs+12, file_name_length)) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		c->action = IVAL(base, ofs+4);

		ok = convert_string_talloc(
			state->changes,
			CH_UTF16LE,
			CH_UNIX,
			base + ofs + 12,
			file_name_length,
			&c->name,
			&namelen);
		if (!ok) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (next_ofs == 0) {
			break;
		}
		ofs += next_ofs;
	}

	tevent_req_done(req);
}

NTSTATUS cli_smb2_notify_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      struct notify_change **pchanges,
			      uint32_t *pnum_changes)
{
	struct cli_smb2_notify_state *state = tevent_req_data(
		req, struct cli_smb2_notify_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pchanges = talloc_move(mem_ctx, &state->changes);
	*pnum_changes = state->num_changes;
	return NT_STATUS_OK;
}

NTSTATUS cli_smb2_notify(struct cli_state *cli, uint16_t fnum,
			 uint32_t buffer_size, uint32_t completion_filter,
			 bool recursive, TALLOC_CTX *mem_ctx,
			 struct notify_change **pchanges,
			 uint32_t *pnum_changes)
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
	req = cli_smb2_notify_send(
		frame,
		ev,
		cli,
		fnum,
		buffer_size,
		completion_filter,
		recursive);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_smb2_notify_recv(req, mem_ctx, pchanges, pnum_changes);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_smb2_set_reparse_point_fnum_state {
	struct cli_state *cli;
	uint16_t fnum;
	struct smb2_hnd *ph;
	DATA_BLOB input_buffer;
};

static void cli_smb2_set_reparse_point_fnum_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_set_reparse_point_fnum_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				DATA_BLOB in_buf)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_set_reparse_point_fnum_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_set_reparse_point_fnum_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->cli = cli;
	state->fnum = fnum;

	status = map_fnum_to_smb2_handle(cli, fnum, &state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->input_buffer = data_blob_talloc(state,
						in_buf.data,
						in_buf.length);
	if (state->input_buffer.data == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_ioctl_send(state, ev, state->cli->conn,
			state->cli->timeout,
			state->cli->smb2.session,
			state->cli->smb2.tcon,
			state->ph->fid_persistent, /* in_fid_persistent */
			state->ph->fid_volatile, /* in_fid_volatile */
			FSCTL_SET_REPARSE_POINT,
			0, /* in_max_input_length */
			&state->input_buffer ,
			0,
			NULL,
			SMB2_IOCTL_FLAG_IS_FSCTL);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_smb2_set_reparse_point_fnum_done,
				req);

	return req;
}

static void cli_smb2_set_reparse_point_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_set_reparse_point_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_set_reparse_point_fnum_state);
	NTSTATUS status;

	status = smb2cli_ioctl_recv(subreq, state,
				NULL,
				NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_smb2_set_reparse_point_fnum_recv(struct tevent_req *req)
{
        return tevent_req_simple_recv_ntstatus(req);
}

struct cli_smb2_get_reparse_point_fnum_state {
	struct cli_state *cli;
	uint16_t fnum;
	struct smb2_hnd *ph;
	DATA_BLOB output_buffer;
};

static void cli_smb2_get_reparse_point_fnum_done(struct tevent_req *subreq);

struct tevent_req *cli_smb2_get_reparse_point_fnum_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t fnum)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_get_reparse_point_fnum_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_get_reparse_point_fnum_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->cli = cli;
	state->fnum = fnum;

	status = map_fnum_to_smb2_handle(cli, fnum, &state->ph);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = smb2cli_ioctl_send(state, ev, state->cli->conn,
			state->cli->timeout,
			state->cli->smb2.session,
			state->cli->smb2.tcon,
			state->ph->fid_persistent, /* in_fid_persistent */
			state->ph->fid_volatile, /* in_fid_volatile */
			FSCTL_GET_REPARSE_POINT,
			0, /* in_max_input_length */
			NULL,
			64*1024,
			NULL,
			SMB2_IOCTL_FLAG_IS_FSCTL);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				cli_smb2_get_reparse_point_fnum_done,
				req);

	return req;
}

static void cli_smb2_get_reparse_point_fnum_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_get_reparse_point_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_get_reparse_point_fnum_state);
	struct cli_state *cli = state->cli;
	NTSTATUS status;

	status = smb2cli_ioctl_recv(subreq, state,
				NULL,
				&state->output_buffer);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		cli->raw_status = status;
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_smb2_get_reparse_point_fnum_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				DATA_BLOB *output)
{
	struct cli_smb2_get_reparse_point_fnum_state *state = tevent_req_data(
		req, struct cli_smb2_get_reparse_point_fnum_state);

	if (tevent_req_is_nterror(req, &state->cli->raw_status)) {
		NTSTATUS status = state->cli->raw_status;
		tevent_req_received(req);
		return status;
	}
	*output = data_blob_dup_talloc(mem_ctx, state->output_buffer);
	if (output->data == NULL) {
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

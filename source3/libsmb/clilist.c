/*
   Unix SMB/CIFS implementation.
   client directory list routines
   Copyright (C) Andrew Tridgell 1994-1998

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
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "trans2.h"
#include "../libcli/smb/smbXcli_base.h"

/****************************************************************************
 Check if a returned directory name is safe.
****************************************************************************/

static NTSTATUS is_bad_name(bool windows_names, const char *name)
{
	const char *bad_name_p = NULL;

	bad_name_p = strchr(name, '/');
	if (bad_name_p != NULL) {
		/*
		 * Windows and POSIX names can't have '/'.
		 * Server is attacking us.
		 */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (windows_names) {
		bad_name_p = strchr(name, '\\');
		if (bad_name_p != NULL) {
			/*
			 * Windows names can't have '\\'.
			 * Server is attacking us.
			 */
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Check if a returned directory name is safe. Disconnect if server is
 sending bad names.
****************************************************************************/

NTSTATUS is_bad_finfo_name(const struct cli_state *cli,
			const struct file_info *finfo)
{
	NTSTATUS status = NT_STATUS_OK;
	bool windows_names = true;

	if (cli->requested_posix_capabilities & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		windows_names = false;
	}
	if (finfo->name != NULL) {
		status = is_bad_name(windows_names, finfo->name);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("bad finfo->name\n");
			return status;
		}
	}
	if (finfo->short_name != NULL) {
		status = is_bad_name(windows_names, finfo->short_name);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("bad finfo->short_name\n");
			return status;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Calculate a safe next_entry_offset.
****************************************************************************/

static size_t calc_next_entry_offset(const char *base, const char *pdata_end)
{
	size_t next_entry_offset = (size_t)IVAL(base,0);

	if (next_entry_offset == 0 ||
			base + next_entry_offset < base ||
			base + next_entry_offset > pdata_end) {
		next_entry_offset = pdata_end - base;
	}
	return next_entry_offset;
}

/****************************************************************************
 Interpret a long filename structure - this is mostly guesses at the moment.
 The length of the structure is returned
 The structure of a long filename depends on the info level.
 SMB_FIND_FILE_BOTH_DIRECTORY_INFO is used
 by NT and SMB_FIND_EA_SIZE is used by OS/2
****************************************************************************/

static size_t interpret_long_filename(TALLOC_CTX *ctx,
					struct cli_state *cli,
					int level,
					const char *base_ptr,
					uint16_t recv_flags2,
					const char *p,
					const char *pdata_end,
					struct file_info *finfo,
					uint32_t *p_resume_key,
					DATA_BLOB *p_last_name_raw)
{
	int len;
	size_t ret;
	const char *base = p;

	data_blob_free(p_last_name_raw);

	if (p_resume_key) {
		*p_resume_key = 0;
	}
	ZERO_STRUCTP(finfo);

	switch (level) {
		case SMB_FIND_INFO_STANDARD: /* OS/2 understands this */
			/* these dates are converted to GMT by
                           make_unix_date */
			if (pdata_end - base < 27) {
				return pdata_end - base;
			}
			/*
			 * What we're returning here as ctime_ts is
			 * actually the server create time.
			 */
			finfo->btime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+4,
					smb1cli_conn_server_time_zone(
						cli->conn)));
			finfo->ctime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+4, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->atime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+8, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->mtime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+12, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->size = IVAL(p,16);
			finfo->attr = SVAL(p,24);
			len = CVAL(p, 26);
			p += 27;
			if (recv_flags2 & FLAGS2_UNICODE_STRINGS) {
				p += ucs2_align(base_ptr, p, STR_UNICODE);
			}

			/* We can safely use len here (which is required by OS/2)
			 * and the NAS-BASIC server instead of +2 or +1 as the
			 * STR_TERMINATE flag below is
			 * actually used as the length calculation.
			 * The len is merely an upper bound.
			 * Due to the explicit 2 byte null termination
			 * in cli_receive_trans/cli_receive_nt_trans
			 * we know this is safe. JRA + kukks
			 */

			if (p + len > pdata_end) {
				return pdata_end - base;
			}

			/* the len+2 below looks strange but it is
			   important to cope with the differences
			   between win2000 and win9x for this call
			   (tridge) */
			ret = pull_string_talloc(ctx,
						 base_ptr,
						 recv_flags2,
						 &finfo->name,
						 p,
						 len+2,
						 STR_TERMINATE);
			if (ret == (size_t)-1) {
				return pdata_end - base;
			}
			p += ret;
			return PTR_DIFF(p, base);

		case SMB_FIND_EA_SIZE: /* this is what OS/2 uses mostly */
			/* these dates are converted to GMT by
                           make_unix_date */
			if (pdata_end - base < 31) {
				return pdata_end - base;
			}
			/*
			 * What we're returning here as ctime_ts is
			 * actually the server create time.
			 */
			finfo->btime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+4,
					smb1cli_conn_server_time_zone(
						cli->conn)));
			finfo->ctime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+4, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->atime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+8, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->mtime_ts = convert_time_t_to_timespec(
				make_unix_date2(p+12, smb1cli_conn_server_time_zone(cli->conn)));
			finfo->size = IVAL(p,16);
			finfo->attr = SVAL(p,24);
			len = CVAL(p, 30);
			p += 31;
			/* check for unisys! */
			if (p + len + 1 > pdata_end) {
				return pdata_end - base;
			}
			ret = pull_string_talloc(ctx,
						 base_ptr,
						 recv_flags2,
						 &finfo->name,
						 p,
						 len,
						 STR_NOALIGN);
			if (ret == (size_t)-1) {
				return pdata_end - base;
			}
			p += ret;
			return PTR_DIFF(p, base) + 1;

		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO: /* NT uses this, but also accepts 2 */
		{
			size_t namelen, slen;

			if (pdata_end - base < 94) {
				return pdata_end - base;
			}

			p += 4; /* next entry offset */

			if (p_resume_key) {
				*p_resume_key = IVAL(p,0);
			}
			p += 4; /* fileindex */

			/* Offset zero is "create time", not "change time". */
			p += 8;
			finfo->atime_ts = interpret_long_date(p);
			p += 8;
			finfo->mtime_ts = interpret_long_date(p);
			p += 8;
			finfo->ctime_ts = interpret_long_date(p);
			p += 8;
			finfo->size = IVAL2_TO_SMB_BIG_UINT(p,0);
			p += 8;
			p += 8; /* alloc size */
			finfo->attr = IVAL(p,0);
			p += 4;
			namelen = IVAL(p,0);
			p += 4;
			p += 4; /* EA size */
			slen = CVAL(p, 0);
			if (slen > 24) {
				/* Bad short name length. */
				return pdata_end - base;
			}
			p += 2;
			ret = pull_string_talloc(ctx,
						 base_ptr,
						 recv_flags2,
						 &finfo->short_name,
						 p,
						 slen,
						 STR_UNICODE);
			if (ret == (size_t)-1) {
				return pdata_end - base;
			}
			p += 24; /* short name? */
			if (p + namelen < p || p + namelen > pdata_end) {
				return pdata_end - base;
			}
			ret = pull_string_talloc(ctx,
						 base_ptr,
						 recv_flags2,
						 &finfo->name,
						 p,
						 namelen,
						 0);
			if (ret == (size_t)-1) {
				return pdata_end - base;
			}

			/* To be robust in the face of unicode conversion failures
			   we need to copy the raw bytes of the last name seen here.
			   Namelen doesn't include the terminating unicode null, so
			   copy it here. */

			if (p_last_name_raw) {
				*p_last_name_raw = data_blob(NULL, namelen+2);
				memcpy(p_last_name_raw->data, p, namelen);
				SSVAL(p_last_name_raw->data, namelen, 0);
			}
			return calc_next_entry_offset(base, pdata_end);
		}
	}

	DEBUG(1,("Unknown long filename format %d\n",level));
	return calc_next_entry_offset(base, pdata_end);
}

/****************************************************************************
 Interpret a short filename structure.
 The length of the structure is returned.
****************************************************************************/

static bool interpret_short_filename(TALLOC_CTX *ctx,
				struct cli_state *cli,
				char *p,
				struct file_info *finfo)
{
	size_t ret;
	ZERO_STRUCTP(finfo);

	finfo->attr = CVAL(p,21);

	/* We don't get birth time. */
	finfo->btime_ts.tv_sec = 0;
	finfo->btime_ts.tv_nsec = 0;
	/* this date is converted to GMT by make_unix_date */
	finfo->ctime_ts.tv_sec = make_unix_date(p+22, smb1cli_conn_server_time_zone(cli->conn));
	finfo->ctime_ts.tv_nsec = 0;
	finfo->mtime_ts.tv_sec = finfo->atime_ts.tv_sec = finfo->ctime_ts.tv_sec;
	finfo->mtime_ts.tv_nsec = finfo->atime_ts.tv_nsec = 0;
	finfo->size = IVAL(p,26);
	ret = pull_string_talloc(ctx,
				 NULL,
				 0,
				 &finfo->name,
				 p+30,
				 12,
				 STR_ASCII);
	if (ret == (size_t)-1) {
		return false;
	}

	if (finfo->name) {
		finfo->short_name = talloc_strdup(ctx, finfo->name);
		if (finfo->short_name == NULL) {
			return false;
		}
	}
	return true;
}

struct cli_list_old_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t vwv[2];
	char *mask;
	int num_asked;
	uint32_t attribute;
	uint8_t search_status[23];
	bool first;
	bool done;
	uint8_t *dirlist;
};

static void cli_list_old_done(struct tevent_req *subreq);

static struct tevent_req *cli_list_old_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    const char *mask,
					    uint32_t attribute)
{
	struct tevent_req *req, *subreq;
	struct cli_list_old_state *state;
	uint8_t *bytes;
	static const uint16_t zero = 0;
	uint32_t usable_space;

	req = tevent_req_create(mem_ctx, &state, struct cli_list_old_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->attribute = attribute;
	state->first = true;
	state->mask = talloc_strdup(state, mask);
	if (tevent_req_nomem(state->mask, req)) {
		return tevent_req_post(req, ev);
	}
	usable_space = cli_state_available_size(cli, 100);
	state->num_asked = usable_space / DIR_STRUCT_SIZE;

	SSVAL(state->vwv + 0, 0, state->num_asked);
	SSVAL(state->vwv + 1, 0, state->attribute);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(cli->conn), mask,
				   strlen(mask)+1, NULL);

	bytes = smb_bytes_push_bytes(bytes, 5, (const uint8_t *)&zero, 2);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, state->ev, state->cli, SMBsearch, 0, 0,
			2, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_list_old_done, req);
	return req;
}

static void cli_list_old_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_list_old_state *state = tevent_req_data(
		req, struct cli_list_old_state);
	NTSTATUS status;
	uint8_t cmd;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	uint16_t received;
	size_t dirlist_len;
	uint8_t *tmp;

	status = cli_smb_recv(subreq, state, NULL, 0, &wct, &vwv, &num_bytes,
			      &bytes);
	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_DOS(ERRDOS, ERRnofiles))
	    && !NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOS(ERRDOS, ERRnofiles))
	    || NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
		received = 0;
	} else {
		if (wct < 1) {
			TALLOC_FREE(subreq);
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}
		received = SVAL(vwv + 0, 0);
	}

	if (received > 0) {
		/*
		 * I don't think this can wrap. received is
		 * initialized from a 16-bit value.
		 */
		if (num_bytes < (received * DIR_STRUCT_SIZE + 3)) {
			TALLOC_FREE(subreq);
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		dirlist_len = talloc_get_size(state->dirlist);

		tmp = talloc_realloc(
			state, state->dirlist, uint8_t,
			dirlist_len + received * DIR_STRUCT_SIZE);
		if (tevent_req_nomem(tmp, req)) {
			return;
		}
		state->dirlist = tmp;
		memcpy(state->dirlist + dirlist_len, bytes + 3,
		       received * DIR_STRUCT_SIZE);

		SSVAL(state->search_status, 0, 21);
		memcpy(state->search_status + 2,
		       bytes + 3 + (received-1)*DIR_STRUCT_SIZE, 21);
		cmd = SMBsearch;
	} else {
		if (state->first || state->done) {
			tevent_req_done(req);
			return;
		}
		state->done = true;
		state->num_asked = 0;
		cmd = SMBfclose;
	}
	TALLOC_FREE(subreq);

	state->first = false;

	SSVAL(state->vwv + 0, 0, state->num_asked);
	SSVAL(state->vwv + 1, 0, state->attribute);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return;
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, smbXcli_conn_use_unicode(state->cli->conn), "",
				   1, NULL);
	bytes = smb_bytes_push_bytes(bytes, 5, state->search_status,
				     sizeof(state->search_status));
	if (tevent_req_nomem(bytes, req)) {
		return;
	}
	subreq = cli_smb_send(state, state->ev, state->cli, cmd, 0, 0,
			      2, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_list_old_done, req);
}

static NTSTATUS cli_list_old_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  struct file_info **pfinfo)
{
	struct cli_list_old_state *state = tevent_req_data(
		req, struct cli_list_old_state);
	NTSTATUS status;
	size_t i, num_received;
	struct file_info *finfo;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	num_received = talloc_array_length(state->dirlist) / DIR_STRUCT_SIZE;

	finfo = talloc_array(mem_ctx, struct file_info, num_received);
	if (finfo == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_received; i++) {
		if (!interpret_short_filename(
			    finfo, state->cli,
			    (char *)state->dirlist + i * DIR_STRUCT_SIZE,
			    &finfo[i])) {
			TALLOC_FREE(finfo);
			return NT_STATUS_NO_MEMORY;
		}
		if (finfo->name == NULL) {
			TALLOC_FREE(finfo);
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		status = is_bad_finfo_name(state->cli, finfo);
		if (!NT_STATUS_IS_OK(status)) {
			smbXcli_conn_disconnect(state->cli->conn, status);
			TALLOC_FREE(finfo);
			return status;
		}
	}
	*pfinfo = finfo;
	return NT_STATUS_OK;
}

NTSTATUS cli_list_old(struct cli_state *cli, const char *mask,
		      uint32_t attribute,
		      NTSTATUS (*fn)(const char *, struct file_info *,
				 const char *, void *), void *state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct file_info *finfo = NULL;
	size_t i, num_finfo;

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
	req = cli_list_old_send(frame, ev, cli, mask, attribute);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_list_old_recv(req, frame, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	num_finfo = talloc_array_length(finfo);
	for (i=0; i<num_finfo; i++) {
		status = fn(cli->dfs_mountpoint, &finfo[i], mask, state);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_list_trans_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	char *mask;
	uint32_t attribute;
	uint16_t info_level;

	int loop_count;
	int total_received;
	uint16_t max_matches;
	bool first;

	int ff_eos;
	int ff_dir_handle;

	uint16_t setup[1];
	uint8_t *param;

	struct file_info *finfo;
};

static void cli_list_trans_done(struct tevent_req *subreq);

static struct tevent_req *cli_list_trans_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct cli_state *cli,
					      const char *mask,
					      uint32_t attribute,
					      uint16_t info_level)
{
	struct tevent_req *req, *subreq;
	struct cli_list_trans_state *state;
	size_t param_len;
	uint16_t additional_flags2 = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_list_trans_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->mask = talloc_strdup(state, mask);
	if (tevent_req_nomem(state->mask, req)) {
		return tevent_req_post(req, ev);
	}
	state->attribute = attribute;
	state->info_level = info_level;
	state->loop_count = 0;
	state->first = true;

	state->max_matches = 1366; /* Match W2k */

	SSVAL(&state->setup[0], 0, TRANSACT2_FINDFIRST);

	state->param = talloc_array(state, uint8_t, 12);
	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}

	SSVAL(state->param, 0, state->attribute);
	SSVAL(state->param, 2, state->max_matches);
	SSVAL(state->param, 4,
	      FLAG_TRANS2_FIND_REQUIRE_RESUME
	      |FLAG_TRANS2_FIND_CLOSE_IF_END
	      |(cli->backup_intent ? FLAG_TRANS2_FIND_BACKUP_INTENT : 0));
	SSVAL(state->param, 6, state->info_level);
	SIVAL(state->param, 8, 0);

	state->param = trans2_bytes_push_str(state->param, smbXcli_conn_use_unicode(cli->conn),
					     state->mask, strlen(state->mask)+1,
					     NULL);
	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}

	if (clistr_is_previous_version_path(state->mask, NULL, NULL, NULL)) {
		additional_flags2 = FLAGS2_REPARSE_PATH;
	}

	param_len = talloc_get_size(state->param);

	subreq = cli_trans_send(state, state->ev, state->cli, additional_flags2,
				SMBtrans2, NULL, -1, 0, 0,
				state->setup, 1, 0,
				state->param, param_len, 10,
				NULL, 0, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_list_trans_done, req);
	return req;
}

static void cli_list_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_list_trans_state *state = tevent_req_data(
		req, struct cli_list_trans_state);
	NTSTATUS status;
	uint8_t *param;
	uint32_t num_param;
	uint8_t *data;
	char *data_end;
	uint32_t num_data;
	uint32_t min_param;
	struct file_info *tmp;
	size_t old_num_finfo;
	uint16_t recv_flags2;
	int ff_searchcount;
	bool ff_eos;
	char *p, *p2;
	uint32_t resume_key = 0;
	int i;
	DATA_BLOB last_name_raw;
	struct file_info *finfo = NULL;
	size_t param_len;
	uint16_t additional_flags2 = 0;

	min_param = (state->first ? 6 : 4);

	status = cli_trans_recv(subreq, talloc_tos(), &recv_flags2,
				NULL, 0, NULL,
				&param, min_param, &num_param,
				&data, 0, &num_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * TODO: retry, OS/2 nofiles
		 */
		tevent_req_nterror(req, status);
		return;
	}

	if (state->first) {
		state->ff_dir_handle = SVAL(param, 0);
		ff_searchcount = SVAL(param, 2);
		ff_eos = SVAL(param, 4) != 0;
	} else {
		ff_searchcount = SVAL(param, 0);
		ff_eos = SVAL(param, 2) != 0;
	}

	old_num_finfo = talloc_array_length(state->finfo);

	tmp = talloc_realloc(state, state->finfo, struct file_info,
				   old_num_finfo + ff_searchcount);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	state->finfo = tmp;

	p2 = p = (char *)data;
	data_end = (char *)data + num_data;
	last_name_raw = data_blob_null;

	for (i=0; i<ff_searchcount; i++) {
		if (p2 >= data_end) {
			ff_eos = true;
			break;
		}
		if ((state->info_level == SMB_FIND_FILE_BOTH_DIRECTORY_INFO)
		    && (i == ff_searchcount-1)) {
			/* Last entry - fixup the last offset length. */
			SIVAL(p2, 0, PTR_DIFF((data + num_data), p2));
		}

		data_blob_free(&last_name_raw);

		finfo = &state->finfo[old_num_finfo + i];

		p2 += interpret_long_filename(
			state->finfo, /* Stick fname to the array as such */
			state->cli, state->info_level,
			(char *)data, recv_flags2, p2,
			data_end, finfo, &resume_key, &last_name_raw);

		if (finfo->name == NULL) {
			DEBUG(1, ("cli_list: Error: unable to parse name from "
				  "info level %d\n", state->info_level));
			tevent_req_nterror(req,
				NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		status = is_bad_finfo_name(state->cli, finfo);
		if (!NT_STATUS_IS_OK(status)) {
			smbXcli_conn_disconnect(state->cli->conn, status);
			tevent_req_nterror(req, status);
			return;
		}

		if (!state->first && (state->mask[0] != '\0') &&
		    strcsequal(finfo->name, state->mask)) {
			DEBUG(1, ("Error: Looping in FIND_NEXT as name %s has "
				  "already been seen?\n", finfo->name));
			ff_eos = true;
			break;
		}
	}

	if (ff_searchcount == 0) {
		ff_eos = true;
	}

	TALLOC_FREE(param);
	TALLOC_FREE(data);

	/*
	 * Shrink state->finfo to the real length we received
	 */
	tmp = talloc_realloc(state, state->finfo, struct file_info,
				   old_num_finfo + i);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	state->finfo = tmp;

	state->first = false;

	if (ff_eos) {
		data_blob_free(&last_name_raw);
		tevent_req_done(req);
		return;
	}

	TALLOC_FREE(state->mask);
	state->mask = talloc_strdup(state, finfo->name);
	if (tevent_req_nomem(state->mask, req)) {
		return;
	}

	SSVAL(&state->setup[0], 0, TRANSACT2_FINDNEXT);

	param = talloc_realloc(state, state->param, uint8_t, 12);
	if (tevent_req_nomem(param, req)) {
		return;
	}
	state->param = param;

	SSVAL(param, 0, state->ff_dir_handle);
	SSVAL(param, 2, state->max_matches); /* max count */
	SSVAL(param, 4, state->info_level);
	/*
	 * For W2K servers serving out FAT filesystems we *must* set
	 * the resume key. If it's not FAT then it's returned as zero.
	 */
	SIVAL(param, 6, resume_key); /* ff_resume_key */
	/*
	 * NB. *DON'T* use continue here. If you do it seems that W2K
	 * and bretheren can miss filenames. Use last filename
	 * continue instead. JRA
	 */
	SSVAL(param, 10, (FLAG_TRANS2_FIND_REQUIRE_RESUME
			  |FLAG_TRANS2_FIND_CLOSE_IF_END
			  |(state->cli->backup_intent ? FLAG_TRANS2_FIND_BACKUP_INTENT : 0)));
	if (last_name_raw.length) {
		state->param = trans2_bytes_push_bytes(state->param,
						       last_name_raw.data,
						       last_name_raw.length);
		if (tevent_req_nomem(state->param, req)) {
			return;
		}
		data_blob_free(&last_name_raw);
	} else {
		state->param = trans2_bytes_push_str(state->param,
						     smbXcli_conn_use_unicode(state->cli->conn),
						     state->mask,
						     strlen(state->mask)+1,
						     NULL);
		if (tevent_req_nomem(state->param, req)) {
			return;
		}
	}
	param_len = talloc_get_size(state->param);

	if (clistr_is_previous_version_path(state->mask, NULL, NULL, NULL)) {
		additional_flags2 = FLAGS2_REPARSE_PATH;
	}

	subreq = cli_trans_send(state, state->ev, state->cli, additional_flags2,
				SMBtrans2, NULL, -1, 0, 0,
				state->setup, 1, 0,
				state->param, param_len, 10,
				NULL, 0, CLI_BUFFER_SIZE);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_list_trans_done, req);
}

static NTSTATUS cli_list_trans_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    struct file_info **finfo)
{
	struct cli_list_trans_state *state = tevent_req_data(
		req, struct cli_list_trans_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*finfo = talloc_move(mem_ctx, &state->finfo);
	return NT_STATUS_OK;
}

NTSTATUS cli_list_trans(struct cli_state *cli, const char *mask,
			uint32_t attribute, int info_level,
			NTSTATUS (*fn)(const char *mnt, struct file_info *finfo,
				   const char *mask, void *private_data),
			void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	int i, num_finfo;
	struct file_info *finfo = NULL;
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
	req = cli_list_trans_send(frame, ev, cli, mask, attribute, info_level);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_list_trans_recv(req, frame, &finfo);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	num_finfo = talloc_array_length(finfo);
	for (i=0; i<num_finfo; i++) {
		status = fn(cli->dfs_mountpoint, &finfo[i], mask, private_data);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_list_state {
	NTSTATUS (*recv_fn)(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    struct file_info **finfo);
	struct file_info *finfo;
};

static void cli_list_done(struct tevent_req *subreq);

struct tevent_req *cli_list_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct cli_state *cli,
				 const char *mask,
				 uint32_t attribute,
				 uint16_t info_level)
{
	struct tevent_req *req, *subreq;
	struct cli_list_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_list_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) <= PROTOCOL_LANMAN1) {
		subreq = cli_list_old_send(state, ev, cli, mask, attribute);
		state->recv_fn = cli_list_old_recv;
	} else {
		subreq = cli_list_trans_send(state, ev, cli, mask, attribute,
					     info_level);
		state->recv_fn = cli_list_trans_recv;
	}
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_list_done, req);
	return req;
}

static void cli_list_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_list_state *state = tevent_req_data(
		req, struct cli_list_state);
	NTSTATUS status;

	status = state->recv_fn(subreq, state, &state->finfo);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_list_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		       struct file_info **finfo, size_t *num_finfo)
{
	struct cli_list_state *state = tevent_req_data(
		req, struct cli_list_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*num_finfo = talloc_array_length(state->finfo);
	*finfo = talloc_move(mem_ctx, &state->finfo);
	return NT_STATUS_OK;
}

NTSTATUS cli_list(struct cli_state *cli, const char *mask, uint32_t attribute,
		  NTSTATUS (*fn)(const char *, struct file_info *, const char *,
			     void *), void *state)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct file_info *finfo;
	size_t i, num_finfo = 0;
	uint16_t info_level;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_list(cli, mask, attribute, fn, state);
	}

	frame = talloc_stackframe();

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

	info_level = (smb1cli_conn_capabilities(cli->conn) & CAP_NT_SMBS)
		? SMB_FIND_FILE_BOTH_DIRECTORY_INFO : SMB_FIND_INFO_STANDARD;

	req = cli_list_send(frame, ev, cli, mask, attribute, info_level);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_list_recv(req, frame, &finfo, &num_finfo);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	for (i=0; i<num_finfo; i++) {
		status = fn(cli->dfs_mountpoint, &finfo[i], mask, state);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}
 fail:
	TALLOC_FREE(frame);
	return status;
}

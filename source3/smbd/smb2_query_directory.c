/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "../libcli/smb/smb_common.h"
#include "trans2.h"
#include "../lib/util/tevent_ntstatus.h"
#include "system/filesys.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static struct tevent_req *smbd_smb2_query_directory_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      struct files_struct *in_fsp,
					      uint8_t in_file_info_class,
					      uint8_t in_flags,
					      uint32_t in_file_index,
					      uint32_t in_output_buffer_length,
					      const char *in_file_name);
static NTSTATUS smbd_smb2_query_directory_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_output_buffer);

static void smbd_smb2_request_find_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_query_directory(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	const uint8_t *inbody;
	uint8_t in_file_info_class;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	uint16_t in_file_name_offset;
	uint16_t in_file_name_length;
	DATA_BLOB in_file_name_buffer;
	char *in_file_name_string;
	size_t in_file_name_string_size;
	uint32_t in_output_buffer_length;
	struct tevent_req *subreq;
	bool ok;

	status = smbd_smb2_request_verify_sizes(req, 0x21);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_file_info_class		= CVAL(inbody, 0x02);
	in_flags			= CVAL(inbody, 0x03);
	in_file_index			= IVAL(inbody, 0x04);
	in_file_id_persistent		= BVAL(inbody, 0x08);
	in_file_id_volatile		= BVAL(inbody, 0x10);
	in_file_name_offset		= SVAL(inbody, 0x18);
	in_file_name_length		= SVAL(inbody, 0x1A);
	in_output_buffer_length		= IVAL(inbody, 0x1C);

	if (in_file_name_offset == 0 && in_file_name_length == 0) {
		/* This is ok */
	} else if (in_file_name_offset !=
		   (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_file_name_length > SMBD_SMB2_IN_DYN_LEN(req)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	/* The output header is 8 bytes. */
	if (in_output_buffer_length <= 8) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	DEBUG(10,("smbd_smb2_request_find_done: in_output_buffer_length = %u\n",
		(unsigned int)in_output_buffer_length ));

	/* Take into account the output header. */
	in_output_buffer_length -= 8;

	in_file_name_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
	in_file_name_buffer.length = in_file_name_length;

	ok = convert_string_talloc(req, CH_UTF16, CH_UNIX,
				   in_file_name_buffer.data,
				   in_file_name_buffer.length,
				   &in_file_name_string,
				   &in_file_name_string_size);
	if (!ok) {
		return smbd_smb2_request_error(req, NT_STATUS_ILLEGAL_CHARACTER);
	}

	if (in_file_name_buffer.length == 0) {
		in_file_name_string_size = 0;
	}

	if (strlen(in_file_name_string) != in_file_name_string_size) {
		return smbd_smb2_request_error(req, NT_STATUS_OBJECT_NAME_INVALID);
	}

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_query_directory_send(req, req->sconn->ev_ctx,
				     req, in_fsp,
				     in_file_info_class,
				     in_flags,
				     in_file_index,
				     in_output_buffer_length,
				     in_file_name_string);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_find_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_find_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint16_t out_output_buffer_offset;
	DATA_BLOB out_output_buffer = data_blob_null;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_query_directory_recv(subreq,
				     req,
				     &out_output_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	out_output_buffer_offset = SMB2_HDR_BODY + 0x08;

	outbody = smbd_smb2_generate_outbody(req, 0x08);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x08 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      out_output_buffer_offset);	/* output buffer offset */
	SIVAL(outbody.data, 0x04,
	      out_output_buffer.length);	/* output buffer length */

	DEBUG(10,("smbd_smb2_request_find_done: out_output_buffer.length = %u\n",
		(unsigned int)out_output_buffer.length ));

	outdyn = out_output_buffer;

	error = smbd_smb2_request_done(req, outbody, &outdyn);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

static struct tevent_req *fetch_write_time_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						connection_struct *conn,
						struct file_id id,
						int info_level,
						char *entry_marshall_buf,
						bool *stop);
static NTSTATUS fetch_write_time_recv(struct tevent_req *req);

static struct tevent_req *fetch_dos_mode_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *dir_fsp,
	struct smb_filename **smb_fname,
	uint32_t info_level,
	uint8_t *entry_marshall_buf);

static NTSTATUS fetch_dos_mode_recv(struct tevent_req *req);

struct smbd_smb2_query_directory_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	uint64_t async_sharemode_count;
	uint32_t find_async_delay_usec;
	DATA_BLOB out_output_buffer;
	struct smb_request *smbreq;
	int in_output_buffer_length;
	struct files_struct *fsp;
	const char *in_file_name;
	NTSTATUS empty_status;
	uint32_t info_level;
	uint32_t max_count;
	char *pdata;
	char *base_data;
	char *end_data;
	uint32_t num;
	uint32_t dirtype;
	bool dont_descend;
	bool ask_sharemode;
	bool async_dosmode;
	bool async_ask_sharemode;
	int last_entry_off;
	size_t max_async_dosmode_active;
	uint32_t async_dosmode_active;
	bool done;
};

static bool smb2_query_directory_next_entry(struct tevent_req *req);
static void smb2_query_directory_fetch_write_time_done(struct tevent_req *subreq);
static void smb2_query_directory_dos_mode_done(struct tevent_req *subreq);
static void smb2_query_directory_waited(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_query_directory_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      struct files_struct *fsp,
					      uint8_t in_file_info_class,
					      uint8_t in_flags,
					      uint32_t in_file_index,
					      uint32_t in_output_buffer_length,
					      const char *in_file_name)
{
	struct smbXsrv_connection *xconn = smb2req->xconn;
	struct tevent_req *req;
	struct smbd_smb2_query_directory_state *state;
	connection_struct *conn = smb2req->tcon->compat;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	NTSTATUS status;
	bool wcard_has_wild = false;
	struct tm tm;
	char *p;
	bool stop = false;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_query_directory_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->smb2req = smb2req;
	state->in_output_buffer_length = in_output_buffer_length;
	state->in_file_name = in_file_name;
	state->out_output_buffer = data_blob_null;
	state->dirtype = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY;

	DEBUG(10,("smbd_smb2_query_directory_send: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	state->smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(state->smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!fsp->fsp_flags.is_directory) {
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	if (strcmp(state->in_file_name, "") == 0) {
		tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_INVALID);
		return tevent_req_post(req, ev);
	}
	if (strchr_m(state->in_file_name, '\\') != NULL) {
		tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_INVALID);
		return tevent_req_post(req, ev);
	}
	if (strchr_m(state->in_file_name, '/') != NULL) {
		tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_INVALID);
		return tevent_req_post(req, ev);
	}

	p = strptime(state->in_file_name, GMT_FORMAT, &tm);
	if ((p != NULL) && (*p =='\0')) {
		/*
		 * Bogus find that asks for a shadow copy timestamp as a
		 * directory. The correct response is that it does not exist as
		 * a directory.
		 */
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_FILE);
		return tevent_req_post(req, ev);
	}

	if (in_output_buffer_length > xconn->smb2.server.max_trans) {
		DEBUG(2,("smbd_smb2_query_directory_send: "
			 "client ignored max trans:%s: 0x%08X: 0x%08X\n",
			 __location__, in_output_buffer_length,
			 xconn->smb2.server.max_trans));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = smbd_smb2_request_verify_creditcharge(smb2req,
					in_output_buffer_length);

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	switch (in_file_info_class) {
	case SMB2_FIND_DIRECTORY_INFO:
		state->info_level = SMB_FIND_FILE_DIRECTORY_INFO;
		break;

	case SMB2_FIND_FULL_DIRECTORY_INFO:
		state->info_level = SMB_FIND_FILE_FULL_DIRECTORY_INFO;
		break;

	case SMB2_FIND_BOTH_DIRECTORY_INFO:
		state->info_level = SMB_FIND_FILE_BOTH_DIRECTORY_INFO;
		break;

	case SMB2_FIND_NAME_INFO:
		state->info_level = SMB_FIND_FILE_NAMES_INFO;
		break;

	case SMB2_FIND_ID_BOTH_DIRECTORY_INFO:
		state->info_level = SMB_FIND_ID_BOTH_DIRECTORY_INFO;
		break;

	case SMB2_FIND_ID_FULL_DIRECTORY_INFO:
		state->info_level = SMB_FIND_ID_FULL_DIRECTORY_INFO;
		break;

	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_INFO_CLASS);
		return tevent_req_post(req, ev);
	}

	if (in_flags & SMB2_CONTINUE_FLAG_REOPEN) {
		int flags;

		status = fd_close(fsp);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		/*
		 * fd_close() will close and invalidate the fsp's file
		 * descriptor. So we have to reopen it.
		 */

		flags = O_RDONLY;
#ifdef O_DIRECTORY
		flags |= O_DIRECTORY;
#endif
		status = fd_open(fsp, flags, 0);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	if (!state->smbreq->posix_pathnames) {
		wcard_has_wild = ms_has_wild(state->in_file_name);
	}

	/* Ensure we've canonicalized any search path if not a wildcard. */
	if (!wcard_has_wild) {
		struct smb_filename *smb_fname = NULL;
		const char *fullpath;
		char tmpbuf[PATH_MAX];
		char *to_free = NULL;
		uint32_t ucf_flags = UCF_ALWAYS_ALLOW_WCARD_LCOMP |
				     (state->smbreq->posix_pathnames ?
					UCF_POSIX_PATHNAMES : 0);

		if (ISDOT(fsp->fsp_name->base_name)) {
			fullpath = state->in_file_name;
		} else {
			size_t len;
			char *tmp;

			len = full_path_tos(
				fsp->fsp_name->base_name, state->in_file_name,
				tmpbuf, sizeof(tmpbuf), &tmp, &to_free);
			if (len == -1) {
				tevent_req_oom(req);
				return tevent_req_post(req, ev);
			}
			fullpath = tmp;
		}
		status = filename_convert(state,
				conn,
				fullpath,
				ucf_flags,
				0,
				&wcard_has_wild,
				&smb_fname);

		TALLOC_FREE(to_free);

		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		/*
		 * We still need to do the case processing
		 * to save off the client-supplied last component.
		 * At least we know there's no @GMT normalization
		 * or MS-DFS paths to do in a directory mask.
		 */
		state->in_file_name = get_original_lcomp(state,
						conn,
						state->in_file_name,
						0);
		if (state->in_file_name == NULL) {
			tevent_req_oom(req);
			return tevent_req_post(req, ev);
		}
	}

	if (fsp->dptr == NULL) {
		status = dptr_create(conn,
				     NULL, /* req */
				     fsp,
				     false, /* old_handle */
				     false, /* expect_close */
				     0, /* spid */
				     state->in_file_name, /* wcard */
				     wcard_has_wild,
				     state->dirtype,
				     &fsp->dptr);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}

		state->empty_status = NT_STATUS_NO_SUCH_FILE;
	} else {
		state->empty_status = STATUS_NO_MORE_FILES;
	}

	if (in_flags & SMB2_CONTINUE_FLAG_RESTART) {
		dptr_SeekDir(fsp->dptr, 0);
	}

	if (in_flags & SMB2_CONTINUE_FLAG_SINGLE) {
		state->max_count = 1;
	} else {
		state->max_count = UINT16_MAX;
	}

#define DIR_ENTRY_SAFETY_MARGIN 4096

	state->out_output_buffer = data_blob_talloc(state, NULL,
			in_output_buffer_length + DIR_ENTRY_SAFETY_MARGIN);
	if (tevent_req_nomem(state->out_output_buffer.data, req)) {
		return tevent_req_post(req, ev);
	}

	state->out_output_buffer.length = 0;
	state->pdata = (char *)state->out_output_buffer.data;
	state->base_data = state->pdata;
	/*
	 * end_data must include the safety margin as it's what is
	 * used to determine if pushed strings have been truncated.
	 */
	state->end_data = state->pdata + in_output_buffer_length + DIR_ENTRY_SAFETY_MARGIN - 1;

	DEBUG(8,("smbd_smb2_query_directory_send: dirpath=<%s> dontdescend=<%s>, "
		"in_output_buffer_length = %u\n",
		 fsp->fsp_name->base_name, lp_dont_descend(talloc_tos(), lp_sub, SNUM(conn)),
		(unsigned int)in_output_buffer_length ));
	if (in_list(fsp->fsp_name->base_name,lp_dont_descend(talloc_tos(), lp_sub, SNUM(conn)),
			conn->case_sensitive)) {
		state->dont_descend = true;
	}

	/*
	 * SMB_FIND_FILE_NAMES_INFO doesn't need stat information
	 *
	 * This may change when we try to improve the delete on close
	 * handling in future.
	 */
	if (state->info_level != SMB_FIND_FILE_NAMES_INFO) {
		state->ask_sharemode = lp_smbd_search_ask_sharemode(SNUM(conn));

		state->async_dosmode = lp_smbd_async_dosmode(SNUM(conn));
	}

	if (state->ask_sharemode && lp_clustering()) {
		state->ask_sharemode = false;
		state->async_ask_sharemode = true;
	}

	if (state->async_dosmode) {
		size_t max_threads;

		max_threads = pthreadpool_tevent_max_threads(conn->sconn->pool);
		if (max_threads == 0 || !per_thread_cwd_supported()) {
			state->async_dosmode = false;
		}

		state->max_async_dosmode_active = lp_smbd_max_async_dosmode(
							SNUM(conn));
		if (state->max_async_dosmode_active == 0) {
			state->max_async_dosmode_active = max_threads * 2;
		}
	}

	if (state->async_dosmode || state->async_ask_sharemode) {
		/*
		 * Should we only set async_internal
		 * if we're not the last request in
		 * a compound chain?
		 */
		smb2_request_set_async_internal(smb2req, true);
	}

	/*
	 * This gets set in autobuild for some tests
	 */
	state->find_async_delay_usec = lp_parm_ulong(SNUM(conn), "smbd",
						     "find async delay usec",
						     0);

	while (!stop) {
		stop = smb2_query_directory_next_entry(req);
	}

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	ok = aio_add_req_to_fsp(fsp, req);
	if (!ok) {
		DBG_ERR("Could not add req to fsp\n");
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	return req;
}

static bool smb2_query_directory_next_entry(struct tevent_req *req)
{
	struct smbd_smb2_query_directory_state *state = tevent_req_data(
		req, struct smbd_smb2_query_directory_state);
	struct smb_filename *smb_fname = NULL; /* relative to fsp !! */
	bool got_exact_match = false;
	int off = state->out_output_buffer.length;
	int space_remaining = state->in_output_buffer_length - off;
	struct file_id file_id;
	NTSTATUS status;
	bool get_dosmode = !state->async_dosmode;
	bool stop = false;

	SMB_ASSERT(space_remaining >= 0);

	status = smbd_dirptr_lanman2_entry(state,
					   state->fsp->conn,
					   state->fsp->dptr,
					   state->smbreq->flags2,
					   state->in_file_name,
					   state->dirtype,
					   state->info_level,
					   false, /* requires_resume_key */
					   state->dont_descend,
					   state->ask_sharemode,
					   get_dosmode,
					   8, /* align to 8 bytes */
					   false, /* no padding */
					   &state->pdata,
					   state->base_data,
					   state->end_data,
					   space_remaining,
					   &smb_fname,
					   &got_exact_match,
					   &state->last_entry_off,
					   NULL,
					   &file_id);

	off = (int)PTR_DIFF(state->pdata, state->base_data);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ILLEGAL_CHARACTER)) {
			/*
			 * Bad character conversion on name. Ignore this
			 * entry.
			 */
			return false;
		} else if (state->num > 0) {
			goto last_entry_done;
		} else if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			tevent_req_nterror(req, NT_STATUS_INFO_LENGTH_MISMATCH);
			return true;
		} else {
			tevent_req_nterror(req, state->empty_status);
			return true;
		}
	}

	if (state->async_ask_sharemode &&
	    !S_ISDIR(smb_fname->st.st_ex_mode))
	{
		struct tevent_req *subreq = NULL;
		char *buf = state->base_data + state->last_entry_off;

		subreq = fetch_write_time_send(state,
					       state->ev,
					       state->fsp->conn,
					       file_id,
					       state->info_level,
					       buf,
					       &stop);
		if (tevent_req_nomem(subreq, req)) {
			return true;
		}
		tevent_req_set_callback(
			subreq,
			smb2_query_directory_fetch_write_time_done,
			req);
		state->async_sharemode_count++;
	}

	if (state->async_dosmode) {
		struct tevent_req *subreq = NULL;
		uint8_t *buf = NULL;
		size_t outstanding_aio;

		buf = (uint8_t *)state->base_data + state->last_entry_off;

		subreq = fetch_dos_mode_send(state,
					     state->ev,
					     state->fsp,
					     &smb_fname,
					     state->info_level,
					     buf);
		if (tevent_req_nomem(subreq, req)) {
			return true;
		}
		tevent_req_set_callback(subreq,
					smb2_query_directory_dos_mode_done,
					req);

		state->async_dosmode_active++;

		outstanding_aio = pthreadpool_tevent_queued_jobs(
					state->fsp->conn->sconn->pool);

		if (outstanding_aio > state->max_async_dosmode_active) {
			stop = true;
		}
	}

	TALLOC_FREE(smb_fname);

	state->num++;
	state->out_output_buffer.length = off;

	if (!state->done && state->num < state->max_count) {
		return stop;
	}

last_entry_done:
	SIVAL(state->out_output_buffer.data, state->last_entry_off, 0);

	state->done = true;

	if (state->async_sharemode_count > 0) {
		DBG_DEBUG("Stopping after %"PRIu64" async mtime "
			  "updates\n", state->async_sharemode_count);
		return true;
	}

	if (state->async_dosmode_active > 0) {
		return true;
	}

	if (state->find_async_delay_usec > 0) {
		struct timeval tv;
		struct tevent_req *subreq = NULL;

		/*
		 * Should we only set async_internal
		 * if we're not the last request in
		 * a compound chain?
		 */
		smb2_request_set_async_internal(state->smb2req, true);

		tv = timeval_current_ofs(0, state->find_async_delay_usec);

		subreq = tevent_wakeup_send(state, state->ev, tv);
		if (tevent_req_nomem(subreq, req)) {
			return true;
		}
		tevent_req_set_callback(subreq,
					smb2_query_directory_waited,
					req);
		return true;
	}

	tevent_req_done(req);
	return true;
}

static void smb2_query_directory_check_next_entry(struct tevent_req *req);

static void smb2_query_directory_fetch_write_time_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_query_directory_state *state = tevent_req_data(
		req, struct smbd_smb2_query_directory_state);
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->fsp);
	SMB_ASSERT(ok);

	state->async_sharemode_count--;

	status = fetch_write_time_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smb2_query_directory_check_next_entry(req);
	return;
}

static void smb2_query_directory_dos_mode_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_query_directory_state *state =
		tevent_req_data(req,
		struct smbd_smb2_query_directory_state);
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->fsp);
	SMB_ASSERT(ok);

	status = fetch_dos_mode_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->async_dosmode_active--;

	smb2_query_directory_check_next_entry(req);
	return;
}

static void smb2_query_directory_check_next_entry(struct tevent_req *req)
{
	struct smbd_smb2_query_directory_state *state = tevent_req_data(
		req, struct smbd_smb2_query_directory_state);
	bool stop = false;

	if (!state->done) {
		while (!stop) {
			stop = smb2_query_directory_next_entry(req);
		}
		return;
	}

	if (state->async_sharemode_count > 0 ||
	    state->async_dosmode_active > 0)
	{
		return;
	}

	if (state->find_async_delay_usec > 0) {
		struct timeval tv;
		struct tevent_req *subreq = NULL;

		tv = timeval_current_ofs(0, state->find_async_delay_usec);

		subreq = tevent_wakeup_send(state, state->ev, tv);
		if (tevent_req_nomem(subreq, req)) {
			tevent_req_post(req, state->ev);
			return;
		}
		tevent_req_set_callback(subreq,
					smb2_query_directory_waited,
					req);
		return;
	}

	tevent_req_done(req);
	return;
}

static void smb2_query_directory_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_query_directory_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_output_buffer)
{
	NTSTATUS status;
	struct smbd_smb2_query_directory_state *state = tevent_req_data(req,
					     struct smbd_smb2_query_directory_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_output_buffer = state->out_output_buffer;
	talloc_steal(mem_ctx, out_output_buffer->data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct fetch_write_time_state {
	connection_struct *conn;
	struct file_id id;
	int info_level;
	char *entry_marshall_buf;
};

static void fetch_write_time_done(struct tevent_req *subreq);

static struct tevent_req *fetch_write_time_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						connection_struct *conn,
						struct file_id id,
						int info_level,
						char *entry_marshall_buf,
						bool *stop)
{
	struct tevent_req *req = NULL;
	struct fetch_write_time_state *state = NULL;
	struct tevent_req *subreq = NULL;
	bool req_queued;

	*stop = false;

	req = tevent_req_create(mem_ctx, &state, struct fetch_write_time_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct fetch_write_time_state) {
		.conn = conn,
		.id = id,
		.info_level = info_level,
		.entry_marshall_buf = entry_marshall_buf,
	};

	subreq = fetch_share_mode_send(state, ev, id, &req_queued);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_write_time_done, req);

	if (req_queued) {
		*stop = true;
	}
	return req;
}

static void fetch_write_time_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_write_time_state *state = tevent_req_data(
		req, struct fetch_write_time_state);
	struct timespec write_time;
	struct share_mode_lock *lck = NULL;
	NTSTATUS status;
	size_t off;

	status = fetch_share_mode_recv(subreq, state, &lck);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	write_time = get_share_mode_write_time(lck);
	TALLOC_FREE(lck);

	if (is_omit_timespec(&write_time)) {
		tevent_req_done(req);
		return;
	}

	switch (state->info_level) {
	case SMB_FIND_FILE_DIRECTORY_INFO:
	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
	case SMB_FIND_ID_FULL_DIRECTORY_INFO:
	case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
		off = 24;
		break;

	default:
		DBG_ERR("Unsupported info_level [%d]\n", state->info_level);
		tevent_req_nterror(req, NT_STATUS_INVALID_LEVEL);
		return;
	}

	put_long_date_full_timespec(state->conn->ts_res,
			       state->entry_marshall_buf + off,
			       &write_time);

	tevent_req_done(req);
	return;
}

static NTSTATUS fetch_write_time_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct fetch_dos_mode_state {
	struct files_struct *dir_fsp;
	struct smb_filename *smb_fname;
	uint32_t info_level;
	uint8_t *entry_marshall_buf;
};

static void fetch_dos_mode_done(struct tevent_req *subreq);

static struct tevent_req *fetch_dos_mode_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct files_struct *dir_fsp,
			struct smb_filename **smb_fname,
			uint32_t info_level,
			uint8_t *entry_marshall_buf)
{
	struct tevent_req *req = NULL;
	struct fetch_dos_mode_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct fetch_dos_mode_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct fetch_dos_mode_state) {
		.dir_fsp = dir_fsp,
		.info_level = info_level,
		.entry_marshall_buf = entry_marshall_buf,
	};

	state->smb_fname = talloc_move(state, smb_fname);

	subreq = dos_mode_at_send(state, ev, dir_fsp, state->smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_dos_mode_done, req);

	return req;
}

static void fetch_dos_mode_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct fetch_dos_mode_state *state =
		tevent_req_data(req,
		struct fetch_dos_mode_state);
	uint32_t dfs_dosmode;
	uint32_t dosmode;
	struct timespec btime_ts = {0};
	bool need_file_id = false;
	uint64_t file_id;
	off_t dosmode_off;
	off_t btime_off;
	off_t file_id_off;
	NTSTATUS status;

	status = dos_mode_at_recv(subreq, &dosmode);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	switch (state->info_level) {
	case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
	case SMB_FIND_FILE_DIRECTORY_INFO:
	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
	case SMB_FIND_ID_FULL_DIRECTORY_INFO:
		btime_off = 8;
		dosmode_off = 56;
		break;

	default:
		DBG_ERR("Unsupported info_level [%u]\n", state->info_level);
		tevent_req_nterror(req, NT_STATUS_INVALID_LEVEL);
		return;
	}


	dfs_dosmode = IVAL(state->entry_marshall_buf, dosmode_off);
	if (dfs_dosmode == 0) {
		/*
		 * DOS mode for a DFS link, only overwrite if still set to 0 and
		 * not already populated by the lower layer for a DFS link in
		 * smbd_dirptr_lanman2_mode_fn().
		 */
		SIVAL(state->entry_marshall_buf, dosmode_off, dosmode);
	}

	btime_ts = get_create_timespec(state->dir_fsp->conn,
				       NULL,
				       state->smb_fname);
	if (lp_dos_filetime_resolution(SNUM(state->dir_fsp->conn))) {
		dos_filetime_timespec(&btime_ts);
	}

	put_long_date_full_timespec(state->dir_fsp->conn->ts_res,
			       (char *)state->entry_marshall_buf + btime_off,
			       &btime_ts);

	switch (state->info_level) {
	case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
		file_id_off = 96;
		need_file_id = true;
		break;
	case SMB_FIND_ID_FULL_DIRECTORY_INFO:
		file_id_off = 72;
		need_file_id = true;
		break;
	default:
		break;
	}

	if (need_file_id) {
		/*
		 * File-ID might have been updated from calculated (based on
		 * inode) to storage based, fetch via DOS attributes in
		 * vfs_default.
		 */
		file_id = SMB_VFS_FS_FILE_ID(state->dir_fsp->conn,
					     &state->smb_fname->st);
		SBVAL(state->entry_marshall_buf, file_id_off, file_id);
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS fetch_dos_mode_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

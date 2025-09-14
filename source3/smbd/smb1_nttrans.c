/*
   Unix SMB/CIFS implementation.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison			1994-2007
   Copyright (C) Stefan (metze) Metzmacher	2003

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
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "smbprofile.h"
#include "lib/util_ea.h"
#include "librpc/gen_ndr/ndr_quota.h"
#include "librpc/gen_ndr/ndr_security.h"

static char *nttrans_realloc(char **ptr, size_t size)
{
	if (ptr==NULL) {
		smb_panic("nttrans_realloc() called with NULL ptr");
	}

	*ptr = (char *)SMB_REALLOC(*ptr, size);
	if(*ptr == NULL) {
		return NULL;
	}
	memset(*ptr,'\0',size);
	return *ptr;
}

/****************************************************************************
 Send the required number of replies back.
 We assume all fields other than the data fields are
 set correctly for the type of call.
 HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static void send_nt_replies(connection_struct *conn,
			    struct smb_request *req, NTSTATUS nt_error,
			    char *params, int paramsize,
			    char *pdata, int datasize)
{
	int data_to_send = datasize;
	int params_to_send = paramsize;
	int useable_space;
	char *pp = params;
	char *pd = pdata;
	int params_sent_thistime, data_sent_thistime, total_sent_thistime;
	int alignment_offset = 1;
	int data_alignment_offset = 0;
	struct smbXsrv_connection *xconn = req->xconn;
	int max_send = xconn->smb1.sessions.max_send;

	/*
	 * If there genuinely are no parameters or data to send just send
	 * the empty packet.
	 */

	if(params_to_send == 0 && data_to_send == 0) {
		reply_smb1_outbuf(req, 18, 0);
		if (NT_STATUS_V(nt_error)) {
			error_packet_set((char *)req->outbuf,
					 0, 0, nt_error,
					 __LINE__,__FILE__);
		}
		show_msg((char *)req->outbuf);
		if (!smb1_srv_send(xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(conn))) {
			exit_server_cleanly("send_nt_replies: smb1_srv_send failed.");
		}
		TALLOC_FREE(req->outbuf);
		return;
	}

	/*
	 * When sending params and data ensure that both are nicely aligned.
	 * Only do this alignment when there is also data to send - else
	 * can cause NT redirector problems.
	 */

	if (((params_to_send % 4) != 0) && (data_to_send != 0)) {
		data_alignment_offset = 4 - (params_to_send % 4);
	}

	/*
	 * Space is bufsize minus Netbios over TCP header minus SMB header.
	 * The alignment_offset is to align the param bytes on a four byte
	 * boundary (2 bytes for data len, one byte pad).
	 * NT needs this to work correctly.
	 */

	useable_space = max_send - (smb_size
				    + 2 * 18 /* wct */
				    + alignment_offset
				    + data_alignment_offset);

	if (useable_space < 0) {
		char *msg = talloc_asprintf(
			talloc_tos(),
			"send_nt_replies failed sanity useable_space = %d!!!",
			useable_space);
		DEBUG(0, ("%s\n", msg));
		exit_server_cleanly(msg);
	}

	while (params_to_send || data_to_send) {

		/*
		 * Calculate whether we will totally or partially fill this packet.
		 */

		total_sent_thistime = params_to_send + data_to_send;

		/*
		 * We can never send more than useable_space.
		 */

		total_sent_thistime = MIN(total_sent_thistime, useable_space);

		reply_smb1_outbuf(req, 18,
			     total_sent_thistime + alignment_offset
			     + data_alignment_offset);

		/*
		 * Set total params and data to be sent.
		 */

		SIVAL(req->outbuf,smb_ntr_TotalParameterCount,paramsize);
		SIVAL(req->outbuf,smb_ntr_TotalDataCount,datasize);

		/*
		 * Calculate how many parameters and data we can fit into
		 * this packet. Parameters get precedence.
		 */

		params_sent_thistime = MIN(params_to_send,useable_space);
		data_sent_thistime = useable_space - params_sent_thistime;
		data_sent_thistime = MIN(data_sent_thistime,data_to_send);

		SIVAL(req->outbuf, smb_ntr_ParameterCount,
		      params_sent_thistime);

		if(params_sent_thistime == 0) {
			SIVAL(req->outbuf,smb_ntr_ParameterOffset,0);
			SIVAL(req->outbuf,smb_ntr_ParameterDisplacement,0);
		} else {
			/*
			 * smb_ntr_ParameterOffset is the offset from the start of the SMB header to the
			 * parameter bytes, however the first 4 bytes of outbuf are
			 * the Netbios over TCP header. Thus use smb_base() to subtract
			 * them from the calculation.
			 */

			SIVAL(req->outbuf,smb_ntr_ParameterOffset,
			      ((smb_buf(req->outbuf)+alignment_offset)
			       - smb_base(req->outbuf)));
			/*
			 * Absolute displacement of param bytes sent in this packet.
			 */

			SIVAL(req->outbuf, smb_ntr_ParameterDisplacement,
			      pp - params);
		}

		/*
		 * Deal with the data portion.
		 */

		SIVAL(req->outbuf, smb_ntr_DataCount, data_sent_thistime);

		if(data_sent_thistime == 0) {
			SIVAL(req->outbuf,smb_ntr_DataOffset,0);
			SIVAL(req->outbuf,smb_ntr_DataDisplacement, 0);
		} else {
			/*
			 * The offset of the data bytes is the offset of the
			 * parameter bytes plus the number of parameters being sent this time.
			 */

			SIVAL(req->outbuf, smb_ntr_DataOffset,
			      ((smb_buf(req->outbuf)+alignment_offset) -
			       smb_base(req->outbuf))
			      + params_sent_thistime + data_alignment_offset);
			SIVAL(req->outbuf,smb_ntr_DataDisplacement, pd - pdata);
		}

		/*
		 * Copy the param bytes into the packet.
		 */

		if(params_sent_thistime) {
			if (alignment_offset != 0) {
				memset(smb_buf(req->outbuf), 0,
				       alignment_offset);
			}
			memcpy((smb_buf(req->outbuf)+alignment_offset), pp,
			       params_sent_thistime);
		}

		/*
		 * Copy in the data bytes
		 */

		if(data_sent_thistime) {
			if (data_alignment_offset != 0) {
				memset((smb_buf(req->outbuf)+alignment_offset+
					params_sent_thistime), 0,
				       data_alignment_offset);
			}
			memcpy(smb_buf(req->outbuf)+alignment_offset
			       +params_sent_thistime+data_alignment_offset,
			       pd,data_sent_thistime);
		}

		DEBUG(9,("nt_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
			params_sent_thistime, data_sent_thistime, useable_space));
		DEBUG(9,("nt_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
			params_to_send, data_to_send, paramsize, datasize));

		if (NT_STATUS_V(nt_error)) {
			error_packet_set((char *)req->outbuf,
					 0, 0, nt_error,
					 __LINE__,__FILE__);
		}

		/* Send the packet */
		show_msg((char *)req->outbuf);
		if (!smb1_srv_send(xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(conn))) {
			exit_server_cleanly("send_nt_replies: smb1_srv_send failed.");
		}

		TALLOC_FREE(req->outbuf);

		pp += params_sent_thistime;
		pd += data_sent_thistime;

		params_to_send -= params_sent_thistime;
		data_to_send -= data_sent_thistime;

		/*
		 * Sanity check
		 */

		if(params_to_send < 0 || data_to_send < 0) {
			DEBUG(0,("send_nt_replies failed sanity check pts = %d, dts = %d\n!!!",
				params_to_send, data_to_send));
			exit_server_cleanly("send_nt_replies: internal error");
		}
	}
}

/****************************************************************************
 Reply to an NT create and X call on a pipe
****************************************************************************/

static void nt_open_pipe(char *fname, connection_struct *conn,
			 struct smb_request *req, uint16_t *ppnum)
{
	files_struct *fsp;
	NTSTATUS status;

	DEBUG(4,("nt_open_pipe: Opening pipe %s.\n", fname));

	/* Strip \\ off the name if present. */
	while (fname[0] == '\\') {
		fname++;
	}

	status = open_np_file(req, fname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					ERRDOS, ERRbadpipe);
			return;
		}
		reply_nterror(req, status);
		return;
	}

	*ppnum = fsp->fnum;
	return;
}

/****************************************************************************
 Reply to an NT create and X call for pipes.
****************************************************************************/

static void do_ntcreate_pipe_open(connection_struct *conn,
				  struct smb_request *req)
{
	char *fname = NULL;
	uint16_t pnum = FNUM_FIELD_INVALID;
	char *p = NULL;
	uint32_t flags = IVAL(req->vwv+3, 1);
	TALLOC_CTX *ctx = talloc_tos();

	srvstr_pull_req_talloc(ctx, req, &fname, req->buf, STR_TERMINATE);

	if (!fname) {
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpipe);
		return;
	}
	nt_open_pipe(fname, conn, req, &pnum);

	if (req->outbuf) {
		/* error reply */
		return;
	}

	/*
	 * Deal with pipe return.
	 */

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		/* This is very strange. We
 		 * return 50 words, but only set
		 * the wcnt to 42 ? It's definitely
 		 * what happens on the wire....
 		 */
		reply_smb1_outbuf(req, 50, 0);
		SCVAL(req->outbuf,smb_wct,42);
	} else {
		reply_smb1_outbuf(req, 34, 0);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	p = (char *)req->outbuf + smb_vwv2;
	p++;
	SSVAL(p,0,pnum);
	p += 2;
	SIVAL(p,0,FILE_WAS_OPENED);
	p += 4;
	p += 32;
	SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
	p += 20;
	/* File type. */
	SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
	/* Device state. */
	SSVAL(p,2, 0x5FF); /* ? */
	p += 4;

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		p += 25;
		SIVAL(p,0,FILE_GENERIC_ALL);
		/*
		 * For pipes W2K3 seems to return
 		 * 0x12019B next.
 		 * This is ((FILE_GENERIC_READ|FILE_GENERIC_WRITE) & ~FILE_APPEND_DATA)
 		 */
		SIVAL(p,4,(FILE_GENERIC_READ|FILE_GENERIC_WRITE)&~FILE_APPEND_DATA);
	}

	DEBUG(5,("do_ntcreate_pipe_open: open pipe = %s\n", fname));
}

struct case_semantics_state {
	connection_struct *conn;
	bool case_sensitive;
	bool case_preserve;
	bool short_case_preserve;
};

/****************************************************************************
 Restore case semantics.
****************************************************************************/

static int restore_case_semantics(struct case_semantics_state *state)
{
	state->conn->case_sensitive = state->case_sensitive;
	state->conn->case_preserve = state->case_preserve;
	state->conn->short_case_preserve = state->short_case_preserve;
	return 0;
}

/****************************************************************************
 Save case semantics.
****************************************************************************/

static struct case_semantics_state *set_posix_case_semantics(TALLOC_CTX *mem_ctx,
						connection_struct *conn)
{
	struct case_semantics_state *result;

	if (!(result = talloc(mem_ctx, struct case_semantics_state))) {
		return NULL;
	}

	result->conn = conn;
	result->case_sensitive = conn->case_sensitive;
	result->case_preserve = conn->case_preserve;
	result->short_case_preserve = conn->short_case_preserve;

	/* Set to POSIX. */
	conn->case_sensitive = True;
	conn->case_preserve = True;
	conn->short_case_preserve = True;

	talloc_set_destructor(result, restore_case_semantics);

	return result;
}

/*
 * Calculate the full path name given a relative fid.
 */
static NTSTATUS get_relative_fid_filename(connection_struct *conn,
					  struct smb_request *req,
					  uint16_t root_dir_fid,
					  char *path,
					  char **path_out)
{
	struct files_struct *dir_fsp = NULL;
	char *new_path = NULL;

	if (root_dir_fid == 0 || path == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	dir_fsp = file_fsp(req, root_dir_fid);
	if (dir_fsp == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (fsp_is_alternate_stream(dir_fsp)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!dir_fsp->fsp_flags.is_directory) {
		/*
		 * Check to see if this is a mac fork of some kind.
		 */
		if (conn->fs_capabilities & FILE_NAMED_STREAMS) {
			char *stream = NULL;

			stream = strchr_m(path, ':');
			if (stream != NULL) {
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
		}

		/*
		 * We need to handle the case when we get a relative open
		 * relative to a file and the pathname is blank - this is a
		 * reopen! (hint from demyn plantenberg)
		 */
		return NT_STATUS_INVALID_HANDLE;
	}

	if (ISDOT(dir_fsp->fsp_name->base_name)) {
		/*
		 * We're at the toplevel dir, the final file name
		 * must not contain ./, as this is filtered out
		 * normally by srvstr_get_path and unix_convert
		 * explicitly rejects paths containing ./.
		 */
		new_path = talloc_strdup(talloc_tos(), path);
	} else {
		/*
		 * Copy in the base directory name.
		 */

		new_path = talloc_asprintf(talloc_tos(),
					   "%s/%s",
					   dir_fsp->fsp_name->base_name,
					   path);
	}
	if (new_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*path_out = new_path;
	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to an NT create and X call.
****************************************************************************/

void reply_ntcreate_and_X(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct files_struct *dirfsp = NULL;
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	uint32_t flags;
	uint32_t access_mask;
	uint32_t file_attributes;
	uint32_t share_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint16_t root_dir_fid;
	uint64_t allocation_size;
	/* Breakout the oplock request bits so we can set the
	   reply bits separately. */
	uint32_t fattr=0;
	off_t file_len = 0;
	int info = 0;
	files_struct *fsp = NULL;
	char *p = NULL;
	struct timespec create_timespec;
	struct timespec c_timespec;
	struct timespec a_timespec;
	struct timespec m_timespec;
	NTSTATUS status;
	int oplock_request;
	uint8_t oplock_granted = NO_OPLOCK_RETURN;
	struct case_semantics_state *case_state = NULL;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBntcreateX);

	if (req->wct < 24) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	flags = IVAL(req->vwv+3, 1);
	access_mask = IVAL(req->vwv+7, 1);
	file_attributes = IVAL(req->vwv+13, 1);
	share_access = IVAL(req->vwv+15, 1);
	create_disposition = IVAL(req->vwv+17, 1);
	create_options = IVAL(req->vwv+19, 1);
	root_dir_fid = (uint16_t)IVAL(req->vwv+5, 1);

	allocation_size = BVAL(req->vwv+9, 1);

	srvstr_get_path_req(ctx, req, &fname, (const char *)req->buf,
			    STR_TERMINATE, &status);

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DBG_DEBUG("flags = 0x%" PRIx32 ", access_mask = 0x%" PRIx32
		  ", file_attributes = 0x%" PRIx32
		  ", share_access = 0x%" PRIx32
		  ", create_disposition = 0x%" PRIx32
		  ", create_options = 0x%" PRIx32 ", root_dir_fid = 0x%" PRIx32
		  ", fname = %s\n",
		  flags,
		  access_mask,
		  file_attributes,
		  share_access,
		  create_disposition,
		  create_options,
		  root_dir_fid,
		  fname);

	/*
	 * we need to remove ignored bits when they come directly from the client
	 * because we reuse some of them for internal stuff
	 */
	create_options &= ~NTCREATEX_OPTIONS_MUST_IGNORE_MASK;

	/*
	 * If it's an IPC, use the pipe handler.
	 */

	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			do_ntcreate_pipe_open(conn, req);
			goto out;
		}
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	if (oplock_request) {
		oplock_request |= (flags & REQUEST_BATCH_OPLOCK)
			? BATCH_OPLOCK : 0;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		case_state = set_posix_case_semantics(ctx, conn);
		if (!case_state) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	}

	if (root_dir_fid != 0) {
		char *new_fname = NULL;

		status = get_relative_fid_filename(conn,
						   req,
						   root_dir_fid,
						   fname,
						   &new_fname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		fname = new_fname;
	}

	ucf_flags = filename_create_ucf_flags(req,
					      create_disposition,
					      create_options);
	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(
		ctx, conn, fname, ucf_flags, twrp, &dirfsp, &smb_fname);

	TALLOC_FREE(case_state);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
				NT_STATUS_PATH_NOT_COVERED,
				ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	/*
	 * Bug #6898 - clients using Windows opens should
	 * never be able to set this attribute into the
	 * VFS.
	 */
	file_attributes &= ~FILE_FLAG_POSIX_SEMANTICS;

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_access,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		file_attributes,			/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		allocation_size,			/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call, no error. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}
		reply_openerror(req, status);
		goto out;
	}

	/* Ensure we're pointing at the correct stat struct. */
	smb_fname = fsp->fsp_name;

	/*
	 * If the caller set the extended oplock request bit
	 * and we granted one (by whatever means) - set the
	 * correct bit for extended oplock reply.
	 */

	if (oplock_request &&
	    (lp_fake_oplocks(SNUM(conn))
	     || EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))) {

		/*
		 * Exclusive oplock granted
		 */

		if (flags & REQUEST_BATCH_OPLOCK) {
			oplock_granted = BATCH_OPLOCK_RETURN;
		} else {
			oplock_granted = EXCLUSIVE_OPLOCK_RETURN;
		}
	} else if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		oplock_granted = LEVEL_II_OPLOCK_RETURN;
	} else {
		oplock_granted = NO_OPLOCK_RETURN;
	}

	file_len = smb_fname->st.st_ex_size;

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		/* This is very strange. We
 		 * return 50 words, but only set
		 * the wcnt to 42 ? It's definitely
 		 * what happens on the wire....
 		 */
		reply_smb1_outbuf(req, 50, 0);
		SCVAL(req->outbuf,smb_wct,42);
	} else {
		reply_smb1_outbuf(req, 34, 0);
	}

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	p = (char *)req->outbuf + smb_vwv2;

	SCVAL(p, 0, oplock_granted);

	p++;
	SSVAL(p,0,fsp->fnum);
	p += 2;
	if ((create_disposition == FILE_SUPERSEDE)
	    && (info == FILE_WAS_OVERWRITTEN)) {
		SIVAL(p,0,FILE_WAS_SUPERSEDED);
	} else {
		SIVAL(p,0,info);
	}
	p += 4;

	fattr = fdos_mode(fsp);
	if (fattr == 0) {
		fattr = FILE_ATTRIBUTE_NORMAL;
	}

	/* Create time. */
	create_timespec = get_create_timespec(conn, fsp, smb_fname);
	a_timespec = smb_fname->st.st_ex_atime;
	m_timespec = smb_fname->st.st_ex_mtime;
	c_timespec = smb_fname->st.st_ex_ctime;

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		dos_filetime_timespec(&create_timespec);
		dos_filetime_timespec(&a_timespec);
		dos_filetime_timespec(&m_timespec);
		dos_filetime_timespec(&c_timespec);
	}

	put_long_date_full_timespec(conn->ts_res, p, &create_timespec); /* create time. */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &a_timespec); /* access time */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &m_timespec); /* write time */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &c_timespec); /* change time */
	p += 8;
	SIVAL(p,0,fattr); /* File Attributes. */
	p += 4;
	SOFF_T(p, 0, SMB_VFS_GET_ALLOC_SIZE(conn,fsp,&smb_fname->st));
	p += 8;
	SOFF_T(p,0,file_len);
	p += 8;
	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		uint16_t file_status = (NO_EAS|NO_SUBSTREAMS|NO_REPARSETAG);
		unsigned int num_streams = 0;
		struct stream_struct *streams = NULL;

		if (lp_ea_support(SNUM(conn))) {
			size_t num_names = 0;
			/* Do we have any EA's ? */
			status = get_ea_names_from_fsp(
			    ctx, smb_fname->fsp, NULL, &num_names);
			if (NT_STATUS_IS_OK(status) && num_names) {
				file_status &= ~NO_EAS;
			}
		}

		status = vfs_fstreaminfo(smb_fname->fsp, ctx,
			&num_streams, &streams);
		/* There is always one stream, ::$DATA. */
		if (NT_STATUS_IS_OK(status) && num_streams > 1) {
			file_status &= ~NO_SUBSTREAMS;
		}
		TALLOC_FREE(streams);
		SSVAL(p,2,file_status);
	}
	p += 4;
	SCVAL(p,0,fsp->fsp_flags.is_directory ? 1 : 0);

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		uint32_t perms = 0;
		p += 25;
		if (fsp->fsp_flags.is_directory ||
		    fsp->fsp_flags.can_write ||
		    can_write_to_fsp(fsp))
		{
			perms = FILE_GENERIC_ALL;
		} else {
			perms = FILE_GENERIC_READ|FILE_EXECUTE;
		}
		SIVAL(p,0,perms);
	}

	DEBUG(5,("reply_ntcreate_and_X: %s, open name = %s\n",
		fsp_fnum_dbg(fsp), smb_fname_str_dbg(smb_fname)));

 out:
	END_PROFILE(SMBntcreateX);
	return;
}

/****************************************************************************
 Reply to a NT_TRANSACT_CREATE call to open a pipe.
****************************************************************************/

static void do_nt_transact_create_pipe(connection_struct *conn,
				       struct smb_request *req,
				       uint16_t **ppsetup, uint32_t setup_count,
				       char **ppparams, uint32_t parameter_count,
				       char **ppdata, uint32_t data_count)
{
	char *fname = NULL;
	char *params = *ppparams;
	uint16_t pnum = FNUM_FIELD_INVALID;
	char *p = NULL;
	NTSTATUS status;
	size_t param_len;
	uint32_t flags;
	TALLOC_CTX *ctx = talloc_tos();

	/*
	 * Ensure minimum number of parameters sent.
	 */

	if(parameter_count < 54) {
		DEBUG(0,("do_nt_transact_create_pipe - insufficient parameters (%u)\n", (unsigned int)parameter_count));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	flags = IVAL(params,0);

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
			params,
			req->flags2,
			&fname,
			params+53,
			parameter_count-53,
			STR_TERMINATE,
			&status);
	} else {
		srvstr_get_path(ctx,
			params,
			req->flags2,
			&fname,
			params+53,
			parameter_count-53,
			STR_TERMINATE,
			&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	nt_open_pipe(fname, conn, req, &pnum);

	if (req->outbuf) {
		/* Error return */
		return;
	}

	/* Realloc the size of parameters and data we will return */
	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		/* Extended response is 32 more byyes. */
		param_len = 101;
	} else {
		param_len = 69;
	}
	params = nttrans_realloc(ppparams, param_len);
	if(params == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	p = params;
	SCVAL(p,0,NO_OPLOCK_RETURN);

	p += 2;
	SSVAL(p,0,pnum);
	p += 2;
	SIVAL(p,0,FILE_WAS_OPENED);
	p += 8;

	p += 32;
	SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
	p += 20;
	/* File type. */
	SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
	/* Device state. */
	SSVAL(p,2, 0x5FF); /* ? */
	p += 4;

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		p += 25;
		SIVAL(p,0,FILE_GENERIC_ALL);
		/*
		 * For pipes W2K3 seems to return
 		 * 0x12019B next.
 		 * This is ((FILE_GENERIC_READ|FILE_GENERIC_WRITE) & ~FILE_APPEND_DATA)
 		 */
		SIVAL(p,4,(FILE_GENERIC_READ|FILE_GENERIC_WRITE)&~FILE_APPEND_DATA);
	}

	DEBUG(5,("do_nt_transact_create_pipe: open name = %s\n", fname));

	/* Send the required number of replies */
	send_nt_replies(conn, req, NT_STATUS_OK, params, param_len, *ppdata, 0);

	return;
}

/****************************************************************************
 Reply to a NT_TRANSACT_CREATE call (needs to process SD's).
****************************************************************************/

static void call_nt_transact_create(connection_struct *conn,
				    struct smb_request *req,
				    uint16_t **ppsetup, uint32_t setup_count,
				    char **ppparams, uint32_t parameter_count,
				    char **ppdata, uint32_t data_count,
				    uint32_t max_data_count)
{
	struct smb_filename *smb_fname = NULL;
	char *fname = NULL;
	char *params = *ppparams;
	char *data = *ppdata;
	/* Breakout the oplock request bits so we can set the reply bits separately. */
	uint32_t fattr=0;
	off_t file_len = 0;
	int info = 0;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp = NULL;
	char *p = NULL;
	uint32_t flags;
	uint32_t access_mask;
	uint32_t file_attributes;
	uint32_t share_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint32_t sd_len;
	struct security_descriptor *sd = NULL;
	uint32_t ea_len;
	uint16_t root_dir_fid;
	struct timespec create_timespec;
	struct timespec c_timespec;
	struct timespec a_timespec;
	struct timespec m_timespec;
	struct ea_list *ea_list = NULL;
	NTSTATUS status;
	size_t param_len;
	uint64_t allocation_size;
	int oplock_request;
	uint8_t oplock_granted;
	struct case_semantics_state *case_state = NULL;
	uint32_t ucf_flags;
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	DEBUG(5,("call_nt_transact_create\n"));

	/*
	 * If it's an IPC, use the pipe handler.
	 */

	if (IS_IPC(conn)) {
		if (lp_nt_pipe_support()) {
			do_nt_transact_create_pipe(
				conn, req,
				ppsetup, setup_count,
				ppparams, parameter_count,
				ppdata, data_count);
			goto out;
		}
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	/*
	 * Ensure minimum number of parameters sent.
	 */

	if(parameter_count < 54) {
		DEBUG(0,("call_nt_transact_create - insufficient parameters (%u)\n", (unsigned int)parameter_count));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	flags = IVAL(params,0);
	access_mask = IVAL(params,8);
	file_attributes = IVAL(params,20);
	share_access = IVAL(params,24);
	create_disposition = IVAL(params,28);
	create_options = IVAL(params,32);
	sd_len = IVAL(params,36);
	ea_len = IVAL(params,40);
	root_dir_fid = (uint16_t)IVAL(params,4);
	allocation_size = BVAL(params,12);

	/*
	 * we need to remove ignored bits when they come directly from the client
	 * because we reuse some of them for internal stuff
	 */
	create_options &= ~NTCREATEX_OPTIONS_MUST_IGNORE_MASK;

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
			params,
			req->flags2,
			&fname,
			params+53,
			parameter_count-53,
			STR_TERMINATE,
			&status);
	} else {
		srvstr_get_path(ctx,
			params,
			req->flags2,
			&fname,
			params+53,
			parameter_count-53,
			STR_TERMINATE,
			&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (file_attributes & FILE_FLAG_POSIX_SEMANTICS) {
		case_state = set_posix_case_semantics(ctx, conn);
		if (!case_state) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	}

	if (root_dir_fid != 0) {
		char *new_fname = NULL;

		status = get_relative_fid_filename(conn,
						   req,
						   root_dir_fid,
						   fname,
						   &new_fname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		fname = new_fname;
	}

	ucf_flags = filename_create_ucf_flags(req,
					      create_disposition,
					      create_options);
	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);

	TALLOC_FREE(case_state);

	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
				NT_STATUS_PATH_NOT_COVERED,
				ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	/* Ensure the data_len is correct for the sd and ea values given. */
	if ((ea_len + sd_len > data_count)
	    || (ea_len > data_count) || (sd_len > data_count)
	    || (ea_len + sd_len < ea_len) || (ea_len + sd_len < sd_len)) {
		DEBUG(10, ("call_nt_transact_create - ea_len = %u, sd_len = "
			   "%u, data_count = %u\n", (unsigned int)ea_len,
			   (unsigned int)sd_len, (unsigned int)data_count));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	if (sd_len) {
		DEBUG(10, ("call_nt_transact_create - sd_len = %d\n",
			   sd_len));

		status = unmarshall_sec_desc(ctx, (uint8_t *)data, sd_len,
					     &sd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("call_nt_transact_create: "
				   "unmarshall_sec_desc failed: %s\n",
				   nt_errstr(status)));
			reply_nterror(req, status);
			goto out;
		}
	}

	if (ea_len) {
		if (!lp_ea_support(SNUM(conn))) {
			DEBUG(10, ("call_nt_transact_create - ea_len = %u but "
				   "EA's not supported.\n",
				   (unsigned int)ea_len));
			reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
			goto out;
		}

		if (ea_len < 10) {
			DEBUG(10,("call_nt_transact_create - ea_len = %u - "
				  "too small (should be more than 10)\n",
				  (unsigned int)ea_len ));
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		/* We have already checked that ea_len <= data_count here. */
		ea_list = read_nttrans_ea_list(talloc_tos(), data + sd_len,
					       ea_len);
		if (ea_list == NULL) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (!req->posix_pathnames &&
				ea_list_has_invalid_name(ea_list)) {
			/* Realloc the size of parameters and data we will return */
			if (flags & EXTENDED_RESPONSE_REQUIRED) {
				/* Extended response is 32 more bytes. */
				param_len = 101;
			} else {
				param_len = 69;
			}
			params = nttrans_realloc(ppparams, param_len);
			if(params == NULL) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}

			memset(params, '\0', param_len);
			send_nt_replies(conn, req, STATUS_INVALID_EA_NAME,
				params, param_len, NULL, 0);
			goto out;
		}
	}

	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	if (oplock_request) {
		oplock_request |= (flags & REQUEST_BATCH_OPLOCK)
			? BATCH_OPLOCK : 0;
	}

	/*
	 * Bug #6898 - clients using Windows opens should
	 * never be able to set this attribute into the
	 * VFS.
	 */
	file_attributes &= ~FILE_FLAG_POSIX_SEMANTICS;

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_access,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		file_attributes,			/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		allocation_size,			/* allocation_size */
		0,					/* private_flags */
		sd,					/* sd */
		ea_list,				/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if(!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call, no error. */
			return;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				return;
			}
		}
		reply_openerror(req, status);
		goto out;
	}

	/* Ensure we're pointing at the correct stat struct. */
	TALLOC_FREE(smb_fname);
	smb_fname = fsp->fsp_name;

	/*
	 * If the caller set the extended oplock request bit
	 * and we granted one (by whatever means) - set the
	 * correct bit for extended oplock reply.
	 */

	if (oplock_request &&
	    (lp_fake_oplocks(SNUM(conn))
	     || EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type))) {

		/*
		 * Exclusive oplock granted
		 */

		if (flags & REQUEST_BATCH_OPLOCK) {
			oplock_granted = BATCH_OPLOCK_RETURN;
		} else {
			oplock_granted = EXCLUSIVE_OPLOCK_RETURN;
		}
	} else if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		oplock_granted = LEVEL_II_OPLOCK_RETURN;
	} else {
		oplock_granted = NO_OPLOCK_RETURN;
	}

	file_len = smb_fname->st.st_ex_size;

	/* Realloc the size of parameters and data we will return */
	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		/* Extended response is 32 more byyes. */
		param_len = 101;
	} else {
		param_len = 69;
	}
	params = nttrans_realloc(ppparams, param_len);
	if(params == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}

	p = params;
	SCVAL(p, 0, oplock_granted);

	p += 2;
	SSVAL(p,0,fsp->fnum);
	p += 2;
	if ((create_disposition == FILE_SUPERSEDE)
	    && (info == FILE_WAS_OVERWRITTEN)) {
		SIVAL(p,0,FILE_WAS_SUPERSEDED);
	} else {
		SIVAL(p,0,info);
	}
	p += 8;

	fattr = fdos_mode(fsp);
	if (fattr == 0) {
		fattr = FILE_ATTRIBUTE_NORMAL;
	}

	/* Create time. */
	create_timespec = get_create_timespec(conn, fsp, smb_fname);
	a_timespec = smb_fname->st.st_ex_atime;
	m_timespec = smb_fname->st.st_ex_mtime;
	c_timespec = smb_fname->st.st_ex_ctime;

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		dos_filetime_timespec(&create_timespec);
		dos_filetime_timespec(&a_timespec);
		dos_filetime_timespec(&m_timespec);
		dos_filetime_timespec(&c_timespec);
	}

	put_long_date_full_timespec(conn->ts_res, p, &create_timespec); /* create time. */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &a_timespec); /* access time */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &m_timespec); /* write time */
	p += 8;
	put_long_date_full_timespec(conn->ts_res, p, &c_timespec); /* change time */
	p += 8;
	SIVAL(p,0,fattr); /* File Attributes. */
	p += 4;
	SOFF_T(p, 0, SMB_VFS_GET_ALLOC_SIZE(conn, fsp, &smb_fname->st));
	p += 8;
	SOFF_T(p,0,file_len);
	p += 8;
	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		uint16_t file_status = (NO_EAS|NO_SUBSTREAMS|NO_REPARSETAG);
		unsigned int num_streams = 0;
		struct stream_struct *streams = NULL;

		if (lp_ea_support(SNUM(conn))) {
			size_t num_names = 0;
			/* Do we have any EA's ? */
			status = get_ea_names_from_fsp(
			    ctx, smb_fname->fsp, NULL, &num_names);
			if (NT_STATUS_IS_OK(status) && num_names) {
				file_status &= ~NO_EAS;
			}
		}

		status = vfs_fstreaminfo(smb_fname->fsp, ctx,
			&num_streams, &streams);
		/* There is always one stream, ::$DATA. */
		if (NT_STATUS_IS_OK(status) && num_streams > 1) {
			file_status &= ~NO_SUBSTREAMS;
		}
		TALLOC_FREE(streams);
		SSVAL(p,2,file_status);
	}
	p += 4;
	SCVAL(p,0,fsp->fsp_flags.is_directory ? 1 : 0);

	if (flags & EXTENDED_RESPONSE_REQUIRED) {
		uint32_t perms = 0;
		p += 25;
		if (fsp->fsp_flags.is_directory ||
		    fsp->fsp_flags.can_write ||
		    can_write_to_fsp(fsp))
		{
			perms = FILE_GENERIC_ALL;
		} else {
			perms = FILE_GENERIC_READ|FILE_EXECUTE;
		}
		SIVAL(p,0,perms);
	}

	DEBUG(5,("call_nt_transact_create: open name = %s\n",
		 smb_fname_str_dbg(smb_fname)));

	/* Send the required number of replies */
	send_nt_replies(conn, req, NT_STATUS_OK, params, param_len, *ppdata, 0);
 out:
	return;
}

/****************************************************************************
 Reply to a NT CANCEL request.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_ntcancel(struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	bool found;

	/*
	 * Go through and cancel any pending change notifies.
	 */

	START_PROFILE(SMBntcancel);
	smb1_srv_cancel_sign_response(xconn);
	found = remove_pending_change_notify_requests_by_mid(sconn, req->mid);
	if (!found) {
		smbd_smb1_brl_finish_by_mid(sconn, req->mid);
	}

	DEBUG(3,("reply_ntcancel: cancel called on mid = %llu.\n",
		(unsigned long long)req->mid));

	END_PROFILE(SMBntcancel);
	return;
}

/****************************************************************************
 Reply to a NT rename request.
****************************************************************************/

void reply_ntrename(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	struct files_struct *src_dirfsp = NULL;
	struct smb_filename *smb_fname_old = NULL;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_new = NULL;
	char *oldname = NULL;
	char *newname = NULL;
	const char *p;
	NTSTATUS status;
	uint32_t attrs;
	uint32_t ucf_flags_src = ucf_flags_from_smb_request(req);
	NTTIME src_twrp = 0;
	uint32_t ucf_flags_dst = ucf_flags_from_smb_request(req);
	NTTIME dst_twrp = 0;
	uint16_t rename_type;
	TALLOC_CTX *ctx = talloc_tos();

	START_PROFILE(SMBntrename);

	if (req->wct < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	attrs = SVAL(req->vwv+0, 0);
	rename_type = SVAL(req->vwv+1, 0);

	p = (const char *)req->buf + 1;
	p += srvstr_get_path_req(ctx, req, &oldname, p, STR_TERMINATE,
				       &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!req->posix_pathnames && ms_has_wild(oldname)) {
		reply_nterror(req, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
		goto out;
	}

	p++;
	p += srvstr_get_path_req(ctx, req, &newname, p, STR_TERMINATE,
				       &status);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	if (!req->posix_pathnames && ms_has_wild(newname)) {
		reply_nterror(req, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
		goto out;
	}

	if (ucf_flags_src & UCF_GMT_PATHNAME) {
		extract_snapshot_token(oldname, &src_twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags_src, &oldname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	status = filename_convert_dirfsp(ctx,
					 conn,
					 oldname,
					 ucf_flags_src,
					 src_twrp,
					 &src_dirfsp,
					 &smb_fname_old);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,
				    NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, status);
		goto out;
	}

	if (!req->posix_pathnames && is_named_stream(smb_fname_old)) {
		if (newname[0] != ':') {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		/*
		 * No point in calling filename_convert()
		 * on a raw stream name. It can never find
		 * the file anyway. Use the same logic as
		 * SMB2_FILE_RENAME_INFORMATION_INTERNAL
		 * and generate smb_fname_new directly.
		 */
		smb_fname_new = synthetic_smb_fname(talloc_tos(),
					smb_fname_old->base_name,
					newname,
					NULL,
					smb_fname_old->twrp,
					smb_fname_old->flags);
		if (smb_fname_new == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}
	} else {
		if (ucf_flags_dst & UCF_GMT_PATHNAME) {
			extract_snapshot_token(newname,
					       &dst_twrp);
		}
		status = smb1_strip_dfs_path(ctx, &ucf_flags_dst, &newname);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
		status = filename_convert_dirfsp(ctx,
						 conn,
						 newname,
						 ucf_flags_dst,
						 dst_twrp,
						 &dst_dirfsp,
						 &smb_fname_new);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_PATH_NOT_COVERED)) {
				reply_botherror(req,
					        NT_STATUS_PATH_NOT_COVERED,
						ERRSRV, ERRbadpath);
				goto out;
			}
			reply_nterror(req, status);
			goto out;
		}
	}

	DEBUG(3,("reply_ntrename: %s -> %s\n",
		 smb_fname_str_dbg(smb_fname_old),
		 smb_fname_str_dbg(smb_fname_new)));

	switch(rename_type) {
	case RENAME_FLAG_RENAME: {
		/*
		 * Get the last component of the destination for
		 * rename_internals().
		 */

		char *dst_original_lcomp = get_original_lcomp(ctx,
							      conn,
							      newname,
							      ucf_flags_dst);
		if (dst_original_lcomp == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			goto out;
		}

		status = rename_internals(ctx,
					  conn,
					  req,
					  src_dirfsp,
					  smb_fname_old,
					  smb_fname_new,
					  dst_original_lcomp,
					  attrs,
					  false,
					  DELETE_ACCESS);

		TALLOC_FREE(dst_original_lcomp);
		break;
	}
	case RENAME_FLAG_HARD_LINK:
		status = hardlink_internals(ctx,
					    conn,
					    req,
					    false,
					    smb_fname_old,
					    smb_fname_new);
		break;
	case RENAME_FLAG_COPY:
		status = copy_internals(ctx,
					conn,
					req,
					src_dirfsp,
					smb_fname_old,
					dst_dirfsp,
					smb_fname_new,
					attrs);
		break;
	case RENAME_FLAG_MOVE_CLUSTER_INFORMATION:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		status = NT_STATUS_ACCESS_DENIED; /* Default error. */
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
		}

		reply_nterror(req, status);
		goto out;
	}

	reply_smb1_outbuf(req, 0, 0);
 out:
	END_PROFILE(SMBntrename);
	return;
}

/****************************************************************************
 Reply to a notify change - queue the request and
 don't allow a directory to be opened.
****************************************************************************/

static void smbd_smb1_notify_reply(struct smb_request *req,
				   NTSTATUS error_code,
				   uint8_t *buf, size_t len)
{
	send_nt_replies(req->conn, req, error_code, (char *)buf, len, NULL, 0);
}

static void call_nt_transact_notify_change(connection_struct *conn,
					   struct smb_request *req,
					   uint16_t **ppsetup,
					   uint32_t setup_count,
					   char **ppparams,
					   uint32_t parameter_count,
					   char **ppdata, uint32_t data_count,
					   uint32_t max_data_count,
					   uint32_t max_param_count)
{
	uint16_t *setup = *ppsetup;
	files_struct *fsp;
	uint32_t filter;
	NTSTATUS status;
	bool recursive;

	if(setup_count < 6) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(setup,4));
	filter = IVAL(setup, 0);
	recursive = (SVAL(setup, 6) != 0) ? True : False;

	DEBUG(3,("call_nt_transact_notify_change\n"));

	if(!fsp) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	DBG_NOTICE("notify change called on %s, filter = %s, recursive = %d\n",
		   fsp_str_dbg(fsp),
		   notify_filter_string(talloc_tos(), filter),
		   recursive);

	if((!fsp->fsp_flags.is_directory) || (conn != fsp->conn)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (fsp->notify == NULL) {

		status = change_notify_create(fsp,
					      max_param_count,
					      filter,
					      recursive);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("change_notify_create returned %s\n",
				   nt_errstr(status)));
			reply_nterror(req, status);
			return;
		}
	}

	if (change_notify_fsp_has_changes(fsp)) {

		/*
		 * We've got changes pending, respond immediately
		 */

		/*
		 * TODO: write a torture test to check the filtering behaviour
		 * here.
		 */

		change_notify_reply(req,
				    NT_STATUS_OK,
				    max_param_count,
				    fsp->notify,
				    smbd_smb1_notify_reply);

		/*
		 * change_notify_reply() above has independently sent its
		 * results
		 */
		return;
	}

	/*
	 * No changes pending, queue the request
	 */

	status = change_notify_add_request(req,
			max_param_count,
			filter,
			recursive, fsp,
			smbd_smb1_notify_reply);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
	}
	return;
}

/****************************************************************************
 Reply to an NT transact rename command.
****************************************************************************/

static void call_nt_transact_rename(connection_struct *conn,
				    struct smb_request *req,
				    uint16_t **ppsetup, uint32_t setup_count,
				    char **ppparams, uint32_t parameter_count,
				    char **ppdata, uint32_t data_count,
				    uint32_t max_data_count)
{
	char *params = *ppparams;
	char *new_name = NULL;
	files_struct *fsp = NULL;
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();

        if(parameter_count < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(params, 0));
	if (!check_fsp(conn, req, fsp)) {
		return;
	}
	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
				params,
				req->flags2,
				&new_name,
				params+4,
				parameter_count - 4,
				STR_TERMINATE,
				&status);
	} else {
		srvstr_get_path(ctx,
				params,
				req->flags2,
				&new_name,
				params+4,
				parameter_count - 4,
				STR_TERMINATE,
				&status);
	}

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	/*
	 * W2K3 ignores this request as the RAW-RENAME test
	 * demonstrates, so we do.
	 */
	send_nt_replies(conn, req, NT_STATUS_OK, NULL, 0, NULL, 0);

	DEBUG(3,("nt transact rename from = %s, to = %s ignored!\n",
		 fsp_str_dbg(fsp), new_name));

	return;
}

/****************************************************************************
 SMB1 reply to query a security descriptor.
****************************************************************************/

static void call_nt_transact_query_security_desc(connection_struct *conn,
						 struct smb_request *req,
						 uint16_t **ppsetup,
						 uint32_t setup_count,
						 char **ppparams,
						 uint32_t parameter_count,
						 char **ppdata,
						 uint32_t data_count,
						 uint32_t max_data_count)
{
	char *params = *ppparams;
	char *data = *ppdata;
	size_t sd_size = 0;
	uint32_t security_info_wanted;
	files_struct *fsp = NULL;
	NTSTATUS status;
	uint8_t *marshalled_sd = NULL;

        if(parameter_count < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(params,0));
	if(!fsp) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	security_info_wanted = IVAL(params,4);

	DEBUG(3,("call_nt_transact_query_security_desc: file = %s, "
		 "info_wanted = 0x%x\n", fsp_str_dbg(fsp),
		 (unsigned int)security_info_wanted));

	params = nttrans_realloc(ppparams, 4);
	if(params == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	/*
	 * Get the permissions to return.
	 */

	status = smbd_do_query_security_desc(conn,
					talloc_tos(),
					fsp,
					security_info_wanted &
					SMB_SUPPORTED_SECINFO_FLAGS,
					max_data_count,
					&marshalled_sd,
					&sd_size);

	if (NT_STATUS_EQUAL(status, NT_STATUS_BUFFER_TOO_SMALL)) {
		SIVAL(params,0,(uint32_t)sd_size);
		send_nt_replies(conn, req, NT_STATUS_BUFFER_TOO_SMALL,
			params, 4, NULL, 0);
		return;
        }

	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	SMB_ASSERT(sd_size > 0);

	SIVAL(params,0,(uint32_t)sd_size);

	if (max_data_count < sd_size) {
		send_nt_replies(conn, req, NT_STATUS_BUFFER_TOO_SMALL,
				params, 4, NULL, 0);
		return;
	}

	/*
	 * Allocate the data we will return.
	 */

	data = nttrans_realloc(ppdata, sd_size);
	if(data == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	memcpy(data, marshalled_sd, sd_size);

	send_nt_replies(conn, req, NT_STATUS_OK, params, 4, data, (int)sd_size);

	return;
}

/****************************************************************************
 Reply to set a security descriptor. Map to UNIX perms or POSIX ACLs.
****************************************************************************/

static void call_nt_transact_set_security_desc(connection_struct *conn,
					       struct smb_request *req,
					       uint16_t **ppsetup,
					       uint32_t setup_count,
					       char **ppparams,
					       uint32_t parameter_count,
					       char **ppdata,
					       uint32_t data_count,
					       uint32_t max_data_count)
{
	char *params= *ppparams;
	char *data = *ppdata;
	files_struct *fsp = NULL;
	uint32_t security_info_sent = 0;
	NTSTATUS status;

	if(parameter_count < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if((fsp = file_fsp(req, SVAL(params,0))) == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	if (!CAN_WRITE(fsp->conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if(!lp_nt_acl_support(SNUM(conn))) {
		goto done;
	}

	security_info_sent = IVAL(params,4);

	DEBUG(3,("call_nt_transact_set_security_desc: file = %s, sent 0x%x\n",
		 fsp_str_dbg(fsp), (unsigned int)security_info_sent));

	if (data_count == 0) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	status = set_sd_blob(fsp, (uint8_t *)data, data_count,
			     security_info_sent & SMB_SUPPORTED_SECINFO_FLAGS);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

  done:
	send_nt_replies(conn, req, NT_STATUS_OK, NULL, 0, NULL, 0);
	return;
}

/****************************************************************************
 Reply to NT IOCTL
****************************************************************************/

static void call_nt_transact_ioctl(connection_struct *conn,
				   struct smb_request *req,
				   uint16_t **ppsetup, uint32_t setup_count,
				   char **ppparams, uint32_t parameter_count,
				   char **ppdata, uint32_t data_count,
				   uint32_t max_data_count)
{
	NTSTATUS status;
	uint32_t function;
	uint16_t fidnum;
	files_struct *fsp;
	uint8_t isFSctl;
	uint8_t compfilter;
	char *out_data = NULL;
	uint32_t out_data_len = 0;
	char *pdata = *ppdata;
	TALLOC_CTX *ctx = talloc_tos();

	if (setup_count != 8) {
		DEBUG(3,("call_nt_transact_ioctl: invalid setup count %d\n", setup_count));
		reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return;
	}

	function = IVAL(*ppsetup, 0);
	fidnum = SVAL(*ppsetup, 4);
	isFSctl = CVAL(*ppsetup, 6);
	compfilter = CVAL(*ppsetup, 7);

	DEBUG(10, ("call_nt_transact_ioctl: function[0x%08X] FID[0x%04X] isFSctl[0x%02X] compfilter[0x%02X]\n", 
		 function, fidnum, isFSctl, compfilter));

	fsp=file_fsp(req, fidnum);

	/*
	 * We don't really implement IOCTLs, especially on files.
	 */
	if (!isFSctl) {
		DEBUG(10, ("isFSctl: 0x%02X indicates IOCTL, not FSCTL!\n",
			isFSctl));
		reply_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return;
	}

	/* Has to be for an open file! */
	if (!check_fsp_open(conn, req, fsp)) {
		return;
	}

	/*
	 * out_data might be allocated by the VFS module, but talloc should be
	 * used, and should be cleaned up when the request ends.
	 */
	status = SMB_VFS_FSCTL(fsp, 
			       ctx,
			       function, 
			       req->flags2,
			       (uint8_t *)pdata, 
			       data_count, 
			       (uint8_t **)&out_data,
			       max_data_count,
			       &out_data_len);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
	} else {
		send_nt_replies(conn, req, NT_STATUS_OK, NULL, 0, out_data, out_data_len);
	}
}


#ifdef HAVE_SYS_QUOTAS
/****************************************************************************
 Reply to get user quota
****************************************************************************/

static void call_nt_transact_get_user_quota(connection_struct *conn,
					    struct smb_request *req,
					    uint16_t **ppsetup,
					    uint32_t setup_count,
					    char **ppparams,
					    uint32_t parameter_count,
					    char **ppdata,
					    uint32_t data_count,
					    uint32_t max_data_count)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	NTSTATUS nt_status = NT_STATUS_OK;
	char *params = *ppparams;
	char *pdata = *ppdata;
	int data_len = 0;
	int param_len = 0;
	files_struct *fsp = NULL;
	DATA_BLOB blob = data_blob_null;
	struct nttrans_query_quota_params info = {0};
	enum ndr_err_code err;
	TALLOC_CTX *tmp_ctx = NULL;
	uint32_t resp_len = 0;
	uint8_t *resp_data = 0;

	tmp_ctx = talloc_init("ntquota_list");
	if (!tmp_ctx) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto error;
	}

	/* access check */
	if (get_current_uid(conn) != sec_initial_uid()) {
		DEBUG(1,("get_user_quota: access_denied service [%s] user "
			 "[%s]\n", lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
			 conn->session_info->unix_info->unix_name));
		nt_status = NT_STATUS_ACCESS_DENIED;
		goto error;
	}

	blob.data = (uint8_t*)params;
	blob.length = parameter_count;

	err = ndr_pull_struct_blob(&blob, tmp_ctx, &info,
		(ndr_pull_flags_fn_t)ndr_pull_nttrans_query_quota_params);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		DEBUG(0,("TRANSACT_GET_USER_QUOTA: failed to pull "
			 "query_quota_params.\n"));
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}
	DBG_DEBUG("info.return_single_entry = %u, info.restart_scan = %u, "
		  "info.sid_list_length = %u, info.start_sid_length = %u, "
		  "info.start_sid_offset = %u\n",
		  (unsigned int)info.return_single_entry,
		  (unsigned int)info.restart_scan,
		  (unsigned int)info.sid_list_length,
		  (unsigned int)info.start_sid_length,
		  (unsigned int)info.start_sid_offset);

	/* set blob to point at data for further parsing */
	blob.data = (uint8_t*)pdata;
	blob.length = data_count;
	/*
	 * Although MS-SMB ref is ambiguous here, a microsoft client will
	 * only ever send a start sid (as part of a list) with
	 * sid_list_length & start_sid_offset both set to the actual list
	 * length. Note: Only a single result is returned in this case
	 * In the case where either start_sid_offset or start_sid_length
	 * are set alone or if both set (but have different values) then
	 * it seems windows will return a number of entries from the start
	 * of the list of users with quotas set. This behaviour is undocumented
	 * and windows clients do not send messages of that type. As such we
	 * currently will reject these requests.
	 */
	if (info.start_sid_length
	|| (info.sid_list_length != info.start_sid_offset)) {
		DBG_ERR("TRANSACT_GET_USER_QUOTA: unsupported single or "
                        "compound sid format\n");
		nt_status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	/* maybe we can check the quota_fnum */
	fsp = file_fsp(req, info.fid);
	if (!check_fsp_ntquota_handle(conn, req, fsp)) {
		DEBUG(3,("TRANSACT_GET_USER_QUOTA: no valid QUOTA HANDLE\n"));
		nt_status = NT_STATUS_INVALID_HANDLE;
		goto error;
	}
	nt_status = smbd_do_query_getinfo_quota(tmp_ctx,
				  fsp,
				  info.restart_scan,
				  info.return_single_entry,
				  info.sid_list_length,
				  &blob,
				  max_data_count,
				  &resp_data,
				  &resp_len);
	if (!NT_STATUS_IS_OK(nt_status)) {
		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MORE_ENTRIES)) {
			goto error;
		}
		nt_status = NT_STATUS_OK;
	}

	param_len = 4;
	params = nttrans_realloc(ppparams, param_len);
	if(params == NULL) {
		nt_status = NT_STATUS_NO_MEMORY;
		goto error;
	}

	data_len = resp_len;
	SIVAL(params, 0, data_len);
	pdata = nttrans_realloc(ppdata, data_len);
	memcpy(pdata, resp_data, data_len);

	TALLOC_FREE(tmp_ctx);
	send_nt_replies(conn, req, nt_status, params, param_len,
			pdata, data_len);
	return;
error:
	TALLOC_FREE(tmp_ctx);
	reply_nterror(req, nt_status);
}

/****************************************************************************
 Reply to set user quota
****************************************************************************/

static void call_nt_transact_set_user_quota(connection_struct *conn,
					    struct smb_request *req,
					    uint16_t **ppsetup,
					    uint32_t setup_count,
					    char **ppparams,
					    uint32_t parameter_count,
					    char **ppdata,
					    uint32_t data_count,
					    uint32_t max_data_count)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *params = *ppparams;
	char *pdata = *ppdata;
	int data_len=0,param_len=0;
	SMB_NTQUOTA_STRUCT qt;
	struct file_quota_information info = {0};
	enum ndr_err_code err;
	struct dom_sid sid;
	DATA_BLOB inblob;
	files_struct *fsp = NULL;
	TALLOC_CTX *ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	ZERO_STRUCT(qt);

	/* access check */
	if (get_current_uid(conn) != sec_initial_uid()) {
		DEBUG(1,("set_user_quota: access_denied service [%s] user "
			 "[%s]\n", lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
			 conn->session_info->unix_info->unix_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto error;
	}

	/*
	 * Ensure minimum number of parameters sent.
	 */

	if (parameter_count < 2) {
		DEBUG(0,("TRANSACT_SET_USER_QUOTA: requires %d >= 2 bytes parameters\n",parameter_count));
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	/* maybe we can check the quota_fnum */
	fsp = file_fsp(req, SVAL(params,0));
	if (!check_fsp_ntquota_handle(conn, req, fsp)) {
		DEBUG(3,("TRANSACT_GET_USER_QUOTA: no valid QUOTA HANDLE\n"));
		status = NT_STATUS_INVALID_HANDLE;
		goto error;
	}

	ctx = talloc_init("set_user_quota");
	if (!ctx) {
		status = NT_STATUS_NO_MEMORY;
		goto error;
	}
	inblob.data = (uint8_t*)pdata;
	inblob.length = data_count;

	err = ndr_pull_struct_blob(
			&inblob,
			ctx,
			&info,
			(ndr_pull_flags_fn_t)ndr_pull_file_quota_information);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		DEBUG(0,("TRANSACT_SET_USER_QUOTA: failed to pull "
			 "file_quota_information\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}
	qt.usedspace = info.quota_used;

	qt.softlim = info.quota_threshold;

	qt.hardlim = info.quota_limit;

	sid = info.sid;

	if (vfs_set_ntquota(fsp, SMB_USER_QUOTA_TYPE, &sid, &qt)!=0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}

	send_nt_replies(conn, req, NT_STATUS_OK, params, param_len,
			pdata, data_len);
	TALLOC_FREE(ctx);
	return;
error:
	TALLOC_FREE(ctx);
	reply_nterror(req, status);
}
#endif /* HAVE_SYS_QUOTAS */

static void handle_nttrans(connection_struct *conn,
			   struct trans_state *state,
			   struct smb_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;

	if (xconn->protocol >= PROTOCOL_NT1) {
		req->flags2 |= 0x40; /* IS_LONG_NAME */
		SSVAL(discard_const_p(uint8_t, req->inbuf),smb_flg2,req->flags2);
	}


	/* Now we must call the relevant NT_TRANS function */
	switch(state->call) {
		case NT_TRANSACT_CREATE:
		{
			START_PROFILE(NT_transact_create);
			call_nt_transact_create(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_create);
			break;
		}

		case NT_TRANSACT_IOCTL:
		{
			START_PROFILE(NT_transact_ioctl);
			call_nt_transact_ioctl(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_ioctl);
			break;
		}

		case NT_TRANSACT_SET_SECURITY_DESC:
		{
			START_PROFILE(NT_transact_set_security_desc);
			call_nt_transact_set_security_desc(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_set_security_desc);
			break;
		}

		case NT_TRANSACT_NOTIFY_CHANGE:
		{
			START_PROFILE(NT_transact_notify_change);
			call_nt_transact_notify_change(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return,
				state->max_param_return);
			END_PROFILE(NT_transact_notify_change);
			break;
		}

		case NT_TRANSACT_RENAME:
		{
			START_PROFILE(NT_transact_rename);
			call_nt_transact_rename(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_rename);
			break;
		}

		case NT_TRANSACT_QUERY_SECURITY_DESC:
		{
			START_PROFILE(NT_transact_query_security_desc);
			call_nt_transact_query_security_desc(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_query_security_desc);
			break;
		}

#ifdef HAVE_SYS_QUOTAS
		case NT_TRANSACT_GET_USER_QUOTA:
		{
			START_PROFILE(NT_transact_get_user_quota);
			call_nt_transact_get_user_quota(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_get_user_quota);
			break;
		}

		case NT_TRANSACT_SET_USER_QUOTA:
		{
			START_PROFILE(NT_transact_set_user_quota);
			call_nt_transact_set_user_quota(
				conn, req,
				&state->setup, state->setup_count,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
			END_PROFILE(NT_transact_set_user_quota);
			break;
		}
#endif /* HAVE_SYS_QUOTAS */

		default:
			/* Error in request */
			DEBUG(0,("handle_nttrans: Unknown request %d in "
				 "nttrans call\n", state->call));
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
	}
	return;
}

/****************************************************************************
 Reply to a SMBNTtrans.
****************************************************************************/

void reply_nttrans(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint32_t pscnt;
	uint32_t psoff;
	uint32_t dscnt;
	uint32_t dsoff;
	uint16_t function_code;
	NTSTATUS result;
	struct trans_state *state;

	START_PROFILE(SMBnttrans);

	if (req->wct < 19) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnttrans);
		return;
	}

	pscnt = IVAL(req->vwv+9, 1);
	psoff = IVAL(req->vwv+11, 1);
	dscnt = IVAL(req->vwv+13, 1);
	dsoff = IVAL(req->vwv+15, 1);
	function_code = SVAL(req->vwv+18, 0);

	if (IS_IPC(conn) && (function_code != NT_TRANSACT_CREATE)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		END_PROFILE(SMBnttrans);
		return;
	}

	result = allow_new_trans(conn->pending_trans, req->mid);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(2, ("Got invalid nttrans request: %s\n", nt_errstr(result)));
		reply_nterror(req, result);
		END_PROFILE(SMBnttrans);
		return;
	}

	if ((state = talloc(conn, struct trans_state)) == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBnttrans);
		return;
	}

	state->cmd = SMBnttrans;

	state->mid = req->mid;
	state->vuid = req->vuid;
	state->total_data = IVAL(req->vwv+3, 1);
	state->data = NULL;
	state->total_param = IVAL(req->vwv+1, 1);
	state->param = NULL;
	state->max_data_return = IVAL(req->vwv+7, 1);
	state->max_param_return = IVAL(req->vwv+5, 1);

	/* setup count is in *words* */
	state->setup_count = 2*CVAL(req->vwv+17, 1);
	state->setup = NULL;
	state->call = function_code;

	DEBUG(10, ("num_setup=%u, "
		   "param_total=%u, this_param=%u, max_param=%u, "
		   "data_total=%u, this_data=%u, max_data=%u, "
		   "param_offset=%u, data_offset=%u\n",
		   (unsigned)state->setup_count,
		   (unsigned)state->total_param, (unsigned)pscnt,
		   (unsigned)state->max_param_return,
		   (unsigned)state->total_data, (unsigned)dscnt,
		   (unsigned)state->max_data_return,
		   (unsigned)psoff, (unsigned)dsoff));

	/*
	 * All nttrans messages we handle have smb_wct == 19 +
	 * state->setup_count.  Ensure this is so as a sanity check.
	 */

	if(req->wct != 19 + (state->setup_count/2)) {
		DEBUG(2,("Invalid smb_wct %d in nttrans call (should be %d)\n",
			 req->wct, 19 + (state->setup_count/2)));
		goto bad_param;
	}

	/* Don't allow more than 128mb for each value. */
	if ((state->total_data > (1024*1024*128)) ||
	    (state->total_param > (1024*1024*128))) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBnttrans);
		return;
	}

	if ((dscnt > state->total_data) || (pscnt > state->total_param))
		goto bad_param;

	if (state->total_data)  {

		if (smb_buffer_oob(state->total_data, 0, dscnt)
		    || smb_buffer_oob(smb_len(req->inbuf), dsoff, dscnt)) {
			goto bad_param;
		}

		/* Can't use talloc here, the core routines do realloc on the
		 * params and data. */
		if ((state->data = (char *)SMB_MALLOC(state->total_data)) == NULL) {
			DEBUG(0,("reply_nttrans: data malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_data));
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnttrans);
			return;
		}

		memcpy(state->data,smb_base(req->inbuf)+dsoff,dscnt);
	}

	if (state->total_param) {

		if (smb_buffer_oob(state->total_param, 0, pscnt)
		    || smb_buffer_oob(smb_len(req->inbuf), psoff, pscnt)) {
			goto bad_param;
		}

		/* Can't use talloc here, the core routines do realloc on the
		 * params and data. */
		if ((state->param = (char *)SMB_MALLOC(state->total_param)) == NULL) {
			DEBUG(0,("reply_nttrans: param malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_param));
			SAFE_FREE(state->data);
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnttrans);
			return;
		}

		memcpy(state->param,smb_base(req->inbuf)+psoff,pscnt);
	}

	state->received_data  = dscnt;
	state->received_param = pscnt;

	if(state->setup_count > 0) {
		DEBUG(10,("reply_nttrans: state->setup_count = %d\n",
			  state->setup_count));

		/*
		 * No overflow possible here, state->setup_count is an
		 * unsigned int, being filled by a single byte from
		 * CVAL(req->vwv+13, 0) above. The cast in the comparison
		 * below is not necessary, it's here to clarify things. The
		 * validity of req->vwv and req->wct has been checked in
		 * init_smb1_request already.
		 */
		if ((state->setup_count/2) + 19 > (unsigned int)req->wct) {
			goto bad_param;
		}

		state->setup = (uint16_t *)TALLOC(state, state->setup_count);
		if (state->setup == NULL) {
			DEBUG(0,("reply_nttrans : Out of memory\n"));
			SAFE_FREE(state->data);
			SAFE_FREE(state->param);
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBnttrans);
			return;
		}

		memcpy(state->setup, req->vwv+19, state->setup_count);
		dump_data(10, (uint8_t *)state->setup, state->setup_count);
	}

	if ((state->received_data == state->total_data) &&
	    (state->received_param == state->total_param)) {
		handle_nttrans(conn, state, req);
		SAFE_FREE(state->param);
		SAFE_FREE(state->data);
		TALLOC_FREE(state);
		END_PROFILE(SMBnttrans);
		return;
	}

	DLIST_ADD(conn->pending_trans, state);

	/* We need to send an interim response then receive the rest
	   of the parameter/data bytes */
	reply_smb1_outbuf(req, 0, 0);
	show_msg((char *)req->outbuf);
	END_PROFILE(SMBnttrans);
	return;

  bad_param:

	DEBUG(0,("reply_nttrans: invalid trans parameters\n"));
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
	END_PROFILE(SMBnttrans);
	return;
}

/****************************************************************************
 Reply to a SMBnttranss
 ****************************************************************************/

void reply_nttranss(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	uint32_t pcnt,poff,dcnt,doff,pdisp,ddisp;
	struct trans_state *state;

	START_PROFILE(SMBnttranss);

	show_msg((const char *)req->inbuf);

	/* Windows clients expect all replies to
	   an NT transact secondary (SMBnttranss 0xA1)
	   to have a command code of NT transact
	   (SMBnttrans 0xA0). See bug #8989 for details. */
	req->cmd = SMBnttrans;

	if (req->wct < 18) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnttranss);
		return;
	}

	for (state = conn->pending_trans; state != NULL;
	     state = state->next) {
		if (state->mid == req->mid) {
			break;
		}
	}

	if ((state == NULL) || (state->cmd != SMBnttrans)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBnttranss);
		return;
	}

	/* Revise state->total_param and state->total_data in case they have
	   changed downwards */
	if (IVAL(req->vwv+1, 1) < state->total_param) {
		state->total_param = IVAL(req->vwv+1, 1);
	}
	if (IVAL(req->vwv+3, 1) < state->total_data) {
		state->total_data = IVAL(req->vwv+3, 1);
	}

	pcnt = IVAL(req->vwv+5, 1);
	poff = IVAL(req->vwv+7, 1);
	pdisp = IVAL(req->vwv+9, 1);

	dcnt = IVAL(req->vwv+11, 1);
	doff = IVAL(req->vwv+13, 1);
	ddisp = IVAL(req->vwv+15, 1);

	state->received_param += pcnt;
	state->received_data += dcnt;

	if ((state->received_data > state->total_data) ||
	    (state->received_param > state->total_param))
		goto bad_param;

	if (pcnt) {
		if (smb_buffer_oob(state->total_param, pdisp, pcnt)
		    || smb_buffer_oob(smb_len(req->inbuf), poff, pcnt)) {
			goto bad_param;
		}
		memcpy(state->param+pdisp, smb_base(req->inbuf)+poff,pcnt);
	}

	if (dcnt) {
		if (smb_buffer_oob(state->total_data, ddisp, dcnt)
		    || smb_buffer_oob(smb_len(req->inbuf), doff, dcnt)) {
			goto bad_param;
		}
		memcpy(state->data+ddisp, smb_base(req->inbuf)+doff,dcnt);
	}

	if ((state->received_param < state->total_param) ||
	    (state->received_data < state->total_data)) {
		END_PROFILE(SMBnttranss);
		return;
	}

	handle_nttrans(conn, state, req);

	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	END_PROFILE(SMBnttranss);
	return;

  bad_param:

	DEBUG(0,("reply_nttranss: invalid trans parameters\n"));
	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
	END_PROFILE(SMBnttranss);
	return;
}

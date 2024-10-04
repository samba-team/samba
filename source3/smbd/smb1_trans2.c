/*
   Unix SMB/CIFS implementation.
   SMB transaction2 handling
   Copyright (C) Jeremy Allison			1994-2007
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Volker Lendecke		2005-2007
   Copyright (C) Steve French			2005
   Copyright (C) James Peach			2006-2007

   Extensively modified by Andrew Tridgell, 1995

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
#include "ntioctl.h"
#include "system/filesys.h"
#include "lib/util/time_basic.h"
#include "version.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/xattr.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "trans2.h"
#include "auth.h"
#include "smbprofile.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "printing.h"
#include "lib/util_ea.h"
#include "lib/readdir_attr.h"
#include "messages.h"
#include "libcli/smb/smb2_posix.h"
#include "lib/util/string_wrappers.h"
#include "source3/lib/substitute.h"
#include "source3/lib/adouble.h"
#include "source3/smbd/dir.h"

#define DIR_ENTRY_SAFETY_MARGIN 4096

/****************************************************************************
  Send the required number of replies back.
  We assume all fields other than the data fields are
  set correctly for the type of call.
  HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static void send_trans2_replies(connection_struct *conn,
				struct smb_request *req,
				NTSTATUS status,
				const char *params,
				int paramsize,
				const char *pdata,
				int datasize,
				int max_data_bytes)
{
	/* As we are using a protocol > LANMAN1 then the max_send
	 variable must have been set in the sessetupX call.
	 This takes precedence over the max_xmit field in the
	 global struct. These different max_xmit variables should
	 be merged as this is now too confusing */

	int data_to_send = datasize;
	int params_to_send = paramsize;
	int useable_space;
	const char *pp = params;
	const char *pd = pdata;
	int params_sent_thistime, data_sent_thistime, total_sent_thistime;
	int alignment_offset = 1; /* JRA. This used to be 3. Set to 1 to make netmon parse ok. */
	int data_alignment_offset = 0;
	bool overflow = False;
	struct smbXsrv_connection *xconn = req->xconn;
	int max_send = xconn->smb1.sessions.max_send;

	/* Modify the data_to_send and datasize and set the error if
	   we're trying to send more than max_data_bytes. We still send
	   the part of the packet(s) that fit. Strange, but needed
	   for OS/2. */

	if (max_data_bytes > 0 && datasize > max_data_bytes) {
		DEBUG(5,("send_trans2_replies: max_data_bytes %d exceeded by data %d\n",
			max_data_bytes, datasize ));
		datasize = data_to_send = max_data_bytes;
		overflow = True;
	}

	/* If there genuinely are no parameters or data to send just send the empty packet */

	if(params_to_send == 0 && data_to_send == 0) {
		reply_smb1_outbuf(req, 10, 0);
		if (NT_STATUS_V(status)) {
			uint8_t eclass;
			uint32_t ecode;
			ntstatus_to_dos(status, &eclass, &ecode);
			error_packet_set((char *)req->outbuf,
					eclass, ecode, status,
					__LINE__,__FILE__);
		}
		show_msg((char *)req->outbuf);
		if (!smb1_srv_send(xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(conn))) {
			exit_server_cleanly("send_trans2_replies: smb1_srv_send failed.");
		}
		TALLOC_FREE(req->outbuf);
		return;
	}

	/* When sending params and data ensure that both are nicely aligned */
	/* Only do this alignment when there is also data to send - else
		can cause NT redirector problems. */

	if (((params_to_send % 4) != 0) && (data_to_send != 0))
		data_alignment_offset = 4 - (params_to_send % 4);

	/* Space is bufsize minus Netbios over TCP header minus SMB header */
	/* The alignment_offset is to align the param bytes on an even byte
		boundary. NT 4.0 Beta needs this to work correctly. */

	useable_space = max_send - (smb_size
				    + 2 * 10 /* wct */
				    + alignment_offset
				    + data_alignment_offset);

	if (useable_space < 0) {
		DEBUG(0, ("send_trans2_replies failed sanity useable_space "
			  "= %d!!!\n", useable_space));
		exit_server_cleanly("send_trans2_replies: Not enough space");
	}

	while (params_to_send || data_to_send) {
		/* Calculate whether we will totally or partially fill this packet */

		total_sent_thistime = params_to_send + data_to_send;

		/* We can never send more than useable_space */
		/*
		 * Note that 'useable_space' does not include the alignment offsets,
		 * but we must include the alignment offsets in the calculation of
		 * the length of the data we send over the wire, as the alignment offsets
		 * are sent here. Fix from Marc_Jacobsen@hp.com.
		 */

		total_sent_thistime = MIN(total_sent_thistime, useable_space);

		reply_smb1_outbuf(req, 10, total_sent_thistime + alignment_offset
			     + data_alignment_offset);

		/* Set total params and data to be sent */
		SSVAL(req->outbuf,smb_tprcnt,paramsize);
		SSVAL(req->outbuf,smb_tdrcnt,datasize);

		/* Calculate how many parameters and data we can fit into
		 * this packet. Parameters get precedence
		 */

		params_sent_thistime = MIN(params_to_send,useable_space);
		data_sent_thistime = useable_space - params_sent_thistime;
		data_sent_thistime = MIN(data_sent_thistime,data_to_send);

		SSVAL(req->outbuf,smb_prcnt, params_sent_thistime);

		/* smb_proff is the offset from the start of the SMB header to the
			parameter bytes, however the first 4 bytes of outbuf are
			the Netbios over TCP header. Thus use smb_base() to subtract
			them from the calculation */

		SSVAL(req->outbuf,smb_proff,
		      ((smb_buf(req->outbuf)+alignment_offset)
		       - smb_base(req->outbuf)));

		if(params_sent_thistime == 0)
			SSVAL(req->outbuf,smb_prdisp,0);
		else
			/* Absolute displacement of param bytes sent in this packet */
			SSVAL(req->outbuf,smb_prdisp,pp - params);

		SSVAL(req->outbuf,smb_drcnt, data_sent_thistime);
		if(data_sent_thistime == 0) {
			SSVAL(req->outbuf,smb_droff,0);
			SSVAL(req->outbuf,smb_drdisp, 0);
		} else {
			/* The offset of the data bytes is the offset of the
				parameter bytes plus the number of parameters being sent this time */
			SSVAL(req->outbuf, smb_droff,
			      ((smb_buf(req->outbuf)+alignment_offset)
			       - smb_base(req->outbuf))
			      + params_sent_thistime + data_alignment_offset);
			SSVAL(req->outbuf,smb_drdisp, pd - pdata);
		}

		/* Initialize the padding for alignment */

		if (alignment_offset != 0) {
			memset(smb_buf(req->outbuf), 0, alignment_offset);
		}

		/* Copy the param bytes into the packet */

		if(params_sent_thistime) {
			memcpy((smb_buf(req->outbuf)+alignment_offset), pp,
			       params_sent_thistime);
		}

		/* Copy in the data bytes */
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

		DEBUG(9,("t2_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
			params_sent_thistime, data_sent_thistime, useable_space));
		DEBUG(9,("t2_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
			params_to_send, data_to_send, paramsize, datasize));

		if (overflow) {
			error_packet_set((char *)req->outbuf,
					 ERRDOS,ERRbufferoverflow,
					 STATUS_BUFFER_OVERFLOW,
					 __LINE__,__FILE__);
		} else if (NT_STATUS_V(status)) {
			uint8_t eclass;
			uint32_t ecode;
			ntstatus_to_dos(status, &eclass, &ecode);
			error_packet_set((char *)req->outbuf,
					eclass, ecode, status,
					__LINE__,__FILE__);
		}

		/* Send the packet */
		show_msg((char *)req->outbuf);
		if (!smb1_srv_send(xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(conn))) {
			exit_server_cleanly("send_trans2_replies: smb1_srv_send failed.");
		}

		TALLOC_FREE(req->outbuf);

		pp += params_sent_thistime;
		pd += data_sent_thistime;

		params_to_send -= params_sent_thistime;
		data_to_send -= data_sent_thistime;

		/* Sanity check */
		if(params_to_send < 0 || data_to_send < 0) {
			DEBUG(0,("send_trans2_replies failed sanity check pts = %d, dts = %d\n!!!",
				params_to_send, data_to_send));
			return;
		}
	}

	return;
}

/****************************************************************************
 Deal with SMB_SET_POSIX_LOCK.
****************************************************************************/

static void smb_set_posix_lock_done(struct tevent_req *subreq);

static NTSTATUS smb_set_posix_lock(connection_struct *conn,
				   struct smb_request *req,
				   const char *pdata,
				   int total_data,
				   files_struct *fsp)
{
	struct tevent_req *subreq = NULL;
	struct smbd_lock_element *lck = NULL;
	uint64_t count;
	uint64_t offset;
	uint64_t smblctx;
	bool blocking_lock = False;
	enum brl_type lock_type;

	NTSTATUS status = NT_STATUS_OK;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	if (fsp == NULL ||
	    fsp->fsp_flags.is_pathref ||
	    fsp_get_io_fd(fsp) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (total_data != POSIX_LOCK_DATA_SIZE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (SVAL(pdata, POSIX_LOCK_TYPE_OFFSET)) {
		case POSIX_LOCK_TYPE_READ:
			lock_type = READ_LOCK;
			break;
		case POSIX_LOCK_TYPE_WRITE:
			/* Return the right POSIX-mappable error code for files opened read-only. */
			if (!fsp->fsp_flags.can_write) {
				return NT_STATUS_INVALID_HANDLE;
			}
			lock_type = WRITE_LOCK;
			break;
		case POSIX_LOCK_TYPE_UNLOCK:
			lock_type = UNLOCK_LOCK;
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	switch (SVAL(pdata, POSIX_LOCK_FLAGS_OFFSET)) {
	case POSIX_LOCK_FLAG_NOWAIT:
		blocking_lock = false;
		break;
	case POSIX_LOCK_FLAG_WAIT:
		blocking_lock = true;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!lp_blocking_locks(SNUM(conn))) {
		blocking_lock = False;
	}

	smblctx = (uint64_t)IVAL(pdata, POSIX_LOCK_PID_OFFSET);
	offset = (((uint64_t) IVAL(pdata,(POSIX_LOCK_START_OFFSET+4))) << 32) |
			((uint64_t) IVAL(pdata,POSIX_LOCK_START_OFFSET));
	count = (((uint64_t) IVAL(pdata,(POSIX_LOCK_LEN_OFFSET+4))) << 32) |
			((uint64_t) IVAL(pdata,POSIX_LOCK_LEN_OFFSET));

	DBG_DEBUG("file %s, lock_type = %u, smblctx = %"PRIu64", "
		  "count = %"PRIu64", offset = %"PRIu64"\n",
		  fsp_str_dbg(fsp),
		  (unsigned int)lock_type,
		  smblctx,
		  count,
		  offset);

	if (lock_type == UNLOCK_LOCK) {
		struct smbd_lock_element l = {
			.req_guid = smbd_request_guid(req, 0),
			.smblctx = smblctx,
			.brltype = UNLOCK_LOCK,
			.lock_flav = POSIX_LOCK,
			.offset = offset,
			.count = count,
		};
		status = smbd_do_unlocking(req, fsp, 1, &l);
		return status;
	}

	lck = talloc(req, struct smbd_lock_element);
	if (lck == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*lck = (struct smbd_lock_element) {
		.req_guid = smbd_request_guid(req, 0),
		.smblctx = smblctx,
		.brltype = lock_type,
		.lock_flav = POSIX_LOCK,
		.count = count,
		.offset = offset,
	};

	subreq = smbd_smb1_do_locks_send(
		fsp,
		req->sconn->ev_ctx,
		&req,
		fsp,
		blocking_lock ? UINT32_MAX : 0,
		true,		/* large_offset */
		1,
		lck);
	if (subreq == NULL) {
		TALLOC_FREE(lck);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb_set_posix_lock_done, req);
	return NT_STATUS_EVENT_PENDING;
}

static void smb_set_posix_lock_done(struct tevent_req *subreq)
{
	struct smb_request *req = NULL;
	NTSTATUS status;
	bool ok;

	ok = smbd_smb1_do_locks_extract_smbreq(subreq, talloc_tos(), &req);
	SMB_ASSERT(ok);

	status = smbd_smb1_do_locks_recv(subreq);
	TALLOC_FREE(subreq);

	if (NT_STATUS_IS_OK(status)) {
		char params[2] = {0};
		/* Fake up max_data_bytes here - we know it fits. */
		send_trans2_replies(
			req->conn,
			req,
			NT_STATUS_OK,
			params,
			2,
			NULL,
			0,
			0xffff);
	} else {
		reply_nterror(req, status);
		ok = smb1_srv_send(req->xconn,
				   (char *)req->outbuf,
				   true,
				   req->seqnum + 1,
				   IS_CONN_ENCRYPTED(req->conn));
		if (!ok) {
			exit_server_cleanly("smb_set_posix_lock_done: "
					    "smb1_srv_send failed.");
		}
	}

	TALLOC_FREE(req);
	return;
}

/****************************************************************************
 Read a list of EA names from an incoming data buffer. Create an ea_list with them.
****************************************************************************/

static struct ea_list *read_ea_name_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size)
{
	struct ea_list *ea_list_head = NULL;
	size_t converted_size, offset = 0;

	while (offset + 2 < data_size) {
		struct ea_list *eal = talloc_zero(ctx, struct ea_list);
		unsigned int namelen = CVAL(pdata,offset);

		offset++; /* Go past the namelen byte. */

		/* integer wrap paranioa. */
		if ((offset + namelen < offset) || (offset + namelen < namelen) ||
				(offset > data_size) || (namelen > data_size) ||
				(offset + namelen >= data_size)) {
			break;
		}
		/* Ensure the name is null terminated. */
		if (pdata[offset + namelen] != '\0') {
			return NULL;
		}
		if (!pull_ascii_talloc(ctx, &eal->ea.name, &pdata[offset],
				       &converted_size)) {
			DEBUG(0,("read_ea_name_list: pull_ascii_talloc "
				 "failed: %s\n", strerror(errno)));
		}
		if (!eal->ea.name) {
			return NULL;
		}

		offset += (namelen + 1); /* Go past the name + terminating zero. */
		DLIST_ADD_END(ea_list_head, eal);
		DEBUG(10,("read_ea_name_list: read ea name %s\n", eal->ea.name));
	}

	return ea_list_head;
}

/****************************************************************************
 Reply to a TRANSACT2_OPEN.
****************************************************************************/

static void call_trans2open(connection_struct *conn,
			    struct smb_request *req,
			    char **pparams, int total_params,
			    char **ppdata, int total_data,
			    unsigned int max_data_bytes)
{
	struct smb_filename *smb_fname = NULL;
	char *params = *pparams;
	char *pdata = *ppdata;
	int deny_mode;
	int32_t open_attr;
	bool oplock_request;
#if 0
	bool return_additional_info;
	int16 open_sattr;
	time_t open_time;
#endif
	int open_ofun;
	uint32_t open_size;
	char *pname;
	char *fname = NULL;
	off_t size=0;
	int fattr = 0;
	SMB_INO_T inode = 0;
	int smb_action = 0;
	struct files_struct *dirfsp = NULL;
	files_struct *fsp;
	struct ea_list *ea_list = NULL;
	uint16_t flags = 0;
	NTSTATUS status;
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = 0;
	uint32_t private_flags = 0;
	NTTIME twrp = 0;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	TALLOC_CTX *ctx = talloc_tos();

	/*
	 * Ensure we have enough parameters to perform the operation.
	 */

	if (total_params < 29) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	flags = SVAL(params, 0);
	deny_mode = SVAL(params, 2);
	open_attr = SVAL(params,6);
        oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
        if (oplock_request) {
                oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;
        }

#if 0
	return_additional_info = BITSETW(params,0);
	open_sattr = SVAL(params, 4);
	open_time = make_unix_date3(params+8);
#endif
	open_ofun = SVAL(params,12);
	open_size = IVAL(params,14);
	pname = &params[28];

	if (IS_IPC(conn)) {
		reply_nterror(req, NT_STATUS_NETWORK_ACCESS_DENIED);
		goto out;
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
			params,
			req->flags2,
			&fname,
			pname,
			total_params - 28,
			STR_TERMINATE,
			&status);
	} else {
		srvstr_get_path(ctx,
			params,
			req->flags2,
			&fname,
			pname,
			total_params - 28,
			STR_TERMINATE,
			&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	DEBUG(3,("call_trans2open %s deny_mode=0x%x attr=%d ofun=0x%x size=%d\n",
		fname, (unsigned int)deny_mode, (unsigned int)open_attr,
		(unsigned int)open_ofun, open_size));

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

	if (open_ofun == 0) {
		reply_nterror(req, NT_STATUS_OBJECT_NAME_COLLISION);
		goto out;
	}

	if (!map_open_params_to_ntcreate(smb_fname->base_name, deny_mode,
					 open_ofun,
					 &access_mask, &share_mode,
					 &create_disposition,
					 &create_options,
					 &private_flags)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	/* Any data in this call is an EA list. */
	if (total_data && (total_data != 4)) {
		if (total_data < 10) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (IVAL(pdata,0) > total_data) {
			DEBUG(10,("call_trans2open: bad total data size (%u) > %u\n",
				IVAL(pdata,0), (unsigned int)total_data));
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		ea_list = read_ea_list(talloc_tos(), pdata + 4,
				       total_data - 4);
		if (!ea_list) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (!lp_ea_support(SNUM(conn))) {
			reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
			goto out;
		}

		if (!req->posix_pathnames &&
				ea_list_has_invalid_name(ea_list)) {
			int param_len = 30;
			*pparams = (char *)SMB_REALLOC(*pparams, param_len);
			if(*pparams == NULL ) {
				reply_nterror(req, NT_STATUS_NO_MEMORY);
				goto out;
			}
			params = *pparams;
			memset(params, '\0', param_len);
			send_trans2_replies(conn, req, STATUS_INVALID_EA_NAME,
				params, param_len, NULL, 0, max_data_bytes);
			goto out;
		}
	}

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_mode,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		open_attr,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		open_size,				/* allocation_size */
		private_flags,
		NULL,					/* sd */
		ea_list,				/* ea_list */
		&fsp,					/* result */
		&smb_action,				/* psbuf */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			goto out;
		}

		if (!NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			reply_openerror(req, status);
			goto out;
		}

		fsp = fcb_or_dos_open(
			req,
			smb_fname,
			access_mask,
			create_options,
			private_flags);
		if (fsp == NULL) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				goto out;
			}
			reply_openerror(req, status);
			goto out;
		}

		smb_action = FILE_WAS_OPENED;
	}

	size = get_file_size_stat(&smb_fname->st);
	fattr = fdos_mode(fsp);
	inode = smb_fname->st.st_ex_ino;
	if (fattr & FILE_ATTRIBUTE_DIRECTORY) {
		close_file_free(req, &fsp, ERROR_CLOSE);
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		goto out;
	}

	/* Realloc the size of parameters and data we will return */
	*pparams = (char *)SMB_REALLOC(*pparams, 30);
	if(*pparams == NULL ) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}
	params = *pparams;

	SSVAL(params,0,fsp->fnum);
	SSVAL(params,2,fattr);
	srv_put_dos_date2_ts(params, 4, smb_fname->st.st_ex_mtime);
	SIVAL(params,8, (uint32_t)size);
	SSVAL(params,12,deny_mode);
	SSVAL(params,14,0); /* open_type - file or directory. */
	SSVAL(params,16,0); /* open_state - only valid for IPC device. */

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		smb_action |= EXTENDED_OPLOCK_GRANTED;
	}

	SSVAL(params,18,smb_action);

	/*
	 * WARNING - this may need to be changed if SMB_INO_T <> 4 bytes.
	 */
	SIVAL(params,20,inode);
	SSVAL(params,24,0); /* Padding. */
	if (flags & 8) {
		uint32_t ea_size = estimate_ea_size(smb_fname->fsp);
		SIVAL(params, 26, ea_size);
	} else {
		SIVAL(params, 26, 0);
	}

	/* Send the required number of replies */
	send_trans2_replies(conn, req, NT_STATUS_OK, params, 30, *ppdata, 0, max_data_bytes);
 out:
	TALLOC_FREE(smb_fname);
}

static NTSTATUS get_lanman2_dir_entry(TALLOC_CTX *ctx,
				connection_struct *conn,
				struct dptr_struct *dirptr,
				uint16_t flags2,
				const char *path_mask,
				uint32_t dirtype,
				int info_level,
				bool requires_resume_key,
				bool dont_descend,
				bool ask_sharemode,
				char **ppdata,
				char *base_data,
				char *end_data,
				int space_remaining,
				int *last_entry_off,
				struct ea_list *name_list)
{
	uint8_t align = 4;
	const bool do_pad = true;

	if (info_level >= 1 && info_level <= 3) {
		/* No alignment on earlier info levels. */
		align = 1;
	}

	return smbd_dirptr_lanman2_entry(ctx, conn, dirptr, flags2,
					 path_mask, dirtype, info_level,
					 requires_resume_key, dont_descend, ask_sharemode,
					 true, align, do_pad,
					 ppdata, base_data, end_data,
					 space_remaining,
					 NULL,
					 last_entry_off, name_list, NULL);
}

/****************************************************************************
 Reply to a TRANS2_FINDFIRST.
****************************************************************************/

static void call_trans2findfirst(connection_struct *conn,
				 struct smb_request *req,
				 char **pparams, int total_params,
				 char **ppdata, int total_data,
				 unsigned int max_data_bytes)
{
	/* We must be careful here that we don't return more than the
		allowed number of data bytes. If this means returning fewer than
		maxentries then so be it. We assume that the redirector has
		enough room for the fixed number of parameter bytes it has
		requested. */
	struct smb_filename *smb_dname = NULL;
	char *params = *pparams;
	char *pdata = *ppdata;
	char *data_end;
	uint32_t dirtype;
	int maxentries;
	uint16_t findfirst_flags;
	bool close_after_first;
	bool close_if_end;
	bool requires_resume_key;
	int info_level;
	char *directory = NULL;
	char *mask = NULL;
	char *p;
	int last_entry_off=0;
	int dptr_num = -1;
	int numentries = 0;
	int i;
	bool finished = False;
	bool dont_descend = False;
	bool out_of_space = False;
	int space_remaining;
	struct ea_list *ea_list = NULL;
	NTSTATUS ntstatus = NT_STATUS_OK;
	bool ask_sharemode;
	struct smbXsrv_connection *xconn = req->xconn;
	struct smbd_server_connection *sconn = req->sconn;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	bool backup_priv = false;
	bool as_root = false;
	files_struct *fsp = NULL;
	struct files_struct *dirfsp = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	if (total_params < 13) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	dirtype = SVAL(params,0);
	maxentries = SVAL(params,2);
	findfirst_flags = SVAL(params,4);
	close_after_first = (findfirst_flags & FLAG_TRANS2_FIND_CLOSE);
	close_if_end = (findfirst_flags & FLAG_TRANS2_FIND_CLOSE_IF_END);
	requires_resume_key = (findfirst_flags & FLAG_TRANS2_FIND_REQUIRE_RESUME);
	backup_priv = ((findfirst_flags & FLAG_TRANS2_FIND_BACKUP_INTENT) &&
				security_token_has_privilege(get_current_nttok(conn),
						SEC_PRIV_BACKUP));

	info_level = SVAL(params,6);

	DBG_NOTICE("dirtype = %"PRIx32", maxentries = %d, "
		   "close_after_first=%d, close_if_end = %d "
		   "requires_resume_key = %d backup_priv = %d level = 0x%x, "
		   "max_data_bytes = %d\n",
		   dirtype,
		   maxentries,
		   close_after_first,
		   close_if_end,
		   requires_resume_key,
		   backup_priv,
		   info_level,
		   max_data_bytes);

	if (!maxentries) {
		/* W2K3 seems to treat zero as 1. */
		maxentries = 1;
	}

	switch (info_level) {
		case SMB_FIND_INFO_STANDARD:
		case SMB_FIND_EA_SIZE:
		case SMB_FIND_EA_LIST:
		case SMB_FIND_FILE_DIRECTORY_INFO:
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		case SMB_FIND_FILE_NAMES_INFO:
		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		case SMB_FIND_ID_FULL_DIRECTORY_INFO:
		case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
			break;
		case SMB_FIND_FILE_UNIX:
		case SMB_FIND_FILE_UNIX_INFO2:
			if (!lp_smb1_unix_extensions()) {
				reply_nterror(req, NT_STATUS_INVALID_LEVEL);
				goto out;
			}
			if (!req->posix_pathnames) {
				reply_nterror(req, NT_STATUS_INVALID_LEVEL);
				goto out;
			}
			break;
		default:
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			goto out;
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(talloc_tos(),
				params,
				req->flags2,
				&directory,
				params+12,
				total_params - 12,
				STR_TERMINATE,
				&ntstatus);
	} else {
		srvstr_get_path(talloc_tos(),
				params,
				req->flags2,
				&directory,
				params+12,
				total_params - 12,
				STR_TERMINATE,
				&ntstatus);
	}
	if (!NT_STATUS_IS_OK(ntstatus)) {
		reply_nterror(req, ntstatus);
		goto out;
	}

	if (backup_priv) {
		become_root();
		as_root = true;
	}
	ntstatus = smb1_strip_dfs_path(talloc_tos(), &ucf_flags, &directory);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		reply_nterror(req, ntstatus);
		goto out;
	}

	ntstatus = filename_convert_smb1_search_path(talloc_tos(),
						     conn,
						     directory,
						     ucf_flags,
						     &dirfsp,
						     &smb_dname,
						     &mask);

	if (!NT_STATUS_IS_OK(ntstatus)) {
		if (NT_STATUS_EQUAL(ntstatus,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req, NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			goto out;
		}
		reply_nterror(req, ntstatus);
		goto out;
	}

	TALLOC_FREE(directory);
	directory = smb_dname->base_name;

	DEBUG(5,("dir=%s, mask = %s\n",directory, mask));

	if (info_level == SMB_FIND_EA_LIST) {
		uint32_t ea_size;

		if (total_data < 4) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		ea_size = IVAL(pdata,0);
		if (ea_size != total_data) {
			DBG_NOTICE("Rejecting EA request with incorrect "
				   "total_data=%d (should be %" PRIu32 ")\n",
				   total_data,
				   ea_size);
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (!lp_ea_support(SNUM(conn))) {
			reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
			goto out;
		}

		/* Pull out the list of names. */
		ea_list = read_ea_name_list(talloc_tos(), pdata + 4, ea_size - 4);
		if (!ea_list) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}
	}

	if (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN < max_data_bytes) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	*ppdata = (char *)SMB_REALLOC(
		*ppdata, max_data_bytes + DIR_ENTRY_SAFETY_MARGIN);
	if(*ppdata == NULL ) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}
	pdata = *ppdata;
	data_end = pdata + max_data_bytes + DIR_ENTRY_SAFETY_MARGIN - 1;
	/*
	 * squash valgrind "writev(vector[...]) points to uninitialised byte(s)"
	 * error.
	 */
	memset(pdata + total_data, 0, ((max_data_bytes + DIR_ENTRY_SAFETY_MARGIN) - total_data));
	/* Realloc the params space */
	*pparams = (char *)SMB_REALLOC(*pparams, 10);
	if (*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}
	params = *pparams;

	/*
	 * Open an fsp on this directory for the dptr.
	 */
	ntstatus = SMB_VFS_CREATE_FILE(
			conn, /* conn */
			req, /* req */
			dirfsp, /* dirfsp */
			smb_dname, /* dname */
			FILE_LIST_DIRECTORY, /* access_mask */
			FILE_SHARE_READ|
			FILE_SHARE_WRITE, /* share_access */
			FILE_OPEN, /* create_disposition*/
			FILE_DIRECTORY_FILE, /* create_options */
			FILE_ATTRIBUTE_DIRECTORY,/* file_attributes */
			NO_OPLOCK, /* oplock_request */
			NULL, /* lease */
			0, /* allocation_size */
			0, /* private_flags */
			NULL, /* sd */
			NULL, /* ea_list */
			&fsp, /* result */
			NULL, /* pinfo */
			NULL, /* in_context */
			NULL);/* out_context */

	if (!NT_STATUS_IS_OK(ntstatus)) {
		DBG_ERR("failed to open directory %s\n",
			smb_fname_str_dbg(smb_dname));
		reply_nterror(req, ntstatus);
		goto out;
	}

	/* Save the wildcard match and attribs we are using on this directory -
		needed as lanman2 assumes these are being saved between calls */

	ntstatus = dptr_create(conn,
				req,
				fsp, /* fsp */
				False,
				mask,
				dirtype,
				&fsp->dptr);

	if (!NT_STATUS_IS_OK(ntstatus)) {
		/*
		 * Use NULL here for the first parameter (req)
		 * as this is not a client visible handle so
		 * can't be part of an SMB1 chain.
		 */
		close_file_free(NULL, &fsp, NORMAL_CLOSE);
		reply_nterror(req, ntstatus);
		goto out;
	}

	if (backup_priv) {
		/* Remember this in case we have
		   to do a findnext. */
		dptr_set_priv(fsp->dptr);
	}

	dptr_num = dptr_dnum(fsp->dptr);
	DEBUG(4,("dptr_num is %d, wcard = %s, attr = %d\n", dptr_num, mask, dirtype));

	/* We don't need to check for VOL here as this is returned by
		a different TRANS2 call. */

	DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
		 directory,lp_dont_descend(talloc_tos(), lp_sub, SNUM(conn))));
	if (in_list(directory,
		    lp_dont_descend(talloc_tos(), lp_sub, SNUM(conn)),
			dptr_case_sensitive(fsp->dptr))) {
		dont_descend = True;
	}

	p = pdata;
	space_remaining = max_data_bytes;
	out_of_space = False;

	ask_sharemode = fsp_search_ask_sharemode(fsp);

	for (i=0;(i<maxentries) && !finished && !out_of_space;i++) {

		ntstatus = get_lanman2_dir_entry(talloc_tos(),
						 conn,
						 fsp->dptr,
						 req->flags2,
						 mask,
						 dirtype,
						 info_level,
						 requires_resume_key,
						 dont_descend,
						 ask_sharemode,
						 &p,
						 pdata,
						 data_end,
						 space_remaining,
						 &last_entry_off,
						 ea_list);
		if (NT_STATUS_EQUAL(ntstatus, NT_STATUS_ILLEGAL_CHARACTER)) {
			/*
			 * Bad character conversion on name. Ignore
			 * this entry.
			 */
			continue;
		}
		if (NT_STATUS_EQUAL(ntstatus, STATUS_MORE_ENTRIES)) {
			out_of_space = true;
		} else {
			finished = !NT_STATUS_IS_OK(ntstatus);
		}

		if (!finished && !out_of_space) {
			numentries++;
		}

		/* Ensure space_remaining never goes -ve. */
		if (PTR_DIFF(p,pdata) > max_data_bytes) {
			space_remaining = 0;
			out_of_space = true;
		} else {
			space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
		}
	}

	/* Check if we can close the dirptr */
	if(close_after_first || (finished && close_if_end)) {
		DEBUG(5,("call_trans2findfirst - (2) closing dptr_num %d\n", dptr_num));
		dptr_num = -1;
		close_file_free(NULL, &fsp, NORMAL_CLOSE);
	}

	/*
	 * If there are no matching entries we must return ERRDOS/ERRbadfile -
	 * from observation of NT. NB. This changes to ERRDOS,ERRnofiles if
	 * the protocol level is less than NT1. Tested with smbclient. JRA.
	 * This should fix the OS/2 client bug #2335.
	 */

	if(numentries == 0) {
		dptr_num = -1;
		/*
		 * We may have already closed the file in the
		 * close_after_first or finished case above.
		 */
		if (fsp != NULL) {
			close_file_free(NULL, &fsp, NORMAL_CLOSE);
		}
		if (xconn->protocol < PROTOCOL_NT1) {
			reply_force_doserror(req, ERRDOS, ERRnofiles);
			goto out;
		} else {
			reply_botherror(req, NT_STATUS_NO_SUCH_FILE,
					ERRDOS, ERRbadfile);
			goto out;
		}
	}

	/* At this point pdata points to numentries directory entries. */

	/* Set up the return parameter block */
	SSVAL(params,0,dptr_num);
	SSVAL(params,2,numentries);
	SSVAL(params,4,finished);
	SSVAL(params,6,0); /* Never an EA error */
	SSVAL(params,8,last_entry_off);

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 10, pdata, PTR_DIFF(p,pdata),
			    max_data_bytes);

	if ((! *directory) && dptr_path(sconn, dptr_num)) {
		directory = talloc_strdup(talloc_tos(),dptr_path(sconn, dptr_num));
		if (!directory) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
		}
	}

	DEBUG( 4, ( "%s mask=%s directory=%s dirtype=%d numentries=%d\n",
		smb_fn_name(req->cmd),
		mask, directory, dirtype, numentries ) );

	/*
	 * Force a name mangle here to ensure that the
	 * mask as an 8.3 name is top of the mangled cache.
	 * The reasons for this are subtle. Don't remove
	 * this code unless you know what you are doing
	 * (see PR#13758). JRA.
	 */

	if(!mangle_is_8_3_wildcards( mask, False, conn->params)) {
		char mangled_name[13];
		name_to_8_3(mask, mangled_name, True, conn->params);
	}
 out:

	if (as_root) {
		unbecome_root();
	}

	TALLOC_FREE(smb_dname);
	return;
}

static bool smbd_dptr_name_equal(struct dptr_struct *dptr,
				 const char *name1,
				 const char *name2)
{
	bool equal;

	if (dptr_case_sensitive(dptr)) {
		equal = (strcmp(name1, name2) == 0);
	} else {
		equal = strequal(name1, name2);
	}

	return equal;
}

/****************************************************************************
 Reply to a TRANS2_FINDNEXT.
****************************************************************************/

static void call_trans2findnext(connection_struct *conn,
				struct smb_request *req,
				char **pparams, int total_params,
				char **ppdata, int total_data,
				unsigned int max_data_bytes)
{
	/* We must be careful here that we don't return more than the
		allowed number of data bytes. If this means returning fewer than
		maxentries then so be it. We assume that the redirector has
		enough room for the fixed number of parameter bytes it has
		requested. */
	char *params = *pparams;
	char *pdata = *ppdata;
	char *data_end;
	int dptr_num;
	int maxentries;
	uint16_t info_level;
	uint32_t resume_key;
	uint16_t findnext_flags;
	bool close_after_request;
	bool close_if_end;
	bool requires_resume_key;
	bool continue_bit;
	char *resume_name = NULL;
	const char *mask = NULL;
	const char *directory = NULL;
	char *p = NULL;
	uint16_t dirtype;
	int numentries = 0;
	int i, last_entry_off=0;
	bool finished = False;
	bool dont_descend = False;
	bool out_of_space = False;
	int space_remaining;
	struct ea_list *ea_list = NULL;
	NTSTATUS ntstatus = NT_STATUS_OK;
	bool ask_sharemode;
	TALLOC_CTX *ctx = talloc_tos();
	struct smbd_server_connection *sconn = req->sconn;
	bool backup_priv = false;
	bool as_root = false;
	files_struct *fsp = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	if (total_params < 13) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	dptr_num = SVAL(params,0);
	maxentries = SVAL(params,2);
	info_level = SVAL(params,4);
	resume_key = IVAL(params,6);
	findnext_flags = SVAL(params,10);
	close_after_request = (findnext_flags & FLAG_TRANS2_FIND_CLOSE);
	close_if_end = (findnext_flags & FLAG_TRANS2_FIND_CLOSE_IF_END);
	requires_resume_key = (findnext_flags & FLAG_TRANS2_FIND_REQUIRE_RESUME);
	continue_bit = (findnext_flags & FLAG_TRANS2_FIND_CONTINUE);

	if (!continue_bit) {
		/* We only need resume_name if continue_bit is zero. */
		if (req->posix_pathnames) {
			srvstr_get_path_posix(ctx,
				params,
				req->flags2,
				&resume_name,
				params+12,
				total_params - 12,
				STR_TERMINATE,
				&ntstatus);
		} else {
			srvstr_get_path(ctx,
				params,
				req->flags2,
				&resume_name,
				params+12,
				total_params - 12,
				STR_TERMINATE,
				&ntstatus);
		}
		if (!NT_STATUS_IS_OK(ntstatus)) {
			/* Win9x or OS/2 can send a resume name of ".." or ".". This will cause the parser to
			   complain (it thinks we're asking for the directory above the shared
			   path or an invalid name). Catch this as the resume name is only compared, never used in
			   a file access. JRA. */
			srvstr_pull_talloc(ctx, params, req->flags2,
				&resume_name, params+12,
				total_params - 12,
				STR_TERMINATE);

			if (!resume_name || !(ISDOT(resume_name) || ISDOTDOT(resume_name))) {
				reply_nterror(req, ntstatus);
				return;
			}
		}
	}

	DBG_NOTICE("dirhandle = %d, max_data_bytes = %u, maxentries = %d, "
		   "close_after_request=%d, close_if_end = %d "
		   "requires_resume_key = %d resume_key = %d "
		   "resume name = %s continue=%d level = %d\n",
		   dptr_num,
		   max_data_bytes,
		   maxentries,
		   close_after_request,
		   close_if_end,
		   requires_resume_key,
		   resume_key,
		   resume_name ? resume_name : "(NULL)",
		   continue_bit,
		   info_level);

	if (!maxentries) {
		/* W2K3 seems to treat zero as 1. */
		maxentries = 1;
	}

	switch (info_level) {
		case SMB_FIND_INFO_STANDARD:
		case SMB_FIND_EA_SIZE:
		case SMB_FIND_EA_LIST:
		case SMB_FIND_FILE_DIRECTORY_INFO:
		case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		case SMB_FIND_FILE_NAMES_INFO:
		case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		case SMB_FIND_ID_FULL_DIRECTORY_INFO:
		case SMB_FIND_ID_BOTH_DIRECTORY_INFO:
			break;
		case SMB_FIND_FILE_UNIX:
		case SMB_FIND_FILE_UNIX_INFO2:
			if (!lp_smb1_unix_extensions()) {
				reply_nterror(req, NT_STATUS_INVALID_LEVEL);
				return;
			}
			if (!req->posix_pathnames) {
				reply_nterror(req, NT_STATUS_INVALID_LEVEL);
				return;
			}
			break;
		default:
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
	}

	if (info_level == SMB_FIND_EA_LIST) {
		uint32_t ea_size;

		if (total_data < 4) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return;
		}

		ea_size = IVAL(pdata,0);
		if (ea_size != total_data) {
			DBG_NOTICE("Rejecting EA request with incorrect "
				   "total_data=%d (should be %" PRIu32 ")\n",
				   total_data,
				   ea_size);
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return;
		}

		if (!lp_ea_support(SNUM(conn))) {
			reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
			return;
		}

		/* Pull out the list of names. */
		ea_list = read_ea_name_list(ctx, pdata + 4, ea_size - 4);
		if (!ea_list) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return;
		}
	}

	if (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN < max_data_bytes) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	*ppdata = (char *)SMB_REALLOC(
		*ppdata, max_data_bytes + DIR_ENTRY_SAFETY_MARGIN);
	if(*ppdata == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	pdata = *ppdata;
	data_end = pdata + max_data_bytes + DIR_ENTRY_SAFETY_MARGIN - 1;

	/*
	 * squash valgrind "writev(vector[...]) points to uninitialised byte(s)"
	 * error.
	 */
	memset(pdata + total_data, 0, (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN) - total_data);
	/* Realloc the params space */
	*pparams = (char *)SMB_REALLOC(*pparams, 6*SIZEOFWORD);
	if(*pparams == NULL ) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	params = *pparams;

	/* Check that the dptr is valid */
	fsp = dptr_fetch_lanman2_fsp(sconn, dptr_num);
	if (fsp == NULL) {
		reply_nterror(req, STATUS_NO_MORE_FILES);
		return;
	}

	directory = dptr_path(sconn, dptr_num);

	/* Get the wildcard mask from the dptr */
	if((mask = dptr_wcard(sconn, dptr_num))== NULL) {
		DEBUG(2,("dptr_num %d has no wildcard\n", dptr_num));
		reply_nterror(req, STATUS_NO_MORE_FILES);
		return;
	}

	/* Get the attr mask from the dptr */
	dirtype = dptr_attr(sconn, dptr_num);

	backup_priv = dptr_get_priv(fsp->dptr);

	DEBUG(3,("dptr_num is %d, mask = %s, attr = %x, dirptr=(0x%lX) "
		"backup_priv = %d\n",
		dptr_num, mask, dirtype,
		(long)fsp->dptr,
		(int)backup_priv));

	/* We don't need to check for VOL here as this is returned by
		a different TRANS2 call. */

	DEBUG(8,("dirpath=<%s> dontdescend=<%s>\n",
		 directory,lp_dont_descend(ctx, lp_sub, SNUM(conn))));
	if (in_list(directory,lp_dont_descend(ctx, lp_sub, SNUM(conn)),
			dptr_case_sensitive(fsp->dptr)))
		dont_descend = True;

	p = pdata;
	space_remaining = max_data_bytes;
	out_of_space = False;

	if (backup_priv) {
		become_root();
		as_root = true;
	}

	/*
	 * Seek to the correct position. We no longer use the resume key but
	 * depend on the last file name instead.
	 */

	if(!continue_bit && resume_name && *resume_name) {
		bool posix_open = fsp->fsp_flags.posix_open;
		char *last_name_sent = NULL;
		bool sequential;

		/*
		 * Remember, name_to_8_3 is called by
		 * get_lanman2_dir_entry(), so the resume name
		 * could be mangled. Ensure we check the unmangled name.
		 */

		if (!posix_open &&
				mangle_is_mangled(resume_name, conn->params)) {
			char *new_resume_name = NULL;
			mangle_lookup_name_from_8_3(ctx,
						resume_name,
						&new_resume_name,
						conn->params);
			if (new_resume_name) {
				resume_name = new_resume_name;
			}
		}

		/*
		 * Fix for NT redirector problem triggered by resume key indexes
		 * changing between directory scans. We now return a resume key of 0
		 * and instead look for the filename to continue from (also given
		 * to us by NT/95/smbfs/smbclient). If no other scans have been done between the
		 * findfirst/findnext (as is usual) then the directory pointer
		 * should already be at the correct place.
		 */

		last_name_sent = smbd_dirptr_get_last_name_sent(fsp->dptr);
		sequential = smbd_dptr_name_equal(fsp->dptr,
						  resume_name,
						  last_name_sent);
		if (!sequential) {
			char *name = NULL;
			bool found = false;

			dptr_RewindDir(fsp->dptr);

			while ((name = dptr_ReadDirName(talloc_tos(),
							fsp->dptr)) != NULL) {
				found = smbd_dptr_name_equal(fsp->dptr,
							     resume_name,
							     name);
				TALLOC_FREE(name);
				if (found) {
					break;
				}
			}

			if (!found) {
				/*
				 * We got a name that used to exist
				 * but does not anymore. Just start
				 * from the beginning. Shown by the
				 * "raw.search.os2 delete" smbtorture
				 * test.
				 */
				dptr_RewindDir(fsp->dptr);
			}
		}
	} /* end if resume_name && !continue_bit */

	ask_sharemode = fsp_search_ask_sharemode(fsp);

	for (i=0;(i<(int)maxentries) && !finished && !out_of_space ;i++) {

		ntstatus = get_lanman2_dir_entry(ctx,
						 conn,
						 fsp->dptr,
						 req->flags2,
						 mask,
						 dirtype,
						 info_level,
						 requires_resume_key,
						 dont_descend,
						 ask_sharemode,
						 &p,
						 pdata,
						 data_end,
						 space_remaining,
						 &last_entry_off,
						 ea_list);
		if (NT_STATUS_EQUAL(ntstatus, NT_STATUS_ILLEGAL_CHARACTER)) {
			/*
			 * Bad character conversion on name. Ignore
			 * this entry.
			 */
			continue;
		}
		if (NT_STATUS_EQUAL(ntstatus, STATUS_MORE_ENTRIES)) {
			out_of_space = true;
		} else {
			finished = !NT_STATUS_IS_OK(ntstatus);
		}

		if (!finished && !out_of_space) {
			numentries++;
		}

		space_remaining = max_data_bytes - PTR_DIFF(p,pdata);
	}

	DEBUG( 3, ( "%s mask=%s directory=%s dirtype=%d numentries=%d\n",
		smb_fn_name(req->cmd),
		mask, directory, dirtype, numentries ) );

	/* Check if we can close the fsp->dptr */
	if(close_after_request || (finished && close_if_end)) {
		DBG_INFO("closing dptr_num = %d\n", dptr_num);
		dptr_num = -1;
		close_file_free(NULL, &fsp, NORMAL_CLOSE);
	}

	if (as_root) {
		unbecome_root();
	}

	/* Set up the return parameter block */
	SSVAL(params,0,numentries);
	SSVAL(params,2,finished);
	SSVAL(params,4,0); /* Never an EA error */
	SSVAL(params,6,last_entry_off);

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 8, pdata, PTR_DIFF(p,pdata),
			    max_data_bytes);

	return;
}

/****************************************************************************
 Reply to a TRANS2_QFSINFO (query filesystem info).
****************************************************************************/

static void call_trans2qfsinfo(connection_struct *conn,
			       struct smb_request *req,
			       char **pparams, int total_params,
			       char **ppdata, int total_data,
			       unsigned int max_data_bytes)
{
	char *params = *pparams;
	uint16_t info_level;
	int data_len = 0;
	size_t fixed_portion;
	NTSTATUS status;

	if (total_params < 2) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	info_level = SVAL(params,0);

	if (ENCRYPTION_REQUIRED(conn) && !req->encrypted) {
		if (info_level != SMB_QUERY_CIFS_UNIX_INFO) {
			DEBUG(0,("call_trans2qfsinfo: encryption required "
				"and info level 0x%x sent.\n",
				(unsigned int)info_level));
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	DEBUG(3,("call_trans2qfsinfo: level = %d\n", info_level));

	status = smbd_do_qfsinfo(req->xconn, conn, req,
				 info_level,
				 req->flags2,
				 max_data_bytes,
				 &fixed_portion,
				 NULL,
				 NULL,
				 ppdata, &data_len);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 0, *ppdata, data_len,
			    max_data_bytes);

	DEBUG( 4, ( "%s info_level = %d\n",
		    smb_fn_name(req->cmd), info_level) );

	return;
}

/****************************************************************************
 Reply to a TRANS2_SETFSINFO (set filesystem info).
****************************************************************************/

static void call_trans2setfsinfo(connection_struct *conn,
				 struct smb_request *req,
				 char **pparams, int total_params,
				 char **ppdata, int total_data,
				 unsigned int max_data_bytes)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *xconn = req->xconn;
	char *pdata = *ppdata;
	char *params = *pparams;
	uint16_t info_level;

	DEBUG(10,("call_trans2setfsinfo: for service [%s]\n",
		  lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));

	/*  */
	if (total_params < 4) {
		DEBUG(0,("call_trans2setfsinfo: requires total_params(%d) >= 4 bytes!\n",
			total_params));
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	info_level = SVAL(params,2);

	if (IS_IPC(conn)) {
		if (info_level != SMB_REQUEST_TRANSPORT_ENCRYPTION &&
				info_level != SMB_SET_CIFS_UNIX_INFO) {
			DEBUG(0,("call_trans2setfsinfo: not an allowed "
				"info level (0x%x) on IPC$.\n",
				(unsigned int)info_level));
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	if (ENCRYPTION_REQUIRED(conn) && !req->encrypted) {
		if (info_level != SMB_REQUEST_TRANSPORT_ENCRYPTION) {
			DEBUG(0,("call_trans2setfsinfo: encryption required "
				"and info level 0x%x sent.\n",
				(unsigned int)info_level));
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	switch(info_level) {
		case SMB_SET_CIFS_UNIX_INFO:
			if (!lp_smb1_unix_extensions()) {
				DEBUG(2,("call_trans2setfsinfo: "
					"SMB_SET_CIFS_UNIX_INFO is invalid with "
					"unix extensions off\n"));
				reply_nterror(req,
					      NT_STATUS_INVALID_LEVEL);
				return;
			}

			/* There should be 12 bytes of capabilities set. */
			if (total_data < 12) {
				reply_nterror(
					req,
					NT_STATUS_INVALID_PARAMETER);
				return;
			}
			xconn->smb1.unix_info.client_major = SVAL(pdata,0);
			xconn->smb1.unix_info.client_minor = SVAL(pdata,2);
			xconn->smb1.unix_info.client_cap_low = IVAL(pdata,4);
			xconn->smb1.unix_info.client_cap_high = IVAL(pdata,8);

			/* Just print these values for now. */
			DBG_DEBUG("set unix_info info. "
				  "major = %"PRIu16", minor = %"PRIu16
				  "cap_low = 0x%"PRIx32", "
				  "cap_high = 0x%"PRIx32"\n",
				  xconn->smb1.unix_info.client_major,
				  xconn->smb1.unix_info.client_minor,
				  xconn->smb1.unix_info.client_cap_low,
				  xconn->smb1.unix_info.client_cap_high);

			/*
			 * Here is where we must switch to posix
			 * pathname processing...
			 */
			if (xconn->smb1.unix_info.client_cap_low &
			    CIFS_UNIX_POSIX_PATHNAMES_CAP)
			{
				lp_set_posix_pathnames();
				mangle_change_to_posix();
			}

			if ((xconn->smb1.unix_info.client_cap_low &
			     CIFS_UNIX_FCNTL_LOCKS_CAP) &&
			    !(xconn->smb1.unix_info.client_cap_low &
			      CIFS_UNIX_POSIX_PATH_OPERATIONS_CAP))
			{
				/* Client that knows how to do posix locks,
				 * but not posix open/mkdir operations. Set a
				 * default type for read/write checks. */

				lp_set_posix_default_cifsx_readwrite_locktype(
					POSIX_LOCK);

			}
			break;

		case SMB_REQUEST_TRANSPORT_ENCRYPTION:
			{
				NTSTATUS status;
				size_t param_len = 0;
				size_t data_len = total_data;

				if (!lp_smb1_unix_extensions()) {
					reply_nterror(
						req,
						NT_STATUS_INVALID_LEVEL);
					return;
				}

				if (lp_server_smb_encrypt(SNUM(conn)) ==
				    SMB_ENCRYPTION_OFF) {
					reply_nterror(
						req,
						NT_STATUS_NOT_SUPPORTED);
					return;
				}

				if (xconn->smb1.echo_handler.trusted_fde) {
					DEBUG( 2,("call_trans2setfsinfo: "
						"request transport encryption disabled"
						"with 'fork echo handler = yes'\n"));
					reply_nterror(
						req,
						NT_STATUS_NOT_SUPPORTED);
					return;
				}

				DEBUG( 4,("call_trans2setfsinfo: "
					"request transport encryption.\n"));

				status = srv_request_encryption_setup(conn,
								(unsigned char **)ppdata,
								&data_len,
								(unsigned char **)pparams,
								&param_len);

				if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
						!NT_STATUS_IS_OK(status)) {
					reply_nterror(req, status);
					return;
				}

				send_trans2_replies(conn, req,
						NT_STATUS_OK,
						*pparams,
						param_len,
						*ppdata,
						data_len,
						max_data_bytes);

				if (NT_STATUS_IS_OK(status)) {
					/* Server-side transport
					 * encryption is now *on*. */
					status = srv_encryption_start(conn);
					if (!NT_STATUS_IS_OK(status)) {
						char *reason = talloc_asprintf(talloc_tos(),
									       "Failure in setting "
									       "up encrypted transport: %s",
									       nt_errstr(status));
						exit_server_cleanly(reason);
					}
				}
				return;
			}

		case SMB_FS_QUOTA_INFORMATION:
			{
				NTSTATUS status;
				DATA_BLOB qdata = {
						.data = (uint8_t *)pdata,
						.length = total_data
				};
				files_struct *fsp = NULL;
				fsp = file_fsp(req, SVAL(params,0));

				status = smb_set_fsquota(conn,
							req,
							fsp,
							&qdata);
				if (!NT_STATUS_IS_OK(status)) {
					reply_nterror(req, status);
					return;
				}
				break;
			}
		default:
			DEBUG(3,("call_trans2setfsinfo: unknown level (0x%X) not implemented yet.\n",
				info_level));
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
			break;
	}

	/*
	 * sending this reply works fine,
	 * but I'm not sure it's the same
	 * like windows do...
	 * --metze
	 */
	reply_smb1_outbuf(req, 10, 0);
}

/****************************************************************************
 Reply to a TRANSACT2_QFILEINFO on a PIPE !
****************************************************************************/

static void call_trans2qpipeinfo(connection_struct *conn,
				 struct smb_request *req,
				 files_struct *fsp,
				 uint16_t info_level,
				 unsigned int tran_call,
				 char **pparams, int total_params,
				 char **ppdata, int total_data,
				 unsigned int max_data_bytes)
{
	char *params = *pparams;
	char *pdata = *ppdata;
	unsigned int data_size = 0;
	unsigned int param_size = 2;

	if (!fsp_is_np(fsp)) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	*pparams = (char *)SMB_REALLOC(*pparams,2);
	if (*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	params = *pparams;
	SSVAL(params,0,0);
	if (max_data_bytes + DIR_ENTRY_SAFETY_MARGIN < max_data_bytes) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	data_size = max_data_bytes + DIR_ENTRY_SAFETY_MARGIN;
	*ppdata = (char *)SMB_REALLOC(*ppdata, data_size);
	if (*ppdata == NULL ) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	pdata = *ppdata;

	switch (info_level) {
		case SMB_FILE_STANDARD_INFORMATION:
			memset(pdata,0,24);
			SOFF_T(pdata,0,4096LL);
			SIVAL(pdata,16,1);
			SIVAL(pdata,20,1);
			data_size = 24;
			break;

		default:
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
	}

	send_trans2_replies(conn, req, NT_STATUS_OK, params, param_size, *ppdata, data_size,
			    max_data_bytes);
}

static void handle_trans2qfilepathinfo_result(
	connection_struct *conn,
	struct smb_request *req,
	uint16_t info_level,
	NTSTATUS status,
	char *pdata,
	int data_return_size,
	size_t fixed_portion,
	unsigned int max_data_bytes)
{
	char params[2] = { 0, 0, };
	int param_size = 2;

	/*
	 * draft-leach-cifs-v1-spec-02.txt
	 * 4.2.14 TRANS2_QUERY_PATH_INFORMATION: Get File Attributes given Path
	 * says:
	 *
	 *  The requested information is placed in the Data portion of the
	 *  transaction response. For the information levels greater than 0x100,
	 *  the transaction response has 1 parameter word which should be
	 *  ignored by the client.
	 *
	 * However Windows only follows this rule for the IS_NAME_VALID call.
	 */
	switch (info_level) {
	case SMB_INFO_IS_NAME_VALID:
		param_size = 0;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		if (open_was_deferred(req->xconn, req->mid)) {
			/* We have re-scheduled this call. */
			return;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			bool ok = defer_smb1_sharing_violation(req);
			if (ok) {
				return;
			}
		}
		reply_nterror(req, status);
		return;
	}

	if (fixed_portion > max_data_bytes) {
		reply_nterror(req, NT_STATUS_INFO_LENGTH_MISMATCH);
		return;
	}

	send_trans2_replies(
		conn,
		req,
		NT_STATUS_OK,
		params,
		param_size,
		pdata,
		data_return_size,
		max_data_bytes);
}

/****************************************************************************
 Reply to a TRANS2_QFILEPATHINFO or TRANSACT2_QFILEINFO (query file info by
 file name or file id).
****************************************************************************/

static void call_trans2qfilepathinfo(connection_struct *conn,
				     struct smb_request *req,
				     unsigned int tran_call,
				     uint16_t info_level,
				     struct smb_filename *smb_fname,
				     struct files_struct *fsp,
				     bool delete_pending,
				     struct timespec write_time_ts,
				     char **pparams, int total_params,
				     char **ppdata, int total_data,
				     unsigned int max_data_bytes)
{
	char *params = *pparams;
	char *pdata = *ppdata;
	unsigned int data_size = 0;
	struct ea_list *ea_list = NULL;
	size_t fixed_portion;
	NTSTATUS status = NT_STATUS_OK;

	DEBUG(3,("call_trans2qfilepathinfo %s (%s) level=%d call=%d "
		 "total_data=%d\n", smb_fname_str_dbg(smb_fname),
		 fsp_fnum_dbg(fsp),
		 info_level,tran_call,total_data));

	/* Pull out any data sent here before we realloc. */
	switch (info_level) {
		case SMB_INFO_QUERY_EAS_FROM_LIST:
		{
			/* Pull any EA list from the data portion. */
			uint32_t ea_size;

			if (total_data < 4) {
				reply_nterror(
					req, NT_STATUS_INVALID_PARAMETER);
				return;
			}
			ea_size = IVAL(pdata,0);

			if (total_data > 0 && ea_size != total_data) {
				DEBUG(4,("call_trans2qfilepathinfo: Rejecting EA request with incorrect \
total_data=%u (should be %u)\n", (unsigned int)total_data, (unsigned int)IVAL(pdata,0) ));
				reply_nterror(
					req, NT_STATUS_INVALID_PARAMETER);
				return;
			}

			if (!lp_ea_support(SNUM(conn))) {
				reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
				return;
			}

			/* Pull out the list of names. */
			ea_list = read_ea_name_list(req, pdata + 4, ea_size - 4);
			if (!ea_list) {
				reply_nterror(
					req, NT_STATUS_INVALID_PARAMETER);
				return;
			}
			break;
		}

		default:
			break;
	}

	*pparams = (char *)SMB_REALLOC(*pparams,2);
	if (*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	params = *pparams;
	SSVAL(params,0,0);

	if ((info_level & SMB2_INFO_SPECIAL) == SMB2_INFO_SPECIAL) {
		/*
		 * We use levels that start with 0xFF00
		 * internally to represent SMB2 specific levels
		 */
		reply_nterror(req, NT_STATUS_INVALID_LEVEL);
		return;
	}

	status = smbd_do_qfilepathinfo(conn, req, req, info_level,
				       fsp, smb_fname,
				       delete_pending, write_time_ts,
				       ea_list,
				       req->flags2, max_data_bytes,
				       &fixed_portion,
				       ppdata, &data_size);

	handle_trans2qfilepathinfo_result(
		conn,
		req,
		info_level,
		status,
		*ppdata,
		data_size,
		fixed_portion,
		max_data_bytes);
}

static NTSTATUS smb_q_unix_basic(
	struct connection_struct *conn,
	struct smb_request *req,
	struct smb_filename *smb_fname,
	struct files_struct *fsp,
	char **ppdata,
	int *ptotal_data)
{
	const int total_data = 100;

	*ppdata = SMB_REALLOC(*ppdata, total_data);
	if (*ppdata == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	store_file_unix_basic(conn, *ppdata, fsp, &smb_fname->st);

	*ptotal_data = total_data;

	return NT_STATUS_OK;
}

static NTSTATUS smb_q_unix_info2(
	struct connection_struct *conn,
	struct smb_request *req,
	struct smb_filename *smb_fname,
	struct files_struct *fsp,
	char **ppdata,
	int *ptotal_data)
{
	const int total_data = 116;

	*ppdata = SMB_REALLOC(*ppdata, total_data);
	if (*ppdata == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	store_file_unix_basic_info2(conn, *ppdata, fsp, &smb_fname->st);

	*ptotal_data = total_data;

	return NT_STATUS_OK;
}

#if defined(HAVE_POSIX_ACLS)
/****************************************************************************
 Utility function to open a fsp for a POSIX handle operation.
****************************************************************************/

static NTSTATUS get_posix_fsp(connection_struct *conn,
			      struct smb_request *req,
			      struct smb_filename *smb_fname,
			      uint32_t access_mask,
			      files_struct **ret_fsp)
{
	NTSTATUS status;
	uint32_t create_disposition = FILE_OPEN;
	uint32_t share_access = FILE_SHARE_READ|
				FILE_SHARE_WRITE|
				FILE_SHARE_DELETE;
	struct smb2_create_blobs *posx = NULL;

	/*
	 * Only FILE_FLAG_POSIX_SEMANTICS matters on existing files,
	 * but set reasonable defaults.
	 */
	uint32_t file_attributes = 0664;
	uint32_t oplock = NO_OPLOCK;
	uint32_t create_options = FILE_NON_DIRECTORY_FILE;

	/* File or directory must exist. */
	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	/* Cannot be a symlink. */
	if (S_ISLNK(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_ACCESS_DENIED;
	}
	/* Set options correctly for directory open. */
	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		/*
		 * Only FILE_FLAG_POSIX_SEMANTICS matters on existing
		 * directories, but set reasonable defaults.
		 */
		file_attributes = 0775;
		create_options = FILE_DIRECTORY_FILE;
	}

	status = make_smb2_posix_create_ctx(
		talloc_tos(), &posx, file_attributes);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
			    nt_errstr(status));
		goto done;
	}

	status = SMB_VFS_CREATE_FILE(
		conn,           /* conn */
		req,            /* req */
		NULL,		/* dirfsp */
		smb_fname,      /* fname */
		access_mask,    /* access_mask */
		share_access,   /* share_access */
		create_disposition,/* create_disposition*/
		create_options, /* create_options */
		file_attributes,/* file_attributes */
		oplock,         /* oplock_request */
		NULL,           /* lease */
		0,              /* allocation_size */
		0,              /* private_flags */
		NULL,           /* sd */
		NULL,           /* ea_list */
		ret_fsp,	/* result */
		NULL,           /* pinfo */
		posx,           /* in_context */
		NULL);          /* out_context */

done:
	TALLOC_FREE(posx);
	return status;
}

/****************************************************************************
 Utility function to count the number of entries in a POSIX acl.
****************************************************************************/

static unsigned int count_acl_entries(connection_struct *conn, SMB_ACL_T posix_acl)
{
	unsigned int ace_count = 0;
	int entry_id = SMB_ACL_FIRST_ENTRY;
	SMB_ACL_ENTRY_T entry;

	while ( posix_acl && (sys_acl_get_entry(posix_acl, entry_id, &entry) == 1)) {
		entry_id = SMB_ACL_NEXT_ENTRY;
		ace_count++;
	}
	return ace_count;
}

/****************************************************************************
 Utility function to marshall a POSIX acl into wire format.
****************************************************************************/

static bool marshall_posix_acl(connection_struct *conn, char *pdata, SMB_STRUCT_STAT *pst, SMB_ACL_T posix_acl)
{
	int entry_id = SMB_ACL_FIRST_ENTRY;
	SMB_ACL_ENTRY_T entry;

	while ( posix_acl && (sys_acl_get_entry(posix_acl, entry_id, &entry) == 1)) {
		SMB_ACL_TAG_T tagtype;
		SMB_ACL_PERMSET_T permset;
		unsigned char perms = 0;
		unsigned int own_grp;

		entry_id = SMB_ACL_NEXT_ENTRY;

		if (sys_acl_get_tag_type(entry, &tagtype) == -1) {
			DEBUG(0,("marshall_posix_acl: SMB_VFS_SYS_ACL_GET_TAG_TYPE failed.\n"));
			return False;
		}

		if (sys_acl_get_permset(entry, &permset) == -1) {
			DEBUG(0,("marshall_posix_acl: SMB_VFS_SYS_ACL_GET_PERMSET failed.\n"));
			return False;
		}

		perms |= (sys_acl_get_perm(permset, SMB_ACL_READ) ? SMB_POSIX_ACL_READ : 0);
		perms |= (sys_acl_get_perm(permset, SMB_ACL_WRITE) ? SMB_POSIX_ACL_WRITE : 0);
		perms |= (sys_acl_get_perm(permset, SMB_ACL_EXECUTE) ? SMB_POSIX_ACL_EXECUTE : 0);

		SCVAL(pdata,1,perms);

		switch (tagtype) {
			case SMB_ACL_USER_OBJ:
				SCVAL(pdata,0,SMB_POSIX_ACL_USER_OBJ);
				own_grp = (unsigned int)pst->st_ex_uid;
				SIVAL(pdata,2,own_grp);
				SIVAL(pdata,6,0);
				break;
			case SMB_ACL_USER:
				{
					uid_t *puid = (uid_t *)sys_acl_get_qualifier(entry);
					if (!puid) {
						DEBUG(0,("marshall_posix_acl: SMB_VFS_SYS_ACL_GET_QUALIFIER failed.\n"));
						return False;
					}
					own_grp = (unsigned int)*puid;
					SCVAL(pdata,0,SMB_POSIX_ACL_USER);
					SIVAL(pdata,2,own_grp);
					SIVAL(pdata,6,0);
					break;
				}
			case SMB_ACL_GROUP_OBJ:
				SCVAL(pdata,0,SMB_POSIX_ACL_GROUP_OBJ);
				own_grp = (unsigned int)pst->st_ex_gid;
				SIVAL(pdata,2,own_grp);
				SIVAL(pdata,6,0);
				break;
			case SMB_ACL_GROUP:
				{
					gid_t *pgid= (gid_t *)sys_acl_get_qualifier(entry);
					if (!pgid) {
						DEBUG(0,("marshall_posix_acl: SMB_VFS_SYS_ACL_GET_QUALIFIER failed.\n"));
						return False;
					}
					own_grp = (unsigned int)*pgid;
					SCVAL(pdata,0,SMB_POSIX_ACL_GROUP);
					SIVAL(pdata,2,own_grp);
					SIVAL(pdata,6,0);
					break;
				}
			case SMB_ACL_MASK:
				SCVAL(pdata,0,SMB_POSIX_ACL_MASK);
				SIVAL(pdata,2,0xFFFFFFFF);
				SIVAL(pdata,6,0xFFFFFFFF);
				break;
			case SMB_ACL_OTHER:
				SCVAL(pdata,0,SMB_POSIX_ACL_OTHER);
				SIVAL(pdata,2,0xFFFFFFFF);
				SIVAL(pdata,6,0xFFFFFFFF);
				break;
			default:
				DEBUG(0,("marshall_posix_acl: unknown tagtype.\n"));
				return False;
		}
		pdata += SMB_POSIX_ACL_ENTRY_SIZE;
	}

	return True;
}
#endif

static NTSTATUS smb_q_posix_acl(
	struct connection_struct *conn,
	struct smb_request *req,
	struct smb_filename *smb_fname,
	struct files_struct *fsp,
	char **ppdata,
	int *ptotal_data)
{
#if !defined(HAVE_POSIX_ACLS)
	return NT_STATUS_INVALID_LEVEL;
#else
	char *pdata = NULL;
	SMB_ACL_T file_acl = NULL;
	SMB_ACL_T def_acl = NULL;
	uint16_t num_file_acls = 0;
	uint16_t num_def_acls = 0;
	unsigned int size_needed = 0;
	NTSTATUS status;
	bool ok;
	bool close_fsp = false;

	/*
	 * Ensure we always operate on a file descriptor, not just
	 * the filename.
	 */
	if (fsp == NULL || !fsp->fsp_flags.is_fsa) {
		uint32_t access_mask = SEC_STD_READ_CONTROL|
					FILE_READ_ATTRIBUTES|
					FILE_WRITE_ATTRIBUTES;

		status = get_posix_fsp(conn,
					req,
					smb_fname,
					access_mask,
					&fsp);

		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		close_fsp = true;
	}

	SMB_ASSERT(fsp != NULL);

	status = refuse_symlink_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	file_acl = SMB_VFS_SYS_ACL_GET_FD(fsp, SMB_ACL_TYPE_ACCESS,
					talloc_tos());

	if (file_acl == NULL && no_acl_syscall_error(errno)) {
		DBG_INFO("ACLs not implemented on "
			"filesystem containing %s\n",
			fsp_str_dbg(fsp));
		status = NT_STATUS_NOT_IMPLEMENTED;
		goto out;
	}

	if (S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		/*
		 * We can only have default POSIX ACLs on
		 * directories.
		 */
		if (!fsp->fsp_flags.is_directory) {
			DBG_INFO("Non-directory open %s\n",
				fsp_str_dbg(fsp));
			status = NT_STATUS_INVALID_HANDLE;
			goto out;
		}
		def_acl = SMB_VFS_SYS_ACL_GET_FD(fsp,
					SMB_ACL_TYPE_DEFAULT,
					talloc_tos());
		def_acl = free_empty_sys_acl(conn, def_acl);
	}

	num_file_acls = count_acl_entries(conn, file_acl);
	num_def_acls = count_acl_entries(conn, def_acl);

	/* Wrap checks. */
	if (num_file_acls + num_def_acls < num_file_acls) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	size_needed = num_file_acls + num_def_acls;

	/*
	 * (size_needed * SMB_POSIX_ACL_ENTRY_SIZE) must be less
	 * than UINT_MAX, so check by division.
	 */
	if (size_needed > (UINT_MAX/SMB_POSIX_ACL_ENTRY_SIZE)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	size_needed = size_needed*SMB_POSIX_ACL_ENTRY_SIZE;
	if (size_needed + SMB_POSIX_ACL_HEADER_SIZE < size_needed) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	size_needed += SMB_POSIX_ACL_HEADER_SIZE;

	*ppdata = SMB_REALLOC(*ppdata, size_needed);
	if (*ppdata == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	pdata = *ppdata;

	SSVAL(pdata,0,SMB_POSIX_ACL_VERSION);
	SSVAL(pdata,2,num_file_acls);
	SSVAL(pdata,4,num_def_acls);
	pdata += SMB_POSIX_ACL_HEADER_SIZE;

	ok = marshall_posix_acl(conn,
			pdata,
			&fsp->fsp_name->st,
			file_acl);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}
	pdata += (num_file_acls*SMB_POSIX_ACL_ENTRY_SIZE);

	ok = marshall_posix_acl(conn,
			pdata,
			&fsp->fsp_name->st,
			def_acl);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	*ptotal_data = size_needed;
	status = NT_STATUS_OK;

  out:

	if (close_fsp) {
		/*
		 * Ensure the stat struct in smb_fname is up to
		 * date. Structure copy.
		 */
		smb_fname->st = fsp->fsp_name->st;
		(void)close_file_free(req, &fsp, NORMAL_CLOSE);
	}

	TALLOC_FREE(file_acl);
	TALLOC_FREE(def_acl);
	return status;
#endif
}

static NTSTATUS smb_q_posix_symlink(
	struct connection_struct *conn,
	struct smb_request *req,
	struct files_struct *dirfsp,
	struct smb_filename *smb_fname,
	char **ppdata,
	int *ptotal_data)
{
	char *target = NULL;
	size_t needed, len;
	char *pdata = NULL;
	NTSTATUS status;

	DBG_DEBUG("SMB_QUERY_FILE_UNIX_LINK for file %s\n",
		  smb_fname_str_dbg(smb_fname));

	if (!S_ISLNK(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_DOS(ERRSRV, ERRbadlink);
	}

	if (fsp_get_pathref_fd(smb_fname->fsp) != -1) {
		/*
		 * fsp is an O_PATH open, Linux does a "freadlink"
		 * with an empty name argument to readlinkat
		 */
		status = readlink_talloc(talloc_tos(),
					 smb_fname->fsp,
					 NULL,
					 &target);
	} else {
		struct smb_filename smb_fname_rel = *smb_fname;
		char *slash = NULL;

		slash = strrchr_m(smb_fname->base_name, '/');
		if (slash != NULL) {
			smb_fname_rel.base_name = slash + 1;
		}
		status = readlink_talloc(talloc_tos(),
					 dirfsp,
					 &smb_fname_rel,
					 &target);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("readlink_talloc() failed: %s\n", nt_errstr(status));
		return status;
	}

	needed = talloc_get_size(target) * 2;

	*ppdata = SMB_REALLOC(*ppdata, needed);
	if (*ppdata == NULL) {
		TALLOC_FREE(target);
		return NT_STATUS_NO_MEMORY;
	}
	pdata = *ppdata;

	status = srvstr_push(
		pdata,
		req->flags2,
		pdata,
		target,
		needed,
		STR_TERMINATE,
		&len);
	TALLOC_FREE(target);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*ptotal_data = len;

	return NT_STATUS_OK;
}

static void call_trans2qpathinfo(
	connection_struct *conn,
	struct smb_request *req,
	char **pparams,
	int total_params,
	char **ppdata,
	int total_data,
	unsigned int max_data_bytes)
{
	char *params = *pparams;
	uint16_t info_level;
	struct smb_filename *smb_fname = NULL;
	bool delete_pending = False;
	struct timespec write_time_ts = { .tv_sec = 0, };
	struct files_struct *dirfsp = NULL;
	files_struct *fsp = NULL;
	char *fname = NULL;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	bool info_level_handled;
	NTSTATUS status = NT_STATUS_OK;

	if (!params) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}


	/* qpathinfo */
	if (total_params < 7) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	info_level = SVAL(params,0);

	DBG_NOTICE("TRANSACT2_QPATHINFO: level = %d\n", info_level);

	if (INFO_LEVEL_IS_UNIX(info_level)) {
		if (!lp_smb1_unix_extensions()) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
		if (!req->posix_pathnames) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(req,
				      params,
				      req->flags2,
				      &fname,
				      &params[6],
				      total_params - 6,
				      STR_TERMINATE,
				      &status);
	} else {
		srvstr_get_path(req,
				params,
				req->flags2,
				&fname,
				&params[6],
				total_params - 6,
				STR_TERMINATE,
				&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(req, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}
	status = filename_convert_dirfsp(req,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			return;
		}
		reply_nterror(req, status);
		return;
	}

	/*
	 * qpathinfo must operate on an existing file, so we
	 * can exit early if filename_convert_dirfsp() returned the
	 * "new file" NT_STATUS_OK, !VALID_STAT case.
	 */

	if (!VALID_STAT(smb_fname->st)) {
		reply_nterror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	fsp = smb_fname->fsp;

	/* If this is a stream, check if there is a delete_pending. */
	if (fsp_is_alternate_stream(fsp)) {

		struct files_struct *base_fsp = fsp->base_fsp;

		get_file_infos(base_fsp->file_id,
			       base_fsp->name_hash,
			       &delete_pending,
			       NULL);
		if (delete_pending) {
			reply_nterror(req, NT_STATUS_DELETE_PENDING);
			return;
		}
	}

	if (fsp_getinfo_ask_sharemode(fsp)) {
		get_file_infos(fsp->file_id,
			       fsp->name_hash,
			       &delete_pending,
			       &write_time_ts);
	}

	if (delete_pending) {
		reply_nterror(req, NT_STATUS_DELETE_PENDING);
		return;
	}

	info_level_handled = true; /* Untouched in switch cases below */

	switch (info_level) {

	default:
		info_level_handled = false;
		break;

	case SMB_QUERY_FILE_UNIX_BASIC:
		status = smb_q_unix_basic(
			conn,
			req,
			smb_fname,
			smb_fname->fsp,
			ppdata,
			&total_data);
		break;

	case SMB_QUERY_FILE_UNIX_INFO2:
		status = smb_q_unix_info2(
			conn,
			req,
			smb_fname,
			smb_fname->fsp,
			ppdata,
			&total_data);
		break;

	case SMB_QUERY_POSIX_ACL:
		status = smb_q_posix_acl(
			conn,
			req,
			smb_fname,
			smb_fname->fsp,
			ppdata,
			&total_data);
		break;

	case SMB_QUERY_FILE_UNIX_LINK:
		status = smb_q_posix_symlink(
			conn,
			req,
			dirfsp,
			smb_fname,
			ppdata,
			&total_data);
		break;
	}

	if (info_level_handled) {
		handle_trans2qfilepathinfo_result(
			conn,
			req,
			info_level,
			status,
			*ppdata,
			total_data,
			total_data,
			max_data_bytes);
		return;
	}

	call_trans2qfilepathinfo(
		conn,
		req,
		TRANSACT2_QPATHINFO,
		info_level,
		smb_fname,
		fsp,
		false,
		write_time_ts,
		pparams,
		total_params,
		ppdata,
		total_data,
		max_data_bytes);
}

static NTSTATUS smb_q_posix_lock(
	struct connection_struct *conn,
	struct smb_request *req,
	struct files_struct *fsp,
	char **ppdata,
	int *ptotal_data)
{
	char *pdata = *ppdata;
	int total_data = *ptotal_data;
	uint64_t count;
	uint64_t offset;
	uint64_t smblctx;
	enum brl_type lock_type;
	NTSTATUS status;

	if (fsp->fsp_flags.is_pathref || (fsp_get_io_fd(fsp) == -1)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (total_data != POSIX_LOCK_DATA_SIZE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (SVAL(pdata, POSIX_LOCK_TYPE_OFFSET)) {
	case POSIX_LOCK_TYPE_READ:
		lock_type = READ_LOCK;
		break;
	case POSIX_LOCK_TYPE_WRITE:
		lock_type = WRITE_LOCK;
		break;
	case POSIX_LOCK_TYPE_UNLOCK:
	default:
		/* There's no point in asking for an unlock... */
		return NT_STATUS_INVALID_PARAMETER;
	}

	smblctx = (uint64_t)IVAL(pdata, POSIX_LOCK_PID_OFFSET);
	offset = BVAL(pdata,POSIX_LOCK_START_OFFSET);
	count = BVAL(pdata,POSIX_LOCK_LEN_OFFSET);

	status = query_lock(
		fsp,
		&smblctx,
		&count,
		&offset,
		&lock_type,
		POSIX_LOCK);

	if (NT_STATUS_IS_OK(status)) {
		/*
		 * For success we just return a copy of what we sent
		 * with the lock type set to POSIX_LOCK_TYPE_UNLOCK.
		 */
		SSVAL(pdata, POSIX_LOCK_TYPE_OFFSET, POSIX_LOCK_TYPE_UNLOCK);
		return NT_STATUS_OK;
	}

	if (!ERROR_WAS_LOCK_DENIED(status)) {
		DBG_DEBUG("query_lock() failed: %s\n", nt_errstr(status));
		return status;
	}

	/*
	 * Here we need to report who has it locked.
	 */

	SSVAL(pdata, POSIX_LOCK_TYPE_OFFSET, lock_type);
	SSVAL(pdata, POSIX_LOCK_FLAGS_OFFSET, 0);
	SIVAL(pdata, POSIX_LOCK_PID_OFFSET, (uint32_t)smblctx);
	SBVAL(pdata, POSIX_LOCK_START_OFFSET, offset);
	SBVAL(pdata, POSIX_LOCK_LEN_OFFSET, count);

	return NT_STATUS_OK;
}

static void call_trans2qfileinfo(
	connection_struct *conn,
	struct smb_request *req,
	char **pparams,
	int total_params,
	char **ppdata,
	int total_data,
	unsigned int max_data_bytes)
{
	char *params = *pparams;
	uint16_t info_level;
	struct smb_filename *smb_fname = NULL;
	bool delete_pending = False;
	struct timespec write_time_ts = { .tv_sec = 0, };
	files_struct *fsp = NULL;
	struct file_id fileid;
	bool info_level_handled;
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	if (params == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (total_params < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(params,0));
	info_level = SVAL(params,2);

	if (IS_IPC(conn)) {
		call_trans2qpipeinfo(
			conn,
			req,
			fsp,
			info_level,
			TRANSACT2_QFILEINFO,
			pparams,
			total_params,
			ppdata,
			total_data,
			max_data_bytes);
		return;
	}

	DBG_NOTICE("TRANSACT2_QFILEINFO: level = %d\n", info_level);

	if (INFO_LEVEL_IS_UNIX(info_level)) {
		if (!lp_smb1_unix_extensions()) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
		if (!req->posix_pathnames) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
	}

	/* Initial check for valid fsp ptr. */
	if (!check_fsp_open(conn, req, fsp)) {
		return;
	}

	smb_fname = fsp->fsp_name;

	if(fsp->fake_file_handle) {
		/*
		 * This is actually for the QUOTA_FAKE_FILE --metze
		 */

		/* We know this name is ok, it's already passed the checks. */

	} else if(fsp_get_pathref_fd(fsp) == -1) {
		/*
		 * This is actually a QFILEINFO on a directory
		 * handle (returned from an NT SMB). NT5.0 seems
		 * to do this call. JRA.
		 */
		ret = vfs_stat(conn, smb_fname);
		if (ret != 0) {
			DBG_NOTICE("vfs_stat of %s failed (%s)\n",
				   smb_fname_str_dbg(smb_fname),
				   strerror(errno));
			reply_nterror(req,
				      map_nt_error_from_unix(errno));
			return;
		}

		if (fsp_getinfo_ask_sharemode(fsp)) {
			fileid = vfs_file_id_from_sbuf(
				conn, &smb_fname->st);
			get_file_infos(fileid, fsp->name_hash,
				       &delete_pending,
				       &write_time_ts);
		}
	} else {
		/*
		 * Original code - this is an open file.
		 */
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("fstat of %s failed (%s)\n",
				  fsp_fnum_dbg(fsp), nt_errstr(status)));
			reply_nterror(req, status);
			return;
		}
		if (fsp_getinfo_ask_sharemode(fsp)) {
			fileid = vfs_file_id_from_sbuf(
				conn, &smb_fname->st);
			get_file_infos(fileid, fsp->name_hash,
				       &delete_pending,
				       &write_time_ts);
		}
	}

	info_level_handled = true; /* Untouched in switch cases below */

	switch (info_level) {

	default:
		info_level_handled = false;
		break;

	case SMB_QUERY_POSIX_LOCK:
		status = smb_q_posix_lock(conn, req, fsp, ppdata, &total_data);
		break;

	case SMB_QUERY_FILE_UNIX_BASIC:
		status = smb_q_unix_basic(
			conn, req, fsp->fsp_name, fsp, ppdata, &total_data);
		break;

	case SMB_QUERY_FILE_UNIX_INFO2:
		status = smb_q_unix_info2(
			conn, req, fsp->fsp_name, fsp, ppdata, &total_data);
		break;

	case SMB_QUERY_POSIX_ACL:
		status = smb_q_posix_acl(
			conn, req, fsp->fsp_name, fsp, ppdata, &total_data);
		break;
	}

	if (info_level_handled) {
		handle_trans2qfilepathinfo_result(
			conn,
			req,
			info_level,
			status,
			*ppdata,
			total_data,
			total_data,
			max_data_bytes);
		return;
	}

	call_trans2qfilepathinfo(
		conn,
		req,
		TRANSACT2_QFILEINFO,
		info_level,
		smb_fname,
		fsp,
		delete_pending,
		write_time_ts,
		pparams,
		total_params,
		ppdata,
		total_data,
		max_data_bytes);
}

static void handle_trans2setfilepathinfo_result(
	connection_struct *conn,
	struct smb_request *req,
	uint16_t info_level,
	NTSTATUS status,
	char *pdata,
	int data_return_size,
	unsigned int max_data_bytes)
{
	char params[2] = { 0, 0, };

	if (NT_STATUS_IS_OK(status)) {
		send_trans2_replies(
			conn,
			req,
			NT_STATUS_OK,
			params,
			2,
			pdata,
			data_return_size,
			max_data_bytes);
		return;
	}

	if (open_was_deferred(req->xconn, req->mid)) {
		/* We have re-scheduled this call. */
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		bool ok = defer_smb1_sharing_violation(req);
		if (ok) {
			return;
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_EVENT_PENDING)) {
		/* We have re-scheduled this call. */
		return;
	}

	if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
		reply_botherror(
			req,
			NT_STATUS_PATH_NOT_COVERED,
			ERRSRV,
			ERRbadpath);
		return;
	}

	if (info_level == SMB_POSIX_PATH_OPEN) {
		reply_openerror(req, status);
		return;
	}

	if (NT_STATUS_EQUAL(status, STATUS_INVALID_EA_NAME)) {
		/*
		 * Invalid EA name needs to return 2 param bytes,
		 * not a zero-length error packet.
		 */

		send_trans2_replies(
			conn,
			req,
			status,
			params,
			2,
			NULL,
			0,
			max_data_bytes);
		return;
	}

	reply_nterror(req, status);
}

/****************************************************************************
 Create a directory with POSIX semantics.
****************************************************************************/

static NTSTATUS smb_posix_mkdir(connection_struct *conn,
				struct smb_request *req,
				char **ppdata,
				int total_data,
				struct smb_filename *smb_fname,
				int *pdata_return_size)
{
	NTSTATUS status = NT_STATUS_OK;
	uint32_t raw_unixmode = 0;
	mode_t unixmode = (mode_t)0;
	files_struct *fsp = NULL;
	uint16_t info_level_return = 0;
	int info;
	char *pdata = *ppdata;
	struct smb2_create_blobs *posx = NULL;

	if (total_data < 18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	raw_unixmode = IVAL(pdata,8);
	/* Next 4 bytes are not yet defined. */

	status = unix_perms_from_wire(conn,
				      &smb_fname->st,
				      raw_unixmode,
				      &unixmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	unixmode = apply_conf_dir_mask(conn, unixmode);

	status = make_smb2_posix_create_ctx(talloc_tos(), &posx, unixmode);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	DEBUG(10,("smb_posix_mkdir: file %s, mode 0%o\n",
		  smb_fname_str_dbg(smb_fname), (unsigned int)unixmode));

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		NULL,					/* dirfsp */
		smb_fname,				/* fname */
		FILE_READ_ATTRIBUTES,			/* access_mask */
		FILE_SHARE_NONE,			/* share_access */
		FILE_CREATE,				/* create_disposition*/
		FILE_DIRECTORY_FILE,			/* create_options */
		0,					/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		posx,					/* in_context_blobs */
		NULL);					/* out_context_blobs */

	TALLOC_FREE(posx);

        if (NT_STATUS_IS_OK(status)) {
                close_file_free(req, &fsp, NORMAL_CLOSE);
        }

	info_level_return = SVAL(pdata,16);

	if (info_level_return == SMB_QUERY_FILE_UNIX_BASIC) {
		*pdata_return_size = 12 + SMB_FILE_UNIX_BASIC_SIZE;
	} else if (info_level_return ==  SMB_QUERY_FILE_UNIX_INFO2) {
		*pdata_return_size = 12 + SMB_FILE_UNIX_INFO2_SIZE;
	} else {
		*pdata_return_size = 12;
	}

	/* Realloc the data size */
	*ppdata = (char *)SMB_REALLOC(*ppdata,*pdata_return_size);
	if (*ppdata == NULL) {
		*pdata_return_size = 0;
		return NT_STATUS_NO_MEMORY;
	}
	pdata = *ppdata;

	SSVAL(pdata,0,NO_OPLOCK_RETURN);
	SSVAL(pdata,2,0); /* No fnum. */
	SIVAL(pdata,4,info); /* Was directory created. */

	switch (info_level_return) {
		case SMB_QUERY_FILE_UNIX_BASIC:
			SSVAL(pdata,8,SMB_QUERY_FILE_UNIX_BASIC);
			SSVAL(pdata,10,0); /* Padding. */
			store_file_unix_basic(conn, pdata + 12, fsp,
					      &smb_fname->st);
			break;
		case SMB_QUERY_FILE_UNIX_INFO2:
			SSVAL(pdata,8,SMB_QUERY_FILE_UNIX_INFO2);
			SSVAL(pdata,10,0); /* Padding. */
			store_file_unix_basic_info2(conn, pdata + 12, fsp,
						    &smb_fname->st);
			break;
		default:
			SSVAL(pdata,8,SMB_NO_INFO_LEVEL_RETURNED);
			SSVAL(pdata,10,0); /* Padding. */
			break;
	}

	return status;
}

/****************************************************************************
 Open/Create a file with POSIX semantics.
****************************************************************************/

#define SMB_O_RDONLY_MAPPING (FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA)
#define SMB_O_WRONLY_MAPPING (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA)

static NTSTATUS smb_posix_open(connection_struct *conn,
			       struct smb_request *req,
			       char **ppdata,
			       int total_data,
			       struct files_struct *dirfsp,
			       struct smb_filename *smb_fname,
			       int *pdata_return_size)
{
	bool extended_oplock_granted = False;
	char *pdata = *ppdata;
	uint32_t flags = 0;
	uint32_t wire_open_mode = 0;
	uint32_t raw_unixmode = 0;
	uint32_t attributes = 0;
	uint32_t create_disp = 0;
	uint32_t access_mask = 0;
	uint32_t create_options = FILE_NON_DIRECTORY_FILE;
	NTSTATUS status = NT_STATUS_OK;
	mode_t unixmode = (mode_t)0;
	files_struct *fsp = NULL;
	int oplock_request = 0;
	int info = 0;
	uint16_t info_level_return = 0;
	struct smb2_create_blobs *posx = NULL;

	if (total_data < 18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	flags = IVAL(pdata,0);
	oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
	if (oplock_request) {
		oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;
	}

	wire_open_mode = IVAL(pdata,4);

	if (wire_open_mode == (SMB_O_CREAT|SMB_O_DIRECTORY)) {
		return smb_posix_mkdir(conn, req,
					ppdata,
					total_data,
					smb_fname,
					pdata_return_size);
	}

	switch (wire_open_mode & SMB_ACCMODE) {
		case SMB_O_RDONLY:
			access_mask = SMB_O_RDONLY_MAPPING;
			break;
		case SMB_O_WRONLY:
			access_mask = SMB_O_WRONLY_MAPPING;
			break;
		case SMB_O_RDWR:
			access_mask = (SMB_O_RDONLY_MAPPING|
					SMB_O_WRONLY_MAPPING);
			break;
		default:
			DEBUG(5,("smb_posix_open: invalid open mode 0x%x\n",
				(unsigned int)wire_open_mode ));
			return NT_STATUS_INVALID_PARAMETER;
	}

	wire_open_mode &= ~SMB_ACCMODE;

	/* First take care of O_CREAT|O_EXCL interactions. */
	switch (wire_open_mode & (SMB_O_CREAT | SMB_O_EXCL)) {
		case (SMB_O_CREAT | SMB_O_EXCL):
			/* File exists fail. File not exist create. */
			create_disp = FILE_CREATE;
			break;
		case SMB_O_CREAT:
			/* File exists open. File not exist create. */
			create_disp = FILE_OPEN_IF;
			break;
		case SMB_O_EXCL:
			/* O_EXCL on its own without O_CREAT is undefined.
			   We deliberately ignore it as some versions of
			   Linux CIFSFS can send a bare O_EXCL on the
			   wire which other filesystems in the kernel
			   ignore. See bug 9519 for details. */

			/* Fallthrough. */

		case 0:
			/* File exists open. File not exist fail. */
			create_disp = FILE_OPEN;
			break;
		default:
			DEBUG(5,("smb_posix_open: invalid create mode 0x%x\n",
				(unsigned int)wire_open_mode ));
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* Next factor in the effects of O_TRUNC. */
	wire_open_mode &= ~(SMB_O_CREAT | SMB_O_EXCL);

	if (wire_open_mode & SMB_O_TRUNC) {
		switch (create_disp) {
			case FILE_CREATE:
				/* (SMB_O_CREAT | SMB_O_EXCL | O_TRUNC) */
				/* Leave create_disp alone as
				   (O_CREAT|O_EXCL|O_TRUNC) == (O_CREAT|O_EXCL)
				*/
				/* File exists fail. File not exist create. */
				break;
			case FILE_OPEN_IF:
				/* SMB_O_CREAT | SMB_O_TRUNC */
				/* File exists overwrite. File not exist create. */
				create_disp = FILE_OVERWRITE_IF;
				break;
			case FILE_OPEN:
				/* SMB_O_TRUNC */
				/* File exists overwrite. File not exist fail. */
				create_disp = FILE_OVERWRITE;
				break;
			default:
				/* Cannot get here. */
				smb_panic("smb_posix_open: logic error");
				return NT_STATUS_INVALID_PARAMETER;
		}
	}

	raw_unixmode = IVAL(pdata,8);
	/* Next 4 bytes are not yet defined. */

	status = unix_perms_from_wire(conn,
				      &smb_fname->st,
				      raw_unixmode,
				      &unixmode);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!VALID_STAT(smb_fname->st)) {
		unixmode = apply_conf_dir_mask(conn, unixmode);
	}

	status = make_smb2_posix_create_ctx(talloc_tos(), &posx, unixmode);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
			    nt_errstr(status));
		return status;
	}

	if (wire_open_mode & SMB_O_SYNC) {
		create_options |= FILE_WRITE_THROUGH;
	}
	if (wire_open_mode & SMB_O_APPEND) {
		access_mask |= FILE_APPEND_DATA;
	}
	if (wire_open_mode & SMB_O_DIRECT) {
		/*
		 * BUG: this doesn't work anymore since
		 * e0814dc5082dd4ecca8a155e0ce24b073158fd92. But since
		 * FILE_FLAG_NO_BUFFERING isn't used at all in the IO codepath,
		 * it doesn't really matter.
		 */
		attributes |= FILE_FLAG_NO_BUFFERING;
	}

	if ((wire_open_mode & SMB_O_DIRECTORY) ||
			VALID_STAT_OF_DIR(smb_fname->st)) {
		if (access_mask != SMB_O_RDONLY_MAPPING) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		create_options &= ~FILE_NON_DIRECTORY_FILE;
		create_options |= FILE_DIRECTORY_FILE;
	}

	DEBUG(10,("smb_posix_open: file %s, smb_posix_flags = %u, mode 0%o\n",
		smb_fname_str_dbg(smb_fname),
		(unsigned int)wire_open_mode,
		(unsigned int)unixmode ));

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		create_disp,				/* create_disposition*/
		create_options,				/* create_options */
		attributes,				/* file_attributes */
		oplock_request,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		posx,					/* in_context_blobs */
		NULL);					/* out_context_blobs */

	TALLOC_FREE(posx);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (oplock_request && lp_fake_oplocks(SNUM(conn))) {
		extended_oplock_granted = True;
	}

	if(oplock_request && EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		extended_oplock_granted = True;
	}

	info_level_return = SVAL(pdata,16);

	/* Allocate the correct return size. */

	if (info_level_return == SMB_QUERY_FILE_UNIX_BASIC) {
		*pdata_return_size = 12 + SMB_FILE_UNIX_BASIC_SIZE;
	} else if (info_level_return ==  SMB_QUERY_FILE_UNIX_INFO2) {
		*pdata_return_size = 12 + SMB_FILE_UNIX_INFO2_SIZE;
	} else {
		*pdata_return_size = 12;
	}

	/* Realloc the data size */
	*ppdata = (char *)SMB_REALLOC(*ppdata,*pdata_return_size);
	if (*ppdata == NULL) {
		close_file_free(req, &fsp, ERROR_CLOSE);
		*pdata_return_size = 0;
		return NT_STATUS_NO_MEMORY;
	}
	pdata = *ppdata;

	if (extended_oplock_granted) {
		if (flags & REQUEST_BATCH_OPLOCK) {
			SSVAL(pdata,0, BATCH_OPLOCK_RETURN);
		} else {
			SSVAL(pdata,0, EXCLUSIVE_OPLOCK_RETURN);
		}
	} else if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		SSVAL(pdata,0, LEVEL_II_OPLOCK_RETURN);
	} else {
		SSVAL(pdata,0,NO_OPLOCK_RETURN);
	}

	SSVAL(pdata,2,fsp->fnum);
	SIVAL(pdata,4,info); /* Was file created etc. */

	switch (info_level_return) {
		case SMB_QUERY_FILE_UNIX_BASIC:
			SSVAL(pdata,8,SMB_QUERY_FILE_UNIX_BASIC);
			SSVAL(pdata,10,0); /* padding. */
			store_file_unix_basic(conn, pdata + 12, fsp,
					      &smb_fname->st);
			break;
		case SMB_QUERY_FILE_UNIX_INFO2:
			SSVAL(pdata,8,SMB_QUERY_FILE_UNIX_INFO2);
			SSVAL(pdata,10,0); /* padding. */
			store_file_unix_basic_info2(conn, pdata + 12, fsp,
						    &smb_fname->st);
			break;
		default:
			SSVAL(pdata,8,SMB_NO_INFO_LEVEL_RETURNED);
			SSVAL(pdata,10,0); /* padding. */
			break;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Delete a file with POSIX semantics.
****************************************************************************/

struct smb_posix_unlink_state {
	struct smb_filename *smb_fname;
	struct files_struct *fsp;
	NTSTATUS status;
};

static void smb_posix_unlink_locked(struct share_mode_lock *lck,
				    void *private_data)
{
	struct smb_posix_unlink_state *state = private_data;
	char del = 1;
	bool other_nonposix_opens;

	other_nonposix_opens = has_other_nonposix_opens(lck, state->fsp);
	if (other_nonposix_opens) {
		/* Fail with sharing violation. */
		state->status = NT_STATUS_SHARING_VIOLATION;
		return;
	}

	/*
	 * Set the delete on close.
	 */
	state->status = smb_set_file_disposition_info(state->fsp->conn,
						      &del,
						      1,
						      state->fsp,
						      state->smb_fname);
}

static NTSTATUS smb_posix_unlink(connection_struct *conn,
				 struct smb_request *req,
				 const char *pdata,
				 int total_data,
				 struct files_struct *dirfsp,
				 struct smb_filename *smb_fname)
{
	struct smb_posix_unlink_state state = {};
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp = NULL;
	uint16_t flags = 0;
	int info = 0;
	int create_options = FILE_OPEN_REPARSE_POINT;
	struct smb2_create_blobs *posx = NULL;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	if (total_data < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	flags = SVAL(pdata,0);

	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if ((flags == SMB_POSIX_UNLINK_DIRECTORY_TARGET) &&
			!VALID_STAT_OF_DIR(smb_fname->st)) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	DEBUG(10,("smb_posix_unlink: %s %s\n",
		(flags == SMB_POSIX_UNLINK_DIRECTORY_TARGET) ? "directory" : "file",
		smb_fname_str_dbg(smb_fname)));

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		create_options |= FILE_DIRECTORY_FILE;
	}

	status = make_smb2_posix_create_ctx(talloc_tos(), &posx, 0777);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("make_smb2_posix_create_ctx failed: %s\n",
			    nt_errstr(status));
		return status;
	}

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_fname,				/* fname */
		DELETE_ACCESS,				/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		create_options,				/* create_options */
		0,					/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		&info,					/* pinfo */
		posx,					/* in_context_blobs */
		NULL);					/* out_context_blobs */

	TALLOC_FREE(posx);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Don't lie to client. If we can't really delete due to
	 * non-POSIX opens return SHARING_VIOLATION.
	 */

	state = (struct smb_posix_unlink_state) {
		.smb_fname = smb_fname,
		.fsp = fsp,
	};

	status = share_mode_do_locked_vfs_allowed(fsp->file_id,
						  smb_posix_unlink_locked,
						  &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_do_locked_vfs_allowed(%s) failed - %s\n",
			fsp_str_dbg(fsp), nt_errstr(status));
		close_file_free(req, &fsp, NORMAL_CLOSE);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = state.status;
	if (!NT_STATUS_IS_OK(status)) {
		close_file_free(req, &fsp, NORMAL_CLOSE);
		return status;
	}
	return close_file_free(req, &fsp, NORMAL_CLOSE);
}

/****************************************************************************
 Deal with SMB_SET_FILE_UNIX_LINK (create a UNIX symlink).
****************************************************************************/

static NTSTATUS smb_set_file_unix_link(connection_struct *conn,
				       struct smb_request *req,
				       const char *pdata,
				       int total_data,
				       struct files_struct *dirfsp,
				       struct smb_filename *new_smb_fname)
{
	char *link_target = NULL;
	struct smb_filename target_fname;
	TALLOC_CTX *ctx = talloc_tos();
	struct smb_filename new_smb_fname_rel = {};
	char *slash = NULL;
	NTSTATUS status;
	int ret;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	/* Set a symbolic link. */
	/* Don't allow this if follow links is false. */

	if (total_data == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!lp_follow_symlinks(SNUM(conn))) {
		return NT_STATUS_ACCESS_DENIED;
	}

	srvstr_pull_talloc(ctx, pdata, req->flags2, &link_target, pdata,
		    total_data, STR_TERMINATE);

	if (!link_target) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	target_fname = (struct smb_filename) {
		.base_name = link_target,
	};

	/* Removes @GMT tokens if any */
	status = canonicalize_snapshot_path(&target_fname, UCF_GMT_PATHNAME, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DBG_DEBUG("SMB_SET_FILE_UNIX_LINK doing symlink %s -> %s\n",
		  new_smb_fname->base_name, link_target);

	new_smb_fname_rel = *new_smb_fname;
	slash = strrchr_m(new_smb_fname_rel.base_name, '/');
	if (slash != NULL) {
		new_smb_fname_rel.base_name = slash + 1;
	}

	ret = SMB_VFS_SYMLINKAT(conn,
				&target_fname,
				dirfsp,
				&new_smb_fname_rel);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_SET_FILE_UNIX_HLINK (create a UNIX hard link).
****************************************************************************/

static NTSTATUS smb_set_file_unix_hlink(connection_struct *conn,
					struct smb_request *req,
					const char *pdata, int total_data,
					struct smb_filename *smb_fname_new)
{
	char *oldname = NULL;
	struct files_struct *src_dirfsp = NULL;
	struct smb_filename *smb_fname_old = NULL;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME old_twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_OK;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	/* Set a hard link. */
	if (total_data == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
			pdata,
			req->flags2,
			&oldname,
			pdata,
			total_data,
			STR_TERMINATE,
			&status);
	} else {
		srvstr_get_path(ctx,
			pdata,
			req->flags2,
			&oldname,
			pdata,
			total_data,
			STR_TERMINATE,
			&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(10,("smb_set_file_unix_hlink: SMB_SET_FILE_UNIX_LINK doing hard link %s -> %s\n",
		smb_fname_str_dbg(smb_fname_new), oldname));

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(oldname, &old_twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &oldname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = filename_convert_dirfsp(ctx,
					 conn,
					 oldname,
					 ucf_flags,
					 old_twrp,
					 &src_dirfsp,
					 &smb_fname_old);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return hardlink_internals(ctx,
				  conn,
				  req,
				  false,
				  smb_fname_old,
				  smb_fname_new);
}

/****************************************************************************
 Allow a UNIX info mknod.
****************************************************************************/

static NTSTATUS smb_unix_mknod(connection_struct *conn,
			       const char *pdata,
			       int total_data,
			       struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname)
{
	uint32_t file_type = IVAL(pdata,56);
#if defined(HAVE_MAKEDEV)
	uint32_t dev_major = IVAL(pdata,60);
	uint32_t dev_minor = IVAL(pdata,68);
#endif
	SMB_DEV_T dev = (SMB_DEV_T)0;
	uint32_t raw_unixmode = IVAL(pdata,84);
	NTSTATUS status;
	mode_t unixmode;
	int ret;
	struct smb_filename *parent_fname = NULL;
	struct smb_filename *atname = NULL;

	if (total_data < 100) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = unix_perms_from_wire(conn,
				      &smb_fname->st,
				      raw_unixmode,
				      &unixmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	unixmode = apply_conf_file_mask(conn, unixmode);

#if defined(HAVE_MAKEDEV)
	dev = makedev(dev_major, dev_minor);
#endif

	switch (file_type) {
		/* We can't create other objects here. */
		case UNIX_TYPE_FILE:
		case UNIX_TYPE_DIR:
		case UNIX_TYPE_SYMLINK:
			return NT_STATUS_ACCESS_DENIED;
#if defined(S_IFIFO)
		case UNIX_TYPE_FIFO:
			unixmode |= S_IFIFO;
			break;
#endif
#if defined(S_IFSOCK)
		case UNIX_TYPE_SOCKET:
			unixmode |= S_IFSOCK;
			break;
#endif
#if defined(S_IFCHR)
		case UNIX_TYPE_CHARDEV:
			/* This is only allowed for root. */
			if (get_current_uid(conn) != sec_initial_uid()) {
				return NT_STATUS_ACCESS_DENIED;
			}
			unixmode |= S_IFCHR;
			break;
#endif
#if defined(S_IFBLK)
		case UNIX_TYPE_BLKDEV:
			if (get_current_uid(conn) != sec_initial_uid()) {
				return NT_STATUS_ACCESS_DENIED;
			}
			unixmode |= S_IFBLK;
			break;
#endif
		default:
			return NT_STATUS_INVALID_PARAMETER;
	}

	DBG_DEBUG("SMB_SET_FILE_UNIX_BASIC doing mknod dev "
		  "%ju mode 0%o for file %s\n",
		  (uintmax_t)dev,
		  (unsigned int)unixmode,
		  smb_fname_str_dbg(smb_fname));

	status = SMB_VFS_PARENT_PATHNAME(dirfsp->conn,
					 talloc_tos(),
					 smb_fname,
					 &parent_fname,
					 &atname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ok - do the mknod. */
	ret = SMB_VFS_MKNODAT(conn,
			      dirfsp,
			      atname,
			      unixmode,
			      dev);

	if (ret != 0) {
		TALLOC_FREE(parent_fname);
		return map_nt_error_from_unix(errno);
	}

	/* If any of the other "set" calls fail we
	 * don't want to end up with a half-constructed mknod.
	 */

	if (lp_inherit_permissions(SNUM(conn))) {
		inherit_access_posix_acl(conn,
					 dirfsp,
					 smb_fname,
					 unixmode);
	}
	TALLOC_FREE(parent_fname);

	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_SET_FILE_UNIX_BASIC.
****************************************************************************/

static NTSTATUS smb_set_file_unix_basic(connection_struct *conn,
					struct smb_request *req,
					const char *pdata,
					int total_data,
					struct files_struct *dirfsp,
					files_struct *fsp,
					struct smb_filename *smb_fname)
{
	struct smb_file_time ft;
	uint32_t raw_unixmode;
	mode_t unixmode;
	off_t size = 0;
	uid_t set_owner = (uid_t)SMB_UID_NO_CHANGE;
	gid_t set_grp = (uid_t)SMB_GID_NO_CHANGE;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *all_fsps = NULL;
	bool modify_mtime = true;
	struct file_id id;
	SMB_STRUCT_STAT sbuf;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	init_smb_file_time(&ft);

	if (total_data < 100) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if(IVAL(pdata, 0) != SMB_SIZE_NO_CHANGE_LO &&
	   IVAL(pdata, 4) != SMB_SIZE_NO_CHANGE_HI) {
		size=IVAL(pdata,0); /* first 8 Bytes are size */
		size |= (((off_t)IVAL(pdata,4)) << 32);
	}

	ft.atime = pull_long_date_full_timespec(pdata+24); /* access_time */
	ft.mtime = pull_long_date_full_timespec(pdata+32); /* modification_time */
	set_owner = (uid_t)IVAL(pdata,40);
	set_grp = (gid_t)IVAL(pdata,48);
	raw_unixmode = IVAL(pdata,84);

	status = unix_perms_from_wire(conn,
				      &smb_fname->st,
				      raw_unixmode,
				      &unixmode);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!VALID_STAT(smb_fname->st)) {
		unixmode = apply_conf_file_mask(conn, unixmode);
	}

	DBG_DEBUG("SMB_SET_FILE_UNIX_BASIC: name = "
		  "%s size = %.0f, uid = %u, gid = %u, raw perms = 0%o\n",
		  smb_fname_str_dbg(smb_fname),
		  (double)size,
		  (unsigned int)set_owner,
		  (unsigned int)set_grp,
		  (int)raw_unixmode);

	sbuf = smb_fname->st;

	if (!VALID_STAT(sbuf)) {
		/*
		 * The only valid use of this is to create character and block
		 * devices, and named pipes. This is deprecated (IMHO) and
		 * a new info level should be used for mknod. JRA.
		 */

		if (dirfsp == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		return smb_unix_mknod(conn,
				      pdata,
				      total_data,
				      dirfsp,
				      smb_fname);
	}

#if 1
	/* Horrible backwards compatibility hack as an old server bug
	 * allowed a CIFS client bug to remain unnoticed :-(. JRA.
	 * */

	if (!size) {
		size = get_file_size_stat(&sbuf);
	}
#endif

	/*
	 * Deal with the UNIX specific mode set.
	 */

	if (raw_unixmode != SMB_MODE_NO_CHANGE) {
		int ret;

		if (fsp == NULL || S_ISLNK(smb_fname->st.st_ex_mode)) {
			DBG_WARNING("Can't set mode on symlink %s\n",
				smb_fname_str_dbg(smb_fname));
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		DEBUG(10,("smb_set_file_unix_basic: SMB_SET_FILE_UNIX_BASIC "
			  "setting mode 0%o for file %s\n",
			  (unsigned int)unixmode,
			  smb_fname_str_dbg(smb_fname)));
		ret = SMB_VFS_FCHMOD(fsp, unixmode);
		if (ret != 0) {
			return map_nt_error_from_unix(errno);
		}
	}

	/*
	 * Deal with the UNIX specific uid set.
	 */

	if ((set_owner != (uid_t)SMB_UID_NO_CHANGE) &&
	    (sbuf.st_ex_uid != set_owner)) {
		int ret;

		DBG_DEBUG("SMB_SET_FILE_UNIX_BASIC "
			  "changing owner %u for path %s\n",
			  (unsigned int)set_owner,
			  smb_fname_str_dbg(smb_fname));

		if (fsp &&
		    !fsp->fsp_flags.is_pathref &&
		    fsp_get_io_fd(fsp) != -1)
		{
			ret = SMB_VFS_FCHOWN(fsp, set_owner, (gid_t)-1);
		} else {
			/*
			 * UNIX extensions calls must always operate
			 * on symlinks.
			 */
			ret = SMB_VFS_LCHOWN(conn, smb_fname,
					     set_owner, (gid_t)-1);
		}

		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			return status;
		}
	}

	/*
	 * Deal with the UNIX specific gid set.
	 */

	if ((set_grp != (uid_t)SMB_GID_NO_CHANGE) &&
	    (sbuf.st_ex_gid != set_grp)) {
		int ret;

		DBG_DEBUG("SMB_SET_FILE_UNIX_BASIC "
			  "changing group %u for file %s\n",
			  (unsigned int)set_grp,
			  smb_fname_str_dbg(smb_fname));
		if (fsp &&
		    !fsp->fsp_flags.is_pathref &&
		    fsp_get_io_fd(fsp) != -1)
		{
			ret = SMB_VFS_FCHOWN(fsp, (uid_t)-1, set_grp);
		} else {
			/*
			 * UNIX extensions calls must always operate
			 * on symlinks.
			 */
			ret = SMB_VFS_LCHOWN(conn, smb_fname, (uid_t)-1,
				  set_grp);
		}
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			return status;
		}
	}

	/* Deal with any size changes. */

	if (S_ISREG(sbuf.st_ex_mode)) {
		status = smb_set_file_size(conn, req,
					   fsp,
					   smb_fname,
					   &sbuf,
					   size,
					   false);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* Deal with any time changes. */
	if (is_omit_timespec(&ft.mtime) && is_omit_timespec(&ft.atime)) {
		/* No change, don't cancel anything. */
		return status;
	}

	id = vfs_file_id_from_sbuf(conn, &sbuf);
	for(all_fsps = file_find_di_first(conn->sconn, id, true); all_fsps;
			all_fsps = file_find_di_next(all_fsps, true)) {
		/*
		 * We're setting the time explicitly for UNIX.
		 * Cancel any pending changes over all handles.
		 */
		all_fsps->fsp_flags.update_write_time_on_close = false;
		TALLOC_FREE(all_fsps->update_write_time_event);
	}

	/*
	 * Override the "setting_write_time"
	 * parameter here as it almost does what
	 * we need. Just remember if we modified
	 * mtime and send the notify ourselves.
	 */
	if (is_omit_timespec(&ft.mtime)) {
		modify_mtime = false;
	}

	status = smb_set_file_time(conn,
				fsp,
				smb_fname,
				&ft,
				false);
	if (modify_mtime) {
		notify_fname(conn, NOTIFY_ACTION_MODIFIED,
			FILE_NOTIFY_CHANGE_LAST_WRITE, smb_fname->base_name);
	}
	return status;
}

/****************************************************************************
 Deal with SMB_SET_FILE_UNIX_INFO2.
****************************************************************************/

static NTSTATUS smb_set_file_unix_info2(connection_struct *conn,
					struct smb_request *req,
					const char *pdata,
					int total_data,
					struct files_struct *dirfsp,
					files_struct *fsp,
					struct smb_filename *smb_fname)
{
	NTSTATUS status;
	uint32_t smb_fflags;
	uint32_t smb_fmask;

	if (!CAN_WRITE(conn)) {
		return NT_STATUS_DOS(ERRSRV, ERRaccess);
	}

	if (total_data < 116) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Start by setting all the fields that are common between UNIX_BASIC
	 * and UNIX_INFO2.
	 */
	status = smb_set_file_unix_basic(conn,
					 req,
					 pdata,
					 total_data,
					 dirfsp,
					 fsp,
					 smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	smb_fflags = IVAL(pdata, 108);
	smb_fmask = IVAL(pdata, 112);

	/* NB: We should only attempt to alter the file flags if the client
	 * sends a non-zero mask.
	 */
	if (smb_fmask != 0) {
		int stat_fflags = 0;

		if (!map_info2_flags_to_sbuf(&smb_fname->st, smb_fflags,
					     smb_fmask, &stat_fflags)) {
			/* Client asked to alter a flag we don't understand. */
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (fsp == NULL || S_ISLNK(smb_fname->st.st_ex_mode)) {
			DBG_WARNING("Can't change flags on symlink %s\n",
				smb_fname_str_dbg(smb_fname));
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (SMB_VFS_FCHFLAGS(fsp, stat_fflags) != 0) {
			return map_nt_error_from_unix(errno);
		}
	}

	/* XXX: need to add support for changing the create_time here. You
	 * can do this for paths on Darwin with setattrlist(2). The right way
	 * to hook this up is probably by extending the VFS utimes interface.
	 */

	return NT_STATUS_OK;
}

/****************************************************************************
 Deal with SMB_SET_POSIX_ACL.
****************************************************************************/

static NTSTATUS smb_set_posix_acl(connection_struct *conn,
				struct smb_request *req,
				const char *pdata,
				int total_data_in,
				files_struct *fsp,
				struct smb_filename *smb_fname)
{
#if !defined(HAVE_POSIX_ACLS)
	return NT_STATUS_INVALID_LEVEL;
#else
	uint16_t posix_acl_version;
	uint16_t num_file_acls;
	uint16_t num_def_acls;
	bool valid_file_acls = true;
	bool valid_def_acls = true;
	NTSTATUS status;
	unsigned int size_needed;
	unsigned int total_data;
	bool close_fsp = false;

	if (total_data_in < 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	total_data = total_data_in;

	if (total_data < SMB_POSIX_ACL_HEADER_SIZE) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	posix_acl_version = SVAL(pdata,0);
	num_file_acls = SVAL(pdata,2);
	num_def_acls = SVAL(pdata,4);

	if (num_file_acls == SMB_POSIX_IGNORE_ACE_ENTRIES) {
		valid_file_acls = false;
		num_file_acls = 0;
	}

	if (num_def_acls == SMB_POSIX_IGNORE_ACE_ENTRIES) {
		valid_def_acls = false;
		num_def_acls = 0;
	}

	if (posix_acl_version != SMB_POSIX_ACL_VERSION) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/* Wrap checks. */
	if (num_file_acls + num_def_acls < num_file_acls) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	size_needed = num_file_acls + num_def_acls;

	/*
	 * (size_needed * SMB_POSIX_ACL_ENTRY_SIZE) must be less
	 * than UINT_MAX, so check by division.
	 */
	if (size_needed > (UINT_MAX/SMB_POSIX_ACL_ENTRY_SIZE)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	size_needed = size_needed*SMB_POSIX_ACL_ENTRY_SIZE;
	if (size_needed + SMB_POSIX_ACL_HEADER_SIZE < size_needed) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	size_needed += SMB_POSIX_ACL_HEADER_SIZE;

	if (total_data < size_needed) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * Ensure we always operate on a file descriptor, not just
	 * the filename.
	 */
	if (fsp == NULL || !fsp->fsp_flags.is_fsa) {
		uint32_t access_mask = SEC_STD_WRITE_OWNER|
					SEC_STD_WRITE_DAC|
					SEC_STD_READ_CONTROL|
					FILE_READ_ATTRIBUTES|
					FILE_WRITE_ATTRIBUTES;

		status = get_posix_fsp(conn,
					req,
					smb_fname,
					access_mask,
					&fsp);

		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		close_fsp = true;
	}

	/* Here we know fsp != NULL */
	SMB_ASSERT(fsp != NULL);

	status = refuse_symlink_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* If we have a default acl, this *must* be a directory. */
	if (valid_def_acls && !fsp->fsp_flags.is_directory) {
		DBG_INFO("Can't set default acls on "
			 "non-directory %s\n",
			 fsp_str_dbg(fsp));
		return NT_STATUS_INVALID_HANDLE;
	}

	DBG_DEBUG("file %s num_file_acls = %"PRIu16", "
		  "num_def_acls = %"PRIu16"\n",
		  fsp_str_dbg(fsp),
		  num_file_acls,
		  num_def_acls);

	/* Move pdata to the start of the file ACL entries. */
	pdata += SMB_POSIX_ACL_HEADER_SIZE;

	if (valid_file_acls) {
		status = set_unix_posix_acl(conn,
					fsp,
					num_file_acls,
					pdata);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	/* Move pdata to the start of the default ACL entries. */
	pdata += (num_file_acls*SMB_POSIX_ACL_ENTRY_SIZE);

	if (valid_def_acls) {
		status = set_unix_posix_default_acl(conn,
					fsp,
					num_def_acls,
					pdata);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	status = NT_STATUS_OK;

  out:

	if (close_fsp) {
		(void)close_file_free(req, &fsp, NORMAL_CLOSE);
	}
	return status;
#endif
}

static void call_trans2setpathinfo(
	connection_struct *conn,
	struct smb_request *req,
	char **pparams,
	int total_params,
	char **ppdata,
	int total_data,
	unsigned int max_data_bytes)
{
	uint16_t info_level;
	struct smb_filename *smb_fname = NULL;
	struct files_struct *dirfsp = NULL;
	struct files_struct *fsp = NULL;
	char *params = *pparams;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	char *fname = NULL;
	bool info_level_handled;
	int data_return_size = 0;
	NTSTATUS status;

	if (params == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* set path info */
	if (total_params < 7) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	info_level = SVAL(params,0);

	if (INFO_LEVEL_IS_UNIX(info_level)) {
		if (!lp_smb1_unix_extensions()) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
		if (!req->posix_pathnames) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(req,
				      params,
				      req->flags2,
				      &fname,
				      &params[6],
				      total_params - 6,
				      STR_TERMINATE,
				      &status);
	} else {
		srvstr_get_path(req,
				params,
				req->flags2,
				&fname,
				&params[6],
				total_params - 6,
				STR_TERMINATE,
				&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	DBG_NOTICE("fname=%s info_level=%d totdata=%d\n",
		   fname,
		   info_level,
		   total_data);

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(fname, &twrp);
	}
	status = smb1_strip_dfs_path(req, &ucf_flags, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}
	status = filename_convert_dirfsp(req,
					 conn,
					 fname,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
					NT_STATUS_PATH_NOT_COVERED,
					ERRSRV, ERRbadpath);
			return;
		}
		reply_nterror(req, status);
		return;
	}

	info_level_handled = true; /* Untouched in switch cases below */

	switch (info_level) {

	default:
		info_level_handled = false;
		break;

	case SMB_POSIX_PATH_OPEN:
		status = smb_posix_open(conn,
					req,
					ppdata,
					total_data,
					dirfsp,
					smb_fname,
					&data_return_size);
		break;

	case SMB_POSIX_PATH_UNLINK:
		status = smb_posix_unlink(conn,
					  req,
					  *ppdata,
					  total_data,
					  dirfsp,
					  smb_fname);
		break;

	case SMB_SET_FILE_UNIX_LINK:
		status = smb_set_file_unix_link(
			conn, req, *ppdata, total_data, dirfsp, smb_fname);
		break;

	case SMB_SET_FILE_UNIX_HLINK:
		status = smb_set_file_unix_hlink(
			conn, req, *ppdata, total_data, smb_fname);
		break;

	case SMB_SET_FILE_UNIX_BASIC:
		status = smb_set_file_unix_basic(conn,
						 req,
						 *ppdata,
						 total_data,
						 dirfsp,
						 smb_fname->fsp,
						 smb_fname);
		break;

	case SMB_SET_FILE_UNIX_INFO2:
		status = smb_set_file_unix_info2(conn,
						 req,
						 *ppdata,
						 total_data,
						 dirfsp,
						 smb_fname->fsp,
						 smb_fname);
		break;
	case SMB_SET_POSIX_ACL:
		status = smb_set_posix_acl(
			conn, req, *ppdata, total_data, NULL, smb_fname);
		break;
	}

	if (info_level_handled) {
		goto done;
	}

	/*
	 * smb_fname->fsp may be NULL if smb_fname points at a symlink
	 * and we're in POSIX context, so be careful when using fsp
	 * below, it can still be NULL.
	 */
	fsp = smb_fname->fsp;
	if (fsp == NULL) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	status = smbd_do_setfilepathinfo(
		conn,
		req,
		req,
		info_level,
		fsp,
		smb_fname,
		ppdata,
		total_data,
		&data_return_size);

done:
	handle_trans2setfilepathinfo_result(
		conn,
		req,
		info_level,
		status,
		*ppdata,
		data_return_size,
		max_data_bytes);
}

static void call_trans2setfileinfo(
	connection_struct *conn,
	struct smb_request *req,
	char **pparams,
	int total_params,
	char **ppdata,
	int total_data,
	unsigned int max_data_bytes)
{
	char *pdata = *ppdata;
	uint16_t info_level;
	struct smb_filename *smb_fname = NULL;
	struct files_struct *fsp = NULL;
	char *params = *pparams;
	int data_return_size = 0;
	bool info_level_handled;
	NTSTATUS status;
	int ret;

	if (params == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (total_params < 4) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	fsp = file_fsp(req, SVAL(params,0));
	/* Basic check for non-null fsp. */
	if (!check_fsp_open(conn, req, fsp)) {
		return;
	}
	info_level = SVAL(params,2);

	if (INFO_LEVEL_IS_UNIX(info_level)) {
		if (!lp_smb1_unix_extensions()) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
		if (!req->posix_pathnames) {
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
		}
	}

	smb_fname = fsp->fsp_name;

	DBG_NOTICE("fnum=%s fname=%s info_level=%d totdata=%d\n",
		   fsp_fnum_dbg(fsp),
		   fsp_str_dbg(fsp),
		   info_level,
		   total_data);

	if (fsp_get_pathref_fd(fsp) == -1) {
		/*
		 * This is actually a SETFILEINFO on a directory
		 * handle (returned from an NT SMB). NT5.0 seems
		 * to do this call. JRA.
		 */
		ret = vfs_stat(conn, smb_fname);
		if (ret != 0) {
			DBG_NOTICE("vfs_stat of %s failed (%s)\n",
				   smb_fname_str_dbg(smb_fname),
				   strerror(errno));
			reply_nterror(req, map_nt_error_from_unix(errno));
			return;
		}
	} else if (fsp->print_file) {
		/*
		 * Doing a DELETE_ON_CLOSE should cancel a print job.
		 */
		if ((info_level == SMB_SET_FILE_DISPOSITION_INFO) &&
		    CVAL(pdata,0)) {

			fsp->fsp_flags.delete_on_close = true;

			DBG_NOTICE("Cancelling print job (%s)\n",
				   fsp_str_dbg(fsp));

			SSVAL(params,0,0);
			send_trans2_replies(
				conn,
				req,
				NT_STATUS_OK,
				params,
				2,
				*ppdata, 0,
				max_data_bytes);
			return;
		} else {
			reply_nterror(req, NT_STATUS_OBJECT_PATH_NOT_FOUND);
			return;
		}
	} else {
		/*
		 * Original code - this is an open file.
		 */
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_NOTICE("fstat of %s failed (%s)\n",
				   fsp_fnum_dbg(fsp),
				   nt_errstr(status));
			reply_nterror(req, status);
			return;
		}
	}

	info_level_handled = true; /* Untouched in switch cases below */

	switch (info_level) {

	default:
		info_level_handled = false;
		break;

	case SMB_SET_FILE_UNIX_BASIC:
		status = smb_set_file_unix_basic(conn,
						 req,
						 pdata,
						 total_data,
						 NULL,
						 fsp,
						 smb_fname);
		break;

	case SMB_SET_FILE_UNIX_INFO2:
		status = smb_set_file_unix_info2(conn,
						 req,
						 pdata,
						 total_data,
						 NULL,
						 fsp,
						 smb_fname);
		break;

	case SMB_SET_POSIX_LOCK:
		status = smb_set_posix_lock(
			conn, req, *ppdata, total_data, fsp);
		break;
	}

	if (info_level_handled) {
		handle_trans2setfilepathinfo_result(
			conn,
			req,
			info_level,
			status,
			*ppdata,
			data_return_size,
			max_data_bytes);
		return;
	}

	status = smbd_do_setfilepathinfo(
		conn,
		req,
		req,
		info_level,
		fsp,
		smb_fname,
		ppdata,
		total_data,
		&data_return_size);

	handle_trans2setfilepathinfo_result(
		conn,
		req,
		info_level,
		status,
		*ppdata,
		data_return_size,
		max_data_bytes);
}

/****************************************************************************
 Reply to a TRANS2_MKDIR (make directory with extended attributes).
****************************************************************************/

static void call_trans2mkdir(connection_struct *conn, struct smb_request *req,
			     char **pparams, int total_params,
			     char **ppdata, int total_data,
			     unsigned int max_data_bytes)
{
	struct files_struct *dirfsp = NULL;
	struct files_struct *fsp = NULL;
	struct smb_filename *smb_dname = NULL;
	char *params = *pparams;
	char *pdata = *ppdata;
	char *directory = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct ea_list *ea_list = NULL;
	uint32_t ucf_flags = ucf_flags_from_smb_request(req);
	NTTIME twrp = 0;
	TALLOC_CTX *ctx = talloc_tos();

	if (!CAN_WRITE(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (total_params < 5) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (req->posix_pathnames) {
		srvstr_get_path_posix(ctx,
			params,
			req->flags2,
			&directory,
			&params[4],
			total_params - 4,
			STR_TERMINATE,
			&status);
	} else {
		srvstr_get_path(ctx,
			params,
			req->flags2,
			&directory,
			&params[4],
			total_params - 4,
			STR_TERMINATE,
			&status);
	}
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		return;
	}

	DEBUG(3,("call_trans2mkdir : name = %s\n", directory));

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(directory, &twrp);
	}
	status = smb1_strip_dfs_path(ctx, &ucf_flags, &directory);
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}
	status = filename_convert_dirfsp(ctx,
					 conn,
					 directory,
					 ucf_flags,
					 twrp,
					 &dirfsp,
					 &smb_dname);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status,NT_STATUS_PATH_NOT_COVERED)) {
			reply_botherror(req,
				NT_STATUS_PATH_NOT_COVERED,
				ERRSRV, ERRbadpath);
			return;
		}
		reply_nterror(req, status);
		return;
        }

	/*
	 * OS/2 workplace shell seems to send SET_EA requests of "null"
	 * length (4 bytes containing IVAL 4).
	 * They seem to have no effect. Bug #3212. JRA.
	 */

	if (total_data && (total_data != 4)) {
		/* Any data in this call is an EA list. */
		if (total_data < 10) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (IVAL(pdata,0) > total_data) {
			DEBUG(10,("call_trans2mkdir: bad total data size (%u) > %u\n",
				IVAL(pdata,0), (unsigned int)total_data));
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		ea_list = read_ea_list(talloc_tos(), pdata + 4,
				       total_data - 4);
		if (!ea_list) {
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto out;
		}

		if (!lp_ea_support(SNUM(conn))) {
			reply_nterror(req, NT_STATUS_EAS_NOT_SUPPORTED);
			goto out;
		}
	}
	/* If total_data == 4 Windows doesn't care what values
	 * are placed in that field, it just ignores them.
	 * The System i QNTC IBM SMB client puts bad values here,
	 * so ignore them. */

	status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dirfsp,					/* dirfsp */
		smb_dname,				/* fname */
		MAXIMUM_ALLOWED_ACCESS,			/* access_mask */
		FILE_SHARE_NONE,			/* share_access */
		FILE_CREATE,				/* create_disposition*/
		FILE_DIRECTORY_FILE,			/* create_options */
		FILE_ATTRIBUTE_DIRECTORY,		/* file_attributes */
		0,					/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		reply_nterror(req, status);
		goto out;
	}

	/* Try and set any given EA. */
	if (ea_list) {
		status = set_ea(conn, fsp, ea_list);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			goto out;
		}
	}

	/* Realloc the parameter and data sizes */
	*pparams = (char *)SMB_REALLOC(*pparams,2);
	if(*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		goto out;
	}
	params = *pparams;

	SSVAL(params,0,0);

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 2, *ppdata, 0, max_data_bytes);

 out:
	if (fsp != NULL) {
		close_file_free(NULL, &fsp, NORMAL_CLOSE);
	}
	TALLOC_FREE(smb_dname);
}

/****************************************************************************
 Reply to a TRANS2_FINDNOTIFYFIRST (start monitoring a directory for changes).
 We don't actually do this - we just send a null response.
****************************************************************************/

static void call_trans2findnotifyfirst(connection_struct *conn,
				       struct smb_request *req,
				       char **pparams, int total_params,
				       char **ppdata, int total_data,
				       unsigned int max_data_bytes)
{
	char *params = *pparams;
	uint16_t info_level;

	if (total_params < 6) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	info_level = SVAL(params,4);
	DEBUG(3,("call_trans2findnotifyfirst - info_level %d\n", info_level));

	switch (info_level) {
		case 1:
		case 2:
			break;
		default:
			reply_nterror(req, NT_STATUS_INVALID_LEVEL);
			return;
	}

	/* Realloc the parameter and data sizes */
	*pparams = (char *)SMB_REALLOC(*pparams,6);
	if (*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	params = *pparams;

	SSVAL(params,0,fnf_handle);
	SSVAL(params,2,0); /* No changes */
	SSVAL(params,4,0); /* No EA errors */

	fnf_handle++;

	if(fnf_handle == 0)
		fnf_handle = 257;

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 6, *ppdata, 0, max_data_bytes);
}

/****************************************************************************
 Reply to a TRANS2_FINDNOTIFYNEXT (continue monitoring a directory for
 changes). Currently this does nothing.
****************************************************************************/

static void call_trans2findnotifynext(connection_struct *conn,
				      struct smb_request *req,
				      char **pparams, int total_params,
				      char **ppdata, int total_data,
				      unsigned int max_data_bytes)
{
	char *params = *pparams;

	DEBUG(3,("call_trans2findnotifynext\n"));

	/* Realloc the parameter and data sizes */
	*pparams = (char *)SMB_REALLOC(*pparams,4);
	if (*pparams == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	params = *pparams;

	SSVAL(params,0,0); /* No changes */
	SSVAL(params,2,0); /* No EA errors */

	send_trans2_replies(conn, req, NT_STATUS_OK, params, 4, *ppdata, 0, max_data_bytes);
}

/****************************************************************************
 Reply to a TRANS2_GET_DFS_REFERRAL - Shirish Kalele <kalele@veritas.com>.
****************************************************************************/

static void call_trans2getdfsreferral(connection_struct *conn,
				      struct smb_request *req,
				      char **pparams, int total_params,
				      char **ppdata, int total_data,
				      unsigned int max_data_bytes)
{
	char *params = *pparams;
	char *pathname = NULL;
	int reply_size = 0;
	int max_referral_level;
	NTSTATUS status = NT_STATUS_OK;
	TALLOC_CTX *ctx = talloc_tos();

	DEBUG(10,("call_trans2getdfsreferral\n"));

	if (!IS_IPC(conn)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (total_params < 3) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	max_referral_level = SVAL(params,0);

	if(!lp_host_msdfs()) {
		reply_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
		return;
	}

	srvstr_pull_talloc(ctx, params, req->flags2, &pathname, &params[2],
		    total_params - 2, STR_TERMINATE);
	if (!pathname) {
		reply_nterror(req, NT_STATUS_NOT_FOUND);
		return;
	}
	reply_size = setup_dfs_referral(
		conn, pathname, max_referral_level, ppdata, &status);
	if (reply_size < 0) {
		reply_nterror(req, status);
		return;
	}

	SSVAL((discard_const_p(uint8_t, req->inbuf)), smb_flg2,
	      SVAL(req->inbuf,smb_flg2) | FLAGS2_DFS_PATHNAMES);
	send_trans2_replies(conn, req, NT_STATUS_OK, 0,0,*ppdata,reply_size, max_data_bytes);
}

#define LMCAT_SPL       0x53
#define LMFUNC_GETJOBID 0x60

/****************************************************************************
 Reply to a TRANS2_IOCTL - used for OS/2 printing.
****************************************************************************/

static void call_trans2ioctl(connection_struct *conn,
			     struct smb_request *req,
			     char **pparams, int total_params,
			     char **ppdata, int total_data,
			     unsigned int max_data_bytes)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *pdata = *ppdata;
	files_struct *fsp = file_fsp(req, SVAL(req->vwv+15, 0));
	NTSTATUS status;
	size_t len = 0;

	/* check for an invalid fid before proceeding */

	if (!fsp) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	if ((SVAL(req->vwv+16, 0) == LMCAT_SPL)
	    && (SVAL(req->vwv+17, 0) == LMFUNC_GETJOBID)) {
		*ppdata = (char *)SMB_REALLOC(*ppdata, 32);
		if (*ppdata == NULL) {
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
		pdata = *ppdata;

		/* NOTE - THIS IS ASCII ONLY AT THE MOMENT - NOT SURE IF OS/2
			CAN ACCEPT THIS IN UNICODE. JRA. */

		/* Job number */
		SSVAL(pdata, 0, print_spool_rap_jobid(fsp->print_file));

		status = srvstr_push(pdata, req->flags2, pdata + 2,
			    lp_netbios_name(), 15,
			    STR_ASCII|STR_TERMINATE, &len); /* Our NetBIOS name */
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			return;
		}
		status = srvstr_push(pdata, req->flags2, pdata+18,
			    lp_servicename(talloc_tos(), lp_sub, SNUM(conn)), 13,
			    STR_ASCII|STR_TERMINATE, &len); /* Service name */
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			return;
		}
		send_trans2_replies(conn, req, NT_STATUS_OK, *pparams, 0, *ppdata, 32,
				    max_data_bytes);
		return;
	}

	DEBUG(2,("Unknown TRANS2_IOCTL\n"));
	reply_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
}

static void handle_trans2(connection_struct *conn, struct smb_request *req,
			  struct trans_state *state)
{
	struct smbXsrv_connection *xconn = req->xconn;

	if (xconn->protocol >= PROTOCOL_NT1) {
		req->flags2 |= 0x40; /* IS_LONG_NAME */
		SSVAL((discard_const_p(uint8_t, req->inbuf)),smb_flg2,req->flags2);
	}

	if (ENCRYPTION_REQUIRED(conn) && !req->encrypted) {
		if (state->call != TRANSACT2_QFSINFO &&
		    state->call != TRANSACT2_SETFSINFO) {
			DEBUG(0,("handle_trans2: encryption required "
				"with call 0x%x\n",
				(unsigned int)state->call));
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
	}

	/* Now we must call the relevant TRANS2 function */
	switch(state->call)  {
	case TRANSACT2_OPEN:
	{
		START_PROFILE(Trans2_open);
		call_trans2open(conn, req,
				&state->param, state->total_param,
				&state->data, state->total_data,
				state->max_data_return);
		END_PROFILE(Trans2_open);
		break;
	}

	case TRANSACT2_FINDFIRST:
	{
		START_PROFILE(Trans2_findfirst);
		call_trans2findfirst(conn, req,
				     &state->param, state->total_param,
				     &state->data, state->total_data,
				     state->max_data_return);
		END_PROFILE(Trans2_findfirst);
		break;
	}

	case TRANSACT2_FINDNEXT:
	{
		START_PROFILE(Trans2_findnext);
		call_trans2findnext(conn, req,
				    &state->param, state->total_param,
				    &state->data, state->total_data,
				    state->max_data_return);
		END_PROFILE(Trans2_findnext);
		break;
	}

	case TRANSACT2_QFSINFO:
	{
		START_PROFILE(Trans2_qfsinfo);
		call_trans2qfsinfo(conn, req,
				   &state->param, state->total_param,
				   &state->data, state->total_data,
				   state->max_data_return);
		END_PROFILE(Trans2_qfsinfo);
	    break;
	}

	case TRANSACT2_SETFSINFO:
	{
		START_PROFILE(Trans2_setfsinfo);
		call_trans2setfsinfo(conn, req,
				     &state->param, state->total_param,
				     &state->data, state->total_data,
				     state->max_data_return);
		END_PROFILE(Trans2_setfsinfo);
		break;
	}

	case TRANSACT2_QPATHINFO:
	{
		START_PROFILE(Trans2_qpathinfo);
		call_trans2qpathinfo(
			conn,
			req,
			&state->param,
			state->total_param,
			&state->data,
			state->total_data,
			state->max_data_return);
		END_PROFILE(Trans2_qpathinfo);
		break;
	}

	case TRANSACT2_QFILEINFO:
	{
		START_PROFILE(Trans2_qfileinfo);
		call_trans2qfileinfo(
			conn,
			req,
			&state->param,
			state->total_param,
			&state->data,
			state->total_data,
			state->max_data_return);
		END_PROFILE(Trans2_qfileinfo);
		break;
	}

	case TRANSACT2_SETPATHINFO:
	{
		START_PROFILE(Trans2_setpathinfo);
		call_trans2setpathinfo(
			conn,
			req,
			&state->param,
			state->total_param,
			&state->data,
			state->total_data,
			state->max_data_return);
		END_PROFILE(Trans2_setpathinfo);
		break;
	}

	case TRANSACT2_SETFILEINFO:
	{
		START_PROFILE(Trans2_setfileinfo);
		call_trans2setfileinfo(
			conn,
			req,
			&state->param,
			state->total_param,
			&state->data,
			state->total_data,
			state->max_data_return);
		END_PROFILE(Trans2_setfileinfo);
		break;
	}

	case TRANSACT2_FINDNOTIFYFIRST:
	{
		START_PROFILE(Trans2_findnotifyfirst);
		call_trans2findnotifyfirst(conn, req,
					   &state->param, state->total_param,
					   &state->data, state->total_data,
					   state->max_data_return);
		END_PROFILE(Trans2_findnotifyfirst);
		break;
	}

	case TRANSACT2_FINDNOTIFYNEXT:
	{
		START_PROFILE(Trans2_findnotifynext);
		call_trans2findnotifynext(conn, req,
					  &state->param, state->total_param,
					  &state->data, state->total_data,
					  state->max_data_return);
		END_PROFILE(Trans2_findnotifynext);
		break;
	}

	case TRANSACT2_MKDIR:
	{
		START_PROFILE(Trans2_mkdir);
		call_trans2mkdir(conn, req,
				 &state->param, state->total_param,
				 &state->data, state->total_data,
				 state->max_data_return);
		END_PROFILE(Trans2_mkdir);
		break;
	}

	case TRANSACT2_GET_DFS_REFERRAL:
	{
		START_PROFILE(Trans2_get_dfs_referral);
		call_trans2getdfsreferral(conn, req,
					  &state->param, state->total_param,
					  &state->data, state->total_data,
					  state->max_data_return);
		END_PROFILE(Trans2_get_dfs_referral);
		break;
	}

	case TRANSACT2_IOCTL:
	{
		START_PROFILE(Trans2_ioctl);
		call_trans2ioctl(conn, req,
				 &state->param, state->total_param,
				 &state->data, state->total_data,
				 state->max_data_return);
		END_PROFILE(Trans2_ioctl);
		break;
	}

	default:
		/* Error in request */
		DEBUG(2,("Unknown request %d in trans2 call\n", state->call));
		reply_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	}
}

/****************************************************************************
 Reply to a SMBtrans2.
 ****************************************************************************/

void reply_trans2(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	unsigned int dsoff;
	unsigned int dscnt;
	unsigned int psoff;
	unsigned int pscnt;
	unsigned int tran_call;
	struct trans_state *state;
	NTSTATUS result;

	START_PROFILE(SMBtrans2);

	if (req->wct < 14) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtrans2);
		return;
	}

	dsoff = SVAL(req->vwv+12, 0);
	dscnt = SVAL(req->vwv+11, 0);
	psoff = SVAL(req->vwv+10, 0);
	pscnt = SVAL(req->vwv+9, 0);
	tran_call = SVAL(req->vwv+14, 0);

	result = allow_new_trans(conn->pending_trans, req->mid);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(2, ("Got invalid trans2 request: %s\n",
			  nt_errstr(result)));
		reply_nterror(req, result);
		END_PROFILE(SMBtrans2);
		return;
	}

	if (IS_IPC(conn)) {
		switch (tran_call) {
		/* List the allowed trans2 calls on IPC$ */
		case TRANSACT2_OPEN:
		case TRANSACT2_GET_DFS_REFERRAL:
		case TRANSACT2_QFILEINFO:
		case TRANSACT2_QFSINFO:
		case TRANSACT2_SETFSINFO:
			break;
		default:
			reply_nterror(req, NT_STATUS_ACCESS_DENIED);
			END_PROFILE(SMBtrans2);
			return;
		}
	}

	if ((state = talloc(conn, struct trans_state)) == NULL) {
		DEBUG(0, ("talloc failed\n"));
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBtrans2);
		return;
	}

	state->cmd = SMBtrans2;

	state->mid = req->mid;
	state->vuid = req->vuid;
	state->setup_count = SVAL(req->vwv+13, 0);
	state->setup = NULL;
	state->total_param = SVAL(req->vwv+0, 0);
	state->param = NULL;
	state->total_data =  SVAL(req->vwv+1, 0);
	state->data = NULL;
	state->max_param_return = SVAL(req->vwv+2, 0);
	state->max_data_return  = SVAL(req->vwv+3, 0);
	state->max_setup_return = SVAL(req->vwv+4, 0);
	state->close_on_completion = BITSETW(req->vwv+5, 0);
	state->one_way = BITSETW(req->vwv+5, 1);

	state->call = tran_call;

	/* All trans2 messages we handle have smb_sucnt == 1 - ensure this
	   is so as a sanity check */
	if (state->setup_count != 1) {
		/*
		 * Need to have rc=0 for ioctl to get job id for OS/2.
		 *  Network printing will fail if function is not successful.
		 *  Similar function in reply.c will be used if protocol
		 *  is LANMAN1.0 instead of LM1.2X002.
		 *  Until DosPrintSetJobInfo with PRJINFO3 is supported,
		 *  outbuf doesn't have to be set(only job id is used).
		 */
		if ( (state->setup_count == 4)
		     && (tran_call == TRANSACT2_IOCTL)
		     && (SVAL(req->vwv+16, 0) == LMCAT_SPL)
		     &&	(SVAL(req->vwv+17, 0) == LMFUNC_GETJOBID)) {
			DEBUG(2,("Got Trans2 DevIOctl jobid\n"));
		} else {
			DEBUG(2,("Invalid smb_sucnt in trans2 call(%u)\n",state->setup_count));
			DEBUG(2,("Transaction is %d\n",tran_call));
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
			END_PROFILE(SMBtrans2);
			return;
		}
	}

	if ((dscnt > state->total_data) || (pscnt > state->total_param))
		goto bad_param;

	if (state->total_data) {

		if (smb_buffer_oob(state->total_data, 0, dscnt)
		    || smb_buffer_oob(smb_len(req->inbuf), dsoff, dscnt)) {
			goto bad_param;
		}

		/* Can't use talloc here, the core routines do realloc on the
		 * params and data. */
		state->data = (char *)SMB_MALLOC(state->total_data);
		if (state->data == NULL) {
			DEBUG(0,("reply_trans2: data malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_data));
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtrans2);
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
		state->param = (char *)SMB_MALLOC(state->total_param);
		if (state->param == NULL) {
			DEBUG(0,("reply_trans: param malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_param));
			SAFE_FREE(state->data);
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtrans2);
			return;
		}

		memcpy(state->param,smb_base(req->inbuf)+psoff,pscnt);
	}

	state->received_data  = dscnt;
	state->received_param = pscnt;

	if ((state->received_param == state->total_param) &&
	    (state->received_data == state->total_data)) {

		handle_trans2(conn, req, state);

		SAFE_FREE(state->data);
		SAFE_FREE(state->param);
		TALLOC_FREE(state);
		END_PROFILE(SMBtrans2);
		return;
	}

	DLIST_ADD(conn->pending_trans, state);

	/* We need to send an interim response then receive the rest
	   of the parameter/data bytes */
	reply_smb1_outbuf(req, 0, 0);
	show_msg((char *)req->outbuf);
	END_PROFILE(SMBtrans2);
	return;

  bad_param:

	DEBUG(0,("reply_trans2: invalid trans parameters\n"));
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	END_PROFILE(SMBtrans2);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
}

/****************************************************************************
 Reply to a SMBtranss2
 ****************************************************************************/

void reply_transs2(struct smb_request *req)
{
	connection_struct *conn = req->conn;
	unsigned int pcnt,poff,dcnt,doff,pdisp,ddisp;
	struct trans_state *state;

	START_PROFILE(SMBtranss2);

	show_msg((const char *)req->inbuf);

	/* Windows clients expect all replies to
	   a transact secondary (SMBtranss2 0x33)
	   to have a command code of transact
	   (SMBtrans2 0x32). See bug #8989
	   and also [MS-CIFS] section 2.2.4.47.2
	   for details.
	*/
	req->cmd = SMBtrans2;

	if (req->wct < 8) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtranss2);
		return;
	}

	for (state = conn->pending_trans; state != NULL;
	     state = state->next) {
		if (state->mid == req->mid) {
			break;
		}
	}

	if ((state == NULL) || (state->cmd != SMBtrans2)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtranss2);
		return;
	}

	/* Revise state->total_param and state->total_data in case they have
	   changed downwards */

	if (SVAL(req->vwv+0, 0) < state->total_param)
		state->total_param = SVAL(req->vwv+0, 0);
	if (SVAL(req->vwv+1, 0) < state->total_data)
		state->total_data = SVAL(req->vwv+1, 0);

	pcnt = SVAL(req->vwv+2, 0);
	poff = SVAL(req->vwv+3, 0);
	pdisp = SVAL(req->vwv+4, 0);

	dcnt = SVAL(req->vwv+5, 0);
	doff = SVAL(req->vwv+6, 0);
	ddisp = SVAL(req->vwv+7, 0);

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
		memcpy(state->param+pdisp,smb_base(req->inbuf)+poff,pcnt);
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
		END_PROFILE(SMBtranss2);
		return;
	}

	handle_trans2(conn, req, state);

	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);

	END_PROFILE(SMBtranss2);
	return;

  bad_param:

	DEBUG(0,("reply_transs2: invalid trans parameters\n"));
	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
	END_PROFILE(SMBtranss2);
}

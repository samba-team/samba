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

/****************************************************************************
  Send the required number of replies back.
  We assume all fields other than the data fields are
  set correctly for the type of call.
  HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

void send_trans2_replies(connection_struct *conn,
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
		reply_outbuf(req, 10, 0);
		if (NT_STATUS_V(status)) {
			uint8_t eclass;
			uint32_t ecode;
			ntstatus_to_dos(status, &eclass, &ecode);
			error_packet_set((char *)req->outbuf,
					eclass, ecode, status,
					__LINE__,__FILE__);
		}
		show_msg((char *)req->outbuf);
		if (!srv_send_smb(xconn,
				(char *)req->outbuf,
				true, req->seqnum+1,
				IS_CONN_ENCRYPTED(conn),
				&req->pcd)) {
			exit_server_cleanly("send_trans2_replies: srv_send_smb failed.");
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
			  "= %d!!!", useable_space));
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

		reply_outbuf(req, 10, total_sent_thistime + alignment_offset
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
		if (!srv_send_smb(xconn,
				(char *)req->outbuf,
				true, req->seqnum+1,
				IS_CONN_ENCRYPTED(conn),
				&req->pcd))
			exit_server_cleanly("send_trans2_replies: srv_send_smb failed.");

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

NTSTATUS smb_set_posix_lock(connection_struct *conn,
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
		ok = srv_send_smb(
			req->xconn,
			(char *)req->outbuf,
			true,
			req->seqnum+1,
			IS_CONN_ENCRYPTED(req->conn),
			NULL);
		if (!ok) {
			exit_server_cleanly("smb_set_posix_lock_done: "
					    "srv_send_smb failed.");
		}
	}

	TALLOC_FREE(req);
	return;
}

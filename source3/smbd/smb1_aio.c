/*
   Unix SMB/Netbios implementation.
   Version 3.0
   async_io read handling using POSIX async io.
   Copyright (C) Jeremy Allison 2005.

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
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"

static void aio_pread_smb1_done(struct tevent_req *req);

/****************************************************************************
 Set up an aio request from a SMBreadX call.
*****************************************************************************/

NTSTATUS schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *smbreq,
			     files_struct *fsp, off_t startpos,
			     size_t smb_maxcnt)
{
	struct aio_extra *aio_ex;
	size_t bufsize;
	size_t min_aio_read_size = lp_aio_read_size(SNUM(conn));
	struct tevent_req *req;
	bool ok;

	ok = vfs_valid_pread_range(startpos, smb_maxcnt);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (fsp_is_alternate_stream(fsp)) {
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_read_size || (smb_maxcnt < min_aio_read_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a read for aio request. */
		DEBUG(10,("schedule_aio_read_and_X: read size (%u) too small "
			  "for minimum aio_read of %u\n",
			  (unsigned int)smb_maxcnt,
			  (unsigned int)min_aio_read_size ));
		return NT_STATUS_RETRY;
	}

	/* Only do this on non-chained and non-chaining reads */
        if (req_is_in_chain(smbreq)) {
		return NT_STATUS_RETRY;
	}

	/* The following is safe from integer wrap as we've already checked
	   smb_maxcnt is 128k or less. Wct is 12 for read replies */

	bufsize = smb_size + 12 * 2 + smb_maxcnt + 1 /* padding byte */;

	if ((aio_ex = create_aio_extra(NULL, fsp, bufsize)) == NULL) {
		DEBUG(10,("schedule_aio_read_and_X: malloc fail.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	construct_reply_common_req(smbreq, (char *)aio_ex->outbuf.data);
	srv_set_message((char *)aio_ex->outbuf.data, 12, 0, True);
	SCVAL(aio_ex->outbuf.data,smb_vwv0,0xFF); /* Never a chained reply. */
	SCVAL(smb_buf(aio_ex->outbuf.data), 0, 0); /* padding byte */

	init_strict_lock_struct(fsp,
			(uint64_t)smbreq->smbpid,
			(uint64_t)startpos,
			(uint64_t)smb_maxcnt,
			READ_LOCK,
			lp_posix_cifsu_locktype(fsp),
			&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK_CHECK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = smb_maxcnt;
	aio_ex->offset = startpos;

	req = SMB_VFS_PREAD_SEND(aio_ex, fsp->conn->sconn->ev_ctx,
				 fsp,
				 smb_buf(aio_ex->outbuf.data) + 1 /* pad */,
				 smb_maxcnt, startpos);
	if (req == NULL) {
		DEBUG(0,("schedule_aio_read_and_X: aio_read failed. "
			 "Error %s\n", strerror(errno) ));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pread_smb1_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	aio_ex->smbreq = talloc_move(aio_ex, &smbreq);

	DEBUG(10,("schedule_aio_read_and_X: scheduled aio_read for file %s, "
		  "offset %.0f, len = %u (mid = %u)\n",
		  fsp_str_dbg(fsp), (double)startpos, (unsigned int)smb_maxcnt,
		  (unsigned int)aio_ex->smbreq->mid ));

	return NT_STATUS_OK;
}

static void aio_pread_smb1_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	files_struct *fsp = aio_ex->fsp;
	size_t outsize;
	char *outbuf = (char *)aio_ex->outbuf.data;
	ssize_t nread;
	struct vfs_aio_state vfs_aio_state;

	nread = SMB_VFS_PREAD_RECV(req, &vfs_aio_state);
	TALLOC_FREE(req);

	DEBUG(10, ("pread_recv returned %d, err = %s\n", (int)nread,
		   (nread == -1) ? strerror(vfs_aio_state.error) : "no error"));

	if (fsp == NULL) {
		DEBUG( 3, ("aio_pread_smb1_done: file closed whilst "
			   "aio outstanding (mid[%llu]).\n",
			   (unsigned long long)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		return;
	}

	if (nread < 0) {
		DEBUG( 3, ("handle_aio_read_complete: file %s nread == %d. "
			   "Error = %s\n", fsp_str_dbg(fsp), (int)nread,
			   strerror(vfs_aio_state.error)));

		ERROR_NT(map_nt_error_from_unix(vfs_aio_state.error));
		outsize = srv_set_message(outbuf,0,0,true);
	} else {
		outsize = setup_readX_header(outbuf, nread);

		fh_set_pos(aio_ex->fsp->fh, aio_ex->offset + nread);
		fh_set_position_information(aio_ex->fsp->fh,
					    fh_get_pos(aio_ex->fsp->fh));

		DEBUG( 3, ("handle_aio_read_complete file %s max=%d "
			   "nread=%d\n", fsp_str_dbg(fsp),
			   (int)aio_ex->nbyte, (int)nread ) );

	}

	if (outsize <= 4) {
		DBG_INFO("Invalid outsize (%zu)\n", outsize);
		TALLOC_FREE(aio_ex);
		return;
	}
	outsize -= 4;
	_smb_setlen_large(outbuf, outsize);

	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->xconn, outbuf,
			  true, aio_ex->smbreq->seqnum+1,
			  IS_CONN_ENCRYPTED(fsp->conn), NULL)) {
		exit_server_cleanly("handle_aio_read_complete: srv_send_smb "
				    "failed.");
	}

	DEBUG(10, ("handle_aio_read_complete: scheduled aio_read completed "
		   "for file %s, offset %.0f, len = %u\n",
		   fsp_str_dbg(fsp), (double)aio_ex->offset,
		   (unsigned int)nread));

	TALLOC_FREE(aio_ex);
}

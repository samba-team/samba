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
#include "lib/tevent_wait.h"

/****************************************************************************
 The buffer we keep around whilst an aio request is in process.
*****************************************************************************/

struct aio_extra {
	files_struct *fsp;
	struct smb_request *smbreq;
	DATA_BLOB outbuf;
	struct lock_struct lock;
	size_t nbyte;
	off_t offset;
	bool write_through;
};

/****************************************************************************
 Accessor function to return write_through state.
*****************************************************************************/

bool aio_write_through_requested(struct aio_extra *aio_ex)
{
	return aio_ex->write_through;
}

static int aio_extra_destructor(struct aio_extra *aio_ex)
{
	outstanding_aio_calls--;
	return 0;
}

/****************************************************************************
 Create the extended aio struct we must keep around for the lifetime
 of the aio call.
*****************************************************************************/

static struct aio_extra *create_aio_extra(TALLOC_CTX *mem_ctx,
					files_struct *fsp,
					size_t buflen)
{
	struct aio_extra *aio_ex = talloc_zero(mem_ctx, struct aio_extra);

	if (!aio_ex) {
		return NULL;
	}

	/* The output buffer stored in the aio_ex is the start of
	   the smb return buffer. The buffer used in the acb
	   is the start of the reply data portion of that buffer. */

	if (buflen) {
		aio_ex->outbuf = data_blob_talloc(aio_ex, NULL, buflen);
		if (!aio_ex->outbuf.data) {
			TALLOC_FREE(aio_ex);
			return NULL;
		}
	}
	talloc_set_destructor(aio_ex, aio_extra_destructor);
	aio_ex->fsp = fsp;
	outstanding_aio_calls++;
	return aio_ex;
}

struct aio_req_fsp_link {
	files_struct *fsp;
	struct tevent_req *req;
};

static int aio_del_req_from_fsp(struct aio_req_fsp_link *lnk)
{
	unsigned i;
	files_struct *fsp = lnk->fsp;
	struct tevent_req *req = lnk->req;

	for (i=0; i<fsp->num_aio_requests; i++) {
		if (fsp->aio_requests[i] == req) {
			break;
		}
	}
	if (i == fsp->num_aio_requests) {
		DEBUG(1, ("req %p not found in fsp %p\n", req, fsp));
		return 0;
	}
	fsp->num_aio_requests -= 1;
	fsp->aio_requests[i] = fsp->aio_requests[fsp->num_aio_requests];

	if (fsp->num_aio_requests == 0) {
		tevent_wait_done(fsp->deferred_close);
	}
	return 0;
}

bool aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req)
{
	size_t array_len;
	struct aio_req_fsp_link *lnk;

	lnk = talloc(req, struct aio_req_fsp_link);
	if (lnk == NULL) {
		return false;
	}

	array_len = talloc_array_length(fsp->aio_requests);
	if (array_len <= fsp->num_aio_requests) {
		struct tevent_req **tmp;

		tmp = talloc_realloc(
			fsp, fsp->aio_requests, struct tevent_req *,
			fsp->num_aio_requests+1);
		if (tmp == NULL) {
			TALLOC_FREE(lnk);
			return false;
		}
		fsp->aio_requests = tmp;
	}
	fsp->aio_requests[fsp->num_aio_requests] = req;
	fsp->num_aio_requests += 1;

	lnk->fsp = fsp;
	lnk->req = req;
	talloc_set_destructor(lnk, aio_del_req_from_fsp);

	return true;
}

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

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
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

	/* Only do this on non-chained and non-chaining reads not using the
	 * write cache. */
        if (req_is_in_chain(smbreq) || (lp_write_cache_size(SNUM(conn)) != 0)) {
		return NT_STATUS_RETRY;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(10,("schedule_aio_read_and_X: Already have %d aio "
			  "activities outstanding.\n",
			  outstanding_aio_calls ));
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

	init_strict_lock_struct(fsp, (uint64_t)smbreq->smbpid,
		(uint64_t)startpos, (uint64_t)smb_maxcnt, READ_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
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
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pread_smb1_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
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
	int outsize;
	char *outbuf = (char *)aio_ex->outbuf.data;
	char *data = smb_buf(outbuf) + 1 /* padding byte */;
	ssize_t nread;
	int err;

	nread = SMB_VFS_PREAD_RECV(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pread_recv returned %d, err = %s\n", (int)nread,
		   (nread == -1) ? strerror(err) : "no error"));

	if (fsp == NULL) {
		DEBUG( 3, ("aio_pread_smb1_done: file closed whilst "
			   "aio outstanding (mid[%llu]).\n",
			   (unsigned long long)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	if (nread < 0) {
		DEBUG( 3, ("handle_aio_read_complete: file %s nread == %d. "
			   "Error = %s\n", fsp_str_dbg(fsp), (int)nread,
			   strerror(err)));

		ERROR_NT(map_nt_error_from_unix(err));
		outsize = srv_set_message(outbuf,0,0,true);
	} else {
		outsize = srv_set_message(outbuf, 12,
					  nread + 1 /* padding byte */, false);
		SSVAL(outbuf,smb_vwv2, 0xFFFF); /* Remaining - must be * -1. */
		SSVAL(outbuf,smb_vwv5, nread);
		SSVAL(outbuf,smb_vwv6, smb_offset(data,outbuf));
		SSVAL(outbuf,smb_vwv7, ((nread >> 16) & 1));
		SSVAL(smb_buf(outbuf), -2, nread);

		aio_ex->fsp->fh->pos = aio_ex->offset + nread;
		aio_ex->fsp->fh->position_information = aio_ex->fsp->fh->pos;

		DEBUG( 3, ("handle_aio_read_complete file %s max=%d "
			   "nread=%d\n", fsp_str_dbg(fsp),
			   (int)aio_ex->nbyte, (int)nread ) );

	}
	smb_setlen(outbuf, outsize - 4);
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

struct pwrite_fsync_state {
	struct tevent_context *ev;
	files_struct *fsp;
	bool write_through;
	ssize_t nwritten;
};

static void pwrite_fsync_write_done(struct tevent_req *subreq);
static void pwrite_fsync_sync_done(struct tevent_req *subreq);

static struct tevent_req *pwrite_fsync_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp,
					    const void *data,
					    size_t n, off_t offset,
					    bool write_through)
{
	struct tevent_req *req, *subreq;
	struct pwrite_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state, struct pwrite_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->write_through = write_through;

	subreq = SMB_VFS_PWRITE_SEND(state, ev, fsp, data, n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, pwrite_fsync_write_done, req);
	return req;
}

static void pwrite_fsync_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct pwrite_fsync_state *state = tevent_req_data(
		req, struct pwrite_fsync_state);
	connection_struct *conn = state->fsp->conn;
	int err;
	bool do_sync;

	state->nwritten = SMB_VFS_PWRITE_RECV(subreq, &err);
	TALLOC_FREE(subreq);
	if (state->nwritten == -1) {
		tevent_req_error(req, err);
		return;
	}

	do_sync = (lp_strict_sync(SNUM(conn)) &&
		   (lp_sync_always(SNUM(conn)) || state->write_through));
	if (!do_sync) {
		tevent_req_done(req);
		return;
	}

	subreq = SMB_VFS_FSYNC_SEND(state, state->ev, state->fsp);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, pwrite_fsync_sync_done, req);
}

static void pwrite_fsync_sync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret, err;

	ret = SMB_VFS_FSYNC_RECV(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static ssize_t pwrite_fsync_recv(struct tevent_req *req, int *perr)
{
	struct pwrite_fsync_state *state = tevent_req_data(
		req, struct pwrite_fsync_state);

	if (tevent_req_is_unix_error(req, perr)) {
		return -1;
	}
	return state->nwritten;
}

static void aio_pwrite_smb1_done(struct tevent_req *req);

/****************************************************************************
 Set up an aio request from a SMBwriteX call.
*****************************************************************************/

NTSTATUS schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *smbreq,
			      files_struct *fsp, const char *data,
			      off_t startpos,
			      size_t numtowrite)
{
	struct aio_extra *aio_ex;
	size_t bufsize;
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));
	struct tevent_req *req;

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_write_size || (numtowrite < min_aio_write_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a write for aio request. */
		DEBUG(10,("schedule_aio_write_and_X: write size (%u) too "
			  "small for minimum aio_write of %u\n",
			  (unsigned int)numtowrite,
			  (unsigned int)min_aio_write_size ));
		return NT_STATUS_RETRY;
	}

	/* Only do this on non-chained and non-chaining writes not using the
	 * write cache. */
        if (req_is_in_chain(smbreq) || (lp_write_cache_size(SNUM(conn)) != 0)) {
		return NT_STATUS_RETRY;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(3,("schedule_aio_write_and_X: Already have %d aio "
			 "activities outstanding.\n",
			  outstanding_aio_calls ));
		DEBUG(10,("schedule_aio_write_and_X: failed to schedule "
			  "aio_write for file %s, offset %.0f, len = %u "
			  "(mid = %u)\n",
			  fsp_str_dbg(fsp), (double)startpos,
			  (unsigned int)numtowrite,
			  (unsigned int)smbreq->mid ));
		return NT_STATUS_RETRY;
	}

	bufsize = smb_size + 6*2;

	if (!(aio_ex = create_aio_extra(NULL, fsp, bufsize))) {
		DEBUG(0,("schedule_aio_write_and_X: malloc fail.\n"));
		return NT_STATUS_NO_MEMORY;
	}
	aio_ex->write_through = BITSETW(smbreq->vwv+7,0);

	construct_reply_common_req(smbreq, (char *)aio_ex->outbuf.data);
	srv_set_message((char *)aio_ex->outbuf.data, 6, 0, True);
	SCVAL(aio_ex->outbuf.data,smb_vwv0,0xFF); /* Never a chained reply. */

	init_strict_lock_struct(fsp, (uint64_t)smbreq->smbpid,
		(uint64_t)startpos, (uint64_t)numtowrite, WRITE_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = numtowrite;
	aio_ex->offset = startpos;

	req = pwrite_fsync_send(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				data, numtowrite, startpos,
				aio_ex->write_through);
	if (req == NULL) {
		DEBUG(3,("schedule_aio_wrote_and_X: aio_write failed. "
			 "Error %s\n", strerror(errno) ));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pwrite_smb1_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	aio_ex->smbreq = talloc_move(aio_ex, &smbreq);

	/* This should actually be improved to span the write. */
	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WRITE);
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WRITE);

	if (!aio_ex->write_through && !lp_sync_always(SNUM(fsp->conn))
	    && fsp->aio_write_behind) {
		/* Lie to the client and immediately claim we finished the
		 * write. */
	        SSVAL(aio_ex->outbuf.data,smb_vwv2,numtowrite);
                SSVAL(aio_ex->outbuf.data,smb_vwv4,(numtowrite>>16)&1);
		show_msg((char *)aio_ex->outbuf.data);
		if (!srv_send_smb(aio_ex->smbreq->xconn,
				(char *)aio_ex->outbuf.data,
				true, aio_ex->smbreq->seqnum+1,
				IS_CONN_ENCRYPTED(fsp->conn),
				&aio_ex->smbreq->pcd)) {
			exit_server_cleanly("schedule_aio_write_and_X: "
					    "srv_send_smb failed.");
		}
		DEBUG(10,("schedule_aio_write_and_X: scheduled aio_write "
			  "behind for file %s\n", fsp_str_dbg(fsp)));
	}

	DEBUG(10,("schedule_aio_write_and_X: scheduled aio_write for file "
		  "%s, offset %.0f, len = %u (mid = %u) "
		  "outstanding_aio_calls = %d\n",
		  fsp_str_dbg(fsp), (double)startpos, (unsigned int)numtowrite,
		  (unsigned int)aio_ex->smbreq->mid, outstanding_aio_calls ));

	return NT_STATUS_OK;
}

static void aio_pwrite_smb1_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	files_struct *fsp = aio_ex->fsp;
	char *outbuf = (char *)aio_ex->outbuf.data;
	ssize_t numtowrite = aio_ex->nbyte;
	ssize_t nwritten;
	int err;

	nwritten = pwrite_fsync_recv(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pwrite_recv returned %d, err = %s\n", (int)nwritten,
		   (nwritten == -1) ? strerror(err) : "no error"));

	if (fsp == NULL) {
		DEBUG( 3, ("aio_pwrite_smb1_done: file closed whilst "
			   "aio outstanding (mid[%llu]).\n",
			   (unsigned long long)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	mark_file_modified(fsp);

	if (fsp->aio_write_behind) {

		if (nwritten != numtowrite) {
			if (nwritten == -1) {
				DEBUG(5,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Error %s\n",
					 fsp_str_dbg(fsp), strerror(err)));
			} else {
				DEBUG(0,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Wanted %u bytes but "
					 "only wrote %d\n", fsp_str_dbg(fsp),
					 (unsigned int)numtowrite,
					 (int)nwritten ));
			}
		} else {
			DEBUG(10,("handle_aio_write_complete: "
				  "aio_write_behind completed for file %s\n",
				  fsp_str_dbg(fsp)));
		}
		/* TODO: should no return success in case of an error !!! */
		TALLOC_FREE(aio_ex);
		return;
	}

	/* We don't need outsize or set_message here as we've already set the
	   fixed size length when we set up the aio call. */

	if (nwritten == -1) {
		DEBUG(3, ("handle_aio_write: file %s wanted %u bytes. "
			  "nwritten == %d. Error = %s\n",
			  fsp_str_dbg(fsp), (unsigned int)numtowrite,
			  (int)nwritten, strerror(err)));

		ERROR_NT(map_nt_error_from_unix(err));
		srv_set_message(outbuf,0,0,true);
        } else {
		SSVAL(outbuf,smb_vwv2,nwritten);
		SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);
		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);
		}

		DEBUG(3,("handle_aio_write: %s, num=%d wrote=%d\n",
			 fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));

		aio_ex->fsp->fh->pos = aio_ex->offset + nwritten;
	}

	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->xconn, outbuf,
			  true, aio_ex->smbreq->seqnum+1,
			  IS_CONN_ENCRYPTED(fsp->conn),
			  NULL)) {
		exit_server_cleanly("handle_aio_write_complete: "
				    "srv_send_smb failed.");
	}

	DEBUG(10, ("handle_aio_write_complete: scheduled aio_write completed "
		   "for file %s, offset %.0f, requested %u, written = %u\n",
		   fsp_str_dbg(fsp), (double)aio_ex->offset,
		   (unsigned int)numtowrite, (unsigned int)nwritten));

	TALLOC_FREE(aio_ex);
}

bool cancel_smb2_aio(struct smb_request *smbreq)
{
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	struct aio_extra *aio_ex = NULL;

	if (smb2req) {
		aio_ex = talloc_get_type(smbreq->async_priv,
					 struct aio_extra);
	}

	if (aio_ex == NULL) {
		return false;
	}

	if (aio_ex->fsp == NULL) {
		return false;
	}

	/*
	 * We let the aio request run. Setting fsp to NULL has the
	 * effect that the _done routines don't send anything out.
	 */

	aio_ex->fsp = NULL;
	return true;
}

static void aio_pread_smb2_done(struct tevent_req *req);

/****************************************************************************
 Set up an aio request from a SMB2 read call.
*****************************************************************************/

NTSTATUS schedule_smb2_aio_read(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				TALLOC_CTX *ctx,
				DATA_BLOB *preadbuf,
				off_t startpos,
				size_t smb_maxcnt)
{
	struct aio_extra *aio_ex;
	size_t min_aio_read_size = lp_aio_read_size(SNUM(conn));
	struct tevent_req *req;

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if (fsp->op == NULL) {
		/* No AIO on internal opens. */
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_read_size || (smb_maxcnt < min_aio_read_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a read for aio request. */
		DEBUG(10,("smb2: read size (%u) too small "
			"for minimum aio_read of %u\n",
			(unsigned int)smb_maxcnt,
			(unsigned int)min_aio_read_size ));
		return NT_STATUS_RETRY;
	}

	/* Only do this on reads not using the write cache. */
	if (lp_write_cache_size(SNUM(conn)) != 0) {
		return NT_STATUS_RETRY;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(10,("smb2: Already have %d aio "
			"activities outstanding.\n",
			outstanding_aio_calls ));
		return NT_STATUS_RETRY;
	}

	/* Create the out buffer. */
	*preadbuf = data_blob_talloc(ctx, NULL, smb_maxcnt);
	if (preadbuf->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	init_strict_lock_struct(fsp, fsp->op->global->open_persistent_id,
		(uint64_t)startpos, (uint64_t)smb_maxcnt, READ_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = smb_maxcnt;
	aio_ex->offset = startpos;

	req = SMB_VFS_PREAD_SEND(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				 preadbuf->data, smb_maxcnt, startpos);
	if (req == NULL) {
		DEBUG(0, ("smb2: SMB_VFS_PREAD_SEND failed. "
			  "Error %s\n", strerror(errno)));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pread_smb2_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	/* We don't need talloc_move here as both aio_ex and
	 * smbreq are children of smbreq->smb2req. */
	aio_ex->smbreq = smbreq;
	smbreq->async_priv = aio_ex;

	DEBUG(10,("smb2: scheduled aio_read for file %s, "
		"offset %.0f, len = %u (mid = %u)\n",
		fsp_str_dbg(fsp), (double)startpos, (unsigned int)smb_maxcnt,
		(unsigned int)aio_ex->smbreq->mid ));

	return NT_STATUS_OK;
}

static void aio_pread_smb2_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	files_struct *fsp = aio_ex->fsp;
	NTSTATUS status;
	ssize_t nread;
	int err = 0;

	nread = SMB_VFS_PREAD_RECV(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pread_recv returned %d, err = %s\n", (int)nread,
		   (nread == -1) ? strerror(err) : "no error"));

	if (fsp == NULL) {
		DEBUG(3, ("%s: request cancelled (mid[%ju])\n",
			  __func__, (uintmax_t)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		tevent_req_nterror(subreq, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	/* Common error or success code processing for async or sync
	   read returns. */

	status = smb2_read_complete(subreq, nread, err);

	if (nread > 0) {
		fsp->fh->pos = aio_ex->offset + nread;
		fsp->fh->position_information = fsp->fh->pos;
	}

	DEBUG(10, ("smb2: scheduled aio_read completed "
		   "for file %s, offset %.0f, len = %u "
		   "(errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(aio_ex->fsp),
		   (double)aio_ex->offset,
		   (unsigned int)nread,
		   err, nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(subreq, status);
		return;
	}
	tevent_req_done(subreq);
}

static void aio_pwrite_smb2_done(struct tevent_req *req);

/****************************************************************************
 Set up an aio request from a SMB2write call.
*****************************************************************************/

NTSTATUS schedule_aio_smb2_write(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				uint64_t in_offset,
				DATA_BLOB in_data,
				bool write_through)
{
	struct aio_extra *aio_ex = NULL;
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));
	struct tevent_req *req;

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return NT_STATUS_RETRY;
	}

	if (fsp->op == NULL) {
		/* No AIO on internal opens. */
		return NT_STATUS_RETRY;
	}

	if ((!min_aio_write_size || (in_data.length < min_aio_write_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a write for aio request. */
		DEBUG(10,("smb2: write size (%u) too "
			"small for minimum aio_write of %u\n",
			(unsigned int)in_data.length,
			(unsigned int)min_aio_write_size ));
		return NT_STATUS_RETRY;
	}

	/* Only do this on writes not using the write cache. */
	if (lp_write_cache_size(SNUM(conn)) != 0) {
		return NT_STATUS_RETRY;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(3,("smb2: Already have %d aio "
			"activities outstanding.\n",
			outstanding_aio_calls ));
		return NT_STATUS_RETRY;
	}

	if (smbreq->unread_bytes) {
		/* Can't do async with recvfile. */
		return NT_STATUS_RETRY;
	}

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	aio_ex->write_through = write_through;

	init_strict_lock_struct(fsp, fsp->op->global->open_persistent_id,
		in_offset, (uint64_t)in_data.length, WRITE_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	aio_ex->nbyte = in_data.length;
	aio_ex->offset = in_offset;

	req = pwrite_fsync_send(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				in_data.data, in_data.length, in_offset,
				write_through);
	if (req == NULL) {
		DEBUG(3, ("smb2: SMB_VFS_PWRITE_SEND failed. "
			  "Error %s\n", strerror(errno)));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}
	tevent_req_set_callback(req, aio_pwrite_smb2_done, aio_ex);

	if (!aio_add_req_to_fsp(fsp, req)) {
		DEBUG(1, ("Could not add req to fsp\n"));
		SMB_VFS_STRICT_UNLOCK(conn, fsp, &aio_ex->lock);
		TALLOC_FREE(aio_ex);
		return NT_STATUS_RETRY;
	}

	/* We don't need talloc_move here as both aio_ex and
	* smbreq are children of smbreq->smb2req. */
	aio_ex->smbreq = smbreq;
	smbreq->async_priv = aio_ex;

	/* This should actually be improved to span the write. */
	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_WRITE);
	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_WRITE);

	/*
	 * We don't want to do write behind due to ownership
	 * issues of the request structs. Maybe add it if I
	 * figure those out. JRA.
	 */

	DEBUG(10,("smb2: scheduled aio_write for file "
		"%s, offset %.0f, len = %u (mid = %u) "
		"outstanding_aio_calls = %d\n",
		fsp_str_dbg(fsp),
		(double)in_offset,
		(unsigned int)in_data.length,
		(unsigned int)aio_ex->smbreq->mid,
		outstanding_aio_calls ));

	return NT_STATUS_OK;
}

static void aio_pwrite_smb2_done(struct tevent_req *req)
{
	struct aio_extra *aio_ex = tevent_req_callback_data(
		req, struct aio_extra);
	ssize_t numtowrite = aio_ex->nbyte;
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	files_struct *fsp = aio_ex->fsp;
	NTSTATUS status;
	ssize_t nwritten;
	int err = 0;

	nwritten = pwrite_fsync_recv(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pwrite_recv returned %d, err = %s\n", (int)nwritten,
		   (nwritten == -1) ? strerror(err) : "no error"));

	if (fsp == NULL) {
		DEBUG(3, ("%s: request cancelled (mid[%ju])\n",
			  __func__, (uintmax_t)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		tevent_req_nterror(subreq, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	mark_file_modified(fsp);

        status = smb2_write_complete_nosync(subreq, nwritten, err);

	DEBUG(10, ("smb2: scheduled aio_write completed "
		   "for file %s, offset %.0f, requested %u, "
		   "written = %u (errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(fsp),
		   (double)aio_ex->offset,
		   (unsigned int)numtowrite,
		   (unsigned int)nwritten,
		   err, nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(subreq, status);
		return;
	}
	tevent_req_done(subreq);
}

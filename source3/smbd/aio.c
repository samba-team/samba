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

#if defined(HAVE_AIO)

/* The signal we'll use to signify aio done. */
#ifndef RT_SIGNAL_AIO
#define RT_SIGNAL_AIO	(SIGRTMIN+3)
#endif

#ifndef HAVE_STRUCT_SIGEVENT_SIGEV_VALUE_SIVAL_PTR
#ifdef HAVE_STRUCT_SIGEVENT_SIGEV_VALUE_SIGVAL_PTR
#define sival_int	sigval_int
#define sival_ptr	sigval_ptr
#endif
#endif

/****************************************************************************
 The buffer we keep around whilst an aio request is in process.
*****************************************************************************/

struct aio_extra {
	struct aio_extra *next, *prev;
	SMB_STRUCT_AIOCB acb;
	files_struct *fsp;
	struct smb_request *smbreq;
	DATA_BLOB outbuf;
	struct lock_struct lock;
	bool write_through;
	int (*handle_completion)(struct aio_extra *ex, int errcode);
};

/****************************************************************************
 Accessor function to return write_through state.
*****************************************************************************/

bool aio_write_through_requested(struct aio_extra *aio_ex)
{
	return aio_ex->write_through;
}

/****************************************************************************
 Initialize the signal handler for aio read/write.
*****************************************************************************/

static void smbd_aio_signal_handler(struct tevent_context *ev_ctx,
				    struct tevent_signal *se,
				    int signum, int count,
				    void *_info, void *private_data)
{
	siginfo_t *info = (siginfo_t *)_info;
	struct aio_extra *aio_ex = (struct aio_extra *)
				info->si_value.sival_ptr;

	smbd_aio_complete_aio_ex(aio_ex);
	TALLOC_FREE(aio_ex);
}


bool initialize_async_io_handler(void)
{
	static bool tried_signal_setup = false;

	if (aio_signal_event) {
		return true;
	}
	if (tried_signal_setup) {
		return false;
	}
	tried_signal_setup = true;

	aio_signal_event = tevent_add_signal(server_event_context(),
					     server_event_context(),
					     RT_SIGNAL_AIO, SA_SIGINFO,
					     smbd_aio_signal_handler,
					     NULL);
	if (!aio_signal_event) {
		DEBUG(10, ("Failed to setup RT_SIGNAL_AIO handler\n"));
		return false;
	}
	return true;
}

static int handle_aio_read_complete(struct aio_extra *aio_ex, int errcode);
static int handle_aio_write_complete(struct aio_extra *aio_ex, int errcode);
static int handle_aio_smb2_read_complete(struct aio_extra *aio_ex, int errcode);
static int handle_aio_smb2_write_complete(struct aio_extra *aio_ex, int errcode);

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
	return 0;
}

static bool aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req)
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
	SMB_STRUCT_AIOCB *a;
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

	bufsize = smb_size + 12 * 2 + smb_maxcnt;

	if ((aio_ex = create_aio_extra(NULL, fsp, bufsize)) == NULL) {
		DEBUG(10,("schedule_aio_read_and_X: malloc fail.\n"));
		return NT_STATUS_NO_MEMORY;
	}
	aio_ex->handle_completion = handle_aio_read_complete;

	construct_reply_common_req(smbreq, (char *)aio_ex->outbuf.data);
	srv_set_message((char *)aio_ex->outbuf.data, 12, 0, True);
	SCVAL(aio_ex->outbuf.data,smb_vwv0,0xFF); /* Never a chained reply. */

	init_strict_lock_struct(fsp, (uint64_t)smbreq->smbpid,
		(uint64_t)startpos, (uint64_t)smb_maxcnt, READ_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	a = &aio_ex->acb;

	/* Now set up the aio record for the read call. */

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = smb_buf(aio_ex->outbuf.data);
	a->aio_nbytes = smb_maxcnt;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = aio_ex;

	req = SMB_VFS_PREAD_SEND(aio_ex, fsp->conn->sconn->ev_ctx,
				 fsp, smb_buf(aio_ex->outbuf.data),
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
	char *data = smb_buf(outbuf);
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
		outsize = srv_set_message(outbuf, 12, nread, False);
		SSVAL(outbuf,smb_vwv2, 0xFFFF); /* Remaining - must be * -1. */
		SSVAL(outbuf,smb_vwv5, nread);
		SSVAL(outbuf,smb_vwv6, smb_offset(data,outbuf));
		SSVAL(outbuf,smb_vwv7, ((nread >> 16) & 1));
		SSVAL(smb_buf(outbuf), -2, nread);

		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nread;
		aio_ex->fsp->fh->position_information = aio_ex->fsp->fh->pos;

		DEBUG( 3, ("handle_aio_read_complete file %s max=%d "
			   "nread=%d\n", fsp_str_dbg(fsp),
			   (int)aio_ex->acb.aio_nbytes, (int)nread ) );

	}
	smb_setlen(outbuf, outsize - 4);
	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->sconn, outbuf,
			  true, aio_ex->smbreq->seqnum+1,
			  IS_CONN_ENCRYPTED(fsp->conn), NULL)) {
		exit_server_cleanly("handle_aio_read_complete: srv_send_smb "
				    "failed.");
	}

	DEBUG(10, ("handle_aio_read_complete: scheduled aio_read completed "
		   "for file %s, offset %.0f, len = %u\n",
		   fsp_str_dbg(fsp), (double)aio_ex->acb.aio_offset,
		   (unsigned int)nread));

	TALLOC_FREE(aio_ex);
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
	SMB_STRUCT_AIOCB *a;
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
	aio_ex->handle_completion = handle_aio_write_complete;
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

	a = &aio_ex->acb;

	/* Now set up the aio record for the write call. */

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = discard_const_p(char, data);
	a->aio_nbytes = numtowrite;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = aio_ex;

	req = SMB_VFS_PWRITE_SEND(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				  data, numtowrite, startpos);
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

	if (!aio_ex->write_through && !lp_syncalways(SNUM(fsp->conn))
	    && fsp->aio_write_behind) {
		/* Lie to the client and immediately claim we finished the
		 * write. */
	        SSVAL(aio_ex->outbuf.data,smb_vwv2,numtowrite);
                SSVAL(aio_ex->outbuf.data,smb_vwv4,(numtowrite>>16)&1);
		show_msg((char *)aio_ex->outbuf.data);
		if (!srv_send_smb(aio_ex->smbreq->sconn,
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
	ssize_t numtowrite = aio_ex->acb.aio_nbytes;
	ssize_t nwritten;
	int err;

	nwritten = SMB_VFS_PWRITE_RECV(req, &err);
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
		NTSTATUS status;

		SSVAL(outbuf,smb_vwv2,nwritten);
		SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);
		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);
		}

		DEBUG(3,("handle_aio_write: %s, num=%d wrote=%d\n",
			 fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));
		status = sync_file(fsp->conn,fsp, aio_ex->write_through);
		if (!NT_STATUS_IS_OK(status)) {
			ERROR_BOTH(map_nt_error_from_unix(errno),
				   ERRHRD, ERRdiskfull);
			srv_set_message(outbuf,0,0,true);
			DEBUG(5, ("handle_aio_write: sync_file for %s "
				  "returned %s\n",
				  fsp_str_dbg(fsp), nt_errstr(status)));
		}

		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nwritten;
	}

	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->sconn, outbuf,
			  true, aio_ex->smbreq->seqnum+1,
			  IS_CONN_ENCRYPTED(fsp->conn),
			  NULL)) {
		exit_server_cleanly("handle_aio_write_complete: "
				    "srv_send_smb failed.");
	}

	DEBUG(10, ("handle_aio_write_complete: scheduled aio_write completed "
		   "for file %s, offset %.0f, requested %u, written = %u\n",
		   fsp_str_dbg(fsp), (double)aio_ex->acb.aio_offset,
		   (unsigned int)numtowrite, (unsigned int)nwritten));

	TALLOC_FREE(aio_ex);
}

bool cancel_smb2_aio(struct smb_request *smbreq)
{
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	struct aio_extra *aio_ex = NULL;
	int ret;

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
	SMB_STRUCT_AIOCB *a;
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
	aio_ex->handle_completion = handle_aio_smb2_read_complete;

	init_strict_lock_struct(fsp, (uint64_t)smbreq->smbpid,
		(uint64_t)startpos, (uint64_t)smb_maxcnt, READ_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	a = &aio_ex->acb;

	/* Now set up the aio record for the read call. */

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = preadbuf->data;
	a->aio_nbytes = smb_maxcnt;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = aio_ex;

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
		DEBUG( 3, ("aio_pread_smb2_done: file closed whilst "
			   "aio outstanding (mid[%llu]).\n",
			   (unsigned long long)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	/* Common error or success code processing for async or sync
	   read returns. */

	status = smb2_read_complete(subreq, nread, err);

	if (nread > 0) {
		fsp->fh->pos = aio_ex->acb.aio_offset + nread;
		fsp->fh->position_information = fsp->fh->pos;
	}

	DEBUG(10, ("smb2: scheduled aio_read completed "
		   "for file %s, offset %.0f, len = %u "
		   "(errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(aio_ex->fsp),
		   (double)aio_ex->acb.aio_offset,
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
	SMB_STRUCT_AIOCB *a = NULL;
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));
	struct tevent_req *req;

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
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

	if (!(aio_ex = create_aio_extra(smbreq->smb2req, fsp, 0))) {
		return NT_STATUS_NO_MEMORY;
	}

	aio_ex->handle_completion = handle_aio_smb2_write_complete;
	aio_ex->write_through = write_through;

	init_strict_lock_struct(fsp, (uint64_t)smbreq->smbpid,
		in_offset, (uint64_t)in_data.length, WRITE_LOCK,
		&aio_ex->lock);

	/* Take the lock until the AIO completes. */
	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &aio_ex->lock)) {
		TALLOC_FREE(aio_ex);
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	a = &aio_ex->acb;

	/* Now set up the aio record for the write call. */

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = in_data.data;
	a->aio_nbytes = in_data.length;
	a->aio_offset = in_offset;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = aio_ex;

	req = SMB_VFS_PWRITE_SEND(aio_ex, fsp->conn->sconn->ev_ctx, fsp,
				  in_data.data, in_data.length, in_offset);
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
	ssize_t numtowrite = aio_ex->acb.aio_nbytes;
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	files_struct *fsp = aio_ex->fsp;
	NTSTATUS status;
	ssize_t nwritten;
	int err = 0;

	nwritten = SMB_VFS_PWRITE_RECV(req, &err);
	TALLOC_FREE(req);

	DEBUG(10, ("pwrite_recv returned %d, err = %s\n", (int)nwritten,
		   (nwritten == -1) ? strerror(err) : "no error"));

	if (fsp == NULL) {
		DEBUG( 3, ("aio_pwrite_smb2_done: file closed whilst "
			   "aio outstanding (mid[%llu]).\n",
			   (unsigned long long)aio_ex->smbreq->mid));
		TALLOC_FREE(aio_ex);
		return;
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

        status = smb2_write_complete(subreq, nwritten, err);

	DEBUG(10, ("smb2: scheduled aio_write completed "
		   "for file %s, offset %.0f, requested %u, "
		   "written = %u (errcode = %d, NTSTATUS = %s)\n",
		   fsp_str_dbg(fsp),
		   (double)aio_ex->acb.aio_offset,
		   (unsigned int)numtowrite,
		   (unsigned int)nwritten,
		   err, nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(subreq, status);
		return;
	}
	tevent_req_done(subreq);
}

/****************************************************************************
 Complete the read and return the data or error back to the client.
 Returns errno or zero if all ok.
*****************************************************************************/

static int handle_aio_read_complete(struct aio_extra *aio_ex, int errcode)
{
	int outsize;
	char *outbuf = (char *)aio_ex->outbuf.data;
	char *data = smb_buf(outbuf);
	ssize_t nread = SMB_VFS_AIO_RETURN(aio_ex->fsp,&aio_ex->acb);

	if (nread < 0) {
		/* We're relying here on the fact that if the fd is
		   closed then the aio will complete and aio_return
		   will return an error. Hopefully this is
		   true.... JRA. */

		DEBUG( 3,( "handle_aio_read_complete: file %s nread == %d. "
			   "Error = %s\n",
			   fsp_str_dbg(aio_ex->fsp), (int)nread, strerror(errcode)));

		ERROR_NT(map_nt_error_from_unix(errcode));
		outsize = srv_set_message(outbuf,0,0,true);
	} else {
		outsize = srv_set_message(outbuf,12,nread,False);
		SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be * -1. */
		SSVAL(outbuf,smb_vwv5,nread);
		SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
		SSVAL(outbuf,smb_vwv7,((nread >> 16) & 1));
		SSVAL(smb_buf(outbuf),-2,nread);

		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nread;
		aio_ex->fsp->fh->position_information = aio_ex->fsp->fh->pos;

		DEBUG( 3, ( "handle_aio_read_complete file %s max=%d "
			    "nread=%d\n",
			    fsp_str_dbg(aio_ex->fsp),
			    (int)aio_ex->acb.aio_nbytes, (int)nread ) );

	}
	smb_setlen(outbuf,outsize - 4);
	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->sconn, outbuf,
			true, aio_ex->smbreq->seqnum+1,
			IS_CONN_ENCRYPTED(aio_ex->fsp->conn), NULL)) {
		exit_server_cleanly("handle_aio_read_complete: srv_send_smb "
				    "failed.");
	}

	DEBUG(10,("handle_aio_read_complete: scheduled aio_read completed "
		  "for file %s, offset %.0f, len = %u\n",
		  fsp_str_dbg(aio_ex->fsp), (double)aio_ex->acb.aio_offset,
		  (unsigned int)nread ));

	return errcode;
}

/****************************************************************************
 Complete the write and return the data or error back to the client.
 Returns error code or zero if all ok.
*****************************************************************************/

static int handle_aio_write_complete(struct aio_extra *aio_ex, int errcode)
{
	files_struct *fsp = aio_ex->fsp;
	char *outbuf = (char *)aio_ex->outbuf.data;
	ssize_t numtowrite = aio_ex->acb.aio_nbytes;
	ssize_t nwritten = SMB_VFS_AIO_RETURN(fsp,&aio_ex->acb);

	if (fsp->aio_write_behind) {
		if (nwritten != numtowrite) {
			if (nwritten == -1) {
				DEBUG(5,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Error %s\n",
					 fsp_str_dbg(fsp), strerror(errcode)));
			} else {
				DEBUG(0,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Wanted %u bytes but "
					 "only wrote %d\n", fsp_str_dbg(fsp),
					 (unsigned int)numtowrite,
					 (int)nwritten ));
				errcode = EIO;
			}
		} else {
			DEBUG(10,("handle_aio_write_complete: "
				  "aio_write_behind completed for file %s\n",
				  fsp_str_dbg(fsp)));
		}
		/* TODO: should no return 0 in case of an error !!! */
		return 0;
	}

	/* We don't need outsize or set_message here as we've already set the
	   fixed size length when we set up the aio call. */

	if(nwritten == -1) {
		DEBUG( 3,( "handle_aio_write: file %s wanted %u bytes. "
			   "nwritten == %d. Error = %s\n",
			   fsp_str_dbg(fsp), (unsigned int)numtowrite,
			   (int)nwritten, strerror(errcode) ));

		ERROR_NT(map_nt_error_from_unix(errcode));
		srv_set_message(outbuf,0,0,true);
        } else {
		NTSTATUS status;

        	SSVAL(outbuf,smb_vwv2,nwritten);
		SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);
		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);
		}

		DEBUG(3,("handle_aio_write: %s, num=%d wrote=%d\n",
			 fsp_fnum_dbg(fsp), (int)numtowrite, (int)nwritten));
		status = sync_file(fsp->conn,fsp, aio_ex->write_through);
		if (!NT_STATUS_IS_OK(status)) {
			errcode = errno;
			ERROR_BOTH(map_nt_error_from_unix(errcode),
				   ERRHRD, ERRdiskfull);
			srv_set_message(outbuf,0,0,true);
                	DEBUG(5,("handle_aio_write: sync_file for %s returned %s\n",
				 fsp_str_dbg(fsp), nt_errstr(status)));
		}

		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nwritten;

		mark_file_modified(aio_ex->fsp);
	}

	show_msg(outbuf);
	if (!srv_send_smb(aio_ex->smbreq->sconn, outbuf,
			  true, aio_ex->smbreq->seqnum+1,
			  IS_CONN_ENCRYPTED(fsp->conn),
			  NULL)) {
		exit_server_cleanly("handle_aio_write_complete: "
				    "srv_send_smb failed.");
	}

	DEBUG(10,("handle_aio_write_complete: scheduled aio_write completed "
		  "for file %s, offset %.0f, requested %u, written = %u\n",
		  fsp_str_dbg(fsp), (double)aio_ex->acb.aio_offset,
		  (unsigned int)numtowrite, (unsigned int)nwritten ));

	return errcode;
}

/****************************************************************************
 Complete the read and return the data or error back to the client.
 Returns errno or zero if all ok.
*****************************************************************************/

static int handle_aio_smb2_read_complete(struct aio_extra *aio_ex, int errcode)
{
	NTSTATUS status;
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	ssize_t nread = SMB_VFS_AIO_RETURN(aio_ex->fsp,&aio_ex->acb);

	/* Common error or success code processing for async or sync
	   read returns. */

	status = smb2_read_complete(subreq, nread, errcode);

	if (nread > 0) {
		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nread;
		aio_ex->fsp->fh->position_information = aio_ex->fsp->fh->pos;
	}

	DEBUG(10,("smb2: scheduled aio_read completed "
		"for file %s, offset %.0f, len = %u "
		"(errcode = %d, NTSTATUS = %s)\n",
		fsp_str_dbg(aio_ex->fsp),
		(double)aio_ex->acb.aio_offset,
		(unsigned int)nread,
		errcode,
		nt_errstr(status) ));

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(subreq, status);
		return errcode;
	}

	tevent_req_done(subreq);
	return errcode;
}

/****************************************************************************
 Complete the SMB2 write and return the data or error back to the client.
 Returns error code or zero if all ok.
*****************************************************************************/

static int handle_aio_smb2_write_complete(struct aio_extra *aio_ex, int errcode)
{
	files_struct *fsp = aio_ex->fsp;
	ssize_t numtowrite = aio_ex->acb.aio_nbytes;
	ssize_t nwritten = SMB_VFS_AIO_RETURN(fsp,&aio_ex->acb);
	struct tevent_req *subreq = aio_ex->smbreq->smb2req->subreq;
	NTSTATUS status;

	status = smb2_write_complete(subreq, nwritten, errcode);

	DEBUG(10,("smb2: scheduled aio_write completed "
		"for file %s, offset %.0f, requested %u, "
		"written = %u (errcode = %d, NTSTATUS = %s)\n",
		fsp_str_dbg(fsp),
		(double)aio_ex->acb.aio_offset,
		(unsigned int)numtowrite,
		(unsigned int)nwritten,
		errcode,
		nt_errstr(status) ));

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(subreq, status);
		return errcode;
	}

	mark_file_modified(fsp);

	tevent_req_done(subreq);
	return errcode;
}

/****************************************************************************
 Handle any aio completion. Returns True if finished (and sets *perr if err
 was non-zero), False if not.
*****************************************************************************/

static bool handle_aio_completed(struct aio_extra *aio_ex, int *perr)
{
	files_struct *fsp = NULL;
	int err;

	if(!aio_ex) {
	        DEBUG(3, ("handle_aio_completed: Non-existing aio_ex passed\n"));
		return false;
	}

	if (!aio_ex->fsp) {
	        DEBUG(3, ("handle_aio_completed: aio_ex->fsp == NULL\n"));
		return false;
	}

	fsp = aio_ex->fsp;

	/* Ensure the operation has really completed. */
	err = SMB_VFS_AIO_ERROR(fsp, &aio_ex->acb);
	if (err == EINPROGRESS) {
		DEBUG(10,( "handle_aio_completed: operation mid %llu still in "
			"process for file %s\n",
			(unsigned long long)aio_ex->smbreq->mid,
			fsp_str_dbg(aio_ex->fsp)));
		return False;
	}

	if (err == ECANCELED) {
		DEBUG(10,( "handle_aio_completed: operation mid %llu canceled "
			"for file %s\n",
			(unsigned long long)aio_ex->smbreq->mid,
			fsp_str_dbg(aio_ex->fsp)));
	}

	/* Unlock now we're done. */
	SMB_VFS_STRICT_UNLOCK(fsp->conn, fsp, &aio_ex->lock);

	err = aio_ex->handle_completion(aio_ex, err);
	if (err) {
		*perr = err; /* Only save non-zero errors. */
	}

	return True;
}

/****************************************************************************
 Handle any aio completion inline.
*****************************************************************************/

void smbd_aio_complete_aio_ex(struct aio_extra *aio_ex)
{
	files_struct *fsp = NULL;
	int ret = 0;

	DEBUG(10,("smbd_aio_complete_mid: mid[%llu]\n",
		(unsigned long long)aio_ex->smbreq->mid));

	fsp = aio_ex->fsp;
	if (fsp == NULL) {
		/* file was closed whilst I/O was outstanding. Just
		 * ignore. */
		DEBUG( 3,( "smbd_aio_complete_mid: file closed whilst "
			"aio outstanding (mid[%llu]).\n",
			(unsigned long long)aio_ex->smbreq->mid));
		return;
	}

	if (!handle_aio_completed(aio_ex, &ret)) {
		return;
	}
}

void aio_fsp_close(files_struct *fsp)
{
	unsigned i;

	for (i=0; i<fsp->num_aio_requests; i++) {
		struct tevent_req *req = fsp->aio_requests[i];
		struct aio_extra *aio_ex = tevent_req_callback_data(
			req, struct aio_extra);
		aio_ex->fsp = NULL;
	}
}

#else

bool initialize_async_io_handler(void)
{
	return false;
}

NTSTATUS schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *smbreq,
			     files_struct *fsp, off_t startpos,
			     size_t smb_maxcnt)
{
	return NT_STATUS_RETRY;
}

NTSTATUS schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *smbreq,
			      files_struct *fsp, const char *data,
			      off_t startpos,
			      size_t numtowrite)
{
	return NT_STATUS_RETRY;
}

bool cancel_smb2_aio(struct smb_request *smbreq)
{
	return false;
}

NTSTATUS schedule_smb2_aio_read(connection_struct *conn,
                                struct smb_request *smbreq,
                                files_struct *fsp,
				TALLOC_CTX *ctx,
				DATA_BLOB *preadbuf,
                                off_t startpos,
                                size_t smb_maxcnt)
{
	return NT_STATUS_RETRY;
}

NTSTATUS schedule_aio_smb2_write(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				uint64_t in_offset,
				DATA_BLOB in_data,
				bool write_through)
{
	return NT_STATUS_RETRY;
}

void aio_fsp_close(files_struct *fsp)
{
	return;
}

int wait_for_aio_completion(files_struct *fsp)
{
	return 0;
}

void smbd_aio_complete_mid(uint64_t mid);

#endif

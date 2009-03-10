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

#if defined(WITH_AIO)

/* The signal we'll use to signify aio done. */
#ifndef RT_SIGNAL_AIO
#ifndef SIGRTMIN
#define SIGRTMIN	NSIG
#endif
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
	bool read_req;
	uint16 mid;
	char *inbuf;
	char *outbuf;
};

static struct aio_extra *aio_list_head;

/****************************************************************************
 Create the extended aio struct we must keep around for the lifetime
 of the aio_read call.
*****************************************************************************/

static struct aio_extra *create_aio_ex_read(files_struct *fsp, size_t buflen,
					    uint16 mid)
{
	struct aio_extra *aio_ex = SMB_MALLOC_P(struct aio_extra);

	if (!aio_ex) {
		return NULL;
	}
	ZERO_STRUCTP(aio_ex);
	/* The output buffer stored in the aio_ex is the start of
	   the smb return buffer. The buffer used in the acb
	   is the start of the reply data portion of that buffer. */
	aio_ex->outbuf = SMB_MALLOC_ARRAY(char, buflen);
	if (!aio_ex->outbuf) {
		SAFE_FREE(aio_ex);
		return NULL;
	}
	DLIST_ADD(aio_list_head, aio_ex);
	aio_ex->fsp = fsp;
	aio_ex->read_req = True;
	aio_ex->mid = mid;
	return aio_ex;
}

/****************************************************************************
 Create the extended aio struct we must keep around for the lifetime
 of the aio_write call.
*****************************************************************************/

static struct aio_extra *create_aio_ex_write(files_struct *fsp,
					     size_t inbuflen,
					     size_t outbuflen,
					     uint16 mid)
{
	struct aio_extra *aio_ex = SMB_MALLOC_P(struct aio_extra);

	if (!aio_ex) {
		return NULL;
	}
	ZERO_STRUCTP(aio_ex);

	/* We need space for an output reply of outbuflen bytes. */
	aio_ex->outbuf = SMB_MALLOC_ARRAY(char, outbuflen);
	if (!aio_ex->outbuf) {
		SAFE_FREE(aio_ex);
		return NULL;
	}

	if (!(aio_ex->inbuf = SMB_MALLOC_ARRAY(char, inbuflen))) {
		SAFE_FREE(aio_ex->outbuf);
		SAFE_FREE(aio_ex);
		return NULL;
	}

	DLIST_ADD(aio_list_head, aio_ex);
	aio_ex->fsp = fsp;
	aio_ex->read_req = False;
	aio_ex->mid = mid;
	return aio_ex;
}

/****************************************************************************
 Delete the extended aio struct.
*****************************************************************************/

static void delete_aio_ex(struct aio_extra *aio_ex)
{
	DLIST_REMOVE(aio_list_head, aio_ex);
	SAFE_FREE(aio_ex->inbuf);
	SAFE_FREE(aio_ex->outbuf);
	SAFE_FREE(aio_ex);
}

/****************************************************************************
 Given the aiocb struct find the extended aio struct containing it.
*****************************************************************************/

static struct aio_extra *find_aio_ex(uint16 mid)
{
	struct aio_extra *p;

	for( p = aio_list_head; p; p = p->next) {
		if (mid == p->mid) {
			return p;
		}
	}
	return NULL;
}

/****************************************************************************
 We can have these many aio buffers in flight.
*****************************************************************************/

static int aio_pending_size;
static sig_atomic_t signals_received;
static int outstanding_aio_calls;
static uint16 *aio_pending_array;

/****************************************************************************
 Signal handler when an aio request completes.
*****************************************************************************/

void aio_request_done(uint16_t mid)
{
	if (signals_received < aio_pending_size) {
		aio_pending_array[signals_received] = mid;
		signals_received++;
	}
	/* Else signal is lost. */
}

static void signal_handler(int sig, siginfo_t *info, void *unused)
{
	aio_request_done(info->si_value.sival_int);
	sys_select_signal(RT_SIGNAL_AIO);
}

/****************************************************************************
 Is there a signal waiting ?
*****************************************************************************/

bool aio_finished(void)
{
	return (signals_received != 0);
}

/****************************************************************************
 Initialize the signal handler for aio read/write.
*****************************************************************************/

void initialize_async_io_handler(void)
{
	struct sigaction act;

	aio_pending_size = lp_maxmux();
	aio_pending_array = SMB_MALLOC_ARRAY(uint16, aio_pending_size);
	SMB_ASSERT(aio_pending_array != NULL);

	ZERO_STRUCT(act);
	act.sa_sigaction = signal_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset( &act.sa_mask );
	if (sigaction(RT_SIGNAL_AIO, &act, NULL) != 0) {
                DEBUG(0,("Failed to setup RT_SIGNAL_AIO handler\n"));
        }

	/* the signal can start off blocked due to a bug in bash */
	BlockSignals(False, RT_SIGNAL_AIO);
}

/****************************************************************************
 Set up an aio request from a SMBreadX call.
*****************************************************************************/

bool schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt)
{
	struct aio_extra *aio_ex;
	SMB_STRUCT_AIOCB *a;
	size_t bufsize;
	size_t min_aio_read_size = lp_aio_read_size(SNUM(conn));

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return false;
	}

	if ((!min_aio_read_size || (smb_maxcnt < min_aio_read_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a read for aio request. */
		DEBUG(10,("schedule_aio_read_and_X: read size (%u) too small "
			  "for minimum aio_read of %u\n",
			  (unsigned int)smb_maxcnt,
			  (unsigned int)min_aio_read_size ));
		return False;
	}

	/* Only do this on non-chained and non-chaining reads not using the
	 * write cache. */
        if (chain_size !=0 || (CVAL(req->inbuf,smb_vwv0) != 0xFF)
	    || (lp_write_cache_size(SNUM(conn)) != 0) ) {
		return False;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(10,("schedule_aio_read_and_X: Already have %d aio "
			  "activities outstanding.\n",
			  outstanding_aio_calls ));
		return False;
	}

	/* The following is safe from integer wrap as we've already checked
	   smb_maxcnt is 128k or less. Wct is 12 for read replies */

	bufsize = smb_size + 12 * 2 + smb_maxcnt;

	if ((aio_ex = create_aio_ex_read(fsp, bufsize, req->mid)) == NULL) {
		DEBUG(10,("schedule_aio_read_and_X: malloc fail.\n"));
		return False;
	}

	construct_reply_common((char *)req->inbuf, aio_ex->outbuf);
	srv_set_message(aio_ex->outbuf, 12, 0, True);
	SCVAL(aio_ex->outbuf,smb_vwv0,0xFF); /* Never a chained reply. */

	a = &aio_ex->acb;

	/* Now set up the aio record for the read call. */
	
	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = smb_buf(aio_ex->outbuf);
	a->aio_nbytes = smb_maxcnt;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_int = aio_ex->mid;

	become_root();
	if (SMB_VFS_AIO_READ(fsp,a) == -1) {
		DEBUG(0,("schedule_aio_read_and_X: aio_read failed. "
			 "Error %s\n", strerror(errno) ));
		delete_aio_ex(aio_ex);
		unbecome_root();
		return False;
	}
	unbecome_root();

	DEBUG(10,("schedule_aio_read_and_X: scheduled aio_read for file %s, "
		  "offset %.0f, len = %u (mid = %u)\n",
		  fsp->fsp_name, (double)startpos, (unsigned int)smb_maxcnt,
		  (unsigned int)aio_ex->mid ));

	srv_defer_sign_response(aio_ex->mid);
	outstanding_aio_calls++;
	return True;
}

/****************************************************************************
 Set up an aio request from a SMBwriteX call.
*****************************************************************************/

bool schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, char *data,
			      SMB_OFF_T startpos,
			      size_t numtowrite)
{
	struct aio_extra *aio_ex;
	SMB_STRUCT_AIOCB *a;
	size_t inbufsize, outbufsize;
	bool write_through = BITSETW(req->inbuf+smb_vwv7,0);
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));

	if (fsp->base_fsp != NULL) {
		/* No AIO on streams yet */
		DEBUG(10, ("AIO on streams not yet supported\n"));
		return false;
	}

	if ((!min_aio_write_size || (numtowrite < min_aio_write_size))
	    && !SMB_VFS_AIO_FORCE(fsp)) {
		/* Too small a write for aio request. */
		DEBUG(10,("schedule_aio_write_and_X: write size (%u) too "
			  "small for minimum aio_write of %u\n",
			  (unsigned int)numtowrite,
			  (unsigned int)min_aio_write_size ));
		return False;
	}

	/* Only do this on non-chained and non-chaining reads not using the
	 * write cache. */
        if (chain_size !=0 || (CVAL(req->inbuf,smb_vwv0) != 0xFF)
	    || (lp_write_cache_size(SNUM(conn)) != 0) ) {
		return False;
	}

	if (outstanding_aio_calls >= aio_pending_size) {
		DEBUG(3,("schedule_aio_write_and_X: Already have %d aio "
			 "activities outstanding.\n",
			  outstanding_aio_calls ));
		DEBUG(10,("schedule_aio_write_and_X: failed to schedule "
			  "aio_write for file %s, offset %.0f, len = %u "
			  "(mid = %u)\n",
			  fsp->fsp_name, (double)startpos,
			  (unsigned int)numtowrite,
			  (unsigned int)req->mid ));
		return False;
	}

	inbufsize =  smb_len(req->inbuf) + 4;
	reply_outbuf(req, 6, 0);
	outbufsize = smb_len(req->outbuf) + 4;
	if (!(aio_ex = create_aio_ex_write(fsp, inbufsize, outbufsize,
					   req->mid))) {
		DEBUG(0,("schedule_aio_write_and_X: malloc fail.\n"));
		return False;
	}

	/* Copy the SMB header already setup in outbuf. */
	memcpy(aio_ex->inbuf, req->inbuf, inbufsize);

	/* Copy the SMB header already setup in outbuf. */
	memcpy(aio_ex->outbuf, req->outbuf, outbufsize);
	TALLOC_FREE(req->outbuf);
	SCVAL(aio_ex->outbuf,smb_vwv0,0xFF); /* Never a chained reply. */

	a = &aio_ex->acb;

	/* Now set up the aio record for the write call. */
	
	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = aio_ex->inbuf + (PTR_DIFF(data, req->inbuf));
	a->aio_nbytes = numtowrite;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_int = aio_ex->mid;

	become_root();
	if (SMB_VFS_AIO_WRITE(fsp,a) == -1) {
		DEBUG(3,("schedule_aio_wrote_and_X: aio_write failed. "
			 "Error %s\n", strerror(errno) ));
		delete_aio_ex(aio_ex);
		unbecome_root();
		return False;
	}
	unbecome_root();
	
	release_level_2_oplocks_on_change(fsp);

	if (!write_through && !lp_syncalways(SNUM(fsp->conn))
	    && fsp->aio_write_behind) {
		/* Lie to the client and immediately claim we finished the
		 * write. */
	        SSVAL(aio_ex->outbuf,smb_vwv2,numtowrite);
                SSVAL(aio_ex->outbuf,smb_vwv4,(numtowrite>>16)&1);
		show_msg(aio_ex->outbuf);
		if (!srv_send_smb(smbd_server_fd(),aio_ex->outbuf,
				IS_CONN_ENCRYPTED(fsp->conn))) {
			exit_server_cleanly("handle_aio_write: srv_send_smb "
					    "failed.");
		}
		DEBUG(10,("schedule_aio_write_and_X: scheduled aio_write "
			  "behind for file %s\n", fsp->fsp_name ));
	} else {
		srv_defer_sign_response(aio_ex->mid);
	}
	outstanding_aio_calls++;

	DEBUG(10,("schedule_aio_write_and_X: scheduled aio_write for file "
		  "%s, offset %.0f, len = %u (mid = %u) "
		  "outstanding_aio_calls = %d\n",
		  fsp->fsp_name, (double)startpos, (unsigned int)numtowrite,
		  (unsigned int)aio_ex->mid, outstanding_aio_calls ));

	return True;
}


/****************************************************************************
 Complete the read and return the data or error back to the client.
 Returns errno or zero if all ok.
*****************************************************************************/

static int handle_aio_read_complete(struct aio_extra *aio_ex)
{
	int ret = 0;
	int outsize;
	char *outbuf = aio_ex->outbuf;
	char *data = smb_buf(outbuf);
	ssize_t nread = SMB_VFS_AIO_RETURN(aio_ex->fsp,&aio_ex->acb);

	if (nread < 0) {
		/* We're relying here on the fact that if the fd is
		   closed then the aio will complete and aio_return
		   will return an error. Hopefully this is
		   true.... JRA. */

		/* If errno is ECANCELED then don't return anything to the
		 * client. */
		if (errno == ECANCELED) {
			srv_cancel_sign_response(aio_ex->mid, false);
			return 0;
		}

		DEBUG( 3,( "handle_aio_read_complete: file %s nread == -1. "
			   "Error = %s\n",
			   aio_ex->fsp->fsp_name, strerror(errno) ));

		ret = errno;
		ERROR_NT(map_nt_error_from_unix(ret));
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
			    aio_ex->fsp->fsp_name,
			    (int)aio_ex->acb.aio_nbytes, (int)nread ) );

	}
	smb_setlen(outbuf,outsize - 4);
	show_msg(outbuf);
	if (!srv_send_smb(smbd_server_fd(),outbuf,
			IS_CONN_ENCRYPTED(aio_ex->fsp->conn))) {
		exit_server_cleanly("handle_aio_read_complete: srv_send_smb "
				    "failed.");
	}

	DEBUG(10,("handle_aio_read_complete: scheduled aio_read completed "
		  "for file %s, offset %.0f, len = %u\n",
		  aio_ex->fsp->fsp_name, (double)aio_ex->acb.aio_offset,
		  (unsigned int)nread ));

	return ret;
}

/****************************************************************************
 Complete the write and return the data or error back to the client.
 Returns errno or zero if all ok.
*****************************************************************************/

static int handle_aio_write_complete(struct aio_extra *aio_ex)
{
	int ret = 0;
	files_struct *fsp = aio_ex->fsp;
	char *outbuf = aio_ex->outbuf;
	ssize_t numtowrite = aio_ex->acb.aio_nbytes;
	ssize_t nwritten = SMB_VFS_AIO_RETURN(fsp,&aio_ex->acb);

	if (fsp->aio_write_behind) {
		if (nwritten != numtowrite) {
			if (nwritten == -1) {
				DEBUG(5,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Error %s\n",
					 fsp->fsp_name, strerror(errno) ));
				ret = errno;
			} else {
				DEBUG(0,("handle_aio_write_complete: "
					 "aio_write_behind failed ! File %s "
					 "is corrupt ! Wanted %u bytes but "
					 "only wrote %d\n", fsp->fsp_name,
					 (unsigned int)numtowrite,
					 (int)nwritten ));
				ret = EIO;
			}
		} else {
			DEBUG(10,("handle_aio_write_complete: "
				  "aio_write_behind completed for file %s\n",
				  fsp->fsp_name ));
		}
		return 0;
	}

	/* We don't need outsize or set_message here as we've already set the
	   fixed size length when we set up the aio call. */

	if(nwritten == -1) {
		DEBUG( 3,( "handle_aio_write: file %s wanted %u bytes. "
			   "nwritten == %d. Error = %s\n",
			   fsp->fsp_name, (unsigned int)numtowrite,
			   (int)nwritten, strerror(errno) ));

		/* If errno is ECANCELED then don't return anything to the
		 * client. */
		if (errno == ECANCELED) {
			srv_cancel_sign_response(aio_ex->mid, false);
			return 0;
		}

		ret = errno;
		ERROR_BOTH(map_nt_error_from_unix(ret), ERRHRD, ERRdiskfull);
		srv_set_message(outbuf,0,0,true);
        } else {
		bool write_through = BITSETW(aio_ex->inbuf+smb_vwv7,0);
		NTSTATUS status;

        	SSVAL(outbuf,smb_vwv2,nwritten);
		SSVAL(outbuf,smb_vwv4,(nwritten>>16)&1);
		if (nwritten < (ssize_t)numtowrite) {
			SCVAL(outbuf,smb_rcls,ERRHRD);
			SSVAL(outbuf,smb_err,ERRdiskfull);
		}

		DEBUG(3,("handle_aio_write: fnum=%d num=%d wrote=%d\n",
			 fsp->fnum, (int)numtowrite, (int)nwritten));
		status = sync_file(fsp->conn,fsp, write_through);
		if (!NT_STATUS_IS_OK(status)) {
			ret = errno;
			ERROR_BOTH(map_nt_error_from_unix(ret),
				   ERRHRD, ERRdiskfull);
			srv_set_message(outbuf,0,0,true);
                	DEBUG(5,("handle_aio_write: sync_file for %s returned %s\n",
				fsp->fsp_name, nt_errstr(status) ));
		}

		aio_ex->fsp->fh->pos = aio_ex->acb.aio_offset + nwritten;
	}

	show_msg(outbuf);
	if (!srv_send_smb(smbd_server_fd(),outbuf,IS_CONN_ENCRYPTED(fsp->conn))) {
		exit_server_cleanly("handle_aio_write: srv_send_smb failed.");
	}

	DEBUG(10,("handle_aio_write_complete: scheduled aio_write completed "
		  "for file %s, offset %.0f, requested %u, written = %u\n",
		  fsp->fsp_name, (double)aio_ex->acb.aio_offset,
		  (unsigned int)numtowrite, (unsigned int)nwritten ));

	return ret;
}

/****************************************************************************
 Handle any aio completion. Returns True if finished (and sets *perr if err
 was non-zero), False if not.
*****************************************************************************/

static bool handle_aio_completed(struct aio_extra *aio_ex, int *perr)
{
	int err;

	if(!aio_ex) {
	        DEBUG(3, ("handle_aio_completed: Non-existing aio_ex passed\n"));
		return false;
	}

	/* Ensure the operation has really completed. */
	if (SMB_VFS_AIO_ERROR(aio_ex->fsp, &aio_ex->acb) == EINPROGRESS) {
		DEBUG(10,( "handle_aio_completed: operation mid %u still in "
			   "process for file %s\n",
			   aio_ex->mid, aio_ex->fsp->fsp_name ));
		return False;
	}

	if (aio_ex->read_req) {
		err = handle_aio_read_complete(aio_ex);
	} else {
		err = handle_aio_write_complete(aio_ex);
	}

	if (err) {
		*perr = err; /* Only save non-zero errors. */
	}

	return True;
}

/****************************************************************************
 Handle any aio completion inline.
 Returns non-zero errno if fail or zero if all ok.
*****************************************************************************/

int process_aio_queue(void)
{
	int i;
	int ret = 0;

	BlockSignals(True, RT_SIGNAL_AIO);

	DEBUG(10,("process_aio_queue: signals_received = %d\n",
		  (int)signals_received));
	DEBUG(10,("process_aio_queue: outstanding_aio_calls = %d\n",
		  outstanding_aio_calls));

	if (!signals_received) {
		BlockSignals(False, RT_SIGNAL_AIO);
		return 0;
	}

	/* Drain all the complete aio_reads. */
	for (i = 0; i < signals_received; i++) {
		uint16 mid = aio_pending_array[i];
		files_struct *fsp = NULL;
		struct aio_extra *aio_ex = find_aio_ex(mid);

		if (!aio_ex) {
			DEBUG(3,("process_aio_queue: Can't find record to "
				 "match mid %u.\n", (unsigned int)mid));
			srv_cancel_sign_response(mid, false);
			continue;
		}

		fsp = aio_ex->fsp;
		if (fsp == NULL) {
			/* file was closed whilst I/O was outstanding. Just
			 * ignore. */
			DEBUG( 3,( "process_aio_queue: file closed whilst "
				   "aio outstanding.\n"));
			srv_cancel_sign_response(mid, false);
			continue;
		}

		if (!handle_aio_completed(aio_ex, &ret)) {
			continue;
		}

		delete_aio_ex(aio_ex);
	}

	outstanding_aio_calls -= signals_received;
	signals_received = 0;
	BlockSignals(False, RT_SIGNAL_AIO);
	return ret;
}

/****************************************************************************
 We're doing write behind and the client closed the file. Wait up to 30
 seconds (my arbitrary choice) for the aio to complete. Return 0 if all writes
 completed, errno to return if not.
*****************************************************************************/

#define SMB_TIME_FOR_AIO_COMPLETE_WAIT 29

int wait_for_aio_completion(files_struct *fsp)
{
	struct aio_extra *aio_ex;
	const SMB_STRUCT_AIOCB **aiocb_list;
	int aio_completion_count = 0;
	time_t start_time = time(NULL);
	int seconds_left;

	for (seconds_left = SMB_TIME_FOR_AIO_COMPLETE_WAIT;
	     seconds_left >= 0;) {
		int err = 0;
		int i;
		struct timespec ts;

		aio_completion_count = 0;
		for( aio_ex = aio_list_head; aio_ex; aio_ex = aio_ex->next) {
			if (aio_ex->fsp == fsp) {
				aio_completion_count++;
			}
		}

		if (!aio_completion_count) {
			return 0;
		}

		DEBUG(3,("wait_for_aio_completion: waiting for %d aio events "
			 "to complete.\n", aio_completion_count ));

		aiocb_list = SMB_MALLOC_ARRAY(const SMB_STRUCT_AIOCB *,
					      aio_completion_count);
		if (!aiocb_list) {
			return ENOMEM;
		}

		for( i = 0, aio_ex = aio_list_head;
		     aio_ex;
		     aio_ex = aio_ex->next) {
			if (aio_ex->fsp == fsp) {
				aiocb_list[i++] = &aio_ex->acb;
			}
		}

		/* Now wait up to seconds_left for completion. */
		ts.tv_sec = seconds_left;
		ts.tv_nsec = 0;

		DEBUG(10,("wait_for_aio_completion: %d events, doing a wait "
			  "of %d seconds.\n",
			  aio_completion_count, seconds_left ));

		err = SMB_VFS_AIO_SUSPEND(fsp, aiocb_list,
					  aio_completion_count, &ts);

		DEBUG(10,("wait_for_aio_completion: returned err = %d, "
			  "errno = %s\n", err, strerror(errno) ));
		
		if (err == -1 && errno == EAGAIN) {
			DEBUG(0,("wait_for_aio_completion: aio_suspend timed "
				 "out waiting for %d events after a wait of "
				 "%d seconds\n", aio_completion_count,
				 seconds_left));
			/* Timeout. */
			cancel_aio_by_fsp(fsp);
			SAFE_FREE(aiocb_list);
			return EIO;
		}

		/* One or more events might have completed - process them if
		 * so. */
		for( i = 0; i < aio_completion_count; i++) {
			uint16 mid = aiocb_list[i]->aio_sigevent.sigev_value.sival_int;

			aio_ex = find_aio_ex(mid);

			if (!aio_ex) {
				DEBUG(0, ("wait_for_aio_completion: mid %u "
					  "doesn't match an aio record\n",
					  (unsigned int)mid ));
				continue;
			}

			if (!handle_aio_completed(aio_ex, &err)) {
				continue;
			}
			delete_aio_ex(aio_ex);
		}

		SAFE_FREE(aiocb_list);
		seconds_left = SMB_TIME_FOR_AIO_COMPLETE_WAIT
			- (time(NULL) - start_time);
	}

	/* We timed out - we don't know why. Return ret if already an error,
	 * else EIO. */
	DEBUG(10,("wait_for_aio_completion: aio_suspend timed out waiting "
		  "for %d events\n",
		  aio_completion_count));

	return EIO;
}

/****************************************************************************
 Cancel any outstanding aio requests. The client doesn't care about the reply.
*****************************************************************************/

void cancel_aio_by_fsp(files_struct *fsp)
{
	struct aio_extra *aio_ex;

	for( aio_ex = aio_list_head; aio_ex; aio_ex = aio_ex->next) {
		if (aio_ex->fsp == fsp) {
			/* Don't delete the aio_extra record as we may have
			   completed and don't yet know it. Just do the
			   aio_cancel call and return. */
			SMB_VFS_AIO_CANCEL(fsp, &aio_ex->acb);
			aio_ex->fsp = NULL; /* fsp will be closed when we
					     * return. */
		}
	}
}

#else
bool aio_finished(void)
{
	return False;
}

void initialize_async_io_handler(void)
{
}

int process_aio_queue(void)
{
	return False;
}

bool schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt)
{
	return False;
}

bool schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, char *data,
			      SMB_OFF_T startpos,
			      size_t numtowrite)
{
	return False;
}

void cancel_aio_by_fsp(files_struct *fsp)
{
}

int wait_for_aio_completion(files_struct *fsp)
{
	return ENOSYS;
}
#endif

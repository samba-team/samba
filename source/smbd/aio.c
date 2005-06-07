/*
   Unix SMB/Netbios implementation.
   Version 3.0
   async_io read handling using POSIX async io.
   Copyright (C) Jeremy Allison 2005.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* #define HAVE_POSIX_ASYNC_IO 1 */
#if HAVE_POSIX_ASYNC_IO

/* The signal we'll use to signify aio done. */
#ifndef RT_SIGNAL_AIO
#define RT_SIGNAL_AIO (SIGRTMIN+3)
#endif

/* Until we have detection of 64-bit aio structs... */
#define SMB_STRUCT_AIOCB struct aiocb

/****************************************************************************
 The buffer we keep around whilst an aio request is in process.
*****************************************************************************/

struct aio_extra {
	struct aio_extra *next, *prev;
	SMB_STRUCT_AIOCB acb;
	files_struct *fsp;
	BOOL read_req;
	uint16 mid;
	char *buf;
};

static struct aio_extra *aio_list_head;

/****************************************************************************
 Create the extended aio struct we must keep around for the lifetime
 of the aio call.
*****************************************************************************/

static struct aio_extra *create_aio_ex_read(files_struct *fsp, size_t buflen, uint16 mid)
{
	struct aio_extra *aio_ex = SMB_MALLOC_P(struct aio_extra);

	if (!aio_ex) {
		return NULL;
	}
	ZERO_STRUCTP(aio_ex);
	/* The buf stored in the aio_ex is the start of
	   the smb return buffer. The buffer used in the acb
	   is the start of the reply data portion of that buffer. */
	aio_ex->buf = SMB_MALLOC_ARRAY(char, buflen);
	if (!aio_ex->buf) {
		SAFE_FREE(aio_ex);
		return NULL;
	}
	DLIST_ADD(aio_list_head, aio_ex);
	aio_ex->fsp = fsp;
	aio_ex->read_req = True;
	return aio_ex;
}

/****************************************************************************
 Delete the extended aio struct.
*****************************************************************************/

static void delete_aio_ex(struct aio_extra *aio_ex)
{
	DLIST_REMOVE(aio_list_head, aio_ex);
	SAFE_FREE(aio_ex->buf);
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

#define AIO_PENDING_SIZE 10
static sig_atomic_t signals_received;
static int outstanding_aio_calls;
static uint16 aio_pending_array[AIO_PENDING_SIZE];

/****************************************************************************
 Signal handler when an aio request completes.
*****************************************************************************/

static void signal_handler(int sig, siginfo_t *info, void *unused)
{
	if (signals_received < AIO_PENDING_SIZE - 1) {
		aio_pending_array[signals_received] = *(uint16 *)(info->si_value.sival_ptr);
		signals_received++;
	} /* Else signal is lost. */
	sys_select_signal();
}


/****************************************************************************
 Initialize the signal handler for aio read/write.
*****************************************************************************/

void initialize_async_io_handler(void)
{
	struct sigaction act;

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

BOOL schedule_aio_read_and_X(connection_struct *conn,
			     char *inbuf, char *outbuf,
			     int length, int len_outbuf,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt)
{
	struct aio_extra *aio_ex;
	SMB_STRUCT_AIOCB *a;
	size_t bufsize;
	size_t min_aio_read_size = lp_aio_read_size(SNUM(conn));

	if (min_aio_read_size && (smb_maxcnt < min_aio_read_size)) {
		/* Too small a read for aio request. */
		DEBUG(10,("schedule_aio_read_and_X: read size (%u) too small "
			  "for minimum aio_read of %u\n",
			  (unsigned int)smb_maxcnt,
			  (unsigned int)min_aio_read_size ));
		return False;
	}

	if (outstanding_aio_calls >= AIO_PENDING_SIZE) {
		DEBUG(10,("schedule_aio_read_and_X: Already have %d aio activities outstanding.\n",
			  outstanding_aio_calls ));
		return False;
	}

	/* The following is safe from integer wrap as we've already
	   checked smb_maxcnt is 128k or less. */
	bufsize = PTR_DIFF(smb_buf(outbuf),outbuf) + smb_maxcnt;

	if ((aio_ex = create_aio_ex_read(fsp, bufsize, SVAL(inbuf,smb_mid))) == NULL) {
		DEBUG(10,("schedule_aio_read_and_X: malloc fail.\n"));
		return False;
	}

	/* Copy the SMB header already setup in outbuf. */
	memcpy(aio_ex->buf, outbuf, smb_size);

	a = &aio_ex->acb;

	/* Now set up the aio record. */
	
	a->aio_fildes = fsp->fd;
	a->aio_buf = smb_buf(aio_ex->buf);
	a->aio_nbytes = smb_maxcnt;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = (void *)&aio_ex->mid;

	if (aio_read(a) == -1) {
		DEBUG(0,("schedule_aio_read_and_X: aio_read failed. Error %s\n",
			strerror(errno) ));
		delete_aio_ex(aio_ex);
		return False;
	}

	DEBUG(10,("schedule_aio_read_and_X: scheduled aio_read for file %s, offset %.0f, len = %u (mid = %u)\n",
		fsp->fsp_name, (double)startpos, (unsigned int)smb_maxcnt, (unsigned int)aio_ex->mid ));

	srv_defer_sign_response(aio_ex->mid);
	outstanding_aio_calls++;
	return True;
}

/****************************************************************************
 Set up an aio request from a SMBwriteX call.
*****************************************************************************/

BOOL schedule_aio_write_and_X(connection_struct *conn,
				char *inbuf, char *outbuf,
				int length, int len_outbuf,
				files_struct *fsp, char *data,
				SMB_OFF_T startpos,
				size_t numtowrite)
{
	struct aio_extra *aio_ex;
	SMB_STRUCT_AIOCB *a;
	size_t bufsize;
	size_t min_aio_write_size = lp_aio_write_size(SNUM(conn));

	if (min_aio_write_size && (numtowrite < min_aio_write_size)) {
		/* Too small a write for aio request. */
		DEBUG(10,("schedule_aio_write_and_X: write size (%u) too small "
			  "for minimum aio_write of %u\n",
			  (unsigned int)numtowrite,
			  (unsigned int)min_aio_write_size ));
		return False;
	}

	if (outstanding_aio_calls >= AIO_PENDING_SIZE) {
		DEBUG(10,("schedule_aio_write_and_X: Already have %d aio activities outstanding.\n",
			  outstanding_aio_calls ));
		return False;
	}

#if 0
	/* The following is safe from integer wrap as we've already
	   checked smb_maxcnt is 128k or less. */
	bufsize = PTR_DIFF(smb_buf(outbuf),outbuf) + smb_maxcnt;

	if ((aio_ex = create_aio_ex_read(fsp, bufsize, SVAL(inbuf,smb_mid))) == NULL) {
		DEBUG(10,("schedule_aio_read_and_X: malloc fail.\n"));
		return False;
	}

	/* Copy the SMB header already setup in outbuf. */
	memcpy(aio_ex->buf, outbuf, smb_size);

	a = &aio_ex->acb;

	/* Now set up the aio record. */
	
	a->aio_fildes = fsp->fd;
	a->aio_buf = smb_buf(aio_ex->buf);
	a->aio_nbytes = smb_maxcnt;
	a->aio_offset = startpos;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = (void *)&aio_ex->mid;

	if (aio_read(a) == -1) {
		DEBUG(0,("schedule_aio_read_and_X: aio_read failed. Error %s\n",
			strerror(errno) ));
		delete_aio_ex(aio_ex);
		return False;
	}

	DEBUG(10,("schedule_aio_read_and_X: scheduled aio_read for file %s, offset %.0f, len = %u (mid = %u)\n",
		fsp->fsp_name, (double)startpos, (unsigned int)smb_maxcnt, (unsigned int)aio_ex->mid ));

	srv_defer_sign_response(aio_ex->mid);
	return True;
#else
	return False;
#endif
}


/****************************************************************************
 Complete the read and return the data or error back to the client.
*****************************************************************************/

static void handle_aio_read_complete(struct aio_extra *aio_ex)
{
	int outsize;
	char *outbuf = aio_ex->buf;
	char *data = smb_buf(outbuf);
	ssize_t nread = aio_return(&aio_ex->acb);

	if (nread < 0) {
		/* We're relying here on the fact that if the fd is
		   closed then the aio will complete and aio_return
		   will return an error. Hopefully this is
		   true.... JRA. */
		DEBUG( 3,( "handle_aio_read_complete: file %s nread == -1. Error = %s\n",
			   aio_ex->fsp->fsp_name, strerror(errno) ));
		outsize = (UNIXERROR(ERRDOS,ERRnoaccess));
	} else {
		outsize = set_message(outbuf,12,nread,False);
		SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be * -1. */
		SSVAL(outbuf,smb_vwv5,nread);
		SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
		SSVAL(outbuf,smb_vwv7,((nread >> 16) & 1));
		SSVAL(smb_buf(outbuf),-2,nread);

		DEBUG( 3, ( "handle_aio_read_complete file %s max=%d nread=%d\n",
			aio_ex->fsp->fsp_name,
			aio_ex->acb.aio_nbytes, (int)nread ) );

	}
	smb_setlen(outbuf,outsize - 4);
	show_msg(outbuf);
	if (!send_smb(smbd_server_fd(),outbuf)) {
		exit_server("handle_aio_read_complete: send_smb failed.");
	}

	DEBUG(10,("handle_aio_read_complete: scheduled aio_read completed for file %s, offset %.0f, len = %u\n",
		aio_ex->fsp->fsp_name, (double)aio_ex->acb.aio_offset, (unsigned int)nread ));
}

/****************************************************************************
 Complete the write and return the data or error back to the client.
*****************************************************************************/

static void handle_aio_write_complete(struct aio_extra *aio_ex)
{
}

/****************************************************************************
 Handle any aio completion inline.
*****************************************************************************/

BOOL process_aio_queue(void)
{
	int i;

	if (!signals_received) {
		return False;
	}

	BlockSignals(True, RT_SIGNAL_AIO);

	DEBUG(10,("process_aio_queue: signals_received = %d\n", (int)signals_received));

	/* Drain all the complete aio_reads. */
	for (i = 0; i < signals_received; i++) {
		uint16 mid = aio_pending_array[i];
		struct aio_extra *aio_ex = find_aio_ex(mid);

		if (!aio_ex) {
			DEBUG(0,("process_aio_queue: Can't find record to match mid %u.\n",
				(unsigned int)mid));
			continue;
		}

		if (aio_ex->read_req) {
			handle_aio_read_complete(aio_ex);
		} else {
			handle_aio_write_complete(aio_ex);
		}
		delete_aio_ex(aio_ex);
	}
	outstanding_aio_calls -= signals_received;
	signals_received = 0;
	BlockSignals(False, RT_SIGNAL_AIO);
	return True;
}

#else
void initialize_async_io_handler(void)
{
}

BOOL process_aio_queue(void)
{
	return False;
}

BOOL schedule_aio_read_and_X(connection_struct *conn,
			     char *inbuf, char *outbuf,
			     int length, int len_outbuf,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt)
{
	return False;
}

BOOL schedule_aio_write_and_X(connection_struct *conn,
                                char *inbuf, char *outbuf,
                                int length, int len_outbuf,
                                files_struct *fsp, char *data,
                                SMB_OFF_T startpos,
                                size_t numtowrite)
{
	return False;
}
#endif

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

#if HAVE_POSIX_ASYNC_IO

#define RT_SIGNAL_AIO (SIGRTMIN+3)
#define AIO_PENDING_SIZE 10
static sig_atomic_t signals_received;
static int outstanding_aio_reads;

struct aio_extra {
	struct aio_extra *next, *prev;
	struct aiocb acb;
	char *buf;
	int fnum;
};

struct aio_extra aio_list_head;

static struct aio_extra *create_aio_ex(void)
{
	struct aio_extra *aio_ex = MALLOC_P();
}

static void delete_aio_ex(struct aio_extra *aio_ex)
{
	DLIST_REMOVE(aio_list_head, aio_ex);
	SAFE_FREE(aio_ex->buf);
}

static struct aio_extra *find_aio_ex(struct aiocb *pacb)
{
	struct aio_extra *p;

	for( p = aio_list_head; p; p = p->next) {
		if (pacb == p->acb) {
			return p;
		}
	}
	return NULL;
}

static struct aiocb aio_pending_array[AIO_PENDING_SIZE];

static void signal_handler(int sig, siginfo_t *info, void *unused)
{
	if (signals_received < AIO_PENDING_SIZE - 1) {
		aio_pending_array[signals_received] = *(struct aiocb *)(info->si_value.sival_ptr);
		signals_received++;
	} /* Else signal is lost. */
	sys_select_signal();
}

BOOL schedule_aio_read_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length, int len_outbuf,
				files_struct *fsp, SMB_OFF_T startpos, size_t smb_maxcnt)
{
	if (outstanding_aio_reads >= AIO_PENDING_SIZE) {
		DEBUG(10,("schedule_aio_read_and_X: Already have %d aio activities outstanding.\n",
			outstanding_aio_reads ));
		return False;
	}
	srv_defer_sign_response(mid);
	return False;
}

void process_aio_queue(void)
{
	int i;

	if (!signals_received) {
		return;
	}

	BlockSignals(True, RT_SIGNAL_NOTIFY);

	/* Drain all the complete aio_reads. */
	for (i = 0; i < signals_received; i++) {
		struct aiocb *acb = &aio_pending_array[i];
		struct aio_extra aio_ex = find_aio_ex(acp);
		char *outbuf = aio_ex->buf;
		char *data = smb_buf(outbuf);
		ssize_t nread = aio_return(&aio_ex->acb);

		if (nread < 0) {
			/* We're relying here on the fact that if the fd is closed then
			   the aio will complete and aio_return will return an error. Hopefully
			   this is true.... JRA. */
			DEBUG( 3,( "process_aio_queue fnum=%d nread == -1. Error = %s\n",
				aio_ex->fnum, strerror(errno) ));
			outsize = (UNIXERROR(ERRDOS,ERRnoaccess));
		} else {
			outsize = set_message(outbuf,12,nread,False);
			SSVAL(outbuf,smb_vwv2,0xFFFF); /* Remaining - must be -1. */
			SSVAL(outbuf,smb_vwv5,nread);
			SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
			SSVAL(outbuf,smb_vwv7,((nread >> 16) & 1));
			SSVAL(smb_buf(outbuf),-2,nread);

			DEBUG( 3, ( "process_aio_queue fnum=%d max=%d nread=%d\n",
				aio_ex->fnum, (int)smb_maxcnt, (int)nread ) );

		}
		smb_setlen(outbuf,outsize - 4);
		if (!send_smb(smbd_server_fd(),outbuf)) {
			exit_server("process_smb: send_smb failed.");
		}

		delete_aio_ex(aio_ex);
	}
	outstanding_aio_reads -= signals_received;
	signals_received = 0;
	BlockSignals(False, RT_SIGNAL_NOTIFY);

}

void initialize_async_io_handler(void)
{
	struct sigaction act;

	ZERO_STRUCT(act);
	act.sa_sigaction = signal_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset( &act.sa_mask );
	if (sigaction(RT_SIGNAL_AIO, &act, NULL) != 0) {
                DEBUG(0,("Failed to setup RT_SIGNAL_AIO handler\n"));
                return NULL;
        }

	/* the signal can start off blocked due to a bug in bash */
	BlockSignals(False, RT_SIGNAL_AIO);
}
#else
void initialize_async_io_handler(void)
{
}

void process_aio_queue(void)
{
}

BOOL schedule_aio_read_and_X(connection_struct *conn, char *inbuf,char *outbuf,int length, int len_outbuf,
				files_struct *fsp, SMB_OFF_T startpos, size_t smb_maxcnt)
{
	return False;
}
#endif

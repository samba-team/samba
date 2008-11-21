/* 
   Unix SMB/CIFS implementation.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton  1997-1998.
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"

#define	PIPE		"\\PIPE\\"
#define	PIPELEN		strlen(PIPE)

#define MAX_PIPE_NAME_LEN	24

/****************************************************************************
 Reply to an open and X on a named pipe.
 This code is basically stolen from reply_open_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_open_pipe_and_X(connection_struct *conn, struct smb_request *req)
{
	const char *fname = NULL;
	char *pipe_name = NULL;
	files_struct *fsp;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_pull_req_talloc(ctx, req, &pipe_name, req->buf, STR_TERMINATE);
	if (!pipe_name) {
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpipe);
		return;
	}

	/* If the name doesn't start \PIPE\ then this is directed */
	/* at a mailslot or something we really, really don't understand, */
	/* not just something we really don't understand. */
	if ( strncmp(pipe_name,PIPE,PIPELEN) != 0 ) {
		reply_doserror(req, ERRSRV, ERRaccess);
		return;
	}

	DEBUG(4,("Opening pipe %s.\n", pipe_name));

	/* Strip \PIPE\ off the name. */
	fname = pipe_name + PIPELEN;

#if 0
	/*
	 * Hack for NT printers... JRA.
	 */
	if(should_fail_next_srvsvc_open(fname)) {
		reply_doserror(req, ERRSRV, ERRaccess);
		return;
	}
#endif

	status = np_open(req, fname, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					ERRDOS, ERRbadpipe);
			return;
		}
		reply_nterror(req, status);
		return;
	}

	/* Prepare the reply */
	reply_outbuf(req, 15, 0);

	/* Mark the opened file as an existing named pipe in message mode. */
	SSVAL(req->outbuf,smb_vwv9,2);
	SSVAL(req->outbuf,smb_vwv10,0xc700);

	SSVAL(req->outbuf, smb_vwv2, fsp->fnum);
	SSVAL(req->outbuf, smb_vwv3, 0);	/* fmode */
	srv_put_dos_date3((char *)req->outbuf, smb_vwv4, 0);	/* mtime */
	SIVAL(req->outbuf, smb_vwv6, 0);	/* size */
	SSVAL(req->outbuf, smb_vwv8, 0);	/* rmode */
	SSVAL(req->outbuf, smb_vwv11, 0x0001);

	chain_reply(req);
	return;
}

/****************************************************************************
 Reply to a write on a pipe.
****************************************************************************/

void reply_pipe_write(struct smb_request *req)
{
	files_struct *fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	size_t numtowrite = SVAL(req->vwv+1, 0);
	ssize_t nwritten;
	const uint8_t *data;

	if (!fsp_is_np(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	if (fsp->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	data = req->buf + 3;

	if (numtowrite == 0) {
		nwritten = 0;
	} else {
		NTSTATUS status;
		status = np_write(fsp, data, numtowrite, &nwritten);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			return;
		}
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0)) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		return;
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);
  
	DEBUG(3,("write-IPC pnum=%04x nwritten=%d\n", fsp->fnum,
		 (int)nwritten));

	return;
}

/****************************************************************************
 Reply to a write and X.

 This code is basically stolen from reply_write_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_pipe_write_and_X(struct smb_request *req)
{
	files_struct *fsp = file_fsp(req, SVAL(req->vwv+2, 0));
	size_t numtowrite = SVAL(req->vwv+10, 0);
	ssize_t nwritten;
	int smb_doff = SVAL(req->vwv+11, 0);
	bool pipe_start_message_raw =
		((SVAL(req->vwv+7, 0) & (PIPE_START_MESSAGE|PIPE_RAW_MODE))
		 == (PIPE_START_MESSAGE|PIPE_RAW_MODE));
	uint8_t *data;

	if (!fsp_is_np(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	if (fsp->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	data = (uint8_t *)smb_base(req->inbuf) + smb_doff;

	if (numtowrite == 0) {
		nwritten = 0;
	} else {
		NTSTATUS status;

		if(pipe_start_message_raw) {
			/*
			 * For the start of a message in named pipe byte mode,
			 * the first two bytes are a length-of-pdu field. Ignore
			 * them (we don't trust the client). JRA.
			 */
	 	       if(numtowrite < 2) {
				DEBUG(0,("reply_pipe_write_and_X: start of "
					 "message set and not enough data "
					 "sent.(%u)\n",
					 (unsigned int)numtowrite ));
				reply_unixerror(req, ERRDOS, ERRnoaccess);
				return;
			}

			data += 2;
			numtowrite -= 2;
		}                        
		status = np_write(fsp, data, numtowrite, &nwritten);
		if (!NT_STATUS_IS_OK(status)) {
			reply_nterror(req, status);
			return;
		}
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0)) {
		reply_unixerror(req, ERRDOS,ERRnoaccess);
		return;
	}

	reply_outbuf(req, 6, 0);

	nwritten = (pipe_start_message_raw ? nwritten + 2 : nwritten);
	SSVAL(req->outbuf,smb_vwv2,nwritten);
  
	DEBUG(3,("writeX-IPC pnum=%04x nwritten=%d\n", fsp->fnum,
		 (int)nwritten));

	chain_reply(req);
}

/****************************************************************************
 Reply to a read and X.
 This code is basically stolen from reply_read_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_pipe_read_and_X(struct smb_request *req)
{
	files_struct *fsp = file_fsp(req, SVAL(req->vwv+0, 0));
	int smb_maxcnt = SVAL(req->vwv+5, 0);
	int smb_mincnt = SVAL(req->vwv+6, 0);
	ssize_t nread;
	uint8_t *data;
	bool unused;
	NTSTATUS status;

	/* we don't use the offset given to use for pipe reads. This
           is deliberate, instead we always return the next lump of
           data on the pipe */
#if 0
	uint32 smb_offs = IVAL(req->vwv+3, 0);
#endif

	if (!fsp_is_np(fsp)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	if (fsp->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	reply_outbuf(req, 12, smb_maxcnt);

	data = (uint8_t *)smb_buf(req->outbuf);

	status = np_read(fsp, data, smb_maxcnt, &nread, &unused);

	if (!NT_STATUS_IS_OK(status)) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		return;
	}

	srv_set_message((char *)req->outbuf, 12, nread, False);
  
	SSVAL(req->outbuf,smb_vwv5,nread);
	SSVAL(req->outbuf,smb_vwv6,
	      req_wct_ofs(req)
	      + 1 		/* the wct field */
	      + 12 * sizeof(uint16_t) /* vwv */
	      + 2);		/* the buflen field */
	SSVAL(req->outbuf,smb_vwv11,smb_maxcnt);
  
	DEBUG(3,("readX-IPC pnum=%04x min=%d max=%d nread=%d\n",
		 fsp->fnum, smb_mincnt, smb_maxcnt, (int)nread));

	chain_reply(req);
}

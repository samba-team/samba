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

/* PIPE/<name>/<pid>/<pnum> */
#define PIPEDB_KEY_FORMAT "PIPE/%s/%u/%d"

struct pipe_dbrec {
	struct server_id pid;
	int pnum;
	uid_t uid;

	char name[MAX_PIPE_NAME_LEN];
	fstring	user;
};

/****************************************************************************
 Reply to an open and X on a named pipe.
 This code is basically stolen from reply_open_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_open_pipe_and_X(connection_struct *conn, struct smb_request *req)
{
	const char *fname = NULL;
	char *pipe_name = NULL;
	smb_np_struct *p;
	int size=0,fmode=0,mtime=0,rmode=0;
	TALLOC_CTX *ctx = talloc_tos();

	/* XXXX we need to handle passed times, sattr and flags */
	srvstr_pull_buf_talloc(ctx, req->inbuf, req->flags2, &pipe_name,
			smb_buf(req->inbuf), STR_TERMINATE);
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

	/* See if it is one we want to handle. */
	if (!is_known_pipename(pipe_name)) {
		reply_botherror(req, NT_STATUS_OBJECT_NAME_NOT_FOUND,
				ERRDOS, ERRbadpipe);
		return;
	}

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

	/* Known pipes arrive with DIR attribs. Remove it so a regular file */
	/* can be opened and add it in after the open. */
	DEBUG(3,("Known pipe %s opening.\n",fname));

	p = open_rpc_pipe_p(fname, conn, req->vuid);
	if (!p) {
		reply_doserror(req, ERRSRV, ERRnofids);
		return;
	}

	/* Prepare the reply */
	reply_outbuf(req, 15, 0);

	/* Mark the opened file as an existing named pipe in message mode. */
	SSVAL(req->outbuf,smb_vwv9,2);
	SSVAL(req->outbuf,smb_vwv10,0xc700);

	if (rmode == 2) {
		DEBUG(4,("Resetting open result to open from create.\n"));
		rmode = 1;
	}

	SSVAL(req->outbuf,smb_vwv2, p->pnum);
	SSVAL(req->outbuf,smb_vwv3,fmode);
	srv_put_dos_date3((char *)req->outbuf,smb_vwv4,mtime);
	SIVAL(req->outbuf,smb_vwv6,size);
	SSVAL(req->outbuf,smb_vwv8,rmode);
	SSVAL(req->outbuf,smb_vwv11,0x0001);

	chain_reply(req);
	return;
}

/****************************************************************************
 Reply to a write on a pipe.
****************************************************************************/

void reply_pipe_write(struct smb_request *req)
{
	smb_np_struct *p = get_rpc_pipe_p(SVAL(req->inbuf,smb_vwv0));
	size_t numtowrite = SVAL(req->inbuf,smb_vwv1);
	int nwritten;
	char *data;

	if (!p) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	if (p->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	data = smb_buf(req->inbuf) + 3;

	if (numtowrite == 0) {
		nwritten = 0;
	} else {
		nwritten = write_to_pipe(p, data, numtowrite);
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0)) {
		reply_unixerror(req, ERRDOS, ERRnoaccess);
		return;
	}

	reply_outbuf(req, 1, 0);

	SSVAL(req->outbuf,smb_vwv0,nwritten);
  
	DEBUG(3,("write-IPC pnum=%04x nwritten=%d\n", p->pnum, nwritten));

	return;
}

/****************************************************************************
 Reply to a write and X.

 This code is basically stolen from reply_write_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_pipe_write_and_X(struct smb_request *req)
{
	smb_np_struct *p = get_rpc_pipe_p(SVAL(req->inbuf,smb_vwv2));
	size_t numtowrite = SVAL(req->inbuf,smb_vwv10);
	int nwritten = -1;
	int smb_doff = SVAL(req->inbuf, smb_vwv11);
	bool pipe_start_message_raw =
		((SVAL(req->inbuf, smb_vwv7)
		  & (PIPE_START_MESSAGE|PIPE_RAW_MODE))
		 == (PIPE_START_MESSAGE|PIPE_RAW_MODE));
	char *data;

	if (!p) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	if (p->vuid != req->vuid) {
		reply_nterror(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	data = smb_base(req->inbuf) + smb_doff;

	if (numtowrite == 0) {
		nwritten = 0;
	} else {
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
		nwritten = write_to_pipe(p, data, numtowrite);
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0)) {
		reply_unixerror(req, ERRDOS,ERRnoaccess);
		return;
	}

	reply_outbuf(req, 6, 0);

	nwritten = (pipe_start_message_raw ? nwritten + 2 : nwritten);
	SSVAL(req->outbuf,smb_vwv2,nwritten);
  
	DEBUG(3,("writeX-IPC pnum=%04x nwritten=%d\n", p->pnum, nwritten));

	chain_reply(req);
}

/****************************************************************************
 Reply to a read and X.
 This code is basically stolen from reply_read_and_X with some
 wrinkles to handle pipes.
****************************************************************************/

void reply_pipe_read_and_X(struct smb_request *req)
{
	smb_np_struct *p = get_rpc_pipe_p(SVAL(req->inbuf,smb_vwv2));
	int smb_maxcnt = SVAL(req->inbuf,smb_vwv5);
	int smb_mincnt = SVAL(req->inbuf,smb_vwv6);
	int nread = -1;
	char *data;
	bool unused;

	/* we don't use the offset given to use for pipe reads. This
           is deliberate, instead we always return the next lump of
           data on the pipe */
#if 0
	uint32 smb_offs = IVAL(req->inbuf,smb_vwv3);
#endif

	if (!p) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	reply_outbuf(req, 12, smb_maxcnt);

	data = smb_buf(req->outbuf);

	nread = read_from_pipe(p, data, smb_maxcnt, &unused);

	if (nread < 0) {
		reply_doserror(req, ERRDOS, ERRnoaccess);
		return;
	}

	srv_set_message((char *)req->outbuf, 12, nread, False);
  
	SSVAL(req->outbuf,smb_vwv5,nread);
	SSVAL(req->outbuf,smb_vwv6,smb_offset(data,req->outbuf));
	SSVAL(smb_buf(req->outbuf),-2,nread);
  
	DEBUG(3,("readX-IPC pnum=%04x min=%d max=%d nread=%d\n",
		 p->pnum, smb_mincnt, smb_maxcnt, nread));

	chain_reply(req);
}

/****************************************************************************
 Reply to a close.
****************************************************************************/

void reply_pipe_close(connection_struct *conn, struct smb_request *req)
{
	smb_np_struct *p = get_rpc_pipe_p(SVAL(req->inbuf,smb_vwv0));

	if (!p) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}

	DEBUG(5,("reply_pipe_close: pnum:%x\n", p->pnum));

	if (!close_rpc_pipe_hnd(p)) {
		reply_doserror(req, ERRDOS, ERRbadfid);
		return;
	}
	
	/* TODO: REMOVE PIPE FROM DB */

	reply_outbuf(req, 0, 0);
	return;
}

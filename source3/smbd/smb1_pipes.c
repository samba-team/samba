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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "auth/auth_util.h"
#include "librpc/rpc/dcerpc_helper.h"

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

#define	PIPE		"PIPE\\"
#define	PIPELEN		strlen(PIPE)

	fname = pipe_name;
	while (fname[0] == '\\') {
		fname++;
	}
	if (!strnequal(fname, PIPE, PIPELEN)) {
		reply_nterror(req, NT_STATUS_OBJECT_PATH_SYNTAX_BAD);
		return;
	}
	fname += PIPELEN;
	while (fname[0] == '\\') {
		fname++;
	}

	DEBUG(4,("Opening pipe %s => %s.\n", pipe_name, fname));

#if 0
	/*
	 * Hack for NT printers... JRA.
	 */
	if(should_fail_next_srvsvc_open(fname)) {
		reply_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
#endif

	status = open_np_file(req, fname, &fsp);
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

	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	/* Mark the opened file as an existing named pipe in message mode. */
	SSVAL(req->outbuf,smb_vwv9,2);
	SSVAL(req->outbuf,smb_vwv10,0xc700);

	SSVAL(req->outbuf, smb_vwv2, fsp->fnum);
	SSVAL(req->outbuf, smb_vwv3, 0);	/* fmode */
	srv_put_dos_date3((char *)req->outbuf, smb_vwv4, 0);	/* mtime */
	SIVAL(req->outbuf, smb_vwv6, 0);	/* size */
	SSVAL(req->outbuf, smb_vwv8, 0);	/* rmode */
	SSVAL(req->outbuf, smb_vwv11, 0x0001);
}

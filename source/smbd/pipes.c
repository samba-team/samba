/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton  1997-1998.
   
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"

#define	PIPE		"\\PIPE\\"
#define	PIPELEN		strlen(PIPE)

extern int DEBUGLEVEL;

extern struct pipe_id_info pipe_names[];

/****************************************************************************
  reply to an open and X on a named pipe

  This code is basically stolen from reply_open_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_open_pipe_and_X(connection_struct * conn,
			  char *inbuf, char *outbuf, int length, int bufsize)
{
	pstring fname;
	uint16 vuid = SVAL(inbuf, smb_uid);
	pipes_struct *p;
	int smb_ofun = SVAL(inbuf, smb_vwv8);
	int size = 0, fmode = 0, mtime = 0, rmode = 0;
	int i;
	vuser_key key;

	/* XXXX we need to handle passed times, sattr and flags */
	pstrcpy(fname, smb_buf(inbuf));

	/* If the name doesn't start \PIPE\ then this is directed */
	/* at a mailslot or something we really, really don't understand, */
	/* not just something we really don't understand. */
	if (strncmp(fname, PIPE, PIPELEN) != 0)
		return (ERROR(ERRSRV, ERRaccess));

	DEBUG(4, ("Opening pipe %s.\n", fname));

	/* See if it is one we want to handle. */
	for (i = 0; pipe_names[i].client_pipe; i++)
		if (strequal(fname, pipe_names[i].client_pipe))
			break;

	if (pipe_names[i].client_pipe == NULL)
		return (ERROR(ERRSRV, ERRaccess));

	/* Strip \PIPE\ off the name. */
	pstrcpy(fname, smb_buf(inbuf) + PIPELEN);

	/* Known pipes arrive with DIR attribs. Remove it so a regular file */
	/* can be opened and add it in after the open. */
	DEBUG(3, ("Known pipe %s opening.\n", fname));
	smb_ofun |= 0x10;	/* Add Create it not exists flag */

	key.pid = getpid();
	key.vuid = vuid;
	p = open_rpc_pipe_p(fname, &key, NULL);
	if (!p)
		return (ERROR(ERRSRV, ERRnofids));

	/* Prepare the reply */
	set_message(outbuf, 15, 0, True);

	/* Mark the opened file as an existing named pipe in message mode. */
	SSVAL(outbuf, smb_vwv9, 2);
	SSVAL(outbuf, smb_vwv10, 0xc700);

	if (rmode == 2)
	{
		DEBUG(4, ("Resetting open result to open from create.\n"));
		rmode = 1;
	}

	SSVAL(outbuf, smb_vwv2, p->pnum);
	SSVAL(outbuf, smb_vwv3, fmode);
	put_dos_date3(outbuf, smb_vwv4, mtime);
	SIVAL(outbuf, smb_vwv6, size);
	SSVAL(outbuf, smb_vwv8, rmode);
	SSVAL(outbuf, smb_vwv11, 0x0001);

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a write 

  This code is basically stolen from reply_write with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_pipe_write(char *inbuf, char *outbuf, int length, int bufsize)
{
	pipes_struct *p = get_rpc_pipe_p(inbuf, smb_vwv0);
	size_t numtowrite = SVAL(inbuf, smb_vwv1);
	int nwritten = -1;
	char *data;
	size_t outsize;

	if (!p)
		return (ERROR(ERRDOS, ERRbadfid));

	data = smb_buf(inbuf) + 3;

	if (numtowrite == 0)
	{
		nwritten = 0;
	}
	else
	{
		nwritten = write_pipe(p, data, numtowrite);
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0))
		return (UNIXERROR(ERRDOS, ERRnoaccess));

	outsize = set_message(outbuf, 1, 0, True);

	SSVAL(outbuf, smb_vwv0, nwritten);

	DEBUG(3,("write-IPC pnum=%04x nwritten=%d\n",
		 p->pnum, nwritten));

	return(outsize);
}

/****************************************************************************
  reply to a write and X

  This code is basically stolen from reply_write_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_pipe_write_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	pipes_struct *p = get_rpc_pipe_p(inbuf, smb_vwv2);
	size_t numtowrite = SVAL(inbuf, smb_vwv10);
	int nwritten = -1;
	int smb_doff = SVAL(inbuf, smb_vwv11);
	int write_mode = SVAL(inbuf, smb_vwv7);
	char *data;

	/* 
	 * start of message mode pipe: indicates start of dce/rpc pdu.
	 */

	BOOL msg;
	msg = IS_BITS_SET_ALL(write_mode, PIPE_START_MESSAGE | PIPE_RAW_MODE);

	if (!p)
		return (ERROR(ERRDOS, ERRbadfid));

	data = smb_base(inbuf) + smb_doff;

	if (numtowrite == 0)
	{
		nwritten = 0;
	}
	else
	{
		if (msg)
		{
			/*
			 * skip the length-of-pdu, the client could be
			 * a nasty bitch and lie to us, e.g
			 * an nt-smb-writepipe-DoS attack.
			 */

			data += 2;
			numtowrite -= 2;
		}

		nwritten = write_pipe(p, data, numtowrite);

		if (msg && nwritten != 0)
		{
			nwritten += 2;
		}
	}

	if ((nwritten == 0 && numtowrite != 0) || (nwritten < 0))
	{
		return (UNIXERROR(ERRDOS, ERRnoaccess));
	}

	set_message(outbuf, 6, 0, True);
	SSVAL(outbuf, smb_vwv2, nwritten);

	DEBUG(3, ("writeX-IPC pnum=%04x nwritten=%d\n", p->pnum, nwritten));

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a read and X

  This code is basically stolen from reply_read_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_pipe_read_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	pipes_struct *p = get_rpc_pipe_p(inbuf, smb_vwv2);
	int smb_maxcnt = SVAL(inbuf, smb_vwv5);
	int smb_mincnt = SVAL(inbuf, smb_vwv6);
	int nread = -1;
	char *data;

	if (!p)
		return (ERROR(ERRDOS, ERRbadfid));

	set_message(outbuf, 12, 0, True);
	data = smb_buf(outbuf);

	nread = read_pipe(p, data, 1, smb_maxcnt);

	if (nread < 0)
		return (UNIXERROR(ERRDOS, ERRnoaccess));

	SSVAL(outbuf, smb_vwv5, nread);
	SSVAL(outbuf, smb_vwv6, smb_offset(data, outbuf));
	SSVAL(smb_buf(outbuf), -2, nread);

	DEBUG(3, ("readX-IPC pnum=%04x min=%d max=%d nread=%d\n",
		  p->pnum, smb_mincnt, smb_maxcnt, nread));

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a close
****************************************************************************/
int reply_pipe_close(connection_struct * conn, char *inbuf, char *outbuf)
{
	pipes_struct *p = get_rpc_pipe_p(inbuf, smb_vwv0);
	int outsize = set_message(outbuf, 0, 0, True);

	if (!p)
		return (ERROR(ERRDOS, ERRbadfid));

	DEBUG(5, ("reply_pipe_close: pnum:%x\n", p->pnum));

	if (!close_rpc_pipe_hnd(p))
		return (ERROR(ERRDOS, ERRbadfid));

	return (outsize);
}

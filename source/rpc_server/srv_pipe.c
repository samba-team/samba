
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/*******************************************************************
 entry point from msrpc to smb.  adds data received to pdu; checks
 pdu; hands pdu off to msrpc, which gets a pdu back (except in the
 case of the RPC_BINDCONT pdu).
 ********************************************************************/
BOOL readwrite_pipe(pipes_struct *p, char *data, int len,
		char **rdata, int *rlen,
		BOOL *pipe_outstanding)
{
	fd_set fds;
	int selrtn;
	struct timeval timeout;

	DEBUG(10,("rpc_to_smb_readwrite: len %d\n", len));

	if (write(p->m->fd, data, len) != len)
	{
		return False;
	}

	if ((*rlen) == 0)
	{
		return False;
	}

	(*rdata) = (char*)Realloc((*rdata), (*rlen));
	if ((*rdata) == NULL)
	{
		return False;
	}

	/* compromise.  MUST read a minimum of an rpc header.
	 * timeout waiting for the rest for 10 seconds */
	(*rlen) = read_with_timeout(p->m->fd, (*rdata), 16,(*rlen), 10000);
	if ((*rlen) < 0)
	{
		return False;
	}
	(*rdata) = (char*)Realloc((*rdata), (*rlen));
	if ((*rdata) == NULL)
	{
		return False;
	}

	/* now check whether there is outstanding data on the pipe.
	 * this is needed to as to report a STATUS message back to
	 * the NT client.  yes, NT clients fail to operate if you
	 * don't set a STATUS_BUFFER_OVERFLOW warning on the SMBtrans
	 * response.  *dur*!  what's msrpc got to do with smb, ANYWAY!!
	 */

	FD_ZERO(&fds);
	FD_SET(p->m->fd,&fds);

	/* Set initial timeout to zero */
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	selrtn = sys_select(p->m->fd+1,&fds,NULL, &timeout);

	/* Check if error */
	if (selrtn == -1)
	{
		/* something is wrong. Maybe the socket is dead? */
		return -1;
	}

	*pipe_outstanding = FD_ISSET(p->m->fd, &fds);

	return True;
}

/****************************************************************************
writes data to a pipe.
****************************************************************************/
ssize_t write_pipe(pipes_struct *p, char *data, size_t n)
{
	DEBUG(6,("write_pipe: %x", p->pnum));
	DEBUG(6,("name: %s open: %s len: %d",
			 p->name, BOOLSTR(p->open), n));

	dump_data(50, data, n);

	return write(p->m->fd, data, n);
}


/****************************************************************************
 reads data from a pipe.

 headers are interspersed with the data at regular intervals.  by the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 ****************************************************************************/
int read_pipe(pipes_struct *p, char *data, int n)
{
	DEBUG(6,("read_pipe: %x name: %s open: %s len: %d",
		 p->pnum, p->name, BOOLSTR(p->open), n));

	if (!p || !p->open)
	{
		DEBUG(6,("pipe not open\n"));
		return -1;		
	}

	/* read a minimum of 1 byte! :-) */
	return read_with_timeout(p->m->fd, data, 1, n, 10000);
}


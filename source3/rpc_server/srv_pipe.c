
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

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
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
		char **rdata, int *rlen)
{
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

	/* read a minimum of an rpc header, then wait for up to 10 seconds
	 * to read up to a maximum of the SMBtrans max data size
	 */
	(*rlen) = read_with_timeout(p->m->fd, (*rdata), 16, (*rlen), 10000);
	if ((*rlen) < 0)
	{
		return False;
	}
	(*rdata) = (char*)Realloc((*rdata), (*rlen));
	if ((*rdata) == NULL)
	{
		return False;
	}
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

	return read_data(p->m->fd, data, n);
}


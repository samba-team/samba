/* 
   Unix SMB/CIFS implementation.
   SMB client oplock functions
   Copyright (C) Andrew Tridgell 2001
   
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

/****************************************************************************
send an ack for an oplock break request
****************************************************************************/
BOOL cli_oplock_ack(struct cli_tree *tree, uint16_t fnum, uint16_t ack_level)
{
	BOOL ret;
	struct cli_request *req;

	req = cli_request_setup(tree, SMBlockingX, 8, 0);

	SSVAL(req->out.vwv,VWV(0),0xFF);
	SSVAL(req->out.vwv,VWV(1),0);
	SSVAL(req->out.vwv,VWV(2),fnum);
	SCVAL(req->out.vwv,VWV(3),LOCKING_ANDX_OPLOCK_RELEASE);
	SCVAL(req->out.vwv,VWV(3)+1,ack_level);
	SIVAL(req->out.vwv,VWV(4),0);
	SSVAL(req->out.vwv,VWV(6),0);
	SSVAL(req->out.vwv,VWV(7),0);

	/* this request does not expect a reply, so tell the signing
	   subsystem not to allocate an id for a reply */
	req->one_way_request = 1;

	ret = cli_request_send(req);	

	return ret;
}


/****************************************************************************
set the oplock handler for a connection
****************************************************************************/
void cli_oplock_handler(struct cli_transport *transport, 
			BOOL (*handler)(struct cli_transport *, uint16_t, uint16_t, uint8_t, void *),
			void *private)
{
	transport->oplock.handler = handler;
	transport->oplock.private = private;
}

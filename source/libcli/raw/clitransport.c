/* 
   Unix SMB/CIFS implementation.
   SMB client transport context management functions
   Copyright (C) Andrew Tridgell 1994-2003
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

/*
  create a transport structure based on an established socket
*/
struct cli_transport *cli_transport_init(struct cli_socket *sock)
{
	TALLOC_CTX *mem_ctx;
	struct cli_transport *transport;

	mem_ctx = talloc_init("cli_transport");
	if (!mem_ctx) return NULL;

	transport = talloc_zero(mem_ctx, sizeof(*transport));
	if (!transport) return NULL;

	transport->mem_ctx = mem_ctx;
	transport->socket = sock;
	transport->negotiate.protocol = PROTOCOL_NT1;
	transport->options.use_spnego = lp_use_spnego();
	transport->negotiate.max_xmit = ~0;
	cli_null_set_signing(transport);
	transport->socket->reference_count++;

	ZERO_STRUCT(transport->called);

	return transport;
}

/*
  decrease reference count on a transport, and destroy if it becomes
  zero
*/
void cli_transport_close(struct cli_transport *transport)
{
	transport->reference_count--;
	if (transport->reference_count <= 0) {
		cli_sock_close(transport->socket);
		talloc_destroy(transport->mem_ctx);
	}
}

/*
  mark the transport as dead
*/
void cli_transport_dead(struct cli_transport *transport)
{
	cli_sock_dead(transport->socket);
}



/****************************************************************************
send a session request (if appropriate)
****************************************************************************/
BOOL cli_transport_connect(struct cli_transport *transport,
			   struct nmb_name *calling, 
			   struct nmb_name *called)
{
	char *p;
	int len = NBT_HDR_SIZE;
	struct cli_request *req;

	if (called) {
		transport->called = *called;
	}

	/* 445 doesn't have session request */
	if (transport->socket->port == 445) {
		return True;
	}

  	/* allocate output buffer */
	req = cli_request_setup_nonsmb(transport, NBT_HDR_SIZE + 2*nbt_mangled_name_len());

	/* put in the destination name */
	p = req->out.buffer + NBT_HDR_SIZE;
	name_mangle(called->name, p, called->name_type);
	len += name_len(p);

	/* and my name */
	p = req->out.buffer+len;
	name_mangle(calling->name, p, calling->name_type);
	len += name_len(p);

	_smb_setlen(req->out.buffer,len-4);
	SCVAL(req->out.buffer,0,0x81);

	if (!cli_request_send(req) ||
	    !cli_request_receive(req)) {
		cli_request_destroy(req);
		return False;
	}
	
	if (CVAL(req->in.buffer,0) != 0x82) {
		transport->error.etype = ETYPE_NBT;
		transport->error.e.nbt_error = CVAL(req->in.buffer,4);
		cli_request_destroy(req);
		return False;
	}

	cli_request_destroy(req);
	return True;
}


/****************************************************************************
get next mid in sequence
****************************************************************************/
uint16_t cli_transport_next_mid(struct cli_transport *transport)
{
	uint16_t mid;
	struct cli_request *req;

	mid = transport->next_mid;

again:
	/* now check to see if this mid is being used by one of the 
	   pending requests. This is quite efficient because the list is
	   usually very short */

	/* the zero mid is reserved for requests that don't have a mid */
	if (mid == 0) mid = 1;

	for (req=transport->pending_requests; req; req=req->next) {
		if (req->mid == mid) {
			mid++;
			goto again;
		}
	}

	transport->next_mid = mid+1;
	return mid;
}

/*
  setup the idle handler for a transport
*/
void cli_transport_idle_handler(struct cli_transport *transport, 
				void (*idle_func)(struct cli_transport *, void *),
				uint_t period,
				void *private)
{
	transport->idle.func = idle_func;
	transport->idle.private = private;
	transport->idle.period = period;
}


/*
  determine if a packet is pending for receive on a transport
*/
BOOL cli_transport_pending(struct cli_transport *transport)
{
	return socket_pending(transport->socket->fd);
}



/*
  wait for data on a transport, periodically calling a wait function
  if one has been defined
  return True if a packet is received
*/
BOOL cli_transport_select(struct cli_transport *transport)
{
	fd_set fds;
	int selrtn;
	int fd;
	struct timeval timeout;

	fd = transport->socket->fd;

	if (fd == -1) {
		return False;
	}

	do {
		uint_t period = 1000;

		FD_ZERO(&fds);
		FD_SET(fd,&fds);
	
		if (transport->idle.func) {
			period = transport->idle.period;
		}

		timeout.tv_sec = period / 1000;
		timeout.tv_usec = 1000*(period%1000);
		
		selrtn = sys_select_intr(fd+1,&fds,NULL,NULL,&timeout);
		
		if (selrtn == 1) {
			/* the fd is readable */
			return True;
		}
		
		if (selrtn == -1) {
			/* sys_select_intr() already handles EINTR, so this
			   is an error. The socket is probably dead */
			return False;
		}
		
		/* only other possibility is that we timed out - call the idle function
		   if there is one */
		if (transport->idle.func) {
			transport->idle.func(transport, transport->idle.private);
		}
	} while (selrtn == 0);

	return True;
}


/*
   Unix SMB/CIFS implementation.

   structures for WINS replication client library

   Copyright (C) Andrew Tridgell 2005

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

#include "librpc/gen_ndr/ndr_winsrepl.h"

/*
  main context structure for the wins replication client library
*/
struct wrepl_socket {
	struct socket_context *sock;
	struct event_context *event_ctx;

	/* a queue of requests pending to be sent */
	struct wrepl_request *send_queue;

	/* a queue of replies waiting to be received */
	struct wrepl_request *recv_queue;

	/* the fd event */
	struct fd_event *fde;
};

enum wrepl_request_state {
	WREPL_REQUEST_SEND  = 0,
	WREPL_REQUEST_RECV  = 1,
	WREPL_REQUEST_DONE  = 2,
	WREPL_REQUEST_ERROR = 3
};

/*
  a WINS replication request
*/
struct wrepl_request {
	struct wrepl_request *next, *prev;
	struct wrepl_socket *wrepl_socket;

	enum wrepl_request_state state;
	NTSTATUS status;

	DATA_BLOB buffer;

	size_t num_read;

	struct wrepl_packet *packet;

	struct {
		void (*fn)(struct wrepl_request *);
		void *private;
	} async;
};

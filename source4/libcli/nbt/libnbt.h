/*
   Unix SMB/CIFS implementation.

   a raw async NBT library

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

#include "librpc/gen_ndr/ndr_nbt.h"

/*
  possible states for pending requests
*/
enum nbt_request_state {NBT_REQUEST_SEND, 
			NBT_REQUEST_WAIT, 
			NBT_REQUEST_DONE,
			NBT_REQUEST_TIMEOUT,
			NBT_REQUEST_ERROR};

/*
  a nbt name request
*/
struct nbt_name_request {
	struct nbt_name_request *next, *prev;

	enum nbt_request_state state;

	NTSTATUS status;

	/* the socket this was on */
	struct nbt_name_socket *nbtsock;

	/* where to send the request */
	const char *dest_addr;
	int dest_port;

	/* the timeout event */
	struct timed_event *te;

	struct nbt_name_packet *request;

	/* shall we allow multiple replies? */
	BOOL allow_multiple_replies;

	uint_t num_replies;
	struct nbt_name_reply {
		struct nbt_name_packet *packet;
		const char *reply_addr;
		int reply_port;
	} *replies;
};



/*
  context structure for operations on name queries
*/
struct nbt_name_socket {
	struct socket_context *sock;
	struct event_context *event_ctx;

	/* a queue of requests pending to be sent */
	struct nbt_name_request *send_queue;

	/* the fd event */
	struct fd_event *fde;

	/* mapping from name_trn_id to pending event */
	struct idr_context *idr;

	/* how many requests are waiting for a reply */
	uint16_t num_pending;
};


/* a simple name query */
struct nbt_name_query {
	struct {
		struct nbt_name name;
		const char *dest_addr;
		BOOL broadcast;
		BOOL wins_lookup;
		int timeout; /* in seconds */
	} in;
	struct {
		const char *reply_from;
		struct nbt_name name;
		const char *reply_addr;
	} out;
};

/* a simple name status query */
struct nbt_name_status {
	struct {
		struct nbt_name name;
		const char *dest_addr;
		int timeout; /* in seconds */
	} in;
	struct {
		const char *reply_from;
		struct nbt_name name;
		struct nbt_rdata_status status;
	} out;
};

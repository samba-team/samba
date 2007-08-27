/* 
   Unix SMB/CIFS implementation.

   structures specific to stream servers

   Copyright (C) Stefan (metze) Metzmacher	2004
   Copyright (C) Andrew Tridgell        	2005
   
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

#ifndef __SERVICE_STREAM_H__
#define __SERVICE_STREAM_H__

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct stream_connection_critical_sizes.
 */
/* version 0 - initial version - metze */
#define SERVER_SERVICE_VERSION 0

/*
  top level context for an established stream connection
*/
struct stream_connection {
	const struct stream_server_ops *ops;
	const struct model_ops *model_ops;
	struct server_id server_id;
	void *private;

	struct {
		struct event_context *ctx;
		struct fd_event *fde;
	} event;

	struct socket_context *socket;
	struct messaging_context *msg_ctx;

	bool processing;
	const char *terminate;
};


/* operations passed to the service_stream code */
struct stream_server_ops {
	/* the name of the server_service */
	const char *name;
	void (*accept_connection)(struct stream_connection *);
	void (*recv_handler)(struct stream_connection *, uint16_t);
	void (*send_handler)(struct stream_connection *, uint16_t);
};

#endif /* __SERVICE_STREAM_H__ */

/* 
   Unix SMB/CIFS implementation.

   server side dcerpc defines

   Copyright (C) Andrew Tridgell 2003
   
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


enum endpoint_type {ENDPOINT_SMB, ENDPOINT_TCP};

/* a description of a single dcerpc endpoint */
struct dcesrv_endpoint {
	enum endpoint_type type;
	union {
		const char *smb_pipe;
		uint32 tcp_port;
	} info;
};


/* the state associated with a dcerpc server connection */
struct dcesrv_state {
	TALLOC_CTX *mem_ctx;

	/* the endpoint that was opened */
	struct dcesrv_endpoint endpoint;

	/* endpoint operations provided by the endpoint server */
	const struct dcesrv_endpoint_ops *ops;

	/* private data for the endpoint server */
	void *private;
};


struct dcesrv_endpoint_ops {
	/* the query function is used to ask an endpoint server if it
	   handles a particular endpoint */
	BOOL (*query)(const struct dcesrv_endpoint *);

	/* connect() is called when a connection is made to an endpoint */
	NTSTATUS (*connect)(struct dcesrv_state *);

	/* disconnect() is called when the endpoint is disconnected */
	void (*disconnect)(struct dcesrv_state *);
};


/* server-wide context information for the dcerpc server */
struct dcesrv_context {
	
	/* the list of endpoints servers that have registered */
	struct dce_endpoint {
		struct dce_endpoint *next, *prev;
		const struct dcesrv_endpoint_ops *endpoint_ops;
	} *endpoint_list;
};

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

/* a description of a single dcerpc endpoint. Not as flexible as a full epm tower,
   but much easier to work with */
struct dcesrv_endpoint {
	enum endpoint_type type;
	union {
		const char *smb_pipe;
		uint32 tcp_port;
	} info;
};

/* a endpoint combined with an interface description */
struct dcesrv_ep_iface {
	const char *name;
	struct dcesrv_endpoint endpoint;
	const char *uuid;
	uint32 if_version;
};

struct dcesrv_state;

/* the dispatch functions for an interface take this form */
typedef NTSTATUS (*dcesrv_dispatch_fn_t)(struct dcesrv_state *, TALLOC_CTX *, void *); 

/* the state of an ongoing dcerpc call */
struct dcesrv_call_state {
	struct dcesrv_call_state *next, *prev;
	struct dcesrv_state *dce;
	TALLOC_CTX *mem_ctx;
	struct dcerpc_packet pkt;

	DATA_BLOB input;

	struct dcesrv_call_reply {
		struct dcesrv_call_reply *next, *prev;
		DATA_BLOB data;
	} *replies;
};


/* a dcerpc handle in internal format */
struct dcesrv_handle {
	struct dcesrv_handle *next, *prev;
	struct policy_handle wire_handle;
	TALLOC_CTX *mem_ctx;
	void *data;
};

/* hold the authentication state information */
struct dcesrv_auth {
	struct ntlmssp_state *ntlmssp_state;
	struct dcerpc_auth *auth_info;
};


/* the state associated with a dcerpc server connection */
struct dcesrv_state {
	/* the top level context for this server */
	struct dcesrv_context *dce;

	TALLOC_CTX *mem_ctx;

	/* the endpoint that was opened */
	struct dcesrv_endpoint endpoint;

	/* endpoint operations provided by the endpoint server */
	const struct dcesrv_endpoint_ops *ops;

	/* the ndr function table for the chosen interface */
	const struct dcerpc_interface_table *ndr;

	/* the dispatch table for the chosen interface. Must contain
	   enough entries for all entries in the ndr table */
	const dcesrv_dispatch_fn_t *dispatch;

	/* the state of the current calls */
	struct dcesrv_call_state *call_list;

	/* the maximum size the client wants to receive */
	uint32 cli_max_recv_frag;

	/* private data for the endpoint server */
	void *private;

	/* current rpc handles - this is really the wrong scope for
	   them, but it will do for now */
	uint32 next_handle;
	struct dcesrv_handle *handles;

	DATA_BLOB partial_input;

	/* the current authentication state */
	struct dcesrv_auth auth_state;
};


struct dcesrv_endpoint_ops {
	/* this function is used to ask an endpoint server if it
	   handles a particular endpoint */
	BOOL (*query_endpoint)(const struct dcesrv_endpoint *);

	/* this function sets up the dispatch table for this
	   connection */
	BOOL (*set_interface)(struct dcesrv_state *, const char *, uint32);

	/* connect() is called when a connection is made to an endpoint */
	NTSTATUS (*connect)(struct dcesrv_state *);

	/* disconnect() is called when the endpoint is disconnected */
	void (*disconnect)(struct dcesrv_state *);

	/* this function is used to ask an endpoint server for a list
	   of endpoints/interfaces it wants to handle */
	int (*lookup_endpoints)(TALLOC_CTX *mem_ctx, struct dcesrv_ep_iface **);
};


/* server-wide context information for the dcerpc server */
struct dcesrv_context {
	
	/* the list of endpoints servers that have registered */
	struct dce_endpoint {
		struct dce_endpoint *next, *prev;
		struct dcesrv_endpoint endpoint;
		const struct dcesrv_endpoint_ops *endpoint_ops;
	} *endpoint_list;
};

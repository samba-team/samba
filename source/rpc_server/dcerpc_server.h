/* 
   Unix SMB/CIFS implementation.

   server side dcerpc defines

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   
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

#ifndef SAMBA_DCERPC_SERVER_H
#define SAMBA_DCERPC_SERVER_H

#include "core.h"
#include "librpc/gen_ndr/misc.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/ndr/libndr.h"

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct dcesrv_critical_sizes.
 */
/* version 1 - initial version - metze */
#define DCERPC_MODULE_VERSION 1

struct dcesrv_connection;
struct dcesrv_call_state;
struct dcesrv_auth;
struct dcesrv_connection_context;

struct dcesrv_interface {
	const char *name;
	struct dcerpc_syntax_id syntax_id;

	/* this function is called when the client binds to this interface  */
	NTSTATUS (*bind)(struct dcesrv_call_state *, const struct dcesrv_interface *);

	/* this function is called when the client disconnects the endpoint */
	void (*unbind)(struct dcesrv_connection_context *, const struct dcesrv_interface *);

	/* the ndr_pull function for the chosen interface.
	 */
	NTSTATUS (*ndr_pull)(struct dcesrv_call_state *, TALLOC_CTX *, struct ndr_pull *, void **);
	
	/* the dispatch function for the chosen interface.
	 */
	NTSTATUS (*dispatch)(struct dcesrv_call_state *, TALLOC_CTX *, void *);

	/* the reply function for the chosen interface.
	 */
	NTSTATUS (*reply)(struct dcesrv_call_state *, TALLOC_CTX *, void *);

	/* the ndr_push function for the chosen interface.
	 */
	NTSTATUS (*ndr_push)(struct dcesrv_call_state *, TALLOC_CTX *, struct ndr_push *, const void *);

	/* for any private use by the interface code */
	const void *private;
};

/* the state of an ongoing dcerpc call */
struct dcesrv_call_state {
	struct dcesrv_call_state *next, *prev;
	struct dcesrv_connection *conn;
	struct dcesrv_connection_context *context;
	struct ncacn_packet pkt;

	/* the backend can mark the call
	 * with DCESRV_CALL_STATE_FLAG_ASYNC
	 * that will cause the frontend to not touch r->out
	 * and skip the reply
	 *
	 * this is only allowed to the backend when DCESRV_CALL_STATE_FLAG_MAY_ASYNC
	 * is alerady set by the frontend
	 *
	 * the backend then needs to call dcesrv_reply() when it's
	 * ready to send the reply
	 */
#define DCESRV_CALL_STATE_FLAG_ASYNC (1<<0)
#define DCESRV_CALL_STATE_FLAG_MAY_ASYNC (1<<1)
	uint32_t state_flags;

	/* the time the request arrived in the server */
	struct timeval time;

	/* the backend can use this event context for async replies */
	struct event_context *event_ctx;

	/* the message_context that will be used for async replies */
	struct messaging_context *msg_ctx;

	/* this is the pointer to the allocated function struct */
	void *r;

	/*
	 * that's the ndr pull context used in dcesrv_request()
	 * needed by dcesrv_reply() to carry over information
	 * for full pointer support.
	 */
	struct ndr_pull *ndr_pull;

	DATA_BLOB input;

	struct data_blob_list_item *replies;

	/* this is used by the boilerplate code to generate DCERPC faults */
	uint32_t fault_code;
};

#define DCESRV_HANDLE_ANY 255

/* a dcerpc handle in internal format */
struct dcesrv_handle {
	struct dcesrv_handle *next, *prev;
	struct dcesrv_connection_context *context;
	struct policy_handle wire_handle;
	void *data;
};

/* hold the authentication state information */
struct dcesrv_auth {
	struct dcerpc_auth *auth_info;
	struct gensec_security *gensec_security;
	struct auth_session_info *session_info;
	NTSTATUS (*session_key)(struct dcesrv_connection *, DATA_BLOB *session_key);
};

struct dcesrv_connection_context {
	struct dcesrv_connection_context *next, *prev;
	uint32_t context_id;

	/* the connection this is on */
	struct dcesrv_connection *conn;

	/* the ndr function table for the chosen interface */
	const struct dcesrv_interface *iface;

	/* private data for the interface implementation */
	void *private;

	/* current rpc handles - this is really the wrong scope for
	   them, but it will do for now */
	struct dcesrv_handle *handles;
};


/* the state associated with a dcerpc server connection */
struct dcesrv_connection {
	/* the top level context for this server */
	struct dcesrv_context *dce_ctx;

	/* the endpoint that was opened */
	const struct dcesrv_endpoint *endpoint;

	/* a list of established context_ids */
	struct dcesrv_connection_context *contexts;

	/* the state of the current incoming call fragments */
	struct dcesrv_call_state *incoming_fragmented_call_list;

	/* the state of the async pending calls */
	struct dcesrv_call_state *pending_call_list;

	/* the state of the current outgoing calls */
	struct dcesrv_call_state *call_list;

	/* the maximum size the client wants to receive */
	uint32_t cli_max_recv_frag;

	DATA_BLOB partial_input;

	/* the current authentication state */
	struct dcesrv_auth auth_state;

	/* the event_context that will be used for this connection */
	struct event_context *event_ctx;

	/* the message_context that will be used for this connection */
	struct messaging_context *msg_ctx;

	/* the server_id that will be used for this connection */
	uint32_t server_id;

	/* the transport level session key */
	DATA_BLOB transport_session_key;

	BOOL processing;

	/* this is the default state_flags for dcesrv_call_state structs */
	uint32_t state_flags;

	struct {
		void *private_data;
		void (*report_output_data)(struct dcesrv_connection *);
		struct socket_address *(*get_my_addr)(struct dcesrv_connection *, TALLOC_CTX *mem_ctx);
		struct socket_address *(*get_peer_addr)(struct dcesrv_connection *, TALLOC_CTX *mem_ctx);
	} transport;
};


struct dcesrv_endpoint_server {
	/* this is the name of the endpoint server */
	const char *name;

	/* this function should register endpoints and some other setup stuff,
	 * it is called when the dcesrv_context gets initialized.
	 */
	NTSTATUS (*init_server)(struct dcesrv_context *, const struct dcesrv_endpoint_server *);

	/* this function can be used by other endpoint servers to
	 * ask for a dcesrv_interface implementation
	 * - iface must be reference to an already existing struct !
	 */
	BOOL (*interface_by_uuid)(struct dcesrv_interface *iface, const struct GUID *, uint32_t);

	/* this function can be used by other endpoint servers to
	 * ask for a dcesrv_interface implementation
	 * - iface must be reference to an already existeng struct !
	 */
	BOOL (*interface_by_name)(struct dcesrv_interface *iface, const char *);
};


/* server-wide context information for the dcerpc server */
struct dcesrv_context {
	/* the list of endpoints that have registered 
	 * by the configured endpoint servers 
	 */
	struct dcesrv_endpoint {
		struct dcesrv_endpoint *next, *prev;
		/* the type and location of the endpoint */
		struct dcerpc_binding *ep_description;
		/* the security descriptor for smb named pipes */
		struct security_descriptor *sd;
		/* the list of interfaces available on this endpoint */
		struct dcesrv_if_list {
			struct dcesrv_if_list *next, *prev;
			struct dcesrv_interface iface;
		} *interface_list;
	} *endpoint_list;
};

/* this structure is used by modules to determine the size of some critical types */
struct dcesrv_critical_sizes {
	int interface_version;
	int sizeof_dcesrv_context;
	int sizeof_dcesrv_endpoint;
	int sizeof_dcesrv_endpoint_server;
	int sizeof_dcesrv_interface;
	int sizeof_dcesrv_if_list;
	int sizeof_dcesrv_connection;
	int sizeof_dcesrv_call_state;
	int sizeof_dcesrv_auth;
	int sizeof_dcesrv_handle;
};

struct model_ops;

#include "rpc_server/dcerpc_server_proto.h"

#endif /* SAMBA_DCERPC_SERVER_H */

/* 
   Unix SMB/CIFS implementation.

   server side dcerpc defines

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct dcesrv_critical_sizes.
 */
/* version 1 - initial version - metze */
#define DCERPC_MODULE_VERSION 1

enum endpoint_type {ENDPOINT_SMB, ENDPOINT_TCP};

/* a description of a single dcerpc endpoint. Not as flexible as a full epm tower,
   but much easier to work with */
struct dcesrv_ep_description {
	enum endpoint_type type;
	union {
		const char *smb_pipe;
		uint32_t tcp_port;
	} info;
};

struct dcesrv_connection;
struct dcesrv_call_state;
struct dcesrv_auth;

/* the dispatch functions for an interface take this form */
typedef NTSTATUS (*dcesrv_dispatch_fn_t)(struct dcesrv_call_state *, TALLOC_CTX *, void *);

struct dcesrv_interface {
	/* the ndr function table for the chosen interface */
	const struct dcerpc_interface_table *ndr;

	/* this function is called when the client binds to this interface  */
	NTSTATUS (*bind)(struct dcesrv_call_state *, const struct dcesrv_interface *);

	/* this function is called when the client disconnects the endpoint */
	void (*unbind)(struct dcesrv_connection *, const struct dcesrv_interface *);

	/* the dispatch function for the chosen interface.
	 */
	dcesrv_dispatch_fn_t dispatch;
}; 

/* the state of an ongoing dcerpc call */
struct dcesrv_call_state {
	struct dcesrv_call_state *next, *prev;
	struct dcesrv_connection *conn;
	TALLOC_CTX *mem_ctx;
	struct dcerpc_packet pkt;

	DATA_BLOB input;

	struct dcesrv_call_reply {
		struct dcesrv_call_reply *next, *prev;
		DATA_BLOB data;
	} *replies;

	/* this is used by the boilerplate code to generate DCERPC faults */
	uint32_t fault_code;
};

#define DCESRV_HANDLE_ANY 255

/* a dcerpc handle in internal format */
struct dcesrv_handle {
	struct dcesrv_handle *next, *prev;
	struct policy_handle wire_handle;
	TALLOC_CTX *mem_ctx;
	void *data;
	void (*destroy)(struct dcesrv_connection *, struct dcesrv_handle *);
};

struct dcesrv_crypto_ops {
	const char *name;
	uint8 auth_type;
	NTSTATUS (*start)(struct dcesrv_auth *auth);
	NTSTATUS (*update)(struct dcesrv_auth *auth, TALLOC_CTX *out_mem_ctx,
				const DATA_BLOB in, DATA_BLOB *out);
	NTSTATUS (*seal)(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length, DATA_BLOB *sig);
	NTSTATUS (*sign)(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				const uint8_t *data, size_t length, DATA_BLOB *sig);
	NTSTATUS (*check_sig)(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx, 
				const uint8_t *data, size_t length, const DATA_BLOB *sig);
	NTSTATUS (*unseal)(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length, DATA_BLOB *sig);
	void (*end)(struct dcesrv_auth *auth);
};

/* hold the authentication state information */
struct dcesrv_auth {
	struct dcerpc_auth *auth_info;
	struct {
		void *private_data;
		const struct dcesrv_crypto_ops *ops;
	} crypto_ctx;
};


/* the state associated with a dcerpc server connection */
struct dcesrv_connection {
	/* the top level context for this server */
	struct dcesrv_context *dce_ctx;

	TALLOC_CTX *mem_ctx;

	/* the endpoint that was opened */
	const struct dcesrv_endpoint *endpoint;

	/* the ndr function table for the chosen interface */
	const struct dcesrv_interface *iface;

	/* the state of the current calls */
	struct dcesrv_call_state *call_list;

	/* the maximum size the client wants to receive */
	uint32_t cli_max_recv_frag;

	/* private data for the interface implementation */
	void *private;

	/* current rpc handles - this is really the wrong scope for
	   them, but it will do for now */
	struct dcesrv_handle *handles;

	DATA_BLOB partial_input;

	/* the current authentication state */
	struct dcesrv_auth auth_state;

	/* the transport level session key, if any */
	DATA_BLOB session_key;
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
	 * - iface must be referenz to an allready existent struct !
	 */
	BOOL (*interface_by_uuid)(struct dcesrv_interface *iface, const char *, uint32_t);

	/* this function can be used by other endpoint servers to
	 * ask for a dcesrv_interface implementation
	 * - iface must be referenz to an allready existent struct !
	 */
	BOOL (*interface_by_name)(struct dcesrv_interface *iface, const char *);
};


/* server-wide context information for the dcerpc server */
struct dcesrv_context {
	TALLOC_CTX *mem_ctx;

	/* the list of endpoints that have registered 
	 * by the configured endpoint servers 
	 */
	struct dcesrv_endpoint {
		struct dcesrv_endpoint *next, *prev;
		/* the type and location of the endpoint */
		struct dcesrv_ep_description ep_description;
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
	int sizeof_dcesrv_ep_description;
	int sizeof_dcesrv_interface;
	int sizeof_dcesrv_if_list;
	int sizeof_dcesrv_connection;
	int sizeof_dcesrv_call_state;
	int sizeof_dcesrv_auth;
	int sizeof_dcesrv_handle;
};

#endif /* SAMBA_DCERPC_SERVER_H */

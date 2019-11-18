/*
   Unix SMB/CIFS implementation.

   server side dcerpc defines

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2019

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

#ifndef _LIBRPC_RPC_DCESRV_CORE_H_
#define _LIBRPC_RPC_DCESRV_CORE_H_

#include "librpc/rpc/rpc_common.h"
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
struct dcesrv_iface_state;
struct cli_credentials;

struct dcesrv_interface {
	const char *name;
	struct ndr_syntax_id syntax_id;

	/* this function is called when the client binds to this interface  */
	NTSTATUS (*bind)(struct dcesrv_connection_context *, const struct dcesrv_interface *);

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

	/* the local dispatch function for the chosen interface.
	 */
	NTSTATUS (*local)(struct dcesrv_call_state *, TALLOC_CTX *, void *);

	/* for any private use by the interface code */
	const void *private_data;

	uint64_t flags;
};

#define DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED 0x00000001

enum dcesrv_call_list {
	DCESRV_LIST_NONE,
	DCESRV_LIST_CALL_LIST,
	DCESRV_LIST_FRAGMENTED_CALL_LIST,
	DCESRV_LIST_PENDING_CALL_LIST
};

struct data_blob_list_item {
	struct data_blob_list_item *prev,*next;
	DATA_BLOB blob;
};

/* the state of an ongoing dcerpc call */
struct dcesrv_call_state {
	struct dcesrv_call_state *next, *prev;
	struct dcesrv_auth *auth_state;
	struct dcesrv_connection *conn;
	struct dcesrv_connection_context *context;
	struct ncacn_packet pkt;

	/*
	 * Used during async bind/alter_context.
	 */
	struct ncacn_packet ack_pkt;

	/*
	  which list this request is in, if any
	 */
	enum dcesrv_call_list list;

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
#define DCESRV_CALL_STATE_FLAG_MULTIPLEXED (1<<3)
#define DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL (1<<4)
	uint32_t state_flags;

	/* the time the request arrived in the server */
	struct timeval time;

	/* the backend can use this event context for async replies */
	struct tevent_context *event_ctx;

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

	/* the reason why we terminate the connection after sending a response */
	const char *terminate_reason;

	/* temporary auth_info fields */
	struct dcerpc_auth in_auth_info;
	struct dcerpc_auth _out_auth_info;
	struct dcerpc_auth *out_auth_info;
};

/*
* DCERPC Handles
* --------------
* The various handles that are used in the RPC servers should be
* created and fetch using the dcesrv_handle_* functions.
*
* Use
* dcesrv_handle_create(struct dcesrv_call_state \*, uint8 handle_type)
* to obtain a new handle of the specified type. Handle types are
* unique within each pipe.
*
* The handle can later be fetched again using:
*
* struct dcesrv_handle *dcesrv_handle_lookup(
*         struct dcesrv_call_state *dce_call,
*         struct policy_handle *p,
*         uint8 handle_type)
*
* and destroyed by:
*
* 	TALLOC_FREE(struct dcesrv_handle *).
*
* User data should be stored in the 'data' member of the dcesrv_handle
* struct.
*/

#define DCESRV_HANDLE_ANY 255

/* a dcerpc handle in internal format */
struct dcesrv_handle {
	struct dcesrv_handle *next, *prev;
	struct dcesrv_assoc_group *assoc_group;
	struct policy_handle wire_handle;
	struct dom_sid *sid;
	enum dcerpc_AuthLevel min_auth_level;
	const struct dcesrv_interface *iface;
	void *data;
};

/* hold the authentication state information */
struct dcesrv_auth {
	struct dcesrv_auth *prev, *next;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	uint32_t auth_context_id;
	struct gensec_security *gensec_security;
	struct auth_session_info *session_info;
	NTSTATUS (*session_key_fn)(struct dcesrv_auth *, DATA_BLOB *session_key);
	bool auth_started;
	bool auth_finished;
	bool auth_audited;
	bool auth_invalid;
};

struct dcesrv_connection_context {
	struct dcesrv_connection_context *next, *prev;
	uint16_t context_id;

	/* the connection this is on */
	struct dcesrv_connection *conn;

	/* the ndr function table for the chosen interface */
	const struct dcesrv_interface *iface;

	/*
	 * the minimum required auth level for this interface
	 */
	enum dcerpc_AuthLevel min_auth_level;
	bool allow_connect;

	/* the negotiated transfer syntax */
	struct ndr_syntax_id transfer_syntax;
};


/* the state associated with a dcerpc server connection */
struct dcesrv_connection {
	/* for the broken_connections DLIST */
	struct dcesrv_connection *prev, *next;

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
	uint16_t max_recv_frag;
	uint16_t max_xmit_frag;

	DATA_BLOB partial_input;

	/* the event_context that will be used for this connection */
	struct tevent_context *event_ctx;

	/* is this connection pending termination?  If so, why? */
	const char *terminate;

	const char *packet_log_dir;

	/* this is the default state_flags for dcesrv_call_state structs */
	uint32_t state_flags;

	struct {
		void *private_data;
		void (*report_output_data)(struct dcesrv_connection *);
		void (*terminate_connection)(struct dcesrv_connection *,
					     const char *);
	} transport;

	struct tstream_context *stream;
	struct tevent_queue *send_queue;

	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;

	/* the current authentication state */
	struct dcesrv_auth *default_auth_state;
	size_t max_auth_states;
	struct dcesrv_auth *auth_states;
	bool got_explicit_auth_level_connect;
	struct dcesrv_auth *default_auth_level_connect;
	bool client_hdr_signing;
	bool support_hdr_signing;
	bool negotiated_hdr_signing;

	/*
	 * remember which pdu types are allowed
	 */
	bool allow_bind;
	bool allow_alter;

	/* the association group the connection belongs to */
	struct dcesrv_assoc_group *assoc_group;

	/* The maximum total payload of reassembled request pdus */
	size_t max_total_request_size;

	/*
	 * Our preferred transfer syntax.
	 */
	const struct ndr_syntax_id *preferred_transfer;

	/*
	 * This is used to block the connection during
	 * pending authentication.
	 */
	struct tevent_req *(*wait_send)(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					void *private_data);
	NTSTATUS (*wait_recv)(struct tevent_req *req);
	void *wait_private;
};


struct dcesrv_endpoint_server {
	/* this is the name of the endpoint server */
	const char *name;

	/* true if the endpoint server has been initialized */
	bool initialized;

	/* this function should register endpoints and some other setup stuff,
	 * it is called when the dcesrv_context gets initialized.
	 */
	NTSTATUS (*init_server)(struct dcesrv_context *, const struct dcesrv_endpoint_server *);

	/* this function should cleanup endpoint server state and unregister
	 * the endpoint server from dcesrv_context */
	NTSTATUS (*shutdown_server)(struct dcesrv_context *, const struct dcesrv_endpoint_server *);

	/* this function can be used by other endpoint servers to
	 * ask for a dcesrv_interface implementation
	 * - iface must be reference to an already existing struct !
	 */
	bool (*interface_by_uuid)(struct dcesrv_interface *iface, const struct GUID *, uint32_t);

	/* this function can be used by other endpoint servers to
	 * ask for a dcesrv_interface implementation
	 * - iface must be reference to an already existeng struct !
	 */
	bool (*interface_by_name)(struct dcesrv_interface *iface, const char *);
};


/* one association groups */
struct dcesrv_assoc_group {
	/* the wire id */
	uint32_t id;

	/* The transport this is valid on */
	enum dcerpc_transport_t transport;

	/* list of handles in this association group */
	struct dcesrv_handle *handles;

	/*
	 * list of iface states per assoc/conn
	 */
	struct dcesrv_iface_state *iface_states;

	/* parent context */
	struct dcesrv_context *dce_ctx;

	/* the negotiated bind time features */
	uint16_t bind_time_features;
};

struct dcesrv_context_callbacks {
	struct {
		void (*successful_authz)(struct dcesrv_call_state *);
	} log;
	struct {
		NTSTATUS (*gensec_prepare)(TALLOC_CTX *mem_ctx,
					struct dcesrv_call_state *call,
					struct gensec_security **out);
	} auth;
	struct {
		NTSTATUS (*find)(struct dcesrv_call_state *);
	} assoc_group;
};

/* server-wide context information for the dcerpc server */
struct dcesrv_context {
	/*
	 * The euid at startup time.
	 *
	 * This is required for DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM
	 */
	uid_t initial_euid;

	/* the list of endpoints that have registered
	 * by the configured endpoint servers
	 */
	struct dcesrv_endpoint {
		struct dcesrv_endpoint *next, *prev;
		/* the type and location of the endpoint */
		struct dcerpc_binding *ep_description;
		/* the secondary endpoint description for the BIND_ACK */
		struct dcerpc_binding *ep_2nd_description;
		/* the security descriptor for smb named pipes */
		struct security_descriptor *sd;
		/* the list of interfaces available on this endpoint */
		struct dcesrv_if_list {
			struct dcesrv_if_list *next, *prev;
			struct dcesrv_interface *iface;
		} *interface_list;

		/*
		 * Should this service be run in a single process (so far only
		 * NETLOGON is not run in a single process)
		 */
		bool use_single_process;
	} *endpoint_list;

	/* loadparm context to use for this connection */
	struct loadparm_context *lp_ctx;

	struct idr_context *assoc_groups_idr;

	struct dcesrv_connection *broken_connections;

	struct dcesrv_context_callbacks callbacks;
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

NTSTATUS dcesrv_interface_register(struct dcesrv_context *dce_ctx,
				   const char *ep_name,
				   const char *ncacn_np_secondary_endpoint,
				   const struct dcesrv_interface *iface,
				   const struct security_descriptor *sd);
NTSTATUS dcerpc_register_ep_server(const struct dcesrv_endpoint_server *ep_server);
NTSTATUS dcesrv_init_ep_servers(struct dcesrv_context *dce_ctx,
				const char **ep_servers);
NTSTATUS dcesrv_init_registered_ep_servers(struct dcesrv_context *dce_ctx);
NTSTATUS dcesrv_shutdown_registered_ep_servers(struct dcesrv_context *dce_ctx);
NTSTATUS dcesrv_init_ep_server(struct dcesrv_context *dce_ctx,
			       const char *ep_server_name);
NTSTATUS dcesrv_shutdown_ep_server(struct dcesrv_context *dce_ctx,
				   const char *name);
const struct dcesrv_endpoint_server *dcesrv_ep_server_byname(const char *name);

NTSTATUS dcesrv_init_context(TALLOC_CTX *mem_ctx,
			     struct loadparm_context *lp_ctx,
			     struct dcesrv_context_callbacks *cb,
			     struct dcesrv_context **_dce_ctx);
NTSTATUS dcesrv_reinit_context(struct dcesrv_context *dce_ctx);

NTSTATUS dcesrv_reply(struct dcesrv_call_state *call);
struct dcesrv_handle *dcesrv_handle_create(struct dcesrv_call_state *call,
					   uint8_t handle_type);

struct dcesrv_handle *dcesrv_handle_lookup(struct dcesrv_call_state *call,
					   const struct policy_handle *p,
					   uint8_t handle_type);

const struct tsocket_address *dcesrv_connection_get_local_address(struct dcesrv_connection *conn);
const struct tsocket_address *dcesrv_connection_get_remote_address(struct dcesrv_connection *conn);

/*
 * Fetch the authentication session key if available.
 *
 * This is the key generated by a gensec authentication.
 */
NTSTATUS dcesrv_auth_session_key(struct dcesrv_call_state *call,
				 DATA_BLOB *session_key);

/*
 * Fetch the transport session key if available.
 * Typically this is the SMB session key
 * or a fixed key for local transports.
 *
 * The key is always truncated to 16 bytes.
*/
NTSTATUS dcesrv_transport_session_key(struct dcesrv_call_state *call,
				      DATA_BLOB *session_key);

/* a useful macro for generating a RPC fault in the backend code */
#define DCESRV_FAULT(code) do { \
	dce_call->fault_code = code; \
	return r->out.result; \
} while(0)

/* a useful macro for generating a RPC fault in the backend code */
#define DCESRV_FAULT_VOID(code) do { \
	dce_call->fault_code = code; \
	return; \
} while(0)

/* a useful macro for checking the validity of a dcerpc policy handle
   and giving the right fault code if invalid */
#define DCESRV_CHECK_HANDLE(h) do {if (!(h)) DCESRV_FAULT(DCERPC_FAULT_CONTEXT_MISMATCH); } while (0)

/* this checks for a valid policy handle, and gives a fault if an
   invalid handle or retval if the handle is of the
   wrong type */
#define DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, retval) do { \
	(h) = dcesrv_handle_lookup(dce_call, (inhandle), DCESRV_HANDLE_ANY); \
	DCESRV_CHECK_HANDLE(h); \
	if ((t) != DCESRV_HANDLE_ANY && (h)->wire_handle.handle_type != (t)) { \
		return retval; \
	} \
} while (0)

/* this checks for a valid policy handle and gives a dcerpc fault
   if its the wrong type of handle */
#define DCESRV_PULL_HANDLE_FAULT(h, inhandle, t) do { \
	(h) = dcesrv_handle_lookup(dce_call, (inhandle), t); \
	DCESRV_CHECK_HANDLE(h); \
} while (0)

#define DCESRV_PULL_HANDLE(h, inhandle, t) DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, NT_STATUS_INVALID_HANDLE)
#define DCESRV_PULL_HANDLE_WERR(h, inhandle, t) DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, WERR_INVALID_HANDLE)

/**
 * retrieve credentials from a dce_call
 */
_PUBLIC_ struct cli_credentials *dcesrv_call_credentials(struct dcesrv_call_state *dce_call);

/**
 * returns true if this is an authenticated call
 */
_PUBLIC_ bool dcesrv_call_authenticated(struct dcesrv_call_state *dce_call);

/**
 * retrieve account_name for a dce_call
 */
_PUBLIC_ const char *dcesrv_call_account_name(struct dcesrv_call_state *dce_call);

/**
 * retrieve session_info from a dce_call
 */
_PUBLIC_ struct auth_session_info *dcesrv_call_session_info(struct dcesrv_call_state *dce_call);

/**
 * retrieve auth type/level from a dce_call
 */
_PUBLIC_ void dcesrv_call_auth_info(struct dcesrv_call_state *dce_call,
				    enum dcerpc_AuthType *auth_type,
				    enum dcerpc_AuthLevel *auth_level);

_PUBLIC_ NTSTATUS dcesrv_interface_bind_require_integrity(struct dcesrv_connection_context *context,
							  const struct dcesrv_interface *iface);
_PUBLIC_ NTSTATUS dcesrv_interface_bind_require_privacy(struct dcesrv_connection_context *context,
						        const struct dcesrv_interface *iface);
_PUBLIC_ NTSTATUS dcesrv_interface_bind_reject_connect(struct dcesrv_connection_context *context,
						       const struct dcesrv_interface *iface);
_PUBLIC_ NTSTATUS dcesrv_interface_bind_allow_connect(struct dcesrv_connection_context *context,
						      const struct dcesrv_interface *iface);

_PUBLIC_ NTSTATUS _dcesrv_iface_state_store_assoc(
		struct dcesrv_call_state *call,
		uint64_t magic,
		void *ptr,
		const char *location);
#define dcesrv_iface_state_store_assoc(call, magic, ptr) \
	_dcesrv_iface_state_store_assoc((call), (magic), (ptr), \
					__location__)
_PUBLIC_ void *_dcesrv_iface_state_find_assoc(
		struct dcesrv_call_state *call,
		uint64_t magic);
#define dcesrv_iface_state_find_assoc(call, magic, _type) \
	talloc_get_type( \
		_dcesrv_iface_state_find_assoc((call), (magic)), \
		_type)

_PUBLIC_ NTSTATUS _dcesrv_iface_state_store_conn(
		struct dcesrv_call_state *call,
		uint64_t magic,
		void *_pptr,
		const char *location);
#define dcesrv_iface_state_store_conn(call, magic, ptr) \
	_dcesrv_iface_state_store_conn((call), (magic), (ptr), \
					__location__)
_PUBLIC_ void *_dcesrv_iface_state_find_conn(
		struct dcesrv_call_state *call,
		uint64_t magic);
#define dcesrv_iface_state_find_conn(call, magic, _type) \
	talloc_get_type( \
		_dcesrv_iface_state_find_conn((call), (magic)), \
		_type)

_PUBLIC_ void dcesrv_cleanup_broken_connections(struct dcesrv_context *dce_ctx);

_PUBLIC_ NTSTATUS dcesrv_endpoint_connect(struct dcesrv_context *dce_ctx,
				TALLOC_CTX *mem_ctx,
				const struct dcesrv_endpoint *ep,
				struct auth_session_info *session_info,
				struct tevent_context *event_ctx,
				uint32_t state_flags,
				struct dcesrv_connection **_p);
_PUBLIC_ NTSTATUS dcesrv_find_endpoint(struct dcesrv_context *dce_ctx,
				const struct dcerpc_binding *ep_description,
				struct dcesrv_endpoint **_out);

_PUBLIC_ void dcesrv_terminate_connection(struct dcesrv_connection *dce_conn,
					  const char *reason);
_PUBLIC_ void dcesrv_sock_report_output_data(struct dcesrv_connection *dce_conn);

_PUBLIC_ NTSTATUS dcesrv_connection_loop_start(struct dcesrv_connection *conn);

_PUBLIC_ const struct dcesrv_interface *find_interface_by_uuid(
				const struct dcesrv_endpoint *endpoint,
				const struct GUID *uuid, uint32_t if_version);

void _dcesrv_save_ndr_fuzz_seed(DATA_BLOB call_blob,
				struct dcesrv_call_state *call,
				int flags);

#if DEVELOPER
#define  dcesrv_save_ndr_fuzz_seed(stub, call, flags) \
	_dcesrv_save_ndr_fuzz_seed(stub, call, flags)
#else
#define  dcesrv_save_ndr_fuzz_seed(stub, call, flags) \
        /* */
#endif


#endif /* _LIBRPC_RPC_DCESRV_CORE_H_ */

/* 
   Unix SMB/CIFS implementation.
   DCERPC interface structures

   Copyright (C) Tim Potter 2003
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

enum dcerpc_transport_t {
	NCACN_NP, NCACN_IP_TCP, NCACN_IP_UDP, NCACN_VNS_IPC, NCACN_VNS_SPP, 
	NCACN_AT_DSP, NCADG_AT_DDP, NCALRPC, NCACN_UNIX_STREAM, NCADG_UNIX_DGRAM,
	NCACN_HTTP, NCADG_IPX, NCACN_SPX };

/*
  this defines a generic security context for signed/sealed dcerpc pipes.
*/
struct dcerpc_pipe;
struct dcerpc_security {
	struct dcerpc_auth *auth_info;
	struct gensec_security *generic_state;

	/* get the session key */
	NTSTATUS (*session_key)(struct dcerpc_pipe *, DATA_BLOB *);
};

struct dcerpc_pipe {
	int reference_count;
	uint32_t call_id;
	uint32_t srv_max_xmit_frag;
	uint32_t srv_max_recv_frag;
	uint_t flags;
	struct dcerpc_security security_state;
	const char *binding_string;

	struct dcerpc_syntax_id syntax;
	struct dcerpc_syntax_id transfer_syntax;

	struct dcerpc_transport {
		enum dcerpc_transport_t transport;
		void *private;

		NTSTATUS (*shutdown_pipe)(struct dcerpc_pipe *);

		const char *(*peer_name)(struct dcerpc_pipe *);

		/* send a request to the server */
		NTSTATUS (*send_request)(struct dcerpc_pipe *, DATA_BLOB *, BOOL trigger_read);

		/* send a read request to the server */
		NTSTATUS (*send_read)(struct dcerpc_pipe *);

		/* get an event context for the connection */
		struct event_context *(*event_context)(struct dcerpc_pipe *);

		/* a callback to the dcerpc code when a full fragment
		   has been received */
		void (*recv_data)(struct dcerpc_pipe *, DATA_BLOB *, NTSTATUS status);

	} transport;

	/* the last fault code from a DCERPC fault */
	uint32_t last_fault_code;

	/* pending requests */
	struct rpc_request *pending;

	/* private pointer for pending full requests */
	void *full_request_private;
};

/* dcerpc pipe flags */
#define DCERPC_DEBUG_PRINT_IN          (1<<0)
#define DCERPC_DEBUG_PRINT_OUT         (1<<1)
#define DCERPC_DEBUG_PRINT_BOTH (DCERPC_DEBUG_PRINT_IN | DCERPC_DEBUG_PRINT_OUT)

#define DCERPC_DEBUG_VALIDATE_IN       (1<<2)
#define DCERPC_DEBUG_VALIDATE_OUT      (1<<3)
#define DCERPC_DEBUG_VALIDATE_BOTH (DCERPC_DEBUG_VALIDATE_IN | DCERPC_DEBUG_VALIDATE_OUT)

#define DCERPC_CONNECT                 (1<<4)
#define DCERPC_SIGN                    (1<<5)
#define DCERPC_SEAL                    (1<<6)

#define DCERPC_PUSH_BIGENDIAN          (1<<7)
#define DCERPC_PULL_BIGENDIAN          (1<<8)

#define DCERPC_SCHANNEL_BDC            (1<<9)
#define DCERPC_SCHANNEL_WORKSTATION    (1<<10)
#define DCERPC_SCHANNEL_DOMAIN         (1<<11)
#define DCERPC_SCHANNEL_ANY            (DCERPC_SCHANNEL_BDC| \
					DCERPC_SCHANNEL_DOMAIN| \
					DCERPC_SCHANNEL_WORKSTATION)
/* use a 128 bit session key */
#define DCERPC_SCHANNEL_128            (1<<12)

#define DCERPC_AUTH_OPTIONS    (DCERPC_SEAL|DCERPC_SIGN|DCERPC_SCHANNEL_ANY)

/* check incoming pad bytes */
#define DCERPC_DEBUG_PAD_CHECK         (1<<13)

/* set LIBNDR_FLAG_REF_ALLOC flag when decoding NDR */
#define DCERPC_NDR_REF_ALLOC           (1<<14)

/*
  this is used to find pointers to calls
*/
struct dcerpc_interface_call {
	const char *name;
	size_t struct_size;
	NTSTATUS (*ndr_push)(struct ndr_push *, int , void *);
	NTSTATUS (*ndr_pull)(struct ndr_pull *, int , void *);
	void (*ndr_print)(struct ndr_print *, const char *, int, void *);	
};

struct dcerpc_endpoint_list {
	uint32_t count;
	const char * const *names;
};

struct dcerpc_interface_table {
	const char *name;
	const char *uuid;
	uint32_t if_version;
	const char *helpstring;
	uint32_t num_calls;
	const struct dcerpc_interface_call *calls;
	const struct dcerpc_endpoint_list *endpoints;
};

struct dcerpc_interface_list
{
	struct dcerpc_interface_list *prev, *next;
	const struct dcerpc_interface_table *table;
};

extern struct dcerpc_interface_list *dcerpc_pipes;


/* this describes a binding to a particular transport/pipe */
struct dcerpc_binding {
	enum dcerpc_transport_t transport;
	struct GUID object;
	int object_version;
	const char *host;
	const char *endpoint;
	const char **options;
	uint32_t flags;
};


enum rpc_request_state {
	RPC_REQUEST_PENDING,
	RPC_REQUEST_DONE
};

/*
  handle for an async dcerpc request
*/
struct rpc_request {
	struct rpc_request *next, *prev;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	uint32_t call_id;
	enum rpc_request_state state;
	DATA_BLOB payload;
	uint_t flags;
	uint32_t fault_code;

	/* use by the ndr level async recv call */
	struct rpc_request_ndr {
		NTSTATUS (*ndr_push)(struct ndr_push *, int, void *);
		NTSTATUS (*ndr_pull)(struct ndr_pull *, int, void *);
		void *struct_ptr;
		size_t struct_size;
		TALLOC_CTX *mem_ctx;
	} ndr;

	struct {
		void (*callback)(struct rpc_request *);
		void *private;
	} async;
};

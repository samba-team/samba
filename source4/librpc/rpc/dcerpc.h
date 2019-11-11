/* 
   Unix SMB/CIFS implementation.

   DCERPC client side interface structures

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003-2005
   
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

/* This is a public header file that is installed as part of Samba. 
 * If you remove any functions or change their signature, update 
 * the so version number. */

#ifndef __S4_DCERPC_H__
#define __S4_DCERPC_H__

#include "../lib/util/data_blob.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "../librpc/ndr/libndr.h"
#include "../librpc/rpc/rpc_common.h"

struct tevent_context;
struct tevent_req;
struct dcerpc_binding_handle;
struct tstream_context;
struct ndr_interface_table;
struct resolve_context;

/*
  this defines a generic security context for signed/sealed dcerpc pipes.
*/
struct dcecli_connection;
struct gensec_settings;
struct cli_credentials;
struct dcecli_security {
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	uint32_t auth_context_id;
	struct {
		struct dcerpc_auth *out;
		struct dcerpc_auth *in;
		TALLOC_CTX *mem;
	} tmp_auth_info;
	struct gensec_security *generic_state;

	/* get the session key */
	NTSTATUS (*session_key)(struct dcecli_connection *, DATA_BLOB *);

	bool verified_bitmask1;

};

/*
  this holds the information that is not specific to a particular rpc context_id
*/
struct rpc_request;
struct dcecli_connection {
	uint32_t call_id;
	uint32_t srv_max_xmit_frag;
	uint32_t srv_max_recv_frag;
	uint32_t flags;
	struct dcecli_security security_state;
	struct tevent_context *event_ctx;

	struct tevent_immediate *io_trigger;
	bool io_trigger_pending;

	/** Directory in which to save ndrdump-parseable files */
	const char *packet_log_dir;

	bool dead;
	bool free_skipped;

	struct dcerpc_transport {
		enum dcerpc_transport_t transport;
		void *private_data;

		struct tstream_context *stream;
		/** to serialize write events */
		struct tevent_queue *write_queue;
		/** the current active read request if any */
		struct tevent_req *read_subreq;
		/** number of read requests other than the current active */
		uint32_t pending_reads;
	} transport;

	const char *server_name;

	/* Requests that have been sent, waiting for a reply */
	struct rpc_request *pending;

	/* Sync requests waiting to be shipped */
	struct rpc_request *request_queue;

	/* the next context_id to be assigned */
	uint32_t next_context_id;

	/* The maximum total payload of reassembled response pdus */
	size_t max_total_response_size;

	/* the negotiated bind time features */
	uint16_t bind_time_features;
};

/*
  this encapsulates a full dcerpc client side pipe 
*/
struct dcerpc_pipe {
	struct dcerpc_binding_handle *binding_handle;

	uint32_t context_id;

	struct GUID object;
	struct ndr_syntax_id syntax;
	struct ndr_syntax_id transfer_syntax;

	struct dcecli_connection *conn;
	const struct dcerpc_binding *binding;

	/** the last fault code from a DCERPC fault */
	uint32_t last_fault_code;

	/** timeout for individual rpc requests, in seconds */
	uint32_t request_timeout;

	/*
	 * Set for the timeout in dcerpc_pipe_connect_b_send(), to
	 * allow the timeout not to destory the stack during a nested
	 * event loop caused by gensec_update()
	 */
	bool inhibit_timeout_processing;
	bool timed_out;

	bool verified_pcontext;
};

/* default timeout for all rpc requests, in seconds */
#define DCERPC_REQUEST_TIMEOUT 60

struct epm_tower;
struct epm_floor;

struct smbcli_tree;
struct smb2_tree;
struct smbXcli_conn;
struct smbXcli_session;
struct smbXcli_tcon;
struct roh_connection;
struct tstream_tls_params;
struct socket_address;

NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx, 
			     struct dcerpc_pipe **pp, 
			     const char *binding,
			     const struct ndr_interface_table *table,
			     struct cli_credentials *credentials,
			     struct tevent_context *ev,
			     struct loadparm_context *lp_ctx);
const char *dcerpc_server_name(struct dcerpc_pipe *p);
struct dcerpc_pipe *dcerpc_pipe_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev);
NTSTATUS dcerpc_pipe_open_smb(struct dcerpc_pipe *p,
			      struct smbcli_tree *tree,
			      const char *pipe_name);
NTSTATUS dcerpc_pipe_open_smb2(struct dcerpc_pipe *p,
			       struct smb2_tree *tree,
			       const char *pipe_name);
NTSTATUS dcerpc_bind_auth_none(struct dcerpc_pipe *p,
			       const struct ndr_interface_table *table);
NTSTATUS dcerpc_fetch_session_key(struct dcerpc_pipe *p,
				  DATA_BLOB *session_key);
struct composite_context;
NTSTATUS dcerpc_secondary_connection_recv(struct composite_context *c,
					  struct dcerpc_pipe **p2);

struct composite_context* dcerpc_pipe_connect_b_send(TALLOC_CTX *parent_ctx,
						     const struct dcerpc_binding *binding,
						     const struct ndr_interface_table *table,
						     struct cli_credentials *credentials,
						     struct tevent_context *ev,
						     struct loadparm_context *lp_ctx);

NTSTATUS dcerpc_pipe_connect_b_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				    struct dcerpc_pipe **p);

NTSTATUS dcerpc_pipe_connect_b(TALLOC_CTX *parent_ctx,
			       struct dcerpc_pipe **pp,
			       const struct dcerpc_binding *binding,
			       const struct ndr_interface_table *table,
			       struct cli_credentials *credentials,
			       struct tevent_context *ev,
			       struct loadparm_context *lp_ctx);

NTSTATUS dcerpc_pipe_auth(TALLOC_CTX *mem_ctx,
			  struct dcerpc_pipe **p, 
			  const struct dcerpc_binding *binding,
			  const struct ndr_interface_table *table,
			  struct cli_credentials *credentials,
			  struct loadparm_context *lp_ctx);
NTSTATUS dcerpc_init(void);
struct composite_context *dcerpc_secondary_smb_send(struct dcecli_connection *c1,
						    struct dcecli_connection *c2,
						    const char *pipe_name);
NTSTATUS dcerpc_secondary_smb_recv(struct composite_context *c);
NTSTATUS dcerpc_secondary_context(struct dcerpc_pipe *p, 
				  struct dcerpc_pipe **pp2,
				  const struct ndr_interface_table *table);
NTSTATUS dcerpc_alter_context(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx,
			      const struct ndr_syntax_id *syntax,
			      const struct ndr_syntax_id *transfer_syntax);

NTSTATUS dcerpc_bind_auth(struct dcerpc_pipe *p,
			  const struct ndr_interface_table *table,
			  struct cli_credentials *credentials,
			  struct gensec_settings *gensec_settings,
			  uint8_t auth_type, uint8_t auth_level,
			  const char *service);
struct composite_context* dcerpc_pipe_connect_send(TALLOC_CTX *parent_ctx,
						   const char *binding,
						   const struct ndr_interface_table *table,
						   struct cli_credentials *credentials,
						   struct tevent_context *ev, struct loadparm_context *lp_ctx);
NTSTATUS dcerpc_pipe_connect_recv(struct composite_context *c,
				  TALLOC_CTX *mem_ctx,
				  struct dcerpc_pipe **pp);

NTSTATUS dcerpc_epm_map_binding(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding,
				const struct ndr_interface_table *table, struct tevent_context *ev,
				struct loadparm_context *lp_ctx);
struct composite_context* dcerpc_secondary_auth_connection_send(struct dcerpc_pipe *p,
								const struct dcerpc_binding *binding,
								const struct ndr_interface_table *table,
								struct cli_credentials *credentials,
								struct loadparm_context *lp_ctx);
NTSTATUS dcerpc_secondary_auth_connection_recv(struct composite_context *c, 
					       TALLOC_CTX *mem_ctx,
					       struct dcerpc_pipe **p);
NTSTATUS dcerpc_secondary_auth_connection(struct dcerpc_pipe *p,
					const struct dcerpc_binding *binding,
					const struct ndr_interface_table *table,
					struct cli_credentials *credentials,
					struct loadparm_context *lp_ctx,
					TALLOC_CTX *mem_ctx,
					struct dcerpc_pipe **p2);

struct composite_context* dcerpc_secondary_connection_send(struct dcerpc_pipe *p,
							   const struct dcerpc_binding *b);

#endif /* __S4_DCERPC_H__ */

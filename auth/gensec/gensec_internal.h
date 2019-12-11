/*
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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

#ifndef __GENSEC_INTERNAL_H__
#define __GENSEC_INTERNAL_H__

struct gensec_security;

struct gensec_security_ops {
	const char *name;
	const char *sasl_name;
	bool weak_crypto;
	uint8_t auth_type;  /* 0 if not offered on DCE-RPC */
	const char **oid;  /* NULL if not offered by SPNEGO */
	NTSTATUS (*client_start)(struct gensec_security *gensec_security);
	NTSTATUS (*server_start)(struct gensec_security *gensec_security);
	/**
	   Determine if a packet has the right 'magic' for this mechanism
	*/
	NTSTATUS (*magic)(struct gensec_security *gensec_security,
			  const DATA_BLOB *first_packet);
	struct tevent_req *(*update_send)(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct gensec_security *gensec_security,
					  const DATA_BLOB in);
	NTSTATUS (*update_recv)(struct tevent_req *req,
				TALLOC_CTX *out_mem_ctx,
				DATA_BLOB *out);
	NTSTATUS (*may_reset_crypto)(struct gensec_security *gensec_security,
				     bool full_reset);
	NTSTATUS (*seal_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				DATA_BLOB *sig);
	NTSTATUS (*sign_packet)(struct gensec_security *gensec_security, TALLOC_CTX *sig_mem_ctx,
				const uint8_t *data, size_t length,
				const uint8_t *whole_pdu, size_t pdu_length,
				DATA_BLOB *sig);
	size_t   (*sig_size)(struct gensec_security *gensec_security, size_t data_size);
	size_t   (*max_input_size)(struct gensec_security *gensec_security);
	size_t   (*max_wrapped_size)(struct gensec_security *gensec_security);
	NTSTATUS (*check_packet)(struct gensec_security *gensec_security,
				 const uint8_t *data, size_t length,
				 const uint8_t *whole_pdu, size_t pdu_length,
				 const DATA_BLOB *sig);
	NTSTATUS (*unseal_packet)(struct gensec_security *gensec_security,
				  uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  const DATA_BLOB *sig);
	NTSTATUS (*wrap)(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *in,
				  DATA_BLOB *out);
	NTSTATUS (*unwrap)(struct gensec_security *gensec_security,
			   TALLOC_CTX *mem_ctx,
			   const DATA_BLOB *in,
			   DATA_BLOB *out);
	NTSTATUS (*session_key)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx,
				DATA_BLOB *session_key);
	NTSTATUS (*session_info)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx,
				 struct auth_session_info **session_info);
	void (*want_feature)(struct gensec_security *gensec_security,
				    uint32_t feature);
	bool (*have_feature)(struct gensec_security *gensec_security,
				    uint32_t feature);
	NTTIME (*expire_time)(struct gensec_security *gensec_security);
	const char *(*final_auth_type)(struct gensec_security *gensec_security);
	bool enabled;
	bool kerberos;
	enum gensec_priority priority;
	bool glue;
};

struct gensec_security_ops_wrapper {
	const struct gensec_security_ops *op;
	const char *oid;
};

struct gensec_security {
	const struct gensec_security_ops *ops;
	void *private_data;
	struct cli_credentials *credentials;
	struct gensec_target target;
	enum gensec_role gensec_role;
	bool subcontext;
	uint32_t want_features;
	uint32_t max_update_size;
	uint8_t dcerpc_auth_level;
	struct tsocket_address *local_addr, *remote_addr;
	struct gensec_settings *settings;

	/* When we are a server, this may be filled in to provide an
	 * NTLM authentication backend, and user lookup (such as if no
	 * PAC is found) */
	struct auth4_context *auth_context;

	struct gensec_security *parent_security;
	struct gensec_security *child_security;

	/*
	 * This is used to mark the context as being
	 * busy in an async gensec_update_send().
	 */
	struct gensec_security **update_busy_ptr;
};

/* this structure is used by backends to determine the size of some critical types */
struct gensec_critical_sizes {
	int interface_version;
	int sizeof_gensec_security_ops;
	int sizeof_gensec_security;
};

NTSTATUS gensec_may_reset_crypto(struct gensec_security *gensec_security,
				 bool full_reset);

const char *gensec_final_auth_type(struct gensec_security *gensec_security);

NTSTATUS gensec_child_ready(struct gensec_security *parent,
			    struct gensec_security *child);
void gensec_child_want_feature(struct gensec_security *gensec_security,
			       uint32_t feature);
bool gensec_child_have_feature(struct gensec_security *gensec_security,
			       uint32_t feature);
NTSTATUS gensec_child_unseal_packet(struct gensec_security *gensec_security,
				    uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    const DATA_BLOB *sig);
NTSTATUS gensec_child_check_packet(struct gensec_security *gensec_security,
				   const uint8_t *data, size_t length,
				   const uint8_t *whole_pdu, size_t pdu_length,
				   const DATA_BLOB *sig);
NTSTATUS gensec_child_seal_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig);
NTSTATUS gensec_child_sign_packet(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  const uint8_t *data, size_t length,
				  const uint8_t *whole_pdu, size_t pdu_length,
				  DATA_BLOB *sig);
NTSTATUS gensec_child_wrap(struct gensec_security *gensec_security,
			   TALLOC_CTX *mem_ctx,
			   const DATA_BLOB *in,
			   DATA_BLOB *out);
NTSTATUS gensec_child_unwrap(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out);
size_t gensec_child_sig_size(struct gensec_security *gensec_security,
			     size_t data_size);
size_t gensec_child_max_input_size(struct gensec_security *gensec_security);
size_t gensec_child_max_wrapped_size(struct gensec_security *gensec_security);
NTSTATUS gensec_child_session_key(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *session_key);
NTSTATUS gensec_child_session_info(struct gensec_security *gensec_security,
				   TALLOC_CTX *mem_ctx,
				   struct auth_session_info **session_info);
NTTIME gensec_child_expire_time(struct gensec_security *gensec_security);
const char *gensec_child_final_auth_type(struct gensec_security *gensec_security);

#endif /* __GENSEC_H__ */

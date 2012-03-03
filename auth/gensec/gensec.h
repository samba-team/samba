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

#ifndef __GENSEC_H__
#define __GENSEC_H__

#include "../lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"

#define GENSEC_SASL_NAME_NTLMSSP "NTLM"

#define GENSEC_OID_NTLMSSP "1.3.6.1.4.1.311.2.2.10"
#define GENSEC_OID_SPNEGO "1.3.6.1.5.5.2"
#define GENSEC_OID_KERBEROS5 "1.2.840.113554.1.2.2"
#define GENSEC_OID_KERBEROS5_OLD "1.2.840.48018.1.2.2"
#define GENSEC_OID_KERBEROS5_USER2USER "1.2.840.113554.1.2.2.3"

enum gensec_priority {
	GENSEC_SPNEGO = 90,
	GENSEC_GSSAPI = 80,
	GENSEC_KRB5 = 70,
	GENSEC_SCHANNEL = 60,
	GENSEC_NTLMSSP = 50,
	GENSEC_SASL = 20,
	GENSEC_OTHER = 0
};

struct gensec_security;
struct gensec_target {
	const char *principal;
	const char *hostname;
	const char *service;
};

#define GENSEC_FEATURE_SESSION_KEY	0x00000001
#define GENSEC_FEATURE_SIGN		0x00000002
#define GENSEC_FEATURE_SEAL		0x00000004
#define GENSEC_FEATURE_DCE_STYLE	0x00000008
#define GENSEC_FEATURE_ASYNC_REPLIES	0x00000010
#define GENSEC_FEATURE_DATAGRAM_MODE	0x00000020
#define GENSEC_FEATURE_SIGN_PKT_HEADER	0x00000040
#define GENSEC_FEATURE_NEW_SPNEGO	0x00000080
#define GENSEC_FEATURE_UNIX_TOKEN	0x00000100

#define GENSEC_EXPIRE_TIME_INFINITY (NTTIME)0x8000000000000000LL

/* GENSEC mode */
enum gensec_role
{
	GENSEC_SERVER,
	GENSEC_CLIENT
};

struct auth_session_info;
struct cli_credentials;
struct gensec_settings;
struct tevent_context;
struct tevent_req;
struct smb_krb5_context;

struct gensec_settings {
	struct loadparm_context *lp_ctx;
	const char *target_hostname;

	/* this allows callers to specify a specific set of ops that
	 * should be used, rather than those loaded by the plugin
	 * mechanism */
	struct gensec_security_ops **backends;

	/* To fill in our own name in the NTLMSSP server */
	const char *server_dns_domain;
	const char *server_dns_name;
	const char *server_netbios_domain;
	const char *server_netbios_name;
};

struct gensec_security_ops {
	const char *name;
	const char *sasl_name;
	uint8_t auth_type;  /* 0 if not offered on DCE-RPC */
	const char **oid;  /* NULL if not offered by SPNEGO */
	NTSTATUS (*client_start)(struct gensec_security *gensec_security);
	NTSTATUS (*server_start)(struct gensec_security *gensec_security);
	/**
	   Determine if a packet has the right 'magic' for this mechanism
	*/
	NTSTATUS (*magic)(struct gensec_security *gensec_security,
			  const DATA_BLOB *first_packet);
	NTSTATUS (*update)(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx,
			   struct tevent_context *ev,
			   const DATA_BLOB in, DATA_BLOB *out);
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
	NTSTATUS (*wrap_packets)(struct gensec_security *gensec_security,
				 TALLOC_CTX *mem_ctx,
				 const DATA_BLOB *in,
				 DATA_BLOB *out,
				 size_t *len_processed);
	NTSTATUS (*unwrap_packets)(struct gensec_security *gensec_security,
				   TALLOC_CTX *mem_ctx,
				   const DATA_BLOB *in,
				   DATA_BLOB *out,
				   size_t *len_processed);
	NTSTATUS (*packet_full_request)(struct gensec_security *gensec_security,
					DATA_BLOB blob, size_t *size);
	NTSTATUS (*session_key)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx,
				DATA_BLOB *session_key);
	NTSTATUS (*session_info)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx,
				 struct auth_session_info **session_info);
	void (*want_feature)(struct gensec_security *gensec_security,
				    uint32_t feature);
	bool (*have_feature)(struct gensec_security *gensec_security,
				    uint32_t feature);
	NTTIME (*expire_time)(struct gensec_security *gensec_security);
	bool enabled;
	bool kerberos;
	enum gensec_priority priority;
};

struct gensec_security_ops_wrapper {
	const struct gensec_security_ops *op;
	const char *oid;
};

#define GENSEC_INTERFACE_VERSION 0

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
};

/* this structure is used by backends to determine the size of some critical types */
struct gensec_critical_sizes {
	int interface_version;
	int sizeof_gensec_security_ops;
	int sizeof_gensec_security;
};

/* Socket wrapper */

struct gensec_security;
struct socket_context;
struct auth4_context;
struct auth_user_info_dc;

/* These functions are for use here only (public because SPNEGO must
 * use them for recursion) */
NTSTATUS gensec_wrap_packets(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *in,
			     DATA_BLOB *out,
			     size_t *len_processed);
/* These functions are for use here only (public because SPNEGO must
 * use them for recursion) */
NTSTATUS gensec_unwrap_packets(struct gensec_security *gensec_security,
			       TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *in,
			       DATA_BLOB *out,
			       size_t *len_processed);

/* These functions are for use here only (public because SPNEGO must
 * use them for recursion) */
NTSTATUS gensec_packet_full_request(struct gensec_security *gensec_security,
				    DATA_BLOB blob, size_t *size);

struct loadparm_context;

NTSTATUS gensec_subcontext_start(TALLOC_CTX *mem_ctx,
				 struct gensec_security *parent,
				 struct gensec_security **gensec_security);
NTSTATUS gensec_client_start(TALLOC_CTX *mem_ctx,
			     struct gensec_security **gensec_security,
			     struct gensec_settings *settings);
NTSTATUS gensec_start_mech_by_ops(struct gensec_security *gensec_security,
				  const struct gensec_security_ops *ops);
NTSTATUS gensec_start_mech_by_sasl_list(struct gensec_security *gensec_security,
						 const char **sasl_names);
void gensec_set_max_update_size(struct gensec_security *gensec_security,
				uint32_t max_update_size);
size_t gensec_max_update_size(struct gensec_security *gensec_security);
NTSTATUS gensec_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx,
		       struct tevent_context *ev,
		       const DATA_BLOB in, DATA_BLOB *out);
struct tevent_req *gensec_update_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct gensec_security *gensec_security,
				      const DATA_BLOB in);
NTSTATUS gensec_update_recv(struct tevent_req *req, TALLOC_CTX *out_mem_ctx, DATA_BLOB *out);
void gensec_want_feature(struct gensec_security *gensec_security,
			 uint32_t feature);
bool gensec_have_feature(struct gensec_security *gensec_security,
			 uint32_t feature);
NTTIME gensec_expire_time(struct gensec_security *gensec_security);
NTSTATUS gensec_set_credentials(struct gensec_security *gensec_security, struct cli_credentials *credentials);
NTSTATUS gensec_set_target_service(struct gensec_security *gensec_security, const char *service);
const char *gensec_get_target_service(struct gensec_security *gensec_security);
NTSTATUS gensec_set_target_hostname(struct gensec_security *gensec_security, const char *hostname);
const char *gensec_get_target_hostname(struct gensec_security *gensec_security);
NTSTATUS gensec_session_key(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *session_key);
NTSTATUS gensec_start_mech_by_oid(struct gensec_security *gensec_security,
				  const char *mech_oid);
const char *gensec_get_name_by_oid(struct gensec_security *gensec_security, const char *oid_string);
struct cli_credentials *gensec_get_credentials(struct gensec_security *gensec_security);
NTSTATUS gensec_init(void);
NTSTATUS gensec_register(const struct gensec_security_ops *ops);
const struct gensec_security_ops *gensec_security_by_oid(struct gensec_security *gensec_security,
							 const char *oid_string);
const struct gensec_security_ops *gensec_security_by_sasl_name(struct gensec_security *gensec_security,
							       const char *sasl_name);
struct gensec_security_ops **gensec_security_mechs(struct gensec_security *gensec_security,
						   TALLOC_CTX *mem_ctx);
const struct gensec_security_ops_wrapper *gensec_security_by_oid_list(
					struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx,
					const char **oid_strings,
					const char *skip);
const char **gensec_security_oids(struct gensec_security *gensec_security,
				  TALLOC_CTX *mem_ctx,
				  const char *skip);
const char **gensec_security_oids_from_ops_wrapped(TALLOC_CTX *mem_ctx,
				const struct gensec_security_ops_wrapper *wops);
size_t gensec_max_input_size(struct gensec_security *gensec_security);
size_t gensec_max_wrapped_size(struct gensec_security *gensec_security);
NTSTATUS gensec_unseal_packet(struct gensec_security *gensec_security,
			      uint8_t *data, size_t length,
			      const uint8_t *whole_pdu, size_t pdu_length,
			      const DATA_BLOB *sig);
NTSTATUS gensec_check_packet(struct gensec_security *gensec_security,
			     const uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     const DATA_BLOB *sig);
size_t gensec_sig_size(struct gensec_security *gensec_security, size_t data_size);
NTSTATUS gensec_seal_packet(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    DATA_BLOB *sig);
NTSTATUS gensec_sign_packet(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    const uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    DATA_BLOB *sig);
NTSTATUS gensec_start_mech(struct gensec_security *gensec_security);
NTSTATUS gensec_start_mech_by_authtype(struct gensec_security *gensec_security,
				       uint8_t auth_type, uint8_t auth_level);
const char *gensec_get_name_by_authtype(struct gensec_security *gensec_security, uint8_t authtype);
NTSTATUS gensec_server_start(TALLOC_CTX *mem_ctx,
			     struct gensec_settings *settings,
			     struct auth4_context *auth_context,
			     struct gensec_security **gensec_security);
NTSTATUS gensec_session_info(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     struct auth_session_info **session_info);

NTSTATUS gensec_set_local_address(struct gensec_security *gensec_security,
		const struct tsocket_address *local);
NTSTATUS gensec_set_remote_address(struct gensec_security *gensec_security,
		const struct tsocket_address *remote);
const struct tsocket_address *gensec_get_local_address(struct gensec_security *gensec_security);
const struct tsocket_address *gensec_get_remote_address(struct gensec_security *gensec_security);

NTSTATUS gensec_start_mech_by_name(struct gensec_security *gensec_security,
					const char *name);

NTSTATUS gensec_unwrap(struct gensec_security *gensec_security,
		       TALLOC_CTX *mem_ctx,
		       const DATA_BLOB *in,
		       DATA_BLOB *out);
NTSTATUS gensec_wrap(struct gensec_security *gensec_security,
		     TALLOC_CTX *mem_ctx,
		     const DATA_BLOB *in,
		     DATA_BLOB *out);

struct gensec_security_ops **gensec_security_all(void);
bool gensec_security_ops_enabled(struct gensec_security_ops *ops, struct gensec_security *security);
struct gensec_security_ops **gensec_use_kerberos_mechs(TALLOC_CTX *mem_ctx,
						       struct gensec_security_ops **old_gensec_list,
						       struct cli_credentials *creds);

NTSTATUS gensec_start_mech_by_sasl_name(struct gensec_security *gensec_security,
					const char *sasl_name);

int gensec_setting_int(struct gensec_settings *settings, const char *mechanism, const char *name, int default_value);
bool gensec_setting_bool(struct gensec_settings *settings, const char *mechanism, const char *name, bool default_value);

NTSTATUS gensec_set_target_principal(struct gensec_security *gensec_security, const char *principal);
const char *gensec_get_target_principal(struct gensec_security *gensec_security);

NTSTATUS gensec_generate_session_info_pac(TALLOC_CTX *mem_ctx,
					  struct gensec_security *gensec_security,
					  struct smb_krb5_context *smb_krb5_context,
					  DATA_BLOB *pac_blob,
					  const char *principal_string,
					  const struct tsocket_address *remote_address,
					  struct auth_session_info **session_info);

NTSTATUS gensec_magic_check_krb5_oid(struct gensec_security *unused,
					const DATA_BLOB *blob);

#endif /* __GENSEC_H__ */

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

#define GENSEC_FINAL_AUTH_TYPE_KRB5 "krb5"
#define GENSEC_FINAL_AUTH_TYPE_NTLMSSP "NTLMSSP"

enum gensec_priority {
	GENSEC_SPNEGO = 90,
	GENSEC_GSSAPI = 80,
	GENSEC_KRB5 = 70,
	GENSEC_SCHANNEL = 60,
	GENSEC_NTLMSSP = 50,
	GENSEC_SASL = 20,
	GENSEC_OTHER = 10,
	GENSEC_EXTERNAL = 0
};

struct gensec_security;
struct gensec_target {
	const char *principal;
	const char *hostname;
	const char *service;
	const char *service_description;
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
#define GENSEC_FEATURE_NTLM_CCACHE	0x00000200
#define GENSEC_FEATURE_LDAP_STYLE	0x00000400
#define GENSEC_FEATURE_NO_AUTHZ_LOG	0x00000800
#define GENSEC_FEATURE_SMB_TRANSPORT	0x00001000
#define GENSEC_FEATURE_LDAPS_TRANSPORT	0x00002000

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
struct tsocket_address;

struct gensec_settings {
	struct loadparm_context *lp_ctx;
	const char *target_hostname;

	/* this allows callers to specify a specific set of ops that
	 * should be used, rather than those loaded by the plugin
	 * mechanism */
	const struct gensec_security_ops * const *backends;

	/* To fill in our own name in the NTLMSSP server */
	const char *server_dns_domain;
	const char *server_dns_name;
	const char *server_netbios_domain;
	const char *server_netbios_name;
};

struct gensec_security_ops;
struct gensec_security_ops_wrapper;

/* Change to 1, loadable modules now take a TALLOC_CTX * init() parameter. */
#define GENSEC_INTERFACE_VERSION 1

/* this structure is used by backends to determine the size of some critical types */
struct gensec_critical_sizes;
const struct gensec_critical_sizes *gensec_interface_version(void);

/* Socket wrapper */

struct gensec_security;
struct auth4_context;
struct auth_user_info_dc;

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
NTSTATUS gensec_update(struct gensec_security *gensec_security,
		       TALLOC_CTX *out_mem_ctx,
		       const DATA_BLOB in, DATA_BLOB *out);
struct tevent_req *gensec_update_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct gensec_security *gensec_security,
				      const DATA_BLOB in);
NTSTATUS gensec_update_recv(struct tevent_req *req, TALLOC_CTX *out_mem_ctx, DATA_BLOB *out);

#define GENSEC_UPDATE_IS_NTERROR(status) ( \
	!NT_STATUS_IS_OK(status) && \
	!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) \
	)

/**
 * @brief Ask for features for a following authentication
 *
 * Typically only one specific feature bit should be passed,
 * but it also works to ask for more features.
 *
 * The features must be requested before starting the
 * gensec_update*() loop.
 *
 * The current expection is GENSEC_FEATURE_SIGN_PKT_HEADER,
 * it can also be requested once the gensec_update*() loop
 * returned NT_STATUS_OK.
 *
 * The features should not be changed during the gensec_update*()
 * loop.
 *
 * @param[in]  gensec_security The context to be used
 *
 * @param[in]  feature         The requested feature[s].
 *
 */
void gensec_want_feature(struct gensec_security *gensec_security,
			 uint32_t feature);
/**
 * @brief Ask for one feature after the finished authentication
 *
 * Because the return value is bool, the caller can only
 * ask for one feature at a time.
 *
 * The features must be requested after the finished
 * gensec_update*() loop.
 *
 * The current expection is GENSEC_FEATURE_SIGN_PKT_HEADER,
 * it can also be requested before the gensec_update*() loop,
 * as the return value only indicates if the backend supports
 * dcerpc header signing, not if header signing will be used
 * between client and server. It will be used only if the caller
 * also used gensec_want_feature(GENSEC_FEATURE_SIGN_PKT_HEADER).
 *
 * @param[in]  gensec_security The context to be used.
 *
 * @param[in]  feature         The requested feature.
 *
 * @return                     true if the feature is supported, false if not.
 */
bool gensec_have_feature(struct gensec_security *gensec_security,
			 uint32_t feature);
NTTIME gensec_expire_time(struct gensec_security *gensec_security);
NTSTATUS gensec_set_credentials(struct gensec_security *gensec_security, struct cli_credentials *credentials);
/**
 * Set the target service (such as 'http' or 'host') on a GENSEC context - ensures it is talloc()ed
 *
 * This is used for Kerberos service principal name resolution.
 */

NTSTATUS gensec_set_target_service(struct gensec_security *gensec_security, const char *service);
const char *gensec_get_target_service(struct gensec_security *gensec_security);
NTSTATUS gensec_set_target_hostname(struct gensec_security *gensec_security, const char *hostname);
const char *gensec_get_target_hostname(struct gensec_security *gensec_security);
/**
 * Set the target service (such as 'samr') on an GENSEC context - ensures it is talloc()ed.
 *
 * This is not the Kerberos service principal, instead this is a
 * constant value that can be logged as part of authentication and
 * authorization logging
 */
const char *gensec_get_target_service_description(struct gensec_security *gensec_security);
NTSTATUS gensec_set_target_service_description(struct gensec_security *gensec_security,
					       const char *service);
NTSTATUS gensec_session_key(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *session_key);
NTSTATUS gensec_start_mech_by_oid(struct gensec_security *gensec_security,
				  const char *mech_oid);
const char *gensec_get_name_by_oid(struct gensec_security *gensec_security, const char *oid_string);
struct cli_credentials *gensec_get_credentials(struct gensec_security *gensec_security);
NTSTATUS gensec_init(void);
NTSTATUS gensec_register(TALLOC_CTX *ctx,
		const struct gensec_security_ops *ops);
const struct gensec_security_ops *gensec_security_by_oid(struct gensec_security *gensec_security,
							 const char *oid_string);
const struct gensec_security_ops *gensec_security_by_sasl_name(struct gensec_security *gensec_security,
							       const char *sasl_name);
const struct gensec_security_ops *gensec_security_by_auth_type(
				struct gensec_security *gensec_security,
				uint32_t auth_type);
const struct gensec_security_ops *gensec_security_by_name(struct gensec_security *gensec_security,
							  const char *name);
const struct gensec_security_ops **gensec_security_mechs(struct gensec_security *gensec_security,
						   TALLOC_CTX *mem_ctx);
const struct gensec_security_ops_wrapper *gensec_security_by_oid_list(
					struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx,
					const char * const *oid_strings,
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

const struct gensec_security_ops * const *gensec_security_all(void);
bool gensec_security_ops_enabled(const struct gensec_security_ops *ops, struct gensec_security *security);
const struct gensec_security_ops **gensec_use_kerberos_mechs(TALLOC_CTX *mem_ctx,
			const struct gensec_security_ops * const *old_gensec_list,
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

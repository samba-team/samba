/*
   Unix SMB/CIFS implementation.
   Standardised Authentication types
   Copyright (C) Andrew Bartlett   2001
   Copyright (C) Stefan Metzmacher 2005

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

#ifndef _SAMBA_AUTH_H
#define _SAMBA_AUTH_H

#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "librpc/gen_ndr/auth.h"
#include "../auth/common_auth.h"

extern const char *krbtgt_attrs[];
extern const char *server_attrs[];
extern const char *user_attrs[];

union netr_Validation;
struct netr_SamBaseInfo;
struct netr_SamInfo3;
struct loadparm_context;

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct auth_critical_sizes.
 */
/* version 1 - version from samba 3.0 - metze */
/* version 2 - initial samba4 version - metze */
/* version 3 - subsequent samba4 version - abartlet */
/* version 4 - subsequent samba4 version - metze */
/* version 0 - till samba4 is stable - metze */
#define AUTH4_INTERFACE_VERSION 0

struct auth_method_context;
struct auth4_context;
struct auth_session_info;
struct ldb_dn;
struct smb_krb5_context;

struct auth_operations {
	const char *name;

	/* Given the user supplied info, check if this backend want to handle the password checking */

	NTSTATUS (*want_check)(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx,
			       const struct auth_usersupplied_info *user_info);

	/* Given the user supplied info, check a password */

	NTSTATUS (*check_password)(struct auth_method_context *ctx, TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info,
				   struct auth_user_info_dc **interim_info,
				   bool *authoritative);
	struct tevent_req *(*check_password_send)(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct auth_method_context *ctx,
				const struct auth_usersupplied_info *user_info);
	NTSTATUS (*check_password_recv)(struct tevent_req *subreq,
				TALLOC_CTX *mem_ctx,
				struct auth_user_info_dc **interim_info,
				bool *authoritative);

	/* Lookup a 'session info interim' return based only on the principal or DN */
	NTSTATUS (*get_user_info_dc_principal)(TALLOC_CTX *mem_ctx,
						       struct auth4_context *auth_context,
						       const char *principal,
						       struct ldb_dn *user_dn,
						       struct auth_user_info_dc **interim_info);
	uint32_t flags;
};

struct auth_method_context {
	struct auth_method_context *prev, *next;
	struct auth4_context *auth_ctx;
	const struct auth_operations *ops;
	int depth;
	void *private_data;
};

/* this structure is used by backends to determine the size of some critical types */
struct auth_critical_sizes {
	int interface_version;
	int sizeof_auth_operations;
	int sizeof_auth_methods;
	int sizeof_auth_context;
	int sizeof_auth_usersupplied_info;
	int sizeof_auth_user_info_dc;
};

 NTSTATUS encrypt_user_info(TALLOC_CTX *mem_ctx, struct auth4_context *auth_context,
			   enum auth_password_state to_state,
			   const struct auth_usersupplied_info *user_info_in,
			   const struct auth_usersupplied_info **user_info_encrypted);

#include "auth/session.h"
#include "auth/unix_token_proto.h"
#include "auth/system_session_proto.h"
#include "libcli/security/security.h"

struct ldb_message;
struct ldb_context;
struct gensec_security;
struct cli_credentials;

NTSTATUS auth_get_challenge(struct auth4_context *auth_ctx, uint8_t chal[8]);
NTSTATUS authsam_account_ok(TALLOC_CTX *mem_ctx,
			    struct ldb_context *sam_ctx,
			    uint32_t logon_parameters,
			    struct ldb_dn *domain_dn,
			    struct ldb_message *msg,
			    const char *logon_workstation,
			    const char *name_for_logs,
			    bool allow_domain_trust,
			    bool password_change);

struct auth_session_info *system_session(struct loadparm_context *lp_ctx);
NTSTATUS authsam_make_user_info_dc(TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx,
					   const char *netbios_name,
					   const char *domain_name,
					   const char *dns_domain_name,
					   struct ldb_dn *domain_dn,
					   struct ldb_message *msg,
					   DATA_BLOB user_sess_key, DATA_BLOB lm_sess_key,
				  struct auth_user_info_dc **_user_info_dc);
NTSTATUS authsam_update_user_info_dc(TALLOC_CTX *mem_ctx,
			struct ldb_context *sam_ctx,
			struct auth_user_info_dc *user_info_dc);
NTSTATUS auth_system_session_info(TALLOC_CTX *parent_ctx,
					   struct loadparm_context *lp_ctx,
					   struct auth_session_info **_session_info) ;

NTSTATUS auth_context_create_methods(TALLOC_CTX *mem_ctx, const char * const *methods,
				     struct tevent_context *ev,
				     struct imessaging_context *msg,
				     struct loadparm_context *lp_ctx,
				     struct ldb_context *sam_ctx,
				     struct auth4_context **auth_ctx);
const char **auth_methods_from_lp(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);

NTSTATUS auth_context_create(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     struct imessaging_context *msg,
			     struct loadparm_context *lp_ctx,
			     struct auth4_context **auth_ctx);
NTSTATUS auth_context_create_for_netlogon(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct imessaging_context *msg,
					  struct loadparm_context *lp_ctx,
					  struct auth4_context **auth_ctx);

NTSTATUS auth_check_password(struct auth4_context *auth_ctx,
			     TALLOC_CTX *mem_ctx,
			     const struct auth_usersupplied_info *user_info, 
			     struct auth_user_info_dc **user_info_dc,
			     uint8_t *pauthoritative);
NTSTATUS auth4_init(void);
NTSTATUS auth_register(TALLOC_CTX *mem_ctx, const struct auth_operations *ops);
NTSTATUS server_service_auth_init(TALLOC_CTX *ctx);
struct tevent_req *authenticate_ldap_simple_bind_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct imessaging_context *msg,
					struct loadparm_context *lp_ctx,
					struct tsocket_address *remote_address,
					struct tsocket_address *local_address,
					bool using_tls,
					const char *dn,
					const char *password);
NTSTATUS authenticate_ldap_simple_bind_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					struct auth_session_info **session_info);
NTSTATUS authenticate_ldap_simple_bind(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct imessaging_context *msg,
				       struct loadparm_context *lp_ctx,
				       struct tsocket_address *remote_address,
				       struct tsocket_address *local_address,
				       bool using_tls,
				       const char *dn,
				       const char *password,
				       struct auth_session_info **session_info);

struct tevent_req *auth_check_password_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct auth4_context *auth_ctx,
					    const struct auth_usersupplied_info *user_info);
NTSTATUS auth_check_password_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct auth_user_info_dc **user_info_dc,
				  uint8_t *pauthoritative);

NTSTATUS auth_context_set_challenge(struct auth4_context *auth_ctx, const uint8_t chal[8], const char *set_by);

NTSTATUS samba_server_gensec_start(TALLOC_CTX *mem_ctx,
				   struct tevent_context *event_ctx,
				   struct imessaging_context *msg_ctx,
				   struct loadparm_context *lp_ctx,
				   struct cli_credentials *server_credentials,
				   const char *target_service,
				   struct gensec_security **gensec_context);
NTSTATUS samba_server_gensec_krb5_start(TALLOC_CTX *mem_ctx,
					struct tevent_context *event_ctx,
					struct imessaging_context *msg_ctx,
					struct loadparm_context *lp_ctx,
					struct cli_credentials *server_credentials,
					const char *target_service,
					struct gensec_security **gensec_context);

#endif /* _SMBAUTH_H_ */

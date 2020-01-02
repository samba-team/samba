/*
   Unix SMB/CIFS implementation.
   Standardised Authentication types
   Copyright (C) Andrew Bartlett 2001-2010

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

#ifndef AUTH_COMMON_AUTH_H
#define AUTH_COMMON_AUTH_H

#include "librpc/gen_ndr/auth.h"

#define USER_INFO_CASE_INSENSITIVE_USERNAME 0x01 /* username may be in any case */
#define USER_INFO_CASE_INSENSITIVE_PASSWORD 0x02 /* password may be in any case */
#define USER_INFO_DONT_CHECK_UNIX_ACCOUNT   0x04 /* don't check unix account status */
#define USER_INFO_INTERACTIVE_LOGON         0x08 /* Interactive logon */
/*unused #define USER_INFO_LOCAL_SAM_ONLY   0x10    Only authenticate against the local SAM, do not map missing passwords to NO_SUCH_USER */
#define USER_INFO_INFO3_AND_NO_AUTHZ        0x20 /* Only fill in server_info->info3 and do not do any authorization steps */

enum auth_password_state {
	AUTH_PASSWORD_PLAIN = 1,
	AUTH_PASSWORD_HASH = 2,
	AUTH_PASSWORD_RESPONSE = 3
};

#define AUTH_SESSION_INFO_DEFAULT_GROUPS     0x01 /* Add the user to the default world and network groups */
#define AUTH_SESSION_INFO_AUTHENTICATED      0x02 /* Add the user to the 'authenticated users' group */
#define AUTH_SESSION_INFO_SIMPLE_PRIVILEGES  0x04 /* Use a trivial map between users and privilages, rather than a DB */
#define AUTH_SESSION_INFO_UNIX_TOKEN         0x08 /* The returned token must have the unix_token and unix_info elements provided */
#define AUTH_SESSION_INFO_NTLM               0x10 /* The returned token must have authenticated-with-NTLM flag set */

struct auth_usersupplied_info
{
	const char *workstation_name;
	const struct tsocket_address *remote_host;
	const struct tsocket_address *local_host;

	uint32_t logon_parameters;

	bool mapped_state;
	bool was_mapped;
	uint64_t logon_id;
	/* the values the client gives us */
	struct {
		const char *account_name;
		const char *domain_name;
	} client, mapped;

	enum auth_password_state password_state;

	struct {
		struct {
			DATA_BLOB lanman;
			DATA_BLOB nt;
		} response;
		struct {
			struct samr_Password *lanman;
			struct samr_Password *nt;
		} hash;

		char *plaintext;
	} password;
	uint32_t flags;

	struct {
		uint32_t negotiate_flags;
		enum netr_SchannelType secure_channel_type;
		const char *computer_name; /* [charset(UTF8)] */
		const char *account_name; /* [charset(UTF8)] */
		struct dom_sid *sid; /* [unique] */
	} netlogon_trust_account;

	const char *service_description;
	const char *auth_description;

	/*
	 * for logging only, normally worked out from the password but
	 * for krb5 logging only (krb5 normally doesn't use this) we
	 * record the enc type here
	 */
	const char *password_type;
};

struct auth_method_context;
struct tevent_context;
struct imessaging_context;
struct loadparm_context;
struct ldb_context;
struct smb_krb5_context;

struct auth4_context {
	struct {
		/* Who set this up in the first place? */
		const char *set_by;

		DATA_BLOB data;
	} challenge;

	/* methods, in the order they should be called */
	struct auth_method_context *methods;

	/* the event context to use for calls that can block */
	struct tevent_context *event_ctx;

	/* the messaging context which can be used by backends */
	struct imessaging_context *msg_ctx;

	/* loadparm context */
	struct loadparm_context *lp_ctx;

	/* SAM database for this local machine - to fill in local groups, or to authenticate local NTLM users */
	struct ldb_context *sam_ctx;

	/* The time this authentication started */
	struct timeval start_time;

	/* Private data for the callbacks on this auth context */
	void *private_data;

	struct tevent_req *(*check_ntlm_password_send)(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct auth4_context *auth_ctx,
					const struct auth_usersupplied_info *user_info);
	NTSTATUS (*check_ntlm_password_recv)(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t *pauthoritative,
					void **server_returned_info,
					DATA_BLOB *nt_session_key,
					DATA_BLOB *lm_session_key);

	NTSTATUS (*get_ntlm_challenge)(struct auth4_context *auth_ctx, uint8_t chal[8]);

	NTSTATUS (*set_ntlm_challenge)(struct auth4_context *auth_ctx, const uint8_t chal[8], const char *set_by);

	NTSTATUS (*generate_session_info)(struct auth4_context *auth_context,
					  TALLOC_CTX *mem_ctx,
					  void *server_returned_info,
					  const char *original_user_name,
					  uint32_t session_info_flags,
					  struct auth_session_info **session_info);

	NTSTATUS (*generate_session_info_pac)(struct auth4_context *auth_ctx,
					      TALLOC_CTX *mem_ctx,
					      struct smb_krb5_context *smb_krb5_context,
					      DATA_BLOB *pac_blob,
					      const char *principal_name,
					      const struct tsocket_address *remote_address,
					      uint32_t session_info_flags,
					      struct auth_session_info **session_info);
};

#define AUTHZ_TRANSPORT_PROTECTION_NONE "NONE"
#define AUTHZ_TRANSPORT_PROTECTION_SMB "SMB"
#define AUTHZ_TRANSPORT_PROTECTION_TLS "TLS"
#define AUTHZ_TRANSPORT_PROTECTION_SEAL "SEAL"
#define AUTHZ_TRANSPORT_PROTECTION_SIGN "SIGN"

/*
 * Log details of an authentication attempt.
 * Successful and unsuccessful attempts are logged.
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authentication events over the message bus.
 */
void log_authentication_event(struct imessaging_context *msg_ctx,
			      struct loadparm_context *lp_ctx,
			      const struct timeval *start_time,
			      const struct auth_usersupplied_info *ui,
			      NTSTATUS status,
			      const char *account_name,
			      const char *domain_name,
			      struct dom_sid *sid);

/*
 * Log details of a successful authorization to a service.
 *
 * Only successful authorizations are logged.  For clarity:
 * - NTLM bad passwords will be recorded by log_authentication_event
 * - Kerberos decrypt failures need to be logged in gensec_gssapi et al
 *
 * The service may later refuse authorization due to an ACL.
 *
 *
 * NOTE: msg_ctx and lp_ctx is optional, but when supplied allows streaming the
 * authorization events over the message bus.
 */
void log_successful_authz_event(struct imessaging_context *msg_ctx,
				struct loadparm_context *lp_ctx,
				const struct tsocket_address *remote,
				const struct tsocket_address *local,
				const char *service_description,
				const char *auth_type,
				const char *transport_protection,
				struct auth_session_info *session_info);
#endif

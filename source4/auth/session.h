/* 
   Unix SMB/CIFS implementation.
   Process and provide the logged on user's authorization token
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

#ifndef _SAMBA_AUTH_SESSION_H
#define _SAMBA_AUTH_SESSION_H

#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/security.h"
#include "libcli/util/werror.h"
#include "lib/util/time.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/auth.h"

struct loadparm_context;
struct tevent_context;
struct ldb_context;
struct ldb_dn;
/* Create a security token for a session SYSTEM (the most
 * trusted/privileged account), including the local machine account as
 * the off-host credentials */
struct auth_session_info *system_session(struct loadparm_context *lp_ctx) ;

enum claims_data_present {
	CLAIMS_DATA_ENCODED_CLAIMS_PRESENT = 0x01,
	CLAIMS_DATA_CLAIMS_PRESENT = 0x02,
	CLAIMS_DATA_SECURITY_CLAIMS_PRESENT = 0x04,
};

struct claims_data {
	DATA_BLOB encoded_claims_set;
	struct CLAIMS_SET *claims_set;
	/*
	 * These security claims are here treated as only a product — the result
	 * of conversion from another format — and ought not to be treated as
	 * authoritative.
	 */
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *security_claims;
	uint32_t n_security_claims;
	enum claims_data_present flags;
};

struct auth_claims {
	struct claims_data *user_claims;
	struct claims_data *device_claims;
};

NTSTATUS auth_anonymous_user_info_dc(TALLOC_CTX *mem_ctx,
					     const char *netbios_name,
					     struct auth_user_info_dc **interim_info);
NTSTATUS auth_generate_security_token(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx, /* Optional, if you don't want privileges */
				       struct ldb_context *sam_ctx, /* Optional, if you don't want local groups */
				       const struct auth_user_info_dc *user_info_dc,
				       const struct auth_user_info_dc *device_info_dc,
				       const struct auth_claims auth_claims,
				       uint32_t session_info_flags,
				       struct security_token **_security_token);
NTSTATUS auth_generate_session_info(TALLOC_CTX *mem_ctx,
				    struct loadparm_context *lp_ctx, /* Optional, if you don't want privileges */
				    struct ldb_context *sam_ctx, /* Optional, if you don't want local groups */
				    const struct auth_user_info_dc *user_info_dc,
				    uint32_t session_info_flags,
				    struct auth_session_info **session_info);
NTSTATUS auth_anonymous_session_info(TALLOC_CTX *parent_ctx, 
				     struct loadparm_context *lp_ctx,
				     struct auth_session_info **session_info);
struct auth_session_info *auth_session_info_from_transport(TALLOC_CTX *mem_ctx,
							   struct auth_session_info_transport *session_info_transport,
							   struct loadparm_context *lp_ctx,
							   const char **reason);
NTSTATUS auth_session_info_transport_from_session(TALLOC_CTX *mem_ctx,
						  struct auth_session_info *session_info,
						  struct tevent_context *event_ctx,
						  struct loadparm_context *lp_ctx,
						  struct auth_session_info_transport **transport_out);

/* Produce a session_info for an arbitrary DN or principal in the local
 * DB, assuming the local DB holds all the groups
 *
 * Supply either a principal or a DN
 */
NTSTATUS authsam_get_session_info_principal(TALLOC_CTX *mem_ctx,
					    struct loadparm_context *lp_ctx,
					    struct ldb_context *sam_ctx,
					    const char *principal,
					    struct ldb_dn *user_dn,
					    uint32_t session_info_flags,
					    struct auth_session_info **session_info);

struct auth_session_info *anonymous_session(TALLOC_CTX *mem_ctx, 
					    struct loadparm_context *lp_ctx);

struct auth_session_info *admin_session(TALLOC_CTX *mem_ctx,
					struct loadparm_context *lp_ctx,
					struct dom_sid *domain_sid);

NTSTATUS encode_claims_set(TALLOC_CTX *mem_ctx,
			   struct CLAIMS_SET *claims_set,
			   DATA_BLOB *claims_blob);

/*
 * Construct a ‘claims_data’ structure from a claims blob, such as is found in a
 * PAC.
 */
NTSTATUS claims_data_from_encoded_claims_set(TALLOC_CTX *claims_data_ctx,
					     const DATA_BLOB *encoded_claims_set,
					     struct claims_data **out);

/*
 * Construct a ‘claims_data’ structure from a talloc‐allocated claims set, such
 * as we might build from searching the database. If this function returns
 * successfully, it assumes ownership of the claims set.
 */
NTSTATUS claims_data_from_claims_set(TALLOC_CTX *claims_data_ctx,
				     struct CLAIMS_SET *claims_set,
				     struct claims_data **out);

/*
 * From a ‘claims_data’ structure, return an encoded claims blob that can be put
 * into a PAC.
 */
NTSTATUS claims_data_encoded_claims_set(TALLOC_CTX *mem_ctx,
					struct claims_data *claims_data,
					DATA_BLOB *encoded_claims_set_out);

/*
 * From a ‘claims_data’ structure, return an array of security claims that can
 * be put in a security token for access checks.
 */
NTSTATUS claims_data_security_claims(TALLOC_CTX *mem_ctx,
				     struct claims_data *claims_data,
				     struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **security_claims_out,
				     uint32_t *n_security_claims_out);

#endif /* _SAMBA_AUTH_SESSION_H */

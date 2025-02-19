/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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

#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include <krb5/krb5.h>

#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"
#include "librpc/gen_ndr/auth.h"
#include "kdc/samba_kdc.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "auth/session.h"

enum samba_asserted_identity {
	SAMBA_ASSERTED_IDENTITY_IGNORE = 0,
	SAMBA_ASSERTED_IDENTITY_SERVICE,
	SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY,
};

enum {
	SAMBA_KDC_FLAG_PROTOCOL_TRANSITION    = 0x00000001,
	SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION = 0x00000002,
	SAMBA_KDC_FLAG_PKINIT_FRESHNESS_USED  = 0x00000004,
};

bool samba_kdc_entry_is_trust(const struct samba_kdc_entry *entry);

struct samba_kdc_entry_pac {
	struct samba_kdc_entry *entry;
	const struct samba_kdc_entry *krbtgt;
	krb5_const_pac pac; /* NULL indicates that no PAC is present. */
#ifndef HAVE_KRB5_PAC_IS_TRUSTED /* MIT */
	bool pac_is_trusted : 1;
#endif /* HAVE_KRB5_PAC_IS_TRUSTED */
};

/*
 * Return true if this entry has an associated PAC issued or signed by a KDC
 * that our KDC trusts. We trust the main krbtgt account, but we don’t trust any
 * RODC krbtgt besides ourselves.
 */
bool samba_krb5_pac_is_trusted(const struct samba_kdc_entry_pac pac);

#ifdef HAVE_KRB5_PAC_IS_TRUSTED /* Heimdal */
struct samba_kdc_entry_pac samba_kdc_entry_pac(krb5_const_pac pac,
					       struct samba_kdc_entry *entry,
					       const struct samba_kdc_entry *krbtgt_entry);
#else /* MIT */
struct samba_kdc_entry_pac samba_kdc_entry_pac_from_trusted(krb5_const_pac pac,
							    struct samba_kdc_entry *entry,
							    const struct samba_kdc_entry *krbtgt_entry,
							    bool is_trusted);
#endif /* HAVE_KRB5_PAC_IS_TRUSTED */

krb5_error_code samba_kdc_encrypt_pac_credentials(krb5_context context,
						  const krb5_keyblock *pkreplykey,
						  const DATA_BLOB *cred_ndr_blob,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *cred_info_blob);

krb5_error_code samba_make_krb5_pac(krb5_context context,
				    const DATA_BLOB *logon_blob,
				    const DATA_BLOB *cred_blob,
				    const DATA_BLOB *upn_blob,
				    const DATA_BLOB *pac_attrs_blob,
				    const DATA_BLOB *requester_sid_blob,
				    const DATA_BLOB *deleg_blob,
				    const DATA_BLOB *client_claims_blob,
				    const DATA_BLOB *device_info_blob,
				    const DATA_BLOB *device_claims_blob,
				    krb5_pac pac);

bool samba_princ_needs_pac(const struct samba_kdc_entry *skdc_entry);

krb5_error_code samba_krbtgt_is_in_db(const struct samba_kdc_entry *skdc_entry,
				      bool *is_in_db,
				      bool *is_trusted);

krb5_error_code samba_kdc_get_user_info_dc(TALLOC_CTX *mem_ctx,
					   krb5_context context,
					   struct samba_kdc_db_context *kdc_db_ctx,
					   const struct samba_kdc_entry_pac entry,
					   const struct auth_user_info_dc **info_out,
					   const struct PAC_DOMAIN_GROUP_MEMBERSHIP **resource_groups_out);

krb5_error_code samba_kdc_get_user_info_from_db(TALLOC_CTX *mem_ctx,
						struct samba_kdc_db_context *kdc_db_ctx,
						struct samba_kdc_entry *entry,
						const struct ldb_message *msg,
						const struct auth_user_info_dc **info_out);

krb5_error_code samba_kdc_map_policy_err(NTSTATUS nt_status);

NTSTATUS samba_kdc_check_client_access(struct samba_kdc_entry *kdc_entry,
				       const char *client_name,
				       const char *workstation,
				       bool password_change);

krb5_error_code samba_kdc_verify_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     uint32_t flags,
				     const struct samba_kdc_entry_pac client,
				     const struct samba_kdc_entry *krbtgt);

struct authn_audit_info;
krb5_error_code samba_kdc_get_pac(TALLOC_CTX *mem_ctx,
				  krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  uint32_t flags,
				  struct samba_kdc_entry *client,
				  const krb5_const_principal server_principal,
				  const struct samba_kdc_entry *server,
				  const struct samba_kdc_entry_pac device,
				  const krb5_keyblock *pk_reply_key,
				  uint64_t pac_attributes,
				  krb5_pac new_pac,
				  struct authn_audit_info **server_audit_info_out,
				  NTSTATUS *status_out);
krb5_error_code samba_kdc_update_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct samba_kdc_db_context *kdc_db_ctx,
				     uint32_t flags,
				     const struct samba_kdc_entry_pac client,
				     const krb5_const_principal server_principal,
				     const struct samba_kdc_entry *server,
				     const krb5_const_principal delegated_proxy_principal,
				     const struct samba_kdc_entry_pac delegated_proxy,
				     const struct samba_kdc_entry_pac device,
				     krb5_pac new_pac,
				     struct authn_audit_info **server_audit_info_out,
				     NTSTATUS *status_out);

NTSTATUS samba_kdc_get_logon_info_blob(TALLOC_CTX *mem_ctx,
				       const struct auth_user_info_dc *user_info_dc,
				       enum auth_group_inclusion group_inclusion,
				       DATA_BLOB **_logon_info_blob);
NTSTATUS samba_kdc_get_cred_ndr_blob(TALLOC_CTX *mem_ctx,
				     const struct samba_kdc_entry *p,
				     DATA_BLOB **_cred_ndr_blob);
NTSTATUS samba_kdc_get_upn_info_blob(TALLOC_CTX *mem_ctx,
				     const struct auth_user_info_dc *user_info_dc,
				     DATA_BLOB **_upn_info_blob);
NTSTATUS samba_kdc_get_pac_attrs_blob(TALLOC_CTX *mem_ctx,
				      uint64_t pac_attributes,
				      DATA_BLOB **_pac_attrs_blob);
NTSTATUS samba_kdc_get_requester_sid_blob(TALLOC_CTX *mem_ctx,
					  const struct auth_user_info_dc *user_info_dc,
					  DATA_BLOB **_requester_sid_blob);
NTSTATUS samba_kdc_get_claims_blob(TALLOC_CTX *mem_ctx,
				   struct samba_kdc_entry *p,
				   const DATA_BLOB **_claims_blob);

krb5_error_code samba_kdc_allowed_to_authenticate_to(TALLOC_CTX *mem_ctx,
						     struct samba_kdc_db_context *kdc_db_ctx,
						     const struct samba_kdc_entry *client,
						     const struct auth_user_info_dc *client_info,
						     const struct auth_user_info_dc *device_info,
						     const struct auth_claims auth_claims,
						     const struct samba_kdc_entry *server,
						     struct authn_audit_info **server_audit_info_out,
						     NTSTATUS *status_out);

krb5_error_code samba_kdc_check_device(TALLOC_CTX *mem_ctx,
				       krb5_context context,
				       struct samba_kdc_db_context *kdc_db_ctx,
				       const struct samba_kdc_entry_pac device,
				       const struct authn_kerberos_client_policy *client_policy,
				       struct authn_audit_info **client_audit_info_out,
				       NTSTATUS *status_out);

krb5_error_code samba_kdc_get_claims_data(TALLOC_CTX *mem_ctx,
					  krb5_context context,
					  struct samba_kdc_db_context *kdc_db_ctx,
					  struct samba_kdc_entry_pac entry,
					  struct claims_data **claims_data_out);

krb5_error_code samba_kdc_get_claims_data_from_pac(TALLOC_CTX *mem_ctx,
						   krb5_context context,
						   struct samba_kdc_entry_pac entry,
						   struct claims_data **claims_data_out);

krb5_error_code samba_kdc_get_claims_data_from_db(struct ldb_context *samdb,
						  struct samba_kdc_entry *entry,
						  struct claims_data **claims_data_out);

NTSTATUS samba_kdc_add_asserted_identity(enum samba_asserted_identity ai,
					 struct auth_user_info_dc *user_info_dc);

NTSTATUS samba_kdc_add_claims_valid(struct auth_user_info_dc *user_info_dc);
NTSTATUS samba_kdc_add_fresh_public_key_identity(struct auth_user_info_dc *user_info_dc);

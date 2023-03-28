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

#include "librpc/gen_ndr/auth.h"

enum samba_asserted_identity {
	SAMBA_ASSERTED_IDENTITY_IGNORE = 0,
	SAMBA_ASSERTED_IDENTITY_SERVICE,
	SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY,
};

enum samba_claims_valid {
	SAMBA_CLAIMS_VALID_EXCLUDE = 0,
	SAMBA_CLAIMS_VALID_INCLUDE,
};

enum samba_compounded_auth {
	SAMBA_COMPOUNDED_AUTH_EXCLUDE = 0,
	SAMBA_COMPOUNDED_AUTH_INCLUDE,
};

enum {
	SAMBA_KDC_FLAG_PROTOCOL_TRANSITION    = 0x00000001,
	SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION = 0x00000002,
	SAMBA_KDC_FLAG_KRBTGT_IN_DB           = 0x00000004,
	SAMBA_KDC_FLAG_KRBTGT_IS_TRUSTED      = 0x00000008,
	SAMBA_KDC_FLAG_SKIP_PAC_BUFFER        = 0x00000010,
	SAMBA_KDC_FLAG_DEVICE_KRBTGT_IS_TRUSTED = 0x00000020,
};

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

int samba_client_requested_pac(krb5_context context,
			       krb5_const_pac pac,
			       TALLOC_CTX *mem_ctx,
			       bool *requested_pac);

int samba_krbtgt_is_in_db(struct samba_kdc_entry *skdc_entry,
			  bool *is_in_db,
			  bool *is_trusted);

NTSTATUS samba_kdc_get_user_info_from_db(TALLOC_CTX *mem_ctx,
					 struct samba_kdc_entry *skdc_entry,
					 const struct ldb_message *msg,
					 const struct auth_user_info_dc **user_info_dc);

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   struct ldb_context *samdb,
				   enum auth_group_inclusion group_inclusion,
				   enum samba_compounded_auth compounded_auth,
				   const krb5_const_pac pac, DATA_BLOB *pac_blob,
				   struct PAC_SIGNATURE_DATA *pac_srv_sig,
				   struct PAC_SIGNATURE_DATA *pac_kdc_sig);

NTSTATUS samba_kdc_get_user_info_dc(TALLOC_CTX *mem_ctx,
				    struct samba_kdc_entry *skdc_entry,
				    enum samba_asserted_identity asserted_identity,
				    enum samba_claims_valid claims_valid,
				    enum samba_compounded_auth compounded_auth,
				    struct auth_user_info_dc *_user_info_dc);

NTSTATUS samba_kdc_update_delegation_info_blob(TALLOC_CTX *mem_ctx,
				krb5_context context,
				krb5_const_pac pac,
				krb5_principal server_principal,
				krb5_principal proxy_principal,
				DATA_BLOB *pac_blob);

krb5_error_code samba_kdc_map_policy_err(NTSTATUS nt_status);

NTSTATUS samba_kdc_check_client_access(struct samba_kdc_entry *kdc_entry,
				       const char *client_name,
				       const char *workstation,
				       bool password_change);

krb5_error_code samba_kdc_validate_pac_blob(
		krb5_context context,
		const struct samba_kdc_entry *client_skdc_entry,
		krb5_const_pac pac);

/*
 * In the RODC case, to confirm that the returned user is permitted to
 * be replicated to the KDC (krbgtgt_xxx user) represented by *rodc
 */
WERROR samba_rodc_confirm_user_is_allowed(uint32_t num_sids,
					  const struct dom_sid *object_sids,
					  const struct samba_kdc_entry *rodc,
					  const struct samba_kdc_entry *object);

krb5_error_code samba_kdc_verify_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     uint32_t flags,
				     struct samba_kdc_entry *client,
				     krb5_principal server_principal,
				     const struct samba_kdc_entry *krbtgt,
				     const struct samba_kdc_entry *device,
				     const krb5_const_pac *device_pac,
				     krb5_const_pac pac);

krb5_error_code samba_kdc_update_pac(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     struct ldb_context *samdb,
				     uint32_t flags,
				     struct samba_kdc_entry *client,
				     krb5_principal server_principal,
				     const struct samba_kdc_entry *server,
				     krb5_principal delegated_proxy_principal,
				     struct samba_kdc_entry *device,
				     krb5_const_pac device_pac,
				     krb5_const_pac old_pac,
				     krb5_pac new_pac);

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
				   const struct samba_kdc_entry *p,
				   DATA_BLOB **_claims_blob);

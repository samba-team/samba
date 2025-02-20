/*
   Unix SMB/CIFS implementation.

   Database Glue between Samba and the KDC

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

struct sdb_keys;
struct sdb_entry;

struct samba_kdc_base_context;
struct samba_kdc_db_context;
struct samba_kdc_entry;

enum samba_kdc_ent_type {
	SAMBA_KDC_ENT_TYPE_CLIENT,
	SAMBA_KDC_ENT_TYPE_SERVER,
	SAMBA_KDC_ENT_TYPE_KRBTGT,
	SAMBA_KDC_ENT_TYPE_TRUST,
	SAMBA_KDC_ENT_TYPE_ANY
};

/*
 * This allows DSDB to parse Kerberos keys without duplicating this
 * difficulty
 */
krb5_error_code samba_kdc_message2entry_keys(krb5_context context,
					     TALLOC_CTX *mem_ctx,
					     struct ldb_context *ldb,
					     const struct ldb_message *msg,
					     bool is_krbtgt,
					     bool is_rodc,
					     uint32_t userAccountControl,
					     enum samba_kdc_ent_type ent_type,
					     unsigned flags,
					     krb5_kvno requested_kvno,
					     struct sdb_entry *entry,
					     const uint32_t supported_enctypes_in,
					     uint32_t *supported_enctypes_out);

int samba_kdc_set_fixed_keys(krb5_context context,
			     const struct ldb_val *secretbuffer,
			     uint32_t supported_enctypes,
			     struct sdb_keys *keys);

krb5_error_code samba_kdc_fetch(krb5_context context,
				struct samba_kdc_db_context *kdc_db_ctx,
				krb5_const_principal principal,
				unsigned flags,
				krb5_kvno kvno,
				struct sdb_entry *entry);

krb5_error_code samba_kdc_firstkey(krb5_context context,
				   struct samba_kdc_db_context *kdc_db_ctx,
				   const unsigned sdb_flags,
				   struct sdb_entry *entry);

krb5_error_code samba_kdc_nextkey(krb5_context context,
				  struct samba_kdc_db_context *kdc_db_ctx,
				  const unsigned sdb_flags,
				  struct sdb_entry *entry);

krb5_error_code
samba_kdc_check_client_matches_target_service(krb5_context context,
			 struct samba_kdc_entry *skdc_entry_client,
			 struct samba_kdc_entry *skdc_entry_server_target);

krb5_error_code
samba_kdc_check_pkinit_ms_upn_match(krb5_context context,
				    struct samba_kdc_db_context *kdc_db_ctx,
				    struct samba_kdc_entry *skdc_entry,
				    krb5_const_principal certificate_principal);

krb5_error_code
samba_kdc_check_s4u2proxy(krb5_context context,
			  struct samba_kdc_db_context *kdc_db_ctx,
			  struct samba_kdc_entry *skdc_entry,
			  krb5_const_principal target_principal);

NTSTATUS samba_kdc_setup_db_ctx(TALLOC_CTX *mem_ctx, struct samba_kdc_base_context *base_ctx,
				struct samba_kdc_db_context **kdc_db_ctx_out);

krb5_error_code dsdb_extract_aes_256_key(krb5_context context,
					 TALLOC_CTX *mem_ctx,
					 struct ldb_context *ldb,
					 const struct ldb_message *msg,
					 uint32_t user_account_control,
					 const uint32_t *kvno,
					 uint32_t *kvno_out,
					 DATA_BLOB *aes_256_key,
					 DATA_BLOB *salt);

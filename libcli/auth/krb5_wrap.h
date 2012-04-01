/*
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Guenther Deschner 2005-2009

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
struct PAC_SIGNATURE_DATA;
struct PAC_DATA;

#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE /* Heimdal */
#define KRB5_KEY_TYPE(k)	((k)->keytype)
#define KRB5_KEY_LENGTH(k)	((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)	((k)->keyvalue.data)
#define KRB5_KEY_DATA_CAST	void
#else /* MIT */
#define KRB5_KEY_TYPE(k)	((k)->enctype)
#define KRB5_KEY_LENGTH(k)	((k)->length)
#define KRB5_KEY_DATA(k)	((k)->contents)
#define KRB5_KEY_DATA_CAST	krb5_octet
#endif /* HAVE_KRB5_KEYBLOCK_KEYVALUE */

int create_kerberos_key_from_string_direct(krb5_context context,
						  krb5_principal host_princ,
						  krb5_data *password,
						  krb5_keyblock *key,
					   krb5_enctype enctype);
void kerberos_free_data_contents(krb5_context context, krb5_data *pdata);
krb5_error_code smb_krb5_kt_free_entry(krb5_context context, krb5_keytab_entry *kt_entry);

 krb5_error_code smb_krb5_parse_name(krb5_context context,
				const char *name, /* in unix charset */
				     krb5_principal *principal);
krb5_error_code smb_krb5_unparse_name(TALLOC_CTX *mem_ctx,
				      krb5_context context,
				      krb5_const_principal principal,
				      char **unix_name);
 krb5_error_code smb_krb5_parse_name_norealm(krb5_context context, 
					    const char *name, 
					     krb5_principal *principal);
 bool smb_krb5_principal_compare_any_realm(krb5_context context, 
					  krb5_const_principal princ1, 
					   krb5_const_principal princ2);
 void smb_krb5_checksum_from_pac_sig(krb5_checksum *cksum,
				     struct PAC_SIGNATURE_DATA *sig);
 krb5_error_code smb_krb5_verify_checksum(krb5_context context,
					  const krb5_keyblock *keyblock,
					 krb5_keyusage usage,
					 krb5_checksum *cksum,
					 uint8_t *data,
					  size_t length);
char *gssapi_error_string(TALLOC_CTX *mem_ctx, 
			  OM_uint32 maj_stat, OM_uint32 min_stat, 
			  const gss_OID mech);
char *smb_get_krb5_error_message(krb5_context context, krb5_error_code code, TALLOC_CTX *mem_ctx);

krb5_error_code check_pac_checksum(DATA_BLOB pac_data,
				   struct PAC_SIGNATURE_DATA *sig,
				   krb5_context context,
				   const krb5_keyblock *keyblock);

NTSTATUS kerberos_decode_pac(TALLOC_CTX *mem_ctx,
			     DATA_BLOB pac_data_blob,
			     krb5_context context,
			     const krb5_keyblock *krbtgt_keyblock,
			     const krb5_keyblock *service_keyblock,
			     krb5_const_principal client_principal,
			     time_t tgs_authtime,
			     struct PAC_DATA **pac_data_out);

NTSTATUS gssapi_obtain_pac_blob(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				gss_name_t gss_client_name,
				DATA_BLOB *pac_data);
NTSTATUS gssapi_get_session_key(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				DATA_BLOB *session_key, 
				uint32_t *keytype);

DATA_BLOB gensec_gssapi_gen_krb5_wrap(TALLOC_CTX *mem_ctx, const DATA_BLOB *ticket, const uint8_t tok_id[2]);

bool gensec_gssapi_parse_krb5_wrap(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, DATA_BLOB *ticket, uint8_t tok_id[2]);

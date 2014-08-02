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

#ifndef _KRB5_SAMBA_H
#define _KRB5_SAMBA_H

#ifdef HAVE_KRB5

#define KRB5_PRIVATE    1       /* this file uses PRIVATE interfaces! */
/* this file uses DEPRECATED interfaces! */

#ifdef KRB5_DEPRECATED
#undef KRB5_DEPRECATED
#endif

#if defined(HAVE_KRB5_DEPRECATED_WITH_IDENTIFIER)
#define KRB5_DEPRECATED 1
#else
#define KRB5_DEPRECATED
#endif

#include "system/kerberos.h"
#include "system/network.h"

#ifndef KRB5_ADDR_NETBIOS
#define KRB5_ADDR_NETBIOS 0x14
#endif

#ifndef KRB5KRB_ERR_RESPONSE_TOO_BIG
#define KRB5KRB_ERR_RESPONSE_TOO_BIG (-1765328332L)
#endif

/* Heimdal uses a slightly different name */
#if defined(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5) && !defined(HAVE_ENCTYPE_ARCFOUR_HMAC)
#define ENCTYPE_ARCFOUR_HMAC ENCTYPE_ARCFOUR_HMAC_MD5
#endif
#if defined(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5_56) && !defined(HAVE_ENCTYPE_ARCFOUR_HMAC_EXP)
#define ENCTYPE_ARCFOUR_HMAC_EXP ENCTYPE_ARCFOUR_HMAC_MD5_56
#endif

/* The older versions of heimdal that don't have this
   define don't seem to use it anyway.  I'm told they
   always use a subkey */
#ifndef HAVE_AP_OPTS_USE_SUBKEY
#define AP_OPTS_USE_SUBKEY 0
#endif

#ifndef KRB5_PW_SALT
#define KRB5_PW_SALT 3
#endif

/* CKSUMTYPE_HMAC_MD5 in Heimdal
   CKSUMTYPE_HMAC_MD5_ARCFOUR in MIT */
#if defined(CKSUMTYPE_HMAC_MD5_ARCFOUR) && !defined(CKSUMTYPE_HMAC_MD5)
#define CKSUMTYPE_HMAC_MD5 CKSUMTYPE_HMAC_MD5_ARCFOUR
#endif

typedef struct {
#if defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) /* MIT */
	krb5_address **addrs;
#elif defined(HAVE_KRB5_ADDRESSES) /* Heimdal */
	krb5_addresses *addrs;
#else
#error UNKNOWN_KRB5_ADDRESS_TYPE
#endif /* defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) */
} smb_krb5_addresses;

#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEY               /* MIT */
#define KRB5_KT_KEY(k)		(&(k)->key)
#elif HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK          /* Heimdal */
#define KRB5_KT_KEY(k)		(&(k)->keyblock)
#else
#error krb5_keytab_entry has no key or keyblock member
#endif /* HAVE_KRB5_KEYTAB_ENTRY_KEY */

/* work around broken krb5.h on sles9 */
#ifdef SIZEOF_LONG
#undef SIZEOF_LONG
#endif

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

krb5_error_code smb_krb5_parse_name(krb5_context context,
				const char *name, /* in unix charset */
                                krb5_principal *principal);

krb5_error_code smb_krb5_unparse_name(TALLOC_CTX *mem_ctx,
				      krb5_context context,
				      krb5_const_principal principal,
				      char **unix_name);

krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc);

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock);
#endif

#ifndef HAVE_KRB5_FREE_UNPARSED_NAME
void krb5_free_unparsed_name(krb5_context ctx, char *val);
#endif

/* Stub out initialize_krb5_error_table since it is not present in all
 * Kerberos implementations. If it's not present, it's not necessary to
 * call it.
 */
#ifndef HAVE_INITIALIZE_KRB5_ERROR_TABLE
#define initialize_krb5_error_table()
#endif

/* Samba wrapper functions for krb5 functionality. */
bool setup_kaddr( krb5_address *pkaddr, struct sockaddr_storage *paddr);
int create_kerberos_key_from_string(krb5_context context,
				    krb5_principal host_princ,
				    krb5_data *password,
				    krb5_keyblock *key,
				    krb5_enctype enctype,
				    bool no_salt);

krb5_error_code get_kerberos_allowed_etypes(krb5_context context, krb5_enctype **enctypes);
bool get_krb5_smb_session_key(TALLOC_CTX *mem_ctx,
			      krb5_context context,
			      krb5_auth_context auth_context,
			      DATA_BLOB *session_key, bool remote);
krb5_error_code smb_krb5_kt_free_entry(krb5_context context, krb5_keytab_entry *kt_entry);
void kerberos_set_creds_enctype(krb5_creds *pcreds, int enctype);
bool kerberos_compatible_enctypes(krb5_context context, krb5_enctype enctype1, krb5_enctype enctype2);
void kerberos_free_data_contents(krb5_context context, krb5_data *pdata);
krb5_error_code smb_krb5_parse_name_norealm(krb5_context context,
					    const char *name,
					    krb5_principal *principal);
bool smb_krb5_principal_compare_any_realm(krb5_context context,
					  krb5_const_principal princ1,
					  krb5_const_principal princ2);
krb5_error_code smb_krb5_renew_ticket(const char *ccache_string, const char *client_string, const char *service_string, time_t *expire_time);
krb5_error_code smb_krb5_gen_netbios_krb5_address(smb_krb5_addresses **kerb_addr,
						  const char *netbios_name);
krb5_error_code smb_krb5_free_addresses(krb5_context context, smb_krb5_addresses *addr);
NTSTATUS krb5_to_nt_status(krb5_error_code kerberos_error);
krb5_error_code nt_status_to_krb5(NTSTATUS nt_status);
void smb_krb5_free_error(krb5_context context, krb5_error *krberror);
krb5_error_code handle_krberror_packet(krb5_context context,
                                         krb5_data *packet);

void smb_krb5_get_init_creds_opt_free(krb5_context context,
				    krb5_get_init_creds_opt *opt);
krb5_error_code smb_krb5_get_init_creds_opt_alloc(krb5_context context,
				    krb5_get_init_creds_opt **opt);
krb5_enctype smb_get_enctype_from_kt_entry(krb5_keytab_entry *kt_entry);
krb5_error_code smb_krb5_enctype_to_string(krb5_context context,
					    krb5_enctype enctype,
					    char **etype_s);
krb5_error_code smb_krb5_open_keytab(krb5_context context,
				      const char *keytab_name,
				      bool write_access,
				      krb5_keytab *keytab);
krb5_error_code smb_krb5_keytab_name(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     krb5_keytab keytab,
				     const char **keytab_name);
krb5_error_code smb_krb5_get_credentials(krb5_context context,
					 krb5_ccache ccache,
					 krb5_principal me,
					 krb5_principal server,
					 krb5_principal impersonate_princ,
					 krb5_creds **out_creds);
krb5_error_code smb_krb5_keyblock_init_contents(krb5_context context,
						krb5_enctype enctype,
						const void *data,
						size_t length,
						krb5_keyblock *key);
krb5_error_code kerberos_kinit_keyblock_cc(krb5_context ctx, krb5_ccache cc,
					   krb5_principal principal,
					   krb5_keyblock *keyblock,
					   const char *target_service,
					   krb5_get_init_creds_opt *krb_options,
					   time_t *expire_time,
					   time_t *kdc_time);
krb5_error_code kerberos_kinit_password_cc(krb5_context ctx,
					   krb5_ccache cc,
					   krb5_principal principal,
					   const char *password,
					   const char *target_service,
					   krb5_get_init_creds_opt *krb_options,
					   time_t *expire_time,
					   time_t *kdc_time);
#ifdef SAMBA4_USES_HEIMDAL
krb5_error_code kerberos_kinit_s4u2_cc(krb5_context ctx,
					krb5_ccache store_cc,
					krb5_principal init_principal,
					const char *init_password,
					krb5_principal impersonate_principal,
					const char *self_service,
					const char *target_service,
					krb5_get_init_creds_opt *krb_options,
					time_t *expire_time,
					time_t *kdc_time);
#endif

#if defined(HAVE_KRB5_MAKE_PRINCIPAL)
#define smb_krb5_make_principal krb5_make_principal
#elif defined(HAVE_KRB5_BUILD_PRINCIPAL_ALLOC_VA)
krb5_error_code smb_krb5_make_principal(krb5_context context,
					krb5_principal *principal,
					const char *realm, ...);
#else
#error krb5_make_principal not available
#endif

#if defined(HAVE_KRB5_CC_GET_LIFETIME)
#define smb_krb5_cc_get_lifetime krb5_cc_get_lifetime
#elif defined(HAVE_KRB5_CC_RETRIEVE_CRED)
krb5_error_code smb_krb5_cc_get_lifetime(krb5_context context,
					 krb5_ccache id,
					 time_t *t);
#else
#error krb5_cc_get_lifetime not available
#endif

#if defined(HAVE_KRB5_FREE_CHECKSUM_CONTENTS)
#define smb_krb5_free_checksum_contents krb5_free_checksum_contents
#elif defined (HAVE_FREE_CHECKSUM)
void smb_krb5_free_checksum_contents(krb5_context ctx, krb5_checksum *cksum);
#else
#error krb5_free_checksum_contents/free_Checksum is not vailable
#endif

krb5_error_code smb_krb5_make_pac_checksum(TALLOC_CTX *mem_ctx,
					   DATA_BLOB *pac_data,
					   krb5_context context,
					   const krb5_keyblock *keyblock,
					   uint32_t *sig_type,
					   DATA_BLOB *sig_blob);

char *smb_krb5_principal_get_realm(krb5_context context,
				   krb5_const_principal principal);

krb5_error_code smb_krb5_principal_set_realm(krb5_context context,
					     krb5_principal principal,
					     const char *realm);

char *kerberos_get_principal_from_service_hostname(TALLOC_CTX *mem_ctx,
						   const char *service,
						   const char *remote_name,
						   const char *default_realm);

char *smb_get_krb5_error_message(krb5_context context,
				 krb5_error_code code,
				 TALLOC_CTX *mem_ctx);

bool unwrap_edata_ntstatus(TALLOC_CTX *mem_ctx,
			   DATA_BLOB *edata,
			   DATA_BLOB *edata_out);


krb5_error_code kt_copy(krb5_context context,
			const char *from,
			const char *to);
krb5_error_code kt_copy_one_principal(krb5_context context,
				      const char *from,
				      const char *to,
				      const char *principal,
				      krb5_kvno kvno,
				      const krb5_enctype *enctypes);

#if defined(HAVE_KRB5_KT_COMPARE)
#define smb_krb5_kt_compare krb5_kt_compare
#else
krb5_boolean smb_krb5_kt_compare(krb5_context context,
				 krb5_keytab_entry *entry,
				 krb5_const_principal principal,
				 krb5_kvno vno,
				 krb5_enctype enctype);
#endif

const krb5_enctype *samba_all_enctypes(void);

uint32_t kerberos_enctype_to_bitmap(krb5_enctype enc_type_enum);
krb5_enctype ms_suptype_to_ietf_enctype(uint32_t enctype_bitmap);
krb5_error_code ms_suptypes_to_ietf_enctypes(TALLOC_CTX *mem_ctx,
					     uint32_t enctype_bitmap,
					     krb5_enctype **enctypes);
int smb_krb5_get_pw_salt(krb5_context context,
			 krb5_principal host_princ,
			 krb5_data *psalt);

int smb_krb5_create_key_from_string(krb5_context context,
				    krb5_principal *host_princ,
				    krb5_data *salt,
				    krb5_data *password,
				    krb5_enctype enctype,
				    krb5_keyblock *key);

krb5_boolean smb_krb5_get_allowed_weak_crypto(krb5_context context);

#ifndef krb5_princ_size
#if defined(HAVE_KRB5_PRINCIPAL_GET_NUM_COMP)
#define krb5_princ_size krb5_principal_get_num_comp
#else
#error krb5_princ_size unavailable
#endif
#endif

char *smb_krb5_principal_get_comp_string(TALLOC_CTX *mem_ctx,
					 krb5_context context,
					 krb5_const_principal principal,
					 unsigned int component);

krb5_error_code krb5_copy_data_contents(krb5_data *p,
					const void *data,
					size_t len);

int smb_krb5_principal_get_type(krb5_context context,
				krb5_const_principal principal);

#if !defined(HAVE_KRB5_WARNX)
krb5_error_code krb5_warnx(krb5_context context, const char *fmt, ...);
#endif

#endif /* HAVE_KRB5 */

int cli_krb5_get_ticket(TALLOC_CTX *mem_ctx,
			const char *principal, time_t time_offset,
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5,
			uint32_t extra_ap_opts, const char *ccname,
			time_t *tgs_expire,
			const char *impersonate_princ_s);

#endif /* _KRB5_SAMBA_H */

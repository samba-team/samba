/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/samba/kdb_samba.h
 *
 * Copyright (c) 2009, Simo Sorce <idra@samba.org>
 * All Rights Reserved.
 *
 *   Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#ifndef _KDB_SAMBA_H_
#define _KDB_SAMBA_H_

#include <stdbool.h>

#include <krb5/krb5.h>
#include <krb5/plugin.h>

#define PAC_LOGON_INFO 1

#ifndef discard_const_p
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
# define discard_const_p(type, ptr) ((type *)((intptr_t)(ptr)))
#else
# define discard_const_p(type, ptr) ((type *)(ptr))
#endif
#endif

/* from kdb_samba_common.c */

struct mit_samba_context *ks_get_context(krb5_context kcontext);

void ks_free_krb5_db_entry(krb5_context context,
			   krb5_db_entry *entry);

bool ks_data_eq_string(krb5_data d, const char *s);

krb5_data ks_make_data(void *data, unsigned int len);

krb5_boolean ks_is_kadmin(krb5_context context,
			  krb5_const_principal princ);

krb5_boolean ks_is_kadmin_history(krb5_context context,
				  krb5_const_principal princ);

krb5_boolean ks_is_kadmin_changepw(krb5_context context,
				   krb5_const_principal princ);

krb5_boolean ks_is_kadmin_admin(krb5_context context,
				krb5_const_principal princ);

/* from kdb_samba_principals.c */

krb5_error_code kdb_samba_db_get_principal(krb5_context context,
					   krb5_const_principal princ,
					   unsigned int kflags,
					   krb5_db_entry **kentry);

void kdb_samba_db_free_principal(krb5_context context,
				 krb5_db_entry *entry);

krb5_error_code kdb_samba_db_put_principal(krb5_context context,
					   krb5_db_entry *entry,
					   char **db_args);

krb5_error_code kdb_samba_db_delete_principal(krb5_context context,
					      krb5_const_principal princ);

#if KRB5_KDB_API_VERSION == 8
krb5_error_code kdb_samba_db_iterate(krb5_context context,
				     char *match_entry,
				     int (*func)(krb5_pointer, krb5_db_entry *),
				     krb5_pointer func_arg,
				     krb5_flags iterflags);
#else
krb5_error_code kdb_samba_db_iterate(krb5_context context,
				     char *match_entry,
				     int (*func)(krb5_pointer, krb5_db_entry *),
				     krb5_pointer func_arg);
#endif

/* from kdb_samba_masterkey.c */

krb5_error_code kdb_samba_fetch_master_key(krb5_context context,
					   krb5_principal name,
					   krb5_keyblock *key,
					   krb5_kvno *kvno,
					   char *db_args);

krb5_error_code kdb_samba_fetch_master_key_list(krb5_context context,
						krb5_principal mname,
						const krb5_keyblock *key,
						krb5_keylist_node **mkeys_list);

/* from kdb_samba_pac.c */

krb5_error_code kdb_samba_dbekd_decrypt_key_data(krb5_context context,
						 const krb5_keyblock *mkey,
						 const krb5_key_data *key_data,
						 krb5_keyblock *kkey,
						 krb5_keysalt *keysalt);

krb5_error_code kdb_samba_dbekd_encrypt_key_data(krb5_context context,
						 const krb5_keyblock *mkey,
						 const krb5_keyblock *kkey,
						 const krb5_keysalt *keysalt,
						 int keyver,
						 krb5_key_data *key_data);

/* from kdb_samba_policies.c */

krb5_error_code kdb_samba_db_sign_auth_data(krb5_context context,
					    unsigned int flags,
					    krb5_const_principal client_princ,
					    krb5_db_entry *client,
					    krb5_db_entry *server,
					    krb5_db_entry *krbtgt,
					    krb5_keyblock *client_key,
					    krb5_keyblock *server_key,
					    krb5_keyblock *krbtgt_key,
					    krb5_keyblock *session_key,
					    krb5_timestamp authtime,
					    krb5_authdata **tgt_auth_data,
					    krb5_authdata ***signed_auth_data);

krb5_error_code kdb_samba_db_check_policy_as(krb5_context context,
					     krb5_kdc_req *kdcreq,
					     krb5_db_entry *client,
					     krb5_db_entry *server,
					     krb5_timestamp kdc_time,
					     const char **status,
					     krb5_pa_data ***e_data_out);

krb5_error_code kdb_samba_db_check_allowed_to_delegate(krb5_context context,
						       krb5_const_principal client,
						       const krb5_db_entry *server,
						       krb5_const_principal proxy);

void kdb_samba_db_audit_as_req(krb5_context kcontext,
			       krb5_kdc_req *request,
			       krb5_db_entry *client,
			       krb5_db_entry *server,
			       krb5_timestamp authtime,
			       krb5_error_code error_code);

/* from kdb_samba_change_pwd.c */

krb5_error_code kdb_samba_change_pwd(krb5_context context,
				     krb5_keyblock *master_key,
				     krb5_key_salt_tuple *ks_tuple,
				     int ks_tuple_count, char *passwd,
				     int new_kvno, krb5_boolean keepold,
				     krb5_db_entry *db_entry);

#endif /* _KDB_SAMBA_H_ */

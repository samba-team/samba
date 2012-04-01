/*
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2011
   Copyright (C) Guenther Deschner 2005-2009
   Copyright (C) Simo Sorce 2010.

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

#include "includes.h"
#ifdef HAVE_KRB5

#include "libcli/auth/krb5_wrap.h"
#include "librpc/gen_ndr/krb5pac.h"

#if defined(HAVE_KRB5_PRINCIPAL2SALT) && defined(HAVE_KRB5_C_STRING_TO_KEY)
/* MIT */
int create_kerberos_key_from_string_direct(krb5_context context,
						  krb5_principal host_princ,
						  krb5_data *password,
						  krb5_keyblock *key,
						  krb5_enctype enctype)
{
	int ret = 0;
	krb5_data salt;

	ret = krb5_principal2salt(context, host_princ, &salt);
	if (ret) {
		DEBUG(1,("krb5_principal2salt failed (%s)\n", error_message(ret)));
		return ret;
	}
	ret = krb5_c_string_to_key(context, enctype, password, &salt, key);
	SAFE_FREE(salt.data);

	return ret;
}
#elif defined(HAVE_KRB5_GET_PW_SALT) && defined(HAVE_KRB5_STRING_TO_KEY_SALT)
/* Heimdal */
int create_kerberos_key_from_string_direct(krb5_context context,
						  krb5_principal host_princ,
						  krb5_data *password,
						  krb5_keyblock *key,
						  krb5_enctype enctype)
{
	int ret;
	krb5_salt salt;

	ret = krb5_get_pw_salt(context, host_princ, &salt);
	if (ret) {
		DEBUG(1,("krb5_get_pw_salt failed (%s)\n", error_message(ret)));
		return ret;
	}

	ret = krb5_string_to_key_salt(context, enctype, (const char *)password->data, salt, key);
	krb5_free_salt(context, salt);

	return ret;
}
#else
#error UNKNOWN_CREATE_KEY_FUNCTIONS
#endif

 void kerberos_free_data_contents(krb5_context context, krb5_data *pdata)
{
#if defined(HAVE_KRB5_FREE_DATA_CONTENTS)
	if (pdata->data) {
		krb5_free_data_contents(context, pdata);
	}
#elif defined(HAVE_KRB5_DATA_FREE)
	krb5_data_free(context, pdata);
#else
	SAFE_FREE(pdata->data);
#endif
}


 krb5_error_code smb_krb5_kt_free_entry(krb5_context context, krb5_keytab_entry *kt_entry)
{
/* Try krb5_free_keytab_entry_contents first, since
 * MIT Kerberos >= 1.7 has both krb5_free_keytab_entry_contents and
 * krb5_kt_free_entry but only has a prototype for the first, while the
 * second is considered private.
 */
#if defined(HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS)
	return krb5_free_keytab_entry_contents(context, kt_entry);
#elif defined(HAVE_KRB5_KT_FREE_ENTRY)
	return krb5_kt_free_entry(context, kt_entry);
#else
#error UNKNOWN_KT_FREE_FUNCTION
#endif
}

/**************************************************************
 Wrappers around kerberos string functions that convert from
 utf8 -> unix charset and vica versa.
**************************************************************/

/**************************************************************
 krb5_parse_name that takes a UNIX charset.
**************************************************************/

 krb5_error_code smb_krb5_parse_name(krb5_context context,
				const char *name, /* in unix charset */
				krb5_principal *principal)
{
	krb5_error_code ret;
	char *utf8_name;
	size_t converted_size;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!push_utf8_talloc(frame, &utf8_name, name, &converted_size)) {
		talloc_free(frame);
		return ENOMEM;
	}

	ret = krb5_parse_name(context, utf8_name, principal);
	TALLOC_FREE(frame);
	return ret;
}

#if !defined(HAVE_KRB5_FREE_UNPARSED_NAME)
static void krb5_free_unparsed_name(krb5_context context, char *val)
{
	SAFE_FREE(val);
}
#endif

/**************************************************************
 krb5_parse_name that returns a UNIX charset name. Must
 be freed with talloc_free() call.
**************************************************************/

krb5_error_code smb_krb5_unparse_name(TALLOC_CTX *mem_ctx,
				      krb5_context context,
				      krb5_const_principal principal,
				      char **unix_name)
{
	krb5_error_code ret;
	char *utf8_name;
	size_t converted_size;

	*unix_name = NULL;
	ret = krb5_unparse_name(context, principal, &utf8_name);
	if (ret) {
		return ret;
	}

	if (!pull_utf8_talloc(mem_ctx, unix_name, utf8_name, &converted_size)) {
		krb5_free_unparsed_name(context, utf8_name);
		return ENOMEM;
	}
	krb5_free_unparsed_name(context, utf8_name);
	return 0;
}

 krb5_error_code smb_krb5_parse_name_norealm(krb5_context context, 
					    const char *name, 
					    krb5_principal *principal)
{
	/* we are cheating here because parse_name will in fact set the realm.
	 * We don't care as the only caller of smb_krb5_parse_name_norealm
	 * ignores the realm anyway when calling
	 * smb_krb5_principal_compare_any_realm later - Guenther */

	return smb_krb5_parse_name(context, name, principal);
}

 bool smb_krb5_principal_compare_any_realm(krb5_context context, 
					  krb5_const_principal princ1, 
					  krb5_const_principal princ2)
{
	return krb5_principal_compare_any_realm(context, princ1, princ2);
}

char *gssapi_error_string(TALLOC_CTX *mem_ctx, 
			  OM_uint32 maj_stat, OM_uint32 min_stat, 
			  const gss_OID mech)
{
	OM_uint32 disp_min_stat, disp_maj_stat;
	gss_buffer_desc maj_error_message;
	gss_buffer_desc min_error_message;
	char *maj_error_string, *min_error_string;
	OM_uint32 msg_ctx = 0;

	char *ret;

	maj_error_message.value = NULL;
	min_error_message.value = NULL;
	maj_error_message.length = 0;
	min_error_message.length = 0;
	
	disp_maj_stat = gss_display_status(&disp_min_stat, maj_stat, GSS_C_GSS_CODE,
			   mech, &msg_ctx, &maj_error_message);
	disp_maj_stat = gss_display_status(&disp_min_stat, min_stat, GSS_C_MECH_CODE,
			   mech, &msg_ctx, &min_error_message);
	
	maj_error_string = talloc_strndup(mem_ctx, (char *)maj_error_message.value, maj_error_message.length);

	min_error_string = talloc_strndup(mem_ctx, (char *)min_error_message.value, min_error_message.length);

	ret = talloc_asprintf(mem_ctx, "%s: %s", maj_error_string, min_error_string);

	talloc_free(maj_error_string);
	talloc_free(min_error_string);

	gss_release_buffer(&disp_min_stat, &maj_error_message);
	gss_release_buffer(&disp_min_stat, &min_error_message);

	return ret;
}


 char *smb_get_krb5_error_message(krb5_context context, krb5_error_code code, TALLOC_CTX *mem_ctx)
{
	char *ret;

#if defined(HAVE_KRB5_GET_ERROR_MESSAGE) && defined(HAVE_KRB5_FREE_ERROR_MESSAGE)
	const char *context_error = krb5_get_error_message(context, code);
	if (context_error) {
		ret = talloc_asprintf(mem_ctx, "%s: %s", error_message(code), context_error);
		krb5_free_error_message(context, context_error);
		return ret;
	}
#endif
	ret = talloc_strdup(mem_ctx, error_message(code));
	return ret;
}

#endif

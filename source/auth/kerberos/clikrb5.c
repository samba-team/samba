/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/network.h"
#include "system/kerberos.h"
#include "system/time.h"
#include "auth/kerberos/kerberos.h"

#ifdef HAVE_KRB5

#if defined(HAVE_KRB5_SET_DEFAULT_IN_TKT_ETYPES) && !defined(HAVE_KRB5_SET_DEFAULT_TGS_KTYPES)
 krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc)
{
	return krb5_set_default_in_tkt_etypes(ctx, enc);
}
#endif

#if defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS)
/* HEIMDAL */
 void setup_kaddr( krb5_address *pkaddr, struct sockaddr *paddr)
{
	pkaddr->addr_type = KRB5_ADDRESS_INET;
	pkaddr->address.length = sizeof(((struct sockaddr_in *)paddr)->sin_addr);
	pkaddr->address.data = (char *)&(((struct sockaddr_in *)paddr)->sin_addr);
}
#elif defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS)
/* MIT */
 void setup_kaddr( krb5_address *pkaddr, struct sockaddr *paddr)
{
	pkaddr->addrtype = ADDRTYPE_INET;
	pkaddr->length = sizeof(((struct sockaddr_in *)paddr)->sin_addr);
	pkaddr->contents = (krb5_octet *)&(((struct sockaddr_in *)paddr)->sin_addr);
}
#else
#error UNKNOWN_ADDRTYPE
#endif

#if defined(HAVE_KRB5_PRINCIPAL2SALT) && defined(HAVE_KRB5_USE_ENCTYPE) && defined(HAVE_KRB5_STRING_TO_KEY) && defined(HAVE_KRB5_ENCRYPT_BLOCK)
 int create_kerberos_key_from_string(krb5_context context,
					krb5_principal host_princ,
					krb5_data *password,
					krb5_keyblock *key,
					krb5_enctype enctype)
{
	int ret;
	krb5_data salt;
	krb5_encrypt_block eblock;

	ret = krb5_principal2salt(context, host_princ, &salt);
	if (ret) {
		DEBUG(1,("krb5_principal2salt failed (%s)\n", error_message(ret)));
		return ret;
	}
	krb5_use_enctype(context, &eblock, enctype);
	ret = krb5_string_to_key(context, &eblock, key, password, &salt);
	SAFE_FREE(salt.data);
	return ret;
}
#elif defined(HAVE_KRB5_GET_PW_SALT) && defined(HAVE_KRB5_STRING_TO_KEY_SALT)
 int create_kerberos_key_from_string(krb5_context context,
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
	ret = krb5_string_to_key_salt(context, enctype, password->data,
				      salt, key);
	krb5_free_salt(context, salt);
	return ret;
}
#else
#error UNKNOWN_CREATE_KEY_FUNCTIONS
#endif

#if defined(HAVE_KRB5_GET_PERMITTED_ENCTYPES)
 krb5_error_code get_kerberos_allowed_etypes(krb5_context context, 
					    krb5_enctype **enctypes)
{
	return krb5_get_permitted_enctypes(context, enctypes);
}
#elif defined(HAVE_KRB5_GET_DEFAULT_IN_TKT_ETYPES)
 krb5_error_code get_kerberos_allowed_etypes(krb5_context context, 
					    krb5_enctype **enctypes)
{
	return krb5_get_default_in_tkt_etypes(context, enctypes);
}
#else
#error UNKNOWN_GET_ENCTYPES_FUNCTIONS
#endif

 void free_kerberos_etypes(krb5_context context, 
			   krb5_enctype *enctypes)
{
#if defined(HAVE_KRB5_FREE_KTYPES)
	krb5_free_ktypes(context, enctypes);
	return;
#else
	SAFE_FREE(enctypes);
	return;
#endif
}

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
 krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context,
					krb5_auth_context auth_context,
					krb5_keyblock *keyblock)
{
	return krb5_auth_con_setkey(context, auth_context, keyblock);
}
#endif

#if !defined(HAVE_KRB5_FREE_UNPARSED_NAME)
 void krb5_free_unparsed_name(krb5_context context, char *val)
{
	SAFE_FREE(val);
}
#endif

 void kerberos_free_data_contents(krb5_context context, krb5_data *pdata)
{
#if defined(HAVE_KRB5_FREE_DATA_CONTENTS)
	if (pdata->data) {
		krb5_free_data_contents(context, pdata);
	}
#else
	SAFE_FREE(pdata->data);
#endif
}

 void kerberos_set_creds_enctype(krb5_creds *pcreds, int enctype)
{
#if defined(HAVE_KRB5_KEYBLOCK_IN_CREDS)
	KRB5_KEY_TYPE((&pcreds->keyblock)) = enctype;
#elif defined(HAVE_KRB5_SESSION_IN_CREDS)
	KRB5_KEY_TYPE((&pcreds->session)) = enctype;
#else
#error UNKNOWN_KEYBLOCK_MEMBER_IN_KRB5_CREDS_STRUCT
#endif
}

 BOOL kerberos_compatible_enctypes(krb5_context context,
				  krb5_enctype enctype1,
				  krb5_enctype enctype2)
{
#if defined(HAVE_KRB5_C_ENCTYPE_COMPARE)
	krb5_boolean similar = 0;

	krb5_c_enctype_compare(context, enctype1, enctype2, &similar);
	return similar ? True : False;
#elif defined(HAVE_KRB5_ENCTYPES_COMPATIBLE_KEYS)
	return krb5_enctypes_compatible_keys(context, enctype1, enctype2) ? True : False;
#endif
}

 krb5_error_code smb_krb5_kt_free_entry(krb5_context context, krb5_keytab_entry *kt_entry)
{
#if defined(HAVE_KRB5_KT_FREE_ENTRY)
	return krb5_kt_free_entry(context, kt_entry);
#elif defined(HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS)
	return krb5_free_keytab_entry_contents(context, kt_entry);
#else
#error UNKNOWN_KT_FREE_FUNCTION
#endif
}

 char *smb_get_krb5_error_message(krb5_context context, krb5_error_code code, TALLOC_CTX *mem_ctx) 
{
	char *ret;
	
#if defined(HAVE_KRB5_GET_ERROR_STRING) && defined(HAVE_KRB5_FREE_ERROR_STRING) 	
	char *context_error = krb5_get_error_string(context);
	if (context_error) {
		ret = talloc_asprintf(mem_ctx, "%s: %s", error_message(code), context_error);
		krb5_free_error_string(context, context_error);
		return ret;
	}
#endif
	ret = talloc_strdup(mem_ctx, error_message(code));
	return ret;
}

#endif

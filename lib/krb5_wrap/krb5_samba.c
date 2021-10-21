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

#include "includes.h"
#include "system/filesys.h"
#include "krb5_samba.h"
#include "lib/crypto/md4.h"
#include "../libds/common/flags.h"

#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif /* HAVE_COM_ERR_H */

#ifndef KRB5_AUTHDATA_WIN2K_PAC
#define KRB5_AUTHDATA_WIN2K_PAC 128
#endif

#ifndef KRB5_AUTHDATA_IF_RELEVANT
#define KRB5_AUTHDATA_IF_RELEVANT 1
#endif

#ifdef HAVE_KRB5

#define GSSAPI_CHECKSUM      0x8003             /* Checksum type value for Kerberos */
#define GSSAPI_BNDLENGTH     16                 /* Bind Length (rfc-1964 pg.3) */
#define GSSAPI_CHECKSUM_SIZE (4+GSSAPI_BNDLENGTH+4) /* Length of bind length,
							bind field, flags field. */
#define GSS_C_DELEG_FLAG 1

/* MIT krb5 1.7beta3 (in Ubuntu Karmic) is missing the prototype,
   but still has the symbol */
#if !HAVE_DECL_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE
krb5_error_code krb5_auth_con_set_req_cksumtype(
	krb5_context     context,
	krb5_auth_context      auth_context,
	krb5_cksumtype     cksumtype);
#endif

#if !defined(SMB_MALLOC)
#undef malloc
#define SMB_MALLOC(s) malloc((s))
#endif

#ifndef SMB_STRDUP
#define SMB_STRDUP(s) strdup(s)
#endif

/**********************************************************
 * MISSING FUNCTIONS
 **********************************************************/

#if !defined(HAVE_KRB5_SET_DEFAULT_TGS_KTYPES)

#if defined(HAVE_KRB5_SET_DEFAULT_TGS_ENCTYPES)

/* With MIT kerberos, we should use krb5_set_default_tgs_enctypes in preference
 * to krb5_set_default_tgs_ktypes. See
 *         http://lists.samba.org/archive/samba-technical/2006-July/048271.html
 *
 * If the MIT libraries are not exporting internal symbols, we will end up in
 * this branch, which is correct. Otherwise we will continue to use the
 * internal symbol
 */
 krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc)
{
    return krb5_set_default_tgs_enctypes(ctx, enc);
}

#elif defined(HAVE_KRB5_SET_DEFAULT_IN_TKT_ETYPES)

/* Heimdal */
 krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc)
{
	return krb5_set_default_in_tkt_etypes(ctx, enc);
}

#endif /* HAVE_KRB5_SET_DEFAULT_TGS_ENCTYPES */

#endif /* HAVE_KRB5_SET_DEFAULT_TGS_KTYPES */


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

#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING) && !defined(HAVE_KRB5_PRINC_COMPONENT)
const krb5_data *krb5_princ_component(krb5_context context,
				      krb5_principal principal, int i);

const krb5_data *krb5_princ_component(krb5_context context,
				      krb5_principal principal, int i)
{
	static krb5_data kdata;

	kdata.data = discard_const_p(char, krb5_principal_get_comp_string(context, principal, i));
	kdata.length = strlen((const char *)kdata.data);
	return &kdata;
}
#endif


/**********************************************************
 * WRAPPING FUNCTIONS
 **********************************************************/

#if defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS)
/* HEIMDAL */

/**
 * @brief Stores the address of a 'struct sockaddr_storage' a krb5_address
 *
 * @param[in]  paddr    A pointer to a 'struct sockaddr_storage to extract the
 *                      address from.
 *
 * @param[out] pkaddr   A Kerberos address to store tha address in.
 *
 * @return True on success, false if an error occurred.
 */
bool smb_krb5_sockaddr_to_kaddr(struct sockaddr_storage *paddr,
				krb5_address *pkaddr)
{
	memset(pkaddr, '\0', sizeof(krb5_address));
#ifdef HAVE_IPV6
	if (paddr->ss_family == AF_INET6) {
		pkaddr->addr_type = KRB5_ADDRESS_INET6;
		pkaddr->address.length = sizeof(((struct sockaddr_in6 *)paddr)->sin6_addr);
		pkaddr->address.data = (char *)&(((struct sockaddr_in6 *)paddr)->sin6_addr);
		return true;
	}
#endif
	if (paddr->ss_family == AF_INET) {
		pkaddr->addr_type = KRB5_ADDRESS_INET;
		pkaddr->address.length = sizeof(((struct sockaddr_in *)paddr)->sin_addr);
		pkaddr->address.data = (char *)&(((struct sockaddr_in *)paddr)->sin_addr);
		return true;
	}
	return false;
}
#elif defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS)
/* MIT */

/**
 * @brief Stores the address of a 'struct sockaddr_storage' a krb5_address
 *
 * @param[in]  paddr    A pointer to a 'struct sockaddr_storage to extract the
 *                      address from.
 *
 * @param[in]  pkaddr A Kerberos address to store tha address in.
 *
 * @return True on success, false if an error occurred.
 */
bool smb_krb5_sockaddr_to_kaddr(struct sockaddr_storage *paddr,
				krb5_address *pkaddr)
{
	memset(pkaddr, '\0', sizeof(krb5_address));
#ifdef HAVE_IPV6
	if (paddr->ss_family == AF_INET6) {
		pkaddr->addrtype = ADDRTYPE_INET6;
		pkaddr->length = sizeof(((struct sockaddr_in6 *)paddr)->sin6_addr);
		pkaddr->contents = (krb5_octet *)&(((struct sockaddr_in6 *)paddr)->sin6_addr);
		return true;
	}
#endif
	if (paddr->ss_family == AF_INET) {
		pkaddr->addrtype = ADDRTYPE_INET;
		pkaddr->length = sizeof(((struct sockaddr_in *)paddr)->sin_addr);
		pkaddr->contents = (krb5_octet *)&(((struct sockaddr_in *)paddr)->sin_addr);
		return true;
	}
	return false;
}
#else
#error UNKNOWN_ADDRTYPE
#endif

krb5_error_code smb_krb5_mk_error(krb5_context context,
				  krb5_error_code error_code,
				  const char *e_text,
				  krb5_data *e_data,
				  const krb5_principal client,
				  const krb5_principal server,
				  krb5_data *enc_err)
{
	krb5_error_code code = EINVAL;
#ifdef SAMBA4_USES_HEIMDAL
	code = krb5_mk_error(context,
			     error_code,
			     e_text,
			     e_data,
			     client,
			     server,
			     NULL, /* client_time */
			     NULL, /* client_usec */
			     enc_err);
#else
	krb5_principal unspec_server = NULL;
	krb5_error errpkt;

	errpkt.ctime = 0;
	errpkt.cusec = 0;

	code = krb5_us_timeofday(context,
				 &errpkt.stime,
				 &errpkt.susec);
	if (code != 0) {
		return code;
	}

	errpkt.error = error_code;

	errpkt.text.length = 0;
	if (e_text != NULL) {
		errpkt.text.length = strlen(e_text);
		errpkt.text.data = discard_const_p(char, e_text);
	}

	errpkt.e_data.magic = KV5M_DATA;
	errpkt.e_data.length = 0;
	errpkt.e_data.data = NULL;
	if (e_data != NULL) {
		errpkt.e_data = *e_data;
	}

	errpkt.client = client;

	if (server != NULL) {
		errpkt.server = server;
	} else {
		code = smb_krb5_make_principal(context,
					       &unspec_server,
					       "<unspecified realm>",
					       NULL);
		if (code != 0) {
			return code;
		}
		errpkt.server = unspec_server;
	}

	code = krb5_mk_error(context,
			     &errpkt,
			     enc_err);
	krb5_free_principal(context, unspec_server);
#endif
	return code;
}

/**
* @brief Create a keyblock based on input parameters
*
* @param context	The krb5_context
* @param host_princ	The krb5_principal to use
* @param salt		The optional salt, if omitted, salt is calculated with
*			the provided principal.
* @param password	The krb5_data containing the password
* @param enctype	The krb5_enctype to use for the keyblock generation
* @param key		The returned krb5_keyblock, caller needs to free with
*			krb5_free_keyblock().
*
* @return krb5_error_code
*/
int smb_krb5_create_key_from_string(krb5_context context,
				    krb5_const_principal host_princ,
				    krb5_data *salt,
				    krb5_data *password,
				    krb5_enctype enctype,
				    krb5_keyblock *key)
{
	int ret = 0;

	if (host_princ == NULL && salt == NULL) {
		return -1;
	}

	if ((int)enctype == (int)ENCTYPE_ARCFOUR_HMAC) {
		TALLOC_CTX *frame = talloc_stackframe();
		uint8_t *utf16 = NULL;
		size_t utf16_size = 0;
		uint8_t nt_hash[16];
		bool ok;

		ok = convert_string_talloc(frame, CH_UNIX, CH_UTF16LE,
					   password->data, password->length,
					   (void **)&utf16, &utf16_size);
		if (!ok) {
			if (errno == 0) {
				errno = EINVAL;
			}
			ret = errno;
			TALLOC_FREE(frame);
			return ret;
		}

		mdfour(nt_hash, utf16, utf16_size);
		memset(utf16, 0, utf16_size);
		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      nt_hash,
						      sizeof(nt_hash),
						      key);
		ZERO_STRUCT(nt_hash);
		if (ret != 0) {
			TALLOC_FREE(frame);
			return ret;
		}

		TALLOC_FREE(frame);
		return 0;
	}

#if defined(HAVE_KRB5_PRINCIPAL2SALT) && defined(HAVE_KRB5_C_STRING_TO_KEY)
{/* MIT */
	krb5_data _salt;

	if (salt == NULL) {
		ret = krb5_principal2salt(context, host_princ, &_salt);
		if (ret) {
			DEBUG(1,("krb5_principal2salt failed (%s)\n", error_message(ret)));
			return ret;
		}
	} else {
		_salt = *salt;
	}
	ret = krb5_c_string_to_key(context, enctype, password, &_salt, key);
	if (salt == NULL) {
		SAFE_FREE(_salt.data);
	}
}
#elif defined(HAVE_KRB5_GET_PW_SALT) && defined(HAVE_KRB5_STRING_TO_KEY_SALT)
{/* Heimdal */
	krb5_salt _salt;

	if (salt == NULL) {
		ret = krb5_get_pw_salt(context, host_princ, &_salt);
		if (ret) {
			DEBUG(1,("krb5_get_pw_salt failed (%s)\n", error_message(ret)));
			return ret;
		}
	} else {
		_salt.saltvalue = *salt;
		_salt.salttype = KRB5_PW_SALT;
	}

	ret = krb5_string_to_key_salt(context, enctype, (const char *)password->data, _salt, key);
	if (salt == NULL) {
		krb5_free_salt(context, _salt);
	}
}
#else
#error UNKNOWN_CREATE_KEY_FUNCTIONS
#endif
	return ret;
}

/**
* @brief Create a salt for a given principal
*
* @param context	The initialized krb5_context
* @param host_princ	The krb5_principal to create the salt for
* @param psalt		A pointer to a krb5_data struct
*
* caller has to free the contents of psalt with smb_krb5_free_data_contents
* when function has succeeded
*
* @return krb5_error_code, returns 0 on success, error code otherwise
*/

int smb_krb5_get_pw_salt(krb5_context context,
			 krb5_const_principal host_princ,
			 krb5_data *psalt)
#if defined(HAVE_KRB5_GET_PW_SALT)
/* Heimdal */
{
	int ret;
	krb5_salt salt;

	ret = krb5_get_pw_salt(context, host_princ, &salt);
	if (ret) {
		return ret;
	}

	psalt->data = salt.saltvalue.data;
	psalt->length = salt.saltvalue.length;

	return ret;
}
#elif defined(HAVE_KRB5_PRINCIPAL2SALT)
/* MIT */
{
	return krb5_principal2salt(context, host_princ, psalt);
}
#else
#error UNKNOWN_SALT_FUNCTIONS
#endif

/**
 * @brief This constructs the salt principal used by active directory
 *
 * Most Kerberos encryption types require a salt in order to
 * calculate the long term private key for user/computer object
 * based on a password.
 *
 * The returned _salt_principal is a string in forms like this:
 * - host/somehost.example.com@EXAMPLE.COM
 * - SomeAccount@EXAMPLE.COM
 * - SomePrincipal@EXAMPLE.COM
 *
 * This is not the form that's used as salt, it's just
 * the human readable form. It needs to be converted by
 * smb_krb5_salt_principal2data().
 *
 * @param[in]  realm              The realm the user/computer is added too.
 *
 * @param[in]  sAMAccountName     The sAMAccountName attribute of the object.
 *
 * @param[in]  userPrincipalName  The userPrincipalName attribute of the object
 *                                or NULL is not available.
 *
 * @param[in]  uac_flags          UF_ACCOUNT_TYPE_MASKed userAccountControl field
 *
 * @param[in]  mem_ctx            The TALLOC_CTX to allocate _salt_principal.
 *
 * @param[out]  _salt_principal   The resulting principal as string.
 *
 * @retval 0 Success; otherwise - Kerberos error codes
 *
 * @see smb_krb5_salt_principal2data
 */
int smb_krb5_salt_principal(krb5_context krb5_ctx,
			    const char *realm,
			    const char *sAMAccountName,
			    const char *userPrincipalName,
			    uint32_t uac_flags,
			    krb5_principal *salt_princ)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *upper_realm = NULL;
	const char *principal = NULL;
	int principal_len = 0;
	krb5_error_code krb5_ret;

	*salt_princ = NULL;

	if (sAMAccountName == NULL) {
		TALLOC_FREE(frame);
		return EINVAL;
	}

	if (realm == NULL) {
		TALLOC_FREE(frame);
		return EINVAL;
	}

	if (uac_flags & ~UF_ACCOUNT_TYPE_MASK) {
		/*
		 * catch callers which still
		 * pass 'true'.
		 */
		TALLOC_FREE(frame);
		return EINVAL;
	}
	if (uac_flags == 0) {
		/*
		 * catch callers which still
		 * pass 'false'.
		 */
		TALLOC_FREE(frame);
		return EINVAL;
	}

	upper_realm = strupper_talloc(frame, realm);
	if (upper_realm == NULL) {
		TALLOC_FREE(frame);
		return ENOMEM;
	}

	/* Many, many thanks to lukeh@padl.com for this
	 * algorithm, described in his Nov 10 2004 mail to
	 * samba-technical@lists.samba.org */

	/*
	 * Determine a salting principal
	 */
	if (uac_flags & UF_TRUST_ACCOUNT_MASK) {
		int computer_len = 0;

		computer_len = strlen(sAMAccountName);
		if (sAMAccountName[computer_len-1] == '$') {
			computer_len -= 1;
		}

		if (uac_flags & UF_INTERDOMAIN_TRUST_ACCOUNT) {
			const char *krbtgt = "krbtgt";
			krb5_ret = krb5_build_principal_ext(krb5_ctx,
							    salt_princ,
							    strlen(upper_realm),
							    upper_realm,
							    strlen(krbtgt),
							    krbtgt,
							    computer_len,
							    sAMAccountName,
							    0);
			if (krb5_ret != 0) {
				TALLOC_FREE(frame);
				return krb5_ret;
			}
		} else {
			const char *host = "host";
			char *tmp = NULL;
			char *tmp_lower = NULL;

			tmp = talloc_asprintf(frame, "%*.*s.%s",
					      computer_len,
					      computer_len,
					      sAMAccountName,
					      realm);
			if (tmp == NULL) {
				TALLOC_FREE(frame);
				return ENOMEM;
			}

			tmp_lower = strlower_talloc(frame, tmp);
			if (tmp_lower == NULL) {
				TALLOC_FREE(frame);
				return ENOMEM;
			}

			krb5_ret = krb5_build_principal_ext(krb5_ctx,
							    salt_princ,
							    strlen(upper_realm),
							    upper_realm,
							    strlen(host),
							    host,
							    strlen(tmp_lower),
							    tmp_lower,
							    0);
			if (krb5_ret != 0) {
				TALLOC_FREE(frame);
				return krb5_ret;
			}
		}

	} else if (userPrincipalName != NULL) {
		/*
		 * We parse the name not only to allow an easy
		 * replacement of the realm (no matter the realm in
		 * the UPN, the salt comes from the upper-case real
		 * realm, but also to correctly provide a salt when
		 * the UPN is host/foo.bar
		 *
		 * This can fail for a UPN of the form foo@bar@REALM
		 * (which is accepted by windows) however.
		 */
		krb5_ret = krb5_parse_name(krb5_ctx,
					   userPrincipalName,
					   salt_princ);

		if (krb5_ret != 0) {
			TALLOC_FREE(frame);
			return krb5_ret;
		}

		/*
		 * No matter what realm (including none) in the UPN,
		 * the realm is replaced with our upper-case realm
		 */
		krb5_ret = smb_krb5_principal_set_realm(krb5_ctx,
							*salt_princ,
							upper_realm);
		if (krb5_ret != 0) {
			krb5_free_principal(krb5_ctx, *salt_princ);
			TALLOC_FREE(frame);
			return krb5_ret;
		}
	} else {
		principal = sAMAccountName;
		principal_len = strlen(principal);

		krb5_ret = krb5_build_principal_ext(krb5_ctx,
						    salt_princ,
						    strlen(upper_realm),
						    upper_realm,
						    principal_len,
						    principal,
						    0);
		if (krb5_ret != 0) {
			TALLOC_FREE(frame);
			return krb5_ret;
		}
	}

	TALLOC_FREE(frame);
	return 0;
}

/**
 * @brief This constructs the salt principal used by active directory
 *
 * Most Kerberos encryption types require a salt in order to
 * calculate the long term private key for user/computer object
 * based on a password.
 *
 * The returned _salt_principal is a string in forms like this:
 * - host/somehost.example.com@EXAMPLE.COM
 * - SomeAccount@EXAMPLE.COM
 * - SomePrincipal@EXAMPLE.COM
 *
 * This is not the form that's used as salt, it's just
 * the human readable form. It needs to be converted by
 * smb_krb5_salt_principal2data().
 *
 * @param[in]  realm              The realm the user/computer is added too.
 *
 * @param[in]  sAMAccountName     The sAMAccountName attribute of the object.
 *
 * @param[in]  userPrincipalName  The userPrincipalName attribute of the object
 *                                or NULL is not available.
 *
 * @param[in]  uac_flags          UF_ACCOUNT_TYPE_MASKed userAccountControl field
 *
 * @param[in]  mem_ctx            The TALLOC_CTX to allocate _salt_principal.
 *
 * @param[out]  _salt_principal   The resulting principal as string.
 *
 * @retval 0 Success; otherwise - Kerberos error codes
 *
 * @see smb_krb5_salt_principal2data
 */
int smb_krb5_salt_principal_str(const char *realm,
				const char *sAMAccountName,
				const char *userPrincipalName,
				uint32_t uac_flags,
				TALLOC_CTX *mem_ctx,
				char **_salt_principal_str)
{
	krb5_principal salt_principal = NULL;
	char *salt_principal_malloc;
	krb5_context krb5_ctx;
	krb5_error_code krb5_ret
		= smb_krb5_init_context_common(&krb5_ctx);
	if (krb5_ret != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(krb5_ret));
		return krb5_ret;
	}

	krb5_ret = smb_krb5_salt_principal(krb5_ctx,
					   realm,
					   sAMAccountName,
					   userPrincipalName,
					   uac_flags,
					   &salt_principal);

	krb5_ret = krb5_unparse_name(krb5_ctx, salt_principal,
				     &salt_principal_malloc);
	if (krb5_ret != 0) {
		krb5_free_principal(krb5_ctx, salt_principal);
		DBG_ERR("kerberos unparse of salt principal failed (%s)\n",
			error_message(krb5_ret));
		return krb5_ret;
	}
	krb5_free_principal(krb5_ctx, salt_principal);
	*_salt_principal_str
		= talloc_strdup(mem_ctx, salt_principal_malloc);
	krb5_free_unparsed_name(krb5_ctx, salt_principal_malloc);

	if (*_salt_principal_str == NULL) {
		return ENOMEM;
	}
	return 0;
}

/**
 * @brief Converts the salt principal string into the salt data blob
 *
 * This function takes a salt_principal as string in forms like this:
 * - host/somehost.example.com@EXAMPLE.COM
 * - SomeAccount@EXAMPLE.COM
 * - SomePrincipal@EXAMPLE.COM
 *
 * It generates values like:
 * - EXAMPLE.COMhost/somehost.example.com
 * - EXAMPLE.COMSomeAccount
 * - EXAMPLE.COMSomePrincipal
 *
 * @param[in]  realm              The realm the user/computer is added too.
 *
 * @param[in]  sAMAccountName     The sAMAccountName attribute of the object.
 *
 * @param[in]  userPrincipalName  The userPrincipalName attribute of the object
 *                                or NULL is not available.
 *
 * @param[in]  is_computer        The indication of the object includes
 *                                objectClass=computer.
 *
 * @param[in]  mem_ctx            The TALLOC_CTX to allocate _salt_principal.
 *
 * @param[out]  _salt_principal   The resulting principal as string.
 *
 * @retval 0 Success; otherwise - Kerberos error codes
 *
 * @see smb_krb5_salt_principal
 */
int smb_krb5_salt_principal2data(krb5_context context,
				 const char *salt_principal,
				 TALLOC_CTX *mem_ctx,
				 char **_salt_data)
{
	krb5_error_code ret;
	krb5_principal salt_princ = NULL;
	krb5_data salt;

	*_salt_data = NULL;

	ret = krb5_parse_name(context, salt_principal, &salt_princ);
	if (ret != 0) {
		return ret;
	}

	ret = smb_krb5_get_pw_salt(context, salt_princ, &salt);
	krb5_free_principal(context, salt_princ);
	if (ret != 0) {
		return ret;
	}

	*_salt_data = talloc_strndup(mem_ctx,
				     (char *)salt.data,
				     salt.length);
	smb_krb5_free_data_contents(context, &salt);
	if (*_salt_data == NULL) {
		return ENOMEM;
	}

	return 0;
}

#if defined(HAVE_KRB5_GET_PERMITTED_ENCTYPES)
/**
 * @brief Get a list of encryption types allowed for session keys
 *
 * @param[in]  context  The library context
 *
 * @param[in]  enctypes An allocated, zero-terminated list of encryption types
 *
 * This function returns an allocated list of encryption types allowed for
 * session keys.
 *
 * Use free() to free the enctypes when it is no longer needed.
 *
 * @retval 0 Success; otherwise - Kerberos error codes
 */
krb5_error_code smb_krb5_get_allowed_etypes(krb5_context context,
					    krb5_enctype **enctypes)
{
	return krb5_get_permitted_enctypes(context, enctypes);
}
#elif defined(HAVE_KRB5_GET_DEFAULT_IN_TKT_ETYPES)
krb5_error_code smb_krb5_get_allowed_etypes(krb5_context context,
					    krb5_enctype **enctypes)
{
#ifdef HAVE_KRB5_PDU_NONE_DECL
	return krb5_get_default_in_tkt_etypes(context, KRB5_PDU_NONE, enctypes);
#else
	return krb5_get_default_in_tkt_etypes(context, enctypes);
#endif
}
#else
#error UNKNOWN_GET_ENCTYPES_FUNCTIONS
#endif


/**
 * @brief Convert a string principal name to a Kerberos principal.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  name     The principal as a unix charset string.
 *
 * @param[out] principal The newly allocated principal.
 *
 * Use krb5_free_principal() to free a principal when it is no longer needed.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_parse_name(krb5_context context,
				    const char *name,
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
	if (ret == KRB5_PARSE_MALFORMED) {
		ret = krb5_parse_name_flags(context, utf8_name,
					    KRB5_PRINCIPAL_PARSE_ENTERPRISE,
					    principal);
	}
	TALLOC_FREE(frame);
	return ret;
}

/**
 * @brief Convert a Kerberos principal structure to a string representation.
 *
 * The resulting string representation will be a unix charset name and is
 * talloc'ed.
 *
 * @param[in]  mem_ctx  The talloc context to allocate memory on.
 *
 * @param[in]  context  The library context.
 *
 * @param[in]  principal The principal.
 *
 * @param[out] unix_name A string representation of the princpial name as with
 *                       unix charset.
 *
 * Use talloc_free() to free the string representation if it is no longer
 * needed.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
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

/**
 * @brief Free the contents of a krb5_data structure and zero the data field.
 *
 * @param[in]  context  The krb5 context
 *
 * @param[in]  pdata    The data structure to free contents of
 *
 * This function frees the contents, not the structure itself.
 */
void smb_krb5_free_data_contents(krb5_context context, krb5_data *pdata)
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

/*
 * @brief copy a buffer into a krb5_data struct
 *
 * @param[in] p			The krb5_data
 * @param[in] data		The data to copy
 * @param[in] length		The length of the data to copy
 * @return krb5_error_code
 *
 * Caller has to free krb5_data with smb_krb5_free_data_contents().
 */
krb5_error_code smb_krb5_copy_data_contents(krb5_data *p,
					    const void *data,
					    size_t len)
{
#if defined(HAVE_KRB5_DATA_COPY)
	return krb5_data_copy(p, data, len);
#else
	if (len) {
		p->data = malloc(len);
		if (p->data == NULL) {
			return ENOMEM;
		}
		memmove(p->data, data, len);
	} else {
		p->data = NULL;
	}
	p->length = len;
	p->magic = KV5M_DATA;
	return 0;
#endif
}

bool smb_krb5_get_smb_session_key(TALLOC_CTX *mem_ctx,
				  krb5_context context,
				  krb5_auth_context auth_context,
				  DATA_BLOB *session_key,
				  bool remote)
{
	krb5_keyblock *skey = NULL;
	krb5_error_code err = 0;
	bool ret = false;

	if (remote) {
#ifdef HAVE_KRB5_AUTH_CON_GETRECVSUBKEY
		err = krb5_auth_con_getrecvsubkey(context,
						  auth_context,
						  &skey);
#else /* HAVE_KRB5_AUTH_CON_GETRECVSUBKEY */
		err = krb5_auth_con_getremotesubkey(context,
						    auth_context, &skey);
#endif /* HAVE_KRB5_AUTH_CON_GETRECVSUBKEY */
	} else {
#ifdef HAVE_KRB5_AUTH_CON_GETSENDSUBKEY
		err = krb5_auth_con_getsendsubkey(context,
						  auth_context,
						  &skey);
#else /* HAVE_KRB5_AUTH_CON_GETSENDSUBKEY */
		err = krb5_auth_con_getlocalsubkey(context,
						   auth_context, &skey);
#endif /* HAVE_KRB5_AUTH_CON_GETSENDSUBKEY */
	}

	if (err || skey == NULL) {
		DEBUG(10, ("KRB5 error getting session key %d\n", err));
		goto done;
	}

	DEBUG(10, ("Got KRB5 session key of length %d\n",
		   (int)KRB5_KEY_LENGTH(skey)));

	*session_key = data_blob_talloc(mem_ctx,
					 KRB5_KEY_DATA(skey),
					 KRB5_KEY_LENGTH(skey));
	dump_data_pw("KRB5 Session Key:\n",
		     session_key->data,
		     session_key->length);

	ret = true;

done:
	if (skey) {
		krb5_free_keyblock(context, skey);
	}

	return ret;
}


/**
 * @brief Get talloced string component of a principal
 *
 * @param[in] mem_ctx		The TALLOC_CTX
 * @param[in] context		The krb5_context
 * @param[in] principal		The principal
 * @param[in] component		The component
 * @return string component
 *
 * Caller must talloc_free if the return value is not NULL.
 *
 */
char *smb_krb5_principal_get_comp_string(TALLOC_CTX *mem_ctx,
					 krb5_context context,
					 krb5_const_principal principal,
					 unsigned int component)
{
#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING)
	return talloc_strdup(mem_ctx, krb5_principal_get_comp_string(context, principal, component));
#else
	krb5_data *data;

	if (component >= krb5_princ_size(context, principal)) {
		return NULL;
	}

	data = krb5_princ_component(context, principal, component);
	if (data == NULL) {
		return NULL;
	}

	return talloc_strndup(mem_ctx, data->data, data->length);
#endif
}

/**
 * @brief
 *
 * @param[in]  ccache_string A string pointing to the cache to renew the ticket
 *                           (e.g. FILE:/tmp/krb5cc_0) or NULL. If the principal
 *                           ccache has not been specified, the default ccache
 *                           will be used.
 *
 * @param[in]  client_string The client principal string (e.g. user@SAMBA.SITE)
 *                           or NULL. If the principal string has not been
 *                           specified, the principal from the ccache will be
 *                           retrieved.
 *
 * @param[in]  service_string The service ticket string
 *                            (e.g. krbtgt/SAMBA.SITE@SAMBA.SITE) or NULL. If
 *                            the sevice ticket is specified, it is parsed (
 *                            with the realm part ignored) and used as the
 *                            server principal of the credential. Otherwise
 *                            the ticket-granting service is used.
 *
 * @param[in]  expire_time    A pointer to store the credentials end time or
 *                            NULL.
 *
 * @return 0 on Succes, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_renew_ticket(const char *ccache_string,
				      const char *client_string,
				      const char *service_string,
				      time_t *expire_time)
{
	krb5_error_code ret;
	krb5_context context = NULL;
	krb5_ccache ccache = NULL;
	krb5_principal client = NULL;
	krb5_creds creds, creds_in;

	ZERO_STRUCT(creds);
	ZERO_STRUCT(creds_in);

	ret = smb_krb5_init_context_common(&context);
	if (ret) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(ret));
		goto done;
	}

	if (!ccache_string) {
		ccache_string = krb5_cc_default_name(context);
	}

	if (!ccache_string) {
		ret = EINVAL;
		goto done;
	}

	DEBUG(10,("smb_krb5_renew_ticket: using %s as ccache\n", ccache_string));

	/* FIXME: we should not fall back to defaults */
	ret = krb5_cc_resolve(context, discard_const_p(char, ccache_string), &ccache);
	if (ret) {
		goto done;
	}

	if (client_string) {
		ret = smb_krb5_parse_name(context, client_string, &client);
		if (ret) {
			goto done;
		}
	} else {
		ret = krb5_cc_get_principal(context, ccache, &client);
		if (ret) {
			goto done;
		}
	}

	ret = krb5_get_renewed_creds(context, &creds, client, ccache, discard_const_p(char, service_string));
	if (ret) {
		DEBUG(10,("smb_krb5_renew_ticket: krb5_get_kdc_cred failed: %s\n", error_message(ret)));
		goto done;
	}

	/* hm, doesn't that create a new one if the old one wasn't there? - Guenther */
	ret = krb5_cc_initialize(context, ccache, client);
	if (ret) {
		goto done;
	}

	ret = krb5_cc_store_cred(context, ccache, &creds);

	if (expire_time) {
		*expire_time = (time_t) creds.times.endtime;
	}

done:
	krb5_free_cred_contents(context, &creds_in);
	krb5_free_cred_contents(context, &creds);

	if (client) {
		krb5_free_principal(context, client);
	}
	if (ccache) {
		krb5_cc_close(context, ccache);
	}
	if (context) {
		krb5_free_context(context);
	}

	return ret;
}

/**
 * @brief Free the data stored in an smb_krb5_addresses structure.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  addr     The address structure to free.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_free_addresses(krb5_context context,
					smb_krb5_addresses *addr)
{
	krb5_error_code ret = 0;
	if (addr == NULL) {
		return ret;
	}
#if defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) /* MIT */
	krb5_free_addresses(context, addr->addrs);
#elif defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS) /* Heimdal */
	ret = krb5_free_addresses(context, addr->addrs);
	SAFE_FREE(addr->addrs);
#endif
	SAFE_FREE(addr);
	addr = NULL;
	return ret;
}

#define MAX_NETBIOSNAME_LEN 16

/**
 * @brief Add a netbios name to the array of addresses
 *
 * @param[in]  kerb_addr A pointer to the smb_krb5_addresses to add the
 *                       netbios name to.
 *
 * @param[in]  netbios_name The netbios name to add.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_gen_netbios_krb5_address(smb_krb5_addresses **kerb_addr,
						   const char *netbios_name)
{
	krb5_error_code ret = 0;
	char buf[MAX_NETBIOSNAME_LEN];
	int len;
#if defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) /* MIT */
	krb5_address **addrs = NULL;
#elif defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS) /* Heimdal */
	krb5_addresses *addrs = NULL;
#endif

	*kerb_addr = (smb_krb5_addresses *)SMB_MALLOC(sizeof(smb_krb5_addresses));
	if (*kerb_addr == NULL) {
		return ENOMEM;
	}

	/* temporarily duplicate put_name() code here to avoid dependency
	 * issues for a 5 lines function */
	len = strlen(netbios_name);
	memcpy(buf, netbios_name,
		(len < MAX_NETBIOSNAME_LEN) ? len : MAX_NETBIOSNAME_LEN - 1);
	if (len < MAX_NETBIOSNAME_LEN - 1) {
		memset(buf + len, ' ', MAX_NETBIOSNAME_LEN - 1 - len);
	}
	buf[MAX_NETBIOSNAME_LEN - 1] = 0x20;

#if defined(HAVE_MAGIC_IN_KRB5_ADDRESS) && defined(HAVE_ADDRTYPE_IN_KRB5_ADDRESS) /* MIT */
	{
		int num_addr = 2;

		addrs = (krb5_address **)SMB_MALLOC(sizeof(krb5_address *) * num_addr);
		if (addrs == NULL) {
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		memset(addrs, 0, sizeof(krb5_address *) * num_addr);

		addrs[0] = (krb5_address *)SMB_MALLOC(sizeof(krb5_address));
		if (addrs[0] == NULL) {
			SAFE_FREE(addrs);
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		addrs[0]->magic = KV5M_ADDRESS;
		addrs[0]->addrtype = KRB5_ADDR_NETBIOS;
		addrs[0]->length = MAX_NETBIOSNAME_LEN;
		addrs[0]->contents = (unsigned char *)SMB_MALLOC(addrs[0]->length);
		if (addrs[0]->contents == NULL) {
			SAFE_FREE(addrs[0]);
			SAFE_FREE(addrs);
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		memcpy(addrs[0]->contents, buf, addrs[0]->length);

		addrs[1] = NULL;
	}
#elif defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS) /* Heimdal */
	{
		addrs = (krb5_addresses *)SMB_MALLOC(sizeof(krb5_addresses));
		if (addrs == NULL) {
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		memset(addrs, 0, sizeof(krb5_addresses));

		addrs->len = 1;
		addrs->val = (krb5_address *)SMB_MALLOC(sizeof(krb5_address));
		if (addrs->val == NULL) {
			SAFE_FREE(addrs);
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		addrs->val[0].addr_type = KRB5_ADDR_NETBIOS;
		addrs->val[0].address.length = MAX_NETBIOSNAME_LEN;
		addrs->val[0].address.data = (unsigned char *)SMB_MALLOC(addrs->val[0].address.length);
		if (addrs->val[0].address.data == NULL) {
			SAFE_FREE(addrs->val);
			SAFE_FREE(addrs);
			SAFE_FREE(*kerb_addr);
			return ENOMEM;
		}

		memcpy(addrs->val[0].address.data, buf, addrs->val[0].address.length);
	}
#else
#error UNKNOWN_KRB5_ADDRESS_FORMAT
#endif
	(*kerb_addr)->addrs = addrs;

	return ret;
}

/**
 * @brief Get the enctype from a key table entry
 *
 * @param[in]  kt_entry Key table entry to get the enctype from.
 *
 * @return The enctype from the entry.
 */
krb5_enctype smb_krb5_kt_get_enctype_from_entry(krb5_keytab_entry *kt_entry)
{
	return KRB5_KEY_TYPE(KRB5_KT_KEY(kt_entry));
}

/**
 * @brief Free the contents of a key table entry.
 *
 * @param[in]  context The library context.
 *
 * @param[in]  kt_entry The key table entry to free the contents of.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 *
 * The pointer itself is not freed.
 */
krb5_error_code smb_krb5_kt_free_entry(krb5_context context,
					krb5_keytab_entry *kt_entry)
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


/**
 * @brief Convert an encryption type to a string.
 *
 * @param[in]  context The library context.
 *
 * @param[in]  enctype The encryption type.
 *
 * @param[in]  etype_s A pointer to store the allocated encryption type as a
 *                     string.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 *
 * The caller needs to free the allocated string etype_s.
 */
krb5_error_code smb_krb5_enctype_to_string(krb5_context context,
					   krb5_enctype enctype,
					   char **etype_s)
{
#ifdef HAVE_KRB5_ENCTYPE_TO_STRING_WITH_KRB5_CONTEXT_ARG
	return krb5_enctype_to_string(context, enctype, etype_s); /* Heimdal */
#elif defined(HAVE_KRB5_ENCTYPE_TO_STRING_WITH_SIZE_T_ARG)
	char buf[256];
	krb5_error_code ret = krb5_enctype_to_string(enctype, buf, 256); /* MIT */
	if (ret) {
		return ret;
	}
	*etype_s = SMB_STRDUP(buf);
	if (!*etype_s) {
		return ENOMEM;
	}
	return ret;
#else
#error UNKNOWN_KRB5_ENCTYPE_TO_STRING_FUNCTION
#endif
}

/* This MAX_NAME_LEN is a constant defined in krb5.h */
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif

/**
 * @brief Open a key table readonly or with readwrite access.
 *
 * Allows one to use a different keytab than the default one using a relative
 * path to the keytab.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  keytab_name_req The path to the key table.
 *
 * @param[in]  write_access Open with readwrite access.
 *
 * @param[in]  keytab A pointer o the opended key table.
 *
 * The keytab pointer should be freed using krb5_kt_close().
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kt_open_relative(krb5_context context,
					  const char *keytab_name_req,
					  bool write_access,
					  krb5_keytab *keytab)
{
	krb5_error_code ret = 0;
	TALLOC_CTX *mem_ctx;
	char keytab_string[MAX_KEYTAB_NAME_LEN];
	char *kt_str = NULL;
	bool found_valid_name = false;
	const char *pragma = "FILE";
	const char *tmp = NULL;

	if (!write_access && !keytab_name_req) {
		/* caller just wants to read the default keytab readonly, so be it */
		return krb5_kt_default(context, keytab);
	}

	mem_ctx = talloc_init("smb_krb5_open_keytab");
	if (!mem_ctx) {
		return ENOMEM;
	}

#ifdef HAVE_WRFILE_KEYTAB
	if (write_access) {
		pragma = "WRFILE";
	}
#endif

	if (keytab_name_req) {

		if (strlen(keytab_name_req) > MAX_KEYTAB_NAME_LEN) {
			ret = KRB5_CONFIG_NOTENUFSPACE;
			goto out;
		}

		if ((strncmp(keytab_name_req, "WRFILE:", 7) == 0) ||
		    (strncmp(keytab_name_req, "FILE:", 5) == 0)) {
			tmp = keytab_name_req;
			goto resolve;
		}

		tmp = talloc_asprintf(mem_ctx, "%s:%s", pragma, keytab_name_req);
		if (!tmp) {
			ret = ENOMEM;
			goto out;
		}

		goto resolve;
	}

	/* we need to handle more complex keytab_strings, like:
	 * "ANY:FILE:/etc/krb5.keytab,krb4:/etc/srvtab" */

	ret = krb5_kt_default_name(context, &keytab_string[0], MAX_KEYTAB_NAME_LEN - 2);
	if (ret) {
		goto out;
	}

	DEBUG(10,("smb_krb5_open_keytab: krb5_kt_default_name returned %s\n", keytab_string));

	tmp = talloc_strdup(mem_ctx, keytab_string);
	if (!tmp) {
		ret = ENOMEM;
		goto out;
	}

	if (strncmp(tmp, "ANY:", 4) == 0) {
		tmp += 4;
	}

	memset(&keytab_string, '\0', sizeof(keytab_string));

	while (next_token_talloc(mem_ctx, &tmp, &kt_str, ",")) {
		if (strncmp(kt_str, "WRFILE:", 7) == 0) {
			found_valid_name = true;
			tmp = kt_str;
			tmp += 7;
		}

		if (strncmp(kt_str, "FILE:", 5) == 0) {
			found_valid_name = true;
			tmp = kt_str;
			tmp += 5;
		}

		if (tmp[0] == '/') {
			/* Treat as a FILE: keytab definition. */
			found_valid_name = true;
		}

		if (found_valid_name) {
			if (tmp[0] != '/') {
				ret = KRB5_KT_BADNAME;
				goto out;
			}

			tmp = talloc_asprintf(mem_ctx, "%s:%s", pragma, tmp);
			if (!tmp) {
				ret = ENOMEM;
				goto out;
			}
			break;
		}
	}

	if (!found_valid_name) {
		ret = KRB5_KT_UNKNOWN_TYPE;
		goto out;
	}

resolve:
	DEBUG(10,("smb_krb5_open_keytab: resolving: %s\n", tmp));
	ret = krb5_kt_resolve(context, tmp, keytab);

out:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * @brief Open a key table readonly or with readwrite access.
 *
 * Allows one to use a different keytab than the default one. The path needs to be
 * an absolute path or an error will be returned.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  keytab_name_req The path to the key table.
 *
 * @param[in]  write_access Open with readwrite access.
 *
 * @param[in]  keytab A pointer o the opended key table.
 *
 * The keytab pointer should be freed using krb5_kt_close().
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kt_open(krb5_context context,
				 const char *keytab_name_req,
				 bool write_access,
				 krb5_keytab *keytab)
{
	int cmp;

	if (keytab_name_req == NULL) {
		return KRB5_KT_BADNAME;
	}

	if (keytab_name_req[0] == '/') {
		goto open_keytab;
	}

	cmp = strncmp(keytab_name_req, "FILE:/", 6);
	if (cmp == 0) {
		goto open_keytab;
	}

	cmp = strncmp(keytab_name_req, "WRFILE:/", 8);
	if (cmp == 0) {
		goto open_keytab;
	}

	DBG_WARNING("ERROR: Invalid keytab name: %s\n", keytab_name_req);

	return KRB5_KT_BADNAME;

open_keytab:
	return smb_krb5_kt_open_relative(context,
					 keytab_name_req,
					 write_access,
					 keytab);
}

/**
 * @brief Get a key table name.
 *
 * @param[in]  mem_ctx The talloc context to use for allocation.
 *
 * @param[in]  context The library context.
 *
 * @param[in]  keytab The key table to get the name from.
 *
 * @param[in]  keytab_name A talloc'ed string of the key table name.
 *
 * The talloc'ed name string needs to be freed with talloc_free().
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kt_get_name(TALLOC_CTX *mem_ctx,
				     krb5_context context,
				     krb5_keytab keytab,
				     const char **keytab_name)
{
	char keytab_string[MAX_KEYTAB_NAME_LEN];
	krb5_error_code ret = 0;

	ret = krb5_kt_get_name(context, keytab,
			       keytab_string, MAX_KEYTAB_NAME_LEN - 2);
	if (ret) {
		return ret;
	}

	*keytab_name = talloc_strdup(mem_ctx, keytab_string);
	if (!*keytab_name) {
		return ENOMEM;
	}

	return ret;
}

/**
 * @brief Seek and delete old entries in a keytab based on the passed
 *        principal.
 *
 * @param[in]  context       The KRB5 context to use.
 *
 * @param[in]  keytab        The keytab to operate on.
 *
 * @param[in]  kvno          The kvnco to use.
 *
 * @param[in]  princ_s       The principal as a string to search for.
 *
 * @param[in]  princ         The principal as a krb5_principal to search for.
 *
 * @param[in]  flush         Whether to flush the complete keytab.
 *
 * @param[in]  keep_old_entries Keep the entry with the previous kvno.
 *
 * @retval 0 on Sucess
 *
 * @return An appropriate KRB5 error code.
 */
krb5_error_code smb_krb5_kt_seek_and_delete_old_entries(krb5_context context,
							krb5_keytab keytab,
							krb5_kvno kvno,
							krb5_enctype enctype,
							const char *princ_s,
							krb5_principal princ,
							bool flush,
							bool keep_old_entries)
{
	krb5_error_code ret;
	krb5_kt_cursor cursor;
	krb5_keytab_entry kt_entry;
	char *ktprinc = NULL;
	krb5_kvno old_kvno = kvno - 1;
	TALLOC_CTX *tmp_ctx;

	ZERO_STRUCT(cursor);
	ZERO_STRUCT(kt_entry);

	ret = krb5_kt_start_seq_get(context, keytab, &cursor);
	if (ret == KRB5_KT_END || ret == ENOENT ) {
		/* no entries */
		return 0;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	DEBUG(3, (__location__ ": Will try to delete old keytab entries\n"));
	while (!krb5_kt_next_entry(context, keytab, &kt_entry, &cursor)) {
		bool name_ok = false;
		krb5_enctype kt_entry_enctype =
			smb_krb5_kt_get_enctype_from_entry(&kt_entry);

		if (!flush && (princ_s != NULL)) {
			ret = smb_krb5_unparse_name(tmp_ctx, context,
						    kt_entry.principal,
						    &ktprinc);
			if (ret) {
				DEBUG(1, (__location__
					  ": smb_krb5_unparse_name failed "
					  "(%s)\n", error_message(ret)));
				goto out;
			}

#ifdef HAVE_KRB5_KT_COMPARE
			name_ok = krb5_kt_compare(context, &kt_entry,
						  princ, 0, 0);
#else
			name_ok = (strcmp(ktprinc, princ_s) == 0);
#endif

			if (!name_ok) {
				DEBUG(10, (__location__ ": ignoring keytab "
					   "entry principal %s, kvno = %d\n",
					   ktprinc, kt_entry.vno));

				/* Not a match,
				 * just free this entry and continue. */
				ret = smb_krb5_kt_free_entry(context,
							     &kt_entry);
				ZERO_STRUCT(kt_entry);
				if (ret) {
					DEBUG(1, (__location__
						  ": smb_krb5_kt_free_entry "
						  "failed (%s)\n",
						  error_message(ret)));
					goto out;
				}

				TALLOC_FREE(ktprinc);
				continue;
			}

			TALLOC_FREE(ktprinc);
		}

		/*------------------------------------------------------------
		 * Save the entries with kvno - 1. This is what microsoft does
		 * to allow people with existing sessions that have kvno - 1
		 * to still work. Otherwise, when the password for the machine
		 * changes, all kerberizied sessions will 'break' until either
		 * the client reboots or the client's session key expires and
		 * they get a new session ticket with the new kvno.
		 * Some keytab files only store the kvno in 8bits, limit
		 * the compare accordingly.
		 */

		if (!flush && ((kt_entry.vno & 0xff) == (old_kvno & 0xff))) {
			DEBUG(5, (__location__ ": Saving previous (kvno %d) "
				  "entry for principal: %s.\n",
				  old_kvno, princ_s));
			continue;
		}

		if (keep_old_entries) {
			DEBUG(5, (__location__ ": Saving old (kvno %d) "
				  "entry for principal: %s.\n",
				  kvno, princ_s));
			continue;
		}

		if (!flush &&
		    ((kt_entry.vno & 0xff) == (kvno & 0xff)) &&
		    (kt_entry_enctype != enctype))
		{
			DEBUG(5, (__location__ ": Saving entry with kvno [%d] "
				  "enctype [%d] for principal: %s.\n",
				  kvno, kt_entry_enctype, princ_s));
			continue;
		}

		DEBUG(5, (__location__ ": Found old entry for principal: %s "
			  "(kvno %d) - trying to remove it.\n",
			  princ_s, kt_entry.vno));

		ret = krb5_kt_end_seq_get(context, keytab, &cursor);
		ZERO_STRUCT(cursor);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_end_seq_get() "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}
		ret = krb5_kt_remove_entry(context, keytab, &kt_entry);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_remove_entry() "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}

		DEBUG(5, (__location__ ": removed old entry for principal: "
			  "%s (kvno %d).\n", princ_s, kt_entry.vno));

		ret = krb5_kt_start_seq_get(context, keytab, &cursor);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_start_seq() failed "
				  "(%s)\n", error_message(ret)));
			goto out;
		}
		ret = smb_krb5_kt_free_entry(context, &kt_entry);
		ZERO_STRUCT(kt_entry);
		if (ret) {
			DEBUG(1, (__location__ ": krb5_kt_remove_entry() "
				  "failed (%s)\n", error_message(ret)));
			goto out;
		}
	}

out:
	talloc_free(tmp_ctx);
	if (!all_zero((uint8_t *)&kt_entry, sizeof(kt_entry))) {
		smb_krb5_kt_free_entry(context, &kt_entry);
	}
	if (!all_zero((uint8_t *)&cursor, sizeof(cursor))) {
		krb5_kt_end_seq_get(context, keytab, &cursor);
	}
	return ret;
}

/**
 * @brief Add a keytab entry for the given principal
 *
 * @param[in]  context       The krb5 context to use.
 *
 * @param[in]  keytab        The keytab to add the entry to.
 *
 * @param[in]  kvno          The kvno to use.
 *
 * @param[in]  princ_s       The principal as a string.
 *
 * @param[in]  salt_principal The salt principal to salt the password with.
 *                            Only needed for keys which support salting.
 *                            If no salt is used set no_salt to false and
 *                            pass NULL here.
 *
 * @param[in]  enctype        The encryption type of the keytab entry.
 *
 * @param[in]  password       The password of the keytab entry.
 *
 * @param[in]  no_salt        If the password should not be salted. Normally
 *                            this is only set to false for encryption types
 *                            which do not support salting like RC4.
 *
 * @param[in]  keep_old_entries Whether to keep or delete old keytab entries.
 *
 * @retval 0 on Success
 *
 * @return A corresponding KRB5 error code.
 *
 * @see smb_krb5_kt_open()
 */
krb5_error_code smb_krb5_kt_add_entry(krb5_context context,
				      krb5_keytab keytab,
				      krb5_kvno kvno,
				      const char *princ_s,
				      const char *salt_principal,
				      krb5_enctype enctype,
				      krb5_data *password,
				      bool no_salt,
				      bool keep_old_entries)
{
	krb5_error_code ret;
	krb5_keytab_entry kt_entry;
	krb5_principal princ = NULL;
	krb5_keyblock *keyp;

	ZERO_STRUCT(kt_entry);

	ret = smb_krb5_parse_name(context, princ_s, &princ);
	if (ret) {
		DEBUG(1, (__location__ ": smb_krb5_parse_name(%s) "
			  "failed (%s)\n", princ_s, error_message(ret)));
		goto out;
	}

	/* Seek and delete old keytab entries */
	ret = smb_krb5_kt_seek_and_delete_old_entries(context,
						      keytab,
						      kvno,
						      enctype,
						      princ_s,
						      princ,
						      false,
						      keep_old_entries);
	if (ret) {
		goto out;
	}

	/* If we get here, we have deleted all the old entries with kvno's
	 * not equal to the current kvno-1. */

	keyp = KRB5_KT_KEY(&kt_entry);

	if (no_salt) {
		KRB5_KEY_DATA(keyp) = (KRB5_KEY_DATA_CAST *)SMB_MALLOC(password->length);
		if (KRB5_KEY_DATA(keyp) == NULL) {
			ret = ENOMEM;
			goto out;
		}
		memcpy(KRB5_KEY_DATA(keyp), password->data, password->length);
		KRB5_KEY_LENGTH(keyp) = password->length;
		KRB5_KEY_TYPE(keyp) = enctype;
	} else {
		krb5_principal salt_princ = NULL;

		/* Now add keytab entries for all encryption types */
		ret = smb_krb5_parse_name(context, salt_principal, &salt_princ);
		if (ret) {
			DBG_WARNING("krb5_parse_name(%s) failed (%s)\n",
				    salt_principal, error_message(ret));
			goto out;
		}

		ret = smb_krb5_create_key_from_string(context,
						      salt_princ,
						      NULL,
						      password,
						      enctype,
						      keyp);
		krb5_free_principal(context, salt_princ);
		if (ret != 0) {
			goto out;
		}
	}

	kt_entry.principal = princ;
	kt_entry.vno       = kvno;

	DEBUG(3, (__location__ ": adding keytab entry for (%s) with "
		  "encryption type (%d) and version (%d)\n",
		  princ_s, enctype, kt_entry.vno));
	ret = krb5_kt_add_entry(context, keytab, &kt_entry);
	krb5_free_keyblock_contents(context, keyp);
	ZERO_STRUCT(kt_entry);
	if (ret) {
		DEBUG(1, (__location__ ": adding entry to keytab "
			  "failed (%s)\n", error_message(ret)));
		goto out;
	}

out:
	if (princ) {
		krb5_free_principal(context, princ);
	}

	return ret;
}

#if defined(HAVE_KRB5_GET_CREDS_OPT_SET_IMPERSONATE) && \
    defined(HAVE_KRB5_GET_CREDS_OPT_ALLOC) && \
    defined(HAVE_KRB5_GET_CREDS)
static krb5_error_code smb_krb5_get_credentials_for_user_opt(krb5_context context,
							     krb5_ccache ccache,
							     krb5_principal me,
							     krb5_principal server,
							     krb5_principal impersonate_princ,
							     krb5_creds **out_creds)
{
	krb5_error_code ret;
	krb5_get_creds_opt opt;

	ret = krb5_get_creds_opt_alloc(context, &opt);
	if (ret) {
		goto done;
	}
	krb5_get_creds_opt_add_options(context, opt, KRB5_GC_FORWARDABLE);

	if (impersonate_princ) {
		ret = krb5_get_creds_opt_set_impersonate(context, opt,
							 impersonate_princ);
		if (ret) {
			goto done;
		}
	}

	ret = krb5_get_creds(context, opt, ccache, server, out_creds);
	if (ret) {
		goto done;
	}

 done:
	if (opt) {
		krb5_get_creds_opt_free(context, opt);
	}
	return ret;
}
#endif /* HAVE_KRB5_GET_CREDS_OPT_SET_IMPERSONATE */

#ifdef HAVE_KRB5_GET_CREDENTIALS_FOR_USER

#if !HAVE_DECL_KRB5_GET_CREDENTIALS_FOR_USER
krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_user(krb5_context context, krb5_flags options,
                              krb5_ccache ccache, krb5_creds *in_creds,
                              krb5_data *subject_cert,
                              krb5_creds **out_creds);
#endif /* !HAVE_DECL_KRB5_GET_CREDENTIALS_FOR_USER */

static krb5_error_code smb_krb5_get_credentials_for_user(krb5_context context,
							 krb5_ccache ccache,
							 krb5_principal me,
							 krb5_principal server,
							 krb5_principal impersonate_princ,
							 krb5_creds **out_creds)
{
	krb5_error_code ret;
	krb5_creds in_creds;

	ZERO_STRUCT(in_creds);

	if (impersonate_princ) {

		in_creds.server = me;
		in_creds.client = impersonate_princ;

		ret = krb5_get_credentials_for_user(context,
						    0, /* krb5_flags options */
						    ccache,
						    &in_creds,
						    NULL, /* krb5_data *subject_cert */
						    out_creds);
	} else {
		in_creds.client = me;
		in_creds.server = server;

		ret = krb5_get_credentials(context, 0, ccache,
					   &in_creds, out_creds);
	}

	return ret;
}
#endif /* HAVE_KRB5_GET_CREDENTIALS_FOR_USER */

/*
 * smb_krb5_get_credentials
 *
 * @brief Get krb5 credentials for a server
 *
 * @param[in] context		An initialized krb5_context
 * @param[in] ccache		An initialized krb5_ccache
 * @param[in] me		The krb5_principal of the caller
 * @param[in] server		The krb5_principal of the requested service
 * @param[in] impersonate_princ The krb5_principal of a user to impersonate as (optional)
 * @param[out] out_creds	The returned krb5_creds structure
 * @return krb5_error_code
 *
 */
krb5_error_code smb_krb5_get_credentials(krb5_context context,
					 krb5_ccache ccache,
					 krb5_principal me,
					 krb5_principal server,
					 krb5_principal impersonate_princ,
					 krb5_creds **out_creds)
{
	krb5_error_code ret;
	krb5_creds *creds = NULL;

	if (out_creds != NULL) {
		*out_creds = NULL;
	}

	if (impersonate_princ) {
#ifdef HAVE_KRB5_GET_CREDS_OPT_SET_IMPERSONATE /* Heimdal */
		ret = smb_krb5_get_credentials_for_user_opt(context, ccache, me, server, impersonate_princ, &creds);
#elif defined(HAVE_KRB5_GET_CREDENTIALS_FOR_USER) /* MIT */
		ret = smb_krb5_get_credentials_for_user(context, ccache, me, server, impersonate_princ, &creds);
#else
		ret = ENOTSUP;
#endif
	} else {
		krb5_creds in_creds;

		ZERO_STRUCT(in_creds);

		in_creds.client = me;
		in_creds.server = server;

		ret = krb5_get_credentials(context, 0, ccache,
					   &in_creds, &creds);
	}
	if (ret) {
		goto done;
	}

	if (out_creds) {
		*out_creds = creds;
	}

 done:
	if (creds && ret) {
		krb5_free_creds(context, creds);
	}

	return ret;
}

/**
 * @brief Initialize a krb5_keyblock with the given data.
 *
 * Initialized a new keyblock, allocates the contents fo the key and
 * copies the data into the keyblock.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  enctype  The encryption type.
 *
 * @param[in]  data     The date to initialize the keyblock with.
 *
 * @param[in]  length   The length of the keyblock.
 *
 * @param[in]  key      Newly allocated keyblock structure.
 *
 * The key date must be freed using krb5_free_keyblock_contents() when it is
 * no longer needed.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_keyblock_init_contents(krb5_context context,
						krb5_enctype enctype,
						const void *data,
						size_t length,
						krb5_keyblock *key)
{
#if defined(HAVE_KRB5_KEYBLOCK_INIT)
	return krb5_keyblock_init(context, enctype, data, length, key);
#else
	memset(key, 0, sizeof(krb5_keyblock));
	KRB5_KEY_DATA(key) = SMB_MALLOC(length);
	if (NULL == KRB5_KEY_DATA(key)) {
		return ENOMEM;
	}
	memcpy(KRB5_KEY_DATA(key), data, length);
	KRB5_KEY_LENGTH(key) = length;
	KRB5_KEY_TYPE(key) = enctype;
	return 0;
#endif
}

/**
 * @brief Simulate a kinit by putting the tgt in the given credential cache.
 *
 * This function uses a keyblock rather than needing the original password.
 *
 * @param[in]  ctx      The library context
 *
 * @param[in]  cc       The credential cache to put the tgt in.
 *
 * @param[in]  principal The client princial
 *
 * @param[in]  keyblock  The keyblock to use.
 *
 * @param[in]  target_service The service name of the initial credentials (or NULL).
 *
 * @param[in]  krb_options Initial credential options.
 *
 * @param[in]  expire_time    A pointer to store the experation time of the
 *                            credentials (or NULL).
 *
 * @param[in]  kdc_time       A pointer to store the time when the ticket becomes
 *                            valid (or NULL).
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kinit_keyblock_ccache(krb5_context ctx,
					       krb5_ccache cc,
					       krb5_principal principal,
					       krb5_keyblock *keyblock,
					       const char *target_service,
					       krb5_get_init_creds_opt *krb_options,
					       time_t *expire_time,
					       time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_creds my_creds;

#if defined(HAVE_KRB5_GET_INIT_CREDS_KEYBLOCK)
	code = krb5_get_init_creds_keyblock(ctx, &my_creds, principal,
					    keyblock, 0, target_service,
					    krb_options);
#elif defined(HAVE_KRB5_GET_INIT_CREDS_KEYTAB)
{
#define SMB_CREDS_KEYTAB "MEMORY:tmp_kinit_keyblock_ccache"
	char tmp_name[64] = {0};
	krb5_keytab_entry entry;
	krb5_keytab keytab;
	int rc;

	memset(&entry, 0, sizeof(entry));
	entry.principal = principal;
	*(KRB5_KT_KEY(&entry)) = *keyblock;

	rc = snprintf(tmp_name, sizeof(tmp_name),
		      "%s-%p",
		      SMB_CREDS_KEYTAB,
		      &my_creds);
	if (rc < 0) {
		return KRB5_KT_BADNAME;
	}
	code = krb5_kt_resolve(ctx, tmp_name, &keytab);
	if (code) {
		return code;
	}

	code = krb5_kt_add_entry(ctx, keytab, &entry);
	if (code) {
		(void)krb5_kt_close(ctx, keytab);
		goto done;
	}

	code = krb5_get_init_creds_keytab(ctx, &my_creds, principal,
					  keytab, 0, target_service,
					  krb_options);
	(void)krb5_kt_close(ctx, keytab);
}
#else
#error krb5_get_init_creds_keyblock not available!
#endif
	if (code) {
		return code;
	}

#ifndef SAMBA4_USES_HEIMDAL /* MIT */
	/*
	 * We need to store the principal as returned from the KDC to the
	 * credentials cache. If we don't do that the KRB5 library is not
	 * able to find the tickets it is looking for
	 */
	principal = my_creds.client;
#endif
	code = krb5_cc_initialize(ctx, cc, principal);
	if (code) {
		goto done;
	}

	code = krb5_cc_store_cred(ctx, cc, &my_creds);
	if (code) {
		goto done;
	}

	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	code = 0;
done:
	krb5_free_cred_contents(ctx, &my_creds);
	return code;
}

/**
 * @brief Simulate a kinit by putting the tgt in the given credential cache.
 *
 * @param[in]  ctx      The library context
 *
 * @param[in]  cc       The credential cache to put the tgt in.
 *
 * @param[in]  principal The client princial
 *
 * @param[in]  password  The password (or NULL).
 *
 * @param[in]  target_service The service name of the initial credentials (or NULL).
 *
 * @param[in]  krb_options Initial credential options.
 *
 * @param[in]  expire_time    A pointer to store the experation time of the
 *                            credentials (or NULL).
 *
 * @param[in]  kdc_time       A pointer to store the time when the ticket becomes
 *                            valid (or NULL).
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kinit_password_ccache(krb5_context ctx,
					       krb5_ccache cc,
					       krb5_principal principal,
					       const char *password,
					       const char *target_service,
					       krb5_get_init_creds_opt *krb_options,
					       time_t *expire_time,
					       time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_creds my_creds;

	code = krb5_get_init_creds_password(ctx, &my_creds, principal,
					    password, NULL, NULL, 0,
					    target_service, krb_options);
	if (code) {
		return code;
	}

	/*
	 * We need to store the principal as returned from the KDC to the
	 * credentials cache. If we don't do that the KRB5 library is not
	 * able to find the tickets it is looking for
	 */
	principal = my_creds.client;
	code = krb5_cc_initialize(ctx, cc, principal);
	if (code) {
		goto done;
	}

	code = krb5_cc_store_cred(ctx, cc, &my_creds);
	if (code) {
		goto done;
	}

	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) my_creds.times.starttime;
	}

	code = 0;
done:
	krb5_free_cred_contents(ctx, &my_creds);
	return code;
}

#ifdef SAMBA4_USES_HEIMDAL
/**
 * @brief Simulate a kinit by putting the tgt in the given credential cache.
 *
 * @param[in]  ctx      The library context
 *
 * @param[in]  cc       The credential cache to store the tgt in.
 *
 * @param[in]  principal The initial client princial.
 *
 * @param[in]  password  The password (or NULL).
 *
 * @param[in]  impersonate_principal The impersonatiion principal (or NULL).
 *
 * @param[in]  self_service The local service for S4U2Self if
 *                          impersonate_principal is specified).
 *
 * @param[in]  target_service The service name of the initial credentials
 *                            (kpasswd/REALM or a remote service). It defaults
 *                            to the krbtgt if NULL.
 *
 * @param[in]  krb_options Initial credential options.
 *
 * @param[in]  expire_time    A pointer to store the experation time of the
 *                            credentials (or NULL).
 *
 * @param[in]  kdc_time       A pointer to store the time when the ticket becomes
 *                            valid (or NULL).
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_kinit_s4u2_ccache(krb5_context ctx,
					   krb5_ccache store_cc,
					   krb5_principal init_principal,
					   const char *init_password,
					   krb5_principal impersonate_principal,
					   const char *self_service,
					   const char *target_service,
					   krb5_get_init_creds_opt *krb_options,
					   time_t *expire_time,
					   time_t *kdc_time)
{
	krb5_error_code code = 0;
	krb5_get_creds_opt options;
	krb5_principal store_principal;
	krb5_creds store_creds;
	krb5_creds *s4u2self_creds;
	Ticket s4u2self_ticket;
	size_t s4u2self_ticketlen;
	krb5_creds *s4u2proxy_creds;
	krb5_principal self_princ;
	bool s4u2proxy;
	krb5_principal target_princ;
	krb5_ccache tmp_cc;
	const char *self_realm;
	const char *client_realm = NULL;
	krb5_principal blacklist_principal = NULL;
	krb5_principal whitelist_principal = NULL;

	code = krb5_get_init_creds_password(ctx, &store_creds,
					    init_principal,
					    init_password,
					    NULL, NULL,
					    0,
					    NULL,
					    krb_options);
	if (code != 0) {
		return code;
	}

	store_principal = init_principal;

	/*
	 * We are trying S4U2Self now:
	 *
	 * As we do not want to expose our TGT in the
	 * krb5_ccache, which is also holds the impersonated creds.
	 *
	 * Some low level krb5/gssapi function might use the TGT
	 * identity and let the client act as our machine account.
	 *
	 * We need to avoid that and use a temporary krb5_ccache
	 * in order to pass our TGT to the krb5_get_creds() function.
	 */
	code = krb5_cc_new_unique(ctx, NULL, NULL, &tmp_cc);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	code = krb5_cc_initialize(ctx, tmp_cc, store_creds.client);
	if (code != 0) {
		krb5_cc_destroy(ctx, tmp_cc);
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	code = krb5_cc_store_cred(ctx, tmp_cc, &store_creds);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	/*
	 * we need to remember the client principal of our
	 * TGT and make sure the KDC does not return this
	 * in the impersonated tickets. This can happen
	 * if the KDC does not support S4U2Self and S4U2Proxy.
	 */
	blacklist_principal = store_creds.client;
	store_creds.client = NULL;
	krb5_free_cred_contents(ctx, &store_creds);

	/*
	 * Check if we also need S4U2Proxy or if S4U2Self is
	 * enough in order to get a ticket for the target.
	 */
	if (target_service == NULL) {
		s4u2proxy = false;
	} else if (strcmp(target_service, self_service) == 0) {
		s4u2proxy = false;
	} else {
		s4u2proxy = true;
	}

	/*
	 * For S4U2Self we need our own service principal,
	 * which belongs to our own realm (available on
	 * our client principal).
	 */
	self_realm = krb5_principal_get_realm(ctx, init_principal);

	code = krb5_parse_name(ctx, self_service, &self_princ);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_principal_set_realm(ctx, self_princ, self_realm);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds_opt_alloc(ctx, &options);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	if (s4u2proxy) {
		/*
		 * If we want S4U2Proxy, we need the forwardable flag
		 * on the S4U2Self ticket.
		 */
		krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_FORWARDABLE);
	}

	code = krb5_get_creds_opt_set_impersonate(ctx, options,
						  impersonate_principal);
	if (code != 0) {
		krb5_get_creds_opt_free(ctx, options);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_principal(ctx, self_princ);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds(ctx, options, tmp_cc,
			      self_princ, &s4u2self_creds);
	krb5_get_creds_opt_free(ctx, options);
	krb5_free_principal(ctx, self_princ);
	if (code != 0) {
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	if (!s4u2proxy) {
		krb5_cc_destroy(ctx, tmp_cc);

		/*
		 * Now make sure we store the impersonated principal
		 * and creds instead of the TGT related stuff
		 * in the krb5_ccache of the caller.
		 */
		code = krb5_copy_creds_contents(ctx, s4u2self_creds,
						&store_creds);
		krb5_free_creds(ctx, s4u2self_creds);
		if (code != 0) {
			return code;
		}

		/*
		 * It's important to store the principal the KDC
		 * returned, as otherwise the caller would not find
		 * the S4U2Self ticket in the krb5_ccache lookup.
		 */
		store_principal = store_creds.client;
		goto store;
	}

	/*
	 * We are trying S4U2Proxy:
	 *
	 * We need the ticket from the S4U2Self step
	 * and our TGT in order to get the delegated ticket.
	 */
	code = decode_Ticket((const uint8_t *)s4u2self_creds->ticket.data,
			     s4u2self_creds->ticket.length,
			     &s4u2self_ticket,
			     &s4u2self_ticketlen);
	if (code != 0) {
		krb5_free_creds(ctx, s4u2self_creds);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	/*
	 * we need to remember the client principal of the
	 * S4U2Self stage and as it needs to match the one we
	 * will get for the S4U2Proxy stage. We need this
	 * in order to detect KDCs which does not support S4U2Proxy.
	 */
	whitelist_principal = s4u2self_creds->client;
	s4u2self_creds->client = NULL;
	krb5_free_creds(ctx, s4u2self_creds);

	/*
	 * For S4U2Proxy we also got a target service principal,
	 * which also belongs to our own realm (available on
	 * our client principal).
	 */
	code = krb5_parse_name(ctx, target_service, &target_princ);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_principal_set_realm(ctx, target_princ, self_realm);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds_opt_alloc(ctx, &options);
	if (code != 0) {
		free_Ticket(&s4u2self_ticket);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_FORWARDABLE);
	krb5_get_creds_opt_set_options(ctx, options, KRB5_GC_CONSTRAINED_DELEGATION);

	code = krb5_get_creds_opt_set_ticket(ctx, options, &s4u2self_ticket);
	free_Ticket(&s4u2self_ticket);
	if (code != 0) {
		krb5_get_creds_opt_free(ctx, options);
		krb5_free_principal(ctx, target_princ);
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_cc_destroy(ctx, tmp_cc);
		return code;
	}

	code = krb5_get_creds(ctx, options, tmp_cc,
			      target_princ, &s4u2proxy_creds);
	krb5_get_creds_opt_free(ctx, options);
	krb5_free_principal(ctx, target_princ);
	krb5_cc_destroy(ctx, tmp_cc);
	if (code != 0) {
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		return code;
	}

	/*
	 * Now make sure we store the impersonated principal
	 * and creds instead of the TGT related stuff
	 * in the krb5_ccache of the caller.
	 */
	code = krb5_copy_creds_contents(ctx, s4u2proxy_creds,
					&store_creds);
	krb5_free_creds(ctx, s4u2proxy_creds);
	if (code != 0) {
		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		return code;
	}

	/*
	 * It's important to store the principal the KDC
	 * returned, as otherwise the caller would not find
	 * the S4U2Self ticket in the krb5_ccache lookup.
	 */
	store_principal = store_creds.client;

 store:
	if (blacklist_principal &&
	    krb5_principal_compare(ctx, store_creds.client, blacklist_principal)) {
		char *sp = NULL;
		char *ip = NULL;

		code = krb5_unparse_name(ctx, blacklist_principal, &sp);
		if (code != 0) {
			sp = NULL;
		}
		code = krb5_unparse_name(ctx, impersonate_principal, &ip);
		if (code != 0) {
			ip = NULL;
		}
		DEBUG(1, ("smb_krb5_kinit_password_cache: "
			  "KDC returned self principal[%s] while impersonating [%s]\n",
			  sp?sp:"<no memory>",
			  ip?ip:"<no memory>"));

		SAFE_FREE(sp);
		SAFE_FREE(ip);

		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_principal(ctx, blacklist_principal);
		krb5_free_cred_contents(ctx, &store_creds);
		return KRB5_FWD_BAD_PRINCIPAL;
	}
	if (blacklist_principal) {
		krb5_free_principal(ctx, blacklist_principal);
	}

	if (whitelist_principal &&
	    !krb5_principal_compare(ctx, store_creds.client, whitelist_principal)) {
		char *sp = NULL;
		char *ep = NULL;

		code = krb5_unparse_name(ctx, store_creds.client, &sp);
		if (code != 0) {
			sp = NULL;
		}
		code = krb5_unparse_name(ctx, whitelist_principal, &ep);
		if (code != 0) {
			ep = NULL;
		}
		DEBUG(1, ("smb_krb5_kinit_password_cache: "
			  "KDC returned wrong principal[%s] we expected [%s]\n",
			  sp?sp:"<no memory>",
			  ep?ep:"<no memory>"));

		SAFE_FREE(sp);
		SAFE_FREE(ep);

		krb5_free_principal(ctx, whitelist_principal);
		krb5_free_cred_contents(ctx, &store_creds);
		return KRB5_FWD_BAD_PRINCIPAL;
	}
	if (whitelist_principal) {
		krb5_free_principal(ctx, whitelist_principal);
	}

	code = krb5_cc_initialize(ctx, store_cc, store_principal);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	code = krb5_cc_store_cred(ctx, store_cc, &store_creds);
	if (code != 0) {
		krb5_free_cred_contents(ctx, &store_creds);
		return code;
	}

	client_realm = krb5_principal_get_realm(ctx, store_creds.client);
	if (client_realm != NULL) {
		/*
		 * Because the CANON flag doesn't have any impact
		 * on the impersonate_principal => store_creds.client
		 * realm mapping. We need to store the credentials twice,
		 * once with the returned realm and once with the
		 * realm of impersonate_principal.
		 */
		code = krb5_principal_set_realm(ctx, store_creds.server,
						client_realm);
		if (code != 0) {
			krb5_free_cred_contents(ctx, &store_creds);
			return code;
		}

		code = krb5_cc_store_cred(ctx, store_cc, &store_creds);
		if (code != 0) {
			krb5_free_cred_contents(ctx, &store_creds);
			return code;
		}
	}

	if (expire_time) {
		*expire_time = (time_t) store_creds.times.endtime;
	}

	if (kdc_time) {
		*kdc_time = (time_t) store_creds.times.starttime;
	}

	krb5_free_cred_contents(ctx, &store_creds);

	return 0;
}
#endif

#if !defined(HAVE_KRB5_MAKE_PRINCIPAL) && defined(HAVE_KRB5_BUILD_PRINCIPAL_ALLOC_VA)
/**
 * @brief Create a principal name using a variable argument list.
 *
 * @param[in]  context  The library context.
 *
 * @param[inout]  principal A pointer to the principal structure.
 *
 * @param[in]  _realm    The realm to use. If NULL then the function will
 *                       get the default realm name.
 *
 * @param[in]  ...       A list of 'char *' components, ending with NULL.
 *
 * Use krb5_free_principal() to free the principal when it is no longer needed.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_make_principal(krb5_context context,
					krb5_principal *principal,
					const char *_realm, ...)
{
	krb5_error_code code;
	bool free_realm;
	char *realm;
	va_list ap;

	if (_realm) {
		realm = discard_const_p(char, _realm);
		free_realm = false;
	} else {
		code = krb5_get_default_realm(context, &realm);
		if (code) {
			return code;
		}
		free_realm = true;
	}

	va_start(ap, _realm);
	code = krb5_build_principal_alloc_va(context, principal,
					     strlen(realm), realm,
					     ap);
	va_end(ap);

	if (free_realm) {
		krb5_free_default_realm(context, realm);
	}

	return code;
}
#endif

#if !defined(HAVE_KRB5_CC_GET_LIFETIME) && defined(HAVE_KRB5_CC_RETRIEVE_CRED)
/**
 * @brief Get the lifetime of the initial ticket in the cache.
 *
 * @param[in]  context  The kerberos context.
 *
 * @param[in]  id       The credential cache to get the ticket lifetime.
 *
 * @param[out] t        A pointer to a time value to store the lifetime.
 *
 * @return              0 on success, a krb5_error_code on error.
 */
krb5_error_code smb_krb5_cc_get_lifetime(krb5_context context,
					 krb5_ccache id,
					 time_t *t)
{
	krb5_cc_cursor cursor;
	krb5_error_code kerr;
	krb5_creds cred;
	krb5_timestamp now;

	*t = 0;

	kerr = krb5_timeofday(context, &now);
	if (kerr) {
		return kerr;
	}

	kerr = krb5_cc_start_seq_get(context, id, &cursor);
	if (kerr) {
		return kerr;
	}

	while ((kerr = krb5_cc_next_cred(context, id, &cursor, &cred)) == 0) {
#ifndef HAVE_FLAGS_IN_KRB5_CREDS
		if (cred.ticket_flags & TKT_FLG_INITIAL) {
#else
		if (cred.flags.b.initial) {
#endif
			if (now < cred.times.endtime) {
				*t = (time_t) (cred.times.endtime - now);
			}
			krb5_free_cred_contents(context, &cred);
			break;
		}
		krb5_free_cred_contents(context, &cred);
	}

	krb5_cc_end_seq_get(context, id, &cursor);

	return kerr;
}
#endif /* HAVE_KRB5_CC_GET_LIFETIME */

#if !defined(HAVE_KRB5_FREE_CHECKSUM_CONTENTS) && defined(HAVE_FREE_CHECKSUM)
void smb_krb5_free_checksum_contents(krb5_context ctx, krb5_checksum *cksum)
{
	free_Checksum(cksum);
}
#endif

/**
 * @brief Compute a checksum operating on a keyblock.
 *
 * This function computes a checksum over a PAC using the keyblock for a keyed
 * checksum.
 *
 * @param[in]  mem_ctx A talloc context to alocate the signature on.
 *
 * @param[in]  pac_data The PAC as input.
 *
 * @param[in]  context  The library context.
 *
 * @param[in]  keyblock Encryption key for a keyed checksum.
 *
 * @param[out] sig_type The checksum type
 *
 * @param[out] sig_blob The talloc'ed checksum
 *
 * The caller must free the sig_blob with talloc_free() when it is not needed
 * anymore.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_make_pac_checksum(TALLOC_CTX *mem_ctx,
					   DATA_BLOB *pac_data,
					   krb5_context context,
					   const krb5_keyblock *keyblock,
					   uint32_t *sig_type,
					   DATA_BLOB *sig_blob)
{
	krb5_error_code ret;
	krb5_checksum cksum;
#if defined(HAVE_KRB5_CRYPTO_INIT) && defined(HAVE_KRB5_CREATE_CHECKSUM)
	krb5_crypto crypto;


	ret = krb5_crypto_init(context,
			       keyblock,
			       0,
			       &crypto);
	if (ret) {
		DEBUG(0,("krb5_crypto_init() failed: %s\n",
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		return ret;
	}
	ret = krb5_create_checksum(context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   0,
				   pac_data->data,
				   pac_data->length,
				   &cksum);
	if (ret) {
		DEBUG(2, ("PAC Verification failed: %s\n",
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
	}

	krb5_crypto_destroy(context, crypto);

	if (ret) {
		return ret;
	}

	*sig_type = cksum.cksumtype;
	*sig_blob = data_blob_talloc(mem_ctx,
					cksum.checksum.data,
					cksum.checksum.length);
#elif defined(HAVE_KRB5_C_MAKE_CHECKSUM)
	krb5_data input;

	input.data = (char *)pac_data->data;
	input.length = pac_data->length;

	ret = krb5_c_make_checksum(context,
				   0,
				   keyblock,
				   KRB5_KEYUSAGE_APP_DATA_CKSUM,
				   &input,
				   &cksum);
	if (ret) {
		DEBUG(2, ("PAC Verification failed: %s\n",
			  smb_get_krb5_error_message(context, ret, mem_ctx)));
		return ret;
	}

	*sig_type = cksum.checksum_type;
	*sig_blob = data_blob_talloc(mem_ctx,
					cksum.contents,
					cksum.length);

#else
#error krb5_create_checksum or krb5_c_make_checksum not available
#endif /* HAVE_KRB5_C_MAKE_CHECKSUM */
	smb_krb5_free_checksum_contents(context, &cksum);

	return 0;
}


/**
 * @brief Get realm of a principal
 *
 * @param[in] mem_ctx   The talloc ctx to put the result on
 *
 * @param[in] context   The library context
 *
 * @param[in] principal The principal to get the realm from.
 *
 * @return A talloced string with the realm or NULL if an error occurred.
 */
char *smb_krb5_principal_get_realm(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   krb5_const_principal principal)
{
#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM /* Heimdal */
	return talloc_strdup(mem_ctx,
			     krb5_principal_get_realm(context, principal));
#elif defined(krb5_princ_realm) /* MIT */
	const krb5_data *realm;
	realm = krb5_princ_realm(context, principal);
	return talloc_strndup(mem_ctx, realm->data, realm->length);
#else
#error UNKNOWN_GET_PRINC_REALM_FUNCTIONS
#endif
}

/**
 * @brief Get realm of a principal
 *
 * @param[in] context   The library context
 *
 * @param[in] principal The principal to set the realm
 *
 * @param[in] realm     The realm as a string to set.
 *
 * @retur 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_principal_set_realm(krb5_context context,
					     krb5_principal principal,
					     const char *realm)
{
#ifdef HAVE_KRB5_PRINCIPAL_SET_REALM /* Heimdal */
	return krb5_principal_set_realm(context, principal, realm);
#elif defined(krb5_princ_realm) && defined(krb5_princ_set_realm) /* MIT */
	krb5_error_code ret;
	krb5_data data;
	krb5_data *old_data;

	old_data = krb5_princ_realm(context, principal);

	ret = smb_krb5_copy_data_contents(&data,
					  realm,
					  strlen(realm));
	if (ret) {
		return ret;
	}

	/* free realm before setting */
	free(old_data->data);

	krb5_princ_set_realm(context, principal, &data);

	return ret;
#else
#error UNKNOWN_PRINC_SET_REALM_FUNCTION
#endif
}


/**
 * @brief Get the realm from the service hostname.
 *
 * This function will look for a domain realm mapping in the [domain_realm]
 * section of the krb5.conf first and fallback to extract the realm from
 * the provided service hostname. As a last resort it will return the
 * provided client_realm.
 *
 * @param[in]  mem_ctx     The talloc context
 *
 * @param[in]  hostname    The service hostname
 *
 * @param[in]  client_realm  If we can not find a mapping, fall back to
 *                           this realm.
 *
 * @return The realm to use for the service hostname, NULL if a fatal error
 *         occured.
 */
char *smb_krb5_get_realm_from_hostname(TALLOC_CTX *mem_ctx,
				       const char *hostname,
				       const char *client_realm)
{
#if defined(HAVE_KRB5_REALM_TYPE)
	/* Heimdal. */
	krb5_realm *realm_list = NULL;
#else
	/* MIT */
	char **realm_list = NULL;
#endif
	char *realm = NULL;
	krb5_error_code kerr;
	krb5_context ctx = NULL;

	kerr = smb_krb5_init_context_common(&ctx);
	if (kerr) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(kerr));
		return NULL;
	}

	kerr = krb5_get_host_realm(ctx, hostname, &realm_list);
	if (kerr == KRB5_ERR_HOST_REALM_UNKNOWN) {
		realm_list = NULL;
		kerr = 0;
	}
	if (kerr != 0) {
		DEBUG(3,("kerberos_get_realm_from_hostname %s: "
			"failed %s\n",
			hostname ? hostname : "(NULL)",
			error_message(kerr) ));
		goto out;
	}

	if (realm_list != NULL &&
	    realm_list[0] != NULL &&
	    realm_list[0][0] != '\0') {
		realm = talloc_strdup(mem_ctx, realm_list[0]);
		if (realm == NULL) {
			goto out;
		}
	} else {
		const char *p = NULL;

		/*
		 * "dc6.samba2003.example.com"
		 * returns a realm of "SAMBA2003.EXAMPLE.COM"
		 *
		 * "dc6." returns realm as NULL
		 */
		p = strchr_m(hostname, '.');
		if (p != NULL && p[1] != '\0') {
			realm = talloc_strdup_upper(mem_ctx, p + 1);
			if (realm == NULL) {
				goto out;
			}
		}
	}

	if (realm == NULL) {
		realm = talloc_strdup(mem_ctx, client_realm);
	}

  out:

	if (ctx) {
		if (realm_list) {
			krb5_free_host_realm(ctx, realm_list);
			realm_list = NULL;
		}
		krb5_free_context(ctx);
		ctx = NULL;
	}
	return realm;
}

/**
 * @brief Get an error string from a Kerberos error code.
 *
 * @param[in]  context  The library context.
 *
 * @param[in]  code     The Kerberos error code.
 *
 * @param[in]  mem_ctx  The talloc context to allocate the error string on.
 *
 * @return A talloc'ed error string or NULL if an error occurred.
 *
 * The caller must free the returned error string with talloc_free() if not
 * needed anymore
 */
char *smb_get_krb5_error_message(krb5_context context,
				 krb5_error_code code,
				 TALLOC_CTX *mem_ctx)
{
	char *ret;

#if defined(HAVE_KRB5_GET_ERROR_MESSAGE) && defined(HAVE_KRB5_FREE_ERROR_MESSAGE)
	const char *context_error = krb5_get_error_message(context, code);
	if (context_error) {
		ret = talloc_asprintf(mem_ctx, "%s: %s",
					error_message(code), context_error);
		krb5_free_error_message(context, context_error);
		return ret;
	}
#endif
	ret = talloc_strdup(mem_ctx, error_message(code));
	return ret;
}

/**
 * @brief Return the type of a krb5_principal
 *
 * @param[in]  context  The library context.
 *
 * @param[in]  principal The principal to get the type from.
 *
 * @return The integer type of the principal.
 */
int smb_krb5_principal_get_type(krb5_context context,
				krb5_const_principal principal)
{
#ifdef HAVE_KRB5_PRINCIPAL_GET_TYPE /* Heimdal */
	return krb5_principal_get_type(context, principal);
#elif defined(krb5_princ_type) /* MIT */
	return krb5_princ_type(context, principal);
#else
#error	UNKNOWN_PRINC_GET_TYPE_FUNCTION
#endif
}

/**
 * @brief Set the type of a principal
 *
 * @param[in]  context  The library context
 *
 * @param[inout] principal The principal to set the type for.
 *
 * @param[in]  type     The principal type to set.
 */
void smb_krb5_principal_set_type(krb5_context context,
				 krb5_principal principal,
				 int type)
{
#ifdef HAVE_KRB5_PRINCIPAL_SET_TYPE /* Heimdal */
	krb5_principal_set_type(context, principal, type);
#elif defined(krb5_princ_type) /* MIT */
	krb5_princ_type(context, principal) = type;
#else
#error	UNKNOWN_PRINC_SET_TYPE_FUNCTION
#endif
}

#if !defined(HAVE_KRB5_WARNX)
/**
 * @brief Log a Kerberos message
 *
 * It sends the message to com_err.
 *
 * @param[in]  context  The library context
 *
 * @param[in]  fmt      The message format
 *
 * @param[in]  ...      The message arguments
 *
 * @return 0 on success.
 */
krb5_error_code krb5_warnx(krb5_context context, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	com_err_va("samba-kdc", errno, fmt, args);
	va_end(args);

	return 0;
}
#endif

/**
 * @brief Copy a credential cache.
 *
 * @param[in]  context  The library context.
 *
 * @param[in]  incc     Credential cache to be copied.
 *
 * @param[inout] outcc  Copy of credential cache to be filled in.
 *
 * @return 0 on success, a Kerberos error code otherwise.
 */
krb5_error_code smb_krb5_cc_copy_creds(krb5_context context,
				       krb5_ccache incc, krb5_ccache outcc)
{
#ifdef HAVE_KRB5_CC_COPY_CACHE /* Heimdal */
	return krb5_cc_copy_cache(context, incc, outcc);
#elif defined(HAVE_KRB5_CC_COPY_CREDS)
	krb5_error_code ret;
	krb5_principal princ = NULL;

	ret = krb5_cc_get_principal(context, incc, &princ);
	if (ret != 0) {
		return ret;
	}
	ret = krb5_cc_initialize(context, outcc, princ);
	krb5_free_principal(context, princ);
	if (ret != 0) {
		return ret;
	}
	return krb5_cc_copy_creds(context, incc, outcc);
#else
#error UNKNOWN_KRB5_CC_COPY_CACHE_OR_CREDS_FUNCTION
#endif
}

/**********************************************************
 * ADS KRB5 CALLS
 **********************************************************/

static bool ads_cleanup_expired_creds(krb5_context context,
				      krb5_ccache  ccache,
				      krb5_creds  *credsp)
{
	krb5_error_code retval;
	const char *cc_type = krb5_cc_get_type(context, ccache);

	DEBUG(3, ("ads_cleanup_expired_creds: Ticket in ccache[%s:%s] expiration %s\n",
		  cc_type, krb5_cc_get_name(context, ccache),
		  http_timestring(talloc_tos(), credsp->times.endtime)));

	/* we will probably need new tickets if the current ones
	   will expire within 10 seconds.
	*/
	if (credsp->times.endtime >= (time(NULL) + 10))
		return false;

	/* heimdal won't remove creds from a file ccache, and
	   perhaps we shouldn't anyway, since internally we
	   use memory ccaches, and a FILE one probably means that
	   we're using creds obtained outside of our exectuable
	*/
	if (strequal(cc_type, "FILE")) {
		DEBUG(5, ("ads_cleanup_expired_creds: We do not remove creds from a %s ccache\n", cc_type));
		return false;
	}

	retval = krb5_cc_remove_cred(context, ccache, 0, credsp);
	if (retval) {
		DEBUG(1, ("ads_cleanup_expired_creds: krb5_cc_remove_cred failed, err %s\n",
			  error_message(retval)));
		/* If we have an error in this, we want to display it,
		   but continue as though we deleted it */
	}
	return true;
}

/* Allocate and setup the auth context into the state we need. */

static krb5_error_code ads_setup_auth_context(krb5_context context,
					      krb5_auth_context *auth_context)
{
	krb5_error_code retval;

	retval = krb5_auth_con_init(context, auth_context );
	if (retval) {
		DEBUG(1,("krb5_auth_con_init failed (%s)\n",
			error_message(retval)));
		return retval;
	}

	/* Ensure this is an addressless ticket. */
	retval = krb5_auth_con_setaddrs(context, *auth_context, NULL, NULL);
	if (retval) {
		DEBUG(1,("krb5_auth_con_setaddrs failed (%s)\n",
			error_message(retval)));
	}

	return retval;
}

#if defined(TKT_FLG_OK_AS_DELEGATE ) && defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY) && defined(KRB5_AUTH_CONTEXT_USE_SUBKEY) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
static krb5_error_code ads_create_gss_checksum(krb5_data *in_data, /* [inout] */
					       uint32_t gss_flags)
{
	unsigned int orig_length = in_data->length;
	unsigned int base_cksum_size = GSSAPI_CHECKSUM_SIZE;
	char *gss_cksum = NULL;

	if (orig_length) {
		/* Extra length field for delgated ticket. */
		base_cksum_size += 4;
	}

	if ((unsigned int)base_cksum_size + orig_length <
			(unsigned int)base_cksum_size) {
                return EINVAL;
        }

	gss_cksum = (char *)SMB_MALLOC(base_cksum_size + orig_length);
	if (gss_cksum == NULL) {
		return ENOMEM;
        }

	memset(gss_cksum, '\0', base_cksum_size + orig_length);
	SIVAL(gss_cksum, 0, GSSAPI_BNDLENGTH);

	/*
	 * GSS_C_NO_CHANNEL_BINDINGS means 16 zero bytes.
	 * This matches the behavior of heimdal and mit.
	 *
	 * And it is needed to work against some closed source
	 * SMB servers.
	 *
	 * See bug #7883
	 */
	memset(&gss_cksum[4], 0x00, GSSAPI_BNDLENGTH);

	SIVAL(gss_cksum, 20, gss_flags);

	if (orig_length && in_data->data != NULL) {
		SSVAL(gss_cksum, 24, 1); /* The Delegation Option identifier */
		SSVAL(gss_cksum, 26, orig_length);
		/* Copy the kerberos KRB_CRED data */
		memcpy(gss_cksum + 28, in_data->data, orig_length);
		free(in_data->data);
		in_data->data = NULL;
		in_data->length = 0;
	}
	in_data->data = gss_cksum;
	in_data->length = base_cksum_size + orig_length;
	return 0;
}
#endif

/*
 * We can't use krb5_mk_req because w2k wants the service to be in a particular
 * format.
 */
static krb5_error_code ads_krb5_mk_req(krb5_context context,
				       krb5_auth_context *auth_context,
				       const krb5_flags ap_req_options,
				       const char *principal,
				       krb5_ccache ccache,
				       krb5_data *outbuf,
				       time_t *expire_time,
				       const char *impersonate_princ_s)
{
	krb5_error_code retval;
	krb5_principal server;
	krb5_principal impersonate_princ = NULL;
	krb5_creds *credsp;
	krb5_creds creds;
	krb5_data in_data;
	bool creds_ready = false;
	int i = 0, maxtries = 3;
	bool ok;

	ZERO_STRUCT(in_data);

	retval = smb_krb5_parse_name(context, principal, &server);
	if (retval != 0) {
		DEBUG(1,("ads_krb5_mk_req: Failed to parse principal %s\n", principal));
		return retval;
	}

	if (impersonate_princ_s) {
		retval = smb_krb5_parse_name(context, impersonate_princ_s,
					     &impersonate_princ);
		if (retval) {
			DEBUG(1,("ads_krb5_mk_req: Failed to parse principal %s\n", impersonate_princ_s));
			goto cleanup_princ;
		}
	}

	/* obtain ticket & session key */
	ZERO_STRUCT(creds);
	if ((retval = krb5_copy_principal(context, server, &creds.server))) {
		DEBUG(1,("ads_krb5_mk_req: krb5_copy_principal failed (%s)\n",
			 error_message(retval)));
		goto cleanup_princ;
	}

	retval = krb5_cc_get_principal(context, ccache, &creds.client);
	if (retval != 0) {
		/* This can commonly fail on smbd startup with no ticket in the cache.
		 * Report at higher level than 1. */
		DEBUG(3,("ads_krb5_mk_req: krb5_cc_get_principal failed (%s)\n",
			 error_message(retval)));
		goto cleanup_creds;
	}

	while (!creds_ready && (i < maxtries)) {

		retval = smb_krb5_get_credentials(context,
						  ccache,
						  creds.client,
						  creds.server,
						  impersonate_princ,
						  &credsp);
		if (retval != 0) {
			DBG_WARNING("smb_krb5_get_credentials failed for %s "
				    "(%s)\n",
				    principal,
				    error_message(retval));
			goto cleanup_creds;
		}

		/* cope with ticket being in the future due to clock skew */
		if ((unsigned)credsp->times.starttime > time(NULL)) {
			time_t t = time(NULL);
			int time_offset =(int)((unsigned)credsp->times.starttime-t);
			DEBUG(4,("ads_krb5_mk_req: Advancing clock by %d seconds to cope with clock skew\n", time_offset));
			krb5_set_real_time(context, t + time_offset + 1, 0);
		}

		ok = ads_cleanup_expired_creds(context, ccache, credsp);
		if (!ok) {
			creds_ready = true;
		}

		i++;
	}

	DBG_DEBUG("Ticket (%s) in ccache (%s:%s) is valid until: (%s - %u)\n",
		  principal,
		  krb5_cc_get_type(context, ccache),
		  krb5_cc_get_name(context, ccache),
		  http_timestring(talloc_tos(),
				  (unsigned)credsp->times.endtime),
		  (unsigned)credsp->times.endtime);

	if (expire_time) {
		*expire_time = (time_t)credsp->times.endtime;
	}

	/* Allocate the auth_context. */
	retval = ads_setup_auth_context(context, auth_context);
	if (retval != 0) {
		DBG_WARNING("ads_setup_auth_context failed (%s)\n",
			    error_message(retval));
		goto cleanup_creds;
	}

#if defined(TKT_FLG_OK_AS_DELEGATE ) && defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY) && defined(KRB5_AUTH_CONTEXT_USE_SUBKEY) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	{
		uint32_t gss_flags = 0;

		if (credsp->ticket_flags & TKT_FLG_OK_AS_DELEGATE) {
			/*
			 * Fetch a forwarded TGT from the KDC so that we can
			 * hand off a 2nd ticket as part of the kerberos
			 * exchange.
			 */

			DBG_INFO("Server marked as OK to delegate to, building "
				 "forwardable TGT\n");

			retval = krb5_auth_con_setuseruserkey(context,
					*auth_context,
					&credsp->keyblock );
			if (retval != 0) {
				DBG_WARNING("krb5_auth_con_setuseruserkey "
					    "failed (%s)\n",
					    error_message(retval));
				goto cleanup_creds;
			}

			/* Must use a subkey for forwarded tickets. */
			retval = krb5_auth_con_setflags(context,
							*auth_context,
							KRB5_AUTH_CONTEXT_USE_SUBKEY);
			if (retval != 0) {
				DBG_WARNING("krb5_auth_con_setflags failed (%s)\n",
					    error_message(retval));
				goto cleanup_creds;
			}

			retval = krb5_fwd_tgt_creds(context,/* Krb5 context [in] */
				*auth_context,  /* Authentication context [in] */
				discard_const_p(char, KRB5_TGS_NAME),  /* Ticket service name ("krbtgt") [in] */
				credsp->client, /* Client principal for the tgt [in] */
				credsp->server, /* Server principal for the tgt [in] */
				ccache,         /* Credential cache to use for storage [in] */
				1,              /* Turn on for "Forwardable ticket" [in] */
				&in_data );     /* Resulting response [out] */

			if (retval) {
				DBG_INFO("krb5_fwd_tgt_creds failed (%s)\n",
					 error_message(retval));

				/*
				 * This is not fatal. Delete the *auth_context and continue
				 * with krb5_mk_req_extended to get a non-forwardable ticket.
				 */

				if (in_data.data) {
					free( in_data.data );
					in_data.data = NULL;
					in_data.length = 0;
				}
				krb5_auth_con_free(context, *auth_context);
				*auth_context = NULL;
				retval = ads_setup_auth_context(context, auth_context);
				if (retval != 0) {
					DBG_WARNING("ads_setup_auth_context failed (%s)\n",
						    error_message(retval));
					goto cleanup_creds;
				}
			} else {
				/* We got a delegated ticket. */
				gss_flags |= GSS_C_DELEG_FLAG;
			}
		}

		/* Frees and reallocates in_data into a GSS checksum blob. */
		retval = ads_create_gss_checksum(&in_data, gss_flags);
		if (retval != 0) {
			goto cleanup_data;
		}

		/* We always want GSS-checksum types. */
		retval = krb5_auth_con_set_req_cksumtype(context, *auth_context, GSSAPI_CHECKSUM );
		if (retval != 0) {
			DEBUG(1,("krb5_auth_con_set_req_cksumtype failed (%s)\n",
				error_message(retval)));
			goto cleanup_data;
		}
	}
#endif

	retval = krb5_mk_req_extended(context, auth_context, ap_req_options,
				      &in_data, credsp, outbuf);
	if (retval != 0) {
		DBG_WARNING("krb5_mk_req_extended failed (%s)\n",
			    error_message(retval));
	}

#if defined(TKT_FLG_OK_AS_DELEGATE ) && defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY) && defined(KRB5_AUTH_CONTEXT_USE_SUBKEY) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
cleanup_data:
#endif

	if (in_data.data) {
		free( in_data.data );
		in_data.length = 0;
	}

	krb5_free_creds(context, credsp);

cleanup_creds:
	krb5_free_cred_contents(context, &creds);

cleanup_princ:
	krb5_free_principal(context, server);
	if (impersonate_princ) {
		krb5_free_principal(context, impersonate_princ);
	}

	return retval;
}

/*
  get a kerberos5 ticket for the given service
*/
int ads_krb5_cli_get_ticket(TALLOC_CTX *mem_ctx,
			    const char *principal,
			    time_t time_offset,
			    DATA_BLOB *ticket,
			    DATA_BLOB *session_key_krb5,
			    uint32_t extra_ap_opts, const char *ccname,
			    time_t *tgs_expire,
			    const char *impersonate_princ_s)
{
	krb5_error_code retval;
	krb5_data packet;
	krb5_context context = NULL;
	krb5_ccache ccdef = NULL;
	krb5_auth_context auth_context = NULL;
	krb5_enctype enc_types[] = {
#ifdef HAVE_ENCTYPE_AES256_CTS_HMAC_SHA1_96
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
#endif
#ifdef HAVE_ENCTYPE_AES128_CTS_HMAC_SHA1_96
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,
#endif
		ENCTYPE_ARCFOUR_HMAC,
		ENCTYPE_DES_CBC_MD5,
		ENCTYPE_DES_CBC_CRC,
		ENCTYPE_NULL};
	bool ok;

	retval = smb_krb5_init_context_common(&context);
	if (retval != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(retval));
		goto failed;
	}

	if (time_offset != 0) {
		krb5_set_real_time(context, time(NULL) + time_offset, 0);
	}

	retval = krb5_cc_resolve(context,
				 ccname ? ccname : krb5_cc_default_name(context),
				 &ccdef);
	if (retval != 0) {
		DBG_WARNING("krb5_cc_default failed (%s)\n",
			    error_message(retval));
		goto failed;
	}

	retval = krb5_set_default_tgs_ktypes(context, enc_types);
	if (retval != 0) {
		DBG_WARNING("krb5_set_default_tgs_ktypes failed (%s)\n",
			    error_message(retval));
		goto failed;
	}

	retval = ads_krb5_mk_req(context,
				 &auth_context,
				 AP_OPTS_USE_SUBKEY | (krb5_flags)extra_ap_opts,
				 principal,
				 ccdef,
				 &packet,
				 tgs_expire,
				 impersonate_princ_s);
	if (retval != 0) {
		goto failed;
	}

	ok = smb_krb5_get_smb_session_key(mem_ctx,
					  context,
					  auth_context,
					  session_key_krb5,
					  false);
	if (!ok) {
		retval = ENOMEM;
		goto failed;
	}

	*ticket = data_blob_talloc(mem_ctx, packet.data, packet.length);

	smb_krb5_free_data_contents(context, &packet);

failed:

	if (context) {
		if (ccdef) {
			krb5_cc_close(context, ccdef);
		}
		if (auth_context) {
			krb5_auth_con_free(context, auth_context);
		}
		krb5_free_context(context);
	}

	return retval;
}

#ifndef SAMBA4_USES_HEIMDAL /* MITKRB5 tracing callback */
static void smb_krb5_trace_cb(krb5_context ctx,
#ifdef HAVE_KRB5_TRACE_INFO
			      const krb5_trace_info *info,
#elif defined(HAVE_KRB5_TRACE_INFO_STRUCT)
			      const struct krb5_trace_info *info,
#else
#error unknown krb5_trace_info
#endif
			      void *data)
{
	if (info != NULL) {
		DBGC_DEBUG(DBGC_KERBEROS, "%s", info->message);
	}
}
#endif

krb5_error_code smb_krb5_init_context_common(krb5_context *_krb5_context)
{
	krb5_error_code ret;
	krb5_context krb5_ctx;

	initialize_krb5_error_table();

	ret = krb5_init_context(&krb5_ctx);
	if (ret) {
		DBG_ERR("Krb5 context initialization failed (%s)\n",
			 error_message(ret));
		return ret;
	}

	/* The MIT Kerberos build relies on using the system krb5.conf file.
	 * If you really want to use another file please set KRB5_CONFIG
	 * accordingly. */
#ifndef SAMBA4_USES_HEIMDAL
	ret = krb5_set_trace_callback(krb5_ctx, smb_krb5_trace_cb, NULL);
	if (ret) {
		DBG_ERR("Failed to set MIT kerberos trace callback! (%s)\n",
			error_message(ret));
	}
#endif

#ifdef SAMBA4_USES_HEIMDAL
	/* Set options in kerberos */
	krb5_set_dns_canonicalize_hostname(krb5_ctx, false);
#endif

	*_krb5_context = krb5_ctx;
	return 0;
}

#else /* HAVE_KRB5 */
/* This saves a few linking headaches */
int ads_krb5_cli_get_ticket(TALLOC_CTX *mem_ctx,
			    const char *principal,
			    time_t time_offset,
			    DATA_BLOB *ticket,
			    DATA_BLOB *session_key_krb5,
			    uint32_t extra_ap_opts, const char *ccname,
			    time_t *tgs_expire,
			    const char *impersonate_princ_s)
{
	 DEBUG(0,("NO KERBEROS SUPPORT\n"));
	 return 1;
}

#endif /* HAVE_KRB5 */

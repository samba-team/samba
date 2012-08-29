/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   
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

#ifndef _AUTH_KERBEROS_H_
#define _AUTH_KERBEROS_H_

#if defined(HAVE_KRB5)

#include "system/kerberos.h"
#include "auth/kerberos/krb5_init_context.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "lib/krb5_wrap/krb5_samba.h"
#include "lib/krb5_wrap/gss_samba.h"

struct auth_user_info_dc;
struct cli_credentials;

struct ccache_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_ccache ccache;
};

struct keytab_container {
	struct smb_krb5_context *smb_krb5_context;
	krb5_keytab keytab;
	bool password_based;
};

/* not really ASN.1, but RFC 1964 */
#define TOK_ID_KRB_AP_REQ	((const uint8_t *)"\x01\x00")
#define TOK_ID_KRB_AP_REP	((const uint8_t *)"\x02\x00")
#define TOK_ID_KRB_ERROR	((const uint8_t *)"\x03\x00")
#define TOK_ID_GSS_GETMIC	((const uint8_t *)"\x01\x01")
#define TOK_ID_GSS_WRAP		((const uint8_t *)"\x02\x01")

#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE
#define KRB5_KEY_TYPE(k)	((k)->keytype)
#define KRB5_KEY_LENGTH(k)	((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)	((k)->keyvalue.data)
#else
#define	KRB5_KEY_TYPE(k)	((k)->enctype)
#define KRB5_KEY_LENGTH(k)	((k)->length)
#define KRB5_KEY_DATA(k)	((k)->contents)
#endif /* HAVE_KRB5_KEYBLOCK_KEYVALUE */

#define ENC_ALL_TYPES (ENC_CRC32 | ENC_RSA_MD5 | ENC_RC4_HMAC_MD5 |	\
		       ENC_HMAC_SHA1_96_AES128 | ENC_HMAC_SHA1_96_AES256)

#ifndef HAVE_KRB5_SET_DEFAULT_TGS_KTYPES
krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc);
#endif

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock);
#endif

#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING) && !defined(HAVE_KRB5_PRINC_COMPONENT)
const krb5_data *krb5_princ_component(krb5_context context, krb5_principal principal, int i );
#endif

#ifndef krb5_princ_size
#if defined(HAVE_KRB5_PRINCIPAL_GET_NUM_COMP)
#define krb5_princ_size krb5_principal_get_num_comp
#else
#error krb5_princ_size unavailable
#endif
#endif

/* Samba wrapper function for krb5 functionality. */
 krb5_error_code kerberos_encode_pac(TALLOC_CTX *mem_ctx,
				    struct PAC_DATA *pac_data,
				    krb5_context context,
				    const krb5_keyblock *krbtgt_keyblock,
				    const krb5_keyblock *service_keyblock,
				    DATA_BLOB *pac);
 krb5_error_code kerberos_create_pac(TALLOC_CTX *mem_ctx,
				     struct auth_user_info_dc *user_info_dc,
				     krb5_context context,
				     const krb5_keyblock *krbtgt_keyblock,
				     const krb5_keyblock *service_keyblock,
				     krb5_principal client_principal,
				     time_t tgs_authtime,
				     DATA_BLOB *pac);

#include "auth/kerberos/proto.h"

#endif /* HAVE_KRB5 */

#endif /* _AUTH_KERBEROS_H_ */

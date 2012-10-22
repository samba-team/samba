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
#include "krb5_samba.h"
#include "lib/util/asn1.h"

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

#if defined(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS)
/* HEIMDAL */
 bool setup_kaddr( krb5_address *pkaddr, struct sockaddr_storage *paddr)
{
	memset(pkaddr, '\0', sizeof(krb5_address));
#if defined(HAVE_IPV6) && defined(KRB5_ADDRESS_INET6)
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
bool setup_kaddr( krb5_address *pkaddr, struct sockaddr_storage *paddr)
{
	memset(pkaddr, '\0', sizeof(krb5_address));
#if defined(HAVE_IPV6) && defined(ADDRTYPE_INET6)
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
#ifdef HAVE_KRB5_PDU_NONE_DECL
	return krb5_get_default_in_tkt_etypes(context, KRB5_PDU_NONE, enctypes);
#else
	return krb5_get_default_in_tkt_etypes(context, enctypes);
#endif
}
#else
#error UNKNOWN_GET_ENCTYPES_FUNCTIONS
#endif

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
 krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context,
					krb5_auth_context auth_context,
					krb5_keyblock *keyblock)
{
	return krb5_auth_con_setkey(context, auth_context, keyblock);
}
#endif

bool unwrap_edata_ntstatus(TALLOC_CTX *mem_ctx,
			   DATA_BLOB *edata,
			   DATA_BLOB *edata_out)
{
	DATA_BLOB edata_contents;
	ASN1_DATA *data;
	int edata_type;

	if (!edata->length) {
		return false;
	}

	data = asn1_init(mem_ctx);
	if (data == NULL) {
		return false;
	}

	asn1_load(data, *edata);
	asn1_start_tag(data, ASN1_SEQUENCE(0));
	asn1_start_tag(data, ASN1_CONTEXT(1));
	asn1_read_Integer(data, &edata_type);

	if (edata_type != KRB5_PADATA_PW_SALT) {
		DEBUG(0,("edata is not of required type %d but of type %d\n",
			KRB5_PADATA_PW_SALT, edata_type));
		asn1_free(data);
		return false;
	}

	asn1_start_tag(data, ASN1_CONTEXT(2));
	asn1_read_OctetString(data, talloc_tos(), &edata_contents);
	asn1_end_tag(data);
	asn1_end_tag(data);
	asn1_end_tag(data);
	asn1_free(data);

	*edata_out = data_blob_talloc(mem_ctx, edata_contents.data, edata_contents.length);

	data_blob_free(&edata_contents);

	return true;
}


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

static krb5_error_code setup_auth_context(krb5_context context,
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
static krb5_error_code create_gss_checksum(krb5_data *in_data, /* [inout] */
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

	if (orig_length) {
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
void krb5_free_unparsed_name(krb5_context context, char *val)
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

/*
  we can't use krb5_mk_req because w2k wants the service to be in a particular format
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
	krb5_error_code 	  retval;
	krb5_principal	  server;
	krb5_principal impersonate_princ = NULL;
	krb5_creds 		* credsp;
	krb5_creds 		  creds;
	krb5_data in_data;
	bool creds_ready = false;
	int i = 0, maxtries = 3;

	ZERO_STRUCT(in_data);

	retval = smb_krb5_parse_name(context, principal, &server);
	if (retval) {
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

	if ((retval = krb5_cc_get_principal(context, ccache, &creds.client))) {
		/* This can commonly fail on smbd startup with no ticket in the cache.
		 * Report at higher level than 1. */
		DEBUG(3,("ads_krb5_mk_req: krb5_cc_get_principal failed (%s)\n",
			 error_message(retval)));
		goto cleanup_creds;
	}

	while (!creds_ready && (i < maxtries)) {

		if ((retval = smb_krb5_get_credentials(context, ccache,
						       creds.client,
						       creds.server,
						       impersonate_princ,
						       &credsp))) {
			DEBUG(1,("ads_krb5_mk_req: smb_krb5_get_credentials failed for %s (%s)\n",
				principal, error_message(retval)));
			goto cleanup_creds;
		}

		/* cope with ticket being in the future due to clock skew */
		if ((unsigned)credsp->times.starttime > time(NULL)) {
			time_t t = time(NULL);
			int time_offset =(int)((unsigned)credsp->times.starttime-t);
			DEBUG(4,("ads_krb5_mk_req: Advancing clock by %d seconds to cope with clock skew\n", time_offset));
			krb5_set_real_time(context, t + time_offset + 1, 0);
		}

		if (!ads_cleanup_expired_creds(context, ccache, credsp)) {
			creds_ready = true;
		}

		i++;
	}

	DEBUG(10,("ads_krb5_mk_req: Ticket (%s) in ccache (%s:%s) is valid until: (%s - %u)\n",
		  principal, krb5_cc_get_type(context, ccache), krb5_cc_get_name(context, ccache),
		  http_timestring(talloc_tos(), (unsigned)credsp->times.endtime), 
		  (unsigned)credsp->times.endtime));

	if (expire_time) {
		*expire_time = (time_t)credsp->times.endtime;
	}

	/* Allocate the auth_context. */
	retval = setup_auth_context(context, auth_context);
	if (retval) {
		DEBUG(1,("setup_auth_context failed (%s)\n",
			error_message(retval)));
		goto cleanup_creds;
	}

#if defined(TKT_FLG_OK_AS_DELEGATE ) && defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY) && defined(KRB5_AUTH_CONTEXT_USE_SUBKEY) && defined(HAVE_KRB5_AUTH_CON_SET_REQ_CKSUMTYPE)
	{
		uint32_t gss_flags = 0;

		if( credsp->ticket_flags & TKT_FLG_OK_AS_DELEGATE ) {
			/* Fetch a forwarded TGT from the KDC so that we can hand off a 2nd ticket
			 as part of the kerberos exchange. */

			DEBUG( 3, ("ads_krb5_mk_req: server marked as OK to delegate to, building forwardable TGT\n")  );

			retval = krb5_auth_con_setuseruserkey(context,
					*auth_context,
					&credsp->keyblock );
			if (retval) {
				DEBUG(1,("krb5_auth_con_setuseruserkey failed (%s)\n",
					error_message(retval)));
				goto cleanup_creds;
			}

			/* Must use a subkey for forwarded tickets. */
			retval = krb5_auth_con_setflags(context,
				*auth_context,
				KRB5_AUTH_CONTEXT_USE_SUBKEY);
			if (retval) {
				DEBUG(1,("krb5_auth_con_setflags failed (%s)\n",
					error_message(retval)));
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
				DEBUG( 3, ("krb5_fwd_tgt_creds failed (%s)\n",
					   error_message( retval ) ) );

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
				retval = setup_auth_context(context, auth_context);
				if (retval) {
					DEBUG(1,("setup_auth_context failed (%s)\n",
						error_message(retval)));
					goto cleanup_creds;
				}
			} else {
				/* We got a delegated ticket. */
				gss_flags |= GSS_C_DELEG_FLAG;
			}
		}

		/* Frees and reallocates in_data into a GSS checksum blob. */
		retval = create_gss_checksum(&in_data, gss_flags);
		if (retval) {
			goto cleanup_data;
		}

		/* We always want GSS-checksum types. */
		retval = krb5_auth_con_set_req_cksumtype(context, *auth_context, GSSAPI_CHECKSUM );
		if (retval) {
			DEBUG(1,("krb5_auth_con_set_req_cksumtype failed (%s)\n",
				error_message(retval)));
			goto cleanup_data;
		}
	}
#endif

	retval = krb5_mk_req_extended(context, auth_context, ap_req_options,
				      &in_data, credsp, outbuf);
	if (retval) {
		DEBUG(1,("ads_krb5_mk_req: krb5_mk_req_extended failed (%s)\n", 
			 error_message(retval)));
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

/*
  get a kerberos5 ticket for the given service
*/
int cli_krb5_get_ticket(TALLOC_CTX *mem_ctx,
			const char *principal, time_t time_offset,
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5,
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

	initialize_krb5_error_table();
	retval = krb5_init_context(&context);
	if (retval) {
		DEBUG(1, ("krb5_init_context failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if (time_offset != 0) {
		krb5_set_real_time(context, time(NULL) + time_offset, 0);
	}

	if ((retval = krb5_cc_resolve(context, ccname ?
			ccname : krb5_cc_default_name(context), &ccdef))) {
		DEBUG(1, ("krb5_cc_default failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if ((retval = krb5_set_default_tgs_ktypes(context, enc_types))) {
		DEBUG(1, ("krb5_set_default_tgs_ktypes failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	retval = ads_krb5_mk_req(context, &auth_context,
				AP_OPTS_USE_SUBKEY | (krb5_flags)extra_ap_opts,
				principal, ccdef, &packet,
				tgs_expire, impersonate_princ_s);
	if (retval) {
		goto failed;
	}

	get_krb5_smb_session_key(mem_ctx, context, auth_context,
				 session_key_krb5, false);

	*ticket = data_blob_talloc(mem_ctx, packet.data, packet.length);

 	kerberos_free_data_contents(context, &packet);

failed:

	if (context) {
		if (ccdef)
			krb5_cc_close(context, ccdef);
		if (auth_context)
			krb5_auth_con_free(context, auth_context);
		krb5_free_context(context);
	}

	return retval;
}

bool get_krb5_smb_session_key(TALLOC_CTX *mem_ctx,
			      krb5_context context,
			      krb5_auth_context auth_context,
			      DATA_BLOB *session_key, bool remote)
{
	krb5_keyblock *skey = NULL;
	krb5_error_code err = 0;
	bool ret = false;

	if (remote) {
		err = krb5_auth_con_getremotesubkey(context,
						    auth_context, &skey);
	} else {
		err = krb5_auth_con_getlocalsubkey(context,
						   auth_context, &skey);
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


#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING) && !defined(HAVE_KRB5_PRINC_COMPONENT)
 const krb5_data *krb5_princ_component(krb5_context context, krb5_principal principal, int i );

 const krb5_data *krb5_princ_component(krb5_context context, krb5_principal principal, int i )
{
	static krb5_data kdata;

	kdata.data = discard_const_p(char, krb5_principal_get_comp_string(context, principal, i));
	kdata.length = strlen((const char *)kdata.data);
	return &kdata;
}
#endif

/* Prototypes */

 krb5_error_code smb_krb5_renew_ticket(const char *ccache_string,	/* FILE:/tmp/krb5cc_0 */
				       const char *client_string,	/* gd@BER.SUSE.DE */
				       const char *service_string,	/* krbtgt/BER.SUSE.DE@BER.SUSE.DE */
				       time_t *expire_time)
{
	krb5_error_code ret;
	krb5_context context = NULL;
	krb5_ccache ccache = NULL;
	krb5_principal client = NULL;
	krb5_creds creds, creds_in, *creds_out = NULL;

	ZERO_STRUCT(creds);
	ZERO_STRUCT(creds_in);

	initialize_krb5_error_table();
	ret = krb5_init_context(&context);
	if (ret) {
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

	if (creds_out) {
		krb5_free_creds(context, creds_out);
	} else {
		krb5_free_cred_contents(context, &creds);
	}

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

 krb5_error_code smb_krb5_free_addresses(krb5_context context, smb_krb5_addresses *addr)
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
			SAFE_FREE(kerb_addr);
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

 void smb_krb5_free_error(krb5_context context, krb5_error *krberror)
{
#ifdef HAVE_KRB5_FREE_ERROR_CONTENTS /* Heimdal */
	krb5_free_error_contents(context, krberror);
#else /* MIT */
	krb5_free_error(context, krberror);
#endif
}

 krb5_error_code handle_krberror_packet(krb5_context context,
					krb5_data *packet)
{
	krb5_error_code ret;
	bool got_error_code = false;

	DEBUG(10,("handle_krberror_packet: got error packet\n"));

#ifdef HAVE_E_DATA_POINTER_IN_KRB5_ERROR /* Heimdal */
	{
		krb5_error krberror;

		if ((ret = krb5_rd_error(context, packet, &krberror))) {
			DEBUG(10,("handle_krberror_packet: krb5_rd_error failed with: %s\n", 
				error_message(ret)));
			return ret;
		}

		if (krberror.e_data == NULL || krberror.e_data->data == NULL) {
			ret = (krb5_error_code) krberror.error_code;
			got_error_code = true;
		}

		smb_krb5_free_error(context, &krberror);
	}
#else /* MIT */
	{
		krb5_error *krberror;

		if ((ret = krb5_rd_error(context, packet, &krberror))) {
			DEBUG(10,("handle_krberror_packet: krb5_rd_error failed with: %s\n", 
				error_message(ret)));
			return ret;
		}

		if (krberror->e_data.data == NULL) {
#if defined(ERROR_TABLE_BASE_krb5)
			ret = ERROR_TABLE_BASE_krb5 + (krb5_error_code) krberror->error;
#else
			ret = (krb5_error_code)krberror->error;
#endif
			got_error_code = true;
		}
		smb_krb5_free_error(context, krberror);
	}
#endif
	if (got_error_code) {
		DEBUG(5,("handle_krberror_packet: got KERBERR from kpasswd: %s (%d)\n", 
			error_message(ret), ret));
	}
	return ret;
}

krb5_error_code smb_krb5_get_init_creds_opt_alloc(krb5_context context,
					    krb5_get_init_creds_opt **opt)
{
	/* Heimdal or modern MIT version */
	return krb5_get_init_creds_opt_alloc(context, opt);
}

void smb_krb5_get_init_creds_opt_free(krb5_context context,
				krb5_get_init_creds_opt *opt)
{
	/* Modern MIT or Heimdal version */
	krb5_get_init_creds_opt_free(context, opt);
}

krb5_enctype smb_get_enctype_from_kt_entry(krb5_keytab_entry *kt_entry)
{
	return KRB5_KEY_TYPE(KRB5_KT_KEY(kt_entry));
}

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


/* caller needs to free etype_s */
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

/**********************************************************************
 * Open a krb5 keytab with flags, handles readonly or readwrite access and
 * allows to process non-default keytab names.
 * @param context krb5_context
 * @param keytab_name_req string
 * @param write_access bool if writable keytab is required
 * @param krb5_keytab pointer to krb5_keytab (close with krb5_kt_close())
 * @return krb5_error_code
**********************************************************************/

/* This MAX_NAME_LEN is a constant defined in krb5.h */
#ifndef MAX_KEYTAB_NAME_LEN
#define MAX_KEYTAB_NAME_LEN 1100
#endif

krb5_error_code smb_krb5_open_keytab(krb5_context context,
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

		if ((strncmp(keytab_name_req, "WRFILE:/", 8) == 0) ||
		    (strncmp(keytab_name_req, "FILE:/", 6) == 0)) {
		    	tmp = keytab_name_req;
			goto resolve;
		}

		if (keytab_name_req[0] != '/') {
			ret = KRB5_KT_BADNAME;
			goto out;
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

krb5_error_code smb_krb5_keytab_name(TALLOC_CTX *mem_ctx,
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
static krb5_error_code smb_krb5_get_credentials_for_user(krb5_context context,
							 krb5_ccache ccache,
							 krb5_principal me,
							 krb5_principal server,
							 krb5_principal impersonate_princ,
							 krb5_creds **out_creds)
{
	krb5_error_code ret;
	krb5_creds in_creds;

#if !HAVE_DECL_KRB5_GET_CREDENTIALS_FOR_USER
krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_user(krb5_context context, krb5_flags options,
                              krb5_ccache ccache, krb5_creds *in_creds,
                              krb5_data *subject_cert,
                              krb5_creds **out_creds);
#endif /* !HAVE_DECL_KRB5_GET_CREDENTIALS_FOR_USER */

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

	*out_creds = NULL;

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

/*
  simulate a kinit, putting the tgt in the given credentials cache.
  Orignally by remus@snapserver.com

  This version is built to use a keyblock, rather than needing the
  original password.

  The impersonate_principal is the principal if NULL, or the principal
  to impersonate

  The target_service defaults to the krbtgt if NULL, but could be
   kpasswd/realm or the local service (if we are doing s4u2self)
*/
krb5_error_code kerberos_kinit_keyblock_cc(krb5_context ctx, krb5_ccache cc,
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
#define SMB_CREDS_KEYTAB "MEMORY:tmp_smb_creds_XXXXXX"
	char tmp_name[sizeof(SMB_CREDS_KEYTAB)];
	krb5_keytab_entry entry;
	krb5_keytab keytab;

	memset(&entry, 0, sizeof(entry));
	entry.principal = principal;
	*(KRB5_KT_KEY(&entry)) = *keyblock;

	memcpy(tmp_name, SMB_CREDS_KEYTAB, sizeof(SMB_CREDS_KEYTAB));
	mktemp(tmp_name);
	if (tmp_name[0] == 0) {
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

krb5_error_code kerberos_kinit_password_cc(krb5_context ctx, krb5_ccache cc,
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
/*
  simulate a kinit, putting the tgt in the given credentials cache.
  Orignally by remus@snapserver.com

  The impersonate_principal is the principal

  The self_service, should be the local service (for S4U2Self if
  impersonate_principal is given).

  The target_service defaults to the krbtgt if NULL, but could be
  kpasswd/realm or a remote service (for S4U2Proxy)

*/
krb5_error_code kerberos_kinit_s4u2_cc(krb5_context ctx,
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
		DEBUG(1, ("kerberos_kinit_password_cc: "
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
		DEBUG(1, ("kerberos_kinit_password_cc: "
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
krb5_error_code smb_krb5_make_principal(krb5_context context,
					krb5_principal *principal,
					const char *_realm, ...)
{
	krb5_error_code code;
	bool free_realm;
	char *realm;
	va_list ap;

	if (_realm) {
		realm = _realm;
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


/*
 * smb_krb5_principal_get_realm
 *
 * @brief Get realm of a principal
 *
 * @param[in] context		The krb5_context
 * @param[in] principal		The principal
 * @return pointer to the realm
 *
 */

char *smb_krb5_principal_get_realm(krb5_context context,
				   krb5_principal principal)
{
#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM /* Heimdal */
	return discard_const_p(char, krb5_principal_get_realm(context, principal));
#elif defined(krb5_princ_realm) /* MIT */
	krb5_data *realm;
	realm = krb5_princ_realm(context, principal);
	return discard_const_p(char, realm->data);
#else
	return NULL;
#endif
}

/************************************************************************
 Routine to get the default realm from the kerberos credentials cache.
 Caller must free if the return value is not NULL.
************************************************************************/

static char *smb_krb5_get_default_realm_from_ccache(TALLOC_CTX *mem_ctx)
{
	char *realm = NULL;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;
	krb5_principal princ = NULL;

	initialize_krb5_error_table();
	if (krb5_init_context(&ctx)) {
		return NULL;
	}

	DEBUG(5,("kerberos_get_default_realm_from_ccache: "
		"Trying to read krb5 cache: %s\n",
		krb5_cc_default_name(ctx)));
	if (krb5_cc_default(ctx, &cc)) {
		DEBUG(0,("kerberos_get_default_realm_from_ccache: "
			"failed to read default cache\n"));
		goto out;
	}
	if (krb5_cc_get_principal(ctx, cc, &princ)) {
		DEBUG(0,("kerberos_get_default_realm_from_ccache: "
			"failed to get default principal\n"));
		goto out;
	}

#if defined(HAVE_KRB5_PRINCIPAL_GET_REALM)
	realm = talloc_strdup(mem_ctx, krb5_principal_get_realm(ctx, princ));
#elif defined(HAVE_KRB5_PRINC_REALM)
	{
		krb5_data *realm_data = krb5_princ_realm(ctx, princ);
		realm = talloc_strndup(mem_ctx, realm_data->data, realm_data->length);
	}
#endif

  out:

	if (ctx) {
		if (princ) {
			krb5_free_principal(ctx, princ);
		}
		if (cc) {
			krb5_cc_close(ctx, cc);
		}
		krb5_free_context(ctx);
	}

	return realm;
}

/************************************************************************
 Routine to get the realm from a given DNS name.
************************************************************************/

static char *smb_krb5_get_realm_from_hostname(TALLOC_CTX *mem_ctx,
						const char *hostname)
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

	initialize_krb5_error_table();
	if (krb5_init_context(&ctx)) {
		return NULL;
	}

	kerr = krb5_get_host_realm(ctx, hostname, &realm_list);
	if (kerr != 0) {
		DEBUG(3,("kerberos_get_realm_from_hostname %s: "
			"failed %s\n",
			hostname ? hostname : "(NULL)",
			error_message(kerr) ));
		goto out;
	}

	if (realm_list && realm_list[0]) {
		realm = talloc_strdup(mem_ctx, realm_list[0]);
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

char *kerberos_get_principal_from_service_hostname(TALLOC_CTX *mem_ctx,
						   const char *service,
						   const char *remote_name,
						   const char *default_realm)
{
	char *realm = NULL;
	char *host = NULL;
	char *principal;
	host = strchr_m(remote_name, '.');
	if (host) {
		/* DNS name. */
		realm = smb_krb5_get_realm_from_hostname(talloc_tos(),
							 remote_name);
	} else {
		/* NetBIOS name - use our realm. */
		realm = smb_krb5_get_default_realm_from_ccache(talloc_tos());
	}

	if (realm == NULL || *realm == '\0') {
		realm = talloc_strdup(talloc_tos(), default_realm);
		if (!realm) {
			return NULL;
		}
		DEBUG(3,("kerberos_get_principal_from_service_hostname: "
			 "cannot get realm from, "
			 "desthost %s or default ccache. Using default "
			 "smb.conf realm %s\n",
			 remote_name,
			 realm));
	}

	principal = talloc_asprintf(mem_ctx,
				    "%s/%s@%s",
				    service, remote_name,
				    realm);
	TALLOC_FREE(realm);
	return principal;
}

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

#else /* HAVE_KRB5 */
 /* this saves a few linking headaches */
 int cli_krb5_get_ticket(TALLOC_CTX *mem_ctx,
			const char *principal, time_t time_offset,
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5,
			uint32_t extra_ap_opts,
			const char *ccname, time_t *tgs_expire,
			const char *impersonate_princ_s)
{
	 DEBUG(0,("NO KERBEROS SUPPORT\n"));
	 return 1;
}

#endif /* HAVE_KRB5 */

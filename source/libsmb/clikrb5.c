/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   
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

#ifdef HAVE_KRB5

#ifdef HAVE_KRB5_KEYBLOCK_KEYVALUE
#define KRB5_KEY_TYPE(k)	((k)->keytype)
#define KRB5_KEY_LENGTH(k)	((k)->keyvalue.length)
#define KRB5_KEY_DATA(k)	((k)->keyvalue.data)
#else
#define	KRB5_KEY_TYPE(k)	((k)->enctype)
#define KRB5_KEY_LENGTH(k)	((k)->length)
#define KRB5_KEY_DATA(k)	((k)->contents)
#endif /* HAVE_KRB5_KEYBLOCK_KEYVALUE */

#ifndef HAVE_KRB5_SET_REAL_TIME
/*
 * This function is not in the Heimdal mainline.
 */
 krb5_error_code krb5_set_real_time(krb5_context context, int32_t seconds, int32_t microseconds)
{
	krb5_error_code ret;
	int32_t sec, usec;

	ret = krb5_us_timeofday(context, &sec, &usec);
	if (ret)
		return ret;

	context->kdc_sec_offset = seconds - sec;
	context->kdc_usec_offset = microseconds - usec;

	return 0;
}
#endif

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
 __ERROR__XX__UNKNOWN_ADDRTYPE
#endif

#if defined(HAVE_KRB5_PRINCIPAL2SALT) && defined(HAVE_KRB5_USE_ENCTYPE) && defined(HAVE_KRB5_STRING_TO_KEY)
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
	return krb5_string_to_key_salt(context, enctype, password->data,
		salt, key);
}
#else
 __ERROR_XX_UNKNOWN_CREATE_KEY_FUNCTIONS
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

 void get_auth_data_from_tkt(DATA_BLOB *auth_data, krb5_ticket *tkt)
{
#if defined(HAVE_KRB5_TKT_ENC_PART2)
	if (tkt->enc_part2)
		*auth_data = data_blob(tkt->enc_part2->authorization_data[0]->contents,
			tkt->enc_part2->authorization_data[0]->length);
#else
	if (tkt->ticket.authorization_data && tkt->ticket.authorization_data->len)
		*auth_data = data_blob(tkt->ticket.authorization_data->val->ad_data.data,
			tkt->ticket.authorization_data->val->ad_data.length);
#endif
}

 krb5_const_principal get_principal_from_tkt(krb5_ticket *tkt)
{
#if defined(HAVE_KRB5_TKT_ENC_PART2)
	return tkt->enc_part2->client;
#else
	return tkt->client;
#endif
}

#if !defined(HAVE_KRB5_LOCATE_KDC)
 krb5_error_code krb5_locate_kdc(krb5_context ctx, const krb5_data *realm, struct sockaddr **addr_pp, int *naddrs, int get_masters)
{
	krb5_krbhst_handle hnd;
	krb5_krbhst_info *hinfo;
	krb5_error_code rc;
	int num_kdcs, i;
	struct sockaddr *sa;

	*addr_pp = NULL;
	*naddrs = 0;

	rc = krb5_krbhst_init(ctx, realm->data, KRB5_KRBHST_KDC, &hnd);
	if (rc) {
		DEBUG(0, ("krb5_locate_kdc: krb5_krbhst_init failed (%s)\n", error_message(rc)));
		return rc;
	}

	for ( num_kdcs = 0; (rc = krb5_krbhst_next(ctx, hnd, &hinfo) == 0); num_kdcs++)
		;

	krb5_krbhst_reset(ctx, hnd);

	if (!num_kdcs) {
		DEBUG(0, ("krb5_locate_kdc: zero kdcs found !\n"));
		krb5_krbhst_free(ctx, hnd);
		return -1;
	}

	sa = malloc( sizeof(struct sockaddr) * num_kdcs );
	if (!sa) {
		DEBUG(0, ("krb5_locate_kdc: malloc failed\n"));
		krb5_krbhst_free(ctx, hnd);
		naddrs = 0;
		return -1;
	}

	memset(*addr_pp, '\0', sizeof(struct sockaddr) * num_kdcs );

	for (i = 0; i < num_kdcs && (rc = krb5_krbhst_next(ctx, hnd, &hinfo) == 0); i++) {
		if (hinfo->ai->ai_family == AF_INET)
			memcpy(&sa[i], hinfo->ai->ai_addr, sizeof(struct sockaddr));
	}

	krb5_krbhst_free(ctx, hnd);

	*naddrs = num_kdcs;
	*addr_pp = sa;
	return 0;
}
#endif

static BOOL ads_cleanup_expired_creds(krb5_context context, 
				      krb5_ccache  ccache,
				      krb5_creds  *credsp)
{
	krb5_error_code retval;

	DEBUG(3, ("Ticket in ccache[%s] expiration %s\n",
		  krb5_cc_default_name(context),
		  http_timestring(credsp->times.endtime)));

	/* we will probably need new tickets if the current ones
	   will expire within 10 seconds.
	*/
	if (credsp->times.endtime >= (time(NULL) + 10))
		return False;

	/* heimdal won't remove creds from a file ccache, and 
	   perhaps we shouldn't anyway, since internally we 
	   use memory ccaches, and a FILE one probably means that
	   we're using creds obtained outside of our exectuable
	*/
	if (StrCaseCmp(krb5_cc_get_type(context, ccache), "FILE") == 0) {
		DEBUG(5, ("We do not remove creds from a FILE ccache\n"));
		return False;
	}
	
	retval = krb5_cc_remove_cred(context, ccache, 0, credsp);
	if (retval) {
		DEBUG(1, ("krb5_cc_remove_cred failed, err %s\n",
			  error_message(retval)));
		/* If we have an error in this, we want to display it,
		   but continue as though we deleted it */
	}
	return True;
}

/*
  we can't use krb5_mk_req because w2k wants the service to be in a particular format
*/
static krb5_error_code ads_krb5_mk_req(krb5_context context, 
				       krb5_auth_context *auth_context, 
				       const krb5_flags ap_req_options,
				       const char *principal,
				       krb5_ccache ccache, 
				       krb5_data *outbuf)
{
	krb5_error_code 	  retval;
	krb5_principal	  server;
	krb5_creds 		* credsp;
	krb5_creds 		  creds;
	krb5_data in_data;
	BOOL creds_ready = False;
	
	retval = krb5_parse_name(context, principal, &server);
	if (retval) {
		DEBUG(1,("Failed to parse principal %s\n", principal));
		return retval;
	}
	
	/* obtain ticket & session key */
	ZERO_STRUCT(creds);
	if ((retval = krb5_copy_principal(context, server, &creds.server))) {
		DEBUG(1,("krb5_copy_principal failed (%s)\n", 
			 error_message(retval)));
		goto cleanup_princ;
	}
	
	if ((retval = krb5_cc_get_principal(context, ccache, &creds.client))) {
		DEBUG(1,("krb5_cc_get_principal failed (%s)\n", 
			 error_message(retval)));
		goto cleanup_creds;
	}

	while(!creds_ready) {
		if ((retval = krb5_get_credentials(context, 0, ccache, 
						   &creds, &credsp))) {
			DEBUG(1,("krb5_get_credentials failed for %s (%s)\n",
				 principal, error_message(retval)));
			goto cleanup_creds;
		}

		/* cope with ticket being in the future due to clock skew */
		if ((unsigned)credsp->times.starttime > time(NULL)) {
			time_t t = time(NULL);
			int time_offset =(unsigned)credsp->times.starttime-t;
			DEBUG(4,("Advancing clock by %d seconds to cope with clock skew\n", time_offset));
			krb5_set_real_time(context, t + time_offset + 1, 0);
		}

		if (!ads_cleanup_expired_creds(context, ccache, credsp))
			creds_ready = True;
	}

	DEBUG(10,("Ticket (%s) in ccache (%s) is valid until: (%s - %d)\n",
		  principal, krb5_cc_default_name(context),
		  http_timestring((unsigned)credsp->times.endtime), 
		  (unsigned)credsp->times.endtime));

	in_data.length = 0;
	retval = krb5_mk_req_extended(context, auth_context, ap_req_options, 
				      &in_data, credsp, outbuf);
	if (retval) {
		DEBUG(1,("krb5_mk_req_extended failed (%s)\n", 
			 error_message(retval)));
	}
	
	krb5_free_creds(context, credsp);

cleanup_creds:
	krb5_free_cred_contents(context, &creds);

cleanup_princ:
	krb5_free_principal(context, server);

	return retval;
}

/*
  get a kerberos5 ticket for the given service 
*/
int cli_krb5_get_ticket(const char *principal, time_t time_offset, 
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5)
{
	krb5_error_code retval;
	krb5_data packet;
	krb5_ccache ccdef;
	krb5_context context;
	krb5_auth_context auth_context = NULL;
	krb5_enctype enc_types[] = {
#ifdef ENCTYPE_ARCFOUR_HMAC
		ENCTYPE_ARCFOUR_HMAC,
#endif 
		ENCTYPE_DES_CBC_MD5, 
		ENCTYPE_DES_CBC_CRC, 
		ENCTYPE_NULL};
	
	retval = krb5_init_context(&context);
	if (retval) {
		DEBUG(1,("krb5_init_context failed (%s)\n", 
			 error_message(retval)));
		goto failed;
	}

	if (time_offset != 0) {
		krb5_set_real_time(context, time(NULL) + time_offset, 0);
	}

	if ((retval = krb5_cc_default(context, &ccdef))) {
		DEBUG(1,("krb5_cc_default failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if ((retval = krb5_set_default_tgs_ktypes(context, enc_types))) {
		DEBUG(1,("krb5_set_default_tgs_ktypes failed (%s)\n",
			 error_message(retval)));
		goto failed;
	}

	if ((retval = ads_krb5_mk_req(context, 
					&auth_context, 
					AP_OPTS_USE_SUBKEY, 
					principal,
					ccdef, &packet))) {
		goto failed;
	}

	get_krb5_smb_session_key(context, auth_context, session_key_krb5, False);

	*ticket = data_blob(packet.data, packet.length);

/* Hmm, heimdal dooesn't have this - what's the correct call? */
#ifdef HAVE_KRB5_FREE_DATA_CONTENTS
 	krb5_free_data_contents(context, &packet); 
#endif

failed:
	if ( context )
		krb5_free_context(context);
		
	return retval;
}

 BOOL get_krb5_smb_session_key(krb5_context context, krb5_auth_context auth_context, DATA_BLOB *session_key, BOOL remote)
 {
	krb5_keyblock *skey;
	krb5_error_code err;
	BOOL ret = False;

	memset(session_key, 0, 16);

	if (remote)
		err = krb5_auth_con_getremotesubkey(context, auth_context, &skey);
	else
		err = krb5_auth_con_getlocalsubkey(context, auth_context, &skey);
	if (err == 0 && skey != NULL) {
		DEBUG(10, ("Got KRB5 session key of length %d\n",  KRB5_KEY_LENGTH(skey)));
		*session_key = data_blob(KRB5_KEY_DATA(skey), KRB5_KEY_LENGTH(skey));
		dump_data_pw("KRB5 Session Key:\n", session_key->data, session_key->length);

		ret = True;

		krb5_free_keyblock(context, skey);
	} else {
		DEBUG(10, ("KRB5 error getting session key %d\n", err));
	}

	return ret;
 }


#if defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING) && !defined(HAVE_KRB5_PRINC_COMPONENT)
 const krb5_data *krb5_princ_component(krb5_context context, krb5_principal principal, int i )
{
	static krb5_data kdata;

	kdata.data = krb5_principal_get_comp_string(context, principal, i);
	kdata.length = strlen(kdata.data);
	return &kdata;
}
#endif

#else /* HAVE_KRB5 */
 /* this saves a few linking headaches */
int cli_krb5_get_ticket(const char *principal, time_t time_offset, 
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5) 
{
	 DEBUG(0,("NO KERBEROS SUPPORT\n"));
	 return 1;
}

#endif

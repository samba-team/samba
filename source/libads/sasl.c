/* 
   Unix SMB/CIFS implementation.
   ads sasl code
   Copyright (C) Andrew Tridgell 2001
   
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

#ifdef HAVE_LDAP

/* 
   perform a LDAP/SASL/SPNEGO/NTLMSSP bind (just how many layers can
   we fit on one socket??)
*/
static ADS_STATUS ads_sasl_spnego_ntlmssp_bind(ADS_STRUCT *ads)
{
	const char *mechs[] = {OID_NTLMSSP, NULL};
	DATA_BLOB msg1;
	DATA_BLOB blob, chal1, chal2, auth;
	uint8 challenge[8];
	uint8 nthash[24], lmhash[24], sess_key[16];
	uint32 neg_flags;
	struct berval cred, *scred;
	ADS_STATUS status;
	int rc;

	if (!ads->auth.password) {
		/* No password, don't segfault below... */
		return ADS_ERROR_NT(NT_STATUS_LOGON_FAILURE);
	}

	neg_flags = NTLMSSP_NEGOTIATE_UNICODE | 
		NTLMSSP_NEGOTIATE_128 | 
		NTLMSSP_NEGOTIATE_NTLM;

	memset(sess_key, 0, 16);

	/* generate the ntlmssp negotiate packet */
	msrpc_gen(&blob, "CddB",
		  "NTLMSSP",
		  NTLMSSP_NEGOTIATE,
		  neg_flags,
		  sess_key, 16);

	/* and wrap it in a SPNEGO wrapper */
	msg1 = gen_negTokenTarg(mechs, blob);
	data_blob_free(&blob);

	cred.bv_val = (char *)msg1.data;
	cred.bv_len = msg1.length;

	rc = ldap_sasl_bind_s(ads->ld, NULL, "GSS-SPNEGO", &cred, NULL, NULL, &scred);
	if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
		status = ADS_ERROR(rc);
		goto failed;
	}

	blob = data_blob(scred->bv_val, scred->bv_len);

	/* the server gives us back two challenges */
	if (!spnego_parse_challenge(blob, &chal1, &chal2)) {
		DEBUG(3,("Failed to parse challenges\n"));
		status = ADS_ERROR(LDAP_OPERATIONS_ERROR);
		goto failed;
	}

	data_blob_free(&blob);

	/* encrypt the password with the challenge */
	memcpy(challenge, chal1.data + 24, 8);
	SMBencrypt(ads->auth.password, challenge,lmhash);
	SMBNTencrypt(ads->auth.password, challenge,nthash);

	data_blob_free(&chal1);
	data_blob_free(&chal2);

	/* this generates the actual auth packet */
	msrpc_gen(&blob, "CdBBUUUBd", 
		  "NTLMSSP", 
		  NTLMSSP_AUTH, 
		  lmhash, 24,
		  nthash, 24,
		  lp_workgroup(), 
		  ads->auth.user_name, 
		  global_myname(),
		  sess_key, 16,
		  neg_flags);

	/* wrap it in SPNEGO */
	auth = spnego_gen_auth(blob);

	data_blob_free(&blob);

	/* now send the auth packet and we should be done */
	cred.bv_val = (char *)auth.data;
	cred.bv_len = auth.length;

	rc = ldap_sasl_bind_s(ads->ld, NULL, "GSS-SPNEGO", &cred, NULL, NULL, &scred);

	return ADS_ERROR(rc);

failed:
	return status;
}

/* 
   perform a LDAP/SASL/SPNEGO/KRB5 bind
*/
static ADS_STATUS ads_sasl_spnego_krb5_bind(ADS_STRUCT *ads, const char *principal)
{
	DATA_BLOB blob;
	struct berval cred, *scred;
	DATA_BLOB session_key;
	int rc;

	rc = spnego_gen_negTokenTarg(principal, ads->auth.time_offset, &blob, &session_key);

	if (rc) {
		return ADS_ERROR_KRB5(rc);
	}

	/* now send the auth packet and we should be done */
	cred.bv_val = (char *)blob.data;
	cred.bv_len = blob.length;

	rc = ldap_sasl_bind_s(ads->ld, NULL, "GSS-SPNEGO", &cred, NULL, NULL, &scred);

	data_blob_free(&blob);
	data_blob_free(&session_key);

	return ADS_ERROR(rc);
}

/* 
   this performs a SASL/SPNEGO bind
*/
static ADS_STATUS ads_sasl_spnego_bind(ADS_STRUCT *ads)
{
	struct berval *scred=NULL;
	int rc, i;
	ADS_STATUS status;
	DATA_BLOB blob;
	char *principal;
	char *OIDs[ASN1_MAX_OIDS];
	BOOL got_kerberos_mechanism = False;

	rc = ldap_sasl_bind_s(ads->ld, NULL, "GSS-SPNEGO", NULL, NULL, NULL, &scred);

	if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
		status = ADS_ERROR(rc);
		goto failed;
	}

	blob = data_blob(scred->bv_val, scred->bv_len);

	ber_bvfree(scred);

#if 0
	file_save("sasl_spnego.dat", blob.data, blob.length);
#endif

	/* the server sent us the first part of the SPNEGO exchange in the negprot 
	   reply */
	if (!spnego_parse_negTokenInit(blob, OIDs, &principal)) {
		data_blob_free(&blob);
		status = ADS_ERROR(LDAP_OPERATIONS_ERROR);
		goto failed;
	}
	data_blob_free(&blob);

	/* make sure the server understands kerberos */
	for (i=0;OIDs[i];i++) {
		DEBUG(3,("got OID=%s\n", OIDs[i]));
		if (strcmp(OIDs[i], OID_KERBEROS5_OLD) == 0 ||
		    strcmp(OIDs[i], OID_KERBEROS5) == 0) {
			got_kerberos_mechanism = True;
		}
		free(OIDs[i]);
	}
	DEBUG(3,("got principal=%s\n", principal));

#ifdef HAVE_KRB5
	if (!(ads->auth.flags & ADS_AUTH_DISABLE_KERBEROS) &&
	    got_kerberos_mechanism) {
		status = ads_sasl_spnego_krb5_bind(ads, principal);
		if (ADS_ERR_OK(status))
			return status;

		status = ADS_ERROR_KRB5(ads_kinit_password(ads)); 

		if (ADS_ERR_OK(status)) {
			status = ads_sasl_spnego_krb5_bind(ads, principal);
		}

		/* only fallback to NTLMSSP if allowed */
		if (ADS_ERR_OK(status) || 
		    !(ads->auth.flags & ADS_AUTH_ALLOW_NTLMSSP)) {
			return status;
		}
	}
#endif

	/* lets do NTLMSSP ... this has the big advantage that we don't need
	   to sync clocks, and we don't rely on special versions of the krb5 
	   library for HMAC_MD4 encryption */
	return ads_sasl_spnego_ntlmssp_bind(ads);

failed:
	return status;
}

#ifdef HAVE_GSSAPI
#define MAX_GSS_PASSES 3

/* this performs a SASL/gssapi bind
   we avoid using cyrus-sasl to make Samba more robust. cyrus-sasl
   is very dependent on correctly configured DNS whereas
   this routine is much less fragile
   see RFC2078 and RFC2222 for details
*/
static ADS_STATUS ads_sasl_gssapi_bind(ADS_STRUCT *ads)
{
	uint32 minor_status;
	gss_name_t serv_name;
	gss_buffer_desc input_name;
	gss_ctx_id_t context_handle;
	gss_OID mech_type = GSS_C_NULL_OID;
	gss_buffer_desc output_token, input_token;
	uint32 ret_flags, conf_state;
	struct berval cred;
	struct berval *scred;
	int i=0;
	int gss_rc, rc;
	uint8 *p;
	uint32 max_msg_size;
	char *sname;
	unsigned sec_layer;
	ADS_STATUS status;
	krb5_principal principal;
	krb5_context ctx;
	krb5_enctype enc_types[] = {
#ifdef ENCTYPE_ARCFOUR_HMAC
			ENCTYPE_ARCFOUR_HMAC,
#endif
			ENCTYPE_DES_CBC_MD5,
			ENCTYPE_NULL};
	gss_OID_desc nt_principal = 
	{10, "\052\206\110\206\367\022\001\002\002\002"};

	/* we need to fetch a service ticket as the ldap user in the
	   servers realm, regardless of our realm */
	asprintf(&sname, "ldap/%s@%s", ads->config.ldap_server_name, ads->config.realm);
	krb5_init_context(&ctx);
	krb5_set_default_tgs_ktypes(ctx, enc_types);
	krb5_parse_name(ctx, sname, &principal);
	free(sname);
	krb5_free_context(ctx);	

	input_name.value = &principal;
	input_name.length = sizeof(principal);

	gss_rc = gss_import_name(&minor_status,&input_name,&nt_principal, &serv_name);
	if (gss_rc) {
		return ADS_ERROR_GSS(gss_rc, minor_status);
	}

	context_handle = GSS_C_NO_CONTEXT;

	input_token.value = NULL;
	input_token.length = 0;

	for (i=0; i < MAX_GSS_PASSES; i++) {
		gss_rc = gss_init_sec_context(&minor_status,
					  GSS_C_NO_CREDENTIAL,
					  &context_handle,
					  serv_name,
					  mech_type,
					  GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
					  0,
					  NULL,
					  &input_token,
					  NULL,
					  &output_token,
					  &ret_flags,
					  NULL);

		if (input_token.value) {
			gss_release_buffer(&minor_status, &input_token);
		}

		if (gss_rc && gss_rc != GSS_S_CONTINUE_NEEDED) {
			status = ADS_ERROR_GSS(gss_rc, minor_status);
			goto failed;
		}

		cred.bv_val = output_token.value;
		cred.bv_len = output_token.length;

		rc = ldap_sasl_bind_s(ads->ld, NULL, "GSSAPI", &cred, NULL, NULL, 
				      &scred);
		if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
			status = ADS_ERROR(rc);
			goto failed;
		}

		if (output_token.value) {
			gss_release_buffer(&minor_status, &output_token);
		}

		if (scred) {
			input_token.value = scred->bv_val;
			input_token.length = scred->bv_len;
		} else {
			input_token.value = NULL;
			input_token.length = 0;
		}

		if (gss_rc == 0) break;
	}

	gss_release_name(&minor_status, &serv_name);

	gss_rc = gss_unwrap(&minor_status,context_handle,&input_token,&output_token,
			    (int *)&conf_state,NULL);
	if (gss_rc) {
		status = ADS_ERROR_GSS(gss_rc, minor_status);
		goto failed;
	}

	gss_release_buffer(&minor_status, &input_token);

	p = (uint8 *)output_token.value;

	file_save("sasl_gssapi.dat", output_token.value, output_token.length);

	max_msg_size = (p[1]<<16) | (p[2]<<8) | p[3];
	sec_layer = *p;

	gss_release_buffer(&minor_status, &output_token);

	output_token.value = malloc(strlen(ads->config.bind_path) + 8);
	p = output_token.value;

	*p++ = 1; /* no sign & seal selection */
	/* choose the same size as the server gave us */
	*p++ = max_msg_size>>16;
	*p++ = max_msg_size>>8;
	*p++ = max_msg_size;
	snprintf((char *)p, strlen(ads->config.bind_path)+4, "dn:%s", ads->config.bind_path);
	p += strlen((const char *)p);

	output_token.length = PTR_DIFF(p, output_token.value);

	gss_rc = gss_wrap(&minor_status, context_handle,0,GSS_C_QOP_DEFAULT,
			  &output_token, (int *)&conf_state,
			  &input_token);
	if (gss_rc) {
		status = ADS_ERROR_GSS(gss_rc, minor_status);
		goto failed;
	}

	free(output_token.value);

	cred.bv_val = input_token.value;
	cred.bv_len = input_token.length;

	rc = ldap_sasl_bind_s(ads->ld, NULL, "GSSAPI", &cred, NULL, NULL, 
			      &scred);
	status = ADS_ERROR(rc);

	gss_release_buffer(&minor_status, &input_token);

failed:
	return status;
}
#endif

/* mapping between SASL mechanisms and functions */
static struct {
	const char *name;
	ADS_STATUS (*fn)(ADS_STRUCT *);
} sasl_mechanisms[] = {
	{"GSS-SPNEGO", ads_sasl_spnego_bind},
#ifdef HAVE_GSSAPI
	{"GSSAPI", ads_sasl_gssapi_bind}, /* doesn't work with .NET RC1. No idea why */
#endif
	{NULL, NULL}
};

ADS_STATUS ads_sasl_bind(ADS_STRUCT *ads)
{
	const char *attrs[] = {"supportedSASLMechanisms", NULL};
	char **values;
	ADS_STATUS status;
	int i, j;
	void *res;

	/* get a list of supported SASL mechanisms */
	status = ads_do_search(ads, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, &res);
	if (!ADS_ERR_OK(status)) return status;

	values = ldap_get_values(ads->ld, res, "supportedSASLMechanisms");

	/* try our supported mechanisms in order */
	for (i=0;sasl_mechanisms[i].name;i++) {
		/* see if the server supports it */
		for (j=0;values && values[j];j++) {
			if (strcmp(values[j], sasl_mechanisms[i].name) == 0) {
				DEBUG(4,("Found SASL mechanism %s\n", values[j]));
				status = sasl_mechanisms[i].fn(ads);
				ldap_value_free(values);
				ldap_msgfree(res);
				return status;
			}
		}
	}

	ldap_value_free(values);
	ldap_msgfree(res);
	return ADS_ERROR(LDAP_AUTH_METHOD_NOT_SUPPORTED);
}

#endif


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

#ifdef HAVE_ADS

#if USE_CYRUS_SASL
/*
  this is a minimal interact function, just enough for SASL to talk
  GSSAPI/kerberos to W2K
  Error handling is a bit of a problem. I can't see how to get Cyrus-sasl
  to give sensible errors
*/
static int sasl_interact(LDAP *ld,unsigned flags,void *defaults,void *in)
{
	sasl_interact_t *interact = in;

	while (interact->id != SASL_CB_LIST_END) {
		interact->result = strdup("");
		interact->len = strlen(interact->result);
		interact++;
	}
	
	return LDAP_SUCCESS;
}
#endif


#define MAX_GSS_PASSES 3

/* this performs a SASL/gssapi bind
   we avoid using cyrus-sasl to make Samba more robust. cyrus-sasl
   is very dependent on correctly configured DNS whereas
   this routine is much less fragile
   see RFC2078 for details
*/
ADS_STATUS ads_sasl_gssapi_bind(ADS_STRUCT *ads)
{
	int minor_status;
	gss_name_t serv_name;
	gss_buffer_desc input_name;
	gss_ctx_id_t context_handle;
	gss_OID mech_type = GSS_C_NULL_OID;
	gss_buffer_desc output_token, input_token;
	OM_uint32 ret_flags, conf_state;
	struct berval cred;
	struct berval *scred;
	int i=0;
	int gss_rc, rc;
	uint8 *p;
	uint32 max_msg_size;
	char *sname;
	ADS_STATUS status;
	krb5_principal principal;
	krb5_context ctx;
	krb5_enctype enc_types[] = {ENCTYPE_DES_CBC_MD5, ENCTYPE_NULL};
	gss_OID_desc nt_principal = 
	{10, "\052\206\110\206\367\022\001\002\002\002"};

	/* we need to fetch a service ticket as the ldap user in the
	   servers realm, regardless of our realm */
	asprintf(&sname, "ldap/%s@%s", ads->ldap_server_name, ads->server_realm);
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
			    &conf_state,NULL);
	if (gss_rc) {
		status = ADS_ERROR_GSS(gss_rc, minor_status);
		goto failed;
	}

	gss_release_buffer(&minor_status, &input_token);

	p = (uint8 *)output_token.value;

	max_msg_size = (p[1]<<16) | (p[2]<<8) | p[3];

	gss_release_buffer(&minor_status, &output_token);

	output_token.value = malloc(strlen(ads->bind_path) + 8);
	p = output_token.value;

	*p++ = 1; /* no sign or seal */
	/* choose the same size as the server gave us */
	*p++ = max_msg_size>>16;
	*p++ = max_msg_size>>8;
	*p++ = max_msg_size;
	snprintf(p, strlen(ads->bind_path)+1, "dn:%s", ads->bind_path);
	p += strlen(ads->bind_path);

	output_token.length = strlen(ads->bind_path) + 8;

	gss_rc = gss_wrap(&minor_status, context_handle,0,GSS_C_QOP_DEFAULT,
			  &output_token, &conf_state,
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

ADS_STATUS ads_sasl_bind(ADS_STRUCT *ads)
{
#if USE_CYRUS_SASL
	int rc;
	rc = ldap_sasl_interactive_bind_s(ads->ld, NULL, NULL, NULL, NULL, 
					  LDAP_SASL_QUIET,
					  sasl_interact, NULL);
	return ADS_ERROR(rc);
#else
	return ads_sasl_gssapi_bind(ads);
#endif
}

#endif


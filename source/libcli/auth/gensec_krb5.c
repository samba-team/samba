/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

enum GENSEC_KRB5_STATE {
	GENSEC_KRB5_SERVER_START,
	GENSEC_KRB5_CLIENT_START,
	GENSEC_KRB5_CLIENT_MUTUAL_AUTH,
	GENSEC_KRB5_DONE
};

struct gensec_krb5_state {
	DATA_BLOB session_key;
	struct PAC_LOGON_INFO *logon_info;
	enum GENSEC_KRB5_STATE state_position;
	krb5_context krb5_context;
	krb5_auth_context krb5_auth_context;
	krb5_ccache krb5_ccache;
	krb5_data ticket;
	krb5_keyblock krb5_keyblock;
	char *peer_principal;
};

#ifdef KRB5_DO_VERIFY_PAC
static NTSTATUS gensec_krb5_pac_checksum(DATA_BLOB pac_data,
					    struct PAC_SIGNATURE_DATA *sig,
					    struct gensec_krb5_state *gensec_krb5_state,
					    uint32 keyusage)
{
	krb5_error_code ret;
	krb5_crypto crypto;
	Checksum cksum;
	int i;

	cksum.cksumtype		= (CKSUMTYPE)sig->type;
	cksum.checksum.length	= sizeof(sig->signature);
	cksum.checksum.data	= sig->signature;


	ret = krb5_crypto_init(gensec_krb5_state->krb5_context,
				&gensec_krb5_state->krb5_keyblock,
				0,
				&crypto);
	if (ret) {
		DEBUG(0,("krb5_crypto_init() failed\n"));
		return NT_STATUS_FOOBAR;
	}
	for (i=0; i < 40; i++) {
		keyusage = i;
		ret = krb5_verify_checksum(gensec_krb5_state->krb5_context,
					   crypto,
					   keyusage,
					   pac_data.data,
					   pac_data.length,
					   &cksum);
		if (!ret) {
			DEBUG(0,("PAC Verified: keyusage: %d\n", keyusage));
			break;
		}
	}
	krb5_crypto_destroy(gensec_krb5_state->krb5_context, crypto);

	if (ret) {
		DEBUG(0,("NOT verifying PAC checksums yet!\n"));
		//return NT_STATUS_LOGON_FAILURE;
	} else {
		DEBUG(0,("PAC checksums verified!\n"));
	}

	return NT_STATUS_OK;
}
#endif

static NTSTATUS gensec_krb5_decode_pac(TALLOC_CTX *mem_ctx,
				struct PAC_LOGON_INFO **logon_info_out,
				DATA_BLOB blob,
				struct gensec_krb5_state *gensec_krb5_state)
{
	NTSTATUS status;
	struct PAC_SIGNATURE_DATA srv_sig;
	struct PAC_SIGNATURE_DATA *srv_sig_ptr;
	struct PAC_SIGNATURE_DATA kdc_sig;
	struct PAC_SIGNATURE_DATA *kdc_sig_ptr;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct PAC_DATA pac_data;
#ifdef KRB5_DO_VERIFY_PAC
	DATA_BLOB tmp_blob = data_blob(NULL, 0);
#endif
	int i;

	status = ndr_pull_struct_blob(&blob, mem_ctx, &pac_data,
					(ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("can't parse the PAC\n"));
		return status;
	}
	NDR_PRINT_DEBUG(PAC_DATA, &pac_data);

	if (pac_data.num_buffers < 3) {
		/* we need logon_ingo, service_key and kdc_key */
		DEBUG(0,("less than 3 PAC buffers\n"));
		return NT_STATUS_FOOBAR;
	}

	for (i=0; i < pac_data.num_buffers; i++) {
		switch (pac_data.buffers[i].type) {
			case PAC_TYPE_LOGON_INFO:
				if (!pac_data.buffers[i].info) {
					break;
				}
				logon_info = &pac_data.buffers[i].info->logon_info;
				break;
			case PAC_TYPE_SRV_CHECKSUM:
				if (!pac_data.buffers[i].info) {
					break;
				}
				srv_sig_ptr = &pac_data.buffers[i].info->srv_cksum;
				srv_sig = pac_data.buffers[i].info->srv_cksum;
				break;
			case PAC_TYPE_KDC_CHECKSUM:
				if (!pac_data.buffers[i].info) {
					break;
				}
				kdc_sig_ptr = &pac_data.buffers[i].info->kdc_cksum;
				kdc_sig = pac_data.buffers[i].info->kdc_cksum;
				break;
			case PAC_TYPE_UNKNOWN_10:
				break;
			default:
				break;
		}
	}

	if (!logon_info) {
		DEBUG(0,("PAC no logon_info\n"));
		return NT_STATUS_FOOBAR;
	}

	if (!srv_sig_ptr) {
		DEBUG(0,("PAC no srv_key\n"));
		return NT_STATUS_FOOBAR;
	}

	if (!kdc_sig_ptr) {
		DEBUG(0,("PAC no kdc_key\n"));
		return NT_STATUS_FOOBAR;
	}
#ifdef KRB5_DO_VERIFY_PAC
	/* clear the kdc_key */
/*	memset((void *)kdc_sig_ptr , '\0', sizeof(*kdc_sig_ptr));*/

	status = ndr_push_struct_blob(&tmp_blob, mem_ctx, &pac_data,
					      (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = ndr_pull_struct_blob(&tmp_blob, mem_ctx, &pac_data,
					(ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("can't parse the PAC\n"));
		return status;
	}
	/*NDR_PRINT_DEBUG(PAC_DATA, &pac_data);*/

	/* verify by kdc_key */
	status = gensec_krb5_pac_checksum(tmp_blob, &kdc_sig, gensec_krb5_state, 0);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* clear the service_key */
/*	memset((void *)srv_sig_ptr , '\0', sizeof(*srv_sig_ptr));*/

	status = ndr_push_struct_blob(&tmp_blob, mem_ctx, &pac_data,
					      (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = ndr_pull_struct_blob(&tmp_blob, mem_ctx, &pac_data,
					(ndr_pull_flags_fn_t)ndr_pull_PAC_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("can't parse the PAC\n"));
		return status;
	}
	NDR_PRINT_DEBUG(PAC_DATA, &pac_data);

	/* verify by servie_key */
	status = gensec_krb5_pac_checksum(tmp_blob, &srv_sig, gensec_krb5_state, 0);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
#endif
	DEBUG(0,("account_name: %s [%s]\n",logon_info->account_name.string, logon_info->full_name.string));
	*logon_info_out = logon_info;

	return status;
}

static void gensec_krb5_end(struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state = gensec_security->private_data;

	if (gensec_krb5_state->ticket.length) { 
	/* Hmm, early heimdal dooesn't have this - correct call would be krb5_data_free */
#ifdef HAVE_KRB5_FREE_DATA_CONTENTS
		krb5_free_data_contents(gensec_krb5_state->krb5_context, &gensec_krb5_state->ticket); 
#endif
	}
	if (gensec_krb5_state->krb5_ccache) {
		/* current heimdal - 0.6.3, which we need anyway, fixes segfaults here */
		krb5_cc_close(gensec_krb5_state->krb5_context, gensec_krb5_state->krb5_ccache);
	}

	krb5_free_keyblock_contents(gensec_krb5_state->krb5_context, 
				    &gensec_krb5_state->krb5_keyblock);
		
	if (gensec_krb5_state->krb5_auth_context) {
		krb5_auth_con_free(gensec_krb5_state->krb5_context, 
				   gensec_krb5_state->krb5_auth_context);
	}

	if (gensec_krb5_state->krb5_context) {
		krb5_free_context(gensec_krb5_state->krb5_context);
	}

	talloc_free(gensec_krb5_state);
	gensec_security->private_data = NULL;
}


static NTSTATUS gensec_krb5_start(struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state;
	krb5_error_code ret = 0;

	gensec_krb5_state = talloc_p(gensec_security, struct gensec_krb5_state);
	if (!gensec_krb5_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_krb5_state;

	initialize_krb5_error_table();
	gensec_krb5_state->krb5_context = NULL;
	gensec_krb5_state->krb5_auth_context = NULL;
	gensec_krb5_state->krb5_ccache = NULL;
	ZERO_STRUCT(gensec_krb5_state->ticket);
	ZERO_STRUCT(gensec_krb5_state->krb5_keyblock);
	gensec_krb5_state->session_key = data_blob(NULL, 0);

	ret = krb5_init_context(&gensec_krb5_state->krb5_context);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_init_context failed (%s)\n", error_message(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (lp_realm() && *lp_realm()) {
		ret = krb5_set_default_realm(gensec_krb5_state->krb5_context, lp_realm());
		if (ret) {
			DEBUG(1,("gensec_krb5_start: krb5_set_default_realm failed (%s)\n", error_message(ret)));
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ret = krb5_auth_con_init(gensec_krb5_state->krb5_context, &gensec_krb5_state->krb5_auth_context);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_auth_con_init failed (%s)\n", error_message(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct gensec_krb5_state *gensec_krb5_state;

	nt_status = gensec_krb5_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_krb5_state = gensec_security->private_data;
	gensec_krb5_state->state_position = GENSEC_KRB5_SERVER_START;

	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_client_start(struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state;
	krb5_error_code ret;
	NTSTATUS nt_status;

	nt_status = gensec_krb5_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_krb5_state = gensec_security->private_data;
	gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_START;

	/* TODO: This is effecivly a static/global variable... */ 
	ret = krb5_cc_default(gensec_krb5_state->krb5_context, &gensec_krb5_state->krb5_ccache);
	if (ret) {
		DEBUG(1,("krb5_cc_default failed (%s)\n",
			 error_message(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}
	
	while (1) {
		if (gensec_security->target.principal) {
			DEBUG(5, ("Finding ticket for target [%s]\n", gensec_security->target.principal));
			ret = ads_krb5_mk_req(gensec_krb5_state->krb5_context, 
					      &gensec_krb5_state->krb5_auth_context,
					      AP_OPTS_USE_SUBKEY | AP_OPTS_MUTUAL_REQUIRED,
					      gensec_security->target.principal,
					      gensec_krb5_state->krb5_ccache, 
					      &gensec_krb5_state->ticket);
			if (ret) {
				DEBUG(1,("ads_krb5_mk_req failed (%s)\n", 
					 error_message(ret)));
			}
		} else {
			krb5_data in_data;
			const char *hostname = gensec_get_target_hostname(gensec_security);
			if (!hostname) {
				DEBUG(1, ("Could not determine hostname for target computer, cannot use kerberos\n"));
				return NT_STATUS_ACCESS_DENIED;
			}
			
			in_data.length = 0;

			ret = krb5_mk_req(gensec_krb5_state->krb5_context, 
					  &gensec_krb5_state->krb5_auth_context,
					  AP_OPTS_USE_SUBKEY | AP_OPTS_MUTUAL_REQUIRED,
					  gensec_get_target_service(gensec_security),
					  hostname,
					  &in_data, gensec_krb5_state->krb5_ccache, 
					  &gensec_krb5_state->ticket);
			if (ret) {
				DEBUG(1,("krb5_mk_req failed (%s)\n", 
					 error_message(ret)));
			}
			
		}
		switch (ret) {
		case 0:
			return NT_STATUS_OK;
		case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
			DEBUG(3, ("Server is not registered with our KDC: %s\n", 
				  error_message(ret)));
			return NT_STATUS_ACCESS_DENIED;
		case KRB5KDC_ERR_PREAUTH_FAILED:
		case KRB5KRB_AP_ERR_TKT_EXPIRED:
		case KRB5_CC_END:
		{
			DEBUG(3, ("kerberos: %s\n", 
				  error_message(ret)));
			/* fall down to remaining code */
		}
		/* just don't print a message for these really ordinary messages */
		case KRB5_FCC_NOFILE:
		case KRB5_CC_NOTFOUND:
		{
			char *password;
			time_t kdc_time = 0;
			nt_status = gensec_get_password(gensec_security, 
							gensec_security, 
							&password);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return nt_status;
			}

			ret = kerberos_kinit_password_cc(gensec_krb5_state->krb5_context, gensec_krb5_state->krb5_ccache, 
							 gensec_get_client_principal(gensec_security, gensec_security), 
							 password, NULL, &kdc_time);

			/* cope with ticket being in the future due to clock skew */
			if ((unsigned)kdc_time > time(NULL)) {
				time_t t = time(NULL);
				int time_offset =(unsigned)kdc_time-t;
				DEBUG(4,("Advancing clock by %d seconds to cope with clock skew\n", time_offset));
				krb5_set_real_time(gensec_krb5_state->krb5_context, t + time_offset + 1, 0);
			}
	
			if (ret) {
				DEBUG(1,("kinit failed (%s)\n", 
					 error_message(ret)));
				return NT_STATUS_WRONG_PASSWORD;
			}
			break;
		}
		default:
			DEBUG(0, ("kerberos: %s\n", 
				  error_message(ret)));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
}


/**
 * Next state function for the Krb5 GENSEC mechanism
 * 
 * @param gensec_krb5_state KRB5 State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

static NTSTATUS gensec_krb5_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
				      const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_krb5_state *gensec_krb5_state = gensec_security->private_data;
	krb5_error_code ret = 0;
	DATA_BLOB pac;
	NTSTATUS nt_status;

	switch (gensec_krb5_state->state_position) {
	case GENSEC_KRB5_CLIENT_START:
	{
		if (ret) {
			DEBUG(1,("ads_krb5_mk_req (request ticket) failed (%s)\n",
				 error_message(ret)));
			nt_status = NT_STATUS_LOGON_FAILURE;
		} else {
			DATA_BLOB unwrapped_out;

#ifndef GENSEC_SEND_UNWRAPPED_KRB5 /* This should be a switch for the torture code to set */
			unwrapped_out = data_blob_talloc(out_mem_ctx, gensec_krb5_state->ticket.data, gensec_krb5_state->ticket.length);
			
			/* wrap that up in a nice GSS-API wrapping */
			*out = gensec_gssapi_gen_krb5_wrap(out_mem_ctx, &unwrapped_out, TOK_ID_KRB_AP_REQ);
#else
			*out = data_blob_talloc(out_mem_ctx, gensec_krb5_state->ticket.data, gensec_krb5_state->ticket.length);
#endif
			gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_MUTUAL_AUTH;
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		}
		
		return nt_status;
	}
		
	case GENSEC_KRB5_CLIENT_MUTUAL_AUTH:
	{
		krb5_data inbuf;
		krb5_ap_rep_enc_part *repl = NULL;
		uint8 tok_id[2];
		DATA_BLOB unwrapped_in;

		if (!gensec_gssapi_parse_krb5_wrap(out_mem_ctx, &in, &unwrapped_in, tok_id)) {
			DEBUG(1,("gensec_gssapi_parse_krb5_wrap(mutual authentication) failed to parse\n"));
			dump_data_pw("Mutual authentication message:\n", in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
		/* TODO: check the tok_id */

		inbuf.data = unwrapped_in.data;
		inbuf.length = unwrapped_in.length;
		ret = krb5_rd_rep(gensec_krb5_state->krb5_context, 
				  gensec_krb5_state->krb5_auth_context,
				  &inbuf, &repl);
		if (ret) {
			DEBUG(1,("krb5_rd_rep (mutual authentication) failed (%s)\n",
				 error_message(ret)));
			dump_data_pw("Mutual authentication message:\n", inbuf.data, inbuf.length);
			nt_status = NT_STATUS_ACCESS_DENIED;
		} else {
			*out = data_blob(NULL, 0);
			nt_status = NT_STATUS_OK;
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
		}
		if (repl) {
			krb5_free_ap_rep_enc_part(gensec_krb5_state->krb5_context, repl);
		}
		return nt_status;
	}

	case GENSEC_KRB5_SERVER_START:
	{
		char *principal;
		DATA_BLOB unwrapped_in;
		DATA_BLOB unwrapped_out;
		uint8 tok_id[2];

		/* Parse the GSSAPI wrapping, if it's there... (win2k3 allows it to be omited) */
		if (!gensec_gssapi_parse_krb5_wrap(out_mem_ctx, &in, &unwrapped_in, tok_id)) {
			nt_status = ads_verify_ticket(out_mem_ctx, 
						      gensec_krb5_state->krb5_context, 
						      gensec_krb5_state->krb5_auth_context, 
						      lp_realm(), &in, 
						      &principal, &pac, &unwrapped_out,
						      &gensec_krb5_state->krb5_keyblock);
		} else {
			/* TODO: check the tok_id */
			nt_status = ads_verify_ticket(out_mem_ctx, 
						      gensec_krb5_state->krb5_context, 
						      gensec_krb5_state->krb5_auth_context, 
						      lp_realm(), &unwrapped_in, 
						      &principal, &pac, &unwrapped_out,
						      &gensec_krb5_state->krb5_keyblock);
		}

		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		if (pac.data) {
			/* decode and verify the pac */
			nt_status = gensec_krb5_decode_pac(gensec_krb5_state, &gensec_krb5_state->logon_info, pac,
							   gensec_krb5_state);
		} else {
			/* NULL PAC, we might need to figure this information out the hard way */
			gensec_krb5_state->logon_info = NULL;
		}

		if (NT_STATUS_IS_OK(nt_status)) {
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
			/* wrap that up in a nice GSS-API wrapping */
			*out = gensec_gssapi_gen_krb5_wrap(out_mem_ctx, &unwrapped_out, TOK_ID_KRB_AP_REP);

			gensec_krb5_state->peer_principal = talloc_steal(gensec_krb5_state, principal);
		}
		return nt_status;
	}
	case GENSEC_KRB5_DONE:
		return NT_STATUS_OK;
	}
	
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_krb5_session_key(struct gensec_security *gensec_security, 
					   DATA_BLOB *session_key) 
{
	struct gensec_krb5_state *gensec_krb5_state = gensec_security->private_data;
	krb5_context context = gensec_krb5_state->krb5_context;
	krb5_auth_context auth_context = gensec_krb5_state->krb5_auth_context;
	krb5_keyblock *skey;
	krb5_error_code err;

	if (gensec_krb5_state->session_key.data) {
		*session_key = gensec_krb5_state->session_key;
		return NT_STATUS_OK;
	}

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		err = krb5_auth_con_getlocalsubkey(context, auth_context, &skey);
		break;
	case GENSEC_SERVER:
		err = krb5_auth_con_getremotesubkey(context, auth_context, &skey);
		break;
	}
	if (err == 0 && skey != NULL) {
		DEBUG(10, ("Got KRB5 session key of length %d\n",  KRB5_KEY_LENGTH(skey)));
		gensec_krb5_state->session_key = data_blob_talloc(gensec_krb5_state, 
						KRB5_KEY_DATA(skey), KRB5_KEY_LENGTH(skey));
		*session_key = gensec_krb5_state->session_key;
		dump_data_pw("KRB5 Session Key:\n", session_key->data, session_key->length);

		krb5_free_keyblock(context, skey);
		return NT_STATUS_OK;
	} else {
		DEBUG(10, ("KRB5 error getting session key %d\n", err));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
}

static NTSTATUS gensec_krb5_session_info(struct gensec_security *gensec_security,
				     struct auth_session_info **session_info_out) 
{
	NTSTATUS nt_status;
	struct gensec_krb5_state *gensec_krb5_state = gensec_security->private_data;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	struct PAC_LOGON_INFO *logon_info = gensec_krb5_state->logon_info;
	struct nt_user_token *ptoken;
	struct dom_sid *sid;
	char *p;
	char *principal;

	*session_info_out = NULL;

	nt_status = make_server_info(gensec_security, &server_info, gensec_krb5_state->peer_principal);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	server_info->guest = False;

	principal = talloc_strdup(server_info, gensec_krb5_state->peer_principal);
	p = strchr(principal, '@');
	if (p) {
		*p = '\0';
	}
	server_info->account_name = principal;
	server_info->domain = talloc_strdup(server_info, p++);
	if (!server_info->domain) {
		free_server_info(&server_info);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = make_session_info(server_info, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		free_server_info(&server_info);
		return nt_status;
	}

	/* IF we have the PAC - otherwise (TODO) we need to get this
	 * data from elsewere - local ldb, or lookup of some
	 * kind... */

	if (logon_info) {
		ptoken = talloc_p(session_info, struct nt_user_token);
		if (!ptoken) {
			return NT_STATUS_NO_MEMORY;
		}
		
		ptoken->num_sids = 0;
		
		ptoken->user_sids = talloc_array_p(ptoken, struct dom_sid*, logon_info->groups_count + 2);
		if (!ptoken->user_sids) {
			return NT_STATUS_NO_MEMORY;
		}
		
		
		sid = dom_sid_dup(session_info, logon_info->dom_sid);
		ptoken->user_sids[0] = dom_sid_add_rid(session_info, sid, logon_info->user_rid);
		ptoken->num_sids++;
		sid = dom_sid_dup(session_info, logon_info->dom_sid);
		ptoken->user_sids[1] = dom_sid_add_rid(session_info, sid, logon_info->group_rid);
		ptoken->num_sids++;
		
		for (;ptoken->num_sids < logon_info->groups_count; ptoken->num_sids++) {
			sid = dom_sid_dup(session_info, logon_info->dom_sid);
			ptoken->user_sids[ptoken->num_sids] = dom_sid_add_rid(session_info, sid, logon_info->groups[ptoken->num_sids - 2].rid);
		}
		
		debug_nt_user_token(DBGC_AUTH, 0, ptoken);
		
		session_info->nt_user_token = ptoken;
	} else {
		session_info->nt_user_token = NULL;
	}

	nt_status = gensec_krb5_session_key(gensec_security, &session_info->session_key);

	session_info->workstation = NULL;

	*session_info_out = session_info;

	return nt_status;
}


static const struct gensec_security_ops gensec_krb5_security_ops = {
	.name		= "krb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = OID_KERBEROS5,
	.client_start   = gensec_krb5_client_start,
	.server_start   = gensec_krb5_server_start,
	.update 	= gensec_krb5_update,
	.session_key	= gensec_krb5_session_key,
	.session_info	= gensec_krb5_session_info,
	.end		= gensec_krb5_end
};

static const struct gensec_security_ops gensec_ms_krb5_security_ops = {
	.name		= "ms_krb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = OID_KERBEROS5_OLD,
	.client_start   = gensec_krb5_client_start,
	.server_start   = gensec_krb5_server_start,
	.update 	= gensec_krb5_update,
	.session_key	= gensec_krb5_session_key,
	.session_info	= gensec_krb5_session_info,
	.end		= gensec_krb5_end
};


NTSTATUS gensec_krb5_init(void)
{
	NTSTATUS ret;

	ret = register_backend("gensec", &gensec_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_krb5_security_ops.name));
		return ret;
	}

	ret = register_backend("gensec", &gensec_ms_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_krb5_security_ops.name));
		return ret;
	}

	return ret;
}

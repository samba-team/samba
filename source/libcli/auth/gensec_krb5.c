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
	TALLOC_CTX *mem_ctx;
	DATA_BLOB session_key;
	DATA_BLOB pac;
	enum GENSEC_KRB5_STATE state_position;
	krb5_context krb5_context;
	krb5_auth_context krb5_auth_context;
};

static NTSTATUS gensec_krb5_start(struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state;
	krb5_error_code ret = 0;

	TALLOC_CTX *mem_ctx = talloc_init("gensec_krb5");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_krb5_state = talloc_p(mem_ctx, struct gensec_krb5_state);
	if (!gensec_krb5_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_krb5_state->mem_ctx = mem_ctx;

	gensec_security->private_data = gensec_krb5_state;

	initialize_krb5_error_table();
	gensec_krb5_state->krb5_context = NULL;
	gensec_krb5_state->krb5_auth_context = NULL;
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
	
	NTSTATUS nt_status;
	nt_status = gensec_krb5_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_krb5_state = gensec_security->private_data;
	gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_START;

	return NT_STATUS_OK;
}

static void gensec_krb5_end(struct gensec_security *gensec_security)
{
	struct gensec_krb5_state *gensec_krb5_state = gensec_security->private_data;

	if (gensec_krb5_state->krb5_auth_context) {
		krb5_auth_con_free(gensec_krb5_state->krb5_context, 
				   gensec_krb5_state->krb5_auth_context);
	}

	if (gensec_krb5_state->krb5_context) {
		krb5_free_context(gensec_krb5_state->krb5_context);
	}

	talloc_destroy(gensec_krb5_state->mem_ctx);
	gensec_security->private_data = NULL;
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
		krb5_data packet;
		krb5_ccache ccdef = NULL;
		
#if 0 /* When we get some way to input the time offset */
		if (time_offset != 0) {
			krb5_set_real_time(context, time(NULL) + time_offset, 0);
		}
#endif

		ret = krb5_cc_default(gensec_krb5_state->krb5_context, &ccdef);
		if (ret) {
			DEBUG(1,("krb5_cc_default failed (%s)\n",
				 error_message(ret)));
			return NT_STATUS_INTERNAL_ERROR;
		}

		ret = ads_krb5_mk_req(gensec_krb5_state->krb5_context, 
				      &gensec_krb5_state->krb5_auth_context, 
				      AP_OPTS_USE_SUBKEY
#ifdef MUTUAL_AUTH
 | AP_OPTS_MUTUAL_REQUIRED
#endif
				      , 
				      gensec_security->target.principal,
				      ccdef, &packet);
		if (ret) {
			DEBUG(1,("ads_krb5_mk_req (request ticket) failed (%s)\n",
				 error_message(ret)));
			nt_status = NT_STATUS_LOGON_FAILURE;
		} else {
			*out = data_blob_talloc(out_mem_ctx, packet.data, packet.length);
			
			/* Hmm, heimdal dooesn't have this - what's the correct call? */
#ifdef HAVE_KRB5_FREE_DATA_CONTENTS
			krb5_free_data_contents(gensec_krb5_state->krb5_context, &packet); 
#endif
#ifdef MUTUAL_AUTH
			gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_MUTUAL_AUTH;
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
#else 
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
			nt_status = NT_STATUS_OK;
#endif
		}
		
		/* Removed by jra. They really need to fix their kerberos so we don't leak memory. 
		   JERRY -- disabled since it causes heimdal 0.6.1rc3 to die
		   SuSE 9.1 Pro 
		*/
#if 0 /* redisabled by gd :) at least until any official heimdal version has it fixed. */
		krb5_cc_close(context, ccdef);
#endif
		return nt_status;
	}
		
	case GENSEC_KRB5_CLIENT_MUTUAL_AUTH:
	{
		krb5_data inbuf;
		krb5_ap_rep_enc_part *repl = NULL;
		inbuf.data = in.data;
		inbuf.length = in.length;
		ret = krb5_rd_rep(gensec_krb5_state->krb5_context, 
				  gensec_krb5_state->krb5_auth_context,
				  &inbuf, &repl);
		if (ret) {
			DEBUG(1,("krb5_rd_rep (mutual authentication) failed (%s)\n",
				 error_message(ret)));
			dump_data_pw("Mutual authentication message:\n", in.data, in.length);
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

		nt_status = ads_verify_ticket(out_mem_ctx, 
					      gensec_krb5_state->krb5_context, 
					      gensec_krb5_state->krb5_auth_context, 
					      lp_realm(), &in, 
					      &principal, &pac, out);
		gensec_krb5_state->pac = data_blob_talloc_steal(out_mem_ctx, gensec_krb5_state->mem_ctx, 
								&pac);
		/* TODO: parse the pac */

		if (NT_STATUS_IS_OK(nt_status)) {
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
		}
		SAFE_FREE(principal);
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
		gensec_krb5_state->session_key = data_blob_talloc(gensec_krb5_state->mem_ctx, 
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


static const struct gensec_security_ops gensec_krb5_security_ops = {
	.name		= "krb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = OID_KERBEROS5,
	.client_start   = gensec_krb5_client_start,
	.server_start   = gensec_krb5_server_start,
	.update 	= gensec_krb5_update,
	.session_key	= gensec_krb5_session_key,
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

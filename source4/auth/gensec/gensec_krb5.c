/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005

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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/auth.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "auth/kerberos/kerberos_credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "auth/gensec/gensec_toplevel_proto.h"
#include "param/param.h"
#include "auth/auth_sam_reply.h"
#include "lib/util/util_net.h"
#include "../lib/util/asn1.h"
#include "auth/kerberos/pac_utils.h"
#include "gensec_krb5.h"

_PUBLIC_ NTSTATUS gensec_krb5_init(TALLOC_CTX *);

enum GENSEC_KRB5_STATE {
	GENSEC_KRB5_SERVER_START,
	GENSEC_KRB5_CLIENT_START,
	GENSEC_KRB5_CLIENT_MUTUAL_AUTH,
	GENSEC_KRB5_DONE
};

struct gensec_krb5_state {
	enum GENSEC_KRB5_STATE state_position;
	struct smb_krb5_context *smb_krb5_context;
	krb5_auth_context auth_context;
	krb5_data enc_ticket;
	krb5_keyblock *keyblock;
	krb5_ticket *ticket;
	bool gssapi;
	krb5_flags ap_req_options;
};

static int gensec_krb5_destroy(struct gensec_krb5_state *gensec_krb5_state)
{
	if (!gensec_krb5_state->smb_krb5_context) {
		/* We can't clean anything else up unless we started up this far */
		return 0;
	}
	if (gensec_krb5_state->enc_ticket.length) { 
		smb_krb5_free_data_contents(gensec_krb5_state->smb_krb5_context->krb5_context,
					    &gensec_krb5_state->enc_ticket); 
	}

	if (gensec_krb5_state->ticket) {
		krb5_free_ticket(gensec_krb5_state->smb_krb5_context->krb5_context, 
				 gensec_krb5_state->ticket);
	}

	/* ccache freed in a child destructor */

	krb5_free_keyblock(gensec_krb5_state->smb_krb5_context->krb5_context, 
			   gensec_krb5_state->keyblock);
		
	if (gensec_krb5_state->auth_context) {
		krb5_auth_con_free(gensec_krb5_state->smb_krb5_context->krb5_context, 
				   gensec_krb5_state->auth_context);
	}

	return 0;
}

static NTSTATUS gensec_krb5_start(struct gensec_security *gensec_security, bool gssapi)
{
	krb5_error_code ret;
	struct gensec_krb5_state *gensec_krb5_state;
	struct cli_credentials *creds;
	const struct tsocket_address *tlocal_addr, *tremote_addr;
	krb5_address my_krb5_addr, peer_krb5_addr;
	
	creds = gensec_get_credentials(gensec_security);
	if (!creds) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	gensec_krb5_state = talloc_zero(gensec_security, struct gensec_krb5_state);
	if (!gensec_krb5_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_krb5_state;
	gensec_krb5_state->gssapi = gssapi;

	talloc_set_destructor(gensec_krb5_state, gensec_krb5_destroy); 

	if (cli_credentials_get_krb5_context(creds, 
					     gensec_security->settings->lp_ctx, &gensec_krb5_state->smb_krb5_context)) {
		talloc_free(gensec_krb5_state);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = krb5_auth_con_init(gensec_krb5_state->smb_krb5_context->krb5_context, &gensec_krb5_state->auth_context);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_auth_con_init failed (%s)\n", 
			 smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, 
						    ret, gensec_krb5_state)));
		talloc_free(gensec_krb5_state);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = krb5_auth_con_setflags(gensec_krb5_state->smb_krb5_context->krb5_context, 
				     gensec_krb5_state->auth_context,
				     KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_auth_con_setflags failed (%s)\n", 
			 smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, 
						    ret, gensec_krb5_state)));
		talloc_free(gensec_krb5_state);
		return NT_STATUS_INTERNAL_ERROR;
	}

	tlocal_addr = gensec_get_local_address(gensec_security);
	if (tlocal_addr) {
		ssize_t sockaddr_ret;
		struct samba_sockaddr addr;
		bool ok;

		addr.sa_socklen = sizeof(addr.u);
		sockaddr_ret = tsocket_address_bsd_sockaddr(
			tlocal_addr, &addr.u.sa, addr.sa_socklen);
		if (sockaddr_ret < 0) {
			talloc_free(gensec_krb5_state);
			return NT_STATUS_INTERNAL_ERROR;
		}
		addr.sa_socklen = sockaddr_ret;
		ok = smb_krb5_sockaddr_to_kaddr(&addr.u.ss, &my_krb5_addr);
		if (!ok) {
			DBG_WARNING("smb_krb5_sockaddr_to_kaddr (local) failed\n");
			talloc_free(gensec_krb5_state);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	tremote_addr = gensec_get_remote_address(gensec_security);
	if (tremote_addr) {
		ssize_t sockaddr_ret;
		struct samba_sockaddr addr;
		bool ok;

		addr.sa_socklen = sizeof(addr.u);
		sockaddr_ret = tsocket_address_bsd_sockaddr(
			tremote_addr, &addr.u.sa, addr.sa_socklen);
		if (sockaddr_ret < 0) {
			talloc_free(gensec_krb5_state);
			return NT_STATUS_INTERNAL_ERROR;
		}
		addr.sa_socklen = sockaddr_ret;
		ok = smb_krb5_sockaddr_to_kaddr(&addr.u.ss, &peer_krb5_addr);
		if (!ok) {
			DBG_WARNING("smb_krb5_sockaddr_to_kaddr (remote) failed\n");
			talloc_free(gensec_krb5_state);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ret = krb5_auth_con_setaddrs(gensec_krb5_state->smb_krb5_context->krb5_context, 
				     gensec_krb5_state->auth_context,
				     tlocal_addr ? &my_krb5_addr : NULL,
				     tremote_addr ? &peer_krb5_addr : NULL);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_auth_con_setaddrs failed (%s)\n", 
			 smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, 
						    ret, gensec_krb5_state)));
		talloc_free(gensec_krb5_state);
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_common_server_start(struct gensec_security *gensec_security, bool gssapi)
{
	NTSTATUS nt_status;
	struct gensec_krb5_state *gensec_krb5_state;

	nt_status = gensec_krb5_start(gensec_security, gssapi);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	
	gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	gensec_krb5_state->state_position = GENSEC_KRB5_SERVER_START;

	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_server_start(struct gensec_security *gensec_security)
{
	return gensec_krb5_common_server_start(gensec_security, false);
}

static NTSTATUS gensec_fake_gssapi_krb5_server_start(struct gensec_security *gensec_security)
{
	return gensec_krb5_common_server_start(gensec_security, true);
}

static NTSTATUS gensec_krb5_common_client_start(struct gensec_security *gensec_security, bool gssapi)
{
	const char *hostname;
	struct gensec_krb5_state *gensec_krb5_state;
	NTSTATUS nt_status;
	hostname = gensec_get_target_hostname(gensec_security);
	if (!hostname) {
		DEBUG(3, ("No hostname for target computer passed in, cannot use kerberos for this connection\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (is_ipaddress(hostname)) {
		DEBUG(2, ("Cannot do krb5 to an IP address"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (strcmp(hostname, "localhost") == 0) {
		DEBUG(2, ("krb5 to 'localhost' does not make sense"));
		return NT_STATUS_INVALID_PARAMETER;
	}
			
	nt_status = gensec_krb5_start(gensec_security, gssapi);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_START;
	gensec_krb5_state->ap_req_options = AP_OPTS_USE_SUBKEY;

	if (gensec_krb5_state->gssapi) {
		/* The Fake GSSAPI model emulates Samba3, which does not do mutual authentication */
		if (gensec_setting_bool(gensec_security->settings, "gensec_fake_gssapi_krb5", "mutual", false)) {
			gensec_krb5_state->ap_req_options |= AP_OPTS_MUTUAL_REQUIRED;
		}
	} else {
		/* The wrapping for KPASSWD (a user of the raw KRB5 API) should be mutually authenticated */
		if (gensec_setting_bool(gensec_security->settings, "gensec_krb5", "mutual", true)) {
			gensec_krb5_state->ap_req_options |= AP_OPTS_MUTUAL_REQUIRED;
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_common_client_creds(struct gensec_security *gensec_security,
						struct tevent_context *ev)
{
	struct gensec_krb5_state *gensec_krb5_state;
	krb5_error_code ret;
	struct ccache_container *ccache_container;
	const char *error_string;
	const char *principal;
	const char *hostname;
	krb5_data in_data = { .length = 0 };
	krb5_data *in_data_p = NULL;
#ifdef SAMBA4_USES_HEIMDAL
	struct tevent_context *previous_ev;
#endif

	if (lpcfg_parm_bool(gensec_security->settings->lp_ctx,
			    NULL, "gensec_krb5", "send_authenticator_checksum", true)) {
		in_data_p = &in_data;
	}
	
	gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;

	principal = gensec_get_target_principal(gensec_security);
	hostname = gensec_get_target_hostname(gensec_security);

	ret = cli_credentials_get_ccache(gensec_get_credentials(gensec_security), 
				         ev,
					 gensec_security->settings->lp_ctx, &ccache_container, &error_string);
	switch (ret) {
	case 0:
		break;
	case KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return NT_STATUS_LOGON_FAILURE;
	case KRB5_KDC_UNREACH:
		DEBUG(3, ("Cannot reach a KDC we require to contact %s: %s\n", principal, error_string));
		return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
	case KRB5_CC_NOTFOUND:
	case KRB5_CC_END:
		DEBUG(3, ("Error preparing credentials we require to contact %s : %s\n", principal, error_string));
		return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
	default:
		DEBUG(1, ("gensec_krb5_start: Aquiring initiator credentials failed: %s\n", error_string));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
#ifdef SAMBA4_USES_HEIMDAL
	/* Do this every time, in case we have weird recursive issues here */
	ret = smb_krb5_context_set_event_ctx(gensec_krb5_state->smb_krb5_context, ev, &previous_ev);
	if (ret != 0) {
		DEBUG(1, ("gensec_krb5_start: Setting event context failed\n"));
		return NT_STATUS_NO_MEMORY;
	}
#endif
	if (principal) {
		krb5_principal target_principal;
		ret = krb5_parse_name(gensec_krb5_state->smb_krb5_context->krb5_context, principal,
				      &target_principal);
		if (ret == 0) {
			krb5_creds this_cred;
			krb5_creds *cred;

			ZERO_STRUCT(this_cred);
			ret = krb5_cc_get_principal(gensec_krb5_state->smb_krb5_context->krb5_context,
						    ccache_container->ccache,
						    &this_cred.client);
			if (ret != 0) {
				krb5_free_principal(gensec_krb5_state->smb_krb5_context->krb5_context,
						    target_principal);
				return NT_STATUS_UNSUCCESSFUL;
			}

			ret = krb5_copy_principal(gensec_krb5_state->smb_krb5_context->krb5_context,
						  target_principal,
						  &this_cred.server);
			krb5_free_principal(gensec_krb5_state->smb_krb5_context->krb5_context,
					    target_principal);
			if (ret != 0) {
				krb5_free_cred_contents(gensec_krb5_state->smb_krb5_context->krb5_context,
							&this_cred);
				return NT_STATUS_UNSUCCESSFUL;
			}
			this_cred.times.endtime = 0;

			ret = krb5_get_credentials(gensec_krb5_state->smb_krb5_context->krb5_context,
						   0,
						   ccache_container->ccache,
						   &this_cred,
						   &cred);
			krb5_free_cred_contents(gensec_krb5_state->smb_krb5_context->krb5_context,
						&this_cred);
			if (ret != 0) {
				return NT_STATUS_UNSUCCESSFUL;
			}

			ret = krb5_mk_req_extended(gensec_krb5_state->smb_krb5_context->krb5_context,
						   &gensec_krb5_state->auth_context,
						   gensec_krb5_state->ap_req_options,
						   in_data_p,
						   cred,
						   &gensec_krb5_state->enc_ticket);
		}
	} else {
		ret = krb5_mk_req(gensec_krb5_state->smb_krb5_context->krb5_context, 
				  &gensec_krb5_state->auth_context,
				  gensec_krb5_state->ap_req_options,
				  discard_const_p(char, gensec_get_target_service(gensec_security)),
				  discard_const_p(char, hostname),
				  in_data_p, ccache_container->ccache, 
				  &gensec_krb5_state->enc_ticket);
	}

#ifdef SAMBA4_USES_HEIMDAL
	smb_krb5_context_remove_event_ctx(gensec_krb5_state->smb_krb5_context, previous_ev, ev);
#endif

	switch (ret) {
	case 0:
		return NT_STATUS_OK;
	case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
		DEBUG(3, ("Server [%s] is not registered with our KDC: %s\n", 
			  hostname, smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, ret, gensec_krb5_state)));
		return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
	case KRB5_KDC_UNREACH:
		DEBUG(3, ("Cannot reach a KDC we require to contact host [%s]: %s\n",
			  hostname, smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, ret, gensec_krb5_state)));
		return NT_STATUS_INVALID_PARAMETER; /* Make SPNEGO ignore us, we can't go any further here */
	case KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5KRB_AP_ERR_TKT_EXPIRED:
	case KRB5_CC_END:
		/* Too much clock skew - we will need to kinit to re-skew the clock */
	case KRB5KRB_AP_ERR_SKEW:
	case KRB5_KDCREP_SKEW:
		DEBUG(3, ("kerberos (mk_req) failed: %s\n", 
			  smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, ret, gensec_krb5_state)));
		FALL_THROUGH;
	/* just don't print a message for these really ordinary messages */
	case KRB5_FCC_NOFILE:
	case KRB5_CC_NOTFOUND:
	case ENOENT:
		
		return NT_STATUS_UNSUCCESSFUL;
		break;
		
	default:
		DEBUG(0, ("kerberos: %s\n", 
			  smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, ret, gensec_krb5_state)));
		return NT_STATUS_UNSUCCESSFUL;
	}
}

static NTSTATUS gensec_krb5_client_start(struct gensec_security *gensec_security)
{
	return gensec_krb5_common_client_start(gensec_security, false);
}

static NTSTATUS gensec_fake_gssapi_krb5_client_start(struct gensec_security *gensec_security)
{
	return gensec_krb5_common_client_start(gensec_security, true);
}


/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
static DATA_BLOB gensec_gssapi_gen_krb5_wrap(TALLOC_CTX *mem_ctx, const DATA_BLOB *ticket, const uint8_t tok_id[2])
{
	struct asn1_data *data;
	DATA_BLOB ret = data_blob_null;

	data = asn1_init(mem_ctx, ASN1_MAX_TREE_DEPTH);
	if (!data || !ticket->data) {
		return ret;
	}

	if (!asn1_push_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_write_OID(data, GENSEC_OID_KERBEROS5)) goto err;

	if (!asn1_write(data, tok_id, 2)) goto err;
	if (!asn1_write(data, ticket->data, ticket->length)) goto err;
	if (!asn1_pop_tag(data)) goto err;


	if (!asn1_extract_blob(data, mem_ctx, &ret)) {
		goto err;
	}
	asn1_free(data);

	return ret;

  err:

	DEBUG(1, ("Failed to build krb5 wrapper at offset %d\n",
		  (int)asn1_current_ofs(data)));
	asn1_free(data);
	return ret;
}

/*
  parse a krb5 GSS-API wrapper packet giving a ticket
*/
static bool gensec_gssapi_parse_krb5_wrap(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, DATA_BLOB *ticket, uint8_t tok_id[2])
{
	bool ret = false;
	struct asn1_data *data = asn1_init(mem_ctx, ASN1_MAX_TREE_DEPTH);
	int data_remaining;

	if (!data) {
		return false;
	}

	if (!asn1_load(data, *blob)) goto err;
	if (!asn1_start_tag(data, ASN1_APPLICATION(0))) goto err;
	if (!asn1_check_OID(data, GENSEC_OID_KERBEROS5)) goto err;

	data_remaining = asn1_tag_remaining(data);

	if (data_remaining < 3) {
		asn1_set_error(data);
	} else {
		if (!asn1_read(data, tok_id, 2)) goto err;
		data_remaining -= 2;
		*ticket = data_blob_talloc(mem_ctx, NULL, data_remaining);
		if (!asn1_read(data, ticket->data, ticket->length)) goto err;
	}

	if (!asn1_end_tag(data)) goto err;

	ret = !asn1_has_error(data);

  err:

	asn1_free(data);

	return ret;
}

static NTSTATUS gensec_krb5_update_internal(struct gensec_security *gensec_security,
					    TALLOC_CTX *out_mem_ctx,
					    struct tevent_context *ev,
					    const DATA_BLOB in, DATA_BLOB *out)
{
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	krb5_error_code ret = 0;
	NTSTATUS nt_status;

	switch (gensec_krb5_state->state_position) {
	case GENSEC_KRB5_CLIENT_START:
	{
		DATA_BLOB unwrapped_out;
		
		nt_status = gensec_krb5_common_client_creds(gensec_security, ev);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		if (gensec_krb5_state->gssapi) {
			unwrapped_out = data_blob_talloc(out_mem_ctx, gensec_krb5_state->enc_ticket.data, gensec_krb5_state->enc_ticket.length);
			
			/* wrap that up in a nice GSS-API wrapping */
			*out = gensec_gssapi_gen_krb5_wrap(out_mem_ctx, &unwrapped_out, TOK_ID_KRB_AP_REQ);
		} else {
			*out = data_blob_talloc(out_mem_ctx, gensec_krb5_state->enc_ticket.data, gensec_krb5_state->enc_ticket.length);
		}
		if (gensec_krb5_state->ap_req_options & AP_OPTS_MUTUAL_REQUIRED) {
			gensec_krb5_state->state_position = GENSEC_KRB5_CLIENT_MUTUAL_AUTH;
			nt_status = NT_STATUS_MORE_PROCESSING_REQUIRED;
		} else {
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
			nt_status = NT_STATUS_OK;
		}
		return nt_status;
	}
		
	case GENSEC_KRB5_CLIENT_MUTUAL_AUTH:
	{
		DATA_BLOB unwrapped_in;
		krb5_data inbuf;
		krb5_ap_rep_enc_part *repl = NULL;
		uint8_t tok_id[2];

		if (gensec_krb5_state->gssapi) {
			if (!gensec_gssapi_parse_krb5_wrap(out_mem_ctx, &in, &unwrapped_in, tok_id)) {
				DEBUG(1,("gensec_gssapi_parse_krb5_wrap(mutual authentication) failed to parse\n"));
				dump_data_pw("Mutual authentication message:\n", in.data, in.length);
				return NT_STATUS_INVALID_PARAMETER;
			}
		} else {
			unwrapped_in = in;
		}
		/* TODO: check the tok_id */

		inbuf.data = (char *)unwrapped_in.data;
		inbuf.length = unwrapped_in.length;
		ret = krb5_rd_rep(gensec_krb5_state->smb_krb5_context->krb5_context, 
				  gensec_krb5_state->auth_context,
				  &inbuf, &repl);
		if (ret) {
			DEBUG(1,("krb5_rd_rep (mutual authentication) failed (%s)\n",
				 smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, ret, out_mem_ctx)));
			dump_data_pw("Mutual authentication message:\n", (uint8_t *)inbuf.data, inbuf.length);
			nt_status = NT_STATUS_ACCESS_DENIED;
		} else {
			*out = data_blob(NULL, 0);
			nt_status = NT_STATUS_OK;
			gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
		}
		if (repl) {
			krb5_free_ap_rep_enc_part(gensec_krb5_state->smb_krb5_context->krb5_context, repl);
		}
		return nt_status;
	}

	case GENSEC_KRB5_SERVER_START:
	{
		DATA_BLOB unwrapped_in;
		DATA_BLOB unwrapped_out = data_blob(NULL, 0);
		krb5_data inbuf, outbuf;
		uint8_t tok_id[2];
		struct keytab_container *keytab;
		krb5_principal server_in_keytab;
		const char *error_string;
		enum credentials_obtained obtained;

		if (!in.data) {
			return NT_STATUS_INVALID_PARAMETER;
		}	

		/* Grab the keytab, however generated */
		ret = cli_credentials_get_keytab(gensec_get_credentials(gensec_security), 
						 gensec_security->settings->lp_ctx, &keytab);
		if (ret) {
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		
		/* This ensures we lookup the correct entry in that
		 * keytab.  A NULL principal is acceptable, and means
		 * that the krb5 libs should search the keytab at
		 * accept time for any matching key */
		ret = principal_from_credentials(out_mem_ctx, gensec_get_credentials(gensec_security), 
						 gensec_krb5_state->smb_krb5_context, 
						 &server_in_keytab, &obtained, &error_string);

		if (ret) {
			DEBUG(2,("Failed to make credentials from principal: %s\n", error_string));
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}

		if (keytab->password_based || obtained < CRED_SPECIFIED) {
			/* 
			 * Use match-by-key in this case (matches
			 * cli_credentials_get_server_gss_creds()
			 * behaviour).  No need to free the memory,
			 * this is handled with a talloc destructor.
			 */
			server_in_keytab = NULL;
		}

		/* Parse the GSSAPI wrapping, if it's there... (win2k3 allows it to be omited) */
		if (gensec_krb5_state->gssapi
		    && gensec_gssapi_parse_krb5_wrap(out_mem_ctx, &in, &unwrapped_in, tok_id)) {
			inbuf.data = (char *)unwrapped_in.data;
			inbuf.length = unwrapped_in.length;
		} else {
			inbuf.data = (char *)in.data;
			inbuf.length = in.length;
		}

		ret = smb_krb5_rd_req_decoded(gensec_krb5_state->smb_krb5_context->krb5_context,
					      &gensec_krb5_state->auth_context,
					      &inbuf,
					      keytab->keytab,
					      server_in_keytab,
					      &outbuf,
					      &gensec_krb5_state->ticket,
					      &gensec_krb5_state->keyblock);

		if (ret) {
			DBG_WARNING("smb_krb5_rd_req_decoded failed\n");
			return NT_STATUS_LOGON_FAILURE;
		}
		unwrapped_out.data = (uint8_t *)outbuf.data;
		unwrapped_out.length = outbuf.length;
		gensec_krb5_state->state_position = GENSEC_KRB5_DONE;
		/* wrap that up in a nice GSS-API wrapping */
		if (gensec_krb5_state->gssapi) {
			*out = gensec_gssapi_gen_krb5_wrap(out_mem_ctx, &unwrapped_out, TOK_ID_KRB_AP_REP);
		} else {
			*out = data_blob_talloc(out_mem_ctx, outbuf.data, outbuf.length);
		}
		smb_krb5_free_data_contents(gensec_krb5_state->smb_krb5_context->krb5_context,
					    &outbuf);
		return NT_STATUS_OK;
	}

	case GENSEC_KRB5_DONE:
	default:
		/* Asking too many times... */
		return NT_STATUS_INVALID_PARAMETER;
	}
}

struct gensec_krb5_update_state {
	NTSTATUS status;
	DATA_BLOB out;
};

static struct tevent_req *gensec_krb5_update_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct gensec_security *gensec_security,
						  const DATA_BLOB in)
{
	struct tevent_req *req = NULL;
	struct gensec_krb5_update_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_krb5_update_state);
	if (req == NULL) {
		return NULL;
	}

	status = gensec_krb5_update_internal(gensec_security,
					     state, ev, in,
					     &state->out);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS gensec_krb5_update_recv(struct tevent_req *req,
					TALLOC_CTX *out_mem_ctx,
					DATA_BLOB *out)
{
	struct gensec_krb5_update_state *state =
		tevent_req_data(req,
		struct gensec_krb5_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	talloc_steal(out_mem_ctx, state->out.data);
	status = state->status;
	tevent_req_received(req);
	return status;
}

static NTSTATUS gensec_krb5_session_key(struct gensec_security *gensec_security, 
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *session_key) 
{
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	krb5_context context = gensec_krb5_state->smb_krb5_context->krb5_context;
	krb5_auth_context auth_context = gensec_krb5_state->auth_context;
	krb5_error_code err = -1;
	bool remote = false;
	bool ok;

	if (gensec_krb5_state->state_position != GENSEC_KRB5_DONE) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		remote = false;
		break;
	case GENSEC_SERVER:
		remote = true;
		break;
	}

	ok = smb_krb5_get_smb_session_key(mem_ctx,
					  context,
					  auth_context,
					  session_key,
					  remote);
	if (!ok) {
		DEBUG(10, ("KRB5 error getting session key %d\n", err));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	return NT_STATUS_OK;
}

#ifdef SAMBA4_USES_HEIMDAL
static NTSTATUS gensec_krb5_session_info(struct gensec_security *gensec_security,
					 TALLOC_CTX *mem_ctx,
					 struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	krb5_context context = gensec_krb5_state->smb_krb5_context->krb5_context;
	struct auth_session_info *session_info = NULL;

	krb5_principal client_principal;
	char *principal_string = NULL;
	
	DATA_BLOB pac_blob, *pac_blob_ptr = NULL;
	krb5_data pac_data;

	krb5_error_code ret;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	
	ret = krb5_ticket_get_client(context, gensec_krb5_state->ticket, &client_principal);
	if (ret) {
		DEBUG(5, ("krb5_ticket_get_client failed to get client principal: %s\n", 
			  smb_get_krb5_error_message(context, 
						     ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	ret = krb5_unparse_name(gensec_krb5_state->smb_krb5_context->krb5_context, 
				client_principal, &principal_string);
	if (ret) {
		DEBUG(1, ("Unable to parse client principal: %s\n",
			  smb_get_krb5_error_message(context, 
						     ret, tmp_ctx)));
		krb5_free_principal(context, client_principal);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = krb5_ticket_get_authorization_data_type(context, gensec_krb5_state->ticket, 
						      KRB5_AUTHDATA_WIN2K_PAC, 
						      &pac_data);
	
	if (ret) {
		/* NO pac */
		DEBUG(5, ("krb5_ticket_get_authorization_data_type failed to find PAC: %s\n", 
			  smb_get_krb5_error_message(context, 
						     ret, tmp_ctx)));
	} else {
		/* Found pac */
		pac_blob = data_blob_talloc(tmp_ctx, pac_data.data, pac_data.length);
		smb_krb5_free_data_contents(context, &pac_data);
		if (!pac_blob.data) {
			free(principal_string);
			krb5_free_principal(context, client_principal);
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		/* decode and verify the pac */
		nt_status = kerberos_decode_pac(gensec_krb5_state,
						pac_blob,
						gensec_krb5_state->smb_krb5_context->krb5_context,
						NULL, gensec_krb5_state->keyblock,
						client_principal,
						gensec_krb5_state->ticket->ticket.authtime, NULL);

		if (!NT_STATUS_IS_OK(nt_status)) {
			free(principal_string);
			krb5_free_principal(context, client_principal);
			talloc_free(tmp_ctx);
			return nt_status;
		}

		pac_blob_ptr = &pac_blob;
	}

	nt_status = gensec_generate_session_info_pac(tmp_ctx,
						     gensec_security,
						     gensec_krb5_state->smb_krb5_context,
						     pac_blob_ptr, principal_string,
						     gensec_get_remote_address(gensec_security),
						     &session_info);

	free(principal_string);
	krb5_free_principal(context, client_principal);

	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = gensec_krb5_session_key(gensec_security, session_info, &session_info->session_key);

	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	*_session_info = talloc_steal(mem_ctx, session_info);

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}
#else /* MIT KERBEROS */
static NTSTATUS gensec_krb5_session_info(struct gensec_security *gensec_security,
					 TALLOC_CTX *mem_ctx,
					 struct auth_session_info **psession_info)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct gensec_krb5_state *gensec_krb5_state =
		(struct gensec_krb5_state *)gensec_security->private_data;
	krb5_context context = gensec_krb5_state->smb_krb5_context->krb5_context;
	struct auth_session_info *session_info = NULL;

	krb5_principal client_principal;
	char *principal_string = NULL;

	krb5_authdata **auth_pac_data = NULL;
	DATA_BLOB pac_blob, *pac_blob_ptr = NULL;

	krb5_error_code code;

	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	code = krb5_copy_principal(context,
				   gensec_krb5_state->ticket->enc_part2->client,
				   &client_principal);
	if (code != 0) {
		DBG_INFO("krb5_copy_principal failed to copy client "
			 "principal: %s\n",
			 smb_get_krb5_error_message(context, code, tmp_ctx));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	code = krb5_unparse_name(context, client_principal, &principal_string);
	if (code != 0) {
		DBG_WARNING("Unable to parse client principal: %s\n",
			    smb_get_krb5_error_message(context, code, tmp_ctx));
		krb5_free_principal(context, client_principal);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	code = krb5_find_authdata(context,
				  gensec_krb5_state->ticket->enc_part2->authorization_data,
				  NULL,
				  KRB5_AUTHDATA_WIN2K_PAC,
				  &auth_pac_data);
	if (code != 0) {
		/* NO pac */
		DBG_INFO("krb5_find_authdata failed to find PAC: %s\n",
			 smb_get_krb5_error_message(context, code, tmp_ctx));
	} else {
		krb5_timestamp ticket_authtime =
			gensec_krb5_state->ticket->enc_part2->times.authtime;

		/* Found pac */
		pac_blob = data_blob_talloc(tmp_ctx,
					    auth_pac_data[0]->contents,
					    auth_pac_data[0]->length);
		krb5_free_authdata(context, auth_pac_data);
		if (pac_blob.data == NULL) {
			free(principal_string);
			krb5_free_principal(context, client_principal);
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		/* decode and verify the pac */
		status = kerberos_decode_pac(gensec_krb5_state,
					     pac_blob,
					     context,
					     NULL,
					     gensec_krb5_state->keyblock,
					     client_principal,
					     ticket_authtime,
					     NULL);

		if (!NT_STATUS_IS_OK(status)) {
			free(principal_string);
			krb5_free_principal(context, client_principal);
			talloc_free(tmp_ctx);
			return status;
		}

		pac_blob_ptr = &pac_blob;
	}
	krb5_free_principal(context, client_principal);

	status = gensec_generate_session_info_pac(tmp_ctx,
						  gensec_security,
						  gensec_krb5_state->smb_krb5_context,
						  pac_blob_ptr,
						  principal_string,
						  gensec_get_remote_address(gensec_security),
						  &session_info);
	SAFE_FREE(principal_string);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	status = gensec_krb5_session_key(gensec_security,
					 session_info,
					 &session_info->session_key);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	*psession_info = talloc_steal(mem_ctx, session_info);
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}
#endif /* SAMBA4_USES_HEIMDAL */

static NTSTATUS gensec_krb5_wrap(struct gensec_security *gensec_security, 
				   TALLOC_CTX *mem_ctx, 
				   const DATA_BLOB *in, 
				   DATA_BLOB *out)
{
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	krb5_context context = gensec_krb5_state->smb_krb5_context->krb5_context;
	krb5_auth_context auth_context = gensec_krb5_state->auth_context;
	krb5_error_code ret;
	krb5_data input, output;
	input.length = in->length;
	input.data = (char *)in->data;
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		ret = krb5_mk_priv(context, auth_context, &input, &output, NULL);
		if (ret) {
			DEBUG(1, ("krb5_mk_priv failed: %s\n", 
				  smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			return NT_STATUS_ACCESS_DENIED;
		}
		*out = data_blob_talloc(mem_ctx, output.data, output.length);
		
		smb_krb5_free_data_contents(context, &output);
	} else {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_krb5_unwrap(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const DATA_BLOB *in, 
				     DATA_BLOB *out)
{
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	krb5_context context = gensec_krb5_state->smb_krb5_context->krb5_context;
	krb5_auth_context auth_context = gensec_krb5_state->auth_context;
	krb5_error_code ret;
	krb5_data input, output;
	krb5_replay_data replay;
	input.length = in->length;
	input.data = (char *)in->data;
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		ret = krb5_rd_priv(context, auth_context, &input, &output, &replay);
		if (ret) {
			DEBUG(1, ("krb5_rd_priv failed: %s\n", 
				  smb_get_krb5_error_message(gensec_krb5_state->smb_krb5_context->krb5_context, 
							     ret, mem_ctx)));
			return NT_STATUS_ACCESS_DENIED;
		}
		*out = data_blob_talloc(mem_ctx, output.data, output.length);
		
		smb_krb5_free_data_contents(context, &output);
	} else {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static bool gensec_krb5_have_feature(struct gensec_security *gensec_security,
				     uint32_t feature)
{
	struct gensec_krb5_state *gensec_krb5_state = (struct gensec_krb5_state *)gensec_security->private_data;
	if (feature & GENSEC_FEATURE_SESSION_KEY) {
		return true;
	} 
	if (gensec_krb5_state->gssapi) {
		return false;
	}

	/*
	 * krb5_mk_priv provides SIGN and SEAL
	 */
	if (feature & GENSEC_FEATURE_SIGN) {
		return true;
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		return true;
	}

	return false;
}

static const char *gensec_krb5_final_auth_type(struct gensec_security *gensec_security)
{
	return GENSEC_FINAL_AUTH_TYPE_KRB5;
}

static const char *gensec_krb5_oids[] = { 
	GENSEC_OID_KERBEROS5,
	GENSEC_OID_KERBEROS5_OLD,
	NULL 
};

static const struct gensec_security_ops gensec_fake_gssapi_krb5_security_ops = {
	.name		= "fake_gssapi_krb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = gensec_krb5_oids,
	.client_start   = gensec_fake_gssapi_krb5_client_start,
	.server_start   = gensec_fake_gssapi_krb5_server_start,
	.update_send	= gensec_krb5_update_send,
	.update_recv	= gensec_krb5_update_recv,
	.magic   	= gensec_magic_check_krb5_oid,
	.session_key	= gensec_krb5_session_key,
	.session_info	= gensec_krb5_session_info,
	.have_feature   = gensec_krb5_have_feature,
	.final_auth_type = gensec_krb5_final_auth_type,
	.enabled        = false,
	.kerberos       = true,
	.priority       = GENSEC_KRB5,
};

static const struct gensec_security_ops gensec_krb5_security_ops = {
	.name		= "krb5",
	.client_start   = gensec_krb5_client_start,
	.server_start   = gensec_krb5_server_start,
	.update_send	= gensec_krb5_update_send,
	.update_recv	= gensec_krb5_update_recv,
	.session_key	= gensec_krb5_session_key,
	.session_info	= gensec_krb5_session_info,
	.have_feature   = gensec_krb5_have_feature,
	.wrap           = gensec_krb5_wrap,
	.unwrap         = gensec_krb5_unwrap,
	.final_auth_type = gensec_krb5_final_auth_type,
	.enabled        = true,
	.kerberos       = true,
	.priority       = GENSEC_KRB5
};

_PUBLIC_ NTSTATUS gensec_krb5_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = gensec_register(ctx, &gensec_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_krb5_security_ops.name));
		return ret;
	}

	ret = gensec_register(ctx, &gensec_fake_gssapi_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_fake_gssapi_krb5_security_ops.name));
		return ret;
	}

	return ret;
}

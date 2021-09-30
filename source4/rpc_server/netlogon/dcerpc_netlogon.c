/*
   Unix SMB/CIFS implementation.

   endpoint server for the netlogon pipe

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2008
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2005
   Copyright (C) Matthias Dieter Wallnöfer            2009-2010

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
#include "rpc_server/dcerpc_server.h"
#include "auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "dsdb/samdb/samdb.h"
#include "../lib/util/util_ldb.h"
#include "../libcli/auth/schannel.h"
#include "libcli/security/security.h"
#include "param/param.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "../libcli/ldap/ldap_ndr.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "librpc/gen_ndr/ndr_winbind.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "lib/socket/netif.h"
#include "rpc_server/common/sid_helper.h"
#include "lib/util/util_str_escape.h"

#define DCESRV_INTERFACE_NETLOGON_BIND(context, iface) \
       dcesrv_interface_netlogon_bind(context, iface)

/*
 * This #define allows the netlogon interface to accept invalid
 * association groups, because association groups are to coordinate
 * handles, and handles are not used in NETLOGON. This in turn avoids
 * the need to coordinate these across multiple possible NETLOGON
 * processes
 */
#define DCESRV_INTERFACE_NETLOGON_FLAGS DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED

static NTSTATUS dcesrv_interface_netlogon_bind(struct dcesrv_connection_context *context,
					       const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_reject_connect(context, iface);
}

#define NETLOGON_SERVER_PIPE_STATE_MAGIC 0x4f555358
struct netlogon_server_pipe_state {
	struct netr_Credential client_challenge;
	struct netr_Credential server_challenge;
};

static NTSTATUS dcesrv_netr_ServerReqChallenge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerReqChallenge *r)
{
	struct netlogon_server_pipe_state *pipe_state = NULL;
	NTSTATUS ntstatus;

	ZERO_STRUCTP(r->out.return_credentials);

	pipe_state = dcesrv_iface_state_find_conn(dce_call,
			NETLOGON_SERVER_PIPE_STATE_MAGIC,
			struct netlogon_server_pipe_state);
	TALLOC_FREE(pipe_state);

	pipe_state = talloc_zero(dce_call,
				 struct netlogon_server_pipe_state);
	if (pipe_state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pipe_state->client_challenge = *r->in.credentials;

	netlogon_creds_random_challenge(&pipe_state->server_challenge);

	*r->out.return_credentials = pipe_state->server_challenge;

	ntstatus = dcesrv_iface_state_store_conn(dce_call,
			NETLOGON_SERVER_PIPE_STATE_MAGIC,
			pipe_state);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		return ntstatus;
	}

	ntstatus = schannel_save_challenge(dce_call->conn->dce_ctx->lp_ctx,
					   &pipe_state->client_challenge,
					   &pipe_state->server_challenge,
					   r->in.computer_name);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		TALLOC_FREE(pipe_state);
		return ntstatus;
	}

	return NT_STATUS_OK;
}

/*
 * Do the actual processing of a netr_ServerAuthenticate3 message.
 * called from dcesrv_netr_ServerAuthenticate3, which handles the logging.
 */
static NTSTATUS dcesrv_netr_ServerAuthenticate3_helper(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct netr_ServerAuthenticate3 *r,
	const char **trust_account_for_search,
	const char **trust_account_in_db,
	struct dom_sid **sid)
{
	struct netlogon_server_pipe_state *pipe_state = NULL;
	bool challenge_valid = false;
	struct netlogon_server_pipe_state challenge;
	struct netlogon_creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	struct samr_Password *curNtHash = NULL;
	struct samr_Password *prevNtHash = NULL;
	uint32_t user_account_control;
	int num_records;
	struct ldb_message **msgs;
	NTSTATUS nt_status;
	const char *attrs[] = {"unicodePwd", "userAccountControl",
			       "objectSid", "samAccountName", NULL};
	uint32_t server_flags = 0;
	uint32_t negotiate_flags = 0;
	bool allow_nt4_crypto = lpcfg_allow_nt4_crypto(dce_call->conn->dce_ctx->lp_ctx);
	bool reject_des_client = !allow_nt4_crypto;
	bool reject_md5_client = lpcfg_reject_md5_clients(dce_call->conn->dce_ctx->lp_ctx);

	ZERO_STRUCTP(r->out.return_credentials);
	*r->out.rid = 0;

	pipe_state = dcesrv_iface_state_find_conn(dce_call,
			NETLOGON_SERVER_PIPE_STATE_MAGIC,
			struct netlogon_server_pipe_state);
	if (pipe_state != NULL) {
		/*
		 * If we had a challenge remembered on the connection
		 * consider this for usage. This can't be cleanup
		 * by other clients.
		 *
		 * This is the default code path for typical clients
		 * which call netr_ServerReqChallenge() and
		 * netr_ServerAuthenticate3() on the same dcerpc connection.
		 */
		challenge = *pipe_state;

		challenge_valid = true;

	} else {
		NTSTATUS ntstatus;

		/*
		 * Fallback and try to get the challenge from
		 * the global cache.
		 *
		 * If too many clients are using this code path,
		 * they may destroy their cache entries as the
		 * TDB has a fixed size limited via a lossy hash
		 *
		 * The TDB used is the schannel store, which is
		 * initialised at startup.
		 *
		 * NOTE: The challenge is deleted from the DB as soon as it is
		 * fetched, to prevent reuse.
		 *
		 */

		ntstatus = schannel_get_challenge(dce_call->conn->dce_ctx->lp_ctx,
						  &challenge.client_challenge,
						  &challenge.server_challenge,
						  r->in.computer_name);

		if (!NT_STATUS_IS_OK(ntstatus)) {
			ZERO_STRUCT(challenge);
		} else {
			challenge_valid = true;
		}
	}

	server_flags = NETLOGON_NEG_ACCOUNT_LOCKOUT |
		       NETLOGON_NEG_PERSISTENT_SAMREPL |
		       NETLOGON_NEG_ARCFOUR |
		       NETLOGON_NEG_PROMOTION_COUNT |
		       NETLOGON_NEG_CHANGELOG_BDC |
		       NETLOGON_NEG_FULL_SYNC_REPL |
		       NETLOGON_NEG_MULTIPLE_SIDS |
		       NETLOGON_NEG_REDO |
		       NETLOGON_NEG_PASSWORD_CHANGE_REFUSAL |
		       NETLOGON_NEG_SEND_PASSWORD_INFO_PDC |
		       NETLOGON_NEG_GENERIC_PASSTHROUGH |
		       NETLOGON_NEG_CONCURRENT_RPC |
		       NETLOGON_NEG_AVOID_ACCOUNT_DB_REPL |
		       NETLOGON_NEG_AVOID_SECURITYAUTH_DB_REPL |
		       NETLOGON_NEG_STRONG_KEYS |
		       NETLOGON_NEG_TRANSITIVE_TRUSTS |
		       NETLOGON_NEG_DNS_DOMAIN_TRUSTS |
		       NETLOGON_NEG_PASSWORD_SET2 |
		       NETLOGON_NEG_GETDOMAININFO |
		       NETLOGON_NEG_CROSS_FOREST_TRUSTS |
		       NETLOGON_NEG_NEUTRALIZE_NT4_EMULATION |
		       NETLOGON_NEG_RODC_PASSTHROUGH |
		       NETLOGON_NEG_SUPPORTS_AES |
		       NETLOGON_NEG_AUTHENTICATED_RPC_LSASS |
		       NETLOGON_NEG_AUTHENTICATED_RPC;

	negotiate_flags = *r->in.negotiate_flags & server_flags;

	if (negotiate_flags & NETLOGON_NEG_STRONG_KEYS) {
		reject_des_client = false;
	}

	if (negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		reject_des_client = false;
		reject_md5_client = false;
	}

	if (reject_des_client || reject_md5_client) {
		/*
		 * Here we match Windows 2012 and return no flags.
		 */
		*r->out.negotiate_flags = 0;
		return NT_STATUS_DOWNGRADE_DETECTED;
	}

	/*
	 * This talloc_free is important to prevent re-use of the
	 * challenge.  We have to delay it this far due to NETApp
	 * servers per:
	 * https://bugzilla.samba.org/show_bug.cgi?id=11291
	 */
	TALLOC_FREE(pipe_state);

	/*
	 * At this point we must also cleanup the TDB cache
	 * entry, if we fail the client needs to call
	 * netr_ServerReqChallenge again.
	 *
	 * Note: this handles a non existing record just fine,
	 * the r->in.computer_name might not be the one used
	 * in netr_ServerReqChallenge(), but we are trying to
	 * just tidy up the normal case to prevent re-use.
	 */
	schannel_delete_challenge(dce_call->conn->dce_ctx->lp_ctx,
				  r->in.computer_name);

	/*
	 * According to Microsoft (see bugid #6099)
	 * Windows 7 looks at the negotiate_flags
	 * returned in this structure *even if the
	 * call fails with access denied!
	 */
	*r->out.negotiate_flags = negotiate_flags;

	switch (r->in.secure_channel_type) {
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
	case SEC_CHAN_BDC:
	case SEC_CHAN_RODC:
		break;
	case SEC_CHAN_NULL:
		return NT_STATUS_INVALID_PARAMETER;
	default:
		DEBUG(1, ("Client asked for an invalid secure channel type: %d\n",
			  r->in.secure_channel_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	if (r->in.secure_channel_type == SEC_CHAN_DOMAIN ||
	    r->in.secure_channel_type == SEC_CHAN_DNS_DOMAIN)
	{
		struct ldb_message *tdo_msg = NULL;
		const char * const tdo_attrs[] = {
			"trustAuthIncoming",
			"trustAttributes",
			"flatName",
			NULL
		};
		char *encoded_name = NULL;
		size_t len;
		const char *flatname = NULL;
		char trailer = '$';
		bool require_trailer = true;
		const char *netbios = NULL;
		const char *dns = NULL;

		if (r->in.secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
			trailer = '.';
			require_trailer = false;
		}

		encoded_name = ldb_binary_encode_string(mem_ctx,
							r->in.account_name);
		if (encoded_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		len = strlen(encoded_name);
		if (len < 2) {
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}

		if (require_trailer && encoded_name[len - 1] != trailer) {
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
		encoded_name[len - 1] = '\0';

		if (r->in.secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
			dns = encoded_name;
		} else {
			netbios = encoded_name;
		}

		nt_status = dsdb_trust_search_tdo(sam_ctx,
						  netbios, dns,
						  tdo_attrs, mem_ctx, &tdo_msg);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			DEBUG(2, ("Client asked for a trusted domain secure channel, "
				  "but there's no tdo for [%s] => [%s] \n",
				  log_escape(mem_ctx, r->in.account_name),
				  encoded_name));
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		nt_status = dsdb_trust_get_incoming_passwords(tdo_msg, mem_ctx,
							      &curNtHash,
							      &prevNtHash);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_ACCOUNT_DISABLED)) {
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		flatname = ldb_msg_find_attr_as_string(tdo_msg, "flatName", NULL);
		if (flatname == NULL) {
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}

		*trust_account_for_search = talloc_asprintf(mem_ctx, "%s$", flatname);
		if (*trust_account_for_search == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		*trust_account_for_search = r->in.account_name;
	}

	/* pull the user attributes */
	num_records = gendb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
				   "(&(sAMAccountName=%s)(objectclass=user))",
				   ldb_binary_encode_string(mem_ctx,
							    *trust_account_for_search));

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in samdb.\n",
			 log_escape(mem_ctx, r->in.account_name)));
		return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
	}

	if (num_records > 1) {
		DEBUG(0,("Found %d records matching user [%s]\n",
			 num_records,
			 log_escape(mem_ctx, r->in.account_name)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*trust_account_in_db = ldb_msg_find_attr_as_string(msgs[0],
							   "samAccountName",
							   NULL);
	if (*trust_account_in_db == NULL) {
		DEBUG(0,("No samAccountName returned in record matching user [%s]\n",
			 r->in.account_name));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	user_account_control = ldb_msg_find_attr_as_uint(msgs[0], "userAccountControl", 0);

	if (user_account_control & UF_ACCOUNTDISABLE) {
		DEBUG(1, ("Account [%s] is disabled\n",
			  log_escape(mem_ctx, r->in.account_name)));
		return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
	}

	if (r->in.secure_channel_type == SEC_CHAN_WKSTA) {
		if (!(user_account_control & UF_WORKSTATION_TRUST_ACCOUNT)) {
			DEBUG(1, ("Client asked for a workstation secure channel, but is not a workstation (member server) acb flags: 0x%x\n", user_account_control));
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
	} else if (r->in.secure_channel_type == SEC_CHAN_DOMAIN ||
		   r->in.secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
		if (!(user_account_control & UF_INTERDOMAIN_TRUST_ACCOUNT)) {
			DEBUG(1, ("Client asked for a trusted domain secure channel, but is not a trusted domain: acb flags: 0x%x\n", user_account_control));

			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
	} else if (r->in.secure_channel_type == SEC_CHAN_BDC) {
		if (!(user_account_control & UF_SERVER_TRUST_ACCOUNT)) {
			DEBUG(1, ("Client asked for a server secure channel, but is not a server (domain controller): acb flags: 0x%x\n", user_account_control));
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
	} else if (r->in.secure_channel_type == SEC_CHAN_RODC) {
		if (!(user_account_control & UF_PARTIAL_SECRETS_ACCOUNT)) {
			DEBUG(1, ("Client asked for a RODC secure channel, but is not a RODC: acb flags: 0x%x\n", user_account_control));
			return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		}
	} else {
		/* we should never reach this */
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!(user_account_control & UF_INTERDOMAIN_TRUST_ACCOUNT)) {
		nt_status = samdb_result_passwords_no_lockout(mem_ctx,
					dce_call->conn->dce_ctx->lp_ctx,
					msgs[0], NULL, &curNtHash);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (curNtHash == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!challenge_valid) {
		DEBUG(1, ("No challenge requested by client [%s/%s], "
			  "cannot authenticate\n",
			  log_escape(mem_ctx, r->in.computer_name),
			  log_escape(mem_ctx, r->in.account_name)));
		return NT_STATUS_ACCESS_DENIED;
	}

	creds = netlogon_creds_server_init(mem_ctx,
					   r->in.account_name,
					   r->in.computer_name,
					   r->in.secure_channel_type,
					   &challenge.client_challenge,
					   &challenge.server_challenge,
					   curNtHash,
					   r->in.credentials,
					   r->out.return_credentials,
					   negotiate_flags);
	if (creds == NULL && prevNtHash != NULL) {
		/*
		 * We fallback to the previous password for domain trusts.
		 *
		 * Note that lpcfg_old_password_allowed_period() doesn't
		 * apply here.
		 */
		creds = netlogon_creds_server_init(mem_ctx,
						   r->in.account_name,
						   r->in.computer_name,
						   r->in.secure_channel_type,
						   &challenge.client_challenge,
						   &challenge.server_challenge,
						   prevNtHash,
						   r->in.credentials,
						   r->out.return_credentials,
						   negotiate_flags);
	}

	if (creds == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}
	creds->sid = samdb_result_dom_sid(creds, msgs[0], "objectSid");
	*sid = talloc_memdup(mem_ctx, creds->sid, sizeof(struct dom_sid));

	nt_status = schannel_save_creds_state(mem_ctx,
					      dce_call->conn->dce_ctx->lp_ctx,
					      creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ZERO_STRUCTP(r->out.return_credentials);
		return nt_status;
	}

	*r->out.rid = samdb_result_rid_from_sid(mem_ctx, msgs[0],
						"objectSid", 0);

	return NT_STATUS_OK;
}

/*
 * Log a netr_ServerAuthenticate3 request, and then invoke
 * dcesrv_netr_ServerAuthenticate3_helper to perform the actual processing
 */
static NTSTATUS dcesrv_netr_ServerAuthenticate3(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct netr_ServerAuthenticate3 *r)
{
	NTSTATUS status;
	struct dom_sid *sid = NULL;
	const char *trust_account_for_search = NULL;
	const char *trust_account_in_db = NULL;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	struct auth_usersupplied_info ui = {
		.local_host = dce_call->conn->local_address,
		.remote_host = dce_call->conn->remote_address,
		.client = {
			.account_name = r->in.account_name,
			.domain_name = lpcfg_workgroup(dce_call->conn->dce_ctx->lp_ctx),
		},
		.service_description = "NETLOGON",
		.auth_description = "ServerAuthenticate",
		.netlogon_trust_account = {
			.computer_name = r->in.computer_name,
			.negotiate_flags = *r->in.negotiate_flags,
			.secure_channel_type = r->in.secure_channel_type,
		},
	};

	status = dcesrv_netr_ServerAuthenticate3_helper(dce_call,
							mem_ctx,
							r,
							&trust_account_for_search,
							&trust_account_in_db,
							&sid);
	ui.netlogon_trust_account.sid = sid;
	ui.netlogon_trust_account.account_name = trust_account_in_db;
	ui.mapped.account_name = trust_account_for_search;
	log_authentication_event(
		imsg_ctx,
		dce_call->conn->dce_ctx->lp_ctx,
		NULL,
		&ui,
		status,
		lpcfg_workgroup(dce_call->conn->dce_ctx->lp_ctx),
		trust_account_in_db,
		sid);

	return status;
}
static NTSTATUS dcesrv_netr_ServerAuthenticate(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerAuthenticate *r)
{
	struct netr_ServerAuthenticate3 a;
	uint32_t rid;
	/* TODO:
	 * negotiate_flags is used as an [in] parameter
	 * so it need to be initialised.
	 *
	 * (I think ... = 0; seems wrong here --metze)
	 */
	uint32_t negotiate_flags_in = 0;
	uint32_t negotiate_flags_out = 0;

	a.in.server_name		= r->in.server_name;
	a.in.account_name		= r->in.account_name;
	a.in.secure_channel_type	= r->in.secure_channel_type;
	a.in.computer_name		= r->in.computer_name;
	a.in.credentials		= r->in.credentials;
	a.in.negotiate_flags		= &negotiate_flags_in;

	a.out.return_credentials	= r->out.return_credentials;
	a.out.rid			= &rid;
	a.out.negotiate_flags		= &negotiate_flags_out;

	return dcesrv_netr_ServerAuthenticate3(dce_call, mem_ctx, &a);
}

static NTSTATUS dcesrv_netr_ServerAuthenticate2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct netr_ServerAuthenticate2 *r)
{
	struct netr_ServerAuthenticate3 r3;
	uint32_t rid = 0;

	r3.in.server_name = r->in.server_name;
	r3.in.account_name = r->in.account_name;
	r3.in.secure_channel_type = r->in.secure_channel_type;
	r3.in.computer_name = r->in.computer_name;
	r3.in.credentials = r->in.credentials;
	r3.out.return_credentials = r->out.return_credentials;
	r3.in.negotiate_flags = r->in.negotiate_flags;
	r3.out.negotiate_flags = r->out.negotiate_flags;
	r3.out.rid = &rid;

	return dcesrv_netr_ServerAuthenticate3(dce_call, mem_ctx, &r3);
}

/*
 * NOTE: The following functions are nearly identical to the ones available in
 * source3/rpc_server/srv_nelog_nt.c
 * The reason we keep 2 copies is that they use different structures to
 * represent the auth_info and the decrpc pipes.
 */
static NTSTATUS dcesrv_netr_creds_server_step_check(struct dcesrv_call_state *dce_call,
						    TALLOC_CTX *mem_ctx,
						    const char *computer_name,
						    struct netr_Authenticator *received_authenticator,
						    struct netr_Authenticator *return_authenticator,
						    struct netlogon_creds_CredentialState **creds_out)
{
	NTSTATUS nt_status;
	int schannel = lpcfg_server_schannel(dce_call->conn->dce_ctx->lp_ctx);
	bool schannel_global_required = (schannel == true);
	bool schannel_required = schannel_global_required;
	const char *explicit_opt = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	uint16_t opnum = dce_call->pkt.u.request.opnum;
	const char *opname = "<unknown>";
	static bool warned_global_once = false;

	if (opnum < ndr_table_netlogon.num_calls) {
		opname = ndr_table_netlogon.calls[opnum].name;
	}

	dcesrv_call_auth_info(dce_call, &auth_type, NULL);

	nt_status = schannel_check_creds_state(mem_ctx,
					       dce_call->conn->dce_ctx->lp_ctx,
					       computer_name,
					       received_authenticator,
					       return_authenticator,
					       &creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ZERO_STRUCTP(return_authenticator);
		return nt_status;
	}

	/*
	 * We don't use lpcfg_parm_bool(), as we
	 * need the explicit_opt pointer in order to
	 * adjust the debug messages.
	 */
	explicit_opt = lpcfg_get_parametric(dce_call->conn->dce_ctx->lp_ctx,
					    NULL,
					    "server require schannel",
					    creds->account_name);
	if (explicit_opt != NULL) {
		schannel_required = lp_bool(explicit_opt);
	}

	if (schannel_required) {
		if (auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
			*creds_out = creds;
			return NT_STATUS_OK;
		}

		DBG_ERR("CVE-2020-1472(ZeroLogon): "
			"%s request (opnum[%u]) without schannel from "
			"client_account[%s] client_computer_name[%s]\n",
			opname, opnum,
			log_escape(mem_ctx, creds->account_name),
			log_escape(mem_ctx, creds->computer_name));
		DBG_ERR("CVE-2020-1472(ZeroLogon): Check if option "
			"'server require schannel:%s = no' is needed! \n",
			log_escape(mem_ctx, creds->account_name));
		TALLOC_FREE(creds);
		ZERO_STRUCTP(return_authenticator);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!schannel_global_required && !warned_global_once) {
		/*
		 * We want admins to notice their misconfiguration!
		 */
		DBG_ERR("CVE-2020-1472(ZeroLogon): "
			"Please configure 'server schannel = yes', "
			"See https://bugzilla.samba.org/show_bug.cgi?id=14497\n");
		warned_global_once = true;
	}

	if (auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		DBG_ERR("CVE-2020-1472(ZeroLogon): "
			"%s request (opnum[%u]) WITH schannel from "
			"client_account[%s] client_computer_name[%s]\n",
			opname, opnum,
			log_escape(mem_ctx, creds->account_name),
			log_escape(mem_ctx, creds->computer_name));
		DBG_ERR("CVE-2020-1472(ZeroLogon): "
			"Option 'server require schannel:%s = no' not needed!?\n",
			log_escape(mem_ctx, creds->account_name));

		*creds_out = creds;
		return NT_STATUS_OK;
	}


	if (explicit_opt != NULL) {
		DBG_INFO("CVE-2020-1472(ZeroLogon): "
			 "%s request (opnum[%u]) without schannel from "
			 "client_account[%s] client_computer_name[%s]\n",
			 opname, opnum,
			 log_escape(mem_ctx, creds->account_name),
			 log_escape(mem_ctx, creds->computer_name));
		DBG_INFO("CVE-2020-1472(ZeroLogon): "
			 "Option 'server require schannel:%s = no' still needed!\n",
			 log_escape(mem_ctx, creds->account_name));
	} else {
		DBG_ERR("CVE-2020-1472(ZeroLogon): "
			"%s request (opnum[%u]) without schannel from "
			"client_account[%s] client_computer_name[%s]\n",
			opname, opnum,
			log_escape(mem_ctx, creds->account_name),
			log_escape(mem_ctx, creds->computer_name));
		DBG_ERR("CVE-2020-1472(ZeroLogon): Check if option "
			"'server require schannel:%s = no' might be needed!\n",
			log_escape(mem_ctx, creds->account_name));
	}

	*creds_out = creds;
	return NT_STATUS_OK;
}

/*
  Change the machine account password for the currently connected
  client.  Supplies only the NT#.
*/

static NTSTATUS dcesrv_netr_ServerPasswordSet(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_ServerPasswordSet *r)
{
	struct netlogon_creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	const char * const attrs[] = { "unicodePwd", NULL };
	struct ldb_message **res;
	struct samr_Password *oldNtHash;
	NTSTATUS nt_status;
	int ret;

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential, r->out.return_authenticator,
							&creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	nt_status = netlogon_creds_des_decrypt(creds, r->in.new_password);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	/* fetch the old password hashes (the NT hash has to exist) */

	ret = gendb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
			   "(&(objectClass=user)(objectSid=%s))",
			   ldap_encode_ndr_dom_sid(mem_ctx, creds->sid));
	if (ret != 1) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	nt_status = samdb_result_passwords_no_lockout(mem_ctx,
						      dce_call->conn->dce_ctx->lp_ctx,
						      res[0], NULL, &oldNtHash);
	if (!NT_STATUS_IS_OK(nt_status) || !oldNtHash) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* Using the sid for the account as the key, set the password */
	nt_status = samdb_set_password_sid(sam_ctx, mem_ctx,
					   creds->sid,
					   NULL, /* Don't have version */
					   NULL, /* Don't have plaintext */
					   NULL, r->in.new_password,
					   NULL, oldNtHash, /* Password change */
					   NULL, NULL);
	return nt_status;
}

/*
  Change the machine account password for the currently connected
  client.  Supplies new plaintext.
*/
static NTSTATUS dcesrv_netr_ServerPasswordSet2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_ServerPasswordSet2 *r)
{
	struct netlogon_creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	const char * const attrs[] = { "dBCSPwd", "unicodePwd", NULL };
	struct ldb_message **res;
	struct samr_Password *oldLmHash, *oldNtHash;
	struct NL_PASSWORD_VERSION version = {};
	const uint32_t *new_version = NULL;
	NTSTATUS nt_status;
	DATA_BLOB new_password = data_blob_null;
	size_t confounder_len;
	DATA_BLOB dec_blob = data_blob_null;
	DATA_BLOB enc_blob = data_blob_null;
	int ret;
	struct samr_CryptPassword password_buf;

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential, r->out.return_authenticator,
							&creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	memcpy(password_buf.data, r->in.new_password->data, 512);
	SIVAL(password_buf.data, 512, r->in.new_password->length);

	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		nt_status = netlogon_creds_aes_decrypt(creds,
						       password_buf.data,
						       516);
	} else {
		nt_status = netlogon_creds_arcfour_crypt(creds,
							 password_buf.data,
							 516);
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	switch (creds->secure_channel_type) {
	case SEC_CHAN_DOMAIN:
	case SEC_CHAN_DNS_DOMAIN: {
		uint32_t len = IVAL(password_buf.data, 512);
		if (len <= 500) {
			uint32_t ofs = 500 - len;
			uint8_t *p;

			p = password_buf.data + ofs;

			version.ReservedField = IVAL(p, 0);
			version.PasswordVersionNumber = IVAL(p, 4);
			version.PasswordVersionPresent = IVAL(p, 8);

			if (version.PasswordVersionPresent == NETLOGON_PASSWORD_VERSION_NUMBER_PRESENT) {
				new_version = &version.PasswordVersionNumber;
			}
		}}
		break;
	default:
		break;
	}

	if (!extract_pw_from_buffer(mem_ctx, password_buf.data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Make sure the length field was encrypted,
	 * otherwise we are under attack.
	 */
	if (new_password.length == r->in.new_password->length) {
		DBG_WARNING("Length[%zu] field not encrypted\n",
			    new_password.length);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * We don't allow empty passwords for machine accounts.
	 */
	if (new_password.length < 2) {
		DBG_WARNING("Empty password Length[%zu]\n",
			    new_password.length);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Make sure the confounder part of CryptPassword
	 * buffer was encrypted, otherwise we are under attack.
	 */
	confounder_len = 512 - new_password.length;
	enc_blob = data_blob_const(r->in.new_password->data, confounder_len);
	dec_blob = data_blob_const(password_buf.data, confounder_len);
	if (data_blob_cmp(&dec_blob, &enc_blob) == 0) {
		DBG_WARNING("Confounder buffer not encrypted Length[%zu]\n",
			    confounder_len);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Check that the password part was actually encrypted,
	 * otherwise we are under attack.
	 */
	enc_blob = data_blob_const(r->in.new_password->data + confounder_len,
				   new_password.length);
	dec_blob = data_blob_const(password_buf.data + confounder_len,
				   new_password.length);
	if (data_blob_cmp(&dec_blob, &enc_blob) == 0) {
		DBG_WARNING("Password buffer not encrypted Length[%zu]\n",
			    new_password.length);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * don't allow zero buffers
	 */
	if (all_zero(new_password.data, new_password.length)) {
		DBG_WARNING("Password zero buffer Length[%zu]\n",
			    new_password.length);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* fetch the old password hashes (at least one of both has to exist) */

	ret = gendb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
			   "(&(objectClass=user)(objectSid=%s))",
			   ldap_encode_ndr_dom_sid(mem_ctx, creds->sid));
	if (ret != 1) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	nt_status = samdb_result_passwords_no_lockout(mem_ctx,
						      dce_call->conn->dce_ctx->lp_ctx,
						      res[0], &oldLmHash, &oldNtHash);
	if (!NT_STATUS_IS_OK(nt_status) || (!oldLmHash && !oldNtHash)) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* Using the sid for the account as the key, set the password */
	nt_status = samdb_set_password_sid(sam_ctx, mem_ctx,
					   creds->sid,
					   new_version,
					   &new_password, /* we have plaintext */
					   NULL, NULL,
					   oldLmHash, oldNtHash, /* Password change */
					   NULL, NULL);
	return nt_status;
}


/*
  netr_LogonUasLogon
*/
static WERROR dcesrv_netr_LogonUasLogon(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct netr_LogonUasLogon *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_LogonUasLogoff
*/
static WERROR dcesrv_netr_LogonUasLogoff(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonUasLogoff *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


static NTSTATUS dcesrv_netr_LogonSamLogon_check(struct dcesrv_call_state *dce_call,
						const struct netr_LogonSamLogonEx *r)
{
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		if (r->in.logon->password == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		switch (r->in.validation_level) {
		case NetlogonValidationSamInfo:  /* 2 */
		case NetlogonValidationSamInfo2: /* 3 */
		case NetlogonValidationSamInfo4: /* 6 */
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		if (r->in.logon->network == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		switch (r->in.validation_level) {
		case NetlogonValidationSamInfo:  /* 2 */
		case NetlogonValidationSamInfo2: /* 3 */
		case NetlogonValidationSamInfo4: /* 6 */
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;

	case NetlogonGenericInformation:
		if (r->in.logon->generic == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		switch (r->in.validation_level) {
		/* TODO: case NetlogonValidationGenericInfo: 4 */
		case NetlogonValidationGenericInfo2: /* 5 */
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	dcesrv_call_auth_info(dce_call, NULL, &auth_level);

	switch (r->in.validation_level) {
	case NetlogonValidationSamInfo4: /* 6 */
		if (auth_level < DCERPC_AUTH_LEVEL_PRIVACY) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		break;

	default:
		break;
	}

	return NT_STATUS_OK;
}

struct dcesrv_netr_LogonSamLogon_base_state {
	struct dcesrv_call_state *dce_call;

	TALLOC_CTX *mem_ctx;

	struct netlogon_creds_CredentialState *creds;

	struct netr_LogonSamLogonEx r;

	uint32_t _ignored_flags;

	struct {
		struct netr_LogonSamLogon *lsl;
		struct netr_LogonSamLogonWithFlags *lslwf;
		struct netr_LogonSamLogonEx *lslex;
	} _r;

	struct kdc_check_generic_kerberos kr;
};

static void dcesrv_netr_LogonSamLogon_base_auth_done(struct tevent_req *subreq);
static void dcesrv_netr_LogonSamLogon_base_krb5_done(struct tevent_req *subreq);
static void dcesrv_netr_LogonSamLogon_base_reply(
	struct dcesrv_netr_LogonSamLogon_base_state *state);

/*
  netr_LogonSamLogon_base

  This version of the function allows other wrappers to say 'do not check the credentials'

  We can't do the traditional 'wrapping' format completely, as this
  function must only run under schannel
*/
static NTSTATUS dcesrv_netr_LogonSamLogon_base_call(struct dcesrv_netr_LogonSamLogon_base_state *state)
{
	struct dcesrv_call_state *dce_call = state->dce_call;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	TALLOC_CTX *mem_ctx = state->mem_ctx;
	struct netr_LogonSamLogonEx *r = &state->r;
	struct netlogon_creds_CredentialState *creds = state->creds;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const char *workgroup = lpcfg_workgroup(lp_ctx);
	struct auth4_context *auth_context = NULL;
	struct auth_usersupplied_info *user_info = NULL;
	NTSTATUS nt_status;
	struct tevent_req *subreq = NULL;

	*r->out.authoritative = 1;

	if (*r->in.flags & NETLOGON_SAMLOGON_FLAG_PASS_TO_FOREST_ROOT) {
		/*
		 * Currently we're always the forest root ourself.
		 */
		return NT_STATUS_NO_SUCH_USER;
	}

	if (*r->in.flags & NETLOGON_SAMLOGON_FLAG_PASS_CROSS_FOREST_HOP) {
		/*
		 * Currently we don't support trusts correctly yet.
		 */
		return NT_STATUS_NO_SUCH_USER;
	}

	user_info = talloc_zero(mem_ctx, struct auth_usersupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info);

	user_info->service_description = "SamLogon";

	nt_status = netlogon_creds_decrypt_samlogon_logon(creds,
							  r->in.logon_level,
							  r->in.logon);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:

		nt_status = auth_context_create_for_netlogon(mem_ctx,
					dce_call->event_ctx,
					imsg_ctx,
					dce_call->conn->dce_ctx->lp_ctx,
					&auth_context);
		NT_STATUS_NOT_OK_RETURN(nt_status);

		user_info->remote_host = dce_call->conn->remote_address;
		user_info->local_host = dce_call->conn->local_address;

		user_info->netlogon_trust_account.secure_channel_type
			= creds->secure_channel_type;
		user_info->netlogon_trust_account.negotiate_flags
			= creds->negotiate_flags;

		/*
		 * These two can be unrelated when the account is
		 * actually that of a trusted domain, so we want to
		 * know which DC in that trusted domain contacted
		 * us
		 */
		user_info->netlogon_trust_account.computer_name
			= creds->computer_name;
		user_info->netlogon_trust_account.account_name
			= creds->account_name;
		user_info->netlogon_trust_account.sid
			= creds->sid;

	default:
		/* We do not need to set up the user_info in this case */
		break;
	}

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		user_info->auth_description = "interactive";

		user_info->logon_parameters
			= r->in.logon->password->identity_info.parameter_control;
		user_info->client.account_name
			= r->in.logon->password->identity_info.account_name.string;
		user_info->client.domain_name
			= r->in.logon->password->identity_info.domain_name.string;
		user_info->workstation_name
			= r->in.logon->password->identity_info.workstation.string;
		user_info->flags |= USER_INFO_INTERACTIVE_LOGON;
		user_info->password_state = AUTH_PASSWORD_HASH;

		user_info->password.hash.lanman = talloc(user_info, struct samr_Password);
		NT_STATUS_HAVE_NO_MEMORY(user_info->password.hash.lanman);
		*user_info->password.hash.lanman = r->in.logon->password->lmpassword;

		user_info->password.hash.nt = talloc(user_info, struct samr_Password);
		NT_STATUS_HAVE_NO_MEMORY(user_info->password.hash.nt);
		*user_info->password.hash.nt = r->in.logon->password->ntpassword;

		user_info->logon_id
		    = r->in.logon->password->identity_info.logon_id;

		break;
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		user_info->auth_description = "network";

		nt_status = auth_context_set_challenge(
			auth_context,
			r->in.logon->network->challenge,
			"netr_LogonSamLogonWithFlags");
		NT_STATUS_NOT_OK_RETURN(nt_status);

		user_info->logon_parameters
			= r->in.logon->network->identity_info.parameter_control;
		user_info->client.account_name
			= r->in.logon->network->identity_info.account_name.string;
		user_info->client.domain_name
			= r->in.logon->network->identity_info.domain_name.string;
		user_info->workstation_name
			= r->in.logon->network->identity_info.workstation.string;

		user_info->password_state = AUTH_PASSWORD_RESPONSE;
		user_info->password.response.lanman = data_blob_talloc(mem_ctx, r->in.logon->network->lm.data, r->in.logon->network->lm.length);
		user_info->password.response.nt = data_blob_talloc(mem_ctx, r->in.logon->network->nt.data, r->in.logon->network->nt.length);

		user_info->logon_id
		    = r->in.logon->network->identity_info.logon_id;

		nt_status = NTLMv2_RESPONSE_verify_netlogon_creds(
					user_info->client.account_name,
					user_info->client.domain_name,
					user_info->password.response.nt,
					creds, workgroup);
		NT_STATUS_NOT_OK_RETURN(nt_status);

		break;


	case NetlogonGenericInformation:
	{
		if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			/* OK */
		} else if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			/* OK */
		} else {
			/* Using DES to verify kerberos tickets makes no sense */
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (strcmp(r->in.logon->generic->package_name.string, "Kerberos") == 0) {
			struct dcerpc_binding_handle *irpc_handle;
			struct netr_GenericInfo2 *generic = talloc_zero(mem_ctx, struct netr_GenericInfo2);
			NT_STATUS_HAVE_NO_MEMORY(generic);

			r->out.validation->generic = generic;

			user_info->logon_id
			    = r->in.logon->generic->identity_info.logon_id;

			irpc_handle = irpc_binding_handle_by_name(mem_ctx,
								  imsg_ctx,
								  "kdc_server",
								  &ndr_table_irpc);
			if (irpc_handle == NULL) {
				return NT_STATUS_NO_LOGON_SERVERS;
			}

			state->kr.in.generic_request =
				data_blob_const(r->in.logon->generic->data,
						r->in.logon->generic->length);

			/*
			 * 60 seconds should be enough
			 */
			dcerpc_binding_handle_set_timeout(irpc_handle, 60);
			subreq = dcerpc_kdc_check_generic_kerberos_r_send(state,
						state->dce_call->event_ctx,
						irpc_handle, &state->kr);
			if (subreq == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
			tevent_req_set_callback(subreq,
					dcesrv_netr_LogonSamLogon_base_krb5_done,
					state);
			return NT_STATUS_OK;
		}

		/* Until we get an implemetnation of these other packages */
		return NT_STATUS_INVALID_PARAMETER;
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	subreq = auth_check_password_send(state, state->dce_call->event_ctx,
					  auth_context, user_info);
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	tevent_req_set_callback(subreq,
				dcesrv_netr_LogonSamLogon_base_auth_done,
				state);
	return NT_STATUS_OK;
}

static void dcesrv_netr_LogonSamLogon_base_auth_done(struct tevent_req *subreq)
{
	struct dcesrv_netr_LogonSamLogon_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_netr_LogonSamLogon_base_state);
	TALLOC_CTX *mem_ctx = state->mem_ctx;
	struct netr_LogonSamLogonEx *r = &state->r;
	struct auth_user_info_dc *user_info_dc = NULL;
	struct netr_SamInfo2 *sam2 = NULL;
	struct netr_SamInfo3 *sam3 = NULL;
	struct netr_SamInfo6 *sam6 = NULL;
	NTSTATUS nt_status;

	nt_status = auth_check_password_recv(subreq, mem_ctx,
					     &user_info_dc,
					     r->out.authoritative);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(nt_status)) {
		r->out.result = nt_status;
		dcesrv_netr_LogonSamLogon_base_reply(state);
		return;
	}

	switch (r->in.validation_level) {
	case 2:
		nt_status = auth_convert_user_info_dc_saminfo2(mem_ctx,
							       user_info_dc,
							       &sam2);
		if (!NT_STATUS_IS_OK(nt_status)) {
			r->out.result = nt_status;
			dcesrv_netr_LogonSamLogon_base_reply(state);
			return;
		}

		r->out.validation->sam2 = sam2;
		break;

	case 3:
		nt_status = auth_convert_user_info_dc_saminfo3(mem_ctx,
							       user_info_dc,
							       &sam3);
		if (!NT_STATUS_IS_OK(nt_status)) {
			r->out.result = nt_status;
			dcesrv_netr_LogonSamLogon_base_reply(state);
			return;
		}

		r->out.validation->sam3 = sam3;
		break;

	case 6:
		nt_status = auth_convert_user_info_dc_saminfo6(mem_ctx,
							       user_info_dc,
							       &sam6);
		if (!NT_STATUS_IS_OK(nt_status)) {
			r->out.result = nt_status;
			dcesrv_netr_LogonSamLogon_base_reply(state);
			return;
		}

		r->out.validation->sam6 = sam6;
		break;

	default:
		if (!NT_STATUS_IS_OK(nt_status)) {
			r->out.result = NT_STATUS_INVALID_INFO_CLASS;
			dcesrv_netr_LogonSamLogon_base_reply(state);
			return;
		}
	}

	/* TODO: Describe and deal with these flags */
	*r->out.flags = 0;

	r->out.result = NT_STATUS_OK;

	dcesrv_netr_LogonSamLogon_base_reply(state);
}

static void dcesrv_netr_LogonSamLogon_base_krb5_done(struct tevent_req *subreq)
{
	struct dcesrv_netr_LogonSamLogon_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_netr_LogonSamLogon_base_state);
	TALLOC_CTX *mem_ctx = state->mem_ctx;
	struct netr_LogonSamLogonEx *r = &state->r;
	struct netr_GenericInfo2 *generic = NULL;
	NTSTATUS status;

	status = dcerpc_kdc_check_generic_kerberos_r_recv(subreq, mem_ctx);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.result = status;
		dcesrv_netr_LogonSamLogon_base_reply(state);
		return;
	}

	generic = r->out.validation->generic;
	generic->length = state->kr.out.generic_reply.length;
	generic->data = state->kr.out.generic_reply.data;

	/* TODO: Describe and deal with these flags */
	*r->out.flags = 0;

	r->out.result = NT_STATUS_OK;

	dcesrv_netr_LogonSamLogon_base_reply(state);
}

static void dcesrv_netr_LogonSamLogon_base_reply(
	struct dcesrv_netr_LogonSamLogon_base_state *state)
{
	struct netr_LogonSamLogonEx *r = &state->r;
	NTSTATUS status;

	if (NT_STATUS_IS_OK(r->out.result)) {
		status = netlogon_creds_encrypt_samlogon_validation(state->creds,
								    r->in.validation_level,
								    r->out.validation);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("netlogon_creds_encrypt_samlogon_validation() "
				"failed - %s\n",
				nt_errstr(status));
		}
	}

	if (state->_r.lslex != NULL) {
		struct netr_LogonSamLogonEx *_r = state->_r.lslex;
		_r->out.result = r->out.result;
	} else if (state->_r.lslwf != NULL) {
		struct netr_LogonSamLogonWithFlags *_r = state->_r.lslwf;
		_r->out.result = r->out.result;
	} else if (state->_r.lsl != NULL) {
		struct netr_LogonSamLogon *_r = state->_r.lsl;
		_r->out.result = r->out.result;
	}

	status = dcesrv_reply(state->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dcesrv_reply() failed - %s\n",
			nt_errstr(status));
	}
}

static NTSTATUS dcesrv_netr_LogonSamLogonEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct netr_LogonSamLogonEx *r)
{
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	struct dcesrv_netr_LogonSamLogon_base_state *state;
	NTSTATUS nt_status;

	*r->out.authoritative = 1;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonSamLogon_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.server_name      = r->in.server_name;
	state->r.in.computer_name    = r->in.computer_name;
	state->r.in.logon_level      = r->in.logon_level;
	state->r.in.logon            = r->in.logon;
	state->r.in.validation_level = r->in.validation_level;
	state->r.in.flags            = r->in.flags;
	state->r.out.validation      = r->out.validation;
	state->r.out.authoritative   = r->out.authoritative;
	state->r.out.flags           = r->out.flags;

	state->_r.lslex = r;

	nt_status = dcesrv_netr_LogonSamLogon_check(dce_call, &state->r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = schannel_get_creds_state(mem_ctx,
					     dce_call->conn->dce_ctx->lp_ctx,
					     r->in.computer_name, &state->creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	dcesrv_call_auth_info(dce_call, &auth_type, NULL);

	if (auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	nt_status = dcesrv_netr_LogonSamLogon_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return nt_status;
	}

	return nt_status;
}

/*
  netr_LogonSamLogonWithFlags

*/
static NTSTATUS dcesrv_netr_LogonSamLogonWithFlags(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct netr_LogonSamLogonWithFlags *r)
{
	struct dcesrv_netr_LogonSamLogon_base_state *state;
	NTSTATUS nt_status;

	*r->out.authoritative = 1;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonSamLogon_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.server_name      = r->in.server_name;
	state->r.in.computer_name    = r->in.computer_name;
	state->r.in.logon_level      = r->in.logon_level;
	state->r.in.logon            = r->in.logon;
	state->r.in.validation_level = r->in.validation_level;
	state->r.in.flags            = r->in.flags;
	state->r.out.validation      = r->out.validation;
	state->r.out.authoritative   = r->out.authoritative;
	state->r.out.flags           = r->out.flags;

	state->_r.lslwf = r;

	nt_status = dcesrv_netr_LogonSamLogon_check(dce_call, &state->r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	r->out.return_authenticator = talloc_zero(mem_ctx,
						  struct netr_Authenticator);
	if (r->out.return_authenticator == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential,
							r->out.return_authenticator,
							&state->creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = dcesrv_netr_LogonSamLogon_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return nt_status;
	}

	return nt_status;
}

/*
  netr_LogonSamLogon
*/
static NTSTATUS dcesrv_netr_LogonSamLogon(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct netr_LogonSamLogon *r)
{
	struct dcesrv_netr_LogonSamLogon_base_state *state;
	NTSTATUS nt_status;

	*r->out.authoritative = 1;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonSamLogon_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.server_name      = r->in.server_name;
	state->r.in.computer_name    = r->in.computer_name;
	state->r.in.logon_level      = r->in.logon_level;
	state->r.in.logon            = r->in.logon;
	state->r.in.validation_level = r->in.validation_level;
	state->r.in.flags            = &state->_ignored_flags;
	state->r.out.validation      = r->out.validation;
	state->r.out.authoritative   = r->out.authoritative;
	state->r.out.flags           = &state->_ignored_flags;

	state->_r.lsl = r;

	nt_status = dcesrv_netr_LogonSamLogon_check(dce_call, &state->r);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	r->out.return_authenticator = talloc_zero(mem_ctx,
						  struct netr_Authenticator);
	if (r->out.return_authenticator == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential,
							r->out.return_authenticator,
							&state->creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = dcesrv_netr_LogonSamLogon_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return nt_status;
	}

	return nt_status;
}


/*
  netr_LogonSamLogoff
*/
static NTSTATUS dcesrv_netr_LogonSamLogoff(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonSamLogoff *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/*
  netr_DatabaseDeltas
*/
static NTSTATUS dcesrv_netr_DatabaseDeltas(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseDeltas *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_DatabaseSync2
*/
static NTSTATUS dcesrv_netr_DatabaseSync2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseSync2 *r)
{
	/* win2k3 native mode returns  "NOT IMPLEMENTED" for this call */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  netr_DatabaseSync
*/
static NTSTATUS dcesrv_netr_DatabaseSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseSync *r)
{
	struct netr_DatabaseSync2 r2;
	NTSTATUS status;

	ZERO_STRUCT(r2);

	r2.in.logon_server = r->in.logon_server;
	r2.in.computername = r->in.computername;
	r2.in.credential = r->in.credential;
	r2.in.database_id = r->in.database_id;
	r2.in.restart_state = SYNCSTATE_NORMAL_STATE;
	r2.in.sync_context = r->in.sync_context;
	r2.out.sync_context = r->out.sync_context;
	r2.out.delta_enum_array = r->out.delta_enum_array;
	r2.in.preferredmaximumlength = r->in.preferredmaximumlength;

	status = dcesrv_netr_DatabaseSync2(dce_call, mem_ctx, &r2);

	return status;
}


/*
  netr_AccountDeltas
*/
static NTSTATUS dcesrv_netr_AccountDeltas(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_AccountDeltas *r)
{
	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  netr_AccountSync
*/
static NTSTATUS dcesrv_netr_AccountSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_AccountSync *r)
{
	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  netr_GetDcName
*/
static WERROR dcesrv_netr_GetDcName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_GetDcName *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	const char * const attrs[] = { NULL };
	struct ldb_context *sam_ctx;
	struct ldb_message **res;
	struct ldb_dn *domain_dn;
	int ret;
	const char *dcname;

	/*
	 * [MS-NRPC] 3.5.5.3.4 NetrGetDCName says
	 * that the domainname needs to be a valid netbios domain
	 * name, if it is not NULL.
	 */
	if (r->in.domainname) {
		const char *dot = strchr(r->in.domainname, '.');
		size_t len = strlen(r->in.domainname);

		if (dot || len > 15) {
			return WERR_NERR_DCNOTFOUND;
		}

		/*
		 * TODO: Should we also varify that only valid
		 *       netbios name characters are used?
		 */
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	domain_dn = samdb_domain_to_dn(sam_ctx, mem_ctx,
				       r->in.domainname);
	if (domain_dn == NULL) {
		return WERR_NO_SUCH_DOMAIN;
	}

	ret = gendb_search_dn(sam_ctx, mem_ctx,
			      domain_dn, &res, attrs);
	if (ret != 1) {
		return WERR_NO_SUCH_DOMAIN;
	}

	/* TODO: - return real IP address
	 *       - check all r->in.* parameters (server_unc is ignored by w2k3!)
	 */
	dcname = talloc_asprintf(mem_ctx, "\\\\%s",
				 lpcfg_netbios_name(dce_call->conn->dce_ctx->lp_ctx));
	W_ERROR_HAVE_NO_MEMORY(dcname);

	*r->out.dcname = dcname;
	return WERR_OK;
}

struct dcesrv_netr_LogonControl_base_state {
	struct dcesrv_call_state *dce_call;

	TALLOC_CTX *mem_ctx;

	struct netr_LogonControl2Ex r;

	struct {
		struct netr_LogonControl *l;
		struct netr_LogonControl2 *l2;
		struct netr_LogonControl2Ex *l2ex;
	} _r;
};

static void dcesrv_netr_LogonControl_base_done(struct tevent_req *subreq);

static WERROR dcesrv_netr_LogonControl_base_call(struct dcesrv_netr_LogonControl_base_state *state)
{
	struct loadparm_context *lp_ctx = state->dce_call->conn->dce_ctx->lp_ctx;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(state->dce_call);
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(state->dce_call->conn);
	enum security_user_level security_level;
	struct dcerpc_binding_handle *irpc_handle;
	struct tevent_req *subreq;
	bool ok;

	/* TODO: check for WERR_INVALID_COMPUTERNAME ? */

	if (state->_r.l != NULL) {
		/*
		 * netr_LogonControl
		 */
		if (state->r.in.level == 0x00000002) {
			return WERR_NOT_SUPPORTED;
		} else if (state->r.in.level != 0x00000001) {
			return WERR_INVALID_LEVEL;
		}

		switch (state->r.in.function_code) {
		case NETLOGON_CONTROL_QUERY:
		case NETLOGON_CONTROL_REPLICATE:
		case NETLOGON_CONTROL_SYNCHRONIZE:
		case NETLOGON_CONTROL_PDC_REPLICATE:
		case NETLOGON_CONTROL_BREAKPOINT:
		case NETLOGON_CONTROL_BACKUP_CHANGE_LOG:
		case NETLOGON_CONTROL_TRUNCATE_LOG:
			break;
		default:
			return WERR_NOT_SUPPORTED;
		}
	}

	if (state->r.in.level < 0x00000001) {
		return WERR_INVALID_LEVEL;
	}

	if (state->r.in.level > 0x00000004) {
		return WERR_INVALID_LEVEL;
	}

	if (state->r.in.function_code == NETLOGON_CONTROL_QUERY) {
		struct netr_NETLOGON_INFO_1 *info1 = NULL;
		struct netr_NETLOGON_INFO_3 *info3 = NULL;

		switch (state->r.in.level) {
		case 0x00000001:
			info1 = talloc_zero(state->mem_ctx,
					    struct netr_NETLOGON_INFO_1);
			if (info1 == NULL) {
				return WERR_NOT_ENOUGH_MEMORY;
			}
			state->r.out.query->info1 = info1;
			return WERR_OK;

		case 0x00000003:
			info3 = talloc_zero(state->mem_ctx,
					    struct netr_NETLOGON_INFO_3);
			if (info3 == NULL) {
				return WERR_NOT_ENOUGH_MEMORY;
			}
			state->r.out.query->info3 = info3;
			return WERR_OK;

		default:
			return WERR_INVALID_PARAMETER;
		}
	}

	/*
	 * Some validations are done before the access check
	 * and some after the access check
	 */
	security_level = security_session_user_level(session_info, NULL);
	if (security_level < SECURITY_ADMINISTRATOR) {
		return WERR_ACCESS_DENIED;
	}

	if (state->_r.l2 != NULL) {
		/*
		 * netr_LogonControl2
		 */
		if (state->r.in.level == 0x00000004) {
			return WERR_INVALID_LEVEL;
		}
	}

	switch (state->r.in.level) {
	case 0x00000001:
		break;

	case 0x00000002:
		switch (state->r.in.function_code) {
		case NETLOGON_CONTROL_REDISCOVER:
		case NETLOGON_CONTROL_TC_QUERY:
		case NETLOGON_CONTROL_TC_VERIFY:
			break;
		default:
			return WERR_INVALID_PARAMETER;
		}

		break;

	case 0x00000003:
		break;

	case 0x00000004:
		if (state->r.in.function_code != NETLOGON_CONTROL_FIND_USER) {
			return WERR_INVALID_PARAMETER;
		}

		break;

	default:
		return WERR_INVALID_LEVEL;
	}

	switch (state->r.in.function_code) {
	case NETLOGON_CONTROL_REDISCOVER:
	case NETLOGON_CONTROL_TC_QUERY:
	case NETLOGON_CONTROL_TC_VERIFY:
		if (state->r.in.level != 2) {
			return WERR_INVALID_PARAMETER;
		}

		if (state->r.in.data == NULL) {
			return WERR_INVALID_PARAMETER;
		}

		if (state->r.in.data->domain == NULL) {
			return WERR_INVALID_PARAMETER;
		}

		break;

	case NETLOGON_CONTROL_CHANGE_PASSWORD:
		if (state->r.in.level != 1) {
			return WERR_INVALID_PARAMETER;
		}

		if (state->r.in.data == NULL) {
			return WERR_INVALID_PARAMETER;
		}

		if (state->r.in.data->domain == NULL) {
			return WERR_INVALID_PARAMETER;
		}

		ok = lpcfg_is_my_domain_or_realm(lp_ctx,
						 state->r.in.data->domain);
		if (!ok) {
			struct ldb_context *sam_ctx;

			sam_ctx = samdb_connect(
				state,
				state->dce_call->event_ctx,
				lp_ctx,
				system_session(lp_ctx),
				state->dce_call->conn->remote_address,
				0);
			if (sam_ctx == NULL) {
				return WERR_DS_UNAVAILABLE;
			}

			/*
			 * Secrets for trusted domains can only be triggered on
			 * the PDC.
			 */
			ok = samdb_is_pdc(sam_ctx);
			TALLOC_FREE(sam_ctx);
			if (!ok) {
				return WERR_INVALID_DOMAIN_ROLE;
			}
		}

		break;
	default:
		return WERR_NOT_SUPPORTED;
	}

	irpc_handle = irpc_binding_handle_by_name(state,
						  imsg_ctx,
						  "winbind_server",
						  &ndr_table_winbind);
	if (irpc_handle == NULL) {
		DEBUG(0,("Failed to get binding_handle for winbind_server task\n"));
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		return WERR_SERVICE_NOT_FOUND;
	}

	/*
	 * 60 seconds timeout should be enough
	 */
	dcerpc_binding_handle_set_timeout(irpc_handle, 60);

	subreq = dcerpc_winbind_LogonControl_send(state,
						  state->dce_call->event_ctx,
						  irpc_handle,
						  state->r.in.function_code,
						  state->r.in.level,
						  state->r.in.data,
						  state->r.out.query);
	if (subreq == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	tevent_req_set_callback(subreq,
				dcesrv_netr_LogonControl_base_done,
				state);

	return WERR_OK;
}

static void dcesrv_netr_LogonControl_base_done(struct tevent_req *subreq)
{
	struct dcesrv_netr_LogonControl_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_netr_LogonControl_base_state);
	NTSTATUS status;

	status = dcerpc_winbind_LogonControl_recv(subreq, state->mem_ctx,
						  &state->r.out.result);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		state->r.out.result = WERR_TIMEOUT;
	} else if (!NT_STATUS_IS_OK(status)) {
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
	}

	if (state->_r.l2ex != NULL) {
		struct netr_LogonControl2Ex *r = state->_r.l2ex;
		r->out.result = state->r.out.result;
	} else if (state->_r.l2 != NULL) {
		struct netr_LogonControl2 *r = state->_r.l2;
		r->out.result = state->r.out.result;
	} else if (state->_r.l != NULL) {
		struct netr_LogonControl *r = state->_r.l;
		r->out.result = state->r.out.result;
	}

	status = dcesrv_reply(state->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n", nt_errstr(status)));
	}
}

/*
  netr_LogonControl
*/
static WERROR dcesrv_netr_LogonControl(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl *r)
{
	struct dcesrv_netr_LogonControl_base_state *state;
	WERROR werr;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonControl_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.logon_server = r->in.logon_server;
	state->r.in.function_code = r->in.function_code;
	state->r.in.level = r->in.level;
	state->r.in.data = NULL;
	state->r.out.query = r->out.query;

	state->_r.l = r;

	werr = dcesrv_netr_LogonControl_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return werr;
	}

	return werr;
}

/*
  netr_LogonControl2
*/
static WERROR dcesrv_netr_LogonControl2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl2 *r)
{
	struct dcesrv_netr_LogonControl_base_state *state;
	WERROR werr;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonControl_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.logon_server = r->in.logon_server;
	state->r.in.function_code = r->in.function_code;
	state->r.in.level = r->in.level;
	state->r.in.data = r->in.data;
	state->r.out.query = r->out.query;

	state->_r.l2 = r;

	werr = dcesrv_netr_LogonControl_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return werr;
	}

	return werr;
}

/*
  netr_LogonControl2Ex
*/
static WERROR dcesrv_netr_LogonControl2Ex(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl2Ex *r)
{
	struct dcesrv_netr_LogonControl_base_state *state;
	WERROR werr;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_LogonControl_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r = *r;
	state->_r.l2ex = r;

	werr = dcesrv_netr_LogonControl_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return werr;
	}

	return werr;
}

static WERROR fill_trusted_domains_array(TALLOC_CTX *mem_ctx,
					 struct ldb_context *sam_ctx,
					 struct netr_DomainTrustList *trusts,
					 uint32_t trust_flags);

/*
  netr_GetAnyDCName
*/
static WERROR dcesrv_netr_GetAnyDCName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_GetAnyDCName *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct netr_DomainTrustList *trusts;
	struct ldb_context *sam_ctx;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	uint32_t i;
	WERROR werr;

	*r->out.dcname = NULL;

	if ((r->in.domainname == NULL) || (r->in.domainname[0] == '\0')) {
		/* if the domainname parameter wasn't set assume our domain */
		r->in.domainname = lpcfg_workgroup(lp_ctx);
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	if (strcasecmp(r->in.domainname, lpcfg_workgroup(lp_ctx)) == 0) {
		/* well we asked for a DC of our own domain */
		if (samdb_is_pdc(sam_ctx)) {
			/* we are the PDC of the specified domain */
			return WERR_NO_SUCH_DOMAIN;
		}

		*r->out.dcname = talloc_asprintf(mem_ctx, "\\%s",
						lpcfg_netbios_name(lp_ctx));
		W_ERROR_HAVE_NO_MEMORY(*r->out.dcname);

		return WERR_OK;
	}

	/* Okay, now we have to consider the trusted domains */

	trusts = talloc_zero(mem_ctx, struct netr_DomainTrustList);
	W_ERROR_HAVE_NO_MEMORY(trusts);

	trusts->count = 0;

	werr = fill_trusted_domains_array(mem_ctx, sam_ctx, trusts,
					  NETR_TRUST_FLAG_INBOUND
					  | NETR_TRUST_FLAG_OUTBOUND);
	W_ERROR_NOT_OK_RETURN(werr);

	for (i = 0; i < trusts->count; i++) {
		if (strcasecmp(r->in.domainname, trusts->array[i].netbios_name) == 0) {
			/* FIXME: Here we need to find a DC for the specified
			 * trusted domain. */

			/* return WERR_OK; */
			return WERR_NO_SUCH_DOMAIN;
		}
	}

	return WERR_NO_SUCH_DOMAIN;
}


/*
  netr_DatabaseRedo
*/
static NTSTATUS dcesrv_netr_DatabaseRedo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseRedo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_NetrEnumerateTrustedDomains
*/
static NTSTATUS dcesrv_netr_NetrEnumerateTrustedDomains(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NetrEnumerateTrustedDomains *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_LogonGetCapabilities
*/
static NTSTATUS dcesrv_netr_LogonGetCapabilities(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonGetCapabilities *r)
{
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS status;

	status = dcesrv_netr_creds_server_step_check(dce_call,
						     mem_ctx,
						     r->in.computer_name,
						     r->in.credential,
						     r->out.return_authenticator,
						     &creds);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " Bad credentials - error\n"));
	}
	NT_STATUS_NOT_OK_RETURN(status);

	if (r->in.query_level != 1) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	r->out.capabilities->server_capabilities = creds->negotiate_flags;

	return NT_STATUS_OK;
}


/*
  netr_NETRLOGONSETSERVICEBITS
*/
static WERROR dcesrv_netr_NETRLOGONSETSERVICEBITS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONSETSERVICEBITS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_LogonGetTrustRid
*/
static WERROR dcesrv_netr_LogonGetTrustRid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonGetTrustRid *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_NETRLOGONCOMPUTESERVERDIGEST
*/
static WERROR dcesrv_netr_NETRLOGONCOMPUTESERVERDIGEST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONCOMPUTESERVERDIGEST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_NETRLOGONCOMPUTECLIENTDIGEST
*/
static WERROR dcesrv_netr_NETRLOGONCOMPUTECLIENTDIGEST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONCOMPUTECLIENTDIGEST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/*
  netr_DsRGetSiteName
*/
static WERROR dcesrv_netr_DsRGetSiteName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct netr_DsRGetSiteName *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct ldb_context *sam_ctx;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	/*
	 * We assume to be a DC when we get called over NETLOGON. Hence we
	 * get our site name always by using "samdb_server_site_name()"
	 * and not "samdb_client_site_name()".
	 */
	*r->out.site = samdb_server_site_name(sam_ctx, mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(*r->out.site);

	return WERR_OK;
}


/*
  fill in a netr_OneDomainInfo from our own domain/forest
*/
static NTSTATUS fill_our_one_domain_info(TALLOC_CTX *mem_ctx,
				const struct lsa_TrustDomainInfoInfoEx *our_tdo,
				struct GUID domain_guid,
				struct netr_OneDomainInfo *info,
				bool is_trust_list)
{
	ZERO_STRUCTP(info);

	if (is_trust_list) {
		struct netr_trust_extension *te = NULL;
		struct netr_trust_extension_info *tei = NULL;

		/* w2k8 only fills this on trusted domains */
		te = talloc_zero(mem_ctx, struct netr_trust_extension);
		if (te == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tei = &te->info;
		tei->flags |= NETR_TRUST_FLAG_PRIMARY;

		/*
		 * We're always within a native forest
		 */
		tei->flags |= NETR_TRUST_FLAG_IN_FOREST;
		tei->flags |= NETR_TRUST_FLAG_NATIVE;

		/* For now we assume we're always the tree root */
		tei->flags |= NETR_TRUST_FLAG_TREEROOT;
		tei->parent_index = 0;

		tei->trust_type = our_tdo->trust_type;
		/*
		 * This needs to be 0 instead of our_tdo->trust_attributes
		 * It means LSA_TRUST_ATTRIBUTE_WITHIN_FOREST won't
		 * be set, while NETR_TRUST_FLAG_IN_FOREST is set above.
		 */
		tei->trust_attributes = 0;

		info->trust_extension.info = te;
	}

	if (is_trust_list) {
		info->dns_domainname.string = our_tdo->domain_name.string;

		/* MS-NRPC 3.5.4.3.9 - must be set to NULL for trust list */
		info->dns_forestname.string = NULL;
	} else {
		info->dns_domainname.string = talloc_asprintf(mem_ctx, "%s.",
						our_tdo->domain_name.string);
		if (info->dns_domainname.string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		info->dns_forestname.string = info->dns_domainname.string;
	}

	info->domainname.string = our_tdo->netbios_name.string;
	info->domain_sid = our_tdo->sid;
	info->domain_guid = domain_guid;

	return NT_STATUS_OK;
}

/*
  fill in a netr_OneDomainInfo from a trust tdo
*/
static NTSTATUS fill_trust_one_domain_info(TALLOC_CTX *mem_ctx,
				struct GUID domain_guid,
				const struct lsa_TrustDomainInfoInfoEx *tdo,
				struct netr_OneDomainInfo *info)
{
	struct netr_trust_extension *te = NULL;
	struct netr_trust_extension_info *tei = NULL;

	ZERO_STRUCTP(info);

	/* w2k8 only fills this on trusted domains */
	te = talloc_zero(mem_ctx, struct netr_trust_extension);
	if (te == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tei = &te->info;

	if (tdo->trust_direction & LSA_TRUST_DIRECTION_INBOUND) {
		tei->flags |= NETR_TRUST_FLAG_INBOUND;
	}
	if (tdo->trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) {
		tei->flags |= NETR_TRUST_FLAG_OUTBOUND;
	}
	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		tei->flags |= NETR_TRUST_FLAG_IN_FOREST;
	}

	/*
	 * TODO: once we support multiple domains within our forest,
	 * we need to fill this correct (or let the caller do it
	 * for all domains marked with NETR_TRUST_FLAG_IN_FOREST).
	 */
	tei->parent_index = 0;

	tei->trust_type = tdo->trust_type;
	tei->trust_attributes = tdo->trust_attributes;

	info->trust_extension.info = te;

	info->domainname.string = tdo->netbios_name.string;
	if (tdo->trust_type != LSA_TRUST_TYPE_DOWNLEVEL) {
		info->dns_domainname.string = tdo->domain_name.string;
	} else {
		info->dns_domainname.string = NULL;
	}
	info->domain_sid = tdo->sid;
	info->domain_guid = domain_guid;

	/* MS-NRPC 3.5.4.3.9 - must be set to NULL for trust list */
	info->dns_forestname.string = NULL;

	return NT_STATUS_OK;
}

/*
  netr_LogonGetDomainInfo
  this is called as part of the ADS domain logon procedure.

  It has an important role in convaying details about the client, such
  as Operating System, Version, Service Pack etc.
*/
static NTSTATUS dcesrv_netr_LogonGetDomainInfo(struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, struct netr_LogonGetDomainInfo *r)
{
	struct netlogon_creds_CredentialState *creds;
	const char * const trusts_attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAttributes",
		"trustDirection",
		"trustType",
		NULL
	};
	const char * const attrs2[] = { "sAMAccountName", "dNSHostName",
		"msDS-SupportedEncryptionTypes", NULL };
	const char *sam_account_name, *old_dns_hostname, *prefix1, *prefix2;
	struct ldb_context *sam_ctx;
	const struct GUID *our_domain_guid = NULL;
	struct lsa_TrustDomainInfoInfoEx *our_tdo = NULL;
	struct ldb_message **res1, *new_msg;
	struct ldb_result *trusts_res = NULL;
	struct ldb_dn *workstation_dn;
	struct netr_DomainInformation *domain_info;
	struct netr_LsaPolicyInformation *lsa_policy_info;
	uint32_t default_supported_enc_types = 0xFFFFFFFF;
	bool update_dns_hostname = true;
	int ret, i;
	NTSTATUS status;

	status = dcesrv_netr_creds_server_step_check(dce_call,
						     mem_ctx,
						     r->in.computer_name,
						     r->in.credential,
						     r->out.return_authenticator,
						     &creds);
	if (!NT_STATUS_IS_OK(status)) {
		char* local  = NULL;
		char* remote = NULL;
		TALLOC_CTX *frame = talloc_stackframe();
		remote = tsocket_address_string(dce_call->conn->remote_address,
						frame);
		local  = tsocket_address_string(dce_call->conn->local_address,
						frame);
		DBG_ERR(("Bad credentials - "
		         "computer[%s] remote[%s] local[%s]\n"),
			log_escape(frame, r->in.computer_name),
			remote,
			local);
		talloc_free(frame);
	}
	NT_STATUS_NOT_OK_RETURN(status);

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	switch (r->in.level) {
	case 1: /* Domain information */

		if (r->in.query->workstation_info == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* Prepares the workstation DN */
		workstation_dn = ldb_dn_new_fmt(mem_ctx, sam_ctx, "<SID=%s>",
						dom_sid_string(mem_ctx, creds->sid));
		NT_STATUS_HAVE_NO_MEMORY(workstation_dn);

		/* Lookup for attributes in workstation object */
		ret = gendb_search_dn(sam_ctx, mem_ctx, workstation_dn, &res1,
				      attrs2);
		if (ret != 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		/* Gets the sam account name which is checked against the DNS
		 * hostname parameter. */
		sam_account_name = ldb_msg_find_attr_as_string(res1[0],
							       "sAMAccountName",
							       NULL);
		if (sam_account_name == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		/*
		 * Checks that the sam account name without a possible "$"
		 * matches as prefix with the DNS hostname in the workstation
		 * info structure.
		 */
		prefix1 = talloc_strndup(mem_ctx, sam_account_name,
					 strcspn(sam_account_name, "$"));
		NT_STATUS_HAVE_NO_MEMORY(prefix1);
		if (r->in.query->workstation_info->dns_hostname != NULL) {
			prefix2 = talloc_strndup(mem_ctx,
						 r->in.query->workstation_info->dns_hostname,
						 strcspn(r->in.query->workstation_info->dns_hostname, "."));
			NT_STATUS_HAVE_NO_MEMORY(prefix2);

			if (strcasecmp(prefix1, prefix2) != 0) {
				update_dns_hostname = false;
			}
		} else {
			update_dns_hostname = false;
		}

		/* Gets the old DNS hostname */
		old_dns_hostname = ldb_msg_find_attr_as_string(res1[0],
							       "dNSHostName",
							       NULL);

		/*
		 * Updates the DNS hostname when the client wishes that the
		 * server should handle this for him
		 * ("NETR_WS_FLAG_HANDLES_SPN_UPDATE" not set). And this is
		 * obviously only checked when we do already have a
		 * "dNSHostName".
		 * See MS-NRPC section 3.5.4.3.9
		 */
		if ((old_dns_hostname != NULL) &&
		    (r->in.query->workstation_info->workstation_flags
		    & NETR_WS_FLAG_HANDLES_SPN_UPDATE) != 0) {
			update_dns_hostname = false;
		}

		/* Gets host information and put them into our directory */

		new_msg = ldb_msg_new(mem_ctx);
		NT_STATUS_HAVE_NO_MEMORY(new_msg);

		new_msg->dn = workstation_dn;

		/* Sets the OS name */

		if (r->in.query->workstation_info->os_name.string == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		ret = ldb_msg_add_string(new_msg, "operatingSystem",
					 r->in.query->workstation_info->os_name.string);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * Sets information from "os_version". On an empty structure
		 * the values are cleared.
		 */
		if (r->in.query->workstation_info->os_version.os != NULL) {
			struct netr_OsVersionInfoEx *os_version;
			const char *os_version_str;

			os_version = &r->in.query->workstation_info->os_version.os->os;

			if (os_version->CSDVersion == NULL) {
				return NT_STATUS_INVALID_PARAMETER;
			}

			os_version_str = talloc_asprintf(new_msg, "%u.%u (%u)",
							 os_version->MajorVersion,
							 os_version->MinorVersion,
							 os_version->BuildNumber);
			NT_STATUS_HAVE_NO_MEMORY(os_version_str);

			ret = ldb_msg_add_string(new_msg,
						 "operatingSystemServicePack",
						 os_version->CSDVersion);
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}

			ret = ldb_msg_add_string(new_msg,
						 "operatingSystemVersion",
						 os_version_str);
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			ret = samdb_msg_add_delete(sam_ctx, mem_ctx, new_msg,
						   "operatingSystemServicePack");
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}

			ret = samdb_msg_add_delete(sam_ctx, mem_ctx, new_msg,
						   "operatingSystemVersion");
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		/*
		 * If the boolean "update_dns_hostname" remained true, then we
		 * are fine to start the update.
		 */
		if (update_dns_hostname) {
			ret = ldb_msg_add_string(new_msg,
						 "dNSHostname",
						 r->in.query->workstation_info->dns_hostname);
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}

			/* This manual "servicePrincipalName" generation is
			 * still needed! Since the update in the samldb LDB
			 * module does only work if the entries already exist
			 * which isn't always the case. */
			ret = ldb_msg_add_string(new_msg,
						 "servicePrincipalName",
						 talloc_asprintf(new_msg, "HOST/%s",
						 r->in.computer_name));
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}

			ret = ldb_msg_add_string(new_msg,
						 "servicePrincipalName",
						 talloc_asprintf(new_msg, "HOST/%s",
						 r->in.query->workstation_info->dns_hostname));
			if (ret != LDB_SUCCESS) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		if (dsdb_replace(sam_ctx, new_msg, 0) != LDB_SUCCESS) {
			DEBUG(3,("Impossible to update samdb: %s\n",
				ldb_errstring(sam_ctx)));
		}

		talloc_free(new_msg);

		/* Writes back the domain information */

		our_domain_guid = samdb_domain_guid(sam_ctx);
		if (our_domain_guid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		status = dsdb_trust_local_tdo_info(mem_ctx, sam_ctx, &our_tdo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dsdb_trust_search_tdos(sam_ctx,
						NULL, /* exclude */
						trusts_attrs,
						mem_ctx,
						&trusts_res);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		domain_info = talloc(mem_ctx, struct netr_DomainInformation);
		NT_STATUS_HAVE_NO_MEMORY(domain_info);

		ZERO_STRUCTP(domain_info);

		/* Informations about the local and trusted domains */

		status = fill_our_one_domain_info(mem_ctx,
						  our_tdo,
						  *our_domain_guid,
						  &domain_info->primary_domain,
						  false);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		domain_info->trusted_domain_count = trusts_res->count + 1;
		domain_info->trusted_domains = talloc_zero_array(mem_ctx,
			struct netr_OneDomainInfo,
			domain_info->trusted_domain_count);
		NT_STATUS_HAVE_NO_MEMORY(domain_info->trusted_domains);

		for (i=0; i < trusts_res->count; i++) {
			struct netr_OneDomainInfo *o =
				&domain_info->trusted_domains[i];
			/* we can't know the guid of trusts outside our forest */
			struct GUID trust_domain_guid = GUID_zero();
			struct lsa_TrustDomainInfoInfoEx *tdo = NULL;

			status = dsdb_trust_parse_tdo_info(mem_ctx,
							   trusts_res->msgs[i],
							   &tdo);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}

			status = fill_trust_one_domain_info(mem_ctx,
							    trust_domain_guid,
							    tdo,
							    o);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		status = fill_our_one_domain_info(mem_ctx,
						  our_tdo,
						  *our_domain_guid,
						  &domain_info->trusted_domains[i],
						  true);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* Sets the supported encryption types */
		domain_info->supported_enc_types = ldb_msg_find_attr_as_uint(res1[0],
			"msDS-SupportedEncryptionTypes",
			default_supported_enc_types);

		/* Other host domain information */

		lsa_policy_info = talloc(mem_ctx,
			struct netr_LsaPolicyInformation);
		NT_STATUS_HAVE_NO_MEMORY(lsa_policy_info);
		ZERO_STRUCTP(lsa_policy_info);

		domain_info->lsa_policy = *lsa_policy_info;

		/* The DNS hostname is only returned back when there is a chance
		 * for a change. */
		if ((r->in.query->workstation_info->workstation_flags
		    & NETR_WS_FLAG_HANDLES_SPN_UPDATE) != 0) {
			domain_info->dns_hostname.string = old_dns_hostname;
		} else {
			domain_info->dns_hostname.string = NULL;
		}

		domain_info->workstation_flags =
			r->in.query->workstation_info->workstation_flags & (
			NETR_WS_FLAG_HANDLES_SPN_UPDATE | NETR_WS_FLAG_HANDLES_INBOUND_TRUSTS);

		r->out.info->domain_info = domain_info;
	break;
	case 2: /* LSA policy information - not used at the moment */
		lsa_policy_info = talloc(mem_ctx,
			struct netr_LsaPolicyInformation);
		NT_STATUS_HAVE_NO_MEMORY(lsa_policy_info);
		ZERO_STRUCTP(lsa_policy_info);

		r->out.info->lsa_policy_info = lsa_policy_info;
	break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	break;
	}

	return NT_STATUS_OK;
}


/*
  netr_ServerPasswordGet
*/
static NTSTATUS dcesrv_netr_ServerPasswordGet(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_ServerPasswordGet *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static bool sam_rodc_access_check(struct ldb_context *sam_ctx,
				  TALLOC_CTX *mem_ctx,
				  struct dom_sid *user_sid,
				  struct ldb_dn *obj_dn)
{
	const char *rodc_attrs[] = { "msDS-KrbTgtLink", "msDS-NeverRevealGroup", "msDS-RevealOnDemandGroup", "objectGUID", NULL };
	const char *obj_attrs[] = { "tokenGroups", "objectSid", "UserAccountControl", "msDS-KrbTgtLinkBL", NULL };
	struct ldb_dn *rodc_dn;
	int ret;
	struct ldb_result *rodc_res = NULL, *obj_res = NULL;
	WERROR werr;
	struct dom_sid *object_sid;
	uint32_t num_never_reveal_sids, num_reveal_sids, num_token_sids;
	struct dom_sid *never_reveal_sids, *reveal_sids, *token_sids;

	rodc_dn = ldb_dn_new_fmt(mem_ctx, sam_ctx, "<SID=%s>",
				 dom_sid_string(mem_ctx, user_sid));
	if (!ldb_dn_validate(rodc_dn)) goto denied;

	/* do the two searches we need */
	ret = dsdb_search_dn(sam_ctx, mem_ctx, &rodc_res, rodc_dn, rodc_attrs,
			     DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS || rodc_res->count != 1) goto denied;

	ret = dsdb_search_dn(sam_ctx, mem_ctx, &obj_res, obj_dn, obj_attrs, 0);
	if (ret != LDB_SUCCESS || obj_res->count != 1) goto denied;

	object_sid = samdb_result_dom_sid(mem_ctx, obj_res->msgs[0], "objectSid");
	if (object_sid == NULL) {
		goto denied;
	}

	/*
	 * The SID list needs to include itself as well as the tokenGroups.
	 *
	 * TODO determine if sIDHistory is required for this check
	 */
	werr = samdb_result_sid_array_ndr(sam_ctx, obj_res->msgs[0],
					  mem_ctx, "tokenGroups",
					  &num_token_sids,
					  &token_sids,
					  object_sid, 1);
	if (!W_ERROR_IS_OK(werr) || token_sids==NULL) {
		goto denied;
	}

	werr = samdb_result_sid_array_dn(sam_ctx, rodc_res->msgs[0],
					 mem_ctx, "msDS-NeverRevealGroup",
					 &num_never_reveal_sids,
					 &never_reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		goto denied;
	}

	werr = samdb_result_sid_array_dn(sam_ctx, rodc_res->msgs[0],
					 mem_ctx, "msDS-RevealOnDemandGroup",
					 &num_reveal_sids,
					 &reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		goto denied;
	}

	if (never_reveal_sids &&
	    sid_list_match(num_token_sids,
			   token_sids,
			   num_never_reveal_sids,
			   never_reveal_sids)) {
		goto denied;
	}

	if (reveal_sids &&
	    sid_list_match(num_token_sids,
			   token_sids,
			   num_reveal_sids,
			   reveal_sids)) {
		goto allowed;
	}

denied:
	return false;
allowed:
	return true;

}

/*
  netr_NetrLogonSendToSam
*/
static NTSTATUS dcesrv_netr_NetrLogonSendToSam(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					       struct netr_NetrLogonSendToSam *r)
{
	struct netlogon_creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	NTSTATUS nt_status;
	DATA_BLOB decrypted_blob;
	enum ndr_err_code ndr_err;
	struct netr_SendToSamBase base_msg = { 0 };

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential,
							r->out.return_authenticator,
							&creds);

	NT_STATUS_NOT_OK_RETURN(nt_status);

	switch (creds->secure_channel_type) {
	case SEC_CHAN_BDC:
	case SEC_CHAN_RODC:
		break;
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
	case SEC_CHAN_NULL:
		return NT_STATUS_INVALID_PARAMETER;
	default:
		DEBUG(1, ("Client asked for an invalid secure channel type: %d\n",
			  creds->secure_channel_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* Buffer is meant to be 16-bit aligned */
	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		nt_status = netlogon_creds_aes_decrypt(creds,
						       r->in.opaque_buffer,
						       r->in.buffer_len);
	} else {
		nt_status = netlogon_creds_arcfour_crypt(creds,
							 r->in.opaque_buffer,
							 r->in.buffer_len);
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	decrypted_blob.data = r->in.opaque_buffer;
	decrypted_blob.length = r->in.buffer_len;

	ndr_err = ndr_pull_struct_blob(&decrypted_blob, mem_ctx, &base_msg,
				       (ndr_pull_flags_fn_t)ndr_pull_netr_SendToSamBase);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		/* We only partially implement SendToSam */
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* Now 'send' to SAM */
	switch (base_msg.message_type) {
	case SendToSamResetBadPasswordCount:
	{
		struct ldb_message *msg = ldb_msg_new(mem_ctx);
		struct ldb_dn *dn = NULL;
		int ret = 0;


		ret = ldb_transaction_start(sam_ctx);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		ret = dsdb_find_dn_by_guid(sam_ctx,
					   mem_ctx,
					   &base_msg.message.reset_bad_password.guid,
					   0,
					   &dn);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (creds->secure_channel_type == SEC_CHAN_RODC &&
		    !sam_rodc_access_check(sam_ctx, mem_ctx, creds->sid, dn)) {
			DEBUG(1, ("Client asked to reset bad password on "
				  "an arbitrary user: %s\n",
				  ldb_dn_get_linearized(dn)));
			ldb_transaction_cancel(sam_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		msg->dn = dn;

		ret = samdb_msg_add_int(sam_ctx, mem_ctx, msg, "badPwdCount", 0);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		ret = dsdb_replace(sam_ctx, msg, 0);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}

		ret = ldb_transaction_commit(sam_ctx);
		if (ret != LDB_SUCCESS) {
			ldb_transaction_cancel(sam_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}

		break;
	}
	default:
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_OK;
}

struct dcesrv_netr_DsRGetDCName_base_state {
	struct dcesrv_call_state *dce_call;
	TALLOC_CTX *mem_ctx;

	struct netr_DsRGetDCNameEx2 r;
	const char *client_site;

	struct {
		struct netr_DsRGetDCName *dc;
		struct netr_DsRGetDCNameEx *dcex;
		struct netr_DsRGetDCNameEx2 *dcex2;
	} _r;
};

static void dcesrv_netr_DsRGetDCName_base_done(struct tevent_req *subreq);

static WERROR dcesrv_netr_DsRGetDCName_base_call(struct dcesrv_netr_DsRGetDCName_base_state *state)
{
	struct dcesrv_call_state *dce_call = state->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	TALLOC_CTX *mem_ctx = state->mem_ctx;
	struct netr_DsRGetDCNameEx2 *r = &state->r;
	struct ldb_context *sam_ctx;
	struct netr_DsRGetDCNameInfo *info;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const struct tsocket_address *local_address;
	char *local_addr = NULL;
	const struct tsocket_address *remote_address;
	char *remote_addr = NULL;
	const char *server_site_name;
	char *guid_str;
	struct netlogon_samlogon_response response;
	NTSTATUS status;
	const char *dc_name = NULL;
	const char *domain_name = NULL;
	const char *pdc_ip;
	bool different_domain = true;

	ZERO_STRUCTP(r->out.info);

	sam_ctx = samdb_connect(state,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	local_address = dcesrv_connection_get_local_address(dce_call->conn);
	if (tsocket_address_is_inet(local_address, "ip")) {
		local_addr = tsocket_address_inet_addr_string(local_address, state);
		W_ERROR_HAVE_NO_MEMORY(local_addr);
	}

	remote_address = dcesrv_connection_get_remote_address(dce_call->conn);
	if (tsocket_address_is_inet(remote_address, "ip")) {
		remote_addr = tsocket_address_inet_addr_string(remote_address, state);
		W_ERROR_HAVE_NO_MEMORY(remote_addr);
	}

	/* "server_unc" is ignored by w2k3 */

	if (r->in.flags & ~(DSGETDC_VALID_FLAGS)) {
		return WERR_INVALID_FLAGS;
	}

	if (r->in.flags & DS_GC_SERVER_REQUIRED &&
	    r->in.flags & DS_PDC_REQUIRED &&
	    r->in.flags & DS_KDC_REQUIRED) {
		return WERR_INVALID_FLAGS;
	}
	if (r->in.flags & DS_IS_FLAT_NAME &&
	    r->in.flags & DS_IS_DNS_NAME) {
		return WERR_INVALID_FLAGS;
	}
	if (r->in.flags & DS_RETURN_DNS_NAME &&
	    r->in.flags & DS_RETURN_FLAT_NAME) {
		return WERR_INVALID_FLAGS;
	}
	if (r->in.flags & DS_DIRECTORY_SERVICE_REQUIRED &&
	    r->in.flags & DS_DIRECTORY_SERVICE_6_REQUIRED) {
		return WERR_INVALID_FLAGS;
	}

	if (r->in.flags & DS_GOOD_TIMESERV_PREFERRED &&
	    r->in.flags &
	    (DS_DIRECTORY_SERVICE_REQUIRED |
	     DS_DIRECTORY_SERVICE_PREFERRED |
	     DS_GC_SERVER_REQUIRED |
	     DS_PDC_REQUIRED |
	     DS_KDC_REQUIRED)) {
		return WERR_INVALID_FLAGS;
	}

	if (r->in.flags & DS_TRY_NEXTCLOSEST_SITE &&
	    r->in.site_name) {
		return WERR_INVALID_FLAGS;
	}

	/*
	 * If we send an all-zero GUID, we should ignore it as winbind actually
	 * checks it with a DNS query. Windows also appears to ignore it.
	 */
	if (r->in.domain_guid != NULL && GUID_all_zero(r->in.domain_guid)) {
		r->in.domain_guid = NULL;
	}

	/* Attempt winbind search only if we suspect the domain is incorrect */
	if (r->in.domain_name != NULL && strcmp("", r->in.domain_name) != 0) {
		if (r->in.flags & DS_IS_FLAT_NAME) {
			if (strcasecmp_m(r->in.domain_name,
					 lpcfg_sam_name(lp_ctx)) == 0) {
				different_domain = false;
			}
		} else if (r->in.flags & DS_IS_DNS_NAME) {
			if (strcasecmp_m(r->in.domain_name,
					 lpcfg_dnsdomain(lp_ctx)) == 0) {
				different_domain = false;
			}
		} else {
			if (strcasecmp_m(r->in.domain_name,
					 lpcfg_sam_name(lp_ctx)) == 0 ||
			    strcasecmp_m(r->in.domain_name,
					 lpcfg_dnsdomain(lp_ctx)) == 0) {
				different_domain = false;
			}
		}
	} else {
		/*
		 * We need to be able to handle empty domain names, where we
		 * revert to our domain by default.
		 */
		different_domain = false;
	}

	/* Proof server site parameter "site_name" if it was specified */
	server_site_name = samdb_server_site_name(sam_ctx, state);
	W_ERROR_HAVE_NO_MEMORY(server_site_name);
	if (different_domain || (r->in.site_name != NULL &&
				 (strcasecmp_m(r->in.site_name,
					     server_site_name) != 0))) {

		struct dcerpc_binding_handle *irpc_handle = NULL;
		struct tevent_req *subreq = NULL;

		/*
		 * Retrieve the client site to override the winbind response.
		 *
		 * DO NOT use Windows fallback for client site.
		 * In the case of multiple domains, this is plainly wrong.
		 *
		 * Note: It's possible that the client may belong to multiple
		 * subnets across domains. It's not clear what this would mean,
		 * but here we only return what this domain knows.
		 */
		state->client_site = samdb_client_site_name(sam_ctx,
							    state,
							    remote_addr,
							    NULL,
							    false);

		irpc_handle = irpc_binding_handle_by_name(state,
							  imsg_ctx,
							  "winbind_server",
							  &ndr_table_winbind);
		if (irpc_handle == NULL) {
			DEBUG(0,("Failed to get binding_handle for "
				 "winbind_server task\n"));
			dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
			return WERR_SERVICE_NOT_FOUND;
		}

		dcerpc_binding_handle_set_timeout(irpc_handle, 60);

		dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;

		subreq = dcerpc_wbint_DsGetDcName_send(state,
						       dce_call->event_ctx,
						       irpc_handle,
						       r->in.domain_name,
						       r->in.domain_guid,
						       r->in.site_name,
						       r->in.flags,
						       r->out.info);
		if (subreq == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		tevent_req_set_callback(subreq,
					dcesrv_netr_DsRGetDCName_base_done,
					state);

		return WERR_OK;
	}

	guid_str = r->in.domain_guid != NULL ?
		 GUID_string(state, r->in.domain_guid) : NULL;

	status = fill_netlogon_samlogon_response(sam_ctx, mem_ctx,
						 r->in.domain_name,
						 r->in.domain_name,
						 NULL, guid_str,
						 r->in.client_account,
						 r->in.mask, remote_addr,
						 NETLOGON_NT_VERSION_5EX_WITH_IP,
						 lp_ctx, &response, true);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	/*
	 * According to MS-NRPC 2.2.1.2.1 we should set the "DS_DNS_FOREST_ROOT"
	 * (O) flag when the returned forest name is in DNS format. This is here
	 * always the case (see below).
	 */
	response.data.nt5_ex.server_type |= DS_DNS_FOREST_ROOT;

	if (r->in.flags & DS_RETURN_DNS_NAME) {
		dc_name = response.data.nt5_ex.pdc_dns_name;
		domain_name = response.data.nt5_ex.dns_domain;
		/*
		 * According to MS-NRPC 2.2.1.2.1 we should set the
		 * "DS_DNS_CONTROLLER" (M) and "DS_DNS_DOMAIN" (N) flags when
		 * the returned information is in DNS form.
		 */
		response.data.nt5_ex.server_type |=
			DS_DNS_CONTROLLER | DS_DNS_DOMAIN;
	} else if (r->in.flags & DS_RETURN_FLAT_NAME) {
		dc_name = response.data.nt5_ex.pdc_name;
		domain_name = response.data.nt5_ex.domain_name;
	} else {

		/*
		 * TODO: autodetect what we need to return
		 * based on the given arguments
		 */
		dc_name = response.data.nt5_ex.pdc_name;
		domain_name = response.data.nt5_ex.domain_name;
	}

	if (!dc_name || !dc_name[0]) {
		return WERR_NO_SUCH_DOMAIN;
	}

	if (!domain_name || !domain_name[0]) {
		return WERR_NO_SUCH_DOMAIN;
	}

	info = talloc(mem_ctx, struct netr_DsRGetDCNameInfo);
	W_ERROR_HAVE_NO_MEMORY(info);
	info->dc_unc = talloc_asprintf(mem_ctx, "%s%s",
			dc_name[0] != '\\'? "\\\\":"",
			talloc_strdup(mem_ctx, dc_name));
	W_ERROR_HAVE_NO_MEMORY(info->dc_unc);

	pdc_ip = local_addr;
	if (pdc_ip == NULL) {
		pdc_ip = "127.0.0.1";
	}
	info->dc_address = talloc_asprintf(mem_ctx, "\\\\%s", pdc_ip);
	W_ERROR_HAVE_NO_MEMORY(info->dc_address);
	info->dc_address_type  = DS_ADDRESS_TYPE_INET;
	info->domain_guid      = response.data.nt5_ex.domain_uuid;
	info->domain_name      = domain_name;
	info->forest_name      = response.data.nt5_ex.forest;
	info->dc_flags         = response.data.nt5_ex.server_type;
	if (r->in.flags & DS_RETURN_DNS_NAME) {
		/* As MS-NRPC.pdf in 2.2.1.2.1 the DS_DNS_CONTROLLER flag should be
		 * returned if we are returning info->dc_unc containing a FQDN.
		 * This attribute is called DomainControllerName in the specs,
		 * it seems that we decide to return FQDN or netbios depending on
		 * DS_RETURN_DNS_NAME.
		 */
		info->dc_flags |= DS_DNS_CONTROLLER;
	}
	info->dc_site_name     = response.data.nt5_ex.server_site;
	info->client_site_name = response.data.nt5_ex.client_site;

	*r->out.info = info;

	return WERR_OK;
}

static void dcesrv_netr_DsRGetDCName_base_done(struct tevent_req *subreq)
{
	struct dcesrv_netr_DsRGetDCName_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_netr_DsRGetDCName_base_state);
	struct dcesrv_call_state *dce_call = state->dce_call;
	NTSTATUS result, status;

	status = dcerpc_wbint_DsGetDcName_recv(subreq,
					       state->mem_ctx,
					       &result);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		state->r.out.result = WERR_TIMEOUT;
		goto finished;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR(__location__ ": IRPC callback failed %s\n",
			nt_errstr(status));
		state->r.out.result = WERR_GEN_FAILURE;
		goto finished;
	}

	if (!NT_STATUS_IS_OK(result)) {
		DBG_NOTICE("DC location via winbind failed - %s\n",
			   nt_errstr(result));
		state->r.out.result = WERR_NO_SUCH_DOMAIN;
		goto finished;
	}

	if (state->r.out.info == NULL || state->r.out.info[0] == NULL) {
		DBG_ERR("DC location via winbind returned no results\n");
		state->r.out.result = WERR_GEN_FAILURE;
		goto finished;
	}

	if (state->r.out.info[0]->dc_unc == NULL) {
		DBG_ERR("DC location via winbind returned no DC unc\n");
		state->r.out.result = WERR_GEN_FAILURE;
		goto finished;
	}

	/*
	 * Either the supplied site name is NULL (possibly via
	 * TRY_NEXT_CLOSEST_SITE) or the resulting site name matches
	 * the input match name.
	 *
	 * TODO: Currently this means that requests with NETBIOS domain
	 * names can fail because they do not return the site name.
	 */
	if (state->r.in.site_name == NULL ||
	    strcasecmp_m("", state->r.in.site_name) == 0 ||
	    (state->r.out.info[0]->dc_site_name != NULL &&
	     strcasecmp_m(state->r.out.info[0]->dc_site_name,
			  state->r.in.site_name) == 0)) {

		state->r.out.info[0]->client_site_name =
			talloc_move(state->mem_ctx, &state->client_site);

		/*
		 * Make sure to return our DC UNC with // prefix.
		 * Winbind currently doesn't send the leading slashes
		 * for some reason.
		 */
		if (strlen(state->r.out.info[0]->dc_unc) > 2 &&
		    strncmp("\\\\", state->r.out.info[0]->dc_unc, 2) != 0) {
			const char *dc_unc = NULL;

			dc_unc = talloc_asprintf(state->mem_ctx,
						 "\\\\%s",
						 state->r.out.info[0]->dc_unc);
			state->r.out.info[0]->dc_unc = dc_unc;
		}

		state->r.out.result = WERR_OK;
	} else {
		state->r.out.info = NULL;
		state->r.out.result = WERR_NO_SUCH_DOMAIN;
	}

finished:
	if (state->_r.dcex2 != NULL) {
		struct netr_DsRGetDCNameEx2 *r = state->_r.dcex2;
		r->out.result = state->r.out.result;
	} else if (state->_r.dcex != NULL) {
		struct netr_DsRGetDCNameEx *r = state->_r.dcex;
		r->out.result = state->r.out.result;
	} else if (state->_r.dc != NULL) {
		struct netr_DsRGetDCName *r = state->_r.dc;
		r->out.result = state->r.out.result;
	}

	TALLOC_FREE(state);
	status = dcesrv_reply(dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n",
			 nt_errstr(status)));
	}
}

/*
  netr_DsRGetDCNameEx2
*/
static WERROR dcesrv_netr_DsRGetDCNameEx2(struct dcesrv_call_state *dce_call,
					  TALLOC_CTX *mem_ctx,
					  struct netr_DsRGetDCNameEx2 *r)
{
	struct dcesrv_netr_DsRGetDCName_base_state *state;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_DsRGetDCName_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r = *r;
	state->_r.dcex2 = r;

	return dcesrv_netr_DsRGetDCName_base_call(state);
}

/*
  netr_DsRGetDCNameEx
*/
static WERROR dcesrv_netr_DsRGetDCNameEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct netr_DsRGetDCNameEx *r)
{
	struct dcesrv_netr_DsRGetDCName_base_state *state;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_DsRGetDCName_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.server_unc = r->in.server_unc;
	state->r.in.client_account = NULL;
	state->r.in.mask = 0;
	state->r.in.domain_guid = r->in.domain_guid;
	state->r.in.domain_name = r->in.domain_name;
	state->r.in.site_name = r->in.site_name;
	state->r.in.flags = r->in.flags;
	state->r.out.info = r->out.info;

	state->_r.dcex = r;

	return dcesrv_netr_DsRGetDCName_base_call(state);
}

/*
 * netr_DsRGetDCName
 *
 * This function is a predecessor to DsrGetDcNameEx2 according to [MS-NRPC].
 * Although it has a site-guid parameter, the documentation 3.5.4.3.3 DsrGetDcName
 * insists that it be ignored.
 */
static WERROR dcesrv_netr_DsRGetDCName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_DsRGetDCName *r)
{
	struct dcesrv_netr_DsRGetDCName_base_state *state;

	state = talloc_zero(mem_ctx, struct dcesrv_netr_DsRGetDCName_base_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->r.in.server_unc = r->in.server_unc;
	state->r.in.client_account = NULL;
	state->r.in.mask = 0;
	state->r.in.domain_name = r->in.domain_name;
	state->r.in.domain_guid = r->in.domain_guid;

	state->r.in.site_name = NULL; /* this is correct, we should ignore site GUID */
	state->r.in.flags = r->in.flags;
	state->r.out.info = r->out.info;

	state->_r.dc = r;

	return dcesrv_netr_DsRGetDCName_base_call(state);
}
/*
  netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN
*/
static WERROR dcesrv_netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_NetrEnumerateTrustedDomainsEx
*/
static WERROR dcesrv_netr_NetrEnumerateTrustedDomainsEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NetrEnumerateTrustedDomainsEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  netr_DsRAddressToSitenamesExW
*/
static WERROR dcesrv_netr_DsRAddressToSitenamesExW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						   struct netr_DsRAddressToSitenamesExW *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct ldb_context *sam_ctx;
	struct netr_DsRAddressToSitenamesExWCtr *ctr;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	sa_family_t sin_family;
	struct sockaddr_in *addr;
#ifdef HAVE_IPV6
	struct sockaddr_in6 *addr6;
	char addr_str[INET6_ADDRSTRLEN];
#else
	char addr_str[INET_ADDRSTRLEN];
#endif
	char *subnet_name;
	const char *res;
	uint32_t i;

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	ctr = talloc(mem_ctx, struct netr_DsRAddressToSitenamesExWCtr);
	W_ERROR_HAVE_NO_MEMORY(ctr);

	*r->out.ctr = ctr;

	ctr->count = r->in.count;
	ctr->sitename = talloc_array(ctr, struct lsa_String, ctr->count);
	W_ERROR_HAVE_NO_MEMORY(ctr->sitename);
	ctr->subnetname = talloc_array(ctr, struct lsa_String, ctr->count);
	W_ERROR_HAVE_NO_MEMORY(ctr->subnetname);

	for (i=0; i<ctr->count; i++) {
		ctr->sitename[i].string = NULL;
		ctr->subnetname[i].string = NULL;

		if (r->in.addresses[i].size < sizeof(sa_family_t)) {
			continue;
		}
		/* The first two byte of the buffer are reserved for the
		 * "sin_family" but for now only the first one is used. */
		sin_family = r->in.addresses[i].buffer[0];

		switch (sin_family) {
		case AF_INET:
			if (r->in.addresses[i].size < sizeof(struct sockaddr_in)) {
				continue;
			}
			addr = (struct sockaddr_in *) r->in.addresses[i].buffer;
			res = inet_ntop(AF_INET, &addr->sin_addr,
					addr_str, sizeof(addr_str));
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			if (r->in.addresses[i].size < sizeof(struct sockaddr_in6)) {
				continue;
			}
			addr6 = (struct sockaddr_in6 *) r->in.addresses[i].buffer;
			res = inet_ntop(AF_INET6, &addr6->sin6_addr,
					addr_str, sizeof(addr_str));
			break;
#endif
		default:
			continue;
		}

		if (res == NULL) {
			continue;
		}

		ctr->sitename[i].string   = samdb_client_site_name(sam_ctx,
								   mem_ctx,
								   addr_str,
								   &subnet_name,
								   true);
		W_ERROR_HAVE_NO_MEMORY(ctr->sitename[i].string);
		ctr->subnetname[i].string = subnet_name;
	}

	return WERR_OK;
}


/*
  netr_DsRAddressToSitenamesW
*/
static WERROR dcesrv_netr_DsRAddressToSitenamesW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DsRAddressToSitenamesW *r)
{
	struct netr_DsRAddressToSitenamesExW r2;
	struct netr_DsRAddressToSitenamesWCtr *ctr;
	uint32_t i;
	WERROR werr;

	ZERO_STRUCT(r2);

	r2.in.server_name = r->in.server_name;
	r2.in.count = r->in.count;
	r2.in.addresses = r->in.addresses;

	r2.out.ctr = talloc(mem_ctx, struct netr_DsRAddressToSitenamesExWCtr *);
	W_ERROR_HAVE_NO_MEMORY(r2.out.ctr);

	ctr = talloc(mem_ctx, struct netr_DsRAddressToSitenamesWCtr);
	W_ERROR_HAVE_NO_MEMORY(ctr);

	*r->out.ctr = ctr;

	ctr->count = r->in.count;
	ctr->sitename = talloc_array(ctr, struct lsa_String, ctr->count);
	W_ERROR_HAVE_NO_MEMORY(ctr->sitename);

	werr = dcesrv_netr_DsRAddressToSitenamesExW(dce_call, mem_ctx, &r2);

	for (i=0; i<ctr->count; i++) {
		ctr->sitename[i].string   = (*r2.out.ctr)->sitename[i].string;
	}

	return werr;
}


/*
  netr_DsrGetDcSiteCoverageW
*/
static WERROR dcesrv_netr_DsrGetDcSiteCoverageW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DsrGetDcSiteCoverageW *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct ldb_context *sam_ctx;
	struct DcSitesCtr *ctr;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_DS_UNAVAILABLE;
	}

	ctr = talloc(mem_ctx, struct DcSitesCtr);
	W_ERROR_HAVE_NO_MEMORY(ctr);

	*r->out.ctr = ctr;

	/* For now only return our default site */
	ctr->num_sites = 1;
	ctr->sites = talloc_array(ctr, struct lsa_String, ctr->num_sites);
	W_ERROR_HAVE_NO_MEMORY(ctr->sites);
	ctr->sites[0].string = samdb_server_site_name(sam_ctx, mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(ctr->sites[0].string);

	return WERR_OK;
}


static WERROR fill_trusted_domains_array(TALLOC_CTX *mem_ctx,
					 struct ldb_context *sam_ctx,
					 struct netr_DomainTrustList *trusts,
					 uint32_t trust_flags)
{
	struct ldb_dn *system_dn;
	struct ldb_message **dom_res = NULL;
	const char *trust_attrs[] = { "flatname", "trustPartner",
				      "securityIdentifier", "trustDirection",
				      "trustType", "trustAttributes", NULL };
	uint32_t n;
	int i;
	int ret;

	if (!(trust_flags & (NETR_TRUST_FLAG_INBOUND |
			     NETR_TRUST_FLAG_OUTBOUND))) {
		return WERR_INVALID_FLAGS;
	}

	system_dn = samdb_search_dn(sam_ctx, mem_ctx,
				    ldb_get_default_basedn(sam_ctx),
				    "(&(objectClass=container)(cn=System))");
	if (!system_dn) {
		return WERR_GEN_FAILURE;
	}

	ret = gendb_search(sam_ctx, mem_ctx, system_dn,
			   &dom_res, trust_attrs,
			   "(objectclass=trustedDomain)");

	for (i = 0; i < ret; i++) {
		unsigned int trust_dir;
		uint32_t flags = 0;

		trust_dir = ldb_msg_find_attr_as_uint(dom_res[i],
						      "trustDirection", 0);

		if (trust_dir & LSA_TRUST_DIRECTION_INBOUND) {
			flags |= NETR_TRUST_FLAG_INBOUND;
		}
		if (trust_dir & LSA_TRUST_DIRECTION_OUTBOUND) {
			flags |= NETR_TRUST_FLAG_OUTBOUND;
		}

		if (!(flags & trust_flags)) {
			/* this trust direction was not requested */
			continue;
		}

		n = trusts->count;
		trusts->array = talloc_realloc(trusts, trusts->array,
					       struct netr_DomainTrust,
					       n + 1);
		W_ERROR_HAVE_NO_MEMORY(trusts->array);

		trusts->array[n].netbios_name = talloc_steal(trusts->array, ldb_msg_find_attr_as_string(dom_res[i], "flatname", NULL));
		if (!trusts->array[n].netbios_name) {
			DEBUG(0, ("DB Error, TrustedDomain entry (%s) "
				  "without flatname\n", 
				  ldb_dn_get_linearized(dom_res[i]->dn)));
		}

		trusts->array[n].dns_name = talloc_steal(trusts->array, ldb_msg_find_attr_as_string(dom_res[i], "trustPartner", NULL));

		trusts->array[n].trust_flags = flags;
		if ((trust_flags & NETR_TRUST_FLAG_IN_FOREST) &&
		    !(flags & NETR_TRUST_FLAG_TREEROOT)) {
			/* TODO: find if we have parent in the list */
			trusts->array[n].parent_index = 0;
		}

		trusts->array[n].trust_type =
				ldb_msg_find_attr_as_uint(dom_res[i],
						  "trustType", 0);
		trusts->array[n].trust_attributes =
				ldb_msg_find_attr_as_uint(dom_res[i],
						  "trustAttributes", 0);

		if ((trusts->array[n].trust_type == LSA_TRUST_TYPE_MIT) ||
		    (trusts->array[n].trust_type == LSA_TRUST_TYPE_DCE)) {
			struct dom_sid zero_sid;
			ZERO_STRUCT(zero_sid);
			trusts->array[n].sid =
				dom_sid_dup(trusts, &zero_sid);
		} else {
			trusts->array[n].sid =
				samdb_result_dom_sid(trusts, dom_res[i],
						     "securityIdentifier");
		}
		trusts->array[n].guid = GUID_zero();

		trusts->count = n + 1;
	}

	talloc_free(dom_res);
	return WERR_OK;
}

/*
  netr_DsrEnumerateDomainTrusts
*/
static WERROR dcesrv_netr_DsrEnumerateDomainTrusts(struct dcesrv_call_state *dce_call,
						   TALLOC_CTX *mem_ctx,
						   struct netr_DsrEnumerateDomainTrusts *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct netr_DomainTrustList *trusts;
	struct ldb_context *sam_ctx;
	int ret;
	struct ldb_message **dom_res;
	const char * const dom_attrs[] = { "objectSid", "objectGUID", NULL };
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const char *dnsdomain = lpcfg_dnsdomain(lp_ctx);
	const char *p;
	WERROR werr;

	if (r->in.trust_flags & 0xFFFFFE00) {
		return WERR_INVALID_FLAGS;
	}

	/* TODO: turn to hard check once we are sure this is 100% correct */
	if (!r->in.server_name) {
		DEBUG(3, ("Invalid domain! Expected name in domain [%s]. "
			  "But received NULL!\n", dnsdomain));
	} else {
		p = strchr(r->in.server_name, '.');
		if (!p) {
			DEBUG(3, ("Invalid domain! Expected name in domain "
				  "[%s]. But received [%s]!\n",
				  dnsdomain, r->in.server_name));
			p = r->in.server_name;
		} else {
			p++;
                }
	        if (strcasecmp(p, dnsdomain)) {
			DEBUG(3, ("Invalid domain! Expected name in domain "
				  "[%s]. But received [%s]!\n",
				  dnsdomain, r->in.server_name));
		}
	}

	trusts = talloc_zero(mem_ctx, struct netr_DomainTrustList);
	W_ERROR_HAVE_NO_MEMORY(trusts);

	trusts->count = 0;
	r->out.trusts = trusts;

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_GEN_FAILURE;
	}

	if ((r->in.trust_flags & NETR_TRUST_FLAG_INBOUND) ||
	    (r->in.trust_flags & NETR_TRUST_FLAG_OUTBOUND)) {

		werr = fill_trusted_domains_array(mem_ctx, sam_ctx,
						  trusts, r->in.trust_flags);
		W_ERROR_NOT_OK_RETURN(werr);
	}

	/* NOTE: we currently are always the root of the forest */
	if (r->in.trust_flags & NETR_TRUST_FLAG_IN_FOREST) {
		uint32_t n = trusts->count;

		ret = gendb_search_dn(sam_ctx, mem_ctx, NULL,
				      &dom_res, dom_attrs);
		if (ret != 1) {
			return WERR_GEN_FAILURE;
		}

		trusts->count = n + 1;
		trusts->array = talloc_realloc(trusts, trusts->array,
					       struct netr_DomainTrust,
					       trusts->count);
		W_ERROR_HAVE_NO_MEMORY(trusts->array);

		trusts->array[n].netbios_name = lpcfg_workgroup(lp_ctx);
		trusts->array[n].dns_name = lpcfg_dnsdomain(lp_ctx);
		trusts->array[n].trust_flags =
			NETR_TRUST_FLAG_NATIVE |
			NETR_TRUST_FLAG_TREEROOT |
			NETR_TRUST_FLAG_IN_FOREST |
			NETR_TRUST_FLAG_PRIMARY;
		/* we are always the root domain for now */
		trusts->array[n].parent_index = 0;
		trusts->array[n].trust_type = LSA_TRUST_TYPE_UPLEVEL;
		trusts->array[n].trust_attributes = 0;
		trusts->array[n].sid = samdb_result_dom_sid(mem_ctx,
							    dom_res[0],
							    "objectSid");
		trusts->array[n].guid = samdb_result_guid(dom_res[0],
							  "objectGUID");
		talloc_free(dom_res);
	}

	return WERR_OK;
}


/*
  netr_DsrDeregisterDNSHostRecords
*/
static WERROR dcesrv_netr_DsrDeregisterDNSHostRecords(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DsrDeregisterDNSHostRecords *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


static NTSTATUS dcesrv_netr_ServerGetTrustInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_ServerGetTrustInfo *r);

/*
  netr_ServerTrustPasswordsGet
*/
static NTSTATUS dcesrv_netr_ServerTrustPasswordsGet(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_ServerTrustPasswordsGet *r)
{
	struct netr_ServerGetTrustInfo r2 = {};
	struct netr_TrustInfo *_ti = NULL;
	NTSTATUS status;

	r2.in.server_name = r->in.server_name;
	r2.in.account_name = r->in.account_name;
	r2.in.secure_channel_type = r->in.secure_channel_type;
	r2.in.computer_name = r->in.computer_name;
	r2.in.credential = r->in.credential;

	r2.out.return_authenticator = r->out.return_authenticator;
	r2.out.new_owf_password = r->out.new_owf_password;
	r2.out.old_owf_password = r->out.old_owf_password;
	r2.out.trust_info = &_ti;

	status = dcesrv_netr_ServerGetTrustInfo(dce_call, mem_ctx, &r2);

	r->out.return_authenticator = r2.out.return_authenticator;
	r->out.new_owf_password = r2.out.new_owf_password;
	r->out.old_owf_password = r2.out.old_owf_password;

	return status;
}

/*
  netr_DsRGetForestTrustInformation
*/
struct dcesrv_netr_DsRGetForestTrustInformation_state {
	struct dcesrv_call_state *dce_call;
	TALLOC_CTX *mem_ctx;
	struct netr_DsRGetForestTrustInformation *r;
};

static void dcesrv_netr_DsRGetForestTrustInformation_done(struct tevent_req *subreq);

static WERROR dcesrv_netr_DsRGetForestTrustInformation(struct dcesrv_call_state *dce_call,
						       TALLOC_CTX *mem_ctx,
						       struct netr_DsRGetForestTrustInformation *r)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	enum security_user_level security_level;
	struct ldb_context *sam_ctx = NULL;
	struct dcesrv_netr_DsRGetForestTrustInformation_state *state = NULL;
	struct dcerpc_binding_handle *irpc_handle = NULL;
	struct tevent_req *subreq = NULL;
	struct ldb_dn *domain_dn = NULL;
	struct ldb_dn *forest_dn = NULL;
	int cmp;
	int forest_level;

	security_level = security_session_user_level(session_info, NULL);
	if (security_level < SECURITY_USER) {
		return WERR_ACCESS_DENIED;
	}

	if (r->in.flags & 0xFFFFFFFE) {
		return WERR_INVALID_FLAGS;
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return WERR_GEN_FAILURE;
	}

	domain_dn = ldb_get_default_basedn(sam_ctx);
	if (domain_dn == NULL) {
		return WERR_GEN_FAILURE;
	}

	forest_dn = ldb_get_root_basedn(sam_ctx);
	if (forest_dn == NULL) {
		return WERR_GEN_FAILURE;
	}

	cmp = ldb_dn_compare(domain_dn, forest_dn);
	if (cmp != 0) {
		return WERR_NERR_ACFNOTLOADED;
	}

	forest_level = dsdb_forest_functional_level(sam_ctx);
	if (forest_level < DS_DOMAIN_FUNCTION_2003) {
		return WERR_INVALID_FUNCTION;
	}

	if (r->in.flags & DS_GFTI_UPDATE_TDO) {
		if (!samdb_is_pdc(sam_ctx)) {
			return WERR_NERR_NOTPRIMARY;
		}

		if (r->in.trusted_domain_name == NULL) {
			return WERR_INVALID_FLAGS;
		}
	}

	if (r->in.trusted_domain_name == NULL) {
		NTSTATUS status;

		/*
		 * information about our own domain
		 */
		status = dsdb_trust_xref_forest_info(mem_ctx, sam_ctx,
						r->out.forest_trust_info);
		if (!NT_STATUS_IS_OK(status)) {
			return ntstatus_to_werror(status);
		}

		return WERR_OK;
	}

	/*
	 * Forward the request to winbindd
	 */

	state = talloc_zero(mem_ctx,
			struct dcesrv_netr_DsRGetForestTrustInformation_state);
	if (state == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;
	state->r = r;

	irpc_handle = irpc_binding_handle_by_name(state,
						  imsg_ctx,
						  "winbind_server",
						  &ndr_table_winbind);
	if (irpc_handle == NULL) {
		DEBUG(0,("Failed to get binding_handle for winbind_server task\n"));
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		return WERR_SERVICE_NOT_FOUND;
	}

	/*
	 * 60 seconds timeout should be enough
	 */
	dcerpc_binding_handle_set_timeout(irpc_handle, 60);

	subreq = dcerpc_winbind_GetForestTrustInformation_send(state,
						state->dce_call->event_ctx,
						irpc_handle,
						r->in.trusted_domain_name,
						r->in.flags,
						r->out.forest_trust_info);
	if (subreq == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	tevent_req_set_callback(subreq,
				dcesrv_netr_DsRGetForestTrustInformation_done,
				state);

	return WERR_OK;
}

static void dcesrv_netr_DsRGetForestTrustInformation_done(struct tevent_req *subreq)
{
	struct dcesrv_netr_DsRGetForestTrustInformation_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_netr_DsRGetForestTrustInformation_state);
	NTSTATUS status;

	status = dcerpc_winbind_GetForestTrustInformation_recv(subreq,
							state->mem_ctx,
							&state->r->out.result);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		state->r->out.result = WERR_TIMEOUT;
	} else if (!NT_STATUS_IS_OK(status)) {
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
	}

	status = dcesrv_reply(state->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n", nt_errstr(status)));
	}
}

/*
  netr_GetForestTrustInformation
*/
static NTSTATUS dcesrv_netr_GetForestTrustInformation(struct dcesrv_call_state *dce_call,
						      TALLOC_CTX *mem_ctx,
						      struct netr_GetForestTrustInformation *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	struct netlogon_creds_CredentialState *creds = NULL;
	struct ldb_context *sam_ctx = NULL;
	struct ldb_dn *domain_dn = NULL;
	struct ldb_dn *forest_dn = NULL;
	int cmp;
	int forest_level;
	NTSTATUS status;

	status = dcesrv_netr_creds_server_step_check(dce_call,
						     mem_ctx,
						     r->in.computer_name,
						     r->in.credential,
						     r->out.return_authenticator,
						     &creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((creds->secure_channel_type != SEC_CHAN_DNS_DOMAIN) &&
	    (creds->secure_channel_type != SEC_CHAN_DOMAIN)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				session_info,
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* TODO: check r->in.server_name is our name */

	domain_dn = ldb_get_default_basedn(sam_ctx);
	if (domain_dn == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	forest_dn = ldb_get_root_basedn(sam_ctx);
	if (forest_dn == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	cmp = ldb_dn_compare(domain_dn, forest_dn);
	if (cmp != 0) {
		return NT_STATUS_INVALID_DOMAIN_STATE;
	}

	forest_level = dsdb_forest_functional_level(sam_ctx);
	if (forest_level < DS_DOMAIN_FUNCTION_2003) {
		return NT_STATUS_INVALID_DOMAIN_STATE;
	}

	status = dsdb_trust_xref_forest_info(mem_ctx, sam_ctx,
					     r->out.forest_trust_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}


/*
  netr_ServerGetTrustInfo
*/
static NTSTATUS dcesrv_netr_ServerGetTrustInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_ServerGetTrustInfo *r)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	struct netlogon_creds_CredentialState *creds = NULL;
	struct ldb_context *sam_ctx = NULL;
	const char * const attrs[] = {
		"unicodePwd",
		"sAMAccountName",
		"userAccountControl",
		NULL
	};
	struct ldb_message **res = NULL;
	struct samr_Password *curNtHash = NULL, *prevNtHash = NULL;
	NTSTATUS nt_status;
	int ret;
	const char *asid = NULL;
	uint32_t uac = 0;
	const char *aname = NULL;
	struct ldb_message *tdo_msg = NULL;
	const char * const tdo_attrs[] = {
		"trustAuthIncoming",
		"trustAttributes",
		NULL
	};
	struct netr_TrustInfo *trust_info = NULL;

	ZERO_STRUCTP(r->out.new_owf_password);
	ZERO_STRUCTP(r->out.old_owf_password);

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential,
							r->out.return_authenticator,
							&creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/* TODO: check r->in.server_name is our name */

	if (strcasecmp_m(r->in.account_name, creds->account_name) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.secure_channel_type != creds->secure_channel_type) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strcasecmp_m(r->in.computer_name, creds->computer_name) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				lp_ctx,
				system_session(lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	asid = ldap_encode_ndr_dom_sid(mem_ctx, creds->sid);
	if (asid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
			   "(&(objectClass=user)(objectSid=%s))",
			   asid);
	if (ret != 1) {
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	switch (creds->secure_channel_type) {
	case SEC_CHAN_DNS_DOMAIN:
	case SEC_CHAN_DOMAIN:
		uac = ldb_msg_find_attr_as_uint(res[0], "userAccountControl", 0);

		if (uac & UF_ACCOUNTDISABLE) {
			return NT_STATUS_ACCOUNT_DISABLED;
		}

		if (!(uac & UF_INTERDOMAIN_TRUST_ACCOUNT)) {
			return NT_STATUS_ACCOUNT_DISABLED;
		}

		aname = ldb_msg_find_attr_as_string(res[0], "sAMAccountName", NULL);
		if (aname == NULL) {
			return NT_STATUS_ACCOUNT_DISABLED;
		}

		nt_status = dsdb_trust_search_tdo_by_type(sam_ctx,
						SEC_CHAN_DOMAIN, aname,
						tdo_attrs, mem_ctx, &tdo_msg);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return NT_STATUS_ACCOUNT_DISABLED;
		}
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		nt_status = dsdb_trust_get_incoming_passwords(tdo_msg, mem_ctx,
							      &curNtHash,
							      &prevNtHash);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		trust_info = talloc_zero(mem_ctx, struct netr_TrustInfo);
		if (trust_info == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		trust_info->count = 1;
		trust_info->data = talloc_array(trust_info, uint32_t,
						trust_info->count);
		if (trust_info->data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		trust_info->data[0] = ldb_msg_find_attr_as_uint(tdo_msg,
							"trustAttributes",
							0);
		break;

	default:
		nt_status = samdb_result_passwords_no_lockout(mem_ctx, lp_ctx,
							      res[0],
							      NULL, &curNtHash);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		prevNtHash = talloc(mem_ctx, struct samr_Password);
		if (prevNtHash == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		E_md4hash("", prevNtHash->hash);
		break;
	}

	if (curNtHash != NULL) {
		*r->out.new_owf_password = *curNtHash;
		nt_status = netlogon_creds_des_encrypt(creds, r->out.new_owf_password);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}
	if (prevNtHash != NULL) {
		*r->out.old_owf_password = *prevNtHash;
		nt_status = netlogon_creds_des_encrypt(creds, r->out.old_owf_password);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	if (trust_info != NULL) {
		*r->out.trust_info = trust_info;
	}

	return NT_STATUS_OK;
}

/*
  netr_Unused47
*/
static NTSTATUS dcesrv_netr_Unused47(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct netr_Unused47 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


struct netr_dnsupdate_RODC_state {
	struct dcesrv_call_state *dce_call;
	struct netr_DsrUpdateReadOnlyServerDnsRecords *r;
	struct dnsupdate_RODC *r2;
};

/*
  called when the forwarded RODC dns update request is finished
 */
static void netr_dnsupdate_RODC_callback(struct tevent_req *subreq)
{
	struct netr_dnsupdate_RODC_state *st =
		tevent_req_callback_data(subreq,
					 struct netr_dnsupdate_RODC_state);
	NTSTATUS status;

	status = dcerpc_dnsupdate_RODC_r_recv(subreq, st->dce_call);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": IRPC callback failed %s\n", nt_errstr(status)));
		st->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
	}

	st->r->out.dns_names = talloc_steal(st->dce_call, st->r2->out.dns_names);

	status = dcesrv_reply(st->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n", nt_errstr(status)));
	}
}

/*
  netr_DsrUpdateReadOnlyServerDnsRecords
*/
static NTSTATUS dcesrv_netr_DsrUpdateReadOnlyServerDnsRecords(struct dcesrv_call_state *dce_call,
							      TALLOC_CTX *mem_ctx,
							      struct netr_DsrUpdateReadOnlyServerDnsRecords *r)
{
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS nt_status;
	struct dcerpc_binding_handle *binding_handle;
	struct netr_dnsupdate_RODC_state *st;
	struct tevent_req *subreq;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);

	nt_status = dcesrv_netr_creds_server_step_check(dce_call,
							mem_ctx,
							r->in.computer_name,
							r->in.credential,
							r->out.return_authenticator,
							&creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	if (creds->secure_channel_type != SEC_CHAN_RODC) {
		return NT_STATUS_ACCESS_DENIED;
	}

	st = talloc_zero(mem_ctx, struct netr_dnsupdate_RODC_state);
	NT_STATUS_HAVE_NO_MEMORY(st);

	st->dce_call = dce_call;
	st->r = r;
	st->r2 = talloc_zero(st, struct dnsupdate_RODC);
	NT_STATUS_HAVE_NO_MEMORY(st->r2);

	st->r2->in.dom_sid = creds->sid;
	st->r2->in.site_name = r->in.site_name;
	st->r2->in.dns_ttl = r->in.dns_ttl;
	st->r2->in.dns_names = r->in.dns_names;
	st->r2->out.dns_names = r->out.dns_names;

	binding_handle = irpc_binding_handle_by_name(st,
						     imsg_ctx,
						     "dnsupdate",
						     &ndr_table_irpc);
	if (binding_handle == NULL) {
		DEBUG(0,("Failed to get binding_handle for dnsupdate task\n"));
		dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* forward the call */
	subreq = dcerpc_dnsupdate_RODC_r_send(st, dce_call->event_ctx,
					      binding_handle, st->r2);
	NT_STATUS_HAVE_NO_MEMORY(subreq);

	dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;

	/* setup the callback */
	tevent_req_set_callback(subreq, netr_dnsupdate_RODC_callback, st);

	return NT_STATUS_OK;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_netlogon_s.c"

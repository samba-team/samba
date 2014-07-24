/*
   Unix SMB/CIFS implementation.

   module to store/fetch session keys for the schannel client

   Copyright (C) Stefan Metzmacher 2013

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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "lib/util/util_tdb.h"
#include "libcli/security/security.h"
#include "../lib/param/param.h"
#include "../libcli/auth/schannel.h"
#include "../librpc/gen_ndr/ndr_schannel.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "../librpc/gen_ndr/server_id.h"
#include "netlogon_creds_cli.h"
#include "source3/include/messages.h"
#include "source3/include/g_lock.h"

struct netlogon_creds_cli_locked_state;

struct netlogon_creds_cli_context {
	struct {
		const char *computer;
		const char *account;
		uint32_t proposed_flags;
		uint32_t required_flags;
		enum netr_SchannelType type;
		enum dcerpc_AuthLevel auth_level;
	} client;

	struct {
		const char *computer;
		const char *netbios_domain;
		uint32_t cached_flags;
		bool try_validation6;
		bool try_logon_ex;
		bool try_logon_with;
	} server;

	struct {
		const char *key_name;
		TDB_DATA key_data;
		struct db_context *ctx;
		struct g_lock_ctx *g_ctx;
		struct netlogon_creds_cli_locked_state *locked_state;
	} db;
};

struct netlogon_creds_cli_locked_state {
	struct netlogon_creds_cli_context *context;
	bool is_glocked;
	struct netlogon_creds_CredentialState *creds;
};

static int netlogon_creds_cli_locked_state_destructor(
		struct netlogon_creds_cli_locked_state *state)
{
	struct netlogon_creds_cli_context *context = state->context;

	if (context == NULL) {
		return 0;
	}

	if (context->db.locked_state == state) {
		context->db.locked_state = NULL;
	}

	if (state->is_glocked) {
		g_lock_unlock(context->db.g_ctx,
			      context->db.key_name);
	}

	return 0;
}

static NTSTATUS netlogon_creds_cli_context_common(
				const char *client_computer,
				const char *client_account,
				enum netr_SchannelType type,
				enum dcerpc_AuthLevel auth_level,
				uint32_t proposed_flags,
				uint32_t required_flags,
				const char *server_computer,
				const char *server_netbios_domain,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_cli_context **_context)
{
	struct netlogon_creds_cli_context *context = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	char *_key_name = NULL;
	char *server_netbios_name = NULL;
	char *p = NULL;

	*_context = NULL;

	context = talloc_zero(mem_ctx, struct netlogon_creds_cli_context);
	if (context == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->client.computer = talloc_strdup(context, client_computer);
	if (context->client.computer == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->client.account = talloc_strdup(context, client_account);
	if (context->client.account == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->client.proposed_flags = proposed_flags;
	context->client.required_flags = required_flags;
	context->client.type = type;
	context->client.auth_level = auth_level;

	context->server.computer = talloc_strdup(context, server_computer);
	if (context->server.computer == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->server.netbios_domain = talloc_strdup(context, server_netbios_domain);
	if (context->server.netbios_domain == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * TODO:
	 * Force the callers to provide a unique
	 * value for server_computer and use this directly.
	 *
	 * For now we have to deal with
	 * "HOSTNAME" vs. "hostname.example.com".
	 */
	server_netbios_name = talloc_strdup(frame, server_computer);
	if (server_netbios_name == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	p = strchr(server_netbios_name, '.');
	if (p != NULL) {
		p[0] = '\0';
	}

	_key_name = talloc_asprintf(frame, "CLI[%s/%s]/SRV[%s/%s]",
				    client_computer,
				    client_account,
				    server_netbios_name,
				    server_netbios_domain);
	if (_key_name == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->db.key_name = talloc_strdup_upper(context, _key_name);
	if (context->db.key_name == NULL) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->db.key_data = string_term_tdb_data(context->db.key_name);

	*_context = context;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static struct db_context *netlogon_creds_cli_global_db;

NTSTATUS netlogon_creds_cli_set_global_db(struct db_context **db)
{
	if (netlogon_creds_cli_global_db != NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	netlogon_creds_cli_global_db = talloc_move(talloc_autofree_context(), db);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_open_global_db(struct loadparm_context *lp_ctx)
{
	char *fname;
	struct db_context *global_db;

	if (netlogon_creds_cli_global_db != NULL) {
		return NT_STATUS_OK;
	}

	fname = lpcfg_private_db_path(talloc_autofree_context(), lp_ctx, "netlogon_creds_cli");
	if (fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	global_db = dbwrap_local_open(talloc_autofree_context(), lp_ctx,
				      fname, 0,
				      TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
				      O_RDWR|O_CREAT,
				      0600, DBWRAP_LOCK_ORDER_2,
				      DBWRAP_FLAG_NONE);
	if (global_db == NULL) {
		DEBUG(0,("netlogon_creds_cli_open_global_db: Failed to open %s - %s\n",
			 fname, strerror(errno)));
		talloc_free(fname);
		return NT_STATUS_NO_MEMORY;
	}
	TALLOC_FREE(fname);

	netlogon_creds_cli_global_db = global_db;
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_context_global(struct loadparm_context *lp_ctx,
				struct messaging_context *msg_ctx,
				const char *client_account,
				enum netr_SchannelType type,
				const char *server_computer,
				const char *server_netbios_domain,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_cli_context **_context)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct netlogon_creds_cli_context *context = NULL;
	const char *client_computer;
	uint32_t proposed_flags;
	uint32_t required_flags = 0;
	bool reject_md5_servers = false;
	bool require_strong_key = false;
	int require_sign_or_seal = true;
	bool seal_secure_channel = true;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;
	bool neutralize_nt4_emulation = false;

	*_context = NULL;

	client_computer = lpcfg_netbios_name(lp_ctx);
	if (strlen(client_computer) > 15) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	/*
	 * allow overwrite per domain
	 * reject md5 servers:<netbios_domain>
	 */
	reject_md5_servers = lpcfg_reject_md5_servers(lp_ctx);
	reject_md5_servers = lpcfg_parm_bool(lp_ctx, NULL,
					     "reject md5 servers",
					     server_netbios_domain,
					     reject_md5_servers);

	/*
	 * allow overwrite per domain
	 * require strong key:<netbios_domain>
	 */
	require_strong_key = lpcfg_require_strong_key(lp_ctx);
	require_strong_key = lpcfg_parm_bool(lp_ctx, NULL,
					     "require strong key",
					     server_netbios_domain,
					     require_strong_key);

	/*
	 * allow overwrite per domain
	 * client schannel:<netbios_domain>
	 */
	require_sign_or_seal = lpcfg_client_schannel(lp_ctx);
	require_sign_or_seal = lpcfg_parm_int(lp_ctx, NULL,
					      "client schannel",
					      server_netbios_domain,
					      require_sign_or_seal);

	/*
	 * allow overwrite per domain
	 * winbind sealed pipes:<netbios_domain>
	 */
	seal_secure_channel = lpcfg_winbind_sealed_pipes(lp_ctx);
	seal_secure_channel = lpcfg_parm_bool(lp_ctx, NULL,
					      "winbind sealed pipes",
					      server_netbios_domain,
					      seal_secure_channel);

	/*
	 * allow overwrite per domain
	 * neutralize nt4 emulation:<netbios_domain>
	 */
	neutralize_nt4_emulation = lpcfg_neutralize_nt4_emulation(lp_ctx);
	neutralize_nt4_emulation = lpcfg_parm_bool(lp_ctx, NULL,
						   "neutralize nt4 emulation",
						   server_netbios_domain,
						   neutralize_nt4_emulation);

	proposed_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	proposed_flags |= NETLOGON_NEG_SUPPORTS_AES;

	switch (type) {
	case SEC_CHAN_WKSTA:
		if (lpcfg_security(lp_ctx) == SEC_ADS) {
			/*
			 * AD domains should be secure
			 */
			required_flags |= NETLOGON_NEG_PASSWORD_SET2;
			require_sign_or_seal = true;
			require_strong_key = true;
		}
		break;

	case SEC_CHAN_DOMAIN:
		break;

	case SEC_CHAN_DNS_DOMAIN:
		/*
		 * AD domains should be secure
		 */
		required_flags |= NETLOGON_NEG_PASSWORD_SET2;
		require_sign_or_seal = true;
		require_strong_key = true;
		neutralize_nt4_emulation = true;
		break;

	case SEC_CHAN_BDC:
		required_flags |= NETLOGON_NEG_PASSWORD_SET2;
		require_sign_or_seal = true;
		require_strong_key = true;
		break;

	case SEC_CHAN_RODC:
		required_flags |= NETLOGON_NEG_RODC_PASSTHROUGH;
		required_flags |= NETLOGON_NEG_PASSWORD_SET2;
		require_sign_or_seal = true;
		require_strong_key = true;
		neutralize_nt4_emulation = true;
		break;

	default:
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (neutralize_nt4_emulation) {
		proposed_flags |= NETLOGON_NEG_NEUTRALIZE_NT4_EMULATION;
	}

	if (require_sign_or_seal == false) {
		proposed_flags &= ~NETLOGON_NEG_AUTHENTICATED_RPC;
	} else {
		required_flags |= NETLOGON_NEG_ARCFOUR;
		required_flags |= NETLOGON_NEG_AUTHENTICATED_RPC;
	}

	if (reject_md5_servers) {
		required_flags |= NETLOGON_NEG_ARCFOUR;
		required_flags |= NETLOGON_NEG_PASSWORD_SET2;
		required_flags |= NETLOGON_NEG_SUPPORTS_AES;
		required_flags |= NETLOGON_NEG_AUTHENTICATED_RPC;
	}

	if (require_strong_key) {
		required_flags |= NETLOGON_NEG_ARCFOUR;
		required_flags |= NETLOGON_NEG_STRONG_KEYS;
		required_flags |= NETLOGON_NEG_AUTHENTICATED_RPC;
	}

	proposed_flags |= required_flags;

	if (seal_secure_channel) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}

	status = netlogon_creds_cli_context_common(client_computer,
						   client_account,
						   type,
						   auth_level,
						   proposed_flags,
						   required_flags,
						   server_computer,
						   server_netbios_domain,
						   mem_ctx,
						   &context);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (msg_ctx != NULL) {
		context->db.g_ctx = g_lock_ctx_init(context, msg_ctx);
		if (context->db.g_ctx == NULL) {
			TALLOC_FREE(context);
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (netlogon_creds_cli_global_db != NULL) {
		context->db.ctx = netlogon_creds_cli_global_db;
		*_context = context;
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	status = netlogon_creds_cli_open_global_db(lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(context);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	context->db.ctx = netlogon_creds_cli_global_db;
	*_context = context;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_context_tmp(const char *client_computer,
				const char *client_account,
				enum netr_SchannelType type,
				uint32_t proposed_flags,
				uint32_t required_flags,
				enum dcerpc_AuthLevel auth_level,
				const char *server_computer,
				const char *server_netbios_domain,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_cli_context **_context)
{
	NTSTATUS status;
	struct netlogon_creds_cli_context *context = NULL;

	*_context = NULL;

	status = netlogon_creds_cli_context_common(client_computer,
						   client_account,
						   type,
						   auth_level,
						   proposed_flags,
						   required_flags,
						   server_computer,
						   server_netbios_domain,
						   mem_ctx,
						   &context);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	context->db.ctx = db_open_rbt(context);
	if (context->db.ctx == NULL) {
		talloc_free(context);
		return NT_STATUS_NO_MEMORY;
	}

	*_context = context;
	return NT_STATUS_OK;
}

enum dcerpc_AuthLevel netlogon_creds_cli_auth_level(
		struct netlogon_creds_cli_context *context)
{
	return context->client.auth_level;
}

struct netlogon_creds_cli_fetch_state {
	TALLOC_CTX *mem_ctx;
	struct netlogon_creds_CredentialState *creds;
	uint32_t required_flags;
	NTSTATUS status;
};

static void netlogon_creds_cli_fetch_parser(TDB_DATA key, TDB_DATA data,
					    void *private_data)
{
	struct netlogon_creds_cli_fetch_state *state =
		(struct netlogon_creds_cli_fetch_state *)private_data;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	uint32_t tmp_flags;

	state->creds = talloc_zero(state->mem_ctx,
				   struct netlogon_creds_CredentialState);
	if (state->creds == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	blob.data = data.dptr;
	blob.length = data.dsize;

	ndr_err = ndr_pull_struct_blob(&blob, state->creds, state->creds,
		(ndr_pull_flags_fn_t)ndr_pull_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(state->creds);
		state->status = ndr_map_error2ntstatus(ndr_err);
		return;
	}

	tmp_flags = state->creds->negotiate_flags;
	tmp_flags &= state->required_flags;
	if (tmp_flags != state->required_flags) {
		TALLOC_FREE(state->creds);
		state->status = NT_STATUS_DOWNGRADE_DETECTED;
		return;
	}

	state->status = NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_get(struct netlogon_creds_cli_context *context,
				TALLOC_CTX *mem_ctx,
				struct netlogon_creds_CredentialState **_creds)
{
	NTSTATUS status;
	struct netlogon_creds_cli_fetch_state fstate = {
		.mem_ctx = mem_ctx,
		.status = NT_STATUS_INTERNAL_ERROR,
		.required_flags = context->client.required_flags,
	};
	static const struct netr_Credential zero_creds;

	*_creds = NULL;

	status = dbwrap_parse_record(context->db.ctx,
				     context->db.key_data,
				     netlogon_creds_cli_fetch_parser,
				     &fstate);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = fstate.status;
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * mark it as invalid for step operations.
	 */
	fstate.creds->sequence = 0;
	fstate.creds->seed = zero_creds;
	fstate.creds->client = zero_creds;
	fstate.creds->server = zero_creds;

	if (context->server.cached_flags == fstate.creds->negotiate_flags) {
		*_creds = fstate.creds;
		return NT_STATUS_OK;
	}

	/*
	 * It is really important to try SamLogonEx here,
	 * because multiple processes can talk to the same
	 * domain controller, without using the credential
	 * chain.
	 *
	 * With a normal SamLogon call, we must keep the
	 * credentials chain updated and intact between all
	 * users of the machine account (which would imply
	 * cross-node communication for every NTLM logon).
	 *
	 * The credentials chain is not per NETLOGON pipe
	 * connection, but globally on the server/client pair
	 * by computer name, while the client is free to use
	 * any computer name. We include the cluster node number
	 * in our computer name in order to avoid cross node
	 * coordination of the credential chain.
	 *
	 * It's also important to use NetlogonValidationSamInfo4 (6),
	 * because it relies on the rpc transport encryption
	 * and avoids using the global netlogon schannel
	 * session key to en/decrypt secret information
	 * like the user_session_key for network logons.
	 *
	 * [MS-APDS] 3.1.5.2 NTLM Network Logon
	 * says NETLOGON_NEG_CROSS_FOREST_TRUSTS and
	 * NETLOGON_NEG_AUTHENTICATED_RPC set together
	 * are the indication that the server supports
	 * NetlogonValidationSamInfo4 (6). And it must only
	 * be used if "SealSecureChannel" is used.
	 *
	 * The "SealSecureChannel" AUTH_TYPE_SCHANNEL/AUTH_LEVEL_PRIVACY
	 * check is done in netlogon_creds_cli_LogonSamLogon*().
	 */
	context->server.cached_flags = fstate.creds->negotiate_flags;
	context->server.try_validation6 = true;
	context->server.try_logon_ex = true;
	context->server.try_logon_with = true;

	if (!(context->server.cached_flags & NETLOGON_NEG_AUTHENTICATED_RPC)) {
		context->server.try_validation6 = false;
		context->server.try_logon_ex = false;
	}
	if (!(context->server.cached_flags & NETLOGON_NEG_CROSS_FOREST_TRUSTS)) {
		context->server.try_validation6 = false;
	}

	*_creds = fstate.creds;
	return NT_STATUS_OK;
}

bool netlogon_creds_cli_validate(struct netlogon_creds_cli_context *context,
			const struct netlogon_creds_CredentialState *creds1)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netlogon_creds_CredentialState *creds2;
	DATA_BLOB blob1;
	DATA_BLOB blob2;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	int cmp;

	status = netlogon_creds_cli_get(context, frame, &creds2);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return false;
	}

	ndr_err = ndr_push_struct_blob(&blob1, frame, creds1,
		(ndr_push_flags_fn_t)ndr_push_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return false;
	}

	ndr_err = ndr_push_struct_blob(&blob2, frame, creds2,
		(ndr_push_flags_fn_t)ndr_push_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return false;
	}

	if (blob1.length != blob2.length) {
		TALLOC_FREE(frame);
		return false;
	}

	cmp = memcmp(blob1.data, blob2.data, blob1.length);
	if (cmp != 0) {
		TALLOC_FREE(frame);
		return false;
	}

	TALLOC_FREE(frame);
	return true;
}

NTSTATUS netlogon_creds_cli_store(struct netlogon_creds_cli_context *context,
				  struct netlogon_creds_CredentialState **_creds)
{
	struct netlogon_creds_CredentialState *creds = *_creds;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	TDB_DATA data;

	*_creds = NULL;

	if (context->db.locked_state == NULL) {
		/*
		 * this was not the result of netlogon_creds_cli_lock*()
		 */
		TALLOC_FREE(creds);
		return NT_STATUS_INVALID_PAGE_PROTECTION;
	}

	if (context->db.locked_state->creds != creds) {
		/*
		 * this was not the result of netlogon_creds_cli_lock*()
		 */
		TALLOC_FREE(creds);
		return NT_STATUS_INVALID_PAGE_PROTECTION;
	}

	ndr_err = ndr_push_struct_blob(&blob, creds, creds,
		(ndr_push_flags_fn_t)ndr_push_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(creds);
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	data.dptr = blob.data;
	data.dsize = blob.length;

	status = dbwrap_store(context->db.ctx,
			      context->db.key_data,
			      data, TDB_REPLACE);
	TALLOC_FREE(creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_delete(struct netlogon_creds_cli_context *context,
				   struct netlogon_creds_CredentialState **_creds)
{
	struct netlogon_creds_CredentialState *creds = *_creds;
	NTSTATUS status;

	*_creds = NULL;

	if (context->db.locked_state == NULL) {
		/*
		 * this was not the result of netlogon_creds_cli_lock*()
		 */
		TALLOC_FREE(creds);
		return NT_STATUS_INVALID_PAGE_PROTECTION;
	}

	if (context->db.locked_state->creds != creds) {
		/*
		 * this was not the result of netlogon_creds_cli_lock*()
		 */
		TALLOC_FREE(creds);
		return NT_STATUS_INVALID_PAGE_PROTECTION;
	}

	status = dbwrap_delete(context->db.ctx,
			       context->db.key_data);
	TALLOC_FREE(creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

struct netlogon_creds_cli_lock_state {
	struct netlogon_creds_cli_locked_state *locked_state;
	struct netlogon_creds_CredentialState *creds;
};

static void netlogon_creds_cli_lock_done(struct tevent_req *subreq);
static void netlogon_creds_cli_lock_fetch(struct tevent_req *req);

struct tevent_req *netlogon_creds_cli_lock_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_lock_state *state;
	struct netlogon_creds_cli_locked_state *locked_state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_lock_state);
	if (req == NULL) {
		return NULL;
	}

	if (context->db.locked_state != NULL) {
		tevent_req_nterror(req, NT_STATUS_LOCK_NOT_GRANTED);
		return tevent_req_post(req, ev);
	}

	locked_state = talloc_zero(state, struct netlogon_creds_cli_locked_state);
	if (tevent_req_nomem(locked_state, req)) {
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(locked_state,
			      netlogon_creds_cli_locked_state_destructor);
	locked_state->context = context;

	context->db.locked_state = locked_state;
	state->locked_state = locked_state;

	if (context->db.g_ctx == NULL) {
		netlogon_creds_cli_lock_fetch(req);
		if (!tevent_req_is_in_progress(req)) {
			return tevent_req_post(req, ev);
		}

		return req;
	}

	subreq = g_lock_lock_send(state, ev,
				  context->db.g_ctx,
				  context->db.key_name,
				  G_LOCK_WRITE);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, netlogon_creds_cli_lock_done, req);

	return req;
}

static void netlogon_creds_cli_lock_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_lock_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_lock_state);
	NTSTATUS status;

	status = g_lock_lock_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->locked_state->is_glocked = true;

	netlogon_creds_cli_lock_fetch(req);
}

static void netlogon_creds_cli_lock_fetch(struct tevent_req *req)
{
	struct netlogon_creds_cli_lock_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_lock_state);
	struct netlogon_creds_cli_context *context = state->locked_state->context;
	struct netlogon_creds_cli_fetch_state fstate = {
		.status = NT_STATUS_INTERNAL_ERROR,
		.required_flags = context->client.required_flags,
	};
	NTSTATUS status;

	fstate.mem_ctx = state;
	status = dbwrap_parse_record(context->db.ctx,
				     context->db.key_data,
				     netlogon_creds_cli_fetch_parser,
				     &fstate);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	status = fstate.status;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (context->server.cached_flags == fstate.creds->negotiate_flags) {
		state->creds = fstate.creds;
		tevent_req_done(req);
		return;
	}

	context->server.cached_flags = fstate.creds->negotiate_flags;
	context->server.try_validation6 = true;
	context->server.try_logon_ex = true;
	context->server.try_logon_with = true;

	if (!(context->server.cached_flags & NETLOGON_NEG_AUTHENTICATED_RPC)) {
		context->server.try_validation6 = false;
		context->server.try_logon_ex = false;
	}
	if (!(context->server.cached_flags & NETLOGON_NEG_CROSS_FOREST_TRUSTS)) {
		context->server.try_validation6 = false;
	}

	state->creds = fstate.creds;
	tevent_req_done(req);
	return;
}

NTSTATUS netlogon_creds_cli_lock_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			struct netlogon_creds_CredentialState **creds)
{
	struct netlogon_creds_cli_lock_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_lock_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	talloc_steal(state->creds, state->locked_state);
	state->locked_state->creds = state->creds;
	*creds = talloc_move(mem_ctx, &state->creds);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_lock(struct netlogon_creds_cli_context *context,
			TALLOC_CTX *mem_ctx,
			struct netlogon_creds_CredentialState **creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_lock_send(frame, ev, context);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_lock_recv(req, mem_ctx, creds);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct netlogon_creds_cli_auth_state {
	struct tevent_context *ev;
	struct netlogon_creds_cli_context *context;
	struct dcerpc_binding_handle *binding_handle;
	struct samr_Password current_nt_hash;
	struct samr_Password previous_nt_hash;
	struct samr_Password used_nt_hash;
	char *srv_name_slash;
	uint32_t current_flags;
	struct netr_Credential client_challenge;
	struct netr_Credential server_challenge;
	struct netlogon_creds_CredentialState *creds;
	struct netr_Credential client_credential;
	struct netr_Credential server_credential;
	uint32_t rid;
	bool try_auth3;
	bool try_auth2;
	bool require_auth2;
	bool try_previous_nt_hash;
	struct netlogon_creds_cli_locked_state *locked_state;
};

static void netlogon_creds_cli_auth_locked(struct tevent_req *subreq);
static void netlogon_creds_cli_auth_challenge_start(struct tevent_req *req);

struct tevent_req *netlogon_creds_cli_auth_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				struct samr_Password current_nt_hash,
				const struct samr_Password *previous_nt_hash)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_auth_state *state;
	struct netlogon_creds_cli_locked_state *locked_state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_auth_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->context = context;
	state->binding_handle = b;
	state->current_nt_hash = current_nt_hash;
	if (previous_nt_hash != NULL) {
		state->previous_nt_hash = *previous_nt_hash;
		state->try_previous_nt_hash = true;
	}

	if (context->db.locked_state != NULL) {
		tevent_req_nterror(req, NT_STATUS_LOCK_NOT_GRANTED);
		return tevent_req_post(req, ev);
	}

	locked_state = talloc_zero(state, struct netlogon_creds_cli_locked_state);
	if (tevent_req_nomem(locked_state, req)) {
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(locked_state,
			      netlogon_creds_cli_locked_state_destructor);
	locked_state->context = context;

	context->db.locked_state = locked_state;
	state->locked_state = locked_state;

	state->srv_name_slash = talloc_asprintf(state, "\\\\%s",
						context->server.computer);
	if (tevent_req_nomem(state->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	state->try_auth3 = true;
	state->try_auth2 = true;

	if (context->client.required_flags != 0) {
		state->require_auth2 = true;
	}

	state->used_nt_hash = state->current_nt_hash;
	state->current_flags = context->client.proposed_flags;

	if (context->db.g_ctx != NULL) {
		struct tevent_req *subreq;

		subreq = g_lock_lock_send(state, ev,
					  context->db.g_ctx,
					  context->db.key_name,
					  G_LOCK_WRITE);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					netlogon_creds_cli_auth_locked,
					req);

		return req;
	}

	status = dbwrap_delete(state->context->db.ctx,
			       state->context->db.key_data);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	netlogon_creds_cli_auth_challenge_start(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void netlogon_creds_cli_auth_locked(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_auth_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_auth_state);
	NTSTATUS status;

	status = g_lock_lock_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->locked_state->is_glocked = true;

	status = dbwrap_delete(state->context->db.ctx,
			       state->context->db.key_data);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	netlogon_creds_cli_auth_challenge_start(req);
}

static void netlogon_creds_cli_auth_challenge_done(struct tevent_req *subreq);

static void netlogon_creds_cli_auth_challenge_start(struct tevent_req *req)
{
	struct netlogon_creds_cli_auth_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_auth_state);
	struct tevent_req *subreq;

	TALLOC_FREE(state->creds);

	generate_random_buffer(state->client_challenge.data,
			       sizeof(state->client_challenge.data));

	subreq = dcerpc_netr_ServerReqChallenge_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.computer,
						&state->client_challenge,
						&state->server_challenge);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				netlogon_creds_cli_auth_challenge_done,
				req);
}

static void netlogon_creds_cli_auth_srvauth_done(struct tevent_req *subreq);

static void netlogon_creds_cli_auth_challenge_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_auth_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_auth_state);
	NTSTATUS status;
	NTSTATUS result;

	status = dcerpc_netr_ServerReqChallenge_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (tevent_req_nterror(req, result)) {
		return;
	}

	if (!state->try_auth3 && !state->try_auth2) {
		state->current_flags = 0;
	}

	/* Calculate the session key and client credentials */

	state->creds = netlogon_creds_client_init(state,
						  state->context->client.account,
						  state->context->client.computer,
						  state->context->client.type,
						  &state->client_challenge,
						  &state->server_challenge,
						  &state->used_nt_hash,
						  &state->client_credential,
						  state->current_flags);
	if (tevent_req_nomem(state->creds, req)) {
		return;
	}

	if (state->try_auth3) {
		subreq = dcerpc_netr_ServerAuthenticate3_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.account,
						state->context->client.type,
						state->context->client.computer,
						&state->client_credential,
						&state->server_credential,
						&state->creds->negotiate_flags,
						&state->rid);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
	} else if (state->try_auth2) {
		state->rid = 0;

		subreq = dcerpc_netr_ServerAuthenticate2_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.account,
						state->context->client.type,
						state->context->client.computer,
						&state->client_credential,
						&state->server_credential,
						&state->creds->negotiate_flags);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
	} else {
		state->rid = 0;

		subreq = dcerpc_netr_ServerAuthenticate_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.account,
						state->context->client.type,
						state->context->client.computer,
						&state->client_credential,
						&state->server_credential);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
	}
	tevent_req_set_callback(subreq,
				netlogon_creds_cli_auth_srvauth_done,
				req);
}

static void netlogon_creds_cli_auth_srvauth_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_auth_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_auth_state);
	NTSTATUS status;
	NTSTATUS result;
	bool ok;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	TDB_DATA data;
	uint32_t tmp_flags;

	if (state->try_auth3) {
		status = dcerpc_netr_ServerAuthenticate3_recv(subreq, state,
							      &result);
		TALLOC_FREE(subreq);
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			state->try_auth3 = false;
			netlogon_creds_cli_auth_challenge_start(req);
			return;
		}
		if (tevent_req_nterror(req, status)) {
			return;
		}
	} else if (state->try_auth2) {
		status = dcerpc_netr_ServerAuthenticate2_recv(subreq, state,
							      &result);
		TALLOC_FREE(subreq);
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			state->try_auth2 = false;
			if (state->require_auth2) {
				status = NT_STATUS_DOWNGRADE_DETECTED;
				tevent_req_nterror(req, status);
				return;
			}
			netlogon_creds_cli_auth_challenge_start(req);
			return;
		}
		if (tevent_req_nterror(req, status)) {
			return;
		}
	} else {
		status = dcerpc_netr_ServerAuthenticate_recv(subreq, state,
							     &result);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	if (!NT_STATUS_IS_OK(result) &&
	    !NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED))
	{
		tevent_req_nterror(req, result);
		return;
	}

	tmp_flags = state->creds->negotiate_flags;
	tmp_flags &= state->context->client.required_flags;
	if (tmp_flags != state->context->client.required_flags) {
		if (NT_STATUS_IS_OK(result)) {
			tevent_req_nterror(req, NT_STATUS_DOWNGRADE_DETECTED);
			return;
		}
		tevent_req_nterror(req, result);
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED)) {

		tmp_flags = state->context->client.proposed_flags;
		if ((state->current_flags == tmp_flags) &&
		    (state->creds->negotiate_flags != tmp_flags))
		{
			/*
			 * lets retry with the negotiated flags
			 */
			state->current_flags = state->creds->negotiate_flags;
			netlogon_creds_cli_auth_challenge_start(req);
			return;
		}

		if (!state->try_previous_nt_hash) {
			/*
			 * we already retried, giving up...
			 */
			tevent_req_nterror(req, result);
			return;
		}

		/*
		 * lets retry with the old nt hash.
		 */
		state->try_previous_nt_hash = false;
		state->used_nt_hash = state->previous_nt_hash;
		state->current_flags = state->context->client.proposed_flags;
		netlogon_creds_cli_auth_challenge_start(req);
		return;
	}

	ok = netlogon_creds_client_check(state->creds,
					 &state->server_credential);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	ndr_err = ndr_push_struct_blob(&blob, state, state->creds,
		(ndr_push_flags_fn_t)ndr_push_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		tevent_req_nterror(req, status);
		return;
	}

	data.dptr = blob.data;
	data.dsize = blob.length;

	status = dbwrap_store(state->context->db.ctx,
			      state->context->db.key_data,
			      data, TDB_REPLACE);
	TALLOC_FREE(state->locked_state);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS netlogon_creds_cli_auth_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_auth(struct netlogon_creds_cli_context *context,
				 struct dcerpc_binding_handle *b,
				 struct samr_Password current_nt_hash,
				 const struct samr_Password *previous_nt_hash)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_auth_send(frame, ev, context, b,
					   current_nt_hash,
					   previous_nt_hash);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_auth_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct netlogon_creds_cli_check_state {
	struct tevent_context *ev;
	struct netlogon_creds_cli_context *context;
	struct dcerpc_binding_handle *binding_handle;

	char *srv_name_slash;

	union netr_Capabilities caps;

	struct netlogon_creds_CredentialState *creds;
	struct netlogon_creds_CredentialState tmp_creds;
	struct netr_Authenticator req_auth;
	struct netr_Authenticator rep_auth;
};

static void netlogon_creds_cli_check_cleanup(struct tevent_req *req,
					     NTSTATUS status);
static void netlogon_creds_cli_check_locked(struct tevent_req *subreq);

struct tevent_req *netlogon_creds_cli_check_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_check_state *state;
	struct tevent_req *subreq;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_check_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->context = context;
	state->binding_handle = b;

	state->srv_name_slash = talloc_asprintf(state, "\\\\%s",
						context->server.computer);
	if (tevent_req_nomem(state->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	dcerpc_binding_handle_auth_info(state->binding_handle,
					&auth_type, &auth_level);

	if (auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	switch (auth_level) {
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	subreq = netlogon_creds_cli_lock_send(state, state->ev,
					      state->context);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_check_locked,
				req);

	return req;
}

static void netlogon_creds_cli_check_cleanup(struct tevent_req *req,
					     NTSTATUS status)
{
	struct netlogon_creds_cli_check_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_check_state);

	if (state->creds == NULL) {
		return;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_DOWNGRADE_DETECTED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		TALLOC_FREE(state->creds);
		return;
	}

	netlogon_creds_cli_delete(state->context, &state->creds);
}

static void netlogon_creds_cli_check_caps(struct tevent_req *subreq);

static void netlogon_creds_cli_check_locked(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_check_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_check_state);
	NTSTATUS status;

	status = netlogon_creds_cli_lock_recv(subreq, state,
					      &state->creds);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * we defer all callbacks in order to cleanup
	 * the database record.
	 */
	tevent_req_defer_callback(req, state->ev);

	state->tmp_creds = *state->creds;
	netlogon_creds_client_authenticator(&state->tmp_creds,
					    &state->req_auth);
	ZERO_STRUCT(state->rep_auth);

	subreq = dcerpc_netr_LogonGetCapabilities_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.computer,
						&state->req_auth,
						&state->rep_auth,
						1,
						&state->caps);
	if (tevent_req_nomem(subreq, req)) {
		status = NT_STATUS_NO_MEMORY;
		netlogon_creds_cli_check_cleanup(req, status);
		return;
	}
	tevent_req_set_callback(subreq,
				netlogon_creds_cli_check_caps,
				req);
}

static void netlogon_creds_cli_check_caps(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_check_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_check_state);
	NTSTATUS status;
	NTSTATUS result;
	bool ok;

	status = dcerpc_netr_LogonGetCapabilities_recv(subreq, state,
						       &result);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
		/*
		 * Note that the negotiated flags are already checked
		 * for our required flags after the ServerAuthenticate3/2 call.
		 */
		uint32_t negotiated = state->tmp_creds.negotiate_flags;

		if (negotiated & NETLOGON_NEG_SUPPORTS_AES) {
			/*
			 * If we have negotiated NETLOGON_NEG_SUPPORTS_AES
			 * already, we expect this to work!
			 */
			status = NT_STATUS_DOWNGRADE_DETECTED;
			tevent_req_nterror(req, status);
			netlogon_creds_cli_check_cleanup(req, status);
			return;
		}

		if (negotiated & NETLOGON_NEG_STRONG_KEYS) {
			/*
			 * If we have negotiated NETLOGON_NEG_STRONG_KEYS
			 * we expect this to work at least as far as the
			 * NOT_SUPPORTED error handled below!
			 *
			 * NT 4.0 and Old Samba servers are not
			 * allowed without "require strong key = no"
			 */
			status = NT_STATUS_DOWNGRADE_DETECTED;
			tevent_req_nterror(req, status);
			netlogon_creds_cli_check_cleanup(req, status);
			return;
		}

		/*
		 * If we not require NETLOGON_NEG_SUPPORTS_AES or
		 * NETLOGON_NEG_STRONG_KEYS, it's ok to ignore
		 * NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE.
		 *
		 * This is needed against NT 4.0 and old Samba servers.
		 *
		 * As we're using DCERPC_AUTH_TYPE_SCHANNEL with
		 * DCERPC_AUTH_LEVEL_INTEGRITY or DCERPC_AUTH_LEVEL_PRIVACY
		 * we should detect a faked NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE
		 * with the next request as the sequence number processing
		 * gets out of sync.
		 */
		netlogon_creds_cli_check_cleanup(req, status);
		tevent_req_done(req);
		return;
	}
	if (tevent_req_nterror(req, status)) {
		netlogon_creds_cli_check_cleanup(req, status);
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_IMPLEMENTED)) {
		/*
		 * Note that the negotiated flags are already checked
		 * for our required flags after the ServerAuthenticate3/2 call.
		 */
		uint32_t negotiated = state->tmp_creds.negotiate_flags;

		if (negotiated & NETLOGON_NEG_SUPPORTS_AES) {
			/*
			 * If we have negotiated NETLOGON_NEG_SUPPORTS_AES
			 * already, we expect this to work!
			 */
			status = NT_STATUS_DOWNGRADE_DETECTED;
			tevent_req_nterror(req, status);
			netlogon_creds_cli_check_cleanup(req, status);
			return;
		}

		/*
		 * This is ok, the server does not support
		 * NETLOGON_NEG_SUPPORTS_AES.
		 *
		 * netr_LogonGetCapabilities() was
		 * netr_LogonDummyRoutine1() before
		 * NETLOGON_NEG_SUPPORTS_AES was invented.
		 */
		netlogon_creds_cli_check_cleanup(req, result);
		tevent_req_done(req);
		return;
	}

	ok = netlogon_creds_client_check(&state->tmp_creds,
					 &state->rep_auth.cred);
	if (!ok) {
		status = NT_STATUS_ACCESS_DENIED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_check_cleanup(req, status);
		return;
	}

	if (tevent_req_nterror(req, result)) {
		netlogon_creds_cli_check_cleanup(req, result);
		return;
	}

	if (state->caps.server_capabilities != state->tmp_creds.negotiate_flags) {
		status = NT_STATUS_DOWNGRADE_DETECTED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_check_cleanup(req, status);
		return;
	}

	/*
	 * This is the key check that makes this check secure.  If we
	 * get OK here (rather than NOT_SUPPORTED), then the server
	 * did support AES. If the server only proposed STRONG_KEYS
	 * and not AES, then it should have failed with
	 * NOT_IMPLEMENTED. We always send AES as a client, so the
	 * server should always have returned it.
	 */
	if (!(state->caps.server_capabilities & NETLOGON_NEG_SUPPORTS_AES)) {
		status = NT_STATUS_DOWNGRADE_DETECTED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_check_cleanup(req, status);
		return;
	}

	*state->creds = state->tmp_creds;
	status = netlogon_creds_cli_store(state->context,
					  &state->creds);
	netlogon_creds_cli_check_cleanup(req, status);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS netlogon_creds_cli_check_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		netlogon_creds_cli_check_cleanup(req, status);
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_check(struct netlogon_creds_cli_context *context,
				  struct dcerpc_binding_handle *b)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_check_send(frame, ev, context, b);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_check_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct netlogon_creds_cli_ServerPasswordSet_state {
	struct tevent_context *ev;
	struct netlogon_creds_cli_context *context;
	struct dcerpc_binding_handle *binding_handle;
	uint32_t old_timeout;

	char *srv_name_slash;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	struct samr_CryptPassword samr_crypt_password;
	struct netr_CryptPassword netr_crypt_password;
	struct samr_Password samr_password;

	struct netlogon_creds_CredentialState *creds;
	struct netlogon_creds_CredentialState tmp_creds;
	struct netr_Authenticator req_auth;
	struct netr_Authenticator rep_auth;
};

static void netlogon_creds_cli_ServerPasswordSet_cleanup(struct tevent_req *req,
						     NTSTATUS status);
static void netlogon_creds_cli_ServerPasswordSet_locked(struct tevent_req *subreq);

struct tevent_req *netlogon_creds_cli_ServerPasswordSet_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const char *new_password,
				const uint32_t *new_version)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_ServerPasswordSet_state *state;
	struct tevent_req *subreq;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_ServerPasswordSet_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->context = context;
	state->binding_handle = b;

	/*
	 * netr_ServerPasswordSet
	 */
	E_md4hash(new_password, state->samr_password.hash);

	/*
	 * netr_ServerPasswordSet2
	 */
	ok = encode_pw_buffer(state->samr_crypt_password.data,
			      new_password, STR_UNICODE);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (new_version != NULL) {
		struct NL_PASSWORD_VERSION version;
		uint32_t len = IVAL(state->samr_crypt_password.data, 512);
		uint32_t ofs = 512 - len;
		uint8_t *p;

		if (len > 500) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return tevent_req_post(req, ev);
		}
		ofs -= 12;

		version.ReservedField = 0;
		version.PasswordVersionNumber = *new_version;
		version.PasswordVersionPresent =
			NETLOGON_PASSWORD_VERSION_NUMBER_PRESENT;

		p = state->samr_crypt_password.data + ofs;
		SIVAL(p, 0, version.ReservedField);
		SIVAL(p, 4, version.PasswordVersionNumber);
		SIVAL(p, 8, version.PasswordVersionPresent);
	}

	state->srv_name_slash = talloc_asprintf(state, "\\\\%s",
						context->server.computer);
	if (tevent_req_nomem(state->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	dcerpc_binding_handle_auth_info(state->binding_handle,
					&state->auth_type,
					&state->auth_level);

	subreq = netlogon_creds_cli_lock_send(state, state->ev,
					      state->context);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_ServerPasswordSet_locked,
				req);

	return req;
}

static void netlogon_creds_cli_ServerPasswordSet_cleanup(struct tevent_req *req,
							 NTSTATUS status)
{
	struct netlogon_creds_cli_ServerPasswordSet_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_ServerPasswordSet_state);

	if (state->creds == NULL) {
		return;
	}

	dcerpc_binding_handle_set_timeout(state->binding_handle,
					  state->old_timeout);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_DOWNGRADE_DETECTED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		TALLOC_FREE(state->creds);
		return;
	}

	netlogon_creds_cli_delete(state->context, &state->creds);
}

static void netlogon_creds_cli_ServerPasswordSet_done(struct tevent_req *subreq);

static void netlogon_creds_cli_ServerPasswordSet_locked(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_ServerPasswordSet_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_ServerPasswordSet_state);
	NTSTATUS status;

	status = netlogon_creds_cli_lock_recv(subreq, state,
					      &state->creds);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		switch (state->auth_level) {
		case DCERPC_AUTH_LEVEL_INTEGRITY:
		case DCERPC_AUTH_LEVEL_PRIVACY:
			break;
		default:
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return;
		}
	} else {
		uint32_t tmp = state->creds->negotiate_flags;

		if (tmp & NETLOGON_NEG_AUTHENTICATED_RPC) {
			/*
			 * if DCERPC_AUTH_TYPE_SCHANNEL is supported
			 * it should be used, which means
			 * we had a chance to verify no downgrade
			 * happened.
			 *
			 * This relies on netlogon_creds_cli_check*
			 * being called before, as first request after
			 * the DCERPC bind.
			 */
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return;
		}
	}

	state->old_timeout = dcerpc_binding_handle_set_timeout(
				state->binding_handle, 600000);

	/*
	 * we defer all callbacks in order to cleanup
	 * the database record.
	 */
	tevent_req_defer_callback(req, state->ev);

	state->tmp_creds = *state->creds;
	netlogon_creds_client_authenticator(&state->tmp_creds,
					    &state->req_auth);
	ZERO_STRUCT(state->rep_auth);

	if (state->tmp_creds.negotiate_flags & NETLOGON_NEG_PASSWORD_SET2) {

		if (state->tmp_creds.negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
			netlogon_creds_aes_encrypt(&state->tmp_creds,
					state->samr_crypt_password.data,
					516);
		} else {
			netlogon_creds_arcfour_crypt(&state->tmp_creds,
					state->samr_crypt_password.data,
					516);
		}

		memcpy(state->netr_crypt_password.data,
		       state->samr_crypt_password.data, 512);
		state->netr_crypt_password.length =
			IVAL(state->samr_crypt_password.data, 512);

		subreq = dcerpc_netr_ServerPasswordSet2_send(state, state->ev,
					state->binding_handle,
					state->srv_name_slash,
					state->tmp_creds.account_name,
					state->tmp_creds.secure_channel_type,
					state->tmp_creds.computer_name,
					&state->req_auth,
					&state->rep_auth,
					&state->netr_crypt_password);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
			return;
		}
	} else {
		netlogon_creds_des_encrypt(&state->tmp_creds,
					   &state->samr_password);

		subreq = dcerpc_netr_ServerPasswordSet_send(state, state->ev,
					state->binding_handle,
					state->srv_name_slash,
					state->tmp_creds.account_name,
					state->tmp_creds.secure_channel_type,
					state->tmp_creds.computer_name,
					&state->req_auth,
					&state->rep_auth,
					&state->samr_password);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
			return;
		}
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_ServerPasswordSet_done,
				req);
}

static void netlogon_creds_cli_ServerPasswordSet_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_ServerPasswordSet_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_ServerPasswordSet_state);
	NTSTATUS status;
	NTSTATUS result;
	bool ok;

	if (state->tmp_creds.negotiate_flags & NETLOGON_NEG_PASSWORD_SET2) {
		status = dcerpc_netr_ServerPasswordSet2_recv(subreq, state,
							     &result);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
			return;
		}
	} else {
		status = dcerpc_netr_ServerPasswordSet_recv(subreq, state,
							    &result);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
			return;
		}
	}

	ok = netlogon_creds_client_check(&state->tmp_creds,
					 &state->rep_auth.cred);
	if (!ok) {
		status = NT_STATUS_ACCESS_DENIED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
		return;
	}

	if (tevent_req_nterror(req, result)) {
		netlogon_creds_cli_ServerPasswordSet_cleanup(req, result);
		return;
	}

	dcerpc_binding_handle_set_timeout(state->binding_handle,
					  state->old_timeout);

	*state->creds = state->tmp_creds;
	status = netlogon_creds_cli_store(state->context,
					  &state->creds);
	if (tevent_req_nterror(req, status)) {
		netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS netlogon_creds_cli_ServerPasswordSet_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		netlogon_creds_cli_ServerPasswordSet_cleanup(req, status);
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_ServerPasswordSet(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const char *new_password,
				const uint32_t *new_version)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_ServerPasswordSet_send(frame, ev, context, b,
							new_password,
							new_version);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_ServerPasswordSet_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct netlogon_creds_cli_LogonSamLogon_state {
	struct tevent_context *ev;
	struct netlogon_creds_cli_context *context;
	struct dcerpc_binding_handle *binding_handle;

	char *srv_name_slash;

	enum netr_LogonInfoClass logon_level;
	const union netr_LogonLevel *const_logon;
	union netr_LogonLevel *logon;
	uint32_t flags;

	uint16_t validation_level;
	union netr_Validation *validation;
	uint8_t authoritative;

	/*
	 * do we need encryption at the application layer?
	 */
	bool user_encrypt;
	bool try_logon_ex;
	bool try_validation6;

	/*
	 * the read only credentials before we started the operation
	 */
	struct netlogon_creds_CredentialState *ro_creds;

	struct netlogon_creds_CredentialState *lk_creds;

	struct netlogon_creds_CredentialState tmp_creds;
	struct netr_Authenticator req_auth;
	struct netr_Authenticator rep_auth;
};

static void netlogon_creds_cli_LogonSamLogon_start(struct tevent_req *req);
static void netlogon_creds_cli_LogonSamLogon_cleanup(struct tevent_req *req,
						     NTSTATUS status);

struct tevent_req *netlogon_creds_cli_LogonSamLogon_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				enum netr_LogonInfoClass logon_level,
				const union netr_LogonLevel *logon,
				uint32_t flags)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_LogonSamLogon_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_LogonSamLogon_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->context = context;
	state->binding_handle = b;

	state->logon_level = logon_level;
	state->const_logon = logon;
	state->flags = flags;

	state->srv_name_slash = talloc_asprintf(state, "\\\\%s",
						context->server.computer);
	if (tevent_req_nomem(state->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	switch (logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceInformation:
	case NetlogonServiceTransitiveInformation:
	case NetlogonGenericInformation:
		state->user_encrypt = true;
		break;

	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		break;
	}

	state->validation = talloc_zero(state, union netr_Validation);
	if (tevent_req_nomem(state->validation, req)) {
		return tevent_req_post(req, ev);
	}

	netlogon_creds_cli_LogonSamLogon_start(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * we defer all callbacks in order to cleanup
	 * the database record.
	 */
	tevent_req_defer_callback(req, state->ev);
	return req;
}

static void netlogon_creds_cli_LogonSamLogon_cleanup(struct tevent_req *req,
						     NTSTATUS status)
{
	struct netlogon_creds_cli_LogonSamLogon_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_LogonSamLogon_state);

	if (state->lk_creds == NULL) {
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
		/*
		 * This is a hack to recover from a bug in old
		 * Samba servers, when LogonSamLogonEx() fails:
		 *
		 * api_net_sam_logon_ex: Failed to marshall NET_R_SAM_LOGON_EX.
		 *
		 * All following request will get NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE.
		 *
		 * A second bug generates NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE,
		 * instead of NT_STATUS_ACCESS_DENIED or NT_STATUS_RPC_SEC_PKG_ERROR
		 * If the sign/seal check fails.
		 *
		 * In that case we need to cleanup the netlogon session.
		 *
		 * It's the job of the caller to disconnect the current
		 * connection, if netlogon_creds_cli_LogonSamLogon()
		 * returns NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE.
		 */
		if (!state->context->server.try_logon_with) {
			status = NT_STATUS_NETWORK_ACCESS_DENIED;
		}
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_DOWNGRADE_DETECTED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		TALLOC_FREE(state->lk_creds);
		return;
	}

	netlogon_creds_cli_delete(state->context, &state->lk_creds);
}

static void netlogon_creds_cli_LogonSamLogon_done(struct tevent_req *subreq);

static void netlogon_creds_cli_LogonSamLogon_start(struct tevent_req *req)
{
	struct netlogon_creds_cli_LogonSamLogon_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_LogonSamLogon_state);
	struct tevent_req *subreq;
	NTSTATUS status;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	TALLOC_FREE(state->ro_creds);
	TALLOC_FREE(state->logon);
	ZERO_STRUCTP(state->validation);

	dcerpc_binding_handle_auth_info(state->binding_handle,
					&auth_type, &auth_level);

	state->try_logon_ex = state->context->server.try_logon_ex;
	state->try_validation6 = state->context->server.try_validation6;

	if (auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
		state->try_logon_ex = false;
	}

	if (auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		state->try_validation6 = false;
	}

	if (state->try_logon_ex) {
		if (state->try_validation6) {
			state->validation_level = 6;
		} else {
			state->validation_level = 3;
			state->user_encrypt = true;
		}

		state->logon = netlogon_creds_shallow_copy_logon(state,
							state->logon_level,
							state->const_logon);
		if (tevent_req_nomem(state->logon, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}

		if (state->user_encrypt) {
			status = netlogon_creds_cli_get(state->context,
							state,
							&state->ro_creds);
			if (!NT_STATUS_IS_OK(status)) {
				status = NT_STATUS_ACCESS_DENIED;
				tevent_req_nterror(req, status);
				netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
				return;
			}

			netlogon_creds_encrypt_samlogon_logon(state->ro_creds,
							      state->logon_level,
							      state->logon);
		}

		subreq = dcerpc_netr_LogonSamLogonEx_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.computer,
						state->logon_level,
						state->logon,
						state->validation_level,
						state->validation,
						&state->authoritative,
						&state->flags);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
		tevent_req_set_callback(subreq,
					netlogon_creds_cli_LogonSamLogon_done,
					req);
		return;
	}

	if (state->lk_creds == NULL) {
		subreq = netlogon_creds_cli_lock_send(state, state->ev,
						      state->context);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
		tevent_req_set_callback(subreq,
					netlogon_creds_cli_LogonSamLogon_done,
					req);
		return;
	}

	state->tmp_creds = *state->lk_creds;
	netlogon_creds_client_authenticator(&state->tmp_creds,
					    &state->req_auth);
	ZERO_STRUCT(state->rep_auth);

	state->logon = netlogon_creds_shallow_copy_logon(state,
						state->logon_level,
						state->const_logon);
	if (tevent_req_nomem(state->logon, req)) {
		status = NT_STATUS_NO_MEMORY;
		netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
		return;
	}

	netlogon_creds_encrypt_samlogon_logon(state->ro_creds,
					      state->logon_level,
					      state->logon);

	state->validation_level = 3;

	if (state->context->server.try_logon_with) {
		subreq = dcerpc_netr_LogonSamLogonWithFlags_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.computer,
						&state->req_auth,
						&state->rep_auth,
						state->logon_level,
						state->logon,
						state->validation_level,
						state->validation,
						&state->authoritative,
						&state->flags);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
	} else {
		state->flags = 0;

		subreq = dcerpc_netr_LogonSamLogon_send(state, state->ev,
						state->binding_handle,
						state->srv_name_slash,
						state->context->client.computer,
						&state->req_auth,
						&state->rep_auth,
						state->logon_level,
						state->logon,
						state->validation_level,
						state->validation,
						&state->authoritative);
		if (tevent_req_nomem(subreq, req)) {
			status = NT_STATUS_NO_MEMORY;
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_LogonSamLogon_done,
				req);
}

static void netlogon_creds_cli_LogonSamLogon_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_LogonSamLogon_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_LogonSamLogon_state);
	NTSTATUS status;
	NTSTATUS result;
	bool ok;

	if (state->try_logon_ex) {
		status = dcerpc_netr_LogonSamLogonEx_recv(subreq,
							  state->validation,
							  &result);
		TALLOC_FREE(subreq);
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			state->context->server.try_validation6 = false;
			state->context->server.try_logon_ex = false;
			netlogon_creds_cli_LogonSamLogon_start(req);
			return;
		}
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}

		if ((state->validation_level == 6) &&
		    (NT_STATUS_EQUAL(result, NT_STATUS_INVALID_INFO_CLASS) ||
		     NT_STATUS_EQUAL(result, NT_STATUS_INVALID_PARAMETER) ||
		     NT_STATUS_EQUAL(result, NT_STATUS_BUFFER_TOO_SMALL)))
		{
			state->context->server.try_validation6 = false;
			netlogon_creds_cli_LogonSamLogon_start(req);
			return;
		}

		if (tevent_req_nterror(req, result)) {
			netlogon_creds_cli_LogonSamLogon_cleanup(req, result);
			return;
		}

		if (state->ro_creds == NULL) {
			tevent_req_done(req);
			return;
		}

		ok = netlogon_creds_cli_validate(state->context, state->ro_creds);
		if (!ok) {
			/*
			 * We got a race, lets retry with on authenticator
			 * protection.
			 */
			TALLOC_FREE(state->ro_creds);
			state->try_logon_ex = false;
			netlogon_creds_cli_LogonSamLogon_start(req);
			return;
		}

		netlogon_creds_decrypt_samlogon_validation(state->ro_creds,
							state->validation_level,
							state->validation);

		tevent_req_done(req);
		return;
	}

	if (state->lk_creds == NULL) {
		status = netlogon_creds_cli_lock_recv(subreq, state,
						      &state->lk_creds);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}

		netlogon_creds_cli_LogonSamLogon_start(req);
		return;
	}

	if (state->context->server.try_logon_with) {
		status = dcerpc_netr_LogonSamLogonWithFlags_recv(subreq,
								 state->validation,
								 &result);
		TALLOC_FREE(subreq);
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			state->context->server.try_logon_with = false;
			netlogon_creds_cli_LogonSamLogon_start(req);
			return;
		}
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
	} else {
		status = dcerpc_netr_LogonSamLogon_recv(subreq,
							state->validation,
							&result);
		TALLOC_FREE(subreq);
		if (tevent_req_nterror(req, status)) {
			netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
			return;
		}
	}

	ok = netlogon_creds_client_check(&state->tmp_creds,
					 &state->rep_auth.cred);
	if (!ok) {
		status = NT_STATUS_ACCESS_DENIED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
		return;
	}

	*state->lk_creds = state->tmp_creds;
	status = netlogon_creds_cli_store(state->context,
					  &state->lk_creds);
	if (tevent_req_nterror(req, status)) {
		netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
		return;
	}

	if (tevent_req_nterror(req, result)) {
		netlogon_creds_cli_LogonSamLogon_cleanup(req, result);
		return;
	}

	netlogon_creds_decrypt_samlogon_validation(&state->tmp_creds,
						state->validation_level,
						state->validation);

	tevent_req_done(req);
}

NTSTATUS netlogon_creds_cli_LogonSamLogon_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint16_t *validation_level,
					union netr_Validation **validation,
					uint8_t *authoritative,
					uint32_t *flags)
{
	struct netlogon_creds_cli_LogonSamLogon_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_LogonSamLogon_state);
	NTSTATUS status;

	/* authoritative is also returned on error */
	*authoritative = state->authoritative;

	if (tevent_req_is_nterror(req, &status)) {
		netlogon_creds_cli_LogonSamLogon_cleanup(req, status);
		tevent_req_received(req);
		return status;
	}

	*validation_level = state->validation_level;
	*validation = talloc_move(mem_ctx, &state->validation);
	*flags = state->flags;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_LogonSamLogon(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				enum netr_LogonInfoClass logon_level,
				const union netr_LogonLevel *logon,
				TALLOC_CTX *mem_ctx,
				uint16_t *validation_level,
				union netr_Validation **validation,
				uint8_t *authoritative,
				uint32_t *flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_LogonSamLogon_send(frame, ev, context, b,
						    logon_level, logon,
						    *flags);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_LogonSamLogon_recv(req, mem_ctx,
						       validation_level,
						       validation,
						       authoritative,
						       flags);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state {
	struct tevent_context *ev;
	struct netlogon_creds_cli_context *context;
	struct dcerpc_binding_handle *binding_handle;

	char *srv_name_slash;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	const char *site_name;
	uint32_t dns_ttl;
	struct NL_DNS_NAME_INFO_ARRAY *dns_names;

	struct netlogon_creds_CredentialState *creds;
	struct netlogon_creds_CredentialState tmp_creds;
	struct netr_Authenticator req_auth;
	struct netr_Authenticator rep_auth;
};

static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(struct tevent_req *req,
						     NTSTATUS status);
static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_locked(struct tevent_req *subreq);

struct tevent_req *netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_send(TALLOC_CTX *mem_ctx,
									     struct tevent_context *ev,
									     struct netlogon_creds_cli_context *context,
									     struct dcerpc_binding_handle *b,
									     const char *site_name,
									     uint32_t dns_ttl,
									     struct NL_DNS_NAME_INFO_ARRAY *dns_names)
{
	struct tevent_req *req;
	struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->context = context;
	state->binding_handle = b;

	state->srv_name_slash = talloc_asprintf(state, "\\\\%s",
						context->server.computer);
	if (tevent_req_nomem(state->srv_name_slash, req)) {
		return tevent_req_post(req, ev);
	}

	state->site_name = site_name;
	state->dns_ttl = dns_ttl;
	state->dns_names = dns_names;

	dcerpc_binding_handle_auth_info(state->binding_handle,
					&state->auth_type,
					&state->auth_level);

	subreq = netlogon_creds_cli_lock_send(state, state->ev,
					      state->context);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_locked,
				req);

	return req;
}

static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(struct tevent_req *req,
							 NTSTATUS status)
{
	struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state);

	if (state->creds == NULL) {
		return;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_DOWNGRADE_DETECTED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		TALLOC_FREE(state->creds);
		return;
	}

	netlogon_creds_cli_delete(state->context, &state->creds);
}

static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_done(struct tevent_req *subreq);

static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_locked(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state);
	NTSTATUS status;

	status = netlogon_creds_cli_lock_recv(subreq, state,
					      &state->creds);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		switch (state->auth_level) {
		case DCERPC_AUTH_LEVEL_INTEGRITY:
		case DCERPC_AUTH_LEVEL_PRIVACY:
			break;
		default:
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return;
		}
	} else {
		uint32_t tmp = state->creds->negotiate_flags;

		if (tmp & NETLOGON_NEG_AUTHENTICATED_RPC) {
			/*
			 * if DCERPC_AUTH_TYPE_SCHANNEL is supported
			 * it should be used, which means
			 * we had a chance to verify no downgrade
			 * happened.
			 *
			 * This relies on netlogon_creds_cli_check*
			 * being called before, as first request after
			 * the DCERPC bind.
			 */
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return;
		}
	}

	/*
	 * we defer all callbacks in order to cleanup
	 * the database record.
	 */
	tevent_req_defer_callback(req, state->ev);

	state->tmp_creds = *state->creds;
	netlogon_creds_client_authenticator(&state->tmp_creds,
					    &state->req_auth);
	ZERO_STRUCT(state->rep_auth);

	subreq = dcerpc_netr_DsrUpdateReadOnlyServerDnsRecords_send(state, state->ev,
								    state->binding_handle,
								    state->srv_name_slash,
								    state->tmp_creds.computer_name,
								    &state->req_auth,
								    &state->rep_auth,
								    state->site_name,
								    state->dns_ttl,
								    state->dns_names);
	if (tevent_req_nomem(subreq, req)) {
		status = NT_STATUS_NO_MEMORY;
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, status);
		return;
	}

	tevent_req_set_callback(subreq,
				netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_done,
				req);
}

static void netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state *state =
		tevent_req_data(req,
		struct netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_state);
	NTSTATUS status;
	NTSTATUS result;
	bool ok;

	/*
	 * We use state->dns_names as the memory context, as this is
	 * the only in/out variable and it has been overwritten by the
	 * out parameter from the server.
	 *
	 * We need to preserve the return value until the caller can use it.
	 */
	status = dcerpc_netr_DsrUpdateReadOnlyServerDnsRecords_recv(subreq, state->dns_names,
								    &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, status);
		return;
	}

	ok = netlogon_creds_client_check(&state->tmp_creds,
					 &state->rep_auth.cred);
	if (!ok) {
		status = NT_STATUS_ACCESS_DENIED;
		tevent_req_nterror(req, status);
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, status);
		return;
	}

	if (tevent_req_nterror(req, result)) {
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, result);
		return;
	}

	*state->creds = state->tmp_creds;
	status = netlogon_creds_cli_store(state->context,
					  &state->creds);
	if (tevent_req_nterror(req, status)) {
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_cleanup(req, status);
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords(
				struct netlogon_creds_cli_context *context,
				struct dcerpc_binding_handle *b,
				const char *site_name,
				uint32_t dns_ttl,
				struct NL_DNS_NAME_INFO_ARRAY *dns_names)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_send(frame, ev, context, b,
									site_name,
									dns_ttl,
									dns_names);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

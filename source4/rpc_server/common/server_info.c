/* 
   Unix SMB/CIFS implementation.

   common server info functions

   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "librpc/gen_ndr/srvsvc.h"
#include "rpc_server/dcerpc_server.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/auth.h"
#include "param/param.h"
#include "rpc_server/common/common.h"
#include "libds/common/roles.h"
#include "auth/auth_util.h"
#include "lib/tsocket/tsocket.h"

/* 
    Here are common server info functions used by some dcerpc server interfaces
*/

/* This hardcoded value should go into a ldb database! */
enum srvsvc_PlatformId dcesrv_common_get_platform_id(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	enum srvsvc_PlatformId id;

	id = lpcfg_parm_int(dce_ctx->lp_ctx, NULL, "server_info", "platform_id", PLATFORM_ID_NT);

	return id;
}

const char *dcesrv_common_get_server_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, const char *server_unc)
{
	const char *p = server_unc;

	/* if there's no string return our NETBIOS name */
	if (!p) {
		return talloc_strdup(mem_ctx, lpcfg_netbios_name(dce_ctx->lp_ctx));
	}

	/* if there're '\\\\' in front remove them otherwise just pass the string */
	if (p[0] == '\\' && p[1] == '\\') {
		p += 2;
	}

	return talloc_strdup(mem_ctx, p);
}


/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_server_type(TALLOC_CTX *mem_ctx, struct tevent_context *event_ctx, struct dcesrv_context *dce_ctx)
{
	int default_server_announce = 0;
	default_server_announce |= SV_TYPE_WORKSTATION;
	default_server_announce |= SV_TYPE_SERVER;
	default_server_announce |= SV_TYPE_SERVER_UNIX;

	default_server_announce |= SV_TYPE_SERVER_NT;
	default_server_announce |= SV_TYPE_NT;

	switch (lpcfg_server_role(dce_ctx->lp_ctx)) {
		case ROLE_DOMAIN_MEMBER:
			default_server_announce |= SV_TYPE_DOMAIN_MEMBER;
			break;
		case ROLE_ACTIVE_DIRECTORY_DC:
		{
			struct ldb_context *samctx;
			TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
			if (!tmp_ctx) {
				break;
			}
			/* open main ldb */
			samctx = samdb_connect(
				tmp_ctx,
				event_ctx,
				dce_ctx->lp_ctx,
				anonymous_session(tmp_ctx, dce_ctx->lp_ctx),
				NULL,
				0);
			if (samctx == NULL) {
				DEBUG(2,("Unable to open samdb in determining server announce flags\n"));
			} else {
				/* Determine if we are the pdc */
				bool is_pdc = samdb_is_pdc(samctx);
				if (is_pdc) {
					default_server_announce |= SV_TYPE_DOMAIN_CTRL;
				} else {
					default_server_announce |= SV_TYPE_DOMAIN_BAKCTRL;
				}
			}
			/* Close it */
			talloc_free(tmp_ctx);
			break;
		}
		case ROLE_STANDALONE:
		default:
			break;
	}
	if (lpcfg_time_server(dce_ctx->lp_ctx))
		default_server_announce |= SV_TYPE_TIME_SOURCE;

	if (lpcfg_host_msdfs(dce_ctx->lp_ctx))
		default_server_announce |= SV_TYPE_DFS_SERVER;


#if 0
	{ 
		/* TODO: announce us as print server when we are a print server */
		bool is_print_server = false;
		if (is_print_server) {
			default_server_announce |= SV_TYPE_PRINTQ_SERVER;
		}
	}
#endif
	return default_server_announce;
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_lan_root(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, "");
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return -1;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_disc(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 15;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_hidden(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_announce(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 240;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_anndelta(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 3000;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_licenses(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_userpath(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, "c:\\");
}

#define INVALID_SHARE_NAME_CHARS " \"*+,./:;<=>?[\\]|"

bool dcesrv_common_validate_share_name(TALLOC_CTX *mem_ctx, const char *share_name)
{
	if (strpbrk(share_name, INVALID_SHARE_NAME_CHARS)) {
		return false;
	}

	return true;
}

static struct ldb_context *dcesrv_samdb_connect_common(
	TALLOC_CTX *mem_ctx,
	struct dcesrv_call_state *dce_call,
	bool as_system)
{
	struct ldb_context *samdb = NULL;
	struct auth_session_info *system_session_info = NULL;
	const struct auth_session_info *call_session_info =
		dcesrv_call_session_info(dce_call);
	struct auth_session_info *user_session_info = NULL;
	struct auth_session_info *ldb_session_info = NULL;
	struct auth_session_info *audit_session_info = NULL;
	struct tsocket_address *remote_address = NULL;

	if (as_system) {
		system_session_info = system_session(dce_call->conn->dce_ctx->lp_ctx);
		if (system_session_info == NULL) {
			return NULL;
		}
	}

	user_session_info = copy_session_info(mem_ctx, call_session_info);
	if (user_session_info == NULL) {
		return NULL;
	}

	if (dce_call->conn->remote_address != NULL) {
		remote_address = tsocket_address_copy(dce_call->conn->remote_address,
						      user_session_info);
		if (remote_address == NULL) {
			return NULL;
		}
	}

	if (system_session_info != NULL) {
		ldb_session_info = system_session_info;
		audit_session_info = user_session_info;
	} else {
		ldb_session_info = user_session_info;
		audit_session_info = NULL;
	}

	/*
	 * We need to make sure every argument
	 * stays arround for the lifetime of 'samdb',
	 * typically it is allocated on the scope of
	 * an assoc group, so we can't reference dce_call->conn,
	 * as the assoc group may stay when the current connection
	 * gets disconnected.
	 *
	 * The following are global per process:
	 * - dce_call->conn->dce_ctx->lp_ctx
	 * - dce_call->event_ctx
	 * - system_session
	 *
	 * We make a copy of:
	 * - dce_call->conn->remote_address
	 * - dce_call->auth_state->session_info
	 */
	samdb = samdb_connect(
		mem_ctx,
		dce_call->event_ctx,
		dce_call->conn->dce_ctx->lp_ctx,
		ldb_session_info,
		remote_address,
		0);
	if (samdb == NULL) {
		talloc_free(user_session_info);
		return NULL;
	}
	talloc_move(samdb, &user_session_info);

	if (audit_session_info != NULL) {
		int ret;

		ret = ldb_set_opaque(samdb,
				     DSDB_NETWORK_SESSION_INFO,
				     audit_session_info);
		if (ret != LDB_SUCCESS) {
			talloc_free(samdb);
			return NULL;
		}
	}

	return samdb;
}

/*
 * Open an ldb connection under the system session and save the remote users
 * session details in a ldb_opaque. This will allow the audit logging to
 * log the original session for operations performed in the system session.
 *
 * Access checks are required by the caller!
 */
struct ldb_context *dcesrv_samdb_connect_as_system(
	TALLOC_CTX *mem_ctx,
	struct dcesrv_call_state *dce_call)
{
	return dcesrv_samdb_connect_common(mem_ctx, dce_call,
					   true /* as_system */);
}

/*
 * Open an ldb connection under the remote users session details.
 *
 * Access checks are done at the ldb level.
 */
struct ldb_context *dcesrv_samdb_connect_as_user(
	TALLOC_CTX *mem_ctx,
	struct dcesrv_call_state *dce_call)
{
	return dcesrv_samdb_connect_common(mem_ctx, dce_call,
					   false /* not as_system */);
}

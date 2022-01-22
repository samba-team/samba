/*
   Unix SMB/Netbios implementation.
   Generic infrastructure for RPC Daemons
   Copyright (C) Simo Sorce 2011
   Copyright (C) Andreas Schneider 2011

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
#include "rpc_server/rpc_config.h"
#include "rpc_server/rpc_server.h"
#include "lib/param/param.h"
#include "librpc/rpc/dcesrv_core.h"
#include "lib/global_contexts.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static struct dcesrv_context_callbacks srv_callbacks = {
	.log.successful_authz = dcesrv_log_successful_authz,
	.auth.gensec_prepare = dcesrv_auth_gensec_prepare,
	.auth.become_root = become_root,
	.auth.unbecome_root = unbecome_root,
	.assoc_group.find = dcesrv_assoc_group_find,
};

static struct dcesrv_context *global_dcesrv_ctx = NULL;

struct dcesrv_context *global_dcesrv_context(void)
{
	NTSTATUS status;

	if (global_dcesrv_ctx == NULL) {
		struct loadparm_context *lp_ctx = NULL;

		DBG_INFO("Initializing DCE/RPC server context\n");

		lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());
		if (lp_ctx == NULL) {
			smb_panic("No memory");
		}

		/*
		 * Note we MUST use the NULL context here, not the
		 * autofree context, to avoid side effects in forked
		 * children exiting.
		 */
		status = dcesrv_init_context(global_event_context(),
					     lp_ctx,
					     &srv_callbacks,
					     &global_dcesrv_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			smb_panic("Failed to init DCE/RPC context");
		}

		talloc_steal(global_dcesrv_ctx, lp_ctx);
	}

	return global_dcesrv_ctx;
}

void global_dcesrv_context_free(void)
{
	TALLOC_FREE(global_dcesrv_ctx);
}

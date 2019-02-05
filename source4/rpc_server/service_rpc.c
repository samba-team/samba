/* 
   Unix SMB/CIFS implementation.

   smbd-specific dcerpc server code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2004,2007
   
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
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/auth.h"
#include "../lib/util/dlinklist.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "librpc/rpc/dcerpc.h"
#include "system/filesys.h"
#include "lib/messaging/irpc.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "../lib/util/tevent_ntstatus.h"
#include "libcli/raw/smb.h"
#include "../libcli/named_pipe_auth/npa_tstream.h"
#include "smbd/process_model.h"

struct dcesrv_context_callbacks srv_callbacks = {
	.log.successful_authz = log_successful_dcesrv_authz_event,
	.auth.gensec_prepare = dcesrv_gensec_prepare,
	.assoc_group.find = dcesrv_assoc_group_find,
};

/*
 * Need to run the majority of the RPC endpoints in a single process to allow
 * for shared handles, and the sharing of ldb contexts.
 *
 * However other endpoints are capable of being run in multiple processes
 * e.g. NETLOGON.
 *
 * To support this the process model is manipulated to force those end points
 * not supporting multiple processes into the single process model. The code
 * responsible for this is in dcesrv_init_endpoints
 *
 */
NTSTATUS server_service_rpc_init(TALLOC_CTX *);

/*
 * Initialise the rpc endpoints.
 */
static NTSTATUS dcesrv_init_endpoints(struct task_server *task,
				      struct dcesrv_context *dce_ctx,
				      bool use_single_process)
{

	struct dcesrv_endpoint *e;
	const struct model_ops *model_ops = NULL;

	/*
	 * For those RPC services that run with shared context we need to
	 * ensure that they don't fork a new process on accept (standard_model).
	 * And as there is only one process handling these requests we need
	 * to handle accept errors in a similar manner to the single process
	 * model.
	 *
	 * To do this we override the process model operations with the single
	 * process operations. This is not the most elegant solution, but it is
	 * the least ugly, and is confined to the next block of code.
	 */
	if (use_single_process == true) {
		model_ops = process_model_startup("single");
		if (model_ops == NULL) {
			DBG_ERR("Unable to load single process model");
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		model_ops = task->model_ops;
	}

	for (e = dce_ctx->endpoint_list; e; e = e->next) {

		enum dcerpc_transport_t transport =
		    dcerpc_binding_get_transport(e->ep_description);

		if (transport == NCACN_HTTP) {
			/*
			 * We don't support ncacn_http yet
			 */
			continue;
		}
		if (e->use_single_process == use_single_process) {
			NTSTATUS status;
			status = dcesrv_add_ep(dce_ctx,
					       task->lp_ctx,
					       e,
					       task->event_ctx,
					       model_ops,
					       task->process_context);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}
	return NT_STATUS_OK;
}

/*
 * Initialise the RPC service.
 * And those end points that can be serviced by multiple processes.
 * The endpoints that need to be run in a single process are setup in the
 * post_fork hook.
*/
static NTSTATUS dcesrv_task_init(struct task_server *task)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct dcesrv_context *dce_ctx;
	const char **ep_servers = NULL;

	dcerpc_server_init(task->lp_ctx);

	task_server_set_title(task, "task[dcesrv]");

	status = dcesrv_init_context(task->event_ctx,
				     task->lp_ctx,
				     &srv_callbacks,
				     &dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ep_servers = lpcfg_dcerpc_endpoint_servers(task->lp_ctx);
	status = dcesrv_init_ep_servers(dce_ctx, ep_servers);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(lpcfg_ncalrpc_dir(task->lp_ctx))) {
		mkdir(lpcfg_ncalrpc_dir(task->lp_ctx), 0755);
	}
	status = dcesrv_init_endpoints(task, dce_ctx, false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	task->private_data = dce_ctx;
	return NT_STATUS_OK;
}

/*
 * Initialise the endpoints that need to run in a single process fork.
 * The endpoint registration is only done for the first process instance.
 *
 */
static void dcesrv_post_fork(struct task_server *task,
			     struct process_details *pd)
{

	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct dcesrv_context *dce_ctx;

	if (task->private_data == NULL) {
		task_server_terminate(task, "dcerpc: No dcesrv_context", true);
		return;
	}
	dce_ctx =
	    talloc_get_type_abort(task->private_data, struct dcesrv_context);

	/*
	 * Ensure the single process endpoints are only available to the
	 * first instance.
	 */
	if (pd->instances == 0) {
		status = dcesrv_init_endpoints(task, dce_ctx, true);
		if (!NT_STATUS_IS_OK(status)) {
			task_server_terminate(
			    task,
			    "dcerpc: Failed to initialise end points",
			    true);
			return;
		}
	}

	irpc_add_name(task->msg_ctx, "rpc_server");
}

NTSTATUS server_service_rpc_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
	    .inhibit_fork_on_accept = false,
	    .inhibit_pre_fork = false,
	    .task_init = dcesrv_task_init,
	    .post_fork = dcesrv_post_fork};
	return register_server_service(ctx, "rpc", &details);
}

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

NTSTATUS server_service_rpc_init(TALLOC_CTX *);

/*
  open the dcerpc server sockets
*/
static void dcesrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct dcesrv_context *dce_ctx;
	struct dcesrv_endpoint *e;
	const struct model_ops *single_model_ops;

	dcerpc_server_init(task->lp_ctx);

	task_server_set_title(task, "task[dcesrv]");

	/*
	 * run the rpc server as a single process to allow for shard
	 * handles, and sharing of ldb contexts.
	 *
	 * We make an exception for NETLOGON below, and this follows
	 * whatever the top level is.
	 */
	single_model_ops = process_model_startup("single");
	if (!single_model_ops) goto failed;

	status = dcesrv_init_context(task->event_ctx,
				     task->lp_ctx,
				     lpcfg_dcerpc_endpoint_servers(task->lp_ctx),
				     &dce_ctx);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(lpcfg_ncalrpc_dir(task->lp_ctx))) {
		mkdir(lpcfg_ncalrpc_dir(task->lp_ctx), 0755);
	}

	for (e=dce_ctx->endpoint_list;e;e=e->next) {
		const struct model_ops *this_model_ops = single_model_ops;

		enum dcerpc_transport_t transport =
			dcerpc_binding_get_transport(e->ep_description);
		const char *transport_str
			= derpc_transport_string_by_transport(transport);

		struct dcesrv_if_list *iface_list;

		/*
		 * Ensure that -Msingle sets e->use_single_process for
		 * consistency
		 */

		if (task->model_ops == single_model_ops) {
			e->use_single_process = true;
		}

		if (transport == NCACN_HTTP) {
			/*
			 * We don't support ncacn_http yet
			 */
			continue;

			/*
			 * For the next two cases, what we are trying
			 * to do is put the NETLOGON server into the
			 * standard process model, not single, as it
			 * has no shared handles and takes a very high
			 * load.  We only do this for ncacn_np and
			 * ncacn_ip_tcp as otherwise it is too hard as
			 * all servers share a socket for ncalrpc and
			 * unix.
			 */
		} else if (e->use_single_process == false) {
			this_model_ops = task->model_ops;
		}

		status = dcesrv_add_ep(dce_ctx, task->lp_ctx, e, task->event_ctx,
				       this_model_ops);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}

		DEBUG(5,("Added endpoint on %s "
			 "using process model %s for",
			 transport_str,
			 this_model_ops->name));

		for (iface_list = e->interface_list;
		     iface_list != NULL;
		     iface_list = iface_list->next) {
			DEBUGADD(5, (" %s", iface_list->iface.name));
		}
		DEBUGADD(5, ("\n"));
	}

	irpc_add_name(task->msg_ctx, "rpc_server");
	return;
failed:
	task_server_terminate(task, "Failed to startup dcerpc server task", true);	
}

NTSTATUS server_service_rpc_init(TALLOC_CTX *ctx)
{
	return register_server_service(ctx, "rpc", dcesrv_task_init);
}

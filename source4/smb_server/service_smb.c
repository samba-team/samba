/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Andrew Tridgell	2004-2005
   Copyright (C) Stefan Metzmacher	2004-2005
   
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
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "smbd/service.h"
#include "smb_server/smb_server.h"
#include "smb_server/service_smb_proto.h"
#include "lib/messaging/irpc.h"
#include "lib/stream/packet.h"
#include "libcli/smb2/smb2.h"
#include "smb_server/smb2/smb2_server.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "param/share.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "ntvfs/ntvfs.h"
#include "lib/cmdline/popt_common.h"
/*
  open the smb server sockets
*/
static NTSTATUS smbsrv_task_init(struct task_server *task)
{	
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	task_server_set_title(task, "task[smbsrv]");

	if (lpcfg_interfaces(task->lp_ctx) && lpcfg_bind_interfaces_only(task->lp_ctx)) {
		int num_interfaces;
		int i;
		struct interface *ifaces;

		load_interface_list(task, task->lp_ctx, &ifaces);

		num_interfaces = iface_list_count(ifaces);

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_list_n_ip(ifaces, i);
			status = smbsrv_add_socket(task, task->event_ctx,
					           task->lp_ctx,
						   task->model_ops,
						   address,
						   task->process_context);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
	} else {
		char **wcard;
		int i;
		wcard = iface_list_wildcard(task);
		if (wcard == NULL) {
			DEBUG(0,("No wildcard addresses available\n"));
			status = NT_STATUS_UNSUCCESSFUL;
			goto failed;
		}
		for (i=0; wcard[i]; i++) {
			status = smbsrv_add_socket(task, task->event_ctx,
						   task->lp_ctx,
						   task->model_ops,
						   wcard[i],
						   task->process_context);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
		talloc_free(wcard);
	}

	irpc_add_name(task->msg_ctx, "smb_server");
	return NT_STATUS_OK;
failed:
	task_server_terminate(task, "Failed to startup smb server task", true);	
	return status;
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_smb_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = smbsrv_task_init,
		.post_fork = NULL
	};
	ntvfs_init(cmdline_lp_ctx);
	share_init();
	return register_server_service(ctx, "smb", &details);
}

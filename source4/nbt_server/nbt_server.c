/* 
   Unix SMB/CIFS implementation.

   NBT server task

   Copyright (C) Andrew Tridgell	2005
   
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
#include "smbd/service.h"
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsserver.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"

NTSTATUS server_service_nbtd_init(TALLOC_CTX *);

/*
  startup the nbtd task
*/
static NTSTATUS nbtd_task_init(struct task_server *task)
{
	struct nbtd_server *nbtsrv;
	NTSTATUS status;
	struct interface *ifaces;

	load_interface_list(task, task->lp_ctx, &ifaces);

	if (iface_list_count(ifaces) == 0) {
		task_server_terminate(task, "nbtd: no network interfaces configured", false);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (lpcfg_disable_netbios(task->lp_ctx)) {
		task_server_terminate(task, "nbtd: 'disable netbios = yes' set in smb.conf, shutting down nbt server", false);
		return NT_STATUS_UNSUCCESSFUL;
	}

	task_server_set_title(task, "task[nbtd]");

	nbtsrv = talloc(task, struct nbtd_server);
	if (nbtsrv == NULL) {
		task_server_terminate(task, "nbtd: out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}

	nbtsrv->task            = task;
	nbtsrv->interfaces      = NULL;
	nbtsrv->bcast_interface = NULL;
	nbtsrv->wins_interface  = NULL;

	/* start listening on the configured network interfaces */
	status = nbtd_startup_interfaces(nbtsrv, task->lp_ctx, ifaces);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to setup interfaces", true);
		return status;
	}

	nbtsrv->sam_ctx = samdb_connect(nbtsrv,
				        task->event_ctx,
					task->lp_ctx,
					system_session(task->lp_ctx),
					NULL,
					0);
	if (nbtsrv->sam_ctx == NULL) {
		task_server_terminate(task, "nbtd failed to open samdb", true);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* start the WINS server, if appropriate */
	status = nbtd_winsserver_init(nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to start WINS server", true);
		return status;
	}

	nbtd_register_irpc(nbtsrv);

	/* start the process of registering our names on all interfaces */
	nbtd_register_names(nbtsrv);

	irpc_add_name(task->msg_ctx, "nbt_server");

	return NT_STATUS_OK;
}


/*
  register ourselves as a available server
*/
NTSTATUS server_service_nbtd_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = nbtd_task_init,
		.post_fork = NULL
	};
	return register_server_service(ctx, "nbt", &details);
}

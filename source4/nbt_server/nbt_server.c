/* 
   Unix SMB/CIFS implementation.

   NBT server task

   Copyright (C) Andrew Tridgell	2005
   
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
#include "events.h"
#include "libcli/nbt/libnbt.h"
#include "smbd/service_task.h"
#include "nbt_server/nbt_server.h"


/*
  receive an incoming request
*/
static void nbt_request_handler(struct nbt_name_socket *nbtsock, 
				struct nbt_name_packet *packet, 
				const char *src_address, int src_port)
{
	struct nbt_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						      struct nbt_interface);
	DEBUG(0,("nbtd request from %s:%d\n", src_address, src_port));

	NDR_PRINT_DEBUG(nbt_name_packet, packet);
}


/*
  startup the nbtd task
*/
static void nbtd_task_init(struct task_server *task)
{
	struct nbt_server *nbtsrv;
	struct nbt_interface *iface;
	NTSTATUS status;

	nbtsrv = talloc(task, struct nbt_server);
	if (nbtsrv == NULL) {
		task_terminate(task, "nbtd: out of memory");
		return;
	}

	nbtsrv->task = task;
	nbtsrv->interfaces = NULL;

	/* start listening on the configured network interfaces */
	status = nbt_startup_interfaces(nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_terminate(task, "nbtd failed to setup interfaces");
		return;
	}

	/* setup the incoming request handler for all our interfaces */
	for (iface=nbtsrv->interfaces;iface;iface=iface->next) {
		nbt_set_incoming_handler(iface->nbtsock, nbt_request_handler, iface);
	}
}


/*
  initialise the nbt server
 */
static NTSTATUS nbtd_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, nbtd_task_init);
}


/*
  register ourselves as a available server
*/
NTSTATUS server_service_nbtd_init(void)
{
	return register_server_service("nbt", nbtd_init);
}

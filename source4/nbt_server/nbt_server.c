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
#include "samba/service_task.h"
#include "samba/service.h"
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsserver.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "dynconfig/dynconfig.h"
#include "lib/util/pidfile.h"
#include "lib/util/util_net.h"
#include "lib/socket/socket.h"
#include "../source3/include/fstring.h"
#include "../source3/libsmb/nmblib.h"
#include "../source3/libsmb/unexpected.h"
#include "../source3/lib/util_procid.h"

NTSTATUS server_service_nbtd_init(TALLOC_CTX *);

static void nbtd_server_msg_send_packet(struct imessaging_context *msg,
					void *private_data,
					uint32_t msg_type,
					struct server_id src,
					size_t num_fds,
					int *fds,
					DATA_BLOB *data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct nbtd_server *nbtsrv =
		talloc_get_type_abort(private_data,
		struct nbtd_server);
	struct packet_struct *p = (struct packet_struct *)data->data;
	struct sockaddr_storage ss;
	struct socket_address *dst = NULL;
	struct nbtd_interface *iface = NULL;
	char buf[1024] = { 0, };
	DATA_BLOB blob = { .length = 0, };

	DBG_DEBUG("Received send_packet from %u\n", (unsigned int)procid_to_pid(&src));

	if (data->length != sizeof(struct packet_struct)) {
		DBG_WARNING("Discarding invalid packet length from %u\n",
			  (unsigned int)procid_to_pid(&src));
		TALLOC_FREE(frame);
		return;
	}

	if ((p->packet_type != NMB_PACKET) &&
	    (p->packet_type != DGRAM_PACKET)) {
		DBG_WARNING("Discarding invalid packet type from %u: %d\n",
			  (unsigned int)procid_to_pid(&src), p->packet_type);
		TALLOC_FREE(frame);
		return;
	}

	if (p->packet_type == DGRAM_PACKET) {
		p->port = 138;
	}

	in_addr_to_sockaddr_storage(&ss, p->ip);
	dst = socket_address_from_sockaddr_storage(frame, &ss, p->port);
	if (dst == NULL) {
		TALLOC_FREE(frame);
		return;
	}
	if (p->port == 0) {
		DBG_WARNING("Discarding packet with missing port for addr[%s] "
			    "from %u\n",
			    dst->addr, (unsigned int)procid_to_pid(&src));
		TALLOC_FREE(frame);
		return;
	}

	iface = nbtd_find_request_iface(nbtsrv, dst->addr, true);
	if (iface == NULL) {
		DBG_WARNING("Could not find iface for packet to addr[%s] "
			    "from %u\n",
			    dst->addr, (unsigned int)procid_to_pid(&src));
		TALLOC_FREE(frame);
		return;
	}

	p->recv_fd = -1;
	p->send_fd = -1;

	if (p->packet_type == DGRAM_PACKET) {
		p->packet.dgram.header.source_ip.s_addr = interpret_addr(iface->ip_address);
		p->packet.dgram.header.source_port = 138;
	}

	blob.length = build_packet(buf, sizeof(buf), p);
	if (blob.length == 0) {
		TALLOC_FREE(frame);
		return;
	}
	blob.data = (uint8_t *)buf;

	if (p->packet_type == DGRAM_PACKET) {
		nbt_dgram_send_raw(iface->dgmsock, dst, blob);
	} else {
		nbt_name_send_raw(iface->nbtsock, dst, blob);
	}

	TALLOC_FREE(frame);
}

static int nbtd_server_destructor(struct nbtd_server *nbtsrv)
{
	struct task_server *task = nbtsrv->task;

	pidfile_unlink(lpcfg_pid_directory(task->lp_ctx), "nmbd");

	return 0;
}

/*
  startup the nbtd task
*/
static NTSTATUS nbtd_task_init(struct task_server *task)
{
	struct nbtd_server *nbtsrv;
	NTSTATUS status;
	struct interface *ifaces;
	const char *nmbd_socket_dir = NULL;
	int unexpected_clients;

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

	talloc_set_destructor(nbtsrv, nbtd_server_destructor);

	/* start listening on the configured network interfaces */
	status = nbtd_startup_interfaces(nbtsrv, task->lp_ctx, ifaces);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to setup interfaces", true);
		return status;
	}

	nmbd_socket_dir = lpcfg_parm_string(task->lp_ctx,
					    NULL,
					    "nmbd",
					    "socket dir");
	if (nmbd_socket_dir == NULL) {
		nmbd_socket_dir = get_dyn_NMBDSOCKETDIR();
	}

	unexpected_clients = lpcfg_parm_int(task->lp_ctx,
					    NULL,
					    "nmbd",
					    "unexpected_clients",
					    200);

	status = nb_packet_server_create(nbtsrv,
					 nbtsrv->task->event_ctx,
					 nmbd_socket_dir,
					 unexpected_clients,
					 &nbtsrv->unexpected_server);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to start unexpected_server", true);
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

	status = imessaging_register(task->msg_ctx,
				     nbtsrv,
				     MSG_SEND_PACKET,
				     nbtd_server_msg_send_packet);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed imessaging_register(MSG_SEND_PACKET)", true);
		return status;
	}

	/* start the process of registering our names on all interfaces */
	nbtd_register_names(nbtsrv);

	irpc_add_name(task->msg_ctx, "nbt_server");

	pidfile_create(lpcfg_pid_directory(task->lp_ctx), "nmbd");

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

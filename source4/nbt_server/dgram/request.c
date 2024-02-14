/* 
   Unix SMB/CIFS implementation.

   NBT datagram server

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
#include "nbt_server/nbt_server.h"
#include "samba/service_task.h"
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"
#include "nbt_server/dgram/proto.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "param/param.h"
#include "lib/util/util_str_escape.h"
#include "lib/util/util_net.h"
#include "../source3/include/fstring.h"
#include "../source3/libsmb/nmblib.h"
#include "../source3/libsmb/unexpected.h"

/*
  a list of mailslots that we have static handlers for
*/
static const struct {
	const char *mailslot_name;
	dgram_mailslot_handler_t handler;
} mailslot_handlers[] = {
	/* Handle both NTLOGON and NETLOGON in the same function, as
	 * they are very similar */
	{ NBT_MAILSLOT_NETLOGON, nbtd_mailslot_netlogon_handler },
	{ NBT_MAILSLOT_NTLOGON,  nbtd_mailslot_netlogon_handler },
	{ NBT_MAILSLOT_BROWSE,   nbtd_mailslot_browse_handler }
};

/*
  receive an incoming dgram request. This is used for general datagram
  requests. Mailslot requests for our listening mailslots
  are handled in the specific mailslot handlers
*/
void dgram_request_handler(struct nbt_dgram_socket *dgmsock, 
			   struct nbt_dgram_packet *packet,
			   struct socket_address *src)
{
	struct nbtd_interface *iface =
		talloc_get_type_abort(dgmsock->incoming.private_data,
		struct nbtd_interface);
	struct nbtd_server *nbtsrv = iface->nbtsrv;
	const char *mailslot_name = NULL;
	struct packet_struct *pstruct = NULL;
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;

	mailslot_name = dgram_mailslot_name(packet);
	if (mailslot_name != NULL) {
		DBG_DEBUG("Unexpected mailslot[%s] datagram request from %s:%d\n",
			  log_escape(packet, mailslot_name),
			  src->addr, src->port);
	} else {
		DBG_DEBUG("Unexpected general datagram request from %s:%d\n",
			  src->addr, src->port);
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(nbt_dgram_packet, packet);
	}

	/*
	 * For now we only pass DGRAM_DIRECT_UNIQUE
	 * messages via nb_packet_dispatch() to
	 * nbtsrv->unexpected_server
	 */
	if (packet->msg_type != DGRAM_DIRECT_UNIQUE) {
		return;
	}

	ndr_err = ndr_push_struct_blob(&blob, packet, packet,
			(ndr_push_flags_fn_t)ndr_push_nbt_dgram_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_push_nbt_dgram_packet - %s\n",
			ndr_errstr(ndr_err));
		return;
	}

	pstruct = parse_packet((char *)blob.data,
			       blob.length,
			       DGRAM_PACKET,
			       interpret_addr2(src->addr),
			       src->port);
	if (pstruct != NULL) {
		nb_packet_dispatch(nbtsrv->unexpected_server, pstruct);
		free_packet(pstruct);
	}
}


/*
  setup the port 138 datagram listener for a given interface
*/
NTSTATUS nbtd_dgram_setup(struct nbtd_interface *iface, const char *bind_address)
{
	struct nbt_dgram_socket *bcast_dgmsock = NULL;
	struct nbtd_server *nbtsrv = iface->nbtsrv;
	struct socket_address *bcast_addr, *bind_addr;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(iface);
	/* the list of mailslots that we are interested in */
	size_t i;

	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strcmp("0.0.0.0", iface->netmask) != 0) {
		/* listen for broadcasts on port 138 */
		bcast_dgmsock = nbt_dgram_socket_init(iface, nbtsrv->task->event_ctx);
		if (!bcast_dgmsock) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	
		bcast_addr = socket_address_from_strings(tmp_ctx, bcast_dgmsock->sock->backend_name, 
							 iface->bcast_address, 
							 lpcfg_dgram_port(iface->nbtsrv->task->lp_ctx));
		if (!bcast_addr) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		status = socket_listen(bcast_dgmsock->sock, bcast_addr, 0, 0);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			DEBUG(0,("Failed to bind to %s:%d - %s\n", 
				 iface->bcast_address, lpcfg_dgram_port(iface->nbtsrv->task->lp_ctx),
				 nt_errstr(status)));
			return status;
		}
	
		dgram_set_incoming_handler(bcast_dgmsock, dgram_request_handler, iface);
	}

	/* listen for unicasts on port 138 */
	iface->dgmsock = nbt_dgram_socket_init(iface, nbtsrv->task->event_ctx);
	if (!iface->dgmsock) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	bind_addr = socket_address_from_strings(tmp_ctx, iface->dgmsock->sock->backend_name, 
						bind_address, lpcfg_dgram_port(iface->nbtsrv->task->lp_ctx));
	if (!bind_addr) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = socket_listen(iface->dgmsock->sock, bind_addr, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 bind_address, lpcfg_dgram_port(iface->nbtsrv->task->lp_ctx), nt_errstr(status)));
		return status;
	}

	dgram_set_incoming_handler(iface->dgmsock, dgram_request_handler, iface);

	talloc_free(tmp_ctx);

	for (i=0;i<ARRAY_SIZE(mailslot_handlers);i++) {
		/* note that we don't need to keep the pointer
		   to the dgmslot around - the callback is all
		   we need */
		struct dgram_mailslot_handler *dgmslot;

		if (bcast_dgmsock) {
			dgmslot = dgram_mailslot_listen(bcast_dgmsock, 
						mailslot_handlers[i].mailslot_name,
						mailslot_handlers[i].handler, iface);
			NT_STATUS_HAVE_NO_MEMORY(dgmslot);
		}

		dgmslot = dgram_mailslot_listen(iface->dgmsock, 
						mailslot_handlers[i].mailslot_name,
						mailslot_handlers[i].handler, iface);
		NT_STATUS_HAVE_NO_MEMORY(dgmslot);
	}

	return NT_STATUS_OK;
}

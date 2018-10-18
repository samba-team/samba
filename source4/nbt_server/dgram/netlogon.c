/* 
   Unix SMB/CIFS implementation.

   NBT datagram netlogon server

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
  
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
#include "lib/socket/socket.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "param/param.h"
#include "smbd/service_task.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "libcli/security/security.h"
#include "nbt_server/dgram/proto.h"
#include "libds/common/roles.h"

/*
  reply to a GETDC request
 */
static NTSTATUS nbtd_netlogon_getdc(struct nbtd_server *nbtsrv,
				    struct nbt_name *dst_name,
				    struct nbt_netlogon_packet *netlogon,
				    TALLOC_CTX *mem_ctx,
				    struct nbt_netlogon_response **presponse,
				    char **preply_mailslot)
{
	struct nbt_netlogon_response_from_pdc *pdc;
	struct ldb_context *samctx;
	struct nbt_netlogon_response *response = NULL;
	char *reply_mailslot = NULL;

	/* only answer getdc requests on the PDC or LOGON names */
	if ((dst_name->type != NBT_NAME_PDC) &&
	    (dst_name->type != NBT_NAME_LOGON)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	samctx = nbtsrv->sam_ctx;

	if (lpcfg_server_role(nbtsrv->task->lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC
	    || !samdb_is_pdc(samctx)) {
		DEBUG(2, ("Not a PDC, so not processing LOGON_PRIMARY_QUERY\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (strcasecmp_m(dst_name->name,
			 lpcfg_workgroup(nbtsrv->task->lp_ctx)) != 0) {
		DBG_INFO("GetDC requested for a domain %s that we don't "
			 "host\n", dst_name->name);
		return NT_STATUS_NOT_SUPPORTED;
	}

	reply_mailslot = talloc_strdup(
		mem_ctx, netlogon->req.pdc.mailslot_name);
	if (reply_mailslot == NULL) {
		goto nomem;
	}

	/* setup a GETDC reply */
	response = talloc_zero(mem_ctx, struct nbt_netlogon_response);
	if (response == NULL) {
		goto nomem;
	}
	response->response_type = NETLOGON_GET_PDC;
	pdc = &response->data.get_pdc;

	pdc->command = NETLOGON_RESPONSE_FROM_PDC;

	pdc->pdc_name = talloc_strdup(
		response, lpcfg_netbios_name(nbtsrv->task->lp_ctx));
	if (pdc->pdc_name == NULL) {
		goto nomem;
	}

	pdc->unicode_pdc_name = pdc->pdc_name;

	pdc->domain_name = talloc_strdup(
		response, lpcfg_workgroup(nbtsrv->task->lp_ctx));
	if (pdc->domain_name == NULL) {
		goto nomem;
	}

	pdc->nt_version       = 1;
	pdc->lmnt_token       = 0xFFFF;
	pdc->lm20_token       = 0xFFFF;

	*presponse = response;
	*preply_mailslot = reply_mailslot;
	return NT_STATUS_OK;

nomem:
	TALLOC_FREE(response);
	TALLOC_FREE(reply_mailslot);
	return NT_STATUS_NO_MEMORY;
}

/*
  reply to a ADS style GETDC request
 */
static NTSTATUS nbtd_netlogon_samlogon(
	struct nbtd_server *nbtsrv,
	struct nbt_name *dst_name,
	const struct socket_address *src,
	struct nbt_netlogon_packet *netlogon,
	TALLOC_CTX *mem_ctx,
	struct nbt_netlogon_response **presponse,
	char **preply_mailslot)
{
	struct ldb_context *samctx;
	struct dom_sid *sid = NULL;
	struct nbt_netlogon_response *response = NULL;
	char *reply_mailslot = NULL;
	NTSTATUS status;

	/* only answer getdc requests on the PDC or LOGON names */
	if ((dst_name->type != NBT_NAME_PDC) &&
	    (dst_name->type != NBT_NAME_LOGON)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	samctx = nbtsrv->sam_ctx;

	if (netlogon->req.logon.sid_size != 0) {
		sid = &netlogon->req.logon.sid;
	}

	reply_mailslot = talloc_strdup(
		mem_ctx, netlogon->req.logon.mailslot_name);
	if (reply_mailslot == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	response = talloc_zero(mem_ctx, struct nbt_netlogon_response);
	if (response == NULL) {
		TALLOC_FREE(reply_mailslot);
		return NT_STATUS_NO_MEMORY;
	}
	response->response_type = NETLOGON_SAMLOGON;

	status = fill_netlogon_samlogon_response(
		samctx, response, NULL, dst_name->name, sid, NULL,
		netlogon->req.logon.user_name,
		netlogon->req.logon.acct_control, src->addr,
		netlogon->req.logon.nt_version, nbtsrv->task->lp_ctx,
		&response->data.samlogon, false);
	if (!NT_STATUS_IS_OK(status)) {
		struct dom_sid_buf buf;

		DBG_NOTICE("NBT netlogon query failed domain=%s sid=%s "
			   "version=%d - %s\n",
			   dst_name->name,
			   dom_sid_str_buf(sid, &buf),
			   netlogon->req.logon.nt_version,
			   nt_errstr(status));
		TALLOC_FREE(reply_mailslot);
		TALLOC_FREE(response);
		return status;
	}

	*presponse = response;
	*preply_mailslot = reply_mailslot;
	return NT_STATUS_OK;
}

static NTSTATUS nbtd_mailslot_netlogon_reply(
	struct nbtd_interface *iface,
	struct nbt_dgram_packet *packet,
	struct socket_address *src,
	TALLOC_CTX *mem_ctx,
	struct nbt_netlogon_response **presponse,
	char **preply_mailslot)
{
	struct nbt_netlogon_packet *netlogon;
	struct nbt_name *dst_name = &packet->data.msg.dest_name;
	struct nbt_netlogon_response *response = NULL;
	struct nbtd_iface_name *iname;
	char *reply_mailslot = NULL;
	NTSTATUS status;

	/*
	  see if the we are listening on the destination netbios name
	*/
	iname = nbtd_find_iname(iface, dst_name, 0);
	if (iname == NULL) {
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	netlogon = talloc(mem_ctx, struct nbt_netlogon_packet);
	if (netlogon == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dgram_mailslot_netlogon_parse_request(netlogon, packet,
						       netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	switch (netlogon->command) {
	case LOGON_PRIMARY_QUERY:
		status = nbtd_netlogon_getdc(
			iface->nbtsrv, &packet->data.msg.dest_name,
			netlogon, mem_ctx, &response, &reply_mailslot);
		break;
	case LOGON_SAM_LOGON_REQUEST:
		status = nbtd_netlogon_samlogon(
			iface->nbtsrv, &packet->data.msg.dest_name, src,
			netlogon, mem_ctx, &response, &reply_mailslot);
		break;
	default:
		DEBUG(2,("unknown netlogon op %d from %s:%d\n",
			 netlogon->command, src->addr, src->port));
		NDR_PRINT_DEBUG(nbt_netlogon_packet, netlogon);
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Calculating reply failed: %s\n",
			  nt_errstr(status));
		goto failed;
	}

	*presponse = response;
	*preply_mailslot = reply_mailslot;
	return NT_STATUS_OK;

failed:
	TALLOC_FREE(reply_mailslot);
	TALLOC_FREE(netlogon);
	return status;
}

/*
  handle incoming netlogon mailslot requests
*/
void nbtd_mailslot_netlogon_handler(struct dgram_mailslot_handler *dgmslot,
				    struct nbt_dgram_packet *packet,
				    struct socket_address *src)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct nbtd_interface *iface =
		talloc_get_type(dgmslot->private_data, struct nbtd_interface);
	struct nbtd_interface *reply_iface = nbtd_find_reply_iface(
		iface, src->addr, false);
	struct nbt_netlogon_response *response = NULL;
	char *reply_mailslot = NULL;

	if (reply_iface->ip_address == NULL) {
		DBG_WARNING("Could not obtain own IP address for datagram "
			    "socket\n");
		return;
	}

	status = nbtd_mailslot_netlogon_reply(
		iface, packet, src, dgmslot, &response, &reply_mailslot);

	if (NT_STATUS_IS_OK(status)) {
		dgram_mailslot_netlogon_reply(
			reply_iface->dgmsock, packet,
			lpcfg_netbios_name(iface->nbtsrv->task->lp_ctx),
			reply_mailslot, response);
	}

	TALLOC_FREE(response);
	TALLOC_FREE(reply_mailslot);
}

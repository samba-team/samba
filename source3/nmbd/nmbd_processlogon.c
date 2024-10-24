/*
   Unix SMB/CIFS implementation.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1994-1998
   Copyright (C) Jeremy Allison 1994-2003
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002

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

   Revision History:

*/

#include "includes.h"
#include "../libcli/netlogon/netlogon.h"
#include "../libcli/cldap/cldap.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "secrets.h"
#include "nmbd/nmbd.h"

struct sam_database_info {
        uint32_t index;
        uint32_t serial_lo, serial_hi;
        uint32_t date_lo, date_hi;
};

/**
 * check whether the client belongs to the hosts
 * for which initial logon should be delayed...
 */
static bool delay_logon(const char *peer_name, const char *peer_addr)
{
	const char **delay_list = lp_init_logon_delayed_hosts();
	const char *peer[2];

	if (delay_list == NULL) {
		return False;
	}

	peer[0] = peer_name;
	peer[1] = peer_addr;

	return list_match(delay_list, (const char *)peer, client_match);
}

static void delayed_init_logon_handler(struct tevent_context *event_ctx,
				       struct tevent_timer *te,
				       struct timeval now,
				       void *private_data)
{
	struct packet_struct *p = (struct packet_struct *)private_data;

	DEBUG(10, ("delayed_init_logon_handler (%lx): re-queuing packet.\n",
		   (unsigned long)te));

	queue_packet(p);

	TALLOC_FREE(te);
}

/****************************************************************************
Process a domain logon packet
**************************************************************************/

void process_logon_packet(struct packet_struct *p, const char *buf,int len,
                          const char *mailslot)
{
	fstring source_name;
	struct dgram_packet *dgram = &p->packet.dgram;
	struct sockaddr_storage ss;
	const struct sockaddr_storage *pss;
	struct in_addr ip;

	DATA_BLOB blob_in, blob_out;
	enum ndr_err_code ndr_err;
	struct nbt_netlogon_packet request;
	struct nbt_netlogon_response response;
	NTSTATUS status;
	const char *pdc_name;

	in_addr_to_sockaddr_storage(&ss, p->ip);
	pss = iface_ip((struct sockaddr *)&ss);
	if (!pss) {
		DEBUG(5,("process_logon_packet:can't find outgoing interface "
			"for packet from IP %s\n",
			inet_ntoa(p->ip) ));
		return;
	}
	ip = ((const struct sockaddr_in *)pss)->sin_addr;

	if (!IS_DC) {
		DEBUG(5,("process_logon_packet: Logon packet received from IP %s and domain \
logons are not enabled.\n", inet_ntoa(p->ip) ));
		return;
	}

	pull_ascii_nstring(source_name, sizeof(source_name), dgram->source_name.name);

	pdc_name = talloc_asprintf(talloc_tos(), "\\\\%s", lp_netbios_name());
	if (!pdc_name) {
		return;
	}

	ZERO_STRUCT(request);

	blob_in = data_blob_const(buf, len);

	ndr_err = ndr_pull_struct_blob(&blob_in, talloc_tos(), &request,
		(ndr_pull_flags_fn_t)ndr_pull_nbt_netlogon_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1,("process_logon_packet: Failed to pull logon packet\n"));
		return;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(nbt_netlogon_packet, &request);
	}

	DEBUG(4,("process_logon_packet: Logon from %s: code = 0x%x\n",
		inet_ntoa(p->ip), request.command));

	switch (request.command) {
	case LOGON_REQUEST: {

		struct nbt_netlogon_response2 response2;

		DEBUG(5,("process_logon_packet: Domain login request from %s at IP %s user=%s token=%x\n",
			request.req.logon0.computer_name, inet_ntoa(p->ip),
			request.req.logon0.user_name,
			request.req.logon0.lm20_token));

		response2.command	= LOGON_RESPONSE2;
		response2.pdc_name	= pdc_name;
		response2.lm20_token	= 0xffff;

		response.response_type = NETLOGON_RESPONSE2;
		response.data.response2 = response2;

		status = push_nbt_netlogon_response(&blob_out, talloc_tos(), &response);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("process_logon_packet: failed to push packet\n"));
			return;
		}

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(nbt_netlogon_response2, &response.data.response2);
		}

		send_mailslot(True, request.req.logon0.mailslot_name,
				(char *)blob_out.data,
				blob_out.length,
				lp_netbios_name(), 0x0,
				source_name,
				dgram->source_name.name_type,
				p->ip, ip, p->port);
		break;
	}

	case LOGON_PRIMARY_QUERY: {

		struct nbt_netlogon_response_from_pdc get_pdc;

		if (!lp_domain_master()) {
			/* We're not Primary Domain Controller -- ignore this */
			return;
		}

		DEBUG(5,("process_logon_packet: GETDC request from %s at IP %s, "
			"reporting %s domain %s 0x%x ntversion=%x lm_nt token=%x lm_20 token=%x\n",
			request.req.pdc.computer_name,
			inet_ntoa(p->ip),
			lp_netbios_name(),
			lp_workgroup(),
			NETLOGON_RESPONSE_FROM_PDC,
			request.req.pdc.nt_version,
			request.req.pdc.lmnt_token,
			request.req.pdc.lm20_token));

		get_pdc.command			= NETLOGON_RESPONSE_FROM_PDC;
		get_pdc.pdc_name		= lp_netbios_name();
		get_pdc._pad			= data_blob_null;
		get_pdc.unicode_pdc_name	= lp_netbios_name();
		get_pdc.domain_name		= lp_workgroup();
		get_pdc.nt_version		= NETLOGON_NT_VERSION_1;
		get_pdc.lmnt_token		= 0xffff;
		get_pdc.lm20_token		= 0xffff;

		response.response_type = NETLOGON_GET_PDC;
		response.data.get_pdc = get_pdc;

		status = push_nbt_netlogon_response(&blob_out, talloc_tos(), &response);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("process_logon_packet: failed to push packet\n"));
			return;
		}

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(nbt_netlogon_response_from_pdc, &response.data.get_pdc);
		}

		send_mailslot(True, request.req.pdc.mailslot_name,
			(char *)blob_out.data,
			blob_out.length,
			lp_netbios_name(), 0x0,
			source_name,
			dgram->source_name.name_type,
			p->ip, ip, p->port);

		return;
	}

	case LOGON_SAM_LOGON_REQUEST: {
		char *source_addr;
		bool user_unknown = false;

		struct netlogon_samlogon_response samlogon;
		struct NETLOGON_SAM_LOGON_RESPONSE_NT40 nt4;

		source_addr = SMB_STRDUP(inet_ntoa(dgram->header.source_ip));
		if (source_addr == NULL) {
			DEBUG(3, ("out of memory copying client"
				  " address string\n"));
			return;
		}

		DEBUG(5,("process_logon_packet: LOGON_SAM_LOGON_REQUEST request from %s(%s) for %s, returning logon svr %s domain %s code %x token=%x\n",
			request.req.logon.computer_name,
			inet_ntoa(p->ip),
			request.req.logon.user_name,
			pdc_name,
			lp_workgroup(),
			LOGON_SAM_LOGON_RESPONSE,
			request.req.logon.lmnt_token));

		if (!request.req.logon.user_name) {
			user_unknown = true;
		}

		nt4.command		= user_unknown ? LOGON_SAM_LOGON_USER_UNKNOWN :
			LOGON_SAM_LOGON_RESPONSE;
		nt4.pdc_name		= pdc_name;
		nt4.user_name		= request.req.logon.user_name;
		nt4.domain_name		= lp_workgroup();
		nt4.nt_version		= NETLOGON_NT_VERSION_1;
		nt4.lmnt_token		= 0xffff;
		nt4.lm20_token		= 0xffff;
		
		samlogon.ntver = NETLOGON_NT_VERSION_1;
		samlogon.data.nt4 = nt4;
		
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(NETLOGON_SAM_LOGON_RESPONSE_NT40, &nt4);
		}

		response.response_type = NETLOGON_SAMLOGON;
		response.data.samlogon = samlogon;

		status = push_nbt_netlogon_response(&blob_out, talloc_tos(), &response);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("process_logon_packet: failed to push packet\n"));
			SAFE_FREE(source_addr);
			return;
		}

		/*
		 * handle delay.
		 * packets requeued after delay are marked as
		 * locked.
		 */
		if ((p->locked == False) &&
		    (strlen(request.req.logon.user_name) == 0) &&
		    delay_logon(source_name, source_addr))
		{
			struct timeval when;

			DEBUG(3, ("process_logon_packet: "
				  "delaying initial logon "
				  "reply for client %s(%s) for "
				  "%u milliseconds\n",
				  source_name, source_addr,
				  lp_init_logon_delay()));

			when = timeval_current_ofs_msec(lp_init_logon_delay());
			p->locked = true;
			tevent_add_timer(nmbd_event_context(),
					NULL,
					when,
					delayed_init_logon_handler,
					p);
		} else {
			DEBUG(3, ("process_logon_packet: "
				  "processing delayed initial "
				  "logon reply for client "
				  "%s(%s)\n",
				  source_name, source_addr));
			p->locked = false;
			send_mailslot(true, request.req.logon.mailslot_name,
				(char *)blob_out.data,
				blob_out.length,
				lp_netbios_name(), 0x0,
				source_name,
				dgram->source_name.name_type,
				p->ip, ip, p->port);
		}

		SAFE_FREE(source_addr);

		break;
	}

	/* Announce change to UAS or SAM.  Send by the domain controller when a
	replication event is required. */

	case NETLOGON_ANNOUNCE_UAS:
		DEBUG(5, ("Got NETLOGON_ANNOUNCE_UAS\n"));
		break;

	default:
		DEBUG(3,("process_logon_packet: Unknown domain request %d\n",
			request.command));
		return;
	}
}

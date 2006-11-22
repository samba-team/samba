/* 
   Unix SMB/CIFS implementation.

   NBT datagram netlogon server

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
#include "nbt_server/nbt_server.h"
#include "lib/socket/socket.h"
#include "lib/ldb/include/ldb.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "db_wrap.h"
#include "librpc/gen_ndr/ndr_nbt.h"

/*
  reply to a GETDC request
 */
static void nbtd_netlogon_getdc(struct dgram_mailslot_handler *dgmslot, 
				struct nbtd_interface *iface,
				struct nbt_dgram_packet *packet, 
				const struct socket_address *src,
				struct nbt_netlogon_packet *netlogon)
{
	struct nbt_name *name = &packet->data.msg.dest_name;
	struct nbtd_interface *reply_iface = nbtd_find_reply_iface(iface, src->addr, False);
	struct nbt_netlogon_packet reply;
	struct nbt_netlogon_response_from_pdc *pdc;
	const char *ref_attrs[] = {"nETBIOSName", NULL};
	struct ldb_message **ref_res;
	struct ldb_context *samctx;
	struct ldb_dn *partitions_basedn;
	int ret;

	/* only answer getdc requests on the PDC or LOGON names */
	if (name->type != NBT_NAME_PDC && name->type != NBT_NAME_LOGON) {
		return;
	}

	samctx = samdb_connect(packet, anonymous_session(packet));
	if (samctx == NULL) {
		DEBUG(2,("Unable to open sam in getdc reply\n"));
		return;
	}

	partitions_basedn = samdb_partitions_dn(samctx, samctx);

	ret = gendb_search(samctx, samctx, partitions_basedn, &ref_res, ref_attrs,
			   "(&(&(nETBIOSName=%s)(objectclass=crossRef))(ncName=*))", 
			   name->name);
	
	if (ret != 1) {
		DEBUG(2,("Unable to find domain reference '%s' in sam\n", name->name));
		return;
	}

	/* setup a GETDC reply */
	ZERO_STRUCT(reply);
	reply.command = NETLOGON_RESPONSE_FROM_PDC;
	pdc = &reply.req.response;

	pdc->pdc_name         = lp_netbios_name();
	pdc->unicode_pdc_name = pdc->pdc_name;
	pdc->domain_name      = samdb_result_string(ref_res[0], "nETBIOSName", name->name);;
	pdc->nt_version       = 1;
	pdc->lmnt_token       = 0xFFFF;
	pdc->lm20_token       = 0xFFFF;


	packet->data.msg.dest_name.type = 0;

	dgram_mailslot_netlogon_reply(reply_iface->dgmsock, 
				      packet, 
				      netlogon->req.pdc.mailslot_name,
				      &reply);
}


/*
  reply to a ADS style GETDC request
 */
static void nbtd_netlogon_getdc2(struct dgram_mailslot_handler *dgmslot,
				 struct nbtd_interface *iface,
				 struct nbt_dgram_packet *packet, 
				 const struct socket_address *src,
				 struct nbt_netlogon_packet *netlogon)
{
	struct nbt_name *name = &packet->data.msg.dest_name;
	struct nbtd_interface *reply_iface = nbtd_find_reply_iface(iface, src->addr, False);
	struct nbt_netlogon_packet reply;
	struct nbt_netlogon_response_from_pdc2 *pdc;
	struct ldb_context *samctx;
	const char *ref_attrs[] = {"nETBIOSName", "dnsRoot", "ncName", NULL};
	const char *dom_attrs[] = {"objectGUID", NULL};
	struct ldb_message **ref_res, **dom_res;
	int ret;
	const char **services = lp_server_services();
	const char *my_ip = reply_iface->ip_address; 
	struct ldb_dn *partitions_basedn;
	if (!my_ip) {
		DEBUG(0, ("Could not obtain own IP address for datagram socket\n"));
		return;
	}

	/* only answer getdc requests on the PDC or LOGON names */
	if (name->type != NBT_NAME_PDC && name->type != NBT_NAME_LOGON) {
		return;
	}

	samctx = samdb_connect(packet, anonymous_session(packet));
	if (samctx == NULL) {
		DEBUG(2,("Unable to open sam in getdc reply\n"));
		return;
	}

	partitions_basedn = samdb_partitions_dn(samctx, samctx);

	ret = gendb_search(samctx, samctx, partitions_basedn, &ref_res, ref_attrs,
				  "(&(&(nETBIOSName=%s)(objectclass=crossRef))(ncName=*))", 
				  name->name);
	
	if (ret != 1) {
		DEBUG(2,("Unable to find domain reference '%s' in sam\n", name->name));
		return;
	}

	/* try and find the domain */
	ret = gendb_search_dn(samctx, samctx, 
			      samdb_result_dn(samctx, samctx, ref_res[0], "ncName", NULL), 
			      &dom_res, dom_attrs);
	if (ret != 1) {
		DEBUG(2,("Unable to find domain from reference '%s' in sam\n",
			 ldb_dn_get_linearized(ref_res[0]->dn)));
		return;
	}

	/* setup a GETDC reply */
	ZERO_STRUCT(reply);
	reply.command = NETLOGON_RESPONSE_FROM_PDC2;

#if 0
	/* newer testing shows that the reply command type is not
	   changed based on whether a username is given in the
	   reply. This was what was causing the w2k join to be so
	   slow */
	if (netlogon->req.pdc2.user_name[0]) {
		reply.command = NETLOGON_RESPONSE_FROM_PDC_USER;
	}
#endif

	pdc = &reply.req.response2;

	/* TODO: accurately depict which services we are running */
	pdc->server_type      = 
		NBT_SERVER_PDC | NBT_SERVER_GC | 
		NBT_SERVER_DS | NBT_SERVER_TIMESERV |
		NBT_SERVER_CLOSEST | NBT_SERVER_WRITABLE | 
		NBT_SERVER_GOOD_TIMESERV;

	/* hmm, probably a better way to do this */
	if (str_list_check(services, "ldap")) {
		pdc->server_type |= NBT_SERVER_LDAP;
	}

	if (str_list_check(services, "kdc")) {
		pdc->server_type |= NBT_SERVER_KDC;
	}

	pdc->domain_uuid      = samdb_result_guid(dom_res[0], "objectGUID");
	pdc->forest           = samdb_result_string(ref_res[0], "dnsRoot", lp_realm());
	pdc->dns_domain       = samdb_result_string(ref_res[0], "dnsRoot", lp_realm());

	/* TODO: get our full DNS name from somewhere else */
	pdc->pdc_dns_name     = talloc_asprintf(packet, "%s.%s", 
						strlower_talloc(packet, lp_netbios_name()), 
						pdc->dns_domain);
	pdc->domain           = samdb_result_string(ref_res[0], "nETBIOSName", name->name);;
	pdc->pdc_name         = lp_netbios_name();
	pdc->user_name        = netlogon->req.pdc2.user_name;
	/* TODO: we need to make sure these are in our DNS zone */
	pdc->server_site      = "Default-First-Site-Name";
	pdc->client_site      = "Default-First-Site-Name";
	pdc->unknown          = 0x10; /* what is this? */
	pdc->unknown2         = 2; /* and this ... */
	pdc->pdc_ip           = my_ip;
	pdc->nt_version       = 13;
	pdc->lmnt_token       = 0xFFFF;
	pdc->lm20_token       = 0xFFFF;

	packet->data.msg.dest_name.type = 0;

	dgram_mailslot_netlogon_reply(reply_iface->dgmsock, 
				      packet, 
				      netlogon->req.pdc2.mailslot_name,
				      &reply);
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
		talloc_get_type(dgmslot->private, struct nbtd_interface);
	struct nbt_netlogon_packet *netlogon = 
		talloc(dgmslot, struct nbt_netlogon_packet);
	struct nbtd_iface_name *iname;
	struct nbt_name *name = &packet->data.msg.dest_name;

	if (netlogon == NULL) goto failed;

	/*
	  see if the we are listening on the destination netbios name
	*/
	iname = nbtd_find_iname(iface, name, 0);
	if (iname == NULL) {
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto failed;
	}

	DEBUG(2,("netlogon request to %s from %s:%d\n", 
		 nbt_name_string(netlogon, name), src->addr, src->port));
	status = dgram_mailslot_netlogon_parse(dgmslot, netlogon, packet, netlogon);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	switch (netlogon->command) {
	case NETLOGON_QUERY_FOR_PDC:
		nbtd_netlogon_getdc(dgmslot, iface, packet, src, netlogon);
		break;
	case NETLOGON_QUERY_FOR_PDC2:
		nbtd_netlogon_getdc2(dgmslot, iface, packet, src, netlogon);
		break;
	default:
		DEBUG(2,("unknown netlogon op %d from %s:%d\n", 
			 netlogon->command, src->addr, src->port));
		NDR_PRINT_DEBUG(nbt_netlogon_packet, netlogon);
		break;
	}

	talloc_free(netlogon);
	return;

failed:
	DEBUG(2,("nbtd netlogon handler failed from %s:%d to %s - %s\n",
		 src->addr, src->port, nbt_name_string(netlogon, name),
		 nt_errstr(status)));
	talloc_free(netlogon);
}

/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2003 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2008 Guenther Deschner (gd@samba.org)
   Copyright (C) 2009 Stefan Metzmacher (metze@samba.org)

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
#include "../libcli/cldap/cldap.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "libads/cldap.h"
#include "libads/netlogon_ping.h"

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

static bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			       struct sockaddr_storage *ss,
			       const char *realm,
			       uint32_t nt_version,
			       uint32_t required_flags,
			       struct netlogon_samlogon_response **_reply)
{
	NTSTATUS status;
	char addrstr[INET6_ADDRSTRLEN];
	const char *dest_str;
	struct tsocket_address *dest_addr;
	struct netlogon_samlogon_response **responses = NULL;
	int ret;

	dest_str = print_sockaddr(addrstr, sizeof(addrstr), ss);

	ret = tsocket_address_inet_from_strings(mem_ctx, "ip",
						dest_str, LDAP_PORT,
						&dest_addr);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		DEBUG(2,("Failed to create cldap tsocket_address for %s - %s\n",
			 dest_str, nt_errstr(status)));
		return false;
	}

	status = netlogon_pings(
		talloc_tos(),			    /* mem_ctx */
		lp_client_netlogon_ping_protocol(), /*proto */
		&dest_addr,			    /* servers */
		1,				    /* num_servers */
		(struct netlogon_ping_filter) {
			.ntversion = nt_version,
			.domain = realm,
			.acct_ctrl = -1,
			.required_flags = required_flags,
		},
		1,				    /* wanted_servers */
		timeval_current_ofs(MAX(3, lp_ldap_timeout() / 2), 0),
		&responses);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("netlogon_pings failed: %s\n", nt_errstr(status));
		return false;
	}
	if (responses == NULL || responses[0] == NULL) {
		DBG_NOTICE("did not get a reply\n");
		TALLOC_FREE(responses);
		return false;
	}
	*_reply = talloc_move(mem_ctx, &responses[0]);

	return true;
}

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  struct sockaddr_storage *ss,
			  const char *realm,
			  uint32_t required_flags,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5)
{
	uint32_t nt_version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	struct netlogon_samlogon_response *reply = NULL;
	bool ret;

	ret = ads_cldap_netlogon(
		mem_ctx, ss, realm, nt_version, required_flags, &reply);
	if (!ret) {
		return false;
	}

	if (reply->ntver != NETLOGON_NT_VERSION_5EX) {
		DEBUG(0,("ads_cldap_netlogon_5: nt_version mismatch: 0x%08x\n",
			reply->ntver));
		return false;
	}

	*reply5 = reply->data.nt5_ex;

	return true;
}

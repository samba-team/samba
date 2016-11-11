/* 
   Unix SMB/CIFS implementation.

   check access rules for socket connections

   Copyright (C) Andrew Tridgell 2004
   
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


/* 
   This module is an adaption of code from the tcpd-1.4 package written
   by Wietse Venema, Eindhoven University of Technology, The Netherlands.

   The code is used here with permission.

   The code has been considerably changed from the original. Bug reports
   should be sent to samba-technical@lists.samba.org
*/

#include "includes.h"
#include "system/network.h"
#include "lib/socket/socket.h"
#include "lib/util/util_net.h"
#include "lib/util/access.h"

/* return true if the char* contains ip addrs only.  Used to avoid 
gethostbyaddr() calls */

static bool only_ipaddrs_in_list(const char** list)
{
	bool only_ip = true;
	
	if (!list)
		return true;
			
	for (; *list ; list++) {
		/* factor out the special strings */
		if (strcmp(*list, "ALL")==0 || 
		    strcmp(*list, "FAIL")==0 || 
		    strcmp(*list, "EXCEPT")==0) {
			continue;
		}
		
		if (!is_ipaddress(*list)) {
			/* 
			 * if we failed, make sure that it was not because the token
			 * was a network/netmask pair.  Only network/netmask pairs
			 * have a '/' in them
			 */
			if ((strchr(*list, '/')) == NULL) {
				only_ip = false;
				DEBUG(3,("only_ipaddrs_in_list: list has non-ip address (%s)\n", *list));
				break;
			}
		}
	}
	
	return only_ip;
}

/* return true if access should be allowed to a service for a socket */
bool socket_check_access(struct socket_context *sock, 
			 const char *service_name,
			 const char **allow_list, const char **deny_list)
{
	bool ret;
	const char *name="";
	struct socket_address *addr;
	TALLOC_CTX *mem_ctx;

	if ((!deny_list  || *deny_list==0) && 
	    (!allow_list || *allow_list==0)) {
		return true;
	}

	mem_ctx = talloc_init("socket_check_access");
	if (!mem_ctx) {
		return false;
	}

	addr = socket_get_peer_addr(sock, mem_ctx);
	if (!addr) {
		DEBUG(0,("socket_check_access: Denied connection from unknown host: could not get peer address from kernel\n"));
		talloc_free(mem_ctx);
		return false;
	}

	/* bypass gethostbyaddr() calls if the lists only contain IP addrs */
	if (!only_ipaddrs_in_list(allow_list) || 
	    !only_ipaddrs_in_list(deny_list)) {
		name = socket_get_peer_name(sock, mem_ctx);
		if (!name) {
			name = addr->addr;
		}
	}

	if (!addr) {
		DEBUG(0,("socket_check_access: Denied connection from unknown host\n"));
		talloc_free(mem_ctx);
		return false;
	}

	ret = allow_access(deny_list, allow_list, name, addr->addr);
	
	if (ret) {
		DEBUG(2,("socket_check_access: Allowed connection to '%s' from %s (%s)\n", 
			 service_name, name, addr->addr));
	} else {
		DEBUG(0,("socket_check_access: Denied connection to '%s' from %s (%s)\n", 
			 service_name, name, addr->addr));
	}

	talloc_free(mem_ctx);

	return ret;
}

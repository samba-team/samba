/* 
   Unix SMB/CIFS implementation.

   Winbind daemon connection manager

   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "includes.h"


/*
  find the DC for a domain using methods appropriate for a RPC domain
*/
BOOL rpc_find_dc(const char *domain, fstring srv_name, struct ipv4_addr *ip_out)
{
	struct ipv4_addr *ip_list = NULL, dc_ip, exclude_ip;
	int count, i;
	BOOL list_ordered;
	BOOL use_pdc_only;
	
	zero_ip(&exclude_ip);

	use_pdc_only = must_use_pdc(domain);
	
	/* Lookup domain controller name */
	   
	if ( use_pdc_only && get_pdc_ip(domain, &dc_ip) ) {
		DEBUG(10,("rpc_find_dc: Atempting to lookup PDC to avoid sam sync delays\n"));
		
		if (name_status_find(domain, 0x1c, 0x20, dc_ip, srv_name)) {
			goto done;
		}
		/* Didn't get name, remember not to talk to this DC. */
		exclude_ip = dc_ip;
	}

	/* get a list of all domain controllers */
	
	if (!get_dc_list( domain, &ip_list, &count, &list_ordered) ) {
		DEBUG(3, ("Could not look up dc's for domain %s\n", domain));
		return False;
	}

	/* Remove the entry we've already failed with (should be the PDC). */

	if ( use_pdc_only ) {
		for (i = 0; i < count; i++) {	
			if (ipv4_equal( exclude_ip, ip_list[i]))
				zero_ip(&ip_list[i]);
		}
	}

	/* Pick a nice close server, but only if the list was not ordered */
	if (!list_ordered && (count > 1) ) {
		qsort(ip_list, count, sizeof(struct ipv4_addr), QSORT_CAST ip_compare);
	}

	for (i = 0; i < count; i++) {
		if (is_zero_ip(ip_list[i]))
			continue;

		if (name_status_find(domain, 0x1c, 0x20, ip_list[i], srv_name)) {
			dc_ip = ip_list[i];
			goto done;
		}
	}


	SAFE_FREE(ip_list);

	return False;
done:
	/* We have the netbios name and IP address of a domain controller.
	   Ideally we should sent a SAMLOGON request to determine whether
	   the DC is alive and kicking.  If we can catch a dead DC before
	   performing a smbcli_connect() we can avoid a 30-second timeout. */

	DEBUG(3, ("rpc_find_dc: Returning DC %s (%s) for domain %s\n", srv_name,
		  inet_ntoa(dc_ip), domain));

	*ip_out = dc_ip;

	SAFE_FREE(ip_list);

	return True;
}


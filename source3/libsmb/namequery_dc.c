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

/****************************************************************************
 Utility function to return the name of a DC. The name is guaranteed to be 
 valid since we have already done a name_status_find on it 
 ***************************************************************************/

BOOL rpc_dc_name(const char *domain, fstring srv_name, struct in_addr *ip_out)
{
	struct ip_service *ip_list = NULL;
	struct in_addr dc_ip, exclude_ip;
	int count, i;
	BOOL use_pdc_only;
	NTSTATUS result;
	
	zero_ip(&exclude_ip);

	use_pdc_only = must_use_pdc(domain);
	
	/* Lookup domain controller name */
	   
	if ( use_pdc_only && get_pdc_ip(domain, &dc_ip) ) 
	{
		DEBUG(10,("rpc_dc_name: Atempting to lookup PDC to avoid sam sync delays\n"));
		
		/* check the connection cache and perform the node status 
		   lookup only if the IP is not found to be bad */

		if (name_status_find(domain, 0x1b, 0x20, dc_ip, srv_name) ) {
			result = check_negative_conn_cache( domain, srv_name );
			if ( NT_STATUS_IS_OK(result) )
				goto done;
		}
		/* Didn't get name, remember not to talk to this DC. */
		exclude_ip = dc_ip;
	}

	/* get a list of all domain controllers */
	
	if ( !get_sorted_dc_list(domain, &ip_list, &count, False) ) {
		DEBUG(3, ("Could not look up dc's for domain %s\n", domain));
		return False;
	}

	/* Remove the entry we've already failed with (should be the PDC). */

	if ( use_pdc_only ) {
		for (i = 0; i < count; i++) {	
			if (ip_equal( exclude_ip, ip_list[i].ip))
				zero_ip(&ip_list[i].ip);
		}
	}

	for (i = 0; i < count; i++) {
		if (is_zero_ip(ip_list[i].ip))
			continue;

		if (name_status_find(domain, 0x1c, 0x20, ip_list[i].ip, srv_name)) {
			result = check_negative_conn_cache( domain, srv_name );
			if ( NT_STATUS_IS_OK(result) ) {
				dc_ip = ip_list[i].ip;
				goto done;
			}
		}
	}
	

	SAFE_FREE(ip_list);

	/* No-one to talk to )-: */
	return False;		/* Boo-hoo */
	
 done:
	/* We have the netbios name and IP address of a domain controller.
	   Ideally we should sent a SAMLOGON request to determine whether
	   the DC is alive and kicking.  If we can catch a dead DC before
	   performing a cli_connect() we can avoid a 30-second timeout. */

	DEBUG(3, ("rpc_dc_name: Returning DC %s (%s) for domain %s\n", srv_name,
		  inet_ntoa(dc_ip), domain));

	*ip_out = dc_ip;

	SAFE_FREE(ip_list);

	return True;
}

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


#define FAILED_CONNECTION_CACHE_TIMEOUT 30 /* Seconds between attempts */

struct failed_connection_cache {
	fstring domain_name;
	fstring controller;
	time_t lookup_time;
	NTSTATUS nt_status;
	struct failed_connection_cache *prev, *next;
};

static struct failed_connection_cache *failed_connection_cache;

/**********************************************************************
 Check for a previously failed connection
**********************************************************************/

static NTSTATUS check_negative_conn_cache( const char *domain, const char *server )
{
	struct failed_connection_cache *fcc;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	
	/* can't check if we don't have strings */
	
	if ( !domain || !server )
		return NT_STATUS_OK;

	for (fcc = failed_connection_cache; fcc; fcc = fcc->next) {
		
		/* 
		 * we have a match IFF the domain and server name matches
		 *   (a) the domain matches, 
		 *   (b) the IP address matches (if we have one)
		 *   (c) the server name (if specified) matches
		 */
		 
		if ( !strequal(domain, fcc->domain_name) || !strequal(server, fcc->controller) )
			continue; /* no match; check the next entry */
		
		/* we have a match so see if it is still current */

		if ((time(NULL) - fcc->lookup_time) > FAILED_CONNECTION_CACHE_TIMEOUT) 
		{
			/* Cache entry has expired, delete it */

			DEBUG(10, ("check_negative_conn_cache: cache entry expired for %s, %s\n", 
				domain, server ));

			DLIST_REMOVE(failed_connection_cache, fcc);
			SAFE_FREE(fcc);

			return NT_STATUS_OK;
		}

		/* The timeout hasn't expired yet so return false */

		DEBUG(10, ("check_negative_conn_cache: returning negative entry for %s, %s\n", 
			domain, server ));

		result = fcc->nt_status;
		return result;
	}

	/* end of function means no cache entry */	
	return NT_STATUS_OK;
}

/**********************************************************************
 Add an entry to the failed conneciton cache
**********************************************************************/

void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) 
{
	struct failed_connection_cache *fcc;

	SMB_ASSERT(!NT_STATUS_IS_OK(result));

	/* Check we already aren't in the cache.  We always have to have 
	   a domain, but maybe not a specific DC name. */

	for (fcc = failed_connection_cache; fcc; fcc = fcc->next) {
		if ( strequal(fcc->domain_name, domain) && strequal(fcc->controller, server) ) 
		{
			DEBUG(10, ("add_failed_connection_entry: domain %s (%s) already tried and failed\n",
				   domain, server ));
			return;
		}
	}

	/* Create negative lookup cache entry for this domain and controller */

	if ( !(fcc = (struct failed_connection_cache *)malloc(sizeof(struct failed_connection_cache))) ) 
	{
		DEBUG(0, ("malloc failed in add_failed_connection_entry!\n"));
		return;
	}
	
	ZERO_STRUCTP(fcc);
	
	fstrcpy( fcc->domain_name, domain );
	fstrcpy( fcc->controller, server );
	fcc->lookup_time = time(NULL);
	fcc->nt_status = result;
	
	DEBUG(10,("add_failed_connection_entry: added domain %s (%s) to failed conn cache\n",
		domain, server ));
	
	DLIST_ADD(failed_connection_cache, fcc);
}

/****************************************************************************
****************************************************************************/
 
void flush_negative_conn_cache( void )
{
	struct failed_connection_cache *fcc;
	
	fcc = failed_connection_cache;

	while (fcc) {
		struct failed_connection_cache *fcc_next;

		fcc_next = fcc->next;
		DLIST_REMOVE(failed_connection_cache, fcc);
		free(fcc);

		fcc = fcc_next;
	}

}

/****************************************************************************
 Utility function to return the name of a DC using RPC. The name is 
 guaranteed to be valid since we have already done a name_status_find on it 
 and we have checked our negative connection cache
 ***************************************************************************/
 
BOOL rpc_find_dc(const char *domain, fstring srv_name, struct in_addr *ip_out)
{
	struct in_addr *ip_list = NULL, dc_ip, exclude_ip;
	int count, i;
	BOOL list_ordered;
	BOOL use_pdc_only;
	NTSTATUS result;
	
	zero_ip(&exclude_ip);

	use_pdc_only = must_use_pdc(domain);
	
	/* Lookup domain controller name */
	   
	if ( use_pdc_only && get_pdc_ip(domain, &dc_ip) ) 
	{
		DEBUG(10,("rpc_find_dc: Atempting to lookup PDC to avoid sam sync delays\n"));
		
		if (name_status_find(domain, 0x1c, 0x20, dc_ip, srv_name)) {
			/* makre we we haven't tried this on previously and failed */
			result = check_negative_conn_cache( domain, srv_name );
			if ( NT_STATUS_IS_OK(result) )
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
			if (ip_equal( exclude_ip, ip_list[i]))
				zero_ip(&ip_list[i]);
		}
	}

	/* Pick a nice close server, but only if the list was not ordered */
	if (!list_ordered && (count > 1) ) {
		qsort(ip_list, count, sizeof(struct in_addr), QSORT_CAST ip_compare);
	}

	for (i = 0; i < count; i++) {
		if (is_zero_ip(ip_list[i]))
			continue;

		if (name_status_find(domain, 0x1c, 0x20, ip_list[i], srv_name)) {
			result = check_negative_conn_cache( domain, srv_name );
			if ( NT_STATUS_IS_OK(result) ) {
				dc_ip = ip_list[i];
				goto done;
			}
		}
	}


	SAFE_FREE(ip_list);

	return False;
done:
	/* We have the netbios name and IP address of a domain controller.
	   Ideally we should sent a SAMLOGON request to determine whether
	   the DC is alive and kicking.  If we can catch a dead DC before
	   performing a cli_connect() we can avoid a 30-second timeout. */

	DEBUG(3, ("rpc_find_dc: Returning DC %s (%s) for domain %s\n", srv_name,
		  inet_ntoa(dc_ip), domain));

	*ip_out = dc_ip;

	SAFE_FREE(ip_list);

	return True;
}


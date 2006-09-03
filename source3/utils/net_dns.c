
/* 
   Samba Unix/Linux Dynamic DNS Update
   net ads commands

   Copyright (C) Krishna Ganugapati (krishnag@centeris.com)         2006
   Copyright (C) Gerald Carter                                      2006

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
#include "utils/net.h"
#include "dns.h"

#if defined(WITH_DNS_UPDATES)

/*********************************************************************
*********************************************************************/

int DoDNSUpdate( char *pszServerName, const char *pszDomainName,
		 char *pszHostName, struct in_addr *iplist, int num_addrs )
{
	int32 dwError = 0;
	DNS_ERROR dns_status;
	HANDLE hDNSServer = ( HANDLE ) NULL;
	int32 dwResponseCode = 0;
	DNS_UPDATE_RESPONSE *pDNSUpdateResponse = NULL;
#if 0
	DNS_UPDATE_RESPONSE *pDNSSecureUpdateResponse = NULL;
#endif

	if ( (num_addrs <= 0) || !iplist ) {
		return -1;
	}
		
	dns_status = DNSOpen( pszServerName, DNS_TCP, &hDNSServer );
	BAIL_ON_DNS_ERROR( dns_status );

	dwError = DNSSendUpdate( hDNSServer, pszDomainName, pszHostName, 
	                         iplist, num_addrs, &pDNSUpdateResponse );
	BAIL_ON_ERROR( dwError );

	dwError = DNSUpdateGetResponseCode( pDNSUpdateResponse,
					    &dwResponseCode );
	if ( dwResponseCode == DNS_REFUSED ) {
		dwError = -1;
	}
	BAIL_ON_ERROR( dwError );

cleanup:
	return dwError;

error:
	goto cleanup;
}

/*********************************************************************
*********************************************************************/

int get_my_ip_address( struct in_addr **ips )
{
	struct iface_struct nics[MAX_INTERFACES];
	int i, n;
	struct in_addr loopback_ip = *interpret_addr2("127.0.0.1");
	struct in_addr *list;
	int count = 0;

	/* find the first non-loopback address from our list of interfaces */

	n = get_interfaces(nics, MAX_INTERFACES);
	
	if ( (list = SMB_MALLOC_ARRAY( struct in_addr, n )) == NULL ) {
		return -1;
	}

	for ( i=0; i<n; i++ ) {
		if ( nics[i].ip.s_addr != loopback_ip.s_addr ) {
			memcpy( &list[count++], &nics[i].ip, sizeof( struct in_addr ) );
		}
	}
	*ips = list;

	return count;
}

#endif	/* defined(WITH_DNS_UPDATES) */

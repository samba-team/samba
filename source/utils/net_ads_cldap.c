/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)

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
#include "../utils/net.h"

#ifdef HAVE_ADS

/*
  do a cldap netlogon query
*/
int ads_cldap_netlogon(ADS_STRUCT *ads)
{
	ASN1_DATA data;
	char ntver[4];
	int sock;

	SIVAL(ntver, 0, 6);

	memset(&data, 0, sizeof(data));

	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	asn1_write_Integer(&data, 4);
	asn1_push_tag(&data, ASN1_APPLICATION(3));
	asn1_write_OctetString(&data, NULL, 0);
	asn1_write_enumerated(&data, 0);
	asn1_write_enumerated(&data, 0);
	asn1_write_Integer(&data, 0);
	asn1_write_Integer(&data, 0);
	asn1_write_BOOLEAN2(&data, False);
	asn1_push_tag(&data, ASN1_CONTEXT(0));

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "DnsDomain", 9);
	asn1_write_OctetString(&data, ads->config.realm, strlen(ads->config.realm));
	asn1_pop_tag(&data);

	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "Host", 4);
	asn1_write_OctetString(&data, "blu", 3);
	asn1_pop_tag(&data);


	asn1_push_tag(&data, ASN1_CONTEXT(3));
	asn1_write_OctetString(&data, "NtVer", 5);
	asn1_write_OctetString(&data, ntver, 4);
	asn1_pop_tag(&data);

	asn1_pop_tag(&data);

	asn1_push_tag(&data,ASN1_SEQUENCE(0));
	asn1_write_OctetString(&data, "NetLogon", 8);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);
	asn1_pop_tag(&data);

	if (data.has_error) {
		d_printf("Failed to build cldap netlogon at offset %d\n", (int)data.ofs);
		asn1_free(&data);
		return -1;
	}

	sock = open_udp_socket(inet_ntoa(ads->ldap_ip), ads->ldap_port);
	if (sock == -1) {
		d_printf("Failed to open udp socket to %s:%u\n", 
			 inet_ntoa(ads->ldap_ip), 
			 ads->ldap_port);
		return -1;
	}

	write(sock, data.data, data.length);
	file_save("cldap_query.dat", data.data, data.length);
	asn1_free(&data);
	return 0;
}


#endif

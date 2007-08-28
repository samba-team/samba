/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner 2007

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

/****************************************************************
****************************************************************/

void display_ds_domain_controller_info(TALLOC_CTX *mem_ctx,
				       const struct DS_DOMAIN_CONTROLLER_INFO *info)
{
	d_printf("domain_controller_name: %s\n",
		info->domain_controller_name);
	d_printf("domain_controller_address: %s\n",
		info->domain_controller_address);
	d_printf("domain_controller_address_type: %d\n",
		info->domain_controller_address_type);
	d_printf("domain_guid: %s\n",
		GUID_string(mem_ctx, info->domain_guid));
	d_printf("domain_name: %s\n",
		info->domain_name);
	d_printf("dns_forest_name: %s\n",
		info->dns_forest_name);

	d_printf("flags: 0x%08x\n"
		 "\tIs a PDC:                                   %s\n"
		 "\tIs a GC of the forest:                      %s\n"
		 "\tIs an LDAP server:                          %s\n"
		 "\tSupports DS:                                %s\n"
		 "\tIs running a KDC:                           %s\n"
		 "\tIs running time services:                   %s\n"
		 "\tIs the closest DC:                          %s\n"
		 "\tIs writable:                                %s\n"
		 "\tHas a hardware clock:                       %s\n"
		 "\tIs a non-domain NC serviced by LDAP server: %s\n"
		 "\tDomainControllerName is a DNS name:         %s\n"
		 "\tDomainName is a DNS name:                   %s\n"
		 "\tDnsForestName is a DNS name:                %s\n",
		 info->flags,
		 (info->flags & ADS_PDC) ? "yes" : "no",
		 (info->flags & ADS_GC) ? "yes" : "no",
		 (info->flags & ADS_LDAP) ? "yes" : "no",
		 (info->flags & ADS_DS) ? "yes" : "no",
		 (info->flags & ADS_KDC) ? "yes" : "no",
		 (info->flags & ADS_TIMESERV) ? "yes" : "no",
		 (info->flags & ADS_CLOSEST) ? "yes" : "no",
		 (info->flags & ADS_WRITABLE) ? "yes" : "no",
		 (info->flags & ADS_GOOD_TIMESERV) ? "yes" : "no",
		 (info->flags & ADS_NDNC) ? "yes" : "no",
		 (info->flags & ADS_DNS_CONTROLLER) ? "yes":"no",
		 (info->flags & ADS_DNS_DOMAIN) ? "yes":"no",
		 (info->flags & ADS_DNS_FOREST) ? "yes":"no");

	d_printf("dc_site_name: %s\n", info->dc_site_name);
	d_printf("client_site_name: %s\n", info->client_site_name);
}

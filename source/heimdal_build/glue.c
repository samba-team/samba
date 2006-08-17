/* 
   Unix SMB/CIFS implementation.

   provide glue functions between heimdal and samba

   Copyright (C) Andrew Tridgell 2005
   
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
#include "system/network.h"
#include "system/kerberos.h"
#include "lib/socket/netif.h"

/*
  get the list of IP addresses for configured interfaces
*/
krb5_error_code KRB5_LIB_FUNCTION krb5_get_all_client_addrs(krb5_context context, krb5_addresses *res)
{
	int i;
	res->len = iface_count();
	res->val = malloc_array_p(HostAddress, res->len);
	if (res->val == NULL) {
		return ENOMEM;
	}
	for (i=0;i<res->len;i++) {
		const char *ip = iface_n_ip(i);
		res->val[i].addr_type = AF_INET;
		res->val[i].address.length = 4;
		res->val[i].address.data = malloc(4);
		if (res->val[i].address.data == NULL) {
			return ENOMEM;
		}
		((struct in_addr *)res->val[i].address.data)->s_addr = inet_addr(ip);
	}

	return 0;
}



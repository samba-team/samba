/* 
   Unix SMB/CIFS implementation.

   provide glue functions between heimdal and samba

   Copyright (C) Andrew Tridgell 2005
   
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
#include "system/network.h"
#include "system/kerberos.h"
#include "lib/socket/netif.h"
#include "param/param.h"

/**
  get the list of IP addresses for configured interfaces
*/
krb5_error_code KRB5_LIB_FUNCTION krb5_get_all_client_addrs(krb5_context context, krb5_addresses *res)
{
	int i;
	struct interface *ifaces;

	load_interfaces(NULL, lp_interfaces(global_loadparm), &ifaces);

	res->len = iface_count(ifaces);
	res->val = malloc_array_p(HostAddress, res->len);
	if (res->val == NULL) {
		talloc_free(ifaces);
		return ENOMEM;
	}
	for (i=0;i<res->len;i++) {
		const char *ip = iface_n_ip(ifaces, i);
		res->val[i].addr_type = AF_INET;
		res->val[i].address.length = 4;
		res->val[i].address.data = malloc(4);
		if (res->val[i].address.data == NULL) {
			talloc_free(ifaces);
			return ENOMEM;
		}
		((struct in_addr *)res->val[i].address.data)->s_addr = inet_addr(ip);
	}

	talloc_free(ifaces);

	return 0;
}

#include "heimdal/lib/krb5/krb5_locl.h"

const krb5_cc_ops krb5_scc_ops = {
    KRB5_CC_OPS_VERSION,
    "_NOTSUPPORTED_SDB",
    NULL, /* scc_retrieve */
    NULL, /* scc_get_principal */
    NULL, /* scc_get_first */
    NULL, /* scc_get_next */
    NULL, /* scc_end_get */
    NULL, /* scc_remove_cred */
    NULL, /* scc_set_flags */
    NULL,
    NULL, /* scc_get_cache_first */
    NULL, /* scc_get_cache_next */
    NULL, /* scc_end_cache_get */
    NULL, /* scc_move */
    NULL, /* scc_get_default_name */
    NULL  /* scc_set_default */
};

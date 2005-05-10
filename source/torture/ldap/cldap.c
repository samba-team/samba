/* 
   Unix SMB/CIFS mplementation.

   test CLDAP operations
   
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
#include "libcli/cldap/cldap.h"
#include "libcli/ldap/ldap.h"
#include "lib/events/events.h"


/*
  test netlogon operations
*/
static BOOL test_cldap_netlogon(TALLOC_CTX *mem_ctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(mem_ctx, NULL);
	NTSTATUS status;
	struct cldap_netlogon search;
	int i;

	search.in.dest_address  = dest;
	search.in.realm   = lp_realm();
	search.in.host    = lp_netbios_name();
	search.in.version = 6;
	status = cldap_netlogon(cldap, mem_ctx, &search);

	if (!NT_STATUS_IS_OK(status)) {
		printf("netlogon failed - %s\n", nt_errstr(status));
	} else {
		NDR_PRINT_DEBUG(nbt_cldap_netlogon, &search.out.netlogon);
	}

	for (i=0;i<20;i++) {
		search.in.version = i;
		status = cldap_netlogon(cldap, mem_ctx, &search);
		if (!NT_STATUS_IS_OK(status)) {
			printf("netlogon[%d] failed - %s\n", i, nt_errstr(status));
		} else {
			NDR_PRINT_DEBUG(nbt_cldap_netlogon, &search.out.netlogon);
		}
	}

	printf("cldap_search gave %s\n", nt_errstr(status));

	return True;	
}

BOOL torture_cldap(void)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = lp_parm_string(-1, "torture", "host");

	mem_ctx = talloc_init("torture_cldap");

	ret &= test_cldap_netlogon(mem_ctx, host);

	talloc_free(mem_ctx);

	return ret;
}


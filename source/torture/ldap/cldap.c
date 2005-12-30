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

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	} \
	if (DEBUGLVL(10)) { \
		NDR_PRINT_UNION_DEBUG(nbt_cldap_netlogon, \
				      search.in.version & 0xF, \
				      &search.out.netlogon); \
	} \
} while (0)

/*
  test netlogon operations
*/
static BOOL test_cldap_netlogon(TALLOC_CTX *mem_ctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(mem_ctx, NULL);
	NTSTATUS status;
	struct cldap_netlogon search, empty_search;
	union nbt_cldap_netlogon n1;
	struct GUID guid;
	int i;
	BOOL ret = True;

	ZERO_STRUCT(search);
	search.in.dest_address = dest;
	search.in.acct_control = -1;
	search.in.version = 6;

	empty_search = search;

	printf("Trying without any attributes\n");
	search = empty_search;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	n1 = search.out.netlogon;

	search.in.user         = "Administrator";
	search.in.realm        = n1.logon5.dns_domain;
	search.in.host         = "__cldap_torture__";

	printf("Scanning for netlogon levels\n");
	for (i=0;i<256;i++) {
		search.in.version = i;
		printf("Trying netlogon level %d\n", i);
		status = cldap_netlogon(cldap, mem_ctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	printf("Scanning for netlogon level bits\n");
	for (i=0;i<31;i++) {
		search.in.version = (1<<i);
		printf("Trying netlogon level 0x%x\n", i);
		status = cldap_netlogon(cldap, mem_ctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	search.in.version = 6;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with User=Administrator\n");

	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a GUID\n");
	search.in.realm       = NULL;
	search.in.domain_guid = GUID_string(mem_ctx, &n1.logon5.domain_uuid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a incorrect GUID\n");
	guid = GUID_random();
	search.in.user        = NULL;
	search.in.domain_guid = GUID_string(mem_ctx, &guid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a AAC\n");
	search.in.acct_control = 0x180;
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a bad AAC\n");
	search.in.acct_control = 0xFF00FF00;
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a user only\n");
	search = empty_search;
	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with just a bad username\n");
	search.in.user = "___no_such_user___";
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with just a bad domain\n");
	search = empty_search;
	search.in.realm = "___no_such_domain___";
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a incorrect domain and correct guid\n");
	search.in.domain_guid = GUID_string(mem_ctx, &n1.logon5.domain_uuid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a incorrect domain and incorrect guid\n");
	search.in.domain_guid = GUID_string(mem_ctx, &guid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a incorrect GUID and correct domain\n");
	search.in.domain_guid = GUID_string(mem_ctx, &guid);
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	return ret;	
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


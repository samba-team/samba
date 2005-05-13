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

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  test netlogon operations
*/
static BOOL test_cldap_netlogon(TALLOC_CTX *mem_ctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(mem_ctx, NULL);
	NTSTATUS status;
	struct cldap_netlogon search;
	union nbt_cldap_netlogon n1;
	struct GUID guid;
	int i;
	BOOL ret = True;

	search.in.dest_address = dest;
	search.in.realm        = lp_realm();
	search.in.host         = lp_netbios_name();
	search.in.user         = NULL;
	search.in.domain_guid  = NULL;
	search.in.domain_sid   = NULL;
	search.in.acct_control = -1;

	printf("Scanning for netlogon levels\n");
	for (i=0;i<256;i++) {
		search.in.version = i;
		printf("Trying netlogon level %d\n", i);
		status = cldap_netlogon(cldap, mem_ctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
		if (DEBUGLVL(10)) {
			NDR_PRINT_UNION_DEBUG(nbt_cldap_netlogon, i & 0xF, 
					      &search.out.netlogon);
		}
	}

	search.in.version = 6;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	n1 = search.out.netlogon;

	printf("Trying with User=Administrator\n");

	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a GUID\n");
	search.in.realm       = NULL;
	search.in.domain_guid = GUID_string(mem_ctx, &n1.logon4.domain_uuid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a incorrect GUID\n");
	guid = GUID_random();
	search.in.user        = NULL;
	search.in.domain_guid = GUID_string(mem_ctx, &guid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a incorrect domain and correct guid\n");
	search.in.realm       = "test.example.com";
	search.in.domain_guid = GUID_string(mem_ctx, &n1.logon4.domain_uuid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a incorrect domain and incorrect guid\n");
	search.in.realm       = "test.example.com";
	search.in.domain_guid = GUID_string(mem_ctx, &guid);
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a AAC\n");
	search.in.acct_control = 0x180;
	search.in.realm = lp_realm();
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a bad AAC\n");
	search.in.acct_control = 0xFF00FF00;
	search.in.realm = lp_realm();
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a user only\n");
	search.in.acct_control = -1;
	search.in.user = "Administrator";
	search.in.realm = NULL;
	search.in.domain_guid = NULL;
	status = cldap_netlogon(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying without any attributes\n");
	search.in.user = NULL;
	search.in.host = NULL;
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


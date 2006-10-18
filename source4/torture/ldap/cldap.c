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
#include "librpc/gen_ndr/ndr_nbt.h"
#include "torture/torture.h"
#include "lib/ldb/include/ldb.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
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

	printf("Trying with User=NULL\n");

	search.in.user = NULL;
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

/*
  convert a ldap result message to a ldb message. This allows us to
  use the convenient ldif dump routines in ldb to print out cldap
  search results
*/
static struct ldb_message *ldap_msg_to_ldb(TALLOC_CTX *mem_ctx, struct ldap_SearchResEntry *res)
{
	struct ldb_message *msg;

	msg = ldb_msg_new(mem_ctx);
	msg->dn = ldb_dn_explode_or_special(msg, res->dn);
	msg->num_elements = res->num_attributes;
	msg->elements = talloc_steal(msg, res->attributes);
	return msg;
}

/*
  dump a set of cldap results
*/
static void cldap_dump_results(struct cldap_search *search)
{
	struct ldb_ldif ldif;
	struct ldb_context *ldb;

	if (!search || !(search->out.response)) {
		return;
	}

	/* we need a ldb context to use ldb_ldif_write_file() */
	ldb = ldb_init(NULL);

	ZERO_STRUCT(ldif);
	ldif.msg = ldap_msg_to_ldb(ldb, search->out.response);

	ldb_ldif_write_file(ldb, stdout, &ldif);

	talloc_free(ldb);
}

/*
  test generic cldap operations
*/
static BOOL test_cldap_generic(TALLOC_CTX *mem_ctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(mem_ctx, NULL);
	NTSTATUS status;
	struct cldap_search search;
	BOOL ret = True;
	const char *attrs[] = { "currentTime", "highestCommittedUSN", NULL };

	ZERO_STRUCT(search);
	search.in.dest_address = dest;
	search.in.timeout = 10;
	search.in.retries = 3;

	status = cldap_search(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("fetching whole rootDSE\n");
	search.in.filter = "(objectclass=*)";
	search.in.attributes = NULL;

	status = cldap_search(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("fetching currentTime and USN\n");
	search.in.filter = "(objectclass=*)";
	search.in.attributes = attrs;

	status = cldap_search(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("Testing a false expression\n");
	search.in.filter = "(&(objectclass=*)(highestCommittedUSN=2))";
	search.in.attributes = attrs;

	status = cldap_search(cldap, mem_ctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	if (DEBUGLVL(3)) cldap_dump_results(&search);
	

done:
	return ret;	
}

BOOL torture_cldap(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = torture_setting_string(torture, "host", NULL);

	mem_ctx = talloc_init("torture_cldap");

	ret &= test_cldap_netlogon(mem_ctx, host);

	/* at the moment don't consider this failing to be a failure */
	test_cldap_generic(mem_ctx, host);

	talloc_free(mem_ctx);

	return ret;
}


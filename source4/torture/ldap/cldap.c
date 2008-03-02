/* 
   Unix SMB/CIFS mplementation.

   test CLDAP operations
   
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
#include "libcli/cldap/cldap.h"
#include "libcli/ldap/ldap.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "torture/torture.h"
#include "lib/ldb/include/ldb.h"
#include "param/param.h"

#define CHECK_STATUS(status, correct) torture_assert_ntstatus_equal(tctx, status, correct, "incorrect status")

#define CHECK_VAL(v, correct) torture_assert_int_equal(tctx, (v), (correct), "incorrect value");

#define CHECK_STRING(v, correct) torture_assert_str_equal(tctx, v, correct, "incorrect value");
/*
  test netlogon operations
*/
static bool test_cldap_netlogon(struct torture_context *tctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(tctx, NULL, lp_iconv_convenience(tctx->lp_ctx));
	NTSTATUS status;
	struct cldap_netlogon search, empty_search;
	union nbt_cldap_netlogon n1;
	struct GUID guid;
	int i;

	ZERO_STRUCT(search);
	search.in.dest_address = dest;
	search.in.dest_port = lp_cldap_port(tctx->lp_ctx);
	search.in.acct_control = -1;
	search.in.version = 6;

	empty_search = search;

	printf("Trying without any attributes\n");
	search = empty_search;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	n1 = search.out.netlogon;

	search.in.user         = "Administrator";
	search.in.realm        = n1.logon5.dns_domain;
	search.in.host         = "__cldap_torture__";

	printf("Scanning for netlogon levels\n");
	for (i=0;i<256;i++) {
		search.in.version = i;
		printf("Trying netlogon level %d\n", i);
		status = cldap_netlogon(cldap, tctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	printf("Scanning for netlogon level bits\n");
	for (i=0;i<31;i++) {
		search.in.version = (1<<i);
		printf("Trying netlogon level 0x%x\n", i);
		status = cldap_netlogon(cldap, tctx, &search);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	search.in.version = 0x20000006;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with User=NULL\n");

	search.in.user = NULL;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);

	printf("Trying with User=Administrator\n");

	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_STRING(search.out.netlogon.logon5.user_name, search.in.user);
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC_USER);

	search.in.version = 6;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with User=NULL\n");

	search.in.user = NULL;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);

	printf("Trying with User=Administrator\n");

	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_STRING(search.out.netlogon.logon5.user_name, search.in.user);
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC_USER);

	printf("Trying with a GUID\n");
	search.in.realm       = NULL;
	search.in.domain_guid = GUID_string(tctx, &n1.logon5.domain_uuid);
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC_USER);
	CHECK_STRING(GUID_string(tctx, &search.out.netlogon.logon5.domain_uuid), search.in.domain_guid);

	printf("Trying with a incorrect GUID\n");
	guid = GUID_random();
	search.in.user        = NULL;
	search.in.domain_guid = GUID_string(tctx, &guid);
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a AAC\n");
	search.in.acct_control = 0x180;
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");

	printf("Trying with a bad AAC\n");
	search.in.acct_control = 0xFF00FF00;
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Trying with a user only\n");
	search = empty_search;
	search.in.user = "Administrator";
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.dns_domain, n1.logon5.dns_domain);
	CHECK_STRING(search.out.netlogon.logon5.user_name, search.in.user);

	printf("Trying with just a bad username\n");
	search.in.user = "___no_such_user___";
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.user_name, search.in.user);
	CHECK_STRING(search.out.netlogon.logon5.dns_domain, n1.logon5.dns_domain);

	printf("Trying with just a bad domain\n");
	search = empty_search;
	search.in.realm = "___no_such_domain___";
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);

	printf("Trying with a incorrect domain and correct guid\n");
	search.in.domain_guid = GUID_string(tctx, &n1.logon5.domain_uuid);
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.dns_domain, n1.logon5.dns_domain);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);

	printf("Trying with a incorrect domain and incorrect guid\n");
	search.in.domain_guid = GUID_string(tctx, &guid);
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_NOT_FOUND);
	CHECK_STRING(search.out.netlogon.logon5.dns_domain, n1.logon5.dns_domain);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);

	printf("Trying with a incorrect GUID and correct domain\n");
	search.in.domain_guid = GUID_string(tctx, &guid);
	search.in.realm = n1.logon5.dns_domain;
	status = cldap_netlogon(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_STRING(search.out.netlogon.logon5.dns_domain, n1.logon5.dns_domain);
	CHECK_STRING(search.out.netlogon.logon5.user_name, "");
	CHECK_VAL(search.out.netlogon.logon5.type, NETLOGON_RESPONSE_FROM_PDC2);

	return true;
}

/*
  convert a ldap result message to a ldb message. This allows us to
  use the convenient ldif dump routines in ldb to print out cldap
  search results
*/
static struct ldb_message *ldap_msg_to_ldb(TALLOC_CTX *mem_ctx, struct ldb_context *ldb, struct ldap_SearchResEntry *res)
{
	struct ldb_message *msg;

	msg = ldb_msg_new(mem_ctx);
	msg->dn = ldb_dn_new(msg, ldb, res->dn);
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
	ldif.msg = ldap_msg_to_ldb(ldb, ldb, search->out.response);

	ldb_ldif_write_file(ldb, stdout, &ldif);

	talloc_free(ldb);
}

/*
  test generic cldap operations
*/
static bool test_cldap_generic(struct torture_context *tctx, const char *dest)
{
	struct cldap_socket *cldap = cldap_socket_init(tctx, NULL, lp_iconv_convenience(tctx->lp_ctx));
	NTSTATUS status;
	struct cldap_search search;
	const char *attrs1[] = { "currentTime", "highestCommittedUSN", NULL };
	const char *attrs2[] = { "currentTime", "highestCommittedUSN", "netlogon", NULL };
	const char *attrs3[] = { "netlogon", NULL };

	ZERO_STRUCT(search);
	search.in.dest_address = dest;
	search.in.dest_port = lp_cldap_port(tctx->lp_ctx);
	search.in.timeout = 10;
	search.in.retries = 3;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("fetching whole rootDSE\n");
	search.in.filter = "(objectclass=*)";
	search.in.attributes = NULL;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("fetching currentTime and USN\n");
	search.in.filter = "(objectclass=*)";
	search.in.attributes = attrs1;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("Testing currentTime, USN and netlogon\n");
	search.in.filter = "(objectclass=*)";
	search.in.attributes = attrs2;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("Testing objectClass=* and netlogon\n");
	search.in.filter = "(objectclass2=*)";
	search.in.attributes = attrs3;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (DEBUGLVL(3)) cldap_dump_results(&search);

	printf("Testing a false expression\n");
	search.in.filter = "(&(objectclass=*)(highestCommittedUSN=2))";
	search.in.attributes = attrs1;

	status = cldap_search(cldap, tctx, &search);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (DEBUGLVL(3)) cldap_dump_results(&search);	

	return true;	
}

bool torture_cldap(struct torture_context *torture)
{
	bool ret = true;
	const char *host = torture_setting_string(torture, "host", NULL);

	ret &= test_cldap_netlogon(torture, host);
	ret &= test_cldap_generic(torture, host);

	return ret;
}


/* 
   Unix SMB/CIFS mplementation.

   test CLDAP operations
   
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Matthias Dieter Wallnöfer 2009
    
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
#include "libcli/ldap/ldap_client.h"
#include "libcli/resolve/resolve.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"

#include "torture/torture.h"
#include "torture/ldap/proto.h"

#define CHECK_STATUS(status, correct) torture_assert_ntstatus_equal(tctx, status, correct, "incorrect status")

#define CHECK_VAL(v, correct) torture_assert_int_equal(tctx, (v), (correct), "incorrect value");

#define CHECK_STRING(v, correct) torture_assert_str_equal(tctx, v, correct, "incorrect value");

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
	ldb = ldb_init(NULL, NULL);

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
	struct cldap_socket *cldap;
	NTSTATUS status;
	struct cldap_search search;
	const char *attrs1[] = { "currentTime", "highestCommittedUSN", NULL };
	const char *attrs2[] = { "currentTime", "highestCommittedUSN", "netlogon", NULL };
	const char *attrs3[] = { "netlogon", NULL };
	struct tsocket_address *dest_addr;
	const char *ip;
	struct nbt_name nbt_name;
	int ret;

	make_nbt_name_server(&nbt_name, dest);

	status = resolve_name_ex(lpcfg_resolve_context(tctx->lp_ctx),
				 0, 0, &nbt_name, tctx, &ip, tctx->ev);
	torture_assert_ntstatus_ok(tctx, status,
			talloc_asprintf(tctx,"Failed to resolve %s: %s",
					nbt_name.name, nt_errstr(status)));

	ret = tsocket_address_inet_from_strings(tctx, "ip",
						ip,
						lpcfg_cldap_port(tctx->lp_ctx),
						&dest_addr);
	CHECK_VAL(ret, 0);

	/* cldap_socket_init should now know about the dest. address */
	status = cldap_socket_init(tctx, NULL, dest_addr, &cldap);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(search);
	search.in.dest_address = NULL;
	search.in.dest_port = 0;
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
	search.in.filter = "(objectclass=*)";
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

	ret &= test_cldap_generic(torture, host);

	return ret;
}


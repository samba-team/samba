/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/rpc/rpc.h"
#include "torture/torture.h"
#include "librpc/ndr/ndr_table.h"
#include "lib/util/dlinklist.h"

/* open a rpc connection to the chosen binding string */
_PUBLIC_ NTSTATUS torture_rpc_connection(TALLOC_CTX *parent_ctx, 
				struct dcerpc_pipe **p, 
				const struct ndr_interface_table *table)
{
        NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_pipe_connect(parent_ctx, 
				     p, binding, table,
				     cmdline_credentials, NULL);
 
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to remote server: %s %s\n", binding, nt_errstr(status));
	}

	return status;
}

/* open a rpc connection to a specific transport */
NTSTATUS torture_rpc_connection_transport(TALLOC_CTX *parent_ctx, 
					  struct dcerpc_pipe **p, 
					  const struct ndr_interface_table *table,
					  enum dcerpc_transport_t transport,
					  uint32_t assoc_group_id)
{
        NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding *b;
	TALLOC_CTX *mem_ctx = talloc_named(parent_ctx, 0, "torture_rpc_connection_smb");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		talloc_free(mem_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to parse dcerpc binding '%s'\n", binding));
		talloc_free(mem_ctx);
		return status;
	}

	b->transport = transport;
	b->assoc_group_id = assoc_group_id;

	status = dcerpc_pipe_connect_b(mem_ctx, p, b, table,
				       cmdline_credentials, NULL);
					   
	if (NT_STATUS_IS_OK(status)) {
		*p = talloc_reference(parent_ctx, *p);
	} else {
		*p = NULL;
	}
	talloc_free(mem_ctx);
        return status;
}

static bool torture_rpc_setup (struct torture_context *tctx, void **data)
{
	NTSTATUS status;
	
	status = torture_rpc_connection(tctx, 
				(struct dcerpc_pipe **)data, 
				(const struct ndr_interface_table *)tctx->active_tcase->data);

	torture_assert_ntstatus_ok(tctx, status, "Error connecting to server");

	return true;
}

static bool torture_rpc_teardown (struct torture_context *tcase, void *data)
{
	talloc_free(data);
	return true;
}

_PUBLIC_ struct torture_tcase *torture_suite_add_rpc_iface_tcase(struct torture_suite *suite, 
								const char *name,
								const struct ndr_interface_table *table)
{
	struct torture_tcase *tcase = torture_suite_add_tcase(suite, name);

	tcase->setup = torture_rpc_setup;
	tcase->teardown = torture_rpc_teardown;
	tcase->data = discard_const(table);

	return tcase;
}

static bool torture_rpc_wrap_test(struct torture_context *tctx, 
								  struct torture_tcase *tcase,
								  struct torture_test *test)
{
	bool (*fn) (struct torture_context *, struct dcerpc_pipe *);

	fn = test->fn;

	return fn(tctx, (struct dcerpc_pipe *)tcase->data);
}

_PUBLIC_ struct torture_test *torture_rpc_tcase_add_test(
					struct torture_tcase *tcase, 
					const char *name, 
					bool (*fn) (struct torture_context *, struct dcerpc_pipe *))
{
	struct torture_test *test;

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = torture_rpc_wrap_test;
	test->dangerous = false;
	test->data = NULL;
	test->fn = fn;

	DLIST_ADD(tcase->tests, test);

	return test;
}

NTSTATUS torture_rpc_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "RPC");

	dcerpc_init();

	ndr_table_init();

	torture_suite_add_simple_test(suite, "LSA", torture_rpc_lsa);
	torture_suite_add_simple_test(suite, "LSALOOKUP", torture_rpc_lsa_lookup);
	torture_suite_add_simple_test(suite, "LSA-GETUSER", torture_rpc_lsa_get_user);
	torture_suite_add_simple_test(suite, "SECRETS", torture_rpc_lsa_secrets);
	torture_suite_add_suite(suite, torture_rpc_echo());
	torture_suite_add_suite(suite, torture_rpc_dfs());
	torture_suite_add_suite(suite, torture_rpc_unixinfo());
	torture_suite_add_suite(suite, torture_rpc_eventlog());
	torture_suite_add_suite(suite, torture_rpc_atsvc());
	torture_suite_add_suite(suite, torture_rpc_wkssvc());
	torture_suite_add_suite(suite, torture_rpc_handles());
	torture_suite_add_simple_test(suite, "SPOOLSS", torture_rpc_spoolss);
	torture_suite_add_simple_test(suite, "SAMR", torture_rpc_samr);
	torture_suite_add_simple_test(suite, "SAMR-USERS", torture_rpc_samr_users);
	torture_suite_add_simple_test(suite, "SAMR-PASSWORDS", torture_rpc_samr_passwords);
	torture_suite_add_simple_test(suite, "NETLOGON", torture_rpc_netlogon);
	torture_suite_add_simple_test(suite, "SAMLOGON", torture_rpc_samlogon);
	torture_suite_add_simple_test(suite, "SAMSYNC", torture_rpc_samsync);
	torture_suite_add_simple_test(suite, "SCHANNEL", torture_rpc_schannel);
	torture_suite_add_simple_test(suite, "SCHANNEL2", torture_rpc_schannel2);
	torture_suite_add_simple_test(suite, "SRVSVC", torture_rpc_srvsvc);
	torture_suite_add_simple_test(suite, "SVCCTL", torture_rpc_svcctl);
	torture_suite_add_simple_test(suite, "EPMAPPER", torture_rpc_epmapper);
	torture_suite_add_simple_test(suite, "WINREG", torture_rpc_winreg);
	torture_suite_add_simple_test(suite, "INITSHUTDOWN", torture_rpc_initshutdown);
	torture_suite_add_simple_test(suite, "OXIDRESOLVE", torture_rpc_oxidresolve);
	torture_suite_add_simple_test(suite, "REMACT", torture_rpc_remact);
	torture_suite_add_simple_test(suite, "MGMT", torture_rpc_mgmt);
	torture_suite_add_simple_test(suite, "SCANNER", torture_rpc_scanner);
	torture_suite_add_simple_test(suite, "AUTOIDL", torture_rpc_autoidl);
	torture_suite_add_simple_test(suite, "COUNTCALLS", torture_rpc_countcalls);
	torture_suite_add_simple_test(suite, "MULTIBIND", torture_multi_bind);
	torture_suite_add_simple_test(suite, "AUTHCONTEXT", torture_bind_authcontext);
	torture_suite_add_simple_test(suite, "BINDSAMBA3", torture_bind_samba3);
	torture_suite_add_simple_test(suite, "NETLOGSAMBA3", torture_netlogon_samba3);
	torture_suite_add_simple_test(suite, "SAMBA3SESSIONKEY", torture_samba3_sessionkey);
	torture_suite_add_simple_test(suite, "SAMBA3-SRVSVC", torture_samba3_rpc_srvsvc);
	torture_suite_add_simple_test(suite, "SAMBA3-SHARESEC",
			    torture_samba3_rpc_sharesec);
	torture_suite_add_simple_test(suite, "SAMBA3-GETUSERNAME",
			    torture_samba3_rpc_getusername);
	torture_suite_add_simple_test(suite, "SAMBA3-LSA", torture_samba3_rpc_lsa);
	torture_suite_add_simple_test(suite, "SAMBA3-SPOOLSS", torture_samba3_rpc_spoolss);
	torture_suite_add_simple_test(suite, "SAMBA3-WKSSVC", torture_samba3_rpc_wkssvc);
	torture_suite_add_simple_test(suite, "RPC-SAMBA3-WINREG", torture_samba3_rpc_winreg);
	torture_suite_add_simple_test(suite, "DRSUAPI", torture_rpc_drsuapi);
	torture_suite_add_simple_test(suite, "CRACKNAMES", torture_rpc_drsuapi_cracknames);
	torture_suite_add_simple_test(suite, "ROT", torture_rpc_rot);
	torture_suite_add_simple_test(suite, "DSSETUP", torture_rpc_dssetup);
	torture_suite_add_simple_test(suite, "ALTERCONTEXT", torture_rpc_alter_context);
	torture_suite_add_simple_test(suite, "JOIN", torture_rpc_join);
	torture_suite_add_simple_test(suite, "DSSYNC", torture_rpc_dssync);
	torture_suite_add_simple_test(suite, "BENCH-RPC", torture_bench_rpc);
	torture_suite_add_simple_test(suite, "ASYNCBIND", torture_async_bind);

	suite->description = talloc_strdup(suite, "DCE/RPC protocol and interface tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}

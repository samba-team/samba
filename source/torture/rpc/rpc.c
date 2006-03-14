/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "torture/rpc/rpc.h"
#include "torture/torture.h"

/* open a rpc connection to the chosen binding string */
NTSTATUS torture_rpc_connection(TALLOC_CTX *parent_ctx, 
				struct dcerpc_pipe **p, 
				const struct dcerpc_interface_table *table)
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
 
        return status;
}

/* open a rpc connection to a specific transport */
NTSTATUS torture_rpc_connection_transport(TALLOC_CTX *parent_ctx, 
					  struct dcerpc_pipe **p, 
					  const struct dcerpc_interface_table *table,
					  enum dcerpc_transport_t transport)
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

NTSTATUS torture_rpc_init(void)
{
    register_torture_op("RPC-LSA", torture_rpc_lsa, 0);
    register_torture_op("RPC-LSALOOKUP", torture_rpc_lsa_lookup, 0);
    register_torture_op("RPC-SECRETS", torture_rpc_lsa_secrets, 0);
    register_torture_op("RPC-ECHO", torture_rpc_echo, 0);
    register_torture_op("RPC-DFS", torture_rpc_dfs, 0);
    register_torture_op("RPC-SPOOLSS", torture_rpc_spoolss, 0);
    register_torture_op("RPC-SAMR", torture_rpc_samr, 0);
    register_torture_op("RPC-UNIXINFO", torture_rpc_unixinfo, 0);
    register_torture_op("RPC-NETLOGON", torture_rpc_netlogon, 0);
    register_torture_op("RPC-SAMLOGON", torture_rpc_samlogon, 0);
    register_torture_op("RPC-SAMSYNC", torture_rpc_samsync, 0);
    register_torture_op("RPC-SCHANNEL", torture_rpc_schannel, 0);
    register_torture_op("RPC-WKSSVC", torture_rpc_wkssvc, 0);
    register_torture_op("RPC-SRVSVC", torture_rpc_srvsvc, 0);
    register_torture_op("RPC-SVCCTL", torture_rpc_svcctl, 0);
    register_torture_op("RPC-ATSVC", torture_rpc_atsvc, 0);
    register_torture_op("RPC-EVENTLOG", torture_rpc_eventlog, 0);
    register_torture_op("RPC-EPMAPPER", torture_rpc_epmapper, 0);
    register_torture_op("RPC-WINREG", torture_rpc_winreg, 0);
    register_torture_op("RPC-INITSHUTDOWN", torture_rpc_initshutdown, 0);
    register_torture_op("RPC-OXIDRESOLVE", torture_rpc_oxidresolve, 0);
    register_torture_op("RPC-REMACT", torture_rpc_remact, 0);
    register_torture_op("RPC-MGMT", torture_rpc_mgmt, 0);
    register_torture_op("RPC-SCANNER", torture_rpc_scanner, 0);
    register_torture_op("RPC-AUTOIDL", torture_rpc_autoidl, 0);
    register_torture_op("RPC-COUNTCALLS", torture_rpc_countcalls, 0);
	register_torture_op("RPC-MULTIBIND", torture_multi_bind, 0);
	register_torture_op("RPC-DRSUAPI", torture_rpc_drsuapi, 0);
	register_torture_op("RPC-CRACKNAMES", torture_rpc_drsuapi_cracknames, 0);
	register_torture_op("RPC-ROT", torture_rpc_rot, 0);
	register_torture_op("RPC-DSSETUP", torture_rpc_dssetup, 0);
    register_torture_op("RPC-ALTERCONTEXT", torture_rpc_alter_context, 0);
    register_torture_op("RPC-JOIN", torture_rpc_join, 0);
    register_torture_op("RPC-DSSYNC", torture_rpc_dssync, 0);
	register_torture_op("BENCH-RPC", torture_bench_rpc, 0);

	return NT_STATUS_OK;
}

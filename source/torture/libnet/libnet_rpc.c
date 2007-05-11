/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2005
   
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
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"
#include "libnet/libnet.h"
#include "libcli/security/security.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/torture.h"


static BOOL test_connect_service(struct libnet_context *ctx,
				 const struct dcerpc_interface_table *iface,
				 const char *binding_string,
				 const char *hostname,
				 const enum libnet_RpcConnect_level level,
				 BOOL badcreds, NTSTATUS expected_status)
{
	NTSTATUS status;
	struct libnet_RpcConnect connect;
	connect.level            = level;
	connect.in.binding       = binding_string;
	connect.in.name          = hostname;
	connect.in.dcerpc_iface  = iface;

	/* if bad credentials are needed, set baduser%badpassword instead
	   of default commandline-passed credentials */
	if (badcreds) {
		cli_credentials_set_username(ctx->cred, "baduser", CRED_SPECIFIED);
		cli_credentials_set_password(ctx->cred, "badpassword", CRED_SPECIFIED);
	}

	status = libnet_RpcConnect(ctx, ctx, &connect);

	if (!NT_STATUS_EQUAL(status, expected_status)) {
		d_printf("Connecting to rpc service %s on %s.\n\tFAILED. Expected: %s."
		       "Received: %s\n",
		       connect.in.dcerpc_iface->name, connect.in.binding, nt_errstr(expected_status),
		       nt_errstr(status));

		return False;
	}

	d_printf("PASSED. Expected: %s, received: %s\n", nt_errstr(expected_status),
	       nt_errstr(status));

	if (connect.level == LIBNET_RPC_CONNECT_DC_INFO && NT_STATUS_IS_OK(status)) {
		d_printf("Domain Controller Info:\n");
		d_printf("\tDomain Name:\t %s\n", connect.out.domain_name);
		d_printf("\tDomain SID:\t %s\n", dom_sid_string(ctx, connect.out.domain_sid));
		d_printf("\tRealm:\t\t %s\n", connect.out.realm);
		d_printf("\tGUID:\t\t %s\n", GUID_string(ctx, connect.out.guid));

	} else if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error string: %s\n", connect.out.error_string);
	}

	return True;
}


static BOOL torture_rpc_connect(struct torture_context *torture,
				const enum libnet_RpcConnect_level level,
				const char *bindstr, const char *hostname)
{
	struct libnet_context *ctx;

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;
	
	d_printf("Testing connection to LSA interface\n");
	if (!test_connect_service(ctx, &dcerpc_table_lsarpc, bindstr,
				  hostname, level, False, NT_STATUS_OK)) {
		d_printf("failed to connect LSA interface\n");
		return False;
	}

	d_printf("Testing connection to SAMR interface\n");
	if (!test_connect_service(ctx, &dcerpc_table_samr, bindstr,
				  hostname, level, False, NT_STATUS_OK)) {
		d_printf("failed to connect SAMR interface\n");
		return False;
	}

	d_printf("Testing connection to SRVSVC interface\n");
	if (!test_connect_service(ctx, &dcerpc_table_srvsvc, bindstr,
				  hostname, level, False, NT_STATUS_OK)) {
		d_printf("failed to connect SRVSVC interface\n");
		return False;
	}

	d_printf("Testing connection to LSA interface with wrong credentials\n");
	if (!test_connect_service(ctx, &dcerpc_table_lsarpc, bindstr,
				  hostname, level, True, NT_STATUS_LOGON_FAILURE)) {
		d_printf("failed to test wrong credentials on LSA interface\n");
		return False;
	}

	d_printf("Testing connection to SAMR interface with wrong credentials\n");
	if (!test_connect_service(ctx, &dcerpc_table_samr, bindstr,
				  hostname, level, True, NT_STATUS_LOGON_FAILURE)) {
		d_printf("failed to test wrong credentials on SAMR interface\n");
		return False;
	}

	talloc_free(ctx);

	return True;
}


BOOL torture_rpc_connect_srv(struct torture_context *torture)
{
	const enum libnet_RpcConnect_level level = LIBNET_RPC_CONNECT_SERVER;
	NTSTATUS status;
	struct dcerpc_binding *binding;
	const char *bindstr;;

	bindstr = torture_setting_string(torture, "binding", NULL);
	status = dcerpc_parse_binding(torture, bindstr, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to parse binding string\n");
		return False;
	}

	return torture_rpc_connect(torture, level, NULL, binding->host);
}


BOOL torture_rpc_connect_pdc(struct torture_context *torture)
{
	const enum libnet_RpcConnect_level level = LIBNET_RPC_CONNECT_PDC;
	NTSTATUS status;
	struct dcerpc_binding *binding;
	const char *bindstr;
	const char *domain_name;
	
	bindstr = torture_setting_string(torture, "binding", NULL);
	status = dcerpc_parse_binding(torture, bindstr, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to parse binding string\n");
		return False;
	}

	/* we're accessing domain controller so the domain name should be
	   passed (it's going to be resolved to dc name and address) instead
	   of specific server name. */
	domain_name = lp_workgroup();
	return torture_rpc_connect(torture, level, NULL, domain_name);
}


BOOL torture_rpc_connect_dc(struct torture_context *torture)
{
	const enum libnet_RpcConnect_level level = LIBNET_RPC_CONNECT_DC;
	NTSTATUS status;
	struct dcerpc_binding *binding;
	const char *bindstr;
	const char *domain_name;
	
	bindstr = torture_setting_string(torture, "binding", NULL);
	status = dcerpc_parse_binding(torture, bindstr, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to parse binding string\n");
		return False;
	}

	/* we're accessing domain controller so the domain name should be
	   passed (it's going to be resolved to dc name and address) instead
	   of specific server name. */
	domain_name = lp_workgroup();
	return torture_rpc_connect(torture, level, NULL, domain_name);
}


BOOL torture_rpc_connect_dc_info(struct torture_context *torture)
{
	const enum libnet_RpcConnect_level level = LIBNET_RPC_CONNECT_DC_INFO;
	NTSTATUS status;
	struct dcerpc_binding *binding;
	const char *bindstr;
	const char *domain_name;
	
	bindstr = torture_setting_string(torture, "binding", NULL);
	status = dcerpc_parse_binding(torture, bindstr, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to parse binding string\n");
		return False;
	}

	/* we're accessing domain controller so the domain name should be
	   passed (it's going to be resolved to dc name and address) instead
	   of specific server name. */
	domain_name = lp_workgroup();
	return torture_rpc_connect(torture, level, NULL, domain_name);
}


BOOL torture_rpc_connect_binding(struct torture_context *torture)
{
	const enum libnet_RpcConnect_level level = LIBNET_RPC_CONNECT_BINDING;
	NTSTATUS status;
	struct dcerpc_binding *binding;
	const char *bindstr;
	
	bindstr = torture_setting_string(torture, "binding", NULL);
	status = dcerpc_parse_binding(torture, bindstr, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to parse binding string\n");
		return False;
	}

	return torture_rpc_connect(torture, level, bindstr, NULL);
}

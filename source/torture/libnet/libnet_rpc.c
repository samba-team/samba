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
#include "libnet/libnet.h"


BOOL test_lsa_np_connect(struct libnet_context *ctx)
{
	NTSTATUS status;
	struct libnet_RpcConnect connect;
	connect.level            = LIBNET_RPC_CONNECT_BINDING;
	connect.in.domain_name   = lp_workgroup();
	connect.in.binding       = talloc_asprintf(ctx, "ncacn_np:%s", lp_workgroup());
	connect.in.dcerpc_iface  = &dcerpc_table_lsarpc;

	status = libnet_RpcConnect(ctx, ctx, &connect);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't connect to rpc service %s on %s: %s\n",
		       connect.in.dcerpc_iface->name, connect.in.domain_name,
		       nt_errstr(status));

		return False;
	}

	return True;
}


BOOL test_samr_np_connect(struct libnet_context *ctx)
{
	NTSTATUS status;
	struct libnet_RpcConnect connect;
	connect.level            = LIBNET_RPC_CONNECT_BINDING;
	connect.in.domain_name   = lp_workgroup();
	connect.in.binding       = talloc_asprintf(ctx, "ncacn_np:%s", lp_workgroup());
	connect.in.dcerpc_iface  = &dcerpc_table_samr;

	status = libnet_RpcConnect(ctx, ctx, &connect);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't connect to rpc service %s on %s: %s\n",
		       connect.in.dcerpc_iface->name, connect.in.domain_name,
		       nt_errstr(status));

		return False;
	}

	return True;
}


BOOL test_lsa_tcpip_connect(struct libnet_context *ctx)
{
	NTSTATUS status;
	struct libnet_RpcConnect connect;
	connect.level            = LIBNET_RPC_CONNECT_BINDING;
	connect.in.domain_name   = lp_workgroup();
	connect.in.binding       = talloc_asprintf(ctx, "ncacn_ip_tcp:%s", lp_netbios_name());
	connect.in.dcerpc_iface  = &dcerpc_table_lsarpc;

	status = libnet_RpcConnect(ctx, ctx, &connect);
	
	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't connect to rpc service %s on %s: %s\n",
		       connect.in.dcerpc_iface->name, connect.in.domain_name,
		       nt_errstr(status));

		return False;
	}

	return True;
}


BOOL test_samr_tcpip_connect(struct libnet_context *ctx)
{
	NTSTATUS status;
	struct libnet_RpcConnect connect;
	connect.level            = LIBNET_RPC_CONNECT_BINDING;
	connect.in.domain_name   = lp_workgroup();
	connect.in.binding       = talloc_asprintf(ctx, "ncacn_ip_tcp:%s", lp_netbios_name());
	connect.in.dcerpc_iface  = &dcerpc_table_samr;

	status = libnet_RpcConnect(ctx, ctx, &connect);
	
	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't connect to rpc service %s on %s: %s\n",
		       connect.in.dcerpc_iface->name, connect.in.domain_name,
		       nt_errstr(status));

		return False;
	}

	return True;
}


BOOL torture_rpc_connect(void)
{
	struct libnet_context *ctx;
	
	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	printf("Testing connection to lsarpc interface via named pipe\n");
	if (!test_lsa_np_connect(ctx)) {
		printf("failed to connect lsarpc interface via named pipe\n");
		return False;
	}

	printf("Testing connection to SAMR service via named pipe\n");
	if (!test_samr_np_connect(ctx)) {
		printf("failed to connect samr interface via named pipe\n");
		return False;
	}

	printf("Testing connection to LSA service via tcp/ip\n");
	if (!test_lsa_tcpip_connect(ctx)) {
		printf("failed to connect lsarpc interface via tcp/ip\n");
		return False;
	}

	printf("Testing connection to SAMR service via tcp/ip\n");
	if (!test_samr_tcpip_connect(ctx)) {
		printf("failed to connect samr interface via tcp/ip\n");
		return False;
	}

	return True;
}

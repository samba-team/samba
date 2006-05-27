/* 
   Unix SMB/CIFS implementation.

   dcerpc torture tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org 2004

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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/rpc/rpc.h"
#include "libcli/libcli.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"

/*
  This test is 'bogus' in that it doesn't actually perform to the
  spec.  We need to deal with other things inside the DCERPC layer,
  before we could have multiple binds.

  We should never pass this test, until such details are fixed in our
  client, and it looks like multible binds are never used anyway.

*/

BOOL torture_multi_bind(struct torture_context *torture) 
{
	struct dcerpc_pipe *p;
	struct dcerpc_binding *binding;
	const char *binding_string = lp_parm_string(-1, "torture", "binding");
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret;

	mem_ctx = talloc_init("torture_multi_bind");

	status = dcerpc_parse_binding(mem_ctx, binding_string, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to parse dcerpc binding '%s'\n", binding_string);
		talloc_free(mem_ctx);
		return False;
	}

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_lsarpc);
	
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	status = dcerpc_pipe_auth(mem_ctx, &p, binding, &dcerpc_table_lsarpc, cmdline_credentials);

	if (NT_STATUS_IS_OK(status)) {
		printf("(incorrectly) allowed re-bind to uuid %s - %s\n", 
			GUID_string(mem_ctx, &dcerpc_table_lsarpc.syntax_id.uuid), nt_errstr(status));
		ret = False;
	} else {
		printf("\n");
		ret = True;
	}

	talloc_free(mem_ctx);

	return ret;
}

BOOL torture_bind_authcontext(struct torture_context *torture) 
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	BOOL ret = False;
	struct lsa_ObjectAttribute objectattr;
	struct lsa_OpenPolicy2 openpolicy;
	struct policy_handle handle;
	struct lsa_Close close;
	struct smbcli_session *tmp;
	struct smbcli_session *session2;
	struct smbcli_state *cli;
	struct dcerpc_pipe *lsa_pipe;
	struct cli_credentials *anon_creds;
	struct smb_composite_sesssetup setup;

	mem_ctx = talloc_init("torture_bind_auth");

	if (mem_ctx == NULL) {
		d_printf("talloc_init failed\n");
		return False;
	}

	status = smbcli_full_connection(mem_ctx, &cli,
					lp_parm_string(-1, "torture", "host"),
					"IPC$", NULL, cmdline_credentials,
					NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("smbcli_full_connection failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	lsa_pipe = dcerpc_pipe_init(mem_ctx, cli->transport->socket->event.ctx);
	if (lsa_pipe == NULL) {
		d_printf("dcerpc_pipe_init failed\n");
		goto done;
	}

	status = dcerpc_pipe_open_smb(lsa_pipe->conn, cli->tree, "\\lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_pipe_open_smb failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	status = dcerpc_bind_auth_none(lsa_pipe, &dcerpc_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_bind_auth_none failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	openpolicy.in.system_name =talloc_asprintf(
		mem_ctx, "\\\\%s", dcerpc_server_name(lsa_pipe));
	ZERO_STRUCT(objectattr);
	openpolicy.in.attr = &objectattr;
	openpolicy.in.access_mask = SEC_GENERIC_WRITE;
	openpolicy.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, mem_ctx, &openpolicy);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_OpenPolicy2 failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	close.in.handle = &handle;
	close.out.handle = &handle;

	status = dcerpc_lsa_Close(lsa_pipe, mem_ctx, &close);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_lsa_Close failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	session2 = smbcli_session_init(cli->transport, mem_ctx, False);
	if (session2 == NULL) {
		d_printf("smbcli_session_init failed\n");
		goto done;
	}

	anon_creds = cli_credentials_init(mem_ctx);
	if (anon_creds == NULL) {
		d_printf("cli_credentials_init failed\n");
		goto done;
	}

	cli_credentials_set_conf(anon_creds);
	cli_credentials_set_anonymous(anon_creds);

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = "";
	setup.in.credentials = anon_creds;

	status = smb_composite_sesssetup(session2, &setup);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("anon session setup failed: %s\n",
			 nt_errstr(status));
		goto done;
	}

	tmp = cli->tree->session;
	cli->tree->session = session2;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, mem_ctx, &openpolicy);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
		d_printf("dcerpc_lsa_OpenPolicy2 with wrong vuid gave %s, "
			 "expected NT_STATUS_INVALID_HANDLE\n",
			 nt_errstr(status));
		goto done;
	}

	ret = True;
 done:
	talloc_free(mem_ctx);
	return ret;
}

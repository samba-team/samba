/* 
   Unix SMB/CIFS implementation.

   test suite for dcerpc alter_context operations

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
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_dssetup.h"
#include "torture/rpc/torture_rpc.h"

bool torture_rpc_alter_context(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p, *p2, *p3;
	struct policy_handle *handle;
	struct ndr_interface_table tmptbl;
	const struct dcerpc_binding *bd = NULL;
	const struct dcerpc_binding *bd2 = NULL;
	struct ndr_syntax_id syntax = { .if_version = 0, };
	struct ndr_syntax_id syntax2 = { .if_version = 0, };
	const struct ndr_syntax_id *transfer_syntax = NULL;
	const struct ndr_syntax_id *transfer_syntax2 = NULL;
	uint32_t flags = 0;
	uint32_t flags2 = 0;
	bool ret = true;

	torture_comment(torture, "opening LSA connection\n");
	status = torture_rpc_connection(torture, &p, &ndr_table_lsarpc);
	torture_assert_ntstatus_ok(torture, status, "connecting");

	bd = dcerpc_binding_handle_get_binding(p->binding_handle);
	syntax = dcerpc_binding_get_abstract_syntax(bd);
	flags = dcerpc_binding_get_flags(bd);
	if (flags & DCERPC_NDR64) {
		transfer_syntax = &ndr_transfer_syntax_ndr64;
	} else {
		transfer_syntax = &ndr_transfer_syntax_ndr;
	}

	torture_comment(torture, "Testing change of primary context\n");
	status = dcerpc_alter_context(p, torture, &syntax, transfer_syntax);
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	if (!test_lsa_OpenPolicy2(p->binding_handle, torture, &handle)) {
		ret = false;
	}

	torture_comment(torture, "Testing change of primary context\n");
	status = dcerpc_alter_context(p, torture, &syntax, transfer_syntax);
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	torture_comment(torture, "Opening secondary DSSETUP context\n");
	status = dcerpc_secondary_context(p, &p2, &ndr_table_dssetup);
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	bd2 = dcerpc_binding_handle_get_binding(p2->binding_handle);
	syntax2 = dcerpc_binding_get_abstract_syntax(bd2);
	flags2 = dcerpc_binding_get_flags(bd2);
	if (flags2 & DCERPC_NDR64) {
		transfer_syntax2 = &ndr_transfer_syntax_ndr64;
	} else {
		transfer_syntax2 = &ndr_transfer_syntax_ndr;
	}

	torture_comment(torture, "Testing change of primary context\n");
	status = dcerpc_alter_context(p2, torture, &syntax2, transfer_syntax2);
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	tmptbl = ndr_table_dssetup;
	tmptbl.syntax_id.if_version += 100;
	torture_comment(torture, "Opening bad secondary connection\n");
	status = dcerpc_secondary_context(p, &p3, &tmptbl);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_RPC_UNSUPPORTED_NAME_SYNTAX,
				      "dcerpc_alter_context with wrong version should fail");

	torture_comment(torture, "Testing DSSETUP pipe operations\n");
	ret &= test_DsRoleGetPrimaryDomainInformation(torture, p2);

	if (handle) {
		ret &= test_lsa_Close(p->binding_handle, torture, handle);
	}

	torture_comment(torture, "Testing change of primary context\n");
	status = dcerpc_alter_context(p, torture, &syntax, transfer_syntax);
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	ret &= test_lsa_OpenPolicy2(p->binding_handle, torture, &handle);

	if (handle) {
		ret &= test_lsa_Close(p->binding_handle, torture, handle);
	}

	torture_comment(torture, "Testing change of primary context\n");
	status = dcerpc_alter_context(p, torture, &syntax2, transfer_syntax2);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {

		ret &= test_lsa_OpenPolicy2_ex(p->binding_handle, torture, &handle,
					       NT_STATUS_CONNECTION_DISCONNECTED,
					       NT_STATUS_CONNECTION_RESET);

		torture_assert(torture, !dcerpc_binding_handle_is_connected(p->binding_handle),
			       "dcerpc disconnected");

		return ret;
	}
	torture_assert_ntstatus_ok(torture, status, "dcerpc_alter_context failed");

	torture_comment(torture, "Testing DSSETUP pipe operations - should fault\n");
	ret &= test_DsRoleGetPrimaryDomainInformation_ext(torture, p, NT_STATUS_RPC_BAD_STUB_DATA);

	ret &= test_lsa_OpenPolicy2(p->binding_handle, torture, &handle);

	if (handle) {
		ret &= test_lsa_Close(p->binding_handle, torture, handle);
	}

	torture_comment(torture, "Testing DSSETUP pipe operations\n");

	ret &= test_DsRoleGetPrimaryDomainInformation(torture, p2);

	return ret;
}

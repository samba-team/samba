/*
   Unix SMB/CIFS implementation.
   test suite for rpc bind operations

   Copyright (C) Guenther Deschner 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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
#include "torture/rpc/torture_rpc.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "lib/cmdline/cmdline.h"

static bool test_openpolicy(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle *handle;

	torture_assert(tctx,
		test_lsa_OpenPolicy2(b, tctx, &handle),
		"failed to open policy");

	torture_assert(tctx,
		test_lsa_Close(b, tctx, handle),
		"failed to close policy");

	return true;
}

static bool test_bind(struct torture_context *tctx,
		      const void *private_data)
{
	struct dcerpc_binding *binding;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	const uint32_t *flags = (const uint32_t *)private_data;

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding),
		"failed to parse binding string");

	status = dcerpc_binding_set_flags(binding, *flags, DCERPC_AUTH_OPTIONS);
	torture_assert_ntstatus_ok(tctx, status, "set flags");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect_b(tctx, &p, binding,
				      &ndr_table_lsarpc,
				      samba_cmdline_get_creds(),
				      tctx->ev,
				      tctx->lp_ctx),
		"failed to connect pipe");

	torture_assert(tctx,
		test_openpolicy(tctx, p),
		"failed to test openpolicy");

	talloc_free(p);

	return true;
}

/**
 * Verifies a handle created in a connection is available on
 * a second connection when the same association group is
 * requested in the bind operation. The LSA interface can't be
 * used because it runs in preforking mode in the selftests.
 * Association groups should work when binding to interfaces
 * running in the same process.
 */
static bool test_assoc_group_handles_external(struct torture_context *tctx,
					      const void *private_data)
{
	struct dcerpc_binding *binding1 = NULL;
	const struct dcerpc_binding *bd1 = NULL;
	struct dcerpc_binding *binding2 = NULL;
	struct dcerpc_pipe *p1 = NULL;
	struct dcerpc_pipe *p2 = NULL;
	struct epm_Lookup r;
	struct epm_LookupHandleFree f;
	struct policy_handle handle;
	uint32_t assoc_group_id;
	uint32_t num_ents = 0;

	ZERO_STRUCT(handle);

	/* Open first pipe and open a policy handle */
	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding1),
		"failed to parse binding string");
	dcerpc_binding_set_transport(binding1, NCACN_IP_TCP);
	dcerpc_binding_set_string_option(binding1, "endpoint", "135");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect_b(tctx, &p1, binding1,
				      &ndr_table_epmapper,
				      samba_cmdline_get_creds(),
				      tctx->ev,
				      tctx->lp_ctx),
		"failed to connect first pipe");

	r.in.inquiry_type = RPC_C_EP_ALL_ELTS;
	r.in.object = NULL;
	r.in.interface_id = NULL;
	r.in.vers_option = RPC_C_VERS_ALL;

	r.in.entry_handle = &handle;
	r.in.max_ents = 1;

	r.out.entry_handle = &handle;
	r.out.num_ents = &num_ents;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_epm_Lookup_r(p1->binding_handle, tctx, &r),
		"failed EPM Lookup");
	torture_assert_int_equal(tctx,
		r.out.result,
		EPMAPPER_STATUS_OK,
		"failed EPM Lookup");

	/* Open second pipe, different association group. Handle not found */
	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding2),
		"failed to parse binding string");
	dcerpc_binding_set_transport(binding2, NCACN_IP_TCP);
	dcerpc_binding_set_string_option(binding2, "endpoint", "135");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect_b(tctx, &p2, binding2,
				      &ndr_table_epmapper,
				      samba_cmdline_get_creds(),
				      tctx->ev,
				      tctx->lp_ctx),
		"failed to connect second pipe");

	torture_assert_ntstatus_equal(tctx,
		dcerpc_epm_Lookup_r(p2->binding_handle, tctx, &r),
		NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
		"Unexpected EPM Lookup success");

	/* Open second pipe, same association group. Handle is found */
	bd1 = dcerpc_binding_handle_get_binding(p1->binding_handle);
	assoc_group_id = dcerpc_binding_get_assoc_group_id(bd1);
	dcerpc_binding_set_assoc_group_id(binding2, assoc_group_id);

	TALLOC_FREE(p2);
	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect_b(tctx, &p2, binding2,
				      &ndr_table_epmapper,
				      samba_cmdline_get_creds(),
				      tctx->ev,
				      tctx->lp_ctx),
		"failed to connect second pipe");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_epm_Lookup_r(p2->binding_handle, tctx, &r),
		"failed EPM Lookup");

	torture_assert_int_equal(tctx,
		r.out.result,
		EPMAPPER_STATUS_OK,
		"failed EPM Lookup");

	/* Cleanup */
	f.in.entry_handle = &handle;
	f.out.entry_handle = &handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_epm_LookupHandleFree_r(p1->binding_handle, tctx, &f),
		"failed EPM LookupHandleFree");

	torture_assert_int_equal(tctx,
		r.out.result,
		EPMAPPER_STATUS_OK,
		"failed EPM LookupHandleFree");

	TALLOC_FREE(p1);
	TALLOC_FREE(p2);
	TALLOC_FREE(binding2);
	TALLOC_FREE(binding1);

	return true;
}

static void test_bind_op(struct torture_suite *suite,
			 const char *name,
			 uint32_t flags)
{
	uint32_t *flags_p = talloc(suite, uint32_t);

	*flags_p = flags;

	torture_suite_add_simple_tcase_const(suite, name, test_bind, flags_p);
}


struct torture_suite *torture_rpc_bind(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "bind");
	struct {
		const char *test_name;
		uint32_t flags;
	} tests[] = {
		{
			.test_name	= "ntlm,sign",
			.flags		= DCERPC_AUTH_NTLM | DCERPC_SIGN
		},{
			.test_name	= "ntlm,sign,seal",
			.flags		= DCERPC_AUTH_NTLM | DCERPC_SIGN | DCERPC_SEAL
		},{
			.test_name	= "spnego,sign",
			.flags		= DCERPC_AUTH_SPNEGO | DCERPC_SIGN
		},{
			.test_name	= "spnego,sign,seal",
			.flags		= DCERPC_AUTH_SPNEGO | DCERPC_SIGN | DCERPC_SEAL
		}
	};
	int i;

	for (i=0; i < ARRAY_SIZE(tests); i++) {
		test_bind_op(suite, tests[i].test_name, tests[i].flags);
	}
	for (i=0; i < ARRAY_SIZE(tests); i++) {
		test_bind_op(suite, talloc_asprintf(suite, "bigendian,%s", tests[i].test_name), tests[i].flags | DCERPC_PUSH_BIGENDIAN);
	}

	torture_suite_add_simple_tcase_const(suite,
					     "assoc_group_handles_external",
					     test_assoc_group_handles_external,
					     NULL);

	return suite;
}

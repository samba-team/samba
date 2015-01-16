/*
   Unix SMB/CIFS implementation.
   test suite for rpc witness operations

   Copyright (C) Guenther Deschner 2015

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
#include "librpc/gen_ndr/ndr_witness_c.h"
#include "librpc/gen_ndr/ndr_srvsvc_c.h"
#include "param/param.h"

struct torture_test_witness_state {
	const char *net_name;
	const char *share_name;
	struct witness_interfaceList *list;
	struct policy_handle context_handle;
};

static bool test_witness_GetInterfaceList(struct torture_context *tctx,
					  struct dcerpc_pipe *p,
					  void *data)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct witness_GetInterfaceList r;
	struct witness_interfaceList *l;
	struct torture_test_witness_state *state =
		(struct torture_test_witness_state *)data;

	r.out.interface_list = &l;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_witness_GetInterfaceList_r(b, tctx, &r),
		"GetInterfaceList failed");

	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetInterfaceList failed");

	state->list = l;

	return true;
}

static bool find_sofs_share(struct torture_context *tctx,
			    const char **sofs_sharename)
{
	struct dcerpc_pipe *p;
	struct dcerpc_binding_handle *b;
	struct srvsvc_NetShareEnumAll r;
	struct srvsvc_NetShareInfoCtr info_ctr;
	struct srvsvc_NetShareCtr1 ctr1;
	uint32_t resume_handle = 0;
	uint32_t totalentries = 0;
	int i;

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_connection_transport(tctx, &p, &ndr_table_srvsvc,
						 NCACN_NP, 0),
		"failed to setup srvsvc connection");

	b = p->binding_handle;

	ZERO_STRUCT(ctr1);

	info_ctr.level = 1;
	info_ctr.ctr.ctr1 = &ctr1;

	r.in.server_unc = dcerpc_server_name(p);
	r.in.max_buffer = -1;
	r.in.info_ctr = &info_ctr;
	r.in.resume_handle = &resume_handle;
	r.out.totalentries = &totalentries;
	r.out.info_ctr = &info_ctr;
	r.out.resume_handle = &resume_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_srvsvc_NetShareEnumAll_r(b, tctx, &r),
		"failed to call srvsvc_NetShareEnumAll");

	torture_assert_werr_ok(tctx,
		r.out.result,
		"failed to call srvsvc_NetShareEnumAll");

	for (i=0; i < r.out.info_ctr->ctr.ctr1->count; i++) {

		if (r.out.info_ctr->ctr.ctr1->array[i].type == STYPE_CLUSTER_SOFS) {
			*sofs_sharename = talloc_strdup(tctx, r.out.info_ctr->ctr.ctr1->array[i].name);
			if (*sofs_sharename == NULL) {
				return false;
			}
			torture_comment(tctx, "using SOFS share: %s\n", *sofs_sharename);
			return true;
		}
		if (r.out.info_ctr->ctr.ctr1->array[i].type == STYPE_DISKTREE) {
			*sofs_sharename = talloc_strdup(tctx, r.out.info_ctr->ctr.ctr1->array[i].name);
			if (*sofs_sharename == NULL) {
				return false;
			}
			torture_comment(tctx, "assuming SOFS share: %s\n", *sofs_sharename);
			return true;
		}
	}

	return false;
}

static bool init_witness_test_state(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct torture_test_witness_state *state)
{
	if (state->net_name == NULL) {
		state->net_name = lpcfg_parm_string(tctx->lp_ctx, NULL, "torture", "net_name");
	}

	if (state->list == NULL) {
		torture_assert(tctx,
			test_witness_GetInterfaceList(tctx, p, state),
			"failed to retrieve GetInterfaceList");
	}

	if (state->share_name == NULL) {
		find_sofs_share(tctx, &state->share_name);
	}

	return true;
}

static bool test_witness_UnRegister_with_handle(struct torture_context *tctx,
						struct dcerpc_pipe *p,
						struct policy_handle *context_handle)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct witness_UnRegister r;

	r.in.context_handle = *context_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_witness_UnRegister_r(b, tctx, &r),
		"UnRegister failed");

	torture_assert_werr_ok(tctx,
		r.out.result,
		"UnRegister failed");

	/* make sure we are not able/allowed to reuse context handles after they
	 * have been unregistered */

	torture_assert_ntstatus_ok(tctx,
		dcerpc_witness_UnRegister_r(b, tctx, &r),
		"UnRegister failed");

	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_INVALID_PARAM,
		"UnRegister failed");

	return true;
}

static bool test_witness_UnRegister(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    void *data)
{
	/* acquire handle and free afterwards */
	return true;
}

static bool get_ip_address_from_interface(struct torture_context *tctx,
					  struct witness_interfaceInfo *i,
					  const char **ip_address)
{
	if (i->flags & WITNESS_INFO_IPv4_VALID) {
		*ip_address = talloc_strdup(tctx, i->ipv4);
		torture_assert(tctx, *ip_address, "talloc_strdup failed");
		return true;
	}

	if (i->flags & WITNESS_INFO_IPv6_VALID) {
		*ip_address = talloc_strdup(tctx, i->ipv6);
		torture_assert(tctx, *ip_address, "talloc_strdup failed");
		return true;
	}

	return false;
}

static bool check_valid_interface(struct torture_context *tctx,
				  struct witness_interfaceInfo *i)
{
	/* continue looking for an interface that allows witness
	 * registration */
	if (!(i->flags & WITNESS_INFO_WITNESS_IF)) {
		return false;
	}

	/* witness should be available of course */
	if (i->state != WITNESS_STATE_AVAILABLE) {
		return false;
	}

	return true;
}

static bool test_witness_Register(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  void *data)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct witness_Register r;
	struct policy_handle context_handle;
	struct torture_test_witness_state *state =
		(struct torture_test_witness_state *)data;
	int i;

	struct {
		enum witness_version version;
		const char *net_name;
		const char *ip_address;
		const char *client_computer_name;
		NTSTATUS expected_status;
		WERROR expected_result;
	} tests[] = {
		{
			.version		= 0,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= 1,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= 123456,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= -1,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V2,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V1,
			.net_name		= "",
			.ip_address		= "",
			.client_computer_name	= "",
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		},{
			.version		= WITNESS_V1,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		},{
			.version		= WITNESS_V2,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V1,
			.net_name		= dcerpc_server_name(p),
			.ip_address		= NULL, /* "99192.168.44.45" */
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		}

	};

	for (i=0; i < ARRAY_SIZE(tests); i++) {

		ZERO_STRUCT(r);

		r.out.context_handle = &context_handle;

		r.in.version = tests[i].version;
		r.in.net_name = tests[i].net_name;
		r.in.ip_address = tests[i].ip_address;
		r.in.client_computer_name = tests[i].client_computer_name;

		torture_assert_ntstatus_equal(tctx,
			dcerpc_witness_Register_r(b, tctx, &r),
			tests[i].expected_status,
			"Register failed");

		torture_assert_werr_equal(tctx,
			r.out.result,
			tests[i].expected_result,
			"Register failed");

		if (W_ERROR_IS_OK(r.out.result)) {

			/* we have a handle, make sure to unregister it */
			torture_assert(tctx,
				test_witness_UnRegister_with_handle(tctx, p, r.out.context_handle),
				"Failed to unregister");
		}
	}

	init_witness_test_state(tctx, p, state);

	for (i=0; state->list && i < state->list->num_interfaces; i++) {

		const char *ip_address;
		struct witness_interfaceInfo interface = state->list->interfaces[i];

		if (!check_valid_interface(tctx, &interface)) {
			continue;
		}

		torture_assert(tctx,
			get_ip_address_from_interface(tctx, &interface, &ip_address),
			"failed to get ip_address from interface");

		r.in.version = WITNESS_V1;
		r.in.net_name = state->net_name;
		r.in.ip_address = ip_address;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_Register_r(b, tctx, &r),
			"Register failed");

		torture_assert_werr_ok(tctx,
			r.out.result,
			"Register failed");

		torture_assert(tctx,
			test_witness_UnRegister_with_handle(tctx, p, r.out.context_handle),
			"Failed to unregister");
	}

	return true;
}

static bool test_witness_RegisterEx(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    void *data)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct witness_RegisterEx r;
	struct policy_handle context_handle;
	struct torture_test_witness_state *state =
		(struct torture_test_witness_state *)data;
	int i;

	struct {
		enum witness_version version;
		const char *net_name;
		const char *ip_address;
		const char *client_computer_name;
		NTSTATUS expected_status;
		WERROR expected_result;
	} tests[] = {
		{
			.version		= 0,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= 1,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= 123456,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= -1,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V1,
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V2,
			.net_name		= "",
			.ip_address		= "",
			.client_computer_name	= "",
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		},{
			.version		= WITNESS_V2,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		},{
			.version		= WITNESS_V1,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_REVISION_MISMATCH
		},{
			.version		= WITNESS_V2,
			.net_name		= dcerpc_server_name(p),
			.ip_address		= NULL, /* "99192.168.44.45" */
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAM
		}

	};

	for (i=0; i < ARRAY_SIZE(tests); i++) {

		ZERO_STRUCT(r);

		r.out.context_handle = &context_handle;

		r.in.version = tests[i].version;
		r.in.net_name = tests[i].net_name;
		r.in.ip_address = tests[i].ip_address;
		r.in.client_computer_name = tests[i].client_computer_name;

		torture_assert_ntstatus_equal(tctx,
			dcerpc_witness_RegisterEx_r(b, tctx, &r),
			tests[i].expected_status,
			"RegisterEx failed");

		torture_assert_werr_equal(tctx,
			r.out.result,
			tests[i].expected_result,
			"RegisterEx failed");

		if (W_ERROR_IS_OK(r.out.result)) {

			/* we have a handle, make sure to unregister it */
			torture_assert(tctx,
				test_witness_UnRegister_with_handle(tctx, p, r.out.context_handle),
				"Failed to unregister");
		}
	}

	init_witness_test_state(tctx, p, state);

	for (i=0; state->list && i < state->list->num_interfaces; i++) {

		const char *ip_address;
		struct witness_interfaceInfo interface = state->list->interfaces[i];

		if (!check_valid_interface(tctx, &interface)) {
			continue;
		}

		torture_assert(tctx,
			get_ip_address_from_interface(tctx, &interface, &ip_address),
			"failed to get ip_address from interface");

		r.in.version = WITNESS_V2;
		r.in.net_name = state->net_name;
		r.in.ip_address = ip_address;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_RegisterEx_r(b, tctx, &r),
			"RegisterEx failed");

		torture_assert_werr_ok(tctx,
			r.out.result,
			"RegisterEx failed");

		torture_assert(tctx,
			test_witness_UnRegister_with_handle(tctx, p, r.out.context_handle),
			"Failed to unregister");
	}

	return true;
}

/* for this test to run, we need to have some basic clusapi client support
 * first, so that we can programmatically change something in the cluster and
 * then receive async notifications - Guenther */

static bool test_witness_AsyncNotify(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     void *data)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct witness_AsyncNotify r;
	struct witness_notifyResponse *response;
	struct torture_test_witness_state *state =
		(struct torture_test_witness_state *)data;
	int i;

	init_witness_test_state(tctx, p, state);

	for (i=0; state->list && i < state->list->num_interfaces; i++) {

		const char *ip_address;
		struct witness_interfaceInfo interface = state->list->interfaces[i];
		struct witness_Register reg;

		if (!check_valid_interface(tctx, &interface)) {
			continue;
		}

		torture_assert(tctx,
			get_ip_address_from_interface(tctx, &interface, &ip_address),
			"failed to get ip_address from interface");

		reg.in.version = WITNESS_V1;
		reg.in.net_name = state->net_name;
		reg.in.ip_address = ip_address;
		reg.in.client_computer_name = lpcfg_netbios_name(tctx->lp_ctx);
		reg.out.context_handle = &state->context_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_Register_r(b, tctx, &reg),
			"Register failed");

		torture_assert_werr_ok(tctx,
			reg.out.result,
			"Register failed");

		r.in.context_handle = state->context_handle;
		r.out.response = &response;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_AsyncNotify_r(b, tctx, &r),
			"AsyncNotify failed");

		torture_assert(tctx,
			test_witness_UnRegister_with_handle(tctx, p, &state->context_handle),
			"Failed to unregister");

		ZERO_STRUCT(state->context_handle);
	}

	return true;
}

struct torture_suite *torture_rpc_witness(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "witness");
	struct torture_test_witness_state *state;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "witness",
						  &ndr_table_witness);

	state = talloc_zero(tcase, struct torture_test_witness_state);

	torture_rpc_tcase_add_test_ex(tcase, "GetInterfaceList",
				      test_witness_GetInterfaceList, state);
	torture_rpc_tcase_add_test_ex(tcase, "Register",
				      test_witness_Register, state);
	torture_rpc_tcase_add_test_ex(tcase, "UnRegister",
				      test_witness_UnRegister, state);
	torture_rpc_tcase_add_test_ex(tcase, "RegisterEx",
				      test_witness_RegisterEx, state);
	torture_rpc_tcase_add_test_ex(tcase, "AsyncNotify",
				      test_witness_AsyncNotify, state);

	return suite;
}

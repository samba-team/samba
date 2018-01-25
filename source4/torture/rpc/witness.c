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
#include "librpc/gen_ndr/ndr_clusapi_c.h"
#include "param/param.h"
#include <tevent.h>
#include "lib/cmdline/popt_common.h"

struct torture_test_clusapi_state {
	struct dcerpc_pipe *p;
};

struct torture_test_witness_state {
	const char *net_name;
	const char *share_name;
	struct witness_interfaceList *list;
	struct policy_handle context_handle;
	struct torture_test_clusapi_state clusapi;
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
						 NCACN_NP, 0, 0),
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
		WERR_INVALID_PARAMETER,
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
			.expected_result	= WERR_INVALID_PARAMETER
		},{
			.version		= WITNESS_V1,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAMETER
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
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAMETER
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
			.expected_result	= WERR_INVALID_PARAMETER
		},{
			.version		= WITNESS_V2,
			.net_name		= NULL,
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAMETER
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
			.ip_address		= NULL,
			.client_computer_name	= lpcfg_netbios_name(tctx->lp_ctx),
			.expected_status	= NT_STATUS_OK,
			.expected_result	= WERR_INVALID_PARAMETER
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

		/*
		 * a valid request with an invalid sharename fails with
		 * WERR_INVALID_STATE
		 */
		r.in.share_name = "any_invalid_share_name";

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_RegisterEx_r(b, tctx, &r),
			"RegisterEx failed");

		torture_assert_werr_equal(tctx,
			r.out.result,
			WERR_INVALID_STATE,
			"RegisterEx failed");

		r.in.share_name = NULL;

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

static bool setup_clusapi_connection(struct torture_context *tctx,
				     struct torture_test_witness_state *s)
{
	struct dcerpc_binding *binding;

	if (s->clusapi.p) {
		return true;
	}

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_binding(tctx, &binding),
		"failed to retrieve torture binding");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_binding_set_transport(binding, NCACN_IP_TCP),
		"failed to set transport");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_binding_set_flags(binding, DCERPC_SEAL, 0),
		"failed to set dcerpc flags");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect_b(tctx, &s->clusapi.p, binding,
				      &ndr_table_clusapi,
				      popt_get_cmdline_credentials(),
				      tctx->ev, tctx->lp_ctx),
		"failed to connect dcerpc pipe");

	return true;
}

#if 0
static bool cluster_get_nodes(struct torture_context *tctx,
			      struct torture_test_witness_state *s)
{
	struct clusapi_CreateEnum r;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	struct dcerpc_binding_handle *b;

	torture_assert(tctx,
		setup_clusapi_connection(tctx, s),
		"failed to setup clusapi connection");

	b = s->clusapi.p->binding_handle;

	r.in.dwType = CLUSTER_ENUM_NODE;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"failed to enumerate nodes");

	return true;
}
#endif

static bool test_GetResourceState_int(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      struct policy_handle *hResource,
				      enum clusapi_ClusterResourceState *State)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceState r;
	const char *NodeName;
	const char *GroupName;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.State = State;
	r.out.NodeName = &NodeName;
	r.out.GroupName = &GroupName;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceState_r(b, tctx, &r),
		"GetResourceState failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetResourceState failed");

	return true;
}

static bool toggle_cluster_resource_state(struct torture_context *tctx,
					  struct dcerpc_pipe *p,
					  const char *resource_name,
					  enum clusapi_ClusterResourceState *old_state,
					  enum clusapi_ClusterResourceState *new_state)
{
	struct policy_handle hResource;
	enum clusapi_ClusterResourceState State;

	torture_assert(tctx,
		test_OpenResource_int(tctx, p, resource_name, &hResource),
		"failed to open resource");
	torture_assert(tctx,
		test_GetResourceState_int(tctx, p, &hResource, &State),
		"failed to query resource state");

	if (old_state) {
		*old_state = State;
	}

	switch (State) {
	case ClusterResourceOffline:
		if (!test_OnlineResource_int(tctx, p, &hResource)) {
			test_CloseResource_int(tctx, p, &hResource);
			torture_warning(tctx, "failed to set resource online");
			return false;
		}
		break;
	case ClusterResourceOnline:
		if (!test_OfflineResource_int(tctx, p, &hResource)) {
			test_CloseResource_int(tctx, p, &hResource);
			torture_warning(tctx, "failed to set resource offline");
			return false;
		}
		break;

	default:
		break;
	}

	torture_assert(tctx,
		test_GetResourceState_int(tctx, p, &hResource, &State),
		"failed to query resource state");

	if (new_state) {
		*new_state = State;
	}

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

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

	setup_clusapi_connection(tctx, state);

	for (i=0; state->list && i < state->list->num_interfaces; i++) {

		const char *ip_address;
		struct witness_interfaceInfo interface = state->list->interfaces[i];
		struct witness_Register reg;
		struct tevent_req *req;
		enum clusapi_ClusterResourceState old_state, new_state;

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

		req = dcerpc_witness_AsyncNotify_r_send(tctx, tctx->ev, b, &r);
		torture_assert(tctx, req, "failed to create request");

		torture_assert(tctx,
			toggle_cluster_resource_state(tctx, state->clusapi.p, state->net_name, &old_state, &new_state),
			"failed to toggle cluster resource state");
		torture_assert(tctx, old_state != new_state, "failed to change cluster resource state");

		torture_assert(tctx,
			tevent_req_poll(req, tctx->ev),
			"failed to call event loop");

		torture_assert_ntstatus_ok(tctx,
			dcerpc_witness_AsyncNotify_r_recv(req, tctx),
			"failed to receive reply");

		torture_assert_int_equal(tctx, response->num, 1, "num");
		torture_assert_int_equal(tctx, response->type, WITNESS_NOTIFY_RESOURCE_CHANGE, "type");

		/*
		 * TODO: find out how ClusterResourceOfflinePending and
		 * ClusterResourceOnlinePending are represented as witness
		 * types.
		 */

		if (new_state == ClusterResourceOffline) {
			torture_assert_int_equal(tctx, response->messages[0].resource_change.type, WITNESS_RESOURCE_STATE_UNAVAILABLE, "resource_change.type");
		}
		if (new_state == ClusterResourceOnline) {
			torture_assert_int_equal(tctx, response->messages[0].resource_change.type, WITNESS_RESOURCE_STATE_AVAILABLE, "resource_change.type");
		}
		torture_assert(tctx,
			test_witness_UnRegister_with_handle(tctx, p, &state->context_handle),
			"Failed to unregister");

		ZERO_STRUCT(state->context_handle);

		torture_assert(tctx,
			toggle_cluster_resource_state(tctx, state->clusapi.p, state->net_name, &old_state, &new_state),
			"failed to toggle cluster resource state");
		torture_assert(tctx, old_state != new_state, "failed to change cluster resource state");
	}

	return true;
}

static bool test_do_witness_RegisterEx(struct torture_context *tctx,
				       struct dcerpc_binding_handle *b,
				       uint32_t version,
				       const char *net_name,
				       const char *share_name,
				       const char *ip_address,
				       const char *client_computer_name,
				       uint32_t flags,
				       uint32_t timeout,
				       struct policy_handle *context_handle)
{
	struct witness_RegisterEx r;

	r.in.version = version;
	r.in.net_name = net_name;
	r.in.share_name = NULL;
	r.in.ip_address = ip_address;
	r.in.client_computer_name = client_computer_name;
	r.in.flags = flags;
	r.in.timeout = timeout;
	r.out.context_handle = context_handle;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_witness_RegisterEx_r(b, tctx, &r),
		"RegisterEx failed");

	torture_assert_werr_ok(tctx,
		r.out.result,
		"RegisterEx failed");

	return true;
}

static void torture_subunit_report_time(struct torture_context *tctx)
{
	struct timespec tp;
	struct tm *tmp;
	char timestr[200];

	if (clock_gettime(CLOCK_REALTIME, &tp) != 0) {
		torture_comment(tctx, "failed to call clock_gettime");
		return;
	}

	tmp = gmtime(&tp.tv_sec);
	if (!tmp) {
		torture_comment(tctx, "failed to call gmtime");
		return;
	}

	if (strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmp) <= 0) {
		torture_comment(tctx, "failed to call strftime");
		return;
	}

	torture_comment(tctx, "time: %s.%06ld\n", timestr, tp.tv_nsec / 1000);
}

static bool test_witness_AsyncNotify_timeouts(struct torture_context *tctx,
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

	setup_clusapi_connection(tctx, state);

	for (i=0; state->list && i < state->list->num_interfaces; i++) {

		const char *ip_address;
		struct witness_interfaceInfo interface = state->list->interfaces[i];
		uint32_t timeouts[] = {
			0, 1, 10, 100, 120
		};
		int t;
		uint32_t old_timeout;

		if (!check_valid_interface(tctx, &interface)) {
			continue;
		}

		torture_assert(tctx,
			get_ip_address_from_interface(tctx, &interface, &ip_address),
			"failed to get ip_address from interface");

		for (t=0; t < ARRAY_SIZE(timeouts); t++) {

			torture_comment(tctx, "Testing Async Notify with timeout of %d milliseconds", timeouts[t]);

			torture_assert(tctx,
				test_do_witness_RegisterEx(tctx, b,
							   WITNESS_V2,
							   state->net_name,
							   NULL,
							   ip_address,
							   lpcfg_netbios_name(tctx->lp_ctx),
							   0,
							   timeouts[t],
							   &state->context_handle),
				"failed to RegisterEx");

			r.in.context_handle = state->context_handle;
			r.out.response = &response;

			old_timeout = dcerpc_binding_handle_set_timeout(b, UINT_MAX);

			torture_subunit_report_time(tctx);

			torture_assert_ntstatus_ok(tctx,
				dcerpc_witness_AsyncNotify_r(b, tctx, &r),
				"AsyncNotify failed");
			torture_assert_werr_equal(tctx,
				r.out.result,
				WERR_TIMEOUT,
				"AsyncNotify failed");

			torture_subunit_report_time(tctx);

			dcerpc_binding_handle_set_timeout(b, old_timeout);

			torture_assert(tctx,
				test_witness_UnRegister_with_handle(tctx, p, &state->context_handle),
				"Failed to unregister");

			ZERO_STRUCT(state->context_handle);
		}
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
	torture_rpc_tcase_add_test_ex(tcase, "AsyncNotify_timeouts",
				      test_witness_AsyncNotify_timeouts, state);

	return suite;
}

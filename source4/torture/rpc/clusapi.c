/*
   Unix SMB/CIFS implementation.
   test suite for clusapi rpc operations

   Copyright (C) Günther Deschner 2015

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
#include "librpc/gen_ndr/ndr_clusapi_c.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"

static bool test_OpenCluster_int(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 struct policy_handle *Cluster)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenCluster r;
	uint32_t Status;

	r.out.Status = &Status;
	r.out.Cluster = Cluster;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenCluster_r(b, tctx, &r),
		"OpenCluster failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(*r.out.Status),
		"OpenCluster failed");

	return true;
}

static bool test_CloseCluster_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *Cluster)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseCluster r;

	r.in.Cluster = Cluster;
	r.out.Cluster = Cluster;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseCluster_r(b, tctx, &r),
		"CloseCluster failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"CloseCluster failed");

	torture_assert(tctx,
		ndr_policy_handle_empty(Cluster),
		"policy_handle non empty after CloseCluster");

	return true;
}

static bool test_OpenCluster(struct torture_context *tctx,
			     struct dcerpc_pipe *p)
{
	struct policy_handle Cluster;

	if (!test_OpenCluster_int(tctx, p, &Cluster)) {
		return false;
	}

	test_CloseCluster_int(tctx, p, &Cluster);

	return true;
}

static bool test_CloseCluster(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle Cluster;

	if (!test_OpenCluster_int(tctx, p, &Cluster)) {
		return false;
	}

	return test_CloseCluster_int(tctx, p, &Cluster);
}

static bool test_SetClusterName(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_SetClusterName r;
	uint32_t rpc_status;

	r.in.NewClusterName = "wurst";
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_SetClusterName_r(b, tctx, &r),
		"SetClusterName failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"SetClusterName failed");

	return true;
}

static bool test_GetClusterName(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetClusterName r;
	const char *ClusterName;
	const char *NodeName;

	r.out.ClusterName = &ClusterName;
	r.out.NodeName = &NodeName;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetClusterName_r(b, tctx, &r),
		"GetClusterName failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"GetClusterName failed");

	return true;
}

static bool test_GetClusterVersion(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetClusterVersion r;
	uint16_t lpwMajorVersion;
	uint16_t lpwMinorVersion;
	uint16_t lpwBuildNumber;
	const char *lpszVendorId;
	const char *lpszCSDVersion;

	r.out.lpwMajorVersion = &lpwMajorVersion;
	r.out.lpwMinorVersion = &lpwMinorVersion;
	r.out.lpwBuildNumber = &lpwBuildNumber;
	r.out.lpszVendorId = &lpszVendorId;
	r.out.lpszCSDVersion = &lpszCSDVersion;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetClusterVersion_r(b, tctx, &r),
		"GetClusterVersion failed");
	torture_assert_werr_equal(tctx,
		W_ERROR(r.out.result),
		WERR_CALL_NOT_IMPLEMENTED,
		"GetClusterVersion failed");

	return true;
}

static bool test_CreateEnum(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_RESOURCE;
	struct ENUM_LIST *ReturnEnum;
	uint32_t rpc_status;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"CreateEnum failed");

	return true;
}

struct torture_suite *torture_rpc_clusapi(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "clusapi");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "clusapi",
						  &ndr_table_clusapi);

	torture_rpc_tcase_add_test(tcase, "OpenCluster",
				   test_OpenCluster);
	torture_rpc_tcase_add_test(tcase, "CloseCluster",
				   test_CloseCluster);
	torture_rpc_tcase_add_test(tcase, "SetClusterName",
				   test_SetClusterName);
	torture_rpc_tcase_add_test(tcase, "GetClusterName",
				   test_GetClusterName);
	torture_rpc_tcase_add_test(tcase, "GetClusterVersion",
				   test_GetClusterVersion);
	torture_rpc_tcase_add_test(tcase, "CreateEnum",
				   test_CreateEnum);

	return suite;
}

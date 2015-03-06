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

static bool test_GetQuorumResource(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetQuorumResource r;
	const char *lpszResourceName;
	const char *lpszDeviceName;
	uint32_t pdwMaxQuorumLogSize;
	uint32_t rpc_status;

	r.out.lpszResourceName = &lpszResourceName;
	r.out.lpszDeviceName = &lpszDeviceName;
	r.out.pdwMaxQuorumLogSize = &pdwMaxQuorumLogSize;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetQuorumResource_r(b, tctx, &r),
		"GetQuorumResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"GetQuorumResource failed");

	return true;
}

static bool test_SetQuorumResource(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_SetQuorumResource r;
	const char *lpszDeviceName = "";
	uint32_t dwMaxQuorumLogSize = 0;
	uint32_t rpc_status;
	struct policy_handle hResource;

	/* we need to figure out how this call works and what we provide as
	   devicename and resource handle - gd
	 */

	torture_skip(tctx, "skipping SetQuorumResource test");

	ZERO_STRUCT(hResource);

	r.in.hResource = hResource;
	r.in.lpszDeviceName = lpszDeviceName;
	r.in.dwMaxQuorumLogSize = dwMaxQuorumLogSize;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_SetQuorumResource_r(b, tctx, &r),
		"SetQuorumResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"SetQuorumResource failed");

	return true;
}

static bool test_OpenResource_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenResource r;
	const char *lpszResourceName = "Cluster Name";
	uint32_t Status;
	uint32_t rpc_status;

	r.in.lpszResourceName = lpszResourceName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hResource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenResource_r(b, tctx, &r),
		"OpenResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(*r.out.Status),
		"OpenResource failed");

	return true;
}

static bool test_CloseResource_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseResource r;

	r.in.Resource = hResource;
	r.out.Resource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseResource_r(b, tctx, &r),
		"CloseResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"CloseResource failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(hResource),
		"policy_handle non empty after CloseResource");

	return true;
}

static bool test_OpenResource(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

static bool test_CloseResource(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	return test_CloseResource_int(tctx, p, &hResource);
}

static bool test_CreateResource_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateResource r;
	const char *lpszResourceName = "Cluster Name";
	const char *lpszResourceType = "wurst";
	uint32_t Status;
	uint32_t rpc_status;
	struct policy_handle hGroup;

	ZERO_STRUCT(hGroup); /* FIXME !!!!!! */

	r.in.hGroup = hGroup;
	r.in.lpszResourceName = lpszResourceName;
	r.in.lpszResourceType = lpszResourceType;
	r.in.dwFlags = 0; /* FIXME */
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hResource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateResource_r(b, tctx, &r),
		"CreateResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(*r.out.Status),
		"CreateResource failed");

	return true;
}

static bool test_DeleteResource_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_DeleteResource r;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_DeleteResource_r(b, tctx, &r),
		"DeleteResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"DeleteResource failed");

	return true;
}

static bool test_CreateResource(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_CreateResource_int(tctx, p, &hResource)) {
		return false;
	}

	test_DeleteResource_int(tctx, p, &hResource);

	return true;
}

static bool test_DeleteResource(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_CreateResource_int(tctx, p, &hResource)) {
		return false;
	}

	return test_DeleteResource_int(tctx, p, &hResource);
}

static bool test_GetResourceState_int(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceState r;
	uint32_t State;
	const char *NodeName;
	const char *GroupName;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.State = &State;
	r.out.NodeName = &NodeName;
	r.out.GroupName = &GroupName;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceState_r(b, tctx, &r),
		"GetResourceState failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"GetResourceState failed");

	return true;
}

static bool test_GetResourceState(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_GetResourceState_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_GetResourceId_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceId r;
	const char *pGuid;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceId_r(b, tctx, &r),
		"GetResourceId failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"GetResourceId failed");

	return true;
}

static bool test_GetResourceId(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_GetResourceId_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_GetResourceType_int(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceType r;
	const char *lpszResourceType;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.lpszResourceType = &lpszResourceType;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceType_r(b, tctx, &r),
		"GetResourceType failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"GetResourceType failed");

	return true;
}

static bool test_GetResourceType(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_GetResourceType_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_FailResource_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_FailResource r;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_FailResource_r(b, tctx, &r),
		"FailResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"FailResource failed");

	return true;
}

static bool test_FailResource(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_FailResource_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_OnlineResource_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OnlineResource r;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OnlineResource_r(b, tctx, &r),
		"OnlineResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"OnlineResource failed");

	return true;
}

static bool test_OnlineResource(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_OnlineResource_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_OfflineResource_int(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OfflineResource r;
	uint32_t rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OfflineResource_r(b, tctx, &r),
		"OfflineResource failed");
	torture_assert_werr_ok(tctx,
		W_ERROR(r.out.result),
		"OfflineResource failed");

	return true;
}

static bool test_OfflineResource(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_OfflineResource_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}


struct torture_suite *torture_rpc_clusapi(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "clusapi");
	struct torture_test *test;

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
	torture_rpc_tcase_add_test(tcase, "GetQuorumResource",
				   test_GetQuorumResource);
	torture_rpc_tcase_add_test(tcase, "SetQuorumResource",
				   test_SetQuorumResource);
	torture_rpc_tcase_add_test(tcase, "OpenResource",
				   test_OpenResource);
	torture_rpc_tcase_add_test(tcase, "CloseResource",
				   test_CloseResource);
	torture_rpc_tcase_add_test(tcase, "CreateResource",
				   test_CreateResource);
	torture_rpc_tcase_add_test(tcase, "DeleteResource",
				   test_DeleteResource);
	torture_rpc_tcase_add_test(tcase, "GetResourceState",
				   test_GetResourceState);
	torture_rpc_tcase_add_test(tcase, "GetResourceId",
				   test_GetResourceId);
	torture_rpc_tcase_add_test(tcase, "GetResourceType",
				   test_GetResourceType);
	test = torture_rpc_tcase_add_test(tcase, "FailResource",
				   test_FailResource);
	test->dangerous = true;
	torture_rpc_tcase_add_test(tcase, "OnlineResource",
				   test_OnlineResource);
	test = torture_rpc_tcase_add_test(tcase, "OfflineResource",
				   test_OfflineResource);
	test->dangerous = true;

	return suite;
}

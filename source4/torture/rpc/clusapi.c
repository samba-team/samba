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
	WERROR Status;

	r.out.Status = &Status;
	r.out.Cluster = Cluster;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenCluster_r(b, tctx, &r),
		"OpenCluster failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenCluster failed");

	return true;
}

static bool test_OpenClusterEx_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *Cluster)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenClusterEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;

	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.Status = &Status;
	r.out.hCluster = Cluster;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenClusterEx_r(b, tctx, &r),
		"OpenClusterEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenClusterEx failed");

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
		r.out.result,
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

static bool test_OpenClusterEx(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle Cluster;

	if (!test_OpenClusterEx_int(tctx, p, &Cluster)) {
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

static bool test_GetClusterName_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    const char **ClusterName)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetClusterName r;
	const char *NodeName;

	r.out.ClusterName = ClusterName;
	r.out.NodeName = &NodeName;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetClusterName_r(b, tctx, &r),
		"GetClusterName failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetClusterName failed");

	return true;
}

static bool test_SetClusterName(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_SetClusterName r;
	const char *NewClusterName;
	WERROR rpc_status;

	torture_assert(tctx,
		test_GetClusterName_int(tctx, p, &NewClusterName),
		"failed to query old ClusterName");

	r.in.NewClusterName = NewClusterName;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_SetClusterName_r(b, tctx, &r),
		"SetClusterName failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_RESOURCE_PROPERTIES_STORED,
		"SetClusterName failed");

	return true;
}

static bool test_GetClusterName(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	const char *ClusterName;

	return test_GetClusterName_int(tctx, p, &ClusterName);
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
		r.out.result,
		WERR_CALL_NOT_IMPLEMENTED,
		"GetClusterVersion failed");

	return true;
}

static bool test_GetClusterVersion2(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetClusterVersion2 r;
	uint16_t lpwMajorVersion;
	uint16_t lpwMinorVersion;
	uint16_t lpwBuildNumber;
	const char *lpszVendorId;
	const char *lpszCSDVersion;
	struct CLUSTER_OPERATIONAL_VERSION_INFO *ppClusterOpVerInfo;
	WERROR rpc_status;

	r.out.lpwMajorVersion = &lpwMajorVersion;
	r.out.lpwMinorVersion = &lpwMinorVersion;
	r.out.lpwBuildNumber = &lpwBuildNumber;
	r.out.lpszVendorId = &lpszVendorId;
	r.out.lpszCSDVersion = &lpszCSDVersion;
	r.out.ppClusterOpVerInfo = &ppClusterOpVerInfo;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetClusterVersion2_r(b, tctx, &r),
		"GetClusterVersion2 failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetClusterVersion2 failed");

	return true;
}

static bool test_CreateEnum(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_RESOURCE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
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
	WERROR rpc_status;

	r.out.lpszResourceName = &lpszResourceName;
	r.out.lpszDeviceName = &lpszDeviceName;
	r.out.pdwMaxQuorumLogSize = &pdwMaxQuorumLogSize;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetQuorumResource_r(b, tctx, &r),
		"GetQuorumResource failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
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
	WERROR rpc_status;
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
		r.out.result,
		"SetQuorumResource failed");

	return true;
}

static bool test_OpenResource_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  const char *lpszResourceName,
				  struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenResource r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszResourceName = lpszResourceName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hResource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenResource_r(b, tctx, &r),
		"OpenResource failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenResource failed");

	return true;
}

static bool test_OpenResourceEx_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    const char *lpszResourceName,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenResourceEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszResourceName = lpszResourceName;
	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hResource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenResourceEx_r(b, tctx, &r),
		"OpenResourceEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenResourceEx failed");

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
		r.out.result,
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

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
		return false;
	}

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

static bool test_OpenResourceEx(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_OpenResourceEx_int(tctx, p, "Cluster Name", &hResource)) {
		return false;
	}

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}


static bool test_CloseResource(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hResource;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
		return false;
	}

	return test_CloseResource_int(tctx, p, &hResource);
}

static bool test_OpenGroup_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       const char *lpszGroupName,
			       struct policy_handle *hGroup);
static bool test_CloseGroup_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *Group);

static bool test_CreateResource_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateResource r;
	const char *lpszResourceName = "wurst";
	const char *lpszResourceType = "Generic Service";
	WERROR Status;
	WERROR rpc_status;
	struct policy_handle hGroup;

	torture_assert(tctx,
		test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup),
		"failed to open group");

	r.in.hGroup = hGroup;
	r.in.lpszResourceName = lpszResourceName;
	r.in.lpszResourceType = lpszResourceType;
	r.in.dwFlags = CLUSTER_RESOURCE_DEFAULT_MONITOR;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hResource = hResource;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateResource_r(b, tctx, &r),
		"CreateResource failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"CreateResource failed");

	test_CloseGroup_int(tctx, p, &hGroup);

	return true;
}

static bool test_DeleteResource_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_DeleteResource r;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_DeleteResource_r(b, tctx, &r),
		"DeleteResource failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
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

static bool test_SetResourceName_int(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_SetResourceName r;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.in.lpszResourceName = "wurst";
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_SetResourceName_r(b, tctx, &r),
		"SetResourceName failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"SetResourceName failed");

	return true;
}

static bool test_SetResourceName(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_CreateResource_int(tctx, p, &hResource)) {
		return false;
	}

	ret = test_SetResourceName_int(tctx, p, &hResource);

	test_DeleteResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_GetResourceState_int(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceState r;
	enum clusapi_ClusterResourceState State;
	const char *NodeName;
	const char *GroupName;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.State = &State;
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

static bool test_GetResourceState(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
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
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceId_r(b, tctx, &r),
		"GetResourceId failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetResourceId failed");

	return true;
}

static bool test_GetResourceId(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
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
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.lpszResourceType = &lpszResourceType;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceType_r(b, tctx, &r),
		"GetResourceType failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetResourceType failed");

	return true;
}

static bool test_GetResourceType(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
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
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_FailResource_r(b, tctx, &r),
		"FailResource failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"FailResource failed");

	return true;
}

static bool test_FailResource(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
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
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OnlineResource_r(b, tctx, &r),
		"OnlineResource failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"OnlineResource failed");

	return true;
}

static bool test_OnlineResource(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
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
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OfflineResource_r(b, tctx, &r),
		"OfflineResource failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"OfflineResource failed");

	return true;
}

static bool test_OfflineResource(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_OfflineResource_int(tctx, p, &hResource);

	test_CloseResource_int(tctx, p, &hResource);

	return ret;
}

static bool test_one_resource(struct torture_context *tctx,
			      struct dcerpc_pipe *p,
			      const char *resource_name)
{
	struct policy_handle hResource;

	torture_assert(tctx,
		test_OpenResource_int(tctx, p, resource_name, &hResource),
		"failed to open resource");
	test_CloseResource_int(tctx, p, &hResource);

	torture_assert(tctx,
		test_OpenResourceEx_int(tctx, p, resource_name, &hResource),
		"failed to openex resource");

	torture_assert(tctx,
		test_GetResourceType_int(tctx, p, &hResource),
		"failed to query resource type");
	torture_assert(tctx,
		test_GetResourceId_int(tctx, p, &hResource),
		"failed to query resource id");
	torture_assert(tctx,
		test_GetResourceState_int(tctx, p, &hResource),
		"failed to query resource id");

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

static bool test_all_resources(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_RESOURCE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateEnum failed");

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_RESOURCE, "type mismatch");

		torture_assert(tctx,
			test_one_resource(tctx, p, e.Name),
			"failed to test one resource");
	}

	return true;
}

static bool test_CreateResEnum(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateResEnum r;
	struct policy_handle hResource;
	uint32_t dwType = CLUSTER_ENUM_RESOURCE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;

	torture_assert(tctx,
		test_OpenResource_int(tctx, p, "Cluster Name", &hResource),
		"OpenResource failed");

	r.in.hResource = hResource;
	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateResEnum_r(b, tctx, &r),
		"CreateResEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateResEnum failed");

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

static bool test_OpenNode_int(struct torture_context *tctx,
			      struct dcerpc_pipe *p,
			      const char *lpszNodeName,
			      struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNode r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNodeName = lpszNodeName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNode= hNode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNode_r(b, tctx, &r),
		"OpenNode failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNode failed");

	return true;
}

static bool test_OpenNodeEx_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				const char *lpszNodeName,
				struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNodeEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNodeName = lpszNodeName;
	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNode= hNode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNodeEx_r(b, tctx, &r),
		"OpenNodeEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNodeEx failed");

	return true;
}


static bool test_CloseNode_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       struct policy_handle *Node)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseNode r;

	r.in.Node = Node;
	r.out.Node = Node;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseNode_r(b, tctx, &r),
		"CloseNode failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseNode failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(Node),
		"policy_handle non empty after CloseNode");

	return true;
}

static bool test_OpenNode(struct torture_context *tctx,
			  struct dcerpc_pipe *p)
{
	struct policy_handle hNode;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	test_CloseNode_int(tctx, p, &hNode);

	return true;
}

static bool test_OpenNodeEx(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct policy_handle hNode;

	if (!test_OpenNodeEx_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	test_CloseNode_int(tctx, p, &hNode);

	return true;
}

static bool test_CloseNode(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct policy_handle hNode;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	return test_CloseNode_int(tctx, p, &hNode);
}

static bool test_GetNodeState_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNodeState r;
	enum clusapi_ClusterNodeState State;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.out.State = &State;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNodeState_r(b, tctx, &r),
		"GetNodeState failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNodeState failed");

	return true;
}

static bool test_GetNodeState(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	ret = test_GetNodeState_int(tctx, p, &hNode);

	test_CloseNode_int(tctx, p, &hNode);

	return ret;
}

static bool test_GetNodeId_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNodeId r;
	const char *pGuid;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNodeId_r(b, tctx, &r),
		"GetNodeId failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNodeId failed");

	return true;
}

static bool test_GetNodeId(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	ret = test_GetNodeId_int(tctx, p, &hNode);

	test_CloseNode_int(tctx, p, &hNode);

	return ret;
}

static bool test_PauseNode_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_PauseNode r;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_PauseNode_r(b, tctx, &r),
		"PauseNode failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"PauseNode failed");

	return true;
}

static bool test_PauseNode(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	ret = test_PauseNode_int(tctx, p, &hNode);

	test_CloseNode_int(tctx, p, &hNode);

	return ret;
}

static bool test_ResumeNode_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_ResumeNode r;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ResumeNode_r(b, tctx, &r),
		"ResumeNode failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_CLUSTER_NODE_NOT_PAUSED,
		"ResumeNode gave unexpected result");

	return true;
}

static bool test_ResumeNode(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	ret = test_ResumeNode_int(tctx, p, &hNode);

	test_CloseNode_int(tctx, p, &hNode);

	return ret;
}

static bool test_EvictNode_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       struct policy_handle *hNode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_EvictNode r;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_EvictNode_r(b, tctx, &r),
		"EvictNode failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"EvictNode failed");

	return true;
}

static bool test_EvictNode(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, p, "NODE1", &hNode)) {
		return false;
	}

	ret = test_EvictNode_int(tctx, p, &hNode);

	test_CloseNode_int(tctx, p, &hNode);

	return ret;
}

static bool test_one_node(struct torture_context *tctx,
			  struct dcerpc_pipe *p,
			  const char *node_name)
{
	struct policy_handle hNode;

	torture_assert(tctx,
		test_OpenNode_int(tctx, p, node_name, &hNode),
		"failed to open node");
	test_CloseNode_int(tctx, p, &hNode);

	torture_assert(tctx,
		test_OpenNodeEx_int(tctx, p, node_name, &hNode),
		"failed to openex node");

	torture_assert(tctx,
		test_GetNodeId_int(tctx, p, &hNode),
		"failed to query node id");
	torture_assert(tctx,
		test_GetNodeState_int(tctx, p, &hNode),
		"failed to query node id");

	test_CloseNode_int(tctx, p, &hNode);

	return true;
}

static bool test_all_nodes(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_NODE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateEnum failed");

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_NODE, "type mismatch");

		torture_assert(tctx,
			test_one_node(tctx, p, e.Name),
			"failed to test one node");
	}

	return true;
}

static bool test_OpenGroup_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       const char *lpszGroupName,
			       struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenGroup r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszGroupName = lpszGroupName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hGroup= hGroup;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenGroup_r(b, tctx, &r),
		"OpenGroup failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenGroup failed");

	return true;
}

static bool test_OpenGroupEx_int(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 const char *lpszGroupName,
				 struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenGroupEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszGroupName = lpszGroupName;
	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hGroup= hGroup;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenGroupEx_r(b, tctx, &r),
		"OpenGroupEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenGroupEx failed");

	return true;
}

static bool test_CloseGroup_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *Group)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseGroup r;

	r.in.Group = Group;
	r.out.Group = Group;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseGroup_r(b, tctx, &r),
		"CloseGroup failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseGroup failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(Group),
		"policy_handle non empty after CloseGroup");

	return true;
}

static bool test_OpenGroup(struct torture_context *tctx,
			   struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	test_CloseGroup_int(tctx, p, &hGroup);

	return true;
}

static bool test_OpenGroupEx(struct torture_context *tctx,
			     struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;

	if (!test_OpenGroupEx_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	test_CloseGroup_int(tctx, p, &hGroup);

	return true;
}

static bool test_CloseGroup(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	return test_CloseGroup_int(tctx, p, &hGroup);
}

static bool test_GetGroupState_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetGroupState r;
	enum clusapi_ClusterGroupState State;
	const char *NodeName;
	WERROR rpc_status;

	r.in.hGroup = *hGroup;
	r.out.State = &State;
	r.out.NodeName = &NodeName;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetGroupState_r(b, tctx, &r),
		"GetGroupState failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetGroupState failed");

	return true;
}

static bool test_GetGroupState(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_GetGroupState_int(tctx, p, &hGroup);

	test_CloseGroup_int(tctx, p, &hGroup);

	return ret;
}

static bool test_GetGroupId_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetGroupId r;
	const char *pGuid;
	WERROR rpc_status;

	r.in.hGroup = *hGroup;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetGroupId_r(b, tctx, &r),
		"GetGroupId failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetGroupId failed");

	return true;
}

static bool test_GetGroupId(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_GetGroupId_int(tctx, p, &hGroup);

	test_CloseGroup_int(tctx, p, &hGroup);

	return ret;
}

static bool test_OnlineGroup_int(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OnlineGroup r;
	WERROR rpc_status;

	r.in.hGroup = *hGroup;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OnlineGroup_r(b, tctx, &r),
		"OnlineGroup failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"OnlineGroup failed");

	return true;
}

static bool test_OnlineGroup(struct torture_context *tctx,
			     struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_OnlineGroup_int(tctx, p, &hGroup);

	test_CloseGroup_int(tctx, p, &hGroup);

	return ret;
}

static bool test_OfflineGroup_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OfflineGroup r;
	WERROR rpc_status;

	r.in.hGroup = *hGroup;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OfflineGroup_r(b, tctx, &r),
		"OfflineGroup failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"OfflineGroup failed");

	return true;
}

static bool test_OfflineGroup(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_OfflineGroup_int(tctx, p, &hGroup);

	test_CloseGroup_int(tctx, p, &hGroup);

	return ret;
}

static bool test_one_group(struct torture_context *tctx,
			   struct dcerpc_pipe *p,
			   const char *node_name)
{
	struct policy_handle hGroup;

	torture_assert(tctx,
		test_OpenGroup_int(tctx, p, node_name, &hGroup),
		"failed to open group");
	test_CloseGroup_int(tctx, p, &hGroup);

	torture_assert(tctx,
		test_OpenGroupEx_int(tctx, p, node_name, &hGroup),
		"failed to openex group");

	torture_assert(tctx,
		test_GetGroupId_int(tctx, p, &hGroup),
		"failed to query group id");
	torture_assert(tctx,
		test_GetGroupState_int(tctx, p, &hGroup),
		"failed to query group id");

	test_CloseGroup_int(tctx, p, &hGroup);

	return true;
}

static bool test_all_groups(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_GROUP;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateEnum failed");

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_GROUP, "type mismatch");

		torture_assert(tctx,
			test_one_group(tctx, p, e.Name),
			"failed to test one group");
	}

	return true;
}

static bool test_BackupClusterDatabase(struct torture_context *tctx,
				       struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_BackupClusterDatabase r;
	WERROR rpc_status;

	r.in.lpszPathName = "c:\\cluster_backup";
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_BackupClusterDatabase_r(b, tctx, &r),
		"BackupClusterDatabase failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_CALL_NOT_IMPLEMENTED,
		"BackupClusterDatabase failed");

	return true;
}

static bool test_SetServiceAccountPassword(struct torture_context *tctx,
					   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_SetServiceAccountPassword r;
	uint32_t SizeReturned;
	uint32_t ExpectedBufferSize;

	r.in.lpszNewPassword = "P@ssw0rd!";
	r.in.dwFlags = IDL_CLUSTER_SET_PASSWORD_IGNORE_DOWN_NODES;
	r.in.ReturnStatusBufferSize = 1024;
	r.out.ReturnStatusBufferPtr = NULL;
	r.out.SizeReturned = &SizeReturned;
	r.out.ExpectedBufferSize = &ExpectedBufferSize;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_SetServiceAccountPassword_r(b, tctx, &r),
		"SetServiceAccountPassword failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_CALL_NOT_IMPLEMENTED,
		"SetServiceAccountPassword failed");

	return true;
}

static bool test_OpenNetwork_int(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 const char *lpszNetworkName,
				 struct policy_handle *hNetwork)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNetwork r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNetworkName = lpszNetworkName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNetwork = hNetwork ;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNetwork_r(b, tctx, &r),
		"OpenNetwork failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNetwork failed");

	return true;
}

static bool test_OpenNetworkEx_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   const char *lpszNetworkName,
				   struct policy_handle *hNetwork)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNetworkEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNetworkName = lpszNetworkName;
	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNetwork = hNetwork ;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNetworkEx_r(b, tctx, &r),
		"OpenNetworkEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNetworkEx failed");

	return true;
}

static bool test_CloseNetwork_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *Network)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseNetwork r;

	r.in.Network = Network;
	r.out.Network = Network;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseNetwork_r(b, tctx, &r),
		"CloseNetwork failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseNetwork failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(Network),
		"policy_handle non empty after CloseNetwork");

	return true;
}

static bool test_OpenNetwork(struct torture_context *tctx,
			     struct dcerpc_pipe *p)
{
	struct policy_handle hNetwork;

	if (!test_OpenNetwork_int(tctx, p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	test_CloseNetwork_int(tctx, p, &hNetwork);

	return true;
}

static bool test_OpenNetworkEx(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	struct policy_handle hNetwork;

	if (!test_OpenNetworkEx_int(tctx, p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	test_CloseNetwork_int(tctx, p, &hNetwork);

	return true;
}

static bool test_CloseNetwork(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hNetwork;

	if (!test_OpenNetwork_int(tctx, p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	return test_CloseNetwork_int(tctx, p, &hNetwork);
}

static bool test_GetNetworkState_int(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     struct policy_handle *hNetwork)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNetworkState r;
	enum clusapi_ClusterNetworkState State;
	WERROR rpc_status;

	r.in.hNetwork = *hNetwork;
	r.out.State = &State;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNetworkState_r(b, tctx, &r),
		"GetNetworkState failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNetworkState failed");

	return true;
}

static bool test_GetNetworkState(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	struct policy_handle hNetwork;
	bool ret = true;

	if (!test_OpenNetwork_int(tctx, p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	ret = test_GetNetworkState_int(tctx, p, &hNetwork);

	test_CloseNetwork_int(tctx, p, &hNetwork);

	return ret;
}

static bool test_GetNetworkId_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hNetwork)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNetworkId r;
	const char *pGuid;
	WERROR rpc_status;

	r.in.hNetwork = *hNetwork;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNetworkId_r(b, tctx, &r),
		"GetNetworkId failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNetworkId failed");

	return true;
}

static bool test_GetNetworkId(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct policy_handle hNetwork;
	bool ret = true;

	if (!test_OpenNetwork_int(tctx, p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	ret = test_GetNetworkId_int(tctx, p, &hNetwork);

	test_CloseNetwork_int(tctx, p, &hNetwork);

	return ret;
}

static bool test_one_network(struct torture_context *tctx,
			     struct dcerpc_pipe *p,
			     const char *network_name)
{
	struct policy_handle hNetwork;

	torture_assert(tctx,
		test_OpenNetwork_int(tctx, p, network_name, &hNetwork),
		"failed to open network");
	test_CloseNetwork_int(tctx, p, &hNetwork);

	torture_assert(tctx,
		test_OpenNetworkEx_int(tctx, p, network_name, &hNetwork),
		"failed to openex network");

	torture_assert(tctx,
		test_GetNetworkId_int(tctx, p, &hNetwork),
		"failed to query network id");
	torture_assert(tctx,
		test_GetNetworkState_int(tctx, p, &hNetwork),
		"failed to query network id");

	test_CloseNetwork_int(tctx, p, &hNetwork);

	return true;
}

static bool test_all_networks(struct torture_context *tctx,
			      struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_NETWORK;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateEnum failed");

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_NETWORK, "type mismatch");

		torture_assert(tctx,
			test_one_network(tctx, p, e.Name),
			"failed to test one network");
	}

	return true;
}

static bool test_OpenNetInterface_int(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      const char *lpszNetInterfaceName,
				      struct policy_handle *hNetInterface)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNetInterface r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNetInterfaceName = lpszNetInterfaceName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNetInterface = hNetInterface;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNetInterface_r(b, tctx, &r),
		"OpenNetInterface failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNetInterface failed");

	return true;
}

static bool test_OpenNetInterfaceEx_int(struct torture_context *tctx,
					struct dcerpc_pipe *p,
					const char *lpszNetInterfaceName,
					struct policy_handle *hNetInterface)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenNetInterfaceEx r;
	uint32_t lpdwGrantedAccess;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszNetInterfaceName = lpszNetInterfaceName;
	r.in.dwDesiredAccess = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.lpdwGrantedAccess = &lpdwGrantedAccess;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hNetInterface = hNetInterface;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenNetInterfaceEx_r(b, tctx, &r),
		"OpenNetInterfaceEx failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenNetInterfaceEx failed");

	return true;
}

static bool test_CloseNetInterface_int(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       struct policy_handle *NetInterface)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseNetInterface r;

	r.in.NetInterface = NetInterface;
	r.out.NetInterface = NetInterface;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseNetInterface_r(b, tctx, &r),
		"CloseNetInterface failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseNetInterface failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(NetInterface),
		"policy_handle non empty after CloseNetInterface");

	return true;
}

static bool test_OpenNetInterface(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterface_int(tctx, p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	return true;
}

static bool test_OpenNetInterfaceEx(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterfaceEx_int(tctx, p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	return true;
}

static bool test_CloseNetInterface(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterface_int(tctx, p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	return test_CloseNetInterface_int(tctx, p, &hNetInterface);
}

static bool test_GetNetInterfaceState_int(struct torture_context *tctx,
					  struct dcerpc_pipe *p,
					  struct policy_handle *hNetInterface)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNetInterfaceState r;
	enum clusapi_ClusterNetInterfaceState State;
	WERROR rpc_status;

	r.in.hNetInterface = *hNetInterface;
	r.out.State = &State;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNetInterfaceState_r(b, tctx, &r),
		"GetNetInterfaceState failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNetInterfaceState failed");

	return true;
}

static bool test_GetNetInterfaceState(struct torture_context *tctx,
				      struct dcerpc_pipe *p)
{
	struct policy_handle hNetInterface;
	bool ret = true;

	if (!test_OpenNetInterface_int(tctx, p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	ret = test_GetNetInterfaceState_int(tctx, p, &hNetInterface);

	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	return ret;
}

static bool test_GetNetInterfaceId_int(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       struct policy_handle *hNetInterface)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetNetInterfaceId r;
	const char *pGuid;
	WERROR rpc_status;

	r.in.hNetInterface = *hNetInterface;
	r.out.pGuid = &pGuid;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetNetInterfaceId_r(b, tctx, &r),
		"GetNetInterfaceId failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetNetInterfaceId failed");

	return true;
}

static bool test_GetNetInterfaceId(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct policy_handle hNetInterface;
	bool ret = true;

	if (!test_OpenNetInterface_int(tctx, p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	ret = test_GetNetInterfaceId_int(tctx, p, &hNetInterface);

	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	return ret;
}

static bool test_one_netinterface(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  const char *netinterface_name)
{
	struct policy_handle hNetInterface;

	torture_assert(tctx,
		test_OpenNetInterface_int(tctx, p, netinterface_name, &hNetInterface),
		"failed to open netinterface");
	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	torture_assert(tctx,
		test_OpenNetInterfaceEx_int(tctx, p, netinterface_name, &hNetInterface),
		"failed to openex netinterface");

	torture_assert(tctx,
		test_GetNetInterfaceId_int(tctx, p, &hNetInterface),
		"failed to query netinterface id");
	torture_assert(tctx,
		test_GetNetInterfaceState_int(tctx, p, &hNetInterface),
		"failed to query netinterface id");

	test_CloseNetInterface_int(tctx, p, &hNetInterface);

	return true;
}

static bool test_all_netinterfaces(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_NETINTERFACE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
		"CreateEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateEnum failed");

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_NETINTERFACE, "type mismatch");

		torture_assert(tctx,
			test_one_netinterface(tctx, p, e.Name),
			"failed to test one netinterface");
	}

	return true;
}

struct torture_suite *torture_rpc_clusapi(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "clusapi");
	struct torture_test *test;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "cluster",
						  &ndr_table_clusapi);

	torture_rpc_tcase_add_test(tcase, "OpenCluster",
				   test_OpenCluster);
	torture_rpc_tcase_add_test(tcase, "OpenClusterEx",
				   test_OpenClusterEx);
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
	torture_rpc_tcase_add_test(tcase, "GetClusterVersion2",
				   test_GetClusterVersion2);
	torture_rpc_tcase_add_test(tcase, "CreateResEnum",
				   test_CreateResEnum);
	torture_rpc_tcase_add_test(tcase, "BackupClusterDatabase",
				   test_BackupClusterDatabase);
	torture_rpc_tcase_add_test(tcase, "SetServiceAccountPassword",
				   test_SetServiceAccountPassword);
	torture_rpc_tcase_add_test(tcase, "all_resources",
				   test_all_resources);

	tcase = torture_suite_add_rpc_iface_tcase(suite, "resource",
						  &ndr_table_clusapi);

	torture_rpc_tcase_add_test(tcase, "GetQuorumResource",
				   test_GetQuorumResource);
	torture_rpc_tcase_add_test(tcase, "SetQuorumResource",
				   test_SetQuorumResource);
	torture_rpc_tcase_add_test(tcase, "OpenResource",
				   test_OpenResource);
	torture_rpc_tcase_add_test(tcase, "OpenResourceEx",
				   test_OpenResourceEx);
	torture_rpc_tcase_add_test(tcase, "CloseResource",
				   test_CloseResource);
	torture_rpc_tcase_add_test(tcase, "CreateResource",
				   test_CreateResource);
	torture_rpc_tcase_add_test(tcase, "DeleteResource",
				   test_DeleteResource);
	torture_rpc_tcase_add_test(tcase, "SetResourceName",
				   test_SetResourceName);
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

	tcase = torture_suite_add_rpc_iface_tcase(suite, "node",
						  &ndr_table_clusapi);

	torture_rpc_tcase_add_test(tcase, "OpenNode",
				   test_OpenNode);
	torture_rpc_tcase_add_test(tcase, "OpenNodeEx",
				   test_OpenNodeEx);
	torture_rpc_tcase_add_test(tcase, "CloseNode",
				   test_CloseNode);
	torture_rpc_tcase_add_test(tcase, "GetNodeState",
				   test_GetNodeState);
	torture_rpc_tcase_add_test(tcase, "GetNodeId",
				   test_GetNodeId);
	test = torture_rpc_tcase_add_test(tcase, "PauseNode",
					  test_PauseNode);
	test->dangerous = true;
	torture_rpc_tcase_add_test(tcase, "ResumeNode",
				   test_ResumeNode);
	test = torture_rpc_tcase_add_test(tcase, "EvictNode",
					  test_EvictNode);
	test->dangerous = true;
	torture_rpc_tcase_add_test(tcase, "all_nodes",
				   test_all_nodes);

	tcase = torture_suite_add_rpc_iface_tcase(suite, "group",
						  &ndr_table_clusapi);

	torture_rpc_tcase_add_test(tcase, "OpenGroup",
				   test_OpenGroup);
	torture_rpc_tcase_add_test(tcase, "OpenGroupEx",
				   test_OpenGroupEx);
	torture_rpc_tcase_add_test(tcase, "CloseGroup",
				   test_CloseGroup);
	torture_rpc_tcase_add_test(tcase, "GetGroupState",
				   test_GetGroupState);
	torture_rpc_tcase_add_test(tcase, "GetGroupId",
				   test_GetGroupId);
	torture_rpc_tcase_add_test(tcase, "OnlineGroup",
				   test_OnlineGroup);
	test = torture_rpc_tcase_add_test(tcase, "OfflineGroup",
				   test_OfflineGroup);
	test->dangerous = true;
	torture_rpc_tcase_add_test(tcase, "all_groups",
				   test_all_groups);

	tcase = torture_suite_add_rpc_iface_tcase(suite, "network",
						  &ndr_table_clusapi);
	torture_rpc_tcase_add_test(tcase, "OpenNetwork",
				   test_OpenNetwork);
	torture_rpc_tcase_add_test(tcase, "OpenNetworkEx",
				   test_OpenNetworkEx);
	torture_rpc_tcase_add_test(tcase, "CloseNetwork",
				   test_CloseNetwork);
	torture_rpc_tcase_add_test(tcase, "GetNetworkState",
				   test_GetNetworkState);
	torture_rpc_tcase_add_test(tcase, "GetNetworkId",
				   test_GetNetworkId);
	torture_rpc_tcase_add_test(tcase, "all_networks",
				   test_all_networks);

	tcase = torture_suite_add_rpc_iface_tcase(suite, "netinterface",
						  &ndr_table_clusapi);
	torture_rpc_tcase_add_test(tcase, "OpenNetInterface",
				   test_OpenNetInterface);
	torture_rpc_tcase_add_test(tcase, "OpenNetInterfaceEx",
				   test_OpenNetInterfaceEx);
	torture_rpc_tcase_add_test(tcase, "CloseNetInterface",
				   test_CloseNetInterface);
	torture_rpc_tcase_add_test(tcase, "GetNetInterfaceState",
				   test_GetNetInterfaceState);
	torture_rpc_tcase_add_test(tcase, "GetNetInterfaceId",
				   test_GetNetInterfaceId);
	torture_rpc_tcase_add_test(tcase, "all_netinterfaces",
				   test_all_netinterfaces);

	return suite;
}

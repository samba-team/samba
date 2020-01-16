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
#include "libcli/registry/util_reg.h"

struct torture_clusapi_context {
	struct dcerpc_pipe *p;
	const char *NodeName;
	const char *ClusterName;
	uint16_t lpwMajorVersion;
	uint16_t lpwMinorVersion;
	uint16_t lpwBuildNumber;
};

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
			     void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	test_CloseCluster_int(tctx, t->p, &Cluster);

	return true;
}

static bool test_OpenClusterEx(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;

	if (!test_OpenClusterEx_int(tctx, t->p, &Cluster)) {
		return false;
	}

	test_CloseCluster_int(tctx, t->p, &Cluster);

	return true;
}

static bool test_CloseCluster(struct torture_context *tctx,
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	return test_CloseCluster_int(tctx, t->p, &Cluster);
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
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct clusapi_SetClusterName r;
	const char *NewClusterName;
	WERROR rpc_status;

	torture_assert(tctx,
		test_GetClusterName_int(tctx, t->p, &NewClusterName),
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
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	const char *ClusterName;

	return test_GetClusterName_int(tctx, t->p, &ClusterName);
}

static bool test_GetClusterVersion(struct torture_context *tctx,
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
				    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType[] = {
		CLUSTER_ENUM_NODE,
		CLUSTER_ENUM_RESTYPE,
		CLUSTER_ENUM_RESOURCE,
		CLUSTER_ENUM_GROUP,
		CLUSTER_ENUM_NETWORK,
		CLUSTER_ENUM_NETINTERFACE,
		CLUSTER_ENUM_INTERNAL_NETWORK,
		CLUSTER_ENUM_SHARED_VOLUME_RESOURCE
	};
	uint32_t dwType_invalid[] = {
		0x00000040,
		0x00000080,
		0x00000100 /* and many more ... */
	};
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	for (i=0; i < ARRAY_SIZE(dwType); i++) {

		r.in.dwType = dwType[i];
		r.out.ReturnEnum = &ReturnEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
			"CreateEnum failed");
		torture_assert_werr_ok(tctx,
			r.out.result,
			"CreateEnum failed");
	}

	for (i=0; i < ARRAY_SIZE(dwType_invalid); i++) {

		r.in.dwType = dwType_invalid[i];
		r.out.ReturnEnum = &ReturnEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateEnum_r(b, tctx, &r),
			"CreateEnum failed");
		torture_assert_werr_equal(tctx,
			r.out.result,
			WERR_INVALID_PARAMETER,
			"CreateEnum failed");
	}

	return true;
}

static bool test_CreateEnumEx_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *Cluster)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateEnumEx r;
	uint32_t dwType[] = {
		CLUSTER_ENUM_NODE,
		CLUSTER_ENUM_RESTYPE,
		CLUSTER_ENUM_RESOURCE,
		CLUSTER_ENUM_GROUP,
		CLUSTER_ENUM_NETWORK,
		CLUSTER_ENUM_NETINTERFACE,
		CLUSTER_ENUM_INTERNAL_NETWORK,
		CLUSTER_ENUM_SHARED_VOLUME_RESOURCE
	};
	uint32_t dwType_invalid[] = {
		0x00000040,
		0x00000080,
		0x00000100 /* and many more ... */
	};
	struct ENUM_LIST *ReturnIdEnum;
	struct ENUM_LIST *ReturnNameEnum;
	WERROR rpc_status;
	int i;

	for (i=0; i < ARRAY_SIZE(dwType); i++) {

		r.in.hCluster = *Cluster;
		r.in.dwType = dwType[i];
		r.in.dwOptions = 0;
		r.out.ReturnIdEnum = &ReturnIdEnum;
		r.out.ReturnNameEnum = &ReturnNameEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateEnumEx_r(b, tctx, &r),
			"CreateEnumEx failed");
		torture_assert_werr_ok(tctx,
			r.out.result,
			"CreateEnumEx failed");
	}

	for (i=0; i < ARRAY_SIZE(dwType_invalid); i++) {

		r.in.hCluster = *Cluster;
		r.in.dwType = dwType_invalid[i];
		r.in.dwOptions = 0;
		r.out.ReturnIdEnum = &ReturnIdEnum;
		r.out.ReturnNameEnum = &ReturnNameEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateEnumEx_r(b, tctx, &r),
			"CreateEnumEx failed");
		torture_assert_werr_equal(tctx,
			r.out.result,
			WERR_INVALID_PARAMETER,
			"CreateEnumEx failed");
	}

	return true;
}

static bool test_CreateEnumEx(struct torture_context *tctx,
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;
	bool ret;

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	ret = test_CreateEnumEx_int(tctx, t->p, &Cluster);

	test_CloseCluster_int(tctx, t->p, &Cluster);

	return ret;
}


static bool test_GetQuorumResource(struct torture_context *tctx,
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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

static bool test_OpenResource_int_exp(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      const char *lpszResourceName,
				      struct policy_handle *hResource,
				      WERROR expected_Status,
				      WERROR expected_rpc_status)
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
	torture_assert_werr_equal(tctx,
		*r.out.Status, expected_Status,
		"OpenResource failed");
	torture_assert_werr_equal(tctx,
		*r.out.rpc_status, expected_rpc_status,
		"OpenResource failed");

	return true;
}

bool test_OpenResource_int(struct torture_context *tctx,
			   struct dcerpc_pipe *p,
			   const char *lpszResourceName,
			   struct policy_handle *hResource)
{
	return test_OpenResource_int_exp(tctx, p,
					 lpszResourceName,
					 hResource,
					 WERR_OK, WERR_OK);
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

bool test_CloseResource_int(struct torture_context *tctx,
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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	test_CloseResource_int(tctx, t->p, &hResource);

	if (!test_OpenResource_int_exp(tctx, t->p, "", &hResource, WERR_RESOURCE_NOT_FOUND, WERR_OK)) {
		return false;
	}

	torture_assert(tctx,
		ndr_policy_handle_empty(&hResource),
		"expected empty policy handle");

	if (!test_OpenResource_int_exp(tctx, t->p, "jfUF38fjSNcfn", &hResource, WERR_RESOURCE_NOT_FOUND, WERR_OK)) {
		return false;
	}

	torture_assert(tctx,
		ndr_policy_handle_empty(&hResource),
		"expected empty policy handle");

	return true;
}

static bool test_OpenResourceEx(struct torture_context *tctx,
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;

	if (!test_OpenResourceEx_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	test_CloseResource_int(tctx, t->p, &hResource);

	return true;
}


static bool test_CloseResource(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	return test_CloseResource_int(tctx, t->p, &hResource);
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
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;

	if (!test_CreateResource_int(tctx, t->p, &hResource)) {
		return false;
	}

	test_DeleteResource_int(tctx, t->p, &hResource);

	return true;
}

static bool test_DeleteResource(struct torture_context *tctx,
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;

	if (!test_CreateResource_int(tctx, t->p, &hResource)) {
		return false;
	}

	return test_DeleteResource_int(tctx, t->p, &hResource);
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
				 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_CreateResource_int(tctx, t->p, &hResource)) {
		return false;
	}

	ret = test_SetResourceName_int(tctx, t->p, &hResource);

	test_DeleteResource_int(tctx, t->p, &hResource);

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
				  void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_GetResourceState_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

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
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_GetResourceId_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

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
				 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_GetResourceType_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_FailResource_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

bool test_OnlineResource_int(struct torture_context *tctx,
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
	if (!W_ERROR_IS_OK(r.out.result) &&
	    !W_ERROR_EQUAL(r.out.result, WERR_IO_PENDING)) {
		torture_result(tctx, TORTURE_FAIL,
			       "OnlineResource failed with %s",
			        win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_OnlineResource(struct torture_context *tctx,
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_OnlineResource_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

bool test_OfflineResource_int(struct torture_context *tctx,
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
	if (!W_ERROR_IS_OK(r.out.result) &&
	    !W_ERROR_EQUAL(r.out.result, WERR_IO_PENDING)) {
		torture_result(tctx, TORTURE_FAIL,
			       "OfflineResource failed with %s",
			       win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_OfflineResource(struct torture_context *tctx,
				 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_OfflineResource_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

static bool test_CreateResEnum_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateResEnum r;
	uint32_t dwType = CLUSTER_ENUM_RESOURCE;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.in.dwType = dwType;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateResEnum_r(b, tctx, &r),
		"CreateResEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateResEnum failed");

	return true;
}

static bool test_CreateResEnum(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_CreateResEnum_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

static bool test_GetResourceDependencyExpression_int(struct torture_context *tctx,
						     struct dcerpc_pipe *p,
						     struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceDependencyExpression r;
	const char *lpszDependencyExpression;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.lpszDependencyExpression = &lpszDependencyExpression;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceDependencyExpression_r(b, tctx, &r),
		"GetResourceDependencyExpression failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetResourceDependencyExpression failed");

	return true;
}

static bool test_GetResourceDependencyExpression(struct torture_context *tctx,
						 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Cluster Name", &hResource)) {
		return false;
	}

	ret = test_GetResourceDependencyExpression_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

static bool test_GetResourceNetworkName_int(struct torture_context *tctx,
					    struct dcerpc_pipe *p,
					    struct policy_handle *hResource)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetResourceNetworkName r;
	const char *lpszName;
	WERROR rpc_status;

	r.in.hResource = *hResource;
	r.out.lpszName = &lpszName;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetResourceNetworkName_r(b, tctx, &r),
		"GetResourceNetworkName failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetResourceNetworkName failed");

	return true;
}

static bool test_GetResourceNetworkName(struct torture_context *tctx,
					void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hResource;
	bool ret = true;

	if (!test_OpenResource_int(tctx, t->p, "Network Name", &hResource)) {
		return false;
	}

	ret = test_GetResourceNetworkName_int(tctx, t->p, &hResource);

	test_CloseResource_int(tctx, t->p, &hResource);

	return ret;
}

static bool test_ResourceTypeControl_int(struct torture_context *tctx,
					 struct dcerpc_pipe *p,
					 struct policy_handle *Cluster,
					 const char *resource_type,
					 enum clusapi_ResourceTypeControlCode dwControlCode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_ResourceTypeControl r;
	uint32_t lpBytesReturned;
	uint32_t lpcbRequired;
	WERROR rpc_status;

	r.in.hCluster = *Cluster;
	r.in.lpszResourceTypeName = resource_type;
	r.in.dwControlCode = 0;
	r.in.lpInBuffer = NULL;
	r.in.nInBufferSize = 0;
	r.in.nOutBufferSize = 0;
	r.out.lpOutBuffer = NULL;
	r.out.lpBytesReturned = &lpBytesReturned;
	r.out.lpcbRequired = &lpcbRequired;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ResourceTypeControl_r(b, tctx, &r),
		"ResourceTypeControl failed");

	if (strequal(r.in.lpszResourceTypeName, "MSMQ") ||
	    strequal(r.in.lpszResourceTypeName, "MSMQTriggers")) {
		torture_assert_werr_equal(tctx,
			r.out.result,
			WERR_CLUSTER_RESTYPE_NOT_SUPPORTED,
			"ResourceTypeControl failed");
		return true;
	}

	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_INVALID_FUNCTION,
		"ResourceTypeControl failed");

	r.in.dwControlCode = dwControlCode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ResourceTypeControl_r(b, tctx, &r),
		"ResourceTypeControl failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, *r.out.lpcbRequired);
		r.in.nOutBufferSize = *r.out.lpcbRequired;
		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_ResourceTypeControl_r(b, tctx, &r),
			"ResourceTypeControl failed");
	}
	torture_assert_werr_ok(tctx,
		r.out.result,
		"ResourceTypeControl failed");

	/* now try what happens when we query with a buffer large enough to hold
	 * the entire packet */

	r.in.nOutBufferSize = 0x4000;
	r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, r.in.nOutBufferSize);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ResourceTypeControl_r(b, tctx, &r),
		"ResourceTypeControl failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"ResourceTypeControl failed");
	torture_assert(tctx, *r.out.lpBytesReturned < r.in.nOutBufferSize,
		"lpBytesReturned expected to be smaller than input size nOutBufferSize");

	return true;
}

static bool test_ResourceTypeControl(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     const char *resourcetype_name)
{
	struct policy_handle Cluster;
	bool ret;
	uint32_t control_codes[] = {
		CLUSCTL_RESOURCE_TYPE_GET_CLASS_INFO,
		CLUSCTL_RESOURCE_TYPE_GET_CHARACTERISTICS,
		CLUSCTL_RESOURCE_TYPE_GET_COMMON_PROPERTIES,
		CLUSCTL_RESOURCE_TYPE_GET_RO_COMMON_PROPERTIES,
		CLUSCTL_RESOURCE_TYPE_GET_PRIVATE_PROPERTIES
	};
	int i;

	if (!test_OpenCluster_int(tctx, p, &Cluster)) {
		return false;
	}

	for (i=0; i < ARRAY_SIZE(control_codes); i++) {
		ret = test_ResourceTypeControl_int(tctx, p, &Cluster,
						   resourcetype_name,
						   control_codes[i]);
		if (!ret) {
			goto done;
		}
	}

 done:
	test_CloseCluster_int(tctx, p, &Cluster);

	return ret;
}



static bool test_one_resourcetype(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  const char *resourcetype_name)
{
	torture_assert(tctx,
		test_ResourceTypeControl(tctx, p, resourcetype_name),
		"failed to query ResourceTypeControl");

	return true;
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
		"failed to query resource state");
	torture_assert(tctx,
		test_CreateResEnum_int(tctx, p, &hResource),
		"failed to query resource enum");
	torture_assert(tctx,
		test_GetResourceDependencyExpression_int(tctx, p, &hResource),
		"failed to query resource dependency expression");
	torture_assert(tctx,
		test_GetResourceNetworkName_int(tctx, p, &hResource),
		"failed to query resource network name");

	test_CloseResource_int(tctx, p, &hResource);

	return true;
}

static bool test_all_resources(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			test_one_resource(tctx, t->p, e.Name),
			"failed to test one resource");
	}

	return true;
}

static bool test_all_resourcetypes(struct torture_context *tctx,
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct clusapi_CreateEnum r;
	uint32_t dwType = CLUSTER_ENUM_RESTYPE;
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

		torture_assert_int_equal(tctx, e.Type, CLUSTER_ENUM_RESTYPE, "type mismatch");

		torture_assert(tctx,
			test_one_resourcetype(tctx, t->p, e.Name),
			"failed to test one resourcetype");
	}

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
			  void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	test_CloseNode_int(tctx, t->p, &hNode);

	return true;
}

static bool test_OpenNodeEx(struct torture_context *tctx,
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;

	if (!test_OpenNodeEx_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	test_CloseNode_int(tctx, t->p, &hNode);

	return true;
}

static bool test_CloseNode(struct torture_context *tctx,
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	return test_CloseNode_int(tctx, t->p, &hNode);
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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_GetNodeState_int(tctx, t->p, &hNode);

	test_CloseNode_int(tctx, t->p, &hNode);

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
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_GetNodeId_int(tctx, t->p, &hNode);

	test_CloseNode_int(tctx, t->p, &hNode);

	return ret;
}

static bool test_NodeControl_int(struct torture_context *tctx,
				 struct dcerpc_pipe *p,
				 struct policy_handle *hNode,
				 enum clusapi_NodeControlCode dwControlCode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_NodeControl r;
	uint32_t lpBytesReturned;
	uint32_t lpcbRequired;
	WERROR rpc_status;

	r.in.hNode = *hNode;
	r.in.dwControlCode = 0;
	r.in.lpInBuffer = NULL;
	r.in.nInBufferSize = 0;
	r.in.nOutBufferSize = 0;
	r.out.lpOutBuffer = NULL;
	r.out.lpBytesReturned = &lpBytesReturned;
	r.out.lpcbRequired = &lpcbRequired;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_NodeControl_r(b, tctx, &r),
		"NodeControl failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_INVALID_FUNCTION,
		"NodeControl failed");

	r.in.dwControlCode = dwControlCode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_NodeControl_r(b, tctx, &r),
		"NodeControl failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, *r.out.lpcbRequired);
		r.in.nOutBufferSize = *r.out.lpcbRequired;
		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_NodeControl_r(b, tctx, &r),
			"NodeControl failed");
	}
	torture_assert_werr_ok(tctx,
		r.out.result,
		"NodeControl failed");

	/* now try what happens when we query with a buffer large enough to hold
	 * the entire packet */

	r.in.nOutBufferSize = 0x4000;
	r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, r.in.nOutBufferSize);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_NodeControl_r(b, tctx, &r),
		"NodeControl failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"NodeControl failed");
	torture_assert(tctx, *r.out.lpBytesReturned < r.in.nOutBufferSize,
		"lpBytesReturned expected to be smaller than input size nOutBufferSize");

	if (dwControlCode == CLUSCTL_NODE_GET_ID) {
		const char *str;
		DATA_BLOB blob = data_blob_const(r.out.lpOutBuffer, *r.out.lpBytesReturned);

		torture_assert(tctx, *r.out.lpBytesReturned >= 4, "must be at least 4 bytes long");
		torture_assert(tctx, (*r.out.lpBytesReturned % 2) == 0, "must be a multiple of 2");

		torture_assert(tctx,
			pull_reg_sz(tctx, &blob, &str),
			"failed to pull unicode string");

		torture_comment(tctx, "got this node id: '%s'", str);
	}

	return true;
}

static bool test_NodeControl(struct torture_context *tctx,
			     void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_NodeControl_int(tctx, t->p, &hNode, CLUSCTL_NODE_GET_RO_COMMON_PROPERTIES);
	if (!ret) {
		return false;
	}

	ret = test_NodeControl_int(tctx, t->p, &hNode, CLUSCTL_NODE_GET_ID);
	if (!ret) {
		return false;
	}

	test_CloseNode_int(tctx, t->p, &hNode);

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
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_PauseNode_int(tctx, t->p, &hNode);

	test_CloseNode_int(tctx, t->p, &hNode);

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
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_ResumeNode_int(tctx, t->p, &hNode);

	test_CloseNode_int(tctx, t->p, &hNode);

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
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNode;
	bool ret = true;

	if (!test_OpenNode_int(tctx, t->p, t->NodeName, &hNode)) {
		return false;
	}

	ret = test_EvictNode_int(tctx, t->p, &hNode);

	test_CloseNode_int(tctx, t->p, &hNode);

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
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			test_one_node(tctx, t->p, e.Name),
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
			   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	test_CloseGroup_int(tctx, t->p, &hGroup);

	return true;
}

static bool test_OpenGroupEx(struct torture_context *tctx,
			     void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;

	if (!test_OpenGroupEx_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	test_CloseGroup_int(tctx, t->p, &hGroup);

	return true;
}

static bool test_CloseGroup(struct torture_context *tctx,
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	return test_CloseGroup_int(tctx, t->p, &hGroup);
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
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_GetGroupState_int(tctx, t->p, &hGroup);

	test_CloseGroup_int(tctx, t->p, &hGroup);

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
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_GetGroupId_int(tctx, t->p, &hGroup);

	test_CloseGroup_int(tctx, t->p, &hGroup);

	return ret;
}

static bool test_GroupControl_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hGroup,
				  enum clusapi_GroupControlCode dwControlCode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GroupControl r;
	uint32_t lpBytesReturned;
	uint32_t lpcbRequired;
	WERROR rpc_status;

	r.in.hGroup = *hGroup;
	r.in.dwControlCode = 0;
	r.in.lpInBuffer = NULL;
	r.in.nInBufferSize = 0;
	r.in.nOutBufferSize = 0;
	r.out.lpOutBuffer = NULL;
	r.out.lpBytesReturned = &lpBytesReturned;
	r.out.lpcbRequired = &lpcbRequired;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GroupControl_r(b, tctx, &r),
		"GroupControl failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_INVALID_FUNCTION,
		"GroupControl failed");

	r.in.dwControlCode = dwControlCode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GroupControl_r(b, tctx, &r),
		"GroupControl failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, *r.out.lpcbRequired);
		r.in.nOutBufferSize = *r.out.lpcbRequired;
		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_GroupControl_r(b, tctx, &r),
			"GroupControl failed");
	}
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GroupControl failed");

	/* now try what happens when we query with a buffer large enough to hold
	 * the entire packet */

	r.in.nOutBufferSize = 0x400;
	r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, r.in.nOutBufferSize);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GroupControl_r(b, tctx, &r),
		"GroupControl failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"GroupControl failed");
	torture_assert(tctx, *r.out.lpBytesReturned < r.in.nOutBufferSize,
		"lpBytesReturned expected to be smaller than input size nOutBufferSize");

	return true;
}

static bool test_CreateGroupResourceEnum_int(struct torture_context *tctx,
					     struct dcerpc_pipe *p,
					     struct policy_handle *hGroup)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateGroupResourceEnum r;
	uint32_t dwType[] = {
		CLUSTER_GROUP_ENUM_CONTAINS,
		CLUSTER_GROUP_ENUM_NODES
	};
	uint32_t dwType_invalid[] = {
		0x00000040,
		0x00000080,
		0x00000100 /* and many more ... */
	};
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i;

	r.in.hGroup = *hGroup;

	for (i=0; i < ARRAY_SIZE(dwType); i++) {

		r.in.hGroup = *hGroup;
		r.in.dwType = dwType[i];
		r.out.ReturnEnum = &ReturnEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateGroupResourceEnum_r(b, tctx, &r),
			"CreateGroupResourceEnum failed");
		torture_assert_werr_ok(tctx,
			r.out.result,
			"CreateGroupResourceEnum failed");
	}

	for (i=0; i < ARRAY_SIZE(dwType_invalid); i++) {

		r.in.dwType = dwType_invalid[i];
		r.out.ReturnEnum = &ReturnEnum;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_CreateGroupResourceEnum_r(b, tctx, &r),
			"CreateGroupResourceEnum failed");
		torture_assert_werr_ok(tctx,
			r.out.result,
			"CreateGroupResourceEnum failed");
	}

	return true;
}


static bool test_GroupControl(struct torture_context *tctx,
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_GroupControl_int(tctx, t->p, &hGroup, CLUSCTL_GROUP_GET_CHARACTERISTICS);
	if (!ret) {
		return false;
	}

	ret = test_GroupControl_int(tctx, t->p, &hGroup, CLUSCTL_GROUP_GET_RO_COMMON_PROPERTIES);
	if (!ret) {
		return false;
	}

	ret = test_GroupControl_int(tctx, t->p, &hGroup, CLUSCTL_GROUP_GET_FLAGS);
	if (!ret) {
		return false;
	}

	test_CloseGroup_int(tctx, t->p, &hGroup);

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
			     void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_OnlineGroup_int(tctx, t->p, &hGroup);

	test_CloseGroup_int(tctx, t->p, &hGroup);

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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroup;
	bool ret = true;

	if (!test_OpenGroup_int(tctx, t->p, "Cluster Group", &hGroup)) {
		return false;
	}

	ret = test_OfflineGroup_int(tctx, t->p, &hGroup);

	test_CloseGroup_int(tctx, t->p, &hGroup);

	return ret;
}

static bool test_one_group(struct torture_context *tctx,
			   struct dcerpc_pipe *p,
			   const char *group_name)
{
	struct policy_handle hGroup;

	torture_assert(tctx,
		test_OpenGroup_int(tctx, p, group_name, &hGroup),
		"failed to open group");
	test_CloseGroup_int(tctx, p, &hGroup);

	torture_assert(tctx,
		test_OpenGroupEx_int(tctx, p, group_name, &hGroup),
		"failed to openex group");

	torture_assert(tctx,
		test_GetGroupId_int(tctx, p, &hGroup),
		"failed to query group id");
	torture_assert(tctx,
		test_GetGroupState_int(tctx, p, &hGroup),
		"failed to query group id");

	torture_assert(tctx,
		test_GroupControl_int(tctx, p, &hGroup, CLUSCTL_GROUP_GET_FLAGS),
		"failed to query group control");

	torture_assert(tctx,
		test_CreateGroupResourceEnum_int(tctx, p, &hGroup),
		"failed to query resource enum");

	test_CloseGroup_int(tctx, p, &hGroup);

	return true;
}

static bool test_all_groups(struct torture_context *tctx,
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			test_one_group(tctx, t->p, e.Name),
			"failed to test one group");
	}

	return true;
}

static bool test_BackupClusterDatabase(struct torture_context *tctx,
				       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
					   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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

static bool test_ClusterControl_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *Cluster,
				    enum clusapi_ClusterControlCode dwControlCode)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_ClusterControl r;
	uint32_t lpBytesReturned;
	uint32_t lpcbRequired;
	WERROR rpc_status;

	r.in.hCluster = *Cluster;
	r.in.dwControlCode = 0;
	r.in.lpInBuffer = NULL;
	r.in.nInBufferSize = 0;
	r.in.nOutBufferSize = 0;
	r.out.lpOutBuffer = NULL;
	r.out.lpBytesReturned = &lpBytesReturned;
	r.out.lpcbRequired = &lpcbRequired;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ClusterControl_r(b, tctx, &r),
		"ClusterControl failed");
	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_INVALID_FUNCTION,
		"ClusterControl failed");

	r.in.dwControlCode = dwControlCode;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ClusterControl_r(b, tctx, &r),
		"ClusterControl failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, *r.out.lpcbRequired);
		r.in.nOutBufferSize = *r.out.lpcbRequired;
		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_ClusterControl_r(b, tctx, &r),
			"ClusterControl failed");
	}
	torture_assert_werr_ok(tctx,
		r.out.result,
		"ClusterControl failed");

	/* now try what happens when we query with a buffer large enough to hold
	 * the entire packet */

	r.in.nOutBufferSize = 0xffff;
	r.out.lpOutBuffer = talloc_zero_array(tctx, uint8_t, r.in.nOutBufferSize);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_ClusterControl_r(b, tctx, &r),
		"ClusterControl failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"ClusterControl failed");
	torture_assert(tctx, *r.out.lpBytesReturned < r.in.nOutBufferSize,
		"lpBytesReturned expected to be smaller than input size nOutBufferSize");

	return true;
}

static bool test_ClusterControl(struct torture_context *tctx,
				void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;
	bool ret;
	uint32_t control_codes[] = {
		CLUSCTL_CLUSTER_GET_COMMON_PROPERTIES,
		CLUSCTL_CLUSTER_GET_RO_COMMON_PROPERTIES,
		CLUSCTL_CLUSTER_GET_FQDN,
		CLUSCTL_CLUSTER_GET_PRIVATE_PROPERTIES,
		CLUSCTL_CLUSTER_CHECK_VOTER_DOWN
	};
	int i;

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	for (i=0; i < ARRAY_SIZE(control_codes); i++) {
		ret = test_ClusterControl_int(tctx, t->p, &Cluster,
					      control_codes[i]);
		if (!ret) {
			goto done;
		}
	}

 done:
	test_CloseCluster_int(tctx, t->p, &Cluster);

	return ret;
}

static bool test_CreateResTypeEnum(struct torture_context *tctx,
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct clusapi_CreateResTypeEnum r;
	uint32_t dwType[] = {
		CLUSTER_RESOURCE_TYPE_ENUM_NODES,
		CLUSTER_RESOURCE_TYPE_ENUM_RESOURCES
	};
	uint32_t dwType_invalid[] = {
		0x00000040,
		0x00000080,
		0x00000100 /* and many more ... */
	};
	const char *valid_names[] = {
		"Physical Disk",
		"Storage Pool"
	};
	const char *invalid_names[] = {
		"INVALID_TYPE_XXXX"
	};
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;
	int i, s;

	for (s = 0; s < ARRAY_SIZE(valid_names); s++) {

		r.in.lpszTypeName = valid_names[s];

		for (i=0; i < ARRAY_SIZE(dwType); i++) {

			r.in.dwType = dwType[i];
			r.out.ReturnEnum = &ReturnEnum;
			r.out.rpc_status = &rpc_status;

			torture_assert_ntstatus_ok(tctx,
				dcerpc_clusapi_CreateResTypeEnum_r(b, tctx, &r),
				"CreateResTypeEnum failed");
			torture_assert_werr_ok(tctx,
				r.out.result,
				"CreateResTypeEnum failed");
		}

		for (i=0; i < ARRAY_SIZE(dwType_invalid); i++) {

			r.in.dwType = dwType_invalid[i];
			r.out.ReturnEnum = &ReturnEnum;
			r.out.rpc_status = &rpc_status;

			torture_assert_ntstatus_ok(tctx,
				dcerpc_clusapi_CreateResTypeEnum_r(b, tctx, &r),
				"CreateResTypeEnum failed");
			torture_assert_werr_ok(tctx,
				r.out.result,
				"CreateResTypeEnum failed");
		}
	}

	for (s = 0; s < ARRAY_SIZE(invalid_names); s++) {

		r.in.lpszTypeName = invalid_names[s];

		for (i=0; i < ARRAY_SIZE(dwType); i++) {

			r.in.dwType = dwType[i];
			r.out.ReturnEnum = &ReturnEnum;
			r.out.rpc_status = &rpc_status;

			torture_assert_ntstatus_ok(tctx,
				dcerpc_clusapi_CreateResTypeEnum_r(b, tctx, &r),
				"CreateResTypeEnum failed");
			torture_assert_werr_equal(tctx,
				r.out.result,
				WERR_CLUSTER_RESOURCE_TYPE_NOT_FOUND,
				"CreateResTypeEnum failed");
		}

		for (i=0; i < ARRAY_SIZE(dwType_invalid); i++) {

			r.in.dwType = dwType_invalid[i];
			r.out.ReturnEnum = &ReturnEnum;
			r.out.rpc_status = &rpc_status;

			torture_assert_ntstatus_ok(tctx,
				dcerpc_clusapi_CreateResTypeEnum_r(b, tctx, &r),
				"CreateResTypeEnum failed");
			torture_assert_werr_equal(tctx,
				r.out.result,
				WERR_CLUSTER_RESOURCE_TYPE_NOT_FOUND,
				"CreateResTypeEnum failed");
		}
	}


	return true;
}

static bool test_CreateGroupEnum_int(struct torture_context *tctx,
				     struct dcerpc_pipe *p,
				     struct policy_handle *Cluster,
				     const char **multi_sz,
				     const char **multi_sz_ro)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CreateGroupEnum r;
	struct GROUP_ENUM_LIST *pResultList;
	WERROR rpc_status;
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB blob_ro = data_blob_null;

	r.in.hCluster = *Cluster;
	r.in.pProperties = blob.data;
	r.in.cbProperties = blob.length;
	r.in.pRoProperties = blob_ro.data;
	r.in.cbRoProperties = blob_ro.length;
	r.out.ppResultList = &pResultList;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateGroupEnum_r(b, tctx, &r),
		"CreateGroupEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateGroupEnum failed");

	if (!push_reg_multi_sz(tctx, &blob, multi_sz)) {
		return false;
	}

	if (!push_reg_multi_sz(tctx, &blob_ro, multi_sz_ro)) {
		return false;
	}

	r.in.pProperties = blob.data;
	r.in.cbProperties = blob.length;

	r.in.pRoProperties = blob_ro.data;
	r.in.cbRoProperties = blob_ro.length;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateGroupEnum_r(b, tctx, &r),
		"CreateGroupEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateGroupEnum failed");

#if 0
	{
		int i;
		enum ndr_err_code ndr_err;

		for (i=0; i < pResultList->EntryCount; i++) {
			struct clusapi_PROPERTY_LIST list;
			torture_comment(tctx, "entry #%d\n", i);

			blob = data_blob_const(pResultList->Entry[i].Properties,
					       pResultList->Entry[i].cbProperties);

			ndr_err = ndr_pull_struct_blob(&blob, tctx, &list,
				(ndr_pull_flags_fn_t)ndr_pull_clusapi_PROPERTY_LIST);
			if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				NDR_PRINT_DEBUG(clusapi_PROPERTY_LIST, &list);
			}

			blob_ro = data_blob_const(pResultList->Entry[i].RoProperties,
						  pResultList->Entry[i].cbRoProperties);

			ndr_err = ndr_pull_struct_blob(&blob_ro, tctx, &list,
				(ndr_pull_flags_fn_t)ndr_pull_clusapi_PROPERTY_LIST);
			if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				NDR_PRINT_DEBUG(clusapi_PROPERTY_LIST, &list);
			}
		}
	}
#endif

	return true;
}

static bool test_CreateGroupEnum(struct torture_context *tctx,
				 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle Cluster;
	bool ret;
	const char *multi_sz[] = {
		"Priority", NULL,
	};
	const char *multi_sz_ro[] = {
		"GroupType", NULL,
	};

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	ret = test_CreateGroupEnum_int(tctx, t->p, &Cluster,
				       multi_sz, multi_sz_ro);
	if (!ret) {
		goto done;
	}

 done:
	test_CloseCluster_int(tctx, t->p, &Cluster);

	return ret;
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
			     void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetwork;

	if (!test_OpenNetwork_int(tctx, t->p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	test_CloseNetwork_int(tctx, t->p, &hNetwork);

	return true;
}

static bool test_OpenNetworkEx(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetwork;

	if (!test_OpenNetworkEx_int(tctx, t->p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	test_CloseNetwork_int(tctx, t->p, &hNetwork);

	return true;
}

static bool test_CloseNetwork(struct torture_context *tctx,
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetwork;

	if (!test_OpenNetwork_int(tctx, t->p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	return test_CloseNetwork_int(tctx, t->p, &hNetwork);
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
				 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetwork;
	bool ret = true;

	if (!test_OpenNetwork_int(tctx, t->p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	ret = test_GetNetworkState_int(tctx, t->p, &hNetwork);

	test_CloseNetwork_int(tctx, t->p, &hNetwork);

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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetwork;
	bool ret = true;

	if (!test_OpenNetwork_int(tctx, t->p, "Cluster Network 1", &hNetwork)) {
		return false;
	}

	ret = test_GetNetworkId_int(tctx, t->p, &hNetwork);

	test_CloseNetwork_int(tctx, t->p, &hNetwork);

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
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			test_one_network(tctx, t->p, e.Name),
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
				  void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterface_int(tctx, t->p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	test_CloseNetInterface_int(tctx, t->p, &hNetInterface);

	return true;
}

static bool test_OpenNetInterfaceEx(struct torture_context *tctx,
				    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterfaceEx_int(tctx, t->p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	test_CloseNetInterface_int(tctx, t->p, &hNetInterface);

	return true;
}

static bool test_CloseNetInterface(struct torture_context *tctx,
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetInterface;

	if (!test_OpenNetInterface_int(tctx, t->p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	return test_CloseNetInterface_int(tctx, t->p, &hNetInterface);
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
				      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetInterface;
	bool ret = true;

	if (!test_OpenNetInterface_int(tctx, t->p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	ret = test_GetNetInterfaceState_int(tctx, t->p, &hNetInterface);

	test_CloseNetInterface_int(tctx, t->p, &hNetInterface);

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
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hNetInterface;
	bool ret = true;

	if (!test_OpenNetInterface_int(tctx, t->p, "node1 - Ethernet", &hNetInterface)) {
		return false;
	}

	ret = test_GetNetInterfaceId_int(tctx, t->p, &hNetInterface);

	test_CloseNetInterface_int(tctx, t->p, &hNetInterface);

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
				   void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
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
			test_one_netinterface(tctx, t->p, e.Name),
			"failed to test one netinterface");
	}

	return true;
}

static bool test_CloseKey_int(struct torture_context *tctx,
			      struct dcerpc_pipe *p,
			      struct policy_handle *pKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseKey r;

	r.in.pKey = pKey;
	r.out.pKey = pKey;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseKey_r(b, tctx, &r),
		"CloseKey failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseKey failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(pKey),
		"policy_handle non empty after CloseKey");

	return true;
}

static bool test_GetRootKey_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *phKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetRootKey r;
	WERROR Status;
	WERROR rpc_status;

	r.in.samDesired = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.Status = &Status;
	r.out.rpc_status = &rpc_status;
	r.out.phKey = phKey;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetRootKey_r(b, tctx, &r),
		"GetRootKey failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"GetRootKey failed");

	return true;
}

static bool test_EnumKey_int(struct torture_context *tctx,
			     struct dcerpc_pipe *p,
			     struct policy_handle *hKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_EnumKey r;
	const char *KeyName;
	NTTIME lpftLastWriteTime;
	WERROR rpc_status;

	r.in.hKey = *hKey;
	r.in.dwIndex = 0;
	r.out.KeyName = &KeyName;
	r.out.lpftLastWriteTime = &lpftLastWriteTime;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_EnumKey_r(b, tctx, &r),
		"EnumKey failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"EnumKey failed");

	return true;
}

static bool test_OpenKey_int(struct torture_context *tctx,
			     struct dcerpc_pipe *p,
			     struct policy_handle *hKey,
			     const char *lpSubKey,
			     struct policy_handle *phKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenKey r;
	WERROR Status;
	WERROR rpc_status;

	r.in.hKey = *hKey;
	r.in.lpSubKey = lpSubKey;
	r.in.samDesired = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.Status = &Status;
	r.out.rpc_status = &rpc_status;
	r.out.phKey = phKey;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenKey_r(b, tctx, &r),
		"OpenKey failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenKey failed");

	return true;
}

static bool test_EnumValue_int(struct torture_context *tctx,
			       struct dcerpc_pipe *p,
			       struct policy_handle *hKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_EnumValue r;
	const char *lpValueName;
	uint32_t lpType;
	uint32_t TotalSize;
	WERROR rpc_status;
	int i = 0;

	do {
		uint32_t lpcbData = 2048;

		r.in.hKey = *hKey;
		r.in.dwIndex = i++;
		r.in.lpcbData = &lpcbData;
		r.out.lpValueName = &lpValueName;
		r.out.lpType = &lpType;
		r.out.lpData = talloc_array(tctx, uint8_t, lpcbData);
		r.out.TotalSize = &TotalSize;
		r.out.rpc_status = &rpc_status;
		r.out.lpcbData = &lpcbData;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_EnumValue_r(b, tctx, &r),
			"EnumValue failed");

	} while (W_ERROR_IS_OK(r.out.result));

	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_NO_MORE_ITEMS,
		"EnumValue failed");

	return true;
}

static bool test_QueryInfoKey_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  struct policy_handle *hKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_QueryInfoKey r;
	uint32_t lpcSubKeys;
	uint32_t lpcbMaxSubKeyLen;
	uint32_t lpcValues;
	uint32_t lpcbMaxValueNameLen;
	uint32_t lpcbMaxValueLen;
	uint32_t lpcbSecurityDescriptor;
	NTTIME lpftLastWriteTime;
	WERROR rpc_status;

	r.in.hKey = *hKey;
	r.out.lpcSubKeys = &lpcSubKeys;
	r.out.lpcbMaxSubKeyLen = &lpcbMaxSubKeyLen;
	r.out.lpcValues = &lpcValues;
	r.out.lpcbMaxValueNameLen = &lpcbMaxValueNameLen;
	r.out.lpcbMaxValueLen = &lpcbMaxValueLen;
	r.out.lpcbSecurityDescriptor = &lpcbSecurityDescriptor;
	r.out.lpftLastWriteTime = &lpftLastWriteTime;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_QueryInfoKey_r(b, tctx, &r),
		"QueryInfoKey failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"QueryInfoKey failed");

	return true;
}

static bool test_GetKeySecurity_int(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    struct policy_handle *hKey)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_GetKeySecurity r;
	uint32_t SecurityInformation = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	struct RPC_SECURITY_DESCRIPTOR pRpcSecurityDescriptor;
	WERROR rpc_status;

	ZERO_STRUCT(pRpcSecurityDescriptor);

	r.in.hKey = *hKey;
	r.in.SecurityInformation = SecurityInformation;
	r.in.pRpcSecurityDescriptor = &pRpcSecurityDescriptor;
	r.out.rpc_status = &rpc_status;
	r.out.pRpcSecurityDescriptor = &pRpcSecurityDescriptor;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_GetKeySecurity_r(b, tctx, &r),
		"GetKeySecurity failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		pRpcSecurityDescriptor.lpSecurityDescriptor = talloc_array(tctx,
		uint8_t, pRpcSecurityDescriptor.cbInSecurityDescriptor);

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_GetKeySecurity_r(b, tctx, &r),
			"GetKeySecurity failed");
	}

	torture_assert_werr_ok(tctx,
		r.out.result,
		"GetKeySecurity failed");

	return true;
}

static bool test_GetRootKey(struct torture_context *tctx,
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hKey;

	if (!test_GetRootKey_int(tctx, t->p, &hKey)) {
		return false;
	}

	test_CloseKey_int(tctx, t->p, &hKey);

	return true;
}

static bool test_CloseKey(struct torture_context *tctx,
			  void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hKey;

	if (!test_GetRootKey_int(tctx, t->p, &hKey)) {
		return false;
	}

	return test_CloseKey_int(tctx, t->p, &hKey);
}

static bool test_EnumKey(struct torture_context *tctx,
			 void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hKey;
	bool ret = true;

	if (!test_GetRootKey_int(tctx, t->p, &hKey)) {
		return false;
	}

	ret = test_EnumKey_int(tctx, t->p, &hKey);

	test_CloseKey_int(tctx, t->p, &hKey);

	return ret;
}

static bool test_QueryValue_int(struct torture_context *tctx,
				struct dcerpc_pipe *p,
				struct policy_handle *hKey,
				const char *ValueName)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_QueryValue r;
	uint32_t lpValueType;
	uint32_t lpcbRequired;
	WERROR rpc_status;

	r.in.hKey = *hKey;
	r.in.lpValueName = ValueName;
	r.in.cbData = 0;
	r.out.lpValueType = &lpValueType;
	r.out.lpData = NULL;
	r.out.lpcbRequired = &lpcbRequired;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_QueryValue_r(b, tctx, &r),
		"QueryValue failed");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {

		r.in.cbData = lpcbRequired;
		r.out.lpData = talloc_zero_array(tctx, uint8_t, r.in.cbData);

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_QueryValue_r(b, tctx, &r),
			"QueryValue failed");
	}

	torture_assert_werr_ok(tctx,
		r.out.result,
		"QueryValue failed");

	if (lpValueType == REG_SZ) {
		const char *s;
		DATA_BLOB blob = data_blob_const(r.out.lpData, lpcbRequired);
		pull_reg_sz(tctx, &blob, &s);
		torture_comment(tctx, "got: %s\n", s);
	}

	return true;
}

static bool test_QueryValue(struct torture_context *tctx,
			    void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hKey;
	bool ret = true;

	if (!test_GetRootKey_int(tctx, t->p, &hKey)) {
		return false;
	}

	ret = test_QueryValue_int(tctx, t->p, &hKey, "ClusterInstanceID");

	test_CloseKey_int(tctx, t->p, &hKey);

	return ret;
}


static bool test_one_key(struct torture_context *tctx,
			 struct dcerpc_pipe *p,
			 struct policy_handle *hKey,
			 const char *KeyName)
{
	struct policy_handle phKey;

	torture_assert(tctx,
		test_OpenKey_int(tctx, p, hKey, KeyName, &phKey),
		"failed to open key");

	torture_assert(tctx,
		test_QueryInfoKey_int(tctx, p, &phKey),
		"failed to enum values");
	torture_assert(tctx,
		test_GetKeySecurity_int(tctx, p, &phKey),
		"failed to get key security");

	torture_assert(tctx,
		test_EnumValue_int(tctx, p, &phKey),
		"failed to enum values");

	torture_assert(tctx,
		test_CloseKey_int(tctx, p, &phKey),
		"failed to close key");

	return true;
}

static bool test_all_keys(struct torture_context *tctx,
			  void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct policy_handle hKey;
	struct clusapi_EnumKey r;
	const char *KeyName;
	NTTIME lpftLastWriteTime;
	WERROR rpc_status;
	int i = 0;

	if (!test_GetRootKey_int(tctx, t->p, &hKey)) {
		return false;
	}

	do {
		r.in.hKey = hKey;
		r.in.dwIndex = i++;
		r.out.KeyName = &KeyName;
		r.out.lpftLastWriteTime = &lpftLastWriteTime;
		r.out.rpc_status = &rpc_status;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_EnumKey_r(b, tctx, &r),
			"EnumKey failed");

		if (W_ERROR_IS_OK(r.out.result)) {
			torture_assert(tctx,
				test_one_key(tctx, t->p, &hKey, KeyName),
				"failed to test one key");
		}

	} while (W_ERROR_IS_OK(r.out.result));

	torture_assert_werr_equal(tctx,
		r.out.result,
		WERR_NO_MORE_ITEMS,
		"EnumKey failed");

	test_CloseKey_int(tctx, t->p, &hKey);

	return true;
}

static bool test_OpenGroupSet_int(struct torture_context *tctx,
				  struct dcerpc_pipe *p,
				  const char *lpszGroupSetName,
				  struct policy_handle *hGroupSet)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_OpenGroupSet r;
	WERROR Status;
	WERROR rpc_status;

	r.in.lpszGroupSetName = lpszGroupSetName;
	r.out.rpc_status = &rpc_status;
	r.out.Status = &Status;
	r.out.hGroupSet = hGroupSet;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_OpenGroupSet_r(b, tctx, &r),
		"OpenGroupSet failed");
	torture_assert_werr_ok(tctx,
		*r.out.Status,
		"OpenGroupSet failed");

	return true;
}

static bool test_CloseGroupSet_int(struct torture_context *tctx,
				   struct dcerpc_pipe *p,
				   struct policy_handle *GroupSet)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct clusapi_CloseGroupSet r;

	r.in.GroupSet = GroupSet;
	r.out.GroupSet = GroupSet;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CloseGroupSet_r(b, tctx, &r),
		"CloseGroupSet failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CloseGroupSet failed");
	torture_assert(tctx,
		ndr_policy_handle_empty(GroupSet),
		"policy_handle non empty after CloseGroupSet");

	return true;
}

static bool test_OpenGroupSet(struct torture_context *tctx,
			      void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroupSet;

	if (t->lpwMajorVersion < 0x000a) {
		torture_skip(tctx, "GroupSet fn not available on old clusters");
		return true;
	}

	if (!test_OpenGroupSet_int(tctx, t->p, "Cluster Group", &hGroupSet)) {
		return false;
	}

	test_CloseGroupSet_int(tctx, t->p, &hGroupSet);

	return true;
}

static bool test_CloseGroupSet(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct policy_handle hGroupSet;

	if (t->lpwMajorVersion < 0x000a) {
		torture_skip(tctx, "GroupSet fn not available on old clusters");
		return true;
	}

	if (!test_OpenGroupSet_int(tctx, t->p, "Cluster Group", &hGroupSet)) {
		return false;
	}

	return test_CloseGroupSet_int(tctx, t->p, &hGroupSet);
}

static bool test_one_groupset(struct torture_context *tctx,
			      struct dcerpc_pipe *p,
			      const char *groupset_name)
{
	struct policy_handle hGroupSet;

	torture_assert(tctx,
		test_OpenGroupSet_int(tctx, p, groupset_name, &hGroupSet),
		"failed to open groupset");

	test_CloseGroupSet_int(tctx, p, &hGroupSet);

	return true;
}

static bool test_all_groupsets(struct torture_context *tctx,
			       void *data)
{
	struct torture_clusapi_context *t =
		talloc_get_type_abort(data, struct torture_clusapi_context);
	struct dcerpc_binding_handle *b = t->p->binding_handle;
	struct clusapi_CreateGroupSetEnum r;
	struct ENUM_LIST *ReturnEnum;
	struct policy_handle Cluster;
	WERROR rpc_status;
	int i;

	if (!test_OpenCluster_int(tctx, t->p, &Cluster)) {
		return false;
	}

	r.in.hCluster = Cluster;
	r.out.ReturnEnum = &ReturnEnum;
	r.out.rpc_status = &rpc_status;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_clusapi_CreateGroupSetEnum_r(b, tctx, &r),
		"CreateGroupSetEnum failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"CreateGroupSetEnum failed");

	test_CloseCluster_int(tctx, t->p, &Cluster);

	for (i=0; i < ReturnEnum->EntryCount; i++) {

		struct ENUM_ENTRY e = ReturnEnum->Entry[i];

		torture_assert(tctx,
			test_one_groupset(tctx, t->p, e.Name),
			"failed to test one groupset");
	}

	return true;
}

static bool torture_rpc_clusapi_setup_common(struct torture_context *tctx,
					     struct torture_clusapi_context *t)
{
	struct dcerpc_binding_handle *b;

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_connection(tctx, &t->p, &ndr_table_clusapi),
		"Error connecting to server");

	b = t->p->binding_handle;

	{
		struct clusapi_GetClusterName r;

		r.out.ClusterName = &t->ClusterName;
		r.out.NodeName = &t->NodeName;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_clusapi_GetClusterName_r(b, tctx, &r),
			"GetClusterName failed");
		torture_assert_werr_ok(tctx,
			r.out.result,
			"GetClusterName failed");
	}
	{
		struct clusapi_GetClusterVersion2 r;
		const char *lpszVendorId;
		const char *lpszCSDVersion;
		struct CLUSTER_OPERATIONAL_VERSION_INFO *ppClusterOpVerInfo;
		WERROR rpc_status;

		r.out.lpwMajorVersion = &t->lpwMajorVersion;
		r.out.lpwMinorVersion = &t->lpwMinorVersion;
		r.out.lpwBuildNumber = &t->lpwBuildNumber;
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
	}

	return true;
}

static bool torture_rpc_clusapi_setup(struct torture_context *tctx,
				      void **data)
{
	struct torture_clusapi_context *t;

	*data = t = talloc_zero(tctx, struct torture_clusapi_context);

	return torture_rpc_clusapi_setup_common(tctx, t);
}

static bool torture_rpc_clusapi_teardown(struct torture_context *tctx,
					 void *data)
{
	talloc_free(data);

	return true;
}

void torture_tcase_cluster(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "OpenCluster",
				      test_OpenCluster);
	torture_tcase_add_simple_test(tcase, "OpenClusterEx",
				      test_OpenClusterEx);
	torture_tcase_add_simple_test(tcase, "CloseCluster",
				      test_CloseCluster);
	torture_tcase_add_simple_test(tcase, "SetClusterName",
				      test_SetClusterName);
	torture_tcase_add_simple_test(tcase, "GetClusterName",
				      test_GetClusterName);
	torture_tcase_add_simple_test(tcase, "GetClusterVersion",
				      test_GetClusterVersion);
	torture_tcase_add_simple_test(tcase, "CreateEnum",
				      test_CreateEnum);
	torture_tcase_add_simple_test(tcase, "CreateEnumEx",
				      test_CreateEnumEx);
	torture_tcase_add_simple_test(tcase, "GetClusterVersion2",
				      test_GetClusterVersion2);
	torture_tcase_add_simple_test(tcase, "BackupClusterDatabase",
				      test_BackupClusterDatabase);
	torture_tcase_add_simple_test(tcase, "SetServiceAccountPassword",
				      test_SetServiceAccountPassword);
	torture_tcase_add_simple_test(tcase, "ClusterControl",
				      test_ClusterControl);
	torture_tcase_add_simple_test(tcase, "CreateResTypeEnum",
				      test_CreateResTypeEnum);
	torture_tcase_add_simple_test(tcase, "CreateGroupEnum",
				      test_CreateGroupEnum);

}

void torture_tcase_resource(struct torture_tcase *tcase)
{
	struct torture_test *test;

	torture_tcase_add_simple_test(tcase, "GetQuorumResource",
				      test_GetQuorumResource);
	torture_tcase_add_simple_test(tcase, "SetQuorumResource",
				      test_SetQuorumResource);
	torture_tcase_add_simple_test(tcase, "OpenResource",
				      test_OpenResource);
	torture_tcase_add_simple_test(tcase, "OpenResourceEx",
				      test_OpenResourceEx);
	torture_tcase_add_simple_test(tcase, "CloseResource",
				      test_CloseResource);
	torture_tcase_add_simple_test(tcase, "CreateResource",
				      test_CreateResource);
	torture_tcase_add_simple_test(tcase, "DeleteResource",
				      test_DeleteResource);
	torture_tcase_add_simple_test(tcase, "SetResourceName",
				      test_SetResourceName);
	torture_tcase_add_simple_test(tcase, "GetResourceState",
				      test_GetResourceState);
	torture_tcase_add_simple_test(tcase, "GetResourceId",
				      test_GetResourceId);
	torture_tcase_add_simple_test(tcase, "GetResourceType",
				      test_GetResourceType);
	torture_tcase_add_simple_test(tcase, "CreateResEnum",
				      test_CreateResEnum);
	test = torture_tcase_add_simple_test(tcase, "FailResource",
				      test_FailResource);
	test->dangerous = true;
	torture_tcase_add_simple_test(tcase, "OnlineResource",
				      test_OnlineResource);
	test = torture_tcase_add_simple_test(tcase, "OfflineResource",
				      test_OfflineResource);
	test->dangerous = true;
	torture_tcase_add_simple_test(tcase, "GetResourceDependencyExpression",
				      test_GetResourceDependencyExpression);
	torture_tcase_add_simple_test(tcase, "GetResourceNetworkName",
				      test_GetResourceNetworkName);
	torture_tcase_add_simple_test(tcase, "all_resources",
				      test_all_resources);
}

void torture_tcase_resourcetype(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "all_resourcetypes",
				      test_all_resourcetypes);
}

void torture_tcase_node(struct torture_tcase *tcase)
{
	struct torture_test *test;

	torture_tcase_add_simple_test(tcase, "OpenNode",
				      test_OpenNode);
	torture_tcase_add_simple_test(tcase, "OpenNodeEx",
				      test_OpenNodeEx);
	torture_tcase_add_simple_test(tcase, "CloseNode",
				      test_CloseNode);
	torture_tcase_add_simple_test(tcase, "GetNodeState",
				      test_GetNodeState);
	torture_tcase_add_simple_test(tcase, "GetNodeId",
				      test_GetNodeId);
	torture_tcase_add_simple_test(tcase, "NodeControl",
				      test_NodeControl);
	test = torture_tcase_add_simple_test(tcase, "PauseNode",
					     test_PauseNode);
	test->dangerous = true;
	torture_tcase_add_simple_test(tcase, "ResumeNode",
				      test_ResumeNode);
	test = torture_tcase_add_simple_test(tcase, "EvictNode",
					     test_EvictNode);
	test->dangerous = true;
	torture_tcase_add_simple_test(tcase, "all_nodes",
				      test_all_nodes);
}

void torture_tcase_group(struct torture_tcase *tcase)
{
	struct torture_test *test;

	torture_tcase_add_simple_test(tcase, "OpenGroup",
				      test_OpenGroup);
	torture_tcase_add_simple_test(tcase, "OpenGroupEx",
				      test_OpenGroupEx);
	torture_tcase_add_simple_test(tcase, "CloseGroup",
				      test_CloseGroup);
	torture_tcase_add_simple_test(tcase, "GetGroupState",
				      test_GetGroupState);
	torture_tcase_add_simple_test(tcase, "GetGroupId",
				      test_GetGroupId);
	torture_tcase_add_simple_test(tcase, "GroupControl",
				      test_GroupControl);
	torture_tcase_add_simple_test(tcase, "OnlineGroup",
				      test_OnlineGroup);
	test = torture_tcase_add_simple_test(tcase, "OfflineGroup",
				      test_OfflineGroup);
	test->dangerous = true;
	torture_tcase_add_simple_test(tcase, "all_groups",
				      test_all_groups);
}

void torture_tcase_network(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "OpenNetwork",
				      test_OpenNetwork);
	torture_tcase_add_simple_test(tcase, "OpenNetworkEx",
				      test_OpenNetworkEx);
	torture_tcase_add_simple_test(tcase, "CloseNetwork",
				      test_CloseNetwork);
	torture_tcase_add_simple_test(tcase, "GetNetworkState",
				      test_GetNetworkState);
	torture_tcase_add_simple_test(tcase, "GetNetworkId",
				      test_GetNetworkId);
	torture_tcase_add_simple_test(tcase, "all_networks",
				      test_all_networks);
}

void torture_tcase_netinterface(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "OpenNetInterface",
				      test_OpenNetInterface);
	torture_tcase_add_simple_test(tcase, "OpenNetInterfaceEx",
				      test_OpenNetInterfaceEx);
	torture_tcase_add_simple_test(tcase, "CloseNetInterface",
				      test_CloseNetInterface);
	torture_tcase_add_simple_test(tcase, "GetNetInterfaceState",
				      test_GetNetInterfaceState);
	torture_tcase_add_simple_test(tcase, "GetNetInterfaceId",
				      test_GetNetInterfaceId);
	torture_tcase_add_simple_test(tcase, "all_netinterfaces",
				      test_all_netinterfaces);
}

void torture_tcase_registry(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "GetRootKey",
				      test_GetRootKey);
	torture_tcase_add_simple_test(tcase, "CloseKey",
				      test_CloseKey);
	torture_tcase_add_simple_test(tcase, "EnumKey",
				      test_EnumKey);
	torture_tcase_add_simple_test(tcase, "QueryValue",
				      test_QueryValue);
	torture_tcase_add_simple_test(tcase, "all_keys",
				      test_all_keys);
}

void torture_tcase_groupset(struct torture_tcase *tcase)
{
	torture_tcase_add_simple_test(tcase, "OpenGroupSet",
				      test_OpenGroupSet);
	torture_tcase_add_simple_test(tcase, "CloseGroupSet",
				      test_CloseGroupSet);
	torture_tcase_add_simple_test(tcase, "all_groupsets",
				      test_all_groupsets);
}

struct torture_suite *torture_rpc_clusapi(TALLOC_CTX *mem_ctx)
{
	struct torture_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "clusapi");

	tcase = torture_suite_add_tcase(suite, "cluster");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_cluster(tcase);

	tcase = torture_suite_add_tcase(suite, "resource");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_resource(tcase);

	tcase = torture_suite_add_tcase(suite, "resourcetype");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_resourcetype(tcase);


	tcase = torture_suite_add_tcase(suite, "node");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_node(tcase);

	tcase = torture_suite_add_tcase(suite, "group");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_group(tcase);

	tcase = torture_suite_add_tcase(suite, "network");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_network(tcase);

	tcase = torture_suite_add_tcase(suite, "netinterface");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_netinterface(tcase);

	tcase = torture_suite_add_tcase(suite, "registry");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_registry(tcase);

	tcase = torture_suite_add_tcase(suite, "groupset");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_clusapi_setup,
				  torture_rpc_clusapi_teardown);

	torture_tcase_groupset(tcase);

	return suite;
}

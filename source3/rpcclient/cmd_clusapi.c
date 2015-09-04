/*
   Unix SMB/CIFS implementation.
   RPC pipe client

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
#include "rpcclient.h"
#include "../librpc/gen_ndr/ndr_clusapi_c.h"

static WERROR cmd_clusapi_open_cluster(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	struct policy_handle Cluster;

	status = dcerpc_clusapi_OpenCluster(b, mem_ctx,
					    &error,
					    &Cluster);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("successfully opened cluster\n");

	status = dcerpc_clusapi_CloseCluster(b, mem_ctx,
					     &Cluster,
					     &error);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("successfully closed cluster\n");

	return WERR_OK;
}

static WERROR cmd_clusapi_get_cluster_name(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	const char *ClusterName;
	const char *NodeName;

	status = dcerpc_clusapi_GetClusterName(b, mem_ctx,
					       &ClusterName,
					       &NodeName,
					       &error);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("ClusterName: %s\n", ClusterName);
	printf("NodeName: %s\n", NodeName);

	return WERR_OK;
}

static WERROR cmd_clusapi_get_cluster_version(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	uint16_t lpwMajorVersion;
	uint16_t lpwMinorVersion;
	uint16_t lpwBuildNumber;
	const char *lpszVendorId;
	const char *lpszCSDVersion;

	status = dcerpc_clusapi_GetClusterVersion(b, mem_ctx,
						  &lpwMajorVersion,
						  &lpwMinorVersion,
						  &lpwBuildNumber,
						  &lpszVendorId,
						  &lpszCSDVersion,
						  &error);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("lpwMajorVersion: %d\n", lpwMajorVersion);
	printf("lpwMinorVersion: %d\n", lpwMinorVersion);
	printf("lpwBuildNumber: %d\n", lpwBuildNumber);
	printf("lpszVendorId: %s\n", lpszVendorId);
	printf("lpszCSDVersion: %s\n", lpszCSDVersion);

	return WERR_OK;
}

static WERROR cmd_clusapi_get_quorum_resource(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	const char *lpszResourceName;
	const char *lpszDeviceName;
	uint32_t pdwMaxQuorumLogSize;
	WERROR rpc_status;

	status = dcerpc_clusapi_GetQuorumResource(b, mem_ctx,
						  &lpszResourceName,
						  &lpszDeviceName,
						  &pdwMaxQuorumLogSize,
						  &rpc_status,
						  &error);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("lpszResourceName: %s\n", lpszResourceName);
	printf("lpszDeviceName: %s\n", lpszDeviceName);
	printf("pdwMaxQuorumLogSize: %d\n", pdwMaxQuorumLogSize);
	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}

static WERROR cmd_clusapi_create_enum(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      int argc,
				      const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	uint32_t dwType = 1;
	struct ENUM_LIST *ReturnEnum;
	WERROR rpc_status;

	if (argc >= 2) {
		sscanf(argv[1],"%x",&dwType);
	}

	status = dcerpc_clusapi_CreateEnum(b, mem_ctx,
					   dwType,
					   &ReturnEnum,
					   &rpc_status,
					   &error);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}

static WERROR cmd_clusapi_create_enumex(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					int argc,
					const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	WERROR error;
	uint32_t dwType = 1;
	struct ENUM_LIST *ReturnIdEnum;
	struct ENUM_LIST *ReturnNameEnum;
	WERROR rpc_status, ignore;
	struct policy_handle Cluster;

	status = dcerpc_clusapi_OpenCluster(b, mem_ctx,
					    &error,
					    &Cluster);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	if (argc >= 2) {
		sscanf(argv[1],"%x",&dwType);
	}

	status = dcerpc_clusapi_CreateEnumEx(b, mem_ctx,
					     Cluster,
					     dwType,
					     0,
					     &ReturnIdEnum,
					     &ReturnNameEnum,
					     &rpc_status,
					     &error);
	dcerpc_clusapi_CloseCluster(b, mem_ctx,
				    &Cluster,
				    &ignore);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("error: %s\n", win_errstr(error));
		return error;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}


static WERROR cmd_clusapi_open_resource(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					int argc,
					const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	const char *lpszResourceName = "Cluster Name";
	WERROR Status;
	struct policy_handle hResource;
	WERROR rpc_status, ignore;

	if (argc >= 2) {
		lpszResourceName = argv[1];
	}

	status = dcerpc_clusapi_OpenResource(b, mem_ctx,
					     lpszResourceName,
					     &Status,
					     &rpc_status,
					     &hResource);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	dcerpc_clusapi_CloseResource(b, mem_ctx,
				     &hResource,
				     &ignore);

	return WERR_OK;
}

static WERROR cmd_clusapi_online_resource(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	const char *lpszResourceName = "Cluster Name";
	WERROR Status;
	struct policy_handle hResource;
	WERROR rpc_status, ignore;

	if (argc >= 2) {
		lpszResourceName = argv[1];
	}

	status = dcerpc_clusapi_OpenResource(b, mem_ctx,
					     lpszResourceName,
					     &Status,
					     &rpc_status,
					     &hResource);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	status = dcerpc_clusapi_OnlineResource(b, mem_ctx,
					       hResource,
					       &Status,
					       &rpc_status);
	dcerpc_clusapi_CloseResource(b, mem_ctx,
				     &hResource,
				     &ignore);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}

static WERROR cmd_clusapi_offline_resource(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	const char *lpszResourceName = "Cluster Name";
	WERROR Status;
	struct policy_handle hResource;
	WERROR rpc_status, ignore;

	if (argc >= 2) {
		lpszResourceName = argv[1];
	}

	status = dcerpc_clusapi_OpenResource(b, mem_ctx,
					     lpszResourceName,
					     &Status,
					     &rpc_status,
					     &hResource);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	status = dcerpc_clusapi_OfflineResource(b, mem_ctx,
						hResource,
						&Status,
						&rpc_status);
	dcerpc_clusapi_CloseResource(b, mem_ctx,
				     &hResource,
				     &ignore);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}

static WERROR cmd_clusapi_get_resource_state(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx,
					     int argc,
					     const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	const char *lpszResourceName = "Cluster Name";
	WERROR Status;
	struct policy_handle hResource;
	WERROR rpc_status;
	enum clusapi_ClusterResourceState State;
	const char *NodeName;
	const char *GroupName;
	WERROR result, ignore;

	if (argc >= 2) {
		lpszResourceName = argv[1];
	}

	status = dcerpc_clusapi_OpenResource(b, mem_ctx,
					     lpszResourceName,
					     &Status,
					     &rpc_status,
					     &hResource);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	status = dcerpc_clusapi_GetResourceState(b, mem_ctx,
						 hResource,
						 &State,
						 &NodeName,
						 &GroupName,
						 &rpc_status,
						 &result);
	dcerpc_clusapi_CloseResource(b, mem_ctx,
				     &hResource,
				     &ignore);

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(Status)) {
		printf("Status: %s\n", win_errstr(Status));
		return Status;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}

static WERROR cmd_clusapi_get_cluster_version2(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       int argc,
					       const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	uint16_t lpwMajorVersion;
	uint16_t lpwMinorVersion;
	uint16_t lpwBuildNumber;
	const char *lpszVendorId;
	const char *lpszCSDVersion;
	struct CLUSTER_OPERATIONAL_VERSION_INFO *ppClusterOpVerInfo;
	WERROR rpc_status;
	WERROR result;

	status = dcerpc_clusapi_GetClusterVersion2(b, mem_ctx,
						   &lpwMajorVersion,
						   &lpwMinorVersion,
						   &lpwBuildNumber,
						   &lpszVendorId,
						   &lpszCSDVersion,
						   &ppClusterOpVerInfo,
						   &rpc_status,
						   &result);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (!W_ERROR_IS_OK(result)) {
		printf("result: %s\n", win_errstr(result));
		return result;
	}

	printf("rpc_status: %s\n", win_errstr(rpc_status));

	return WERR_OK;
}


struct cmd_set clusapi_commands[] = {

	{ "CLUSAPI" },
	{ "clusapi_open_cluster", RPC_RTYPE_WERROR, NULL, cmd_clusapi_open_cluster, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_get_cluster_name", RPC_RTYPE_WERROR, NULL, cmd_clusapi_get_cluster_name, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_get_cluster_version", RPC_RTYPE_WERROR, NULL, cmd_clusapi_get_cluster_version, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_get_quorum_resource", RPC_RTYPE_WERROR, NULL, cmd_clusapi_get_quorum_resource, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_create_enum", RPC_RTYPE_WERROR, NULL, cmd_clusapi_create_enum, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_create_enumex", RPC_RTYPE_WERROR, NULL, cmd_clusapi_create_enumex, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_open_resource", RPC_RTYPE_WERROR, NULL, cmd_clusapi_open_resource, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_online_resource", RPC_RTYPE_WERROR, NULL, cmd_clusapi_online_resource, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_offline_resource", RPC_RTYPE_WERROR, NULL, cmd_clusapi_offline_resource, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_get_resource_state", RPC_RTYPE_WERROR, NULL, cmd_clusapi_get_resource_state, &ndr_table_clusapi, NULL, "bla", "" },
	{ "clusapi_get_cluster_version2", RPC_RTYPE_WERROR, NULL, cmd_clusapi_get_cluster_version2, &ndr_table_clusapi, NULL, "bla", "" },
	{ NULL }
};

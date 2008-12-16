#include "../librpc/gen_ndr/ndr_drsuapi.h"
#ifndef __CLI_DRSUAPI__
#define __CLI_DRSUAPI__
NTSTATUS rpccli_drsuapi_DsBind(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       struct GUID *bind_guid /* [in] [unique] */,
			       struct drsuapi_DsBindInfoCtr *bind_info /* [in,out] [unique] */,
			       struct policy_handle *bind_handle /* [out] [ref] */,
			       WERROR *werror);
NTSTATUS rpccli_drsuapi_DsUnbind(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *bind_handle /* [in,out] [ref] */,
				 WERROR *werror);
NTSTATUS rpccli_drsuapi_DsReplicaSync(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      struct policy_handle *bind_handle /* [in] [ref] */,
				      int32_t level /* [in]  */,
				      union drsuapi_DsReplicaSyncRequest req /* [in] [switch_is(level)] */,
				      WERROR *werror);
NTSTATUS rpccli_drsuapi_DsGetNCChanges(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *bind_handle /* [in] [ref] */,
				       int32_t level /* [in]  */,
				       union drsuapi_DsGetNCChangesRequest *req /* [in] [ref,switch_is(level)] */,
				       int32_t *level_out /* [out] [ref] */,
				       union drsuapi_DsGetNCChangesCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
				       WERROR *werror);
NTSTATUS rpccli_drsuapi_DsReplicaUpdateRefs(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    struct policy_handle *bind_handle /* [in] [ref] */,
					    int32_t level /* [in]  */,
					    union drsuapi_DsReplicaUpdateRefsRequest req /* [in] [switch_is(level)] */,
					    WERROR *werror);
NTSTATUS rpccli_DRSUAPI_REPLICA_ADD(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_DRSUAPI_REPLICA_DEL(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_DRSUAPI_REPLICA_MODIFY(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       WERROR *werror);
NTSTATUS rpccli_DRSUAPI_VERIFY_NAMES(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_drsuapi_DsGetMemberships(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *bind_handle /* [in] [ref] */,
					 int32_t level /* [in]  */,
					 union drsuapi_DsGetMembershipsRequest *req /* [in] [ref,switch_is(level)] */,
					 int32_t *level_out /* [out] [ref] */,
					 union drsuapi_DsGetMembershipsCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
					 WERROR *werror);
NTSTATUS rpccli_DRSUAPI_INTER_DOMAIN_MOVE(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  WERROR *werror);
NTSTATUS rpccli_drsuapi_DsGetNT4ChangeLog(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  struct policy_handle *bind_handle /* [in] [ref] */,
					  uint32_t level /* [in]  */,
					  union drsuapi_DsGetNT4ChangeLogRequest *req /* [in] [ref,switch_is(level)] */,
					  uint32_t *level_out /* [out] [ref] */,
					  union drsuapi_DsGetNT4ChangeLogInfo *info /* [out] [ref,switch_is(*level_out)] */,
					  WERROR *werror);
NTSTATUS rpccli_drsuapi_DsCrackNames(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *bind_handle /* [in] [ref] */,
				     int32_t level /* [in]  */,
				     union drsuapi_DsNameRequest *req /* [in] [ref,switch_is(level)] */,
				     int32_t *level_out /* [out] [ref] */,
				     union drsuapi_DsNameCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
				     WERROR *werror);
NTSTATUS rpccli_drsuapi_DsWriteAccountSpn(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  struct policy_handle *bind_handle /* [in] [ref] */,
					  int32_t level /* [in]  */,
					  union drsuapi_DsWriteAccountSpnRequest *req /* [in] [ref,switch_is(level)] */,
					  int32_t *level_out /* [out] [ref] */,
					  union drsuapi_DsWriteAccountSpnResult *res /* [out] [ref,switch_is(*level_out)] */,
					  WERROR *werror);
NTSTATUS rpccli_drsuapi_DsRemoveDSServer(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *bind_handle /* [in] [ref] */,
					 int32_t level /* [in]  */,
					 union drsuapi_DsRemoveDSServerRequest *req /* [in] [ref,switch_is(level)] */,
					 int32_t *level_out /* [out] [ref] */,
					 union drsuapi_DsRemoveDSServerResult *res /* [out] [ref,switch_is(*level_out)] */,
					 WERROR *werror);
NTSTATUS rpccli_DRSUAPI_REMOVE_DS_DOMAIN(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_drsuapi_DsGetDomainControllerInfo(struct rpc_pipe_client *cli,
						  TALLOC_CTX *mem_ctx,
						  struct policy_handle *bind_handle /* [in] [ref] */,
						  int32_t level /* [in]  */,
						  union drsuapi_DsGetDCInfoRequest *req /* [in] [ref,switch_is(level)] */,
						  int32_t *level_out /* [out] [ref] */,
						  union drsuapi_DsGetDCInfoCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
						  WERROR *werror);
NTSTATUS rpccli_drsuapi_DsAddEntry(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   struct policy_handle *bind_handle /* [in] [ref] */,
				   int32_t level /* [in]  */,
				   union drsuapi_DsAddEntryRequest *req /* [in] [ref,switch_is(level)] */,
				   int32_t *level_out /* [out] [ref] */,
				   union drsuapi_DsAddEntryCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
				   WERROR *werror);
NTSTATUS rpccli_DRSUAPI_EXECUTE_KCC(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    WERROR *werror);
NTSTATUS rpccli_drsuapi_DsReplicaGetInfo(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *bind_handle /* [in] [ref] */,
					 enum drsuapi_DsReplicaGetInfoLevel level /* [in]  */,
					 union drsuapi_DsReplicaGetInfoRequest *req /* [in] [ref,switch_is(level)] */,
					 enum drsuapi_DsReplicaInfoType *info_type /* [out] [ref] */,
					 union drsuapi_DsReplicaInfo *info /* [out] [ref,switch_is(*info_type)] */,
					 WERROR *werror);
NTSTATUS rpccli_DRSUAPI_ADD_SID_HISTORY(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					WERROR *werror);
NTSTATUS rpccli_drsuapi_DsGetMemberships2(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  struct policy_handle *bind_handle /* [in] [ref] */,
					  int32_t level /* [in]  */,
					  union drsuapi_DsGetMemberships2Request *req /* [in] [ref,switch_is(level)] */,
					  int32_t *level_out /* [out] [ref] */,
					  union drsuapi_DsGetMemberships2Ctr *ctr /* [out] [ref,switch_is(*level_out)] */,
					  WERROR *werror);
NTSTATUS rpccli_DRSUAPI_REPLICA_VERIFY_OBJECTS(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       WERROR *werror);
NTSTATUS rpccli_DRSUAPI_GET_OBJECT_EXISTENCE(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx,
					     WERROR *werror);
NTSTATUS rpccli_drsuapi_QuerySitesByCost(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *bind_handle /* [in] [ref] */,
					 int32_t level /* [in]  */,
					 union drsuapi_QuerySitesByCostRequest *req /* [in] [ref,switch_is(level)] */,
					 int32_t *level_out /* [out] [ref] */,
					 union drsuapi_QuerySitesByCostCtr *ctr /* [out] [ref,switch_is(*level_out)] */,
					 WERROR *werror);
#endif /* __CLI_DRSUAPI__ */

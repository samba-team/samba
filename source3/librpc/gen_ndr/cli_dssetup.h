#include "librpc/gen_ndr/ndr_dssetup.h"
#ifndef __CLI_DSSETUP__
#define __CLI_DSSETUP__
NTSTATUS rpccli_dssetup_DsRoleGetPrimaryDomainInformation(struct rpc_pipe_client *cli,
							  TALLOC_CTX *mem_ctx,
							  enum dssetup_DsRoleInfoLevel level /* [in]  */,
							  union dssetup_DsRoleInfo *info /* [out] [unique,switch_is(level)] */,
							  WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleDnsNameToFlatName(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx,
						WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleDcAsDc(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleDcAsReplica(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleDemoteDc(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleGetDcOperationProgress(struct rpc_pipe_client *cli,
						     TALLOC_CTX *mem_ctx,
						     WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleGetDcOperationResults(struct rpc_pipe_client *cli,
						    TALLOC_CTX *mem_ctx,
						    WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleCancel(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleServerSaveStateForUpgrade(struct rpc_pipe_client *cli,
							TALLOC_CTX *mem_ctx,
							WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleUpgradeDownlevelServer(struct rpc_pipe_client *cli,
						     TALLOC_CTX *mem_ctx,
						     WERROR *werror);
NTSTATUS rpccli_dssetup_DsRoleAbortDownlevelServerUpgrade(struct rpc_pipe_client *cli,
							  TALLOC_CTX *mem_ctx,
							  WERROR *werror);
#endif /* __CLI_DSSETUP__ */

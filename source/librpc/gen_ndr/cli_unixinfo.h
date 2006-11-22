#include "librpc/gen_ndr/ndr_unixinfo.h"
#ifndef __CLI_UNIXINFO__
#define __CLI_UNIXINFO__
NTSTATUS rpccli_unixinfo_SidToUid(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct dom_sid sid, uint64_t *uid);
NTSTATUS rpccli_unixinfo_UidToSid(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint64_t uid, struct dom_sid *sid);
NTSTATUS rpccli_unixinfo_SidToGid(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct dom_sid sid, uint64_t *gid);
NTSTATUS rpccli_unixinfo_GidToSid(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint64_t gid, struct dom_sid *sid);
NTSTATUS rpccli_unixinfo_GetPWUid(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t *count, uint64_t *uids, struct unixinfo_GetPWUidInfo **infos);
#endif /* __CLI_UNIXINFO__ */

#include "librpc/gen_ndr/ndr_dfs.h"
#ifndef __CLI_NETDFS__
#define __CLI_NETDFS__
NTSTATUS rpccli_dfs_GetManagerVersion(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t *exist_flag);
NTSTATUS rpccli_dfs_Add(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *path, const char *server, const char *share, const char *comment, uint32_t flags);
NTSTATUS rpccli_dfs_Remove(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *path, const char *server, const char *share);
NTSTATUS rpccli_dfs_SetInfo(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_GetInfo(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *path, const char *server, const char *share, uint32_t level, union dfs_Info *info);
NTSTATUS rpccli_dfs_Enum(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t level, uint32_t bufsize, struct dfs_EnumStruct **info, uint32_t *unknown, uint32_t **total);
NTSTATUS rpccli_dfs_Rename(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_Move(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_ManagerGetConfigInfo(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_ManagerSendSiteInfo(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_AddFtRoot(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_RemoveFtRoot(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_AddStdRoot(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_RemoveStdRoot(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_ManagerInitialize(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_AddStdRootForced(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_GetDcAddress(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_SetDcAddress(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_FlushFtTable(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_Add2(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_Remove2(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_dfs_EnumEx(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *name, uint32_t level, uint32_t bufsize, struct dfs_EnumStruct **info, uint32_t **total);
NTSTATUS rpccli_dfs_SetInfo2(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx);
#endif /* __CLI_NETDFS__ */

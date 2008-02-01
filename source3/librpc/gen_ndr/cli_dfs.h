#include "librpc/gen_ndr/ndr_dfs.h"
#ifndef __CLI_NETDFS__
#define __CLI_NETDFS__
NTSTATUS rpccli_dfs_GetManagerVersion(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      enum dfs_ManagerVersion *version);
NTSTATUS rpccli_dfs_Add(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			const char *path,
			const char *server,
			const char *share,
			const char *comment,
			uint32_t flags,
			WERROR *werror);
NTSTATUS rpccli_dfs_Remove(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   const char *dfs_entry_path,
			   const char *servername,
			   const char *sharename,
			   WERROR *werror);
NTSTATUS rpccli_dfs_SetInfo(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    const char *dfs_entry_path,
			    const char *servername,
			    const char *sharename,
			    uint32_t level,
			    union dfs_Info *info,
			    WERROR *werror);
NTSTATUS rpccli_dfs_GetInfo(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    const char *dfs_entry_path,
			    const char *servername,
			    const char *sharename,
			    uint32_t level,
			    union dfs_Info *info,
			    WERROR *werror);
NTSTATUS rpccli_dfs_Enum(struct rpc_pipe_client *cli,
			 TALLOC_CTX *mem_ctx,
			 uint32_t level,
			 uint32_t bufsize,
			 struct dfs_EnumStruct *info,
			 uint32_t *total,
			 WERROR *werror);
NTSTATUS rpccli_dfs_Rename(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   WERROR *werror);
NTSTATUS rpccli_dfs_Move(struct rpc_pipe_client *cli,
			 TALLOC_CTX *mem_ctx,
			 WERROR *werror);
NTSTATUS rpccli_dfs_ManagerGetConfigInfo(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 WERROR *werror);
NTSTATUS rpccli_dfs_ManagerSendSiteInfo(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					WERROR *werror);
NTSTATUS rpccli_dfs_AddFtRoot(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      const char *servername,
			      const char *dns_servername,
			      const char *dfsname,
			      const char *rootshare,
			      const char *comment,
			      const char *dfs_config_dn,
			      uint8_t unknown1,
			      uint32_t flags,
			      struct dfs_UnknownStruct **unknown2,
			      WERROR *werror);
NTSTATUS rpccli_dfs_RemoveFtRoot(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername,
				 const char *dns_servername,
				 const char *dfsname,
				 const char *rootshare,
				 uint32_t flags,
				 struct dfs_UnknownStruct **unknown,
				 WERROR *werror);
NTSTATUS rpccli_dfs_AddStdRoot(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       const char *servername,
			       const char *rootshare,
			       const char *comment,
			       uint32_t flags,
			       WERROR *werror);
NTSTATUS rpccli_dfs_RemoveStdRoot(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  const char *servername,
				  const char *rootshare,
				  uint32_t flags,
				  WERROR *werror);
NTSTATUS rpccli_dfs_ManagerInitialize(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      const char *servername,
				      uint32_t flags,
				      WERROR *werror);
NTSTATUS rpccli_dfs_AddStdRootForced(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *servername,
				     const char *rootshare,
				     const char *comment,
				     const char *store,
				     WERROR *werror);
NTSTATUS rpccli_dfs_GetDcAddress(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername,
				 const char **server_fullname,
				 uint8_t *is_root,
				 uint32_t *ttl,
				 WERROR *werror);
NTSTATUS rpccli_dfs_SetDcAddress(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername,
				 const char *server_fullname,
				 uint32_t flags,
				 uint32_t ttl,
				 WERROR *werror);
NTSTATUS rpccli_dfs_FlushFtTable(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername,
				 const char *rootshare,
				 WERROR *werror);
NTSTATUS rpccli_dfs_Add2(struct rpc_pipe_client *cli,
			 TALLOC_CTX *mem_ctx,
			 WERROR *werror);
NTSTATUS rpccli_dfs_Remove2(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    WERROR *werror);
NTSTATUS rpccli_dfs_EnumEx(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   const char *dfs_name,
			   uint32_t level,
			   uint32_t bufsize,
			   struct dfs_EnumStruct *info,
			   uint32_t *total,
			   WERROR *werror);
NTSTATUS rpccli_dfs_SetInfo2(struct rpc_pipe_client *cli,
			     TALLOC_CTX *mem_ctx,
			     WERROR *werror);
#endif /* __CLI_NETDFS__ */

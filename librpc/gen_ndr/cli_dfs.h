#include "../librpc/gen_ndr/ndr_dfs.h"
#ifndef __CLI_NETDFS__
#define __CLI_NETDFS__
NTSTATUS rpccli_dfs_GetManagerVersion(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      enum dfs_ManagerVersion *version /* [out] [ref] */);
NTSTATUS rpccli_dfs_Add(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			const char *path /* [in] [ref,charset(UTF16)] */,
			const char *server /* [in] [ref,charset(UTF16)] */,
			const char *share /* [in] [unique,charset(UTF16)] */,
			const char *comment /* [in] [unique,charset(UTF16)] */,
			uint32_t flags /* [in]  */,
			WERROR *werror);
NTSTATUS rpccli_dfs_Remove(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   const char *dfs_entry_path /* [in] [ref,charset(UTF16)] */,
			   const char *servername /* [in] [unique,charset(UTF16)] */,
			   const char *sharename /* [in] [unique,charset(UTF16)] */,
			   WERROR *werror);
NTSTATUS rpccli_dfs_SetInfo(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    const char *dfs_entry_path /* [in] [charset(UTF16)] */,
			    const char *servername /* [in] [unique,charset(UTF16)] */,
			    const char *sharename /* [in] [unique,charset(UTF16)] */,
			    uint32_t level /* [in]  */,
			    union dfs_Info *info /* [in] [ref,switch_is(level)] */,
			    WERROR *werror);
NTSTATUS rpccli_dfs_GetInfo(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    const char *dfs_entry_path /* [in] [charset(UTF16)] */,
			    const char *servername /* [in] [unique,charset(UTF16)] */,
			    const char *sharename /* [in] [unique,charset(UTF16)] */,
			    uint32_t level /* [in]  */,
			    union dfs_Info *info /* [out] [ref,switch_is(level)] */,
			    WERROR *werror);
NTSTATUS rpccli_dfs_Enum(struct rpc_pipe_client *cli,
			 TALLOC_CTX *mem_ctx,
			 uint32_t level /* [in]  */,
			 uint32_t bufsize /* [in]  */,
			 struct dfs_EnumStruct *info /* [in,out] [unique] */,
			 uint32_t *total /* [in,out] [unique] */,
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
			      const char *servername /* [in] [charset(UTF16)] */,
			      const char *dns_servername /* [in] [charset(UTF16)] */,
			      const char *dfsname /* [in] [charset(UTF16)] */,
			      const char *rootshare /* [in] [charset(UTF16)] */,
			      const char *comment /* [in] [charset(UTF16)] */,
			      const char *dfs_config_dn /* [in] [charset(UTF16)] */,
			      uint8_t unknown1 /* [in]  */,
			      uint32_t flags /* [in]  */,
			      struct dfs_UnknownStruct **unknown2 /* [in,out] [unique] */,
			      WERROR *werror);
NTSTATUS rpccli_dfs_RemoveFtRoot(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername /* [in] [charset(UTF16)] */,
				 const char *dns_servername /* [in] [charset(UTF16)] */,
				 const char *dfsname /* [in] [charset(UTF16)] */,
				 const char *rootshare /* [in] [charset(UTF16)] */,
				 uint32_t flags /* [in]  */,
				 struct dfs_UnknownStruct **unknown /* [in,out] [unique] */,
				 WERROR *werror);
NTSTATUS rpccli_dfs_AddStdRoot(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       const char *servername /* [in] [charset(UTF16)] */,
			       const char *rootshare /* [in] [charset(UTF16)] */,
			       const char *comment /* [in] [charset(UTF16)] */,
			       uint32_t flags /* [in]  */,
			       WERROR *werror);
NTSTATUS rpccli_dfs_RemoveStdRoot(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  const char *servername /* [in] [charset(UTF16)] */,
				  const char *rootshare /* [in] [charset(UTF16)] */,
				  uint32_t flags /* [in]  */,
				  WERROR *werror);
NTSTATUS rpccli_dfs_ManagerInitialize(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      const char *servername /* [in] [ref,charset(UTF16)] */,
				      uint32_t flags /* [in]  */,
				      WERROR *werror);
NTSTATUS rpccli_dfs_AddStdRootForced(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *servername /* [in] [charset(UTF16)] */,
				     const char *rootshare /* [in] [charset(UTF16)] */,
				     const char *comment /* [in] [charset(UTF16)] */,
				     const char *store /* [in] [charset(UTF16)] */,
				     WERROR *werror);
NTSTATUS rpccli_dfs_GetDcAddress(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername /* [in] [charset(UTF16)] */,
				 const char **server_fullname /* [in,out] [ref,charset(UTF16)] */,
				 uint8_t *is_root /* [in,out] [ref] */,
				 uint32_t *ttl /* [in,out] [ref] */,
				 WERROR *werror);
NTSTATUS rpccli_dfs_SetDcAddress(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername /* [in] [charset(UTF16)] */,
				 const char *server_fullname /* [in] [charset(UTF16)] */,
				 uint32_t flags /* [in]  */,
				 uint32_t ttl /* [in]  */,
				 WERROR *werror);
NTSTATUS rpccli_dfs_FlushFtTable(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *servername /* [in] [charset(UTF16)] */,
				 const char *rootshare /* [in] [charset(UTF16)] */,
				 WERROR *werror);
NTSTATUS rpccli_dfs_Add2(struct rpc_pipe_client *cli,
			 TALLOC_CTX *mem_ctx,
			 WERROR *werror);
NTSTATUS rpccli_dfs_Remove2(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    WERROR *werror);
NTSTATUS rpccli_dfs_EnumEx(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   const char *dfs_name /* [in] [charset(UTF16)] */,
			   uint32_t level /* [in]  */,
			   uint32_t bufsize /* [in]  */,
			   struct dfs_EnumStruct *info /* [in,out] [unique] */,
			   uint32_t *total /* [in,out] [unique] */,
			   WERROR *werror);
NTSTATUS rpccli_dfs_SetInfo2(struct rpc_pipe_client *cli,
			     TALLOC_CTX *mem_ctx,
			     WERROR *werror);
#endif /* __CLI_NETDFS__ */

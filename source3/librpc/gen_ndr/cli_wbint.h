#include "librpc/gen_ndr/ndr_wbint.h"
#ifndef __CLI_WBINT__
#define __CLI_WBINT__
struct tevent_req *rpccli_wbint_Ping_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct rpc_pipe_client *cli,
					  uint32_t _in_data /* [in]  */,
					  uint32_t *_out_data /* [out] [ref] */);
NTSTATUS rpccli_wbint_Ping_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_wbint_Ping(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t in_data /* [in]  */,
			   uint32_t *out_data /* [out] [ref] */);
struct tevent_req *rpccli_wbint_LookupSid_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct rpc_pipe_client *cli,
					       struct dom_sid *_sid /* [in] [ref] */,
					       enum lsa_SidType *_type /* [out] [ref] */,
					       const char **_domain /* [out] [ref,charset(UTF8)] */,
					       const char **_name /* [out] [ref,charset(UTF8)] */);
NTSTATUS rpccli_wbint_LookupSid_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     NTSTATUS *result);
NTSTATUS rpccli_wbint_LookupSid(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct dom_sid *sid /* [in] [ref] */,
				enum lsa_SidType *type /* [out] [ref] */,
				const char **domain /* [out] [ref,charset(UTF8)] */,
				const char **name /* [out] [ref,charset(UTF8)] */);
struct tevent_req *rpccli_wbint_LookupName_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct rpc_pipe_client *cli,
						const char *_domain /* [in] [ref,charset(UTF8)] */,
						const char *_name /* [in] [ref,charset(UTF8)] */,
						uint32_t _flags /* [in]  */,
						enum lsa_SidType *_type /* [out] [ref] */,
						struct dom_sid *_sid /* [out] [ref] */);
NTSTATUS rpccli_wbint_LookupName_recv(struct tevent_req *req,
				      TALLOC_CTX *mem_ctx,
				      NTSTATUS *result);
NTSTATUS rpccli_wbint_LookupName(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 const char *domain /* [in] [ref,charset(UTF8)] */,
				 const char *name /* [in] [ref,charset(UTF8)] */,
				 uint32_t flags /* [in]  */,
				 enum lsa_SidType *type /* [out] [ref] */,
				 struct dom_sid *sid /* [out] [ref] */);
struct tevent_req *rpccli_wbint_Sid2Uid_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct rpc_pipe_client *cli,
					     const char *_dom_name /* [in] [unique,charset(UTF8)] */,
					     struct dom_sid *_sid /* [in] [ref] */,
					     uint64_t *_uid /* [out] [ref] */);
NTSTATUS rpccli_wbint_Sid2Uid_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   NTSTATUS *result);
NTSTATUS rpccli_wbint_Sid2Uid(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      const char *dom_name /* [in] [unique,charset(UTF8)] */,
			      struct dom_sid *sid /* [in] [ref] */,
			      uint64_t *uid /* [out] [ref] */);
struct tevent_req *rpccli_wbint_Sid2Gid_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct rpc_pipe_client *cli,
					     const char *_dom_name /* [in] [unique,charset(UTF8)] */,
					     struct dom_sid *_sid /* [in] [ref] */,
					     uint64_t *_gid /* [out] [ref] */);
NTSTATUS rpccli_wbint_Sid2Gid_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   NTSTATUS *result);
NTSTATUS rpccli_wbint_Sid2Gid(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      const char *dom_name /* [in] [unique,charset(UTF8)] */,
			      struct dom_sid *sid /* [in] [ref] */,
			      uint64_t *gid /* [out] [ref] */);
#endif /* __CLI_WBINT__ */

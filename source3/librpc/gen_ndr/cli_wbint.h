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
#endif /* __CLI_WBINT__ */

#include "../librpc/gen_ndr/ndr_rap.h"
#ifndef __SRV_RAP__
#define __SRV_RAP__
void _rap_NetShareEnum(pipes_struct *p, struct rap_NetShareEnum *r);
void _rap_NetServerEnum2(pipes_struct *p, struct rap_NetServerEnum2 *r);
void _rap_WserverGetInfo(pipes_struct *p, struct rap_WserverGetInfo *r);
void _rap_NetPrintQEnum(pipes_struct *p, struct rap_NetPrintQEnum *r);
void rap_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_rap_dispatch(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const struct ndr_interface_table *table, uint32_t opnum, void *r);
void _rap_NetShareEnum(pipes_struct *p, struct rap_NetShareEnum *r);
void _rap_NetServerEnum2(pipes_struct *p, struct rap_NetServerEnum2 *r);
void _rap_WserverGetInfo(pipes_struct *p, struct rap_WserverGetInfo *r);
void _rap_NetPrintQEnum(pipes_struct *p, struct rap_NetPrintQEnum *r);
NTSTATUS rpc_rap_init(void);
#endif /* __SRV_RAP__ */

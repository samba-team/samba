#include "librpc/gen_ndr/ndr_wbint.h"
#ifndef __SRV_WBINT__
#define __SRV_WBINT__
void _wbint_Ping(pipes_struct *p, struct wbint_Ping *r);
NTSTATUS _wbint_LookupSid(pipes_struct *p, struct wbint_LookupSid *r);
NTSTATUS _wbint_LookupName(pipes_struct *p, struct wbint_LookupName *r);
NTSTATUS _wbint_Sid2Uid(pipes_struct *p, struct wbint_Sid2Uid *r);
NTSTATUS _wbint_Sid2Gid(pipes_struct *p, struct wbint_Sid2Gid *r);
NTSTATUS _wbint_Uid2Sid(pipes_struct *p, struct wbint_Uid2Sid *r);
NTSTATUS _wbint_Gid2Sid(pipes_struct *p, struct wbint_Gid2Sid *r);
NTSTATUS _wbint_QueryUser(pipes_struct *p, struct wbint_QueryUser *r);
void wbint_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_wbint_dispatch(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const struct ndr_interface_table *table, uint32_t opnum, void *r);
void _wbint_Ping(pipes_struct *p, struct wbint_Ping *r);
NTSTATUS _wbint_LookupSid(pipes_struct *p, struct wbint_LookupSid *r);
NTSTATUS _wbint_LookupName(pipes_struct *p, struct wbint_LookupName *r);
NTSTATUS _wbint_Sid2Uid(pipes_struct *p, struct wbint_Sid2Uid *r);
NTSTATUS _wbint_Sid2Gid(pipes_struct *p, struct wbint_Sid2Gid *r);
NTSTATUS _wbint_Uid2Sid(pipes_struct *p, struct wbint_Uid2Sid *r);
NTSTATUS _wbint_Gid2Sid(pipes_struct *p, struct wbint_Gid2Sid *r);
NTSTATUS _wbint_QueryUser(pipes_struct *p, struct wbint_QueryUser *r);
NTSTATUS rpc_wbint_init(void);
#endif /* __SRV_WBINT__ */

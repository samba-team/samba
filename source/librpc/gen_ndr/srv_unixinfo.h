#include "librpc/gen_ndr/ndr_unixinfo.h"
#ifndef __SRV_UNIXINFO__
#define __SRV_UNIXINFO__
NTSTATUS _unixinfo_SidToUid(pipes_struct *p, struct unixinfo_SidToUid *r);
NTSTATUS _unixinfo_UidToSid(pipes_struct *p, struct unixinfo_UidToSid *r);
NTSTATUS _unixinfo_SidToGid(pipes_struct *p, struct unixinfo_SidToGid *r);
NTSTATUS _unixinfo_GidToSid(pipes_struct *p, struct unixinfo_GidToSid *r);
NTSTATUS _unixinfo_GetPWUid(pipes_struct *p, struct unixinfo_GetPWUid *r);
void unixinfo_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_unixinfo_init(void);
#endif /* __SRV_UNIXINFO__ */

#include "librpc/gen_ndr/ndr_unixinfo.h"
#ifndef __SRV_UNIXINFO__
#define __SRV_UNIXINFO__
NTSTATUS _unixinfo_SidToUid(pipes_struct *p, struct dom_sid sid, uint64_t *uid);
NTSTATUS _unixinfo_UidToSid(pipes_struct *p, uint64_t uid, struct dom_sid *sid);
NTSTATUS _unixinfo_SidToGid(pipes_struct *p, struct dom_sid sid, uint64_t *gid);
NTSTATUS _unixinfo_GidToSid(pipes_struct *p, uint64_t gid, struct dom_sid *sid);
NTSTATUS _unixinfo_GetPWUid(pipes_struct *p, uint32_t *count, uint64_t *uids, struct unixinfo_GetPWUidInfo *infos);
void unixinfo_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_netdfs_init(void);
#endif /* __SRV_UNIXINFO__ */

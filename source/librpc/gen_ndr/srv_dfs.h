#include "librpc/gen_ndr/ndr_dfs.h"
#ifndef __SRV_NETDFS__
#define __SRV_NETDFS__
void _dfs_GetManagerVersion(pipes_struct *p, uint32_t *exist_flag);
WERROR _dfs_Add(pipes_struct *p, const char *path, const char *server, const char *share, const char *comment, uint32_t flags);
WERROR _dfs_Remove(pipes_struct *p, const char *path, const char *server, const char *share);
WERROR _dfs_SetInfo(pipes_struct *p);
WERROR _dfs_GetInfo(pipes_struct *p, const char *path, const char *server, const char *share, uint32_t level, union dfs_Info *info);
WERROR _dfs_Enum(pipes_struct *p, uint32_t level, uint32_t bufsize, struct dfs_EnumStruct *info, uint32_t *unknown, uint32_t *total);
WERROR _dfs_Rename(pipes_struct *p);
WERROR _dfs_Move(pipes_struct *p);
WERROR _dfs_ManagerGetConfigInfo(pipes_struct *p);
WERROR _dfs_ManagerSendSiteInfo(pipes_struct *p);
WERROR _dfs_AddFtRoot(pipes_struct *p);
WERROR _dfs_RemoveFtRoot(pipes_struct *p);
WERROR _dfs_AddStdRoot(pipes_struct *p);
WERROR _dfs_RemoveStdRoot(pipes_struct *p);
WERROR _dfs_ManagerInitialize(pipes_struct *p);
WERROR _dfs_AddStdRootForced(pipes_struct *p);
WERROR _dfs_GetDcAddress(pipes_struct *p);
WERROR _dfs_SetDcAddress(pipes_struct *p);
WERROR _dfs_FlushFtTable(pipes_struct *p);
WERROR _dfs_Add2(pipes_struct *p);
WERROR _dfs_Remove2(pipes_struct *p);
WERROR _dfs_EnumEx(pipes_struct *p, const char *name, uint32_t level, uint32_t bufsize, struct dfs_EnumStruct *info, uint32_t *total);
WERROR _dfs_SetInfo2(pipes_struct *p);
void netdfs_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_netdfs_init(void);
#endif /* __SRV_NETDFS__ */

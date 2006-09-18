#include "librpc/gen_ndr/ndr_wkssvc.h"
#ifndef __SRV_WKSSVC__
#define __SRV_WKSSVC__
WERROR _wkssvc_NetWkstaGetInfo(pipes_struct *p, const char *server_name, uint32_t level, union wkssvc_NetWkstaInfo *info);
WERROR _wkssvc_NetWkstaSetInfo(pipes_struct *p, const char *server_name, uint32_t level, union wkssvc_NetWkstaInfo *info, uint32_t *parm_error);
WERROR _wkssvc_NetWkstaEnumUsers(pipes_struct *p, const char *server_name, uint32_t level, union WKS_USER_ENUM_UNION *users, uint32_t prefmaxlen, uint32_t *entriesread, uint32_t *totalentries, uint32_t *resumehandle);
WERROR _WKSSVC_NETRWKSTAUSERGETINFO(pipes_struct *p);
WERROR _WKSSVC_NETRWKSTAUSERSETINFO(pipes_struct *p);
WERROR _wkssvc_NetWkstaTransportEnum(pipes_struct *p, const char *server_name, uint32_t *level, union wkssvc_NetWkstaTransportCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle);
WERROR _WKSSVC_NETRWKSTATRANSPORTADD(pipes_struct *p);
WERROR _WKSSVC_NETRWKSTATRANSPORTDEL(pipes_struct *p);
WERROR _WKSSVC_NETRUSEADD(pipes_struct *p);
WERROR _WKSSVC_NETRUSEGETINFO(pipes_struct *p);
WERROR _WKSSVC_NETRUSEDEL(pipes_struct *p);
WERROR _WKSSVC_NETRUSEENUM(pipes_struct *p);
WERROR _WKSSVC_NETRMESSAGEBUFFERSEND(pipes_struct *p);
WERROR _WKSSVC_NETRWORKSTATIONSTATISTICSGET(pipes_struct *p);
WERROR _WKSSVC_NETRLOGONDOMAINNAMEADD(pipes_struct *p);
WERROR _WKSSVC_NETRLOGONDOMAINNAMEDEL(pipes_struct *p);
WERROR _WKSSVC_NETRJOINDOMAIN(pipes_struct *p);
WERROR _WKSSVC_NETRUNJOINDOMAIN(pipes_struct *p);
WERROR _WKSSVC_NETRRENAMEMACHINEINDOMAIN(pipes_struct *p);
WERROR _WKSSVC_NETRVALIDATENAME(pipes_struct *p);
WERROR _WKSSVC_NETRGETJOININFORMATION(pipes_struct *p);
WERROR _WKSSVC_NETRGETJOINABLEOUS(pipes_struct *p);
WERROR _wkssvc_NetrJoinDomain2(pipes_struct *p, const char *server_name, const char *domain_name, const char *account_name, const char *admin_account, struct wkssvc_PasswordBuffer *encrypted_password, uint32_t join_flags);
WERROR _wkssvc_NetrUnjoinDomain2(pipes_struct *p, const char *server_name, const char *account, struct wkssvc_PasswordBuffer *encrypted_password, uint32_t unjoin_flags);
WERROR _wkssvc_NetrRenameMachineInDomain2(pipes_struct *p, const char *server_name, const char *NewMachineName, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t RenameOptions);
WERROR _WKSSVC_NETRVALIDATENAME2(pipes_struct *p);
WERROR _WKSSVC_NETRGETJOINABLEOUS2(pipes_struct *p);
WERROR _wkssvc_NetrAddAlternateComputerName(pipes_struct *p, const char *server_name, const char *NewAlternateMachineName, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t Reserved);
WERROR _wkssvc_NetrRemoveAlternateComputerName(pipes_struct *p, const char *server_name, const char *AlternateMachineNameToRemove, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t Reserved);
WERROR _WKSSVC_NETRSETPRIMARYCOMPUTERNAME(pipes_struct *p);
WERROR _WKSSVC_NETRENUMERATECOMPUTERNAMES(pipes_struct *p);
void wkssvc_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_wkssvc_init(void);
#endif /* __SRV_WKSSVC__ */

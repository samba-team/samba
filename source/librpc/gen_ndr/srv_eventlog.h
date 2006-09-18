#include "librpc/gen_ndr/ndr_eventlog.h"
#ifndef __SRV_EVENTLOG__
#define __SRV_EVENTLOG__
NTSTATUS _eventlog_ClearEventLogW(pipes_struct *p, struct policy_handle *handle, struct lsa_String *unknown);
NTSTATUS _eventlog_BackupEventLogW(pipes_struct *p);
NTSTATUS _eventlog_CloseEventLog(pipes_struct *p, struct policy_handle *handle);
NTSTATUS _eventlog_DeregisterEventSource(pipes_struct *p);
NTSTATUS _eventlog_GetNumRecords(pipes_struct *p, struct policy_handle *handle, uint32_t *number);
NTSTATUS _eventlog_GetOldestRecord(pipes_struct *p);
NTSTATUS _eventlog_ChangeNotify(pipes_struct *p);
NTSTATUS _eventlog_OpenEventLogW(pipes_struct *p, struct eventlog_OpenUnknown0 *unknown0, struct lsa_String logname, struct lsa_String servername, uint32_t unknown2, uint32_t unknown3, struct policy_handle *handle);
NTSTATUS _eventlog_RegisterEventSourceW(pipes_struct *p);
NTSTATUS _eventlog_OpenBackupEventLogW(pipes_struct *p);
NTSTATUS _eventlog_ReadEventLogW(pipes_struct *p, struct policy_handle *handle, uint32_t flags, uint32_t offset, uint32_t number_of_bytes, uint8_t *data, uint32_t *sent_size, uint32_t *real_size);
NTSTATUS _eventlog_ReportEventW(pipes_struct *p);
NTSTATUS _eventlog_ClearEventLogA(pipes_struct *p);
NTSTATUS _eventlog_BackupEventLogA(pipes_struct *p);
NTSTATUS _eventlog_OpenEventLogA(pipes_struct *p);
NTSTATUS _eventlog_RegisterEventSourceA(pipes_struct *p);
NTSTATUS _eventlog_OpenBackupEventLogA(pipes_struct *p);
NTSTATUS _eventlog_ReadEventLogA(pipes_struct *p);
NTSTATUS _eventlog_ReportEventA(pipes_struct *p);
NTSTATUS _eventlog_RegisterClusterSvc(pipes_struct *p);
NTSTATUS _eventlog_DeregisterClusterSvc(pipes_struct *p);
NTSTATUS _eventlog_WriteClusterEvents(pipes_struct *p);
NTSTATUS _eventlog_GetLogIntormation(pipes_struct *p);
NTSTATUS _eventlog_FlushEventLog(pipes_struct *p, struct policy_handle *handle);
void eventlog_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_eventlog_init(void);
#endif /* __SRV_EVENTLOG__ */

#include "librpc/gen_ndr/ndr_eventlog.h"
#ifndef __CLI_EVENTLOG__
#define __CLI_EVENTLOG__
NTSTATUS rpccli_eventlog_ClearEventLogW(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *handle,
					struct lsa_String *backupfile);
NTSTATUS rpccli_eventlog_BackupEventLogW(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_CloseEventLog(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle);
NTSTATUS rpccli_eventlog_DeregisterEventSource(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_GetNumRecords(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle,
				       uint32_t *number);
NTSTATUS rpccli_eventlog_GetOldestRecord(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *handle,
					 uint32_t *oldest_entry);
NTSTATUS rpccli_eventlog_ChangeNotify(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenEventLogW(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct eventlog_OpenUnknown0 *unknown0,
				       struct lsa_String *logname,
				       struct lsa_String *servername,
				       uint32_t unknown2,
				       uint32_t unknown3,
				       struct policy_handle *handle);
NTSTATUS rpccli_eventlog_RegisterEventSourceW(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenBackupEventLogW(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_ReadEventLogW(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle,
				       uint32_t flags,
				       uint32_t offset,
				       uint32_t number_of_bytes,
				       uint8_t *data,
				       uint32_t *sent_size,
				       uint32_t *real_size);
NTSTATUS rpccli_eventlog_ReportEventW(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_ClearEventLogA(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_BackupEventLogA(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenEventLogA(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_RegisterEventSourceA(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenBackupEventLogA(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_ReadEventLogA(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_ReportEventA(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_RegisterClusterSvc(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_DeregisterClusterSvc(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_WriteClusterEvents(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_GetLogIntormation(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_FlushEventLog(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle);
#endif /* __CLI_EVENTLOG__ */

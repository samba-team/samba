#include "librpc/gen_ndr/ndr_eventlog.h"
#ifndef __CLI_EVENTLOG__
#define __CLI_EVENTLOG__
NTSTATUS rpccli_eventlog_ClearEventLogW(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *handle /* [in] [ref] */,
					struct lsa_String *backupfile /* [in] [unique] */);
NTSTATUS rpccli_eventlog_BackupEventLogW(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_CloseEventLog(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle /* [in,out] [ref] */);
NTSTATUS rpccli_eventlog_DeregisterEventSource(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_GetNumRecords(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle /* [in] [ref] */,
				       uint32_t *number /* [out] [ref] */);
NTSTATUS rpccli_eventlog_GetOldestRecord(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 struct policy_handle *handle /* [in] [ref] */,
					 uint32_t *oldest_entry /* [out] [ref] */);
NTSTATUS rpccli_eventlog_ChangeNotify(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenEventLogW(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct eventlog_OpenUnknown0 *unknown0 /* [in] [unique] */,
				       struct lsa_String *logname /* [in] [ref] */,
				       struct lsa_String *servername /* [in] [ref] */,
				       uint32_t unknown2 /* [in]  */,
				       uint32_t unknown3 /* [in]  */,
				       struct policy_handle *handle /* [out] [ref] */);
NTSTATUS rpccli_eventlog_RegisterEventSourceW(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_OpenBackupEventLogW(struct rpc_pipe_client *cli,
					     TALLOC_CTX *mem_ctx);
NTSTATUS rpccli_eventlog_ReadEventLogW(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       struct policy_handle *handle /* [in] [ref] */,
				       uint32_t flags /* [in]  */,
				       uint32_t offset /* [in]  */,
				       uint32_t number_of_bytes /* [in] [range(0,0x7FFFF)] */,
				       uint8_t *data /* [out] [ref,size_is(number_of_bytes)] */,
				       uint32_t *sent_size /* [out] [ref] */,
				       uint32_t *real_size /* [out] [ref] */);
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
				       struct policy_handle *handle /* [in] [ref] */);
#endif /* __CLI_EVENTLOG__ */

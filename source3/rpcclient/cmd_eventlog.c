/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Günther Deschner 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpcclient.h"

static NTSTATUS get_eventlog_handle(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    const char *log,
				    struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_OpenUnknown0 unknown0;
	struct lsa_String logname, servername;

	unknown0.unknown0 = 0x005c;
	unknown0.unknown1 = 0x0001;

	init_lsa_String(&logname, log);
	init_lsa_String(&servername, NULL);

	status = rpccli_eventlog_OpenEventLogW(cli, mem_ctx,
					       &unknown0,
					       &logname,
					       &servername,
					       0x00000001, /* major */
					       0x00000001, /* minor */
					       handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS cmd_eventlog_readlog(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc,
				     const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;

	uint32_t flags = EVENTLOG_BACKWARDS_READ |
			 EVENTLOG_SEQUENTIAL_READ;
	uint32_t offset = 0;
	uint32_t number_of_bytes = 0;
	uint8_t *data = NULL;
	uint32_t sent_size = 0;
	uint32_t real_size = 0;

	if (argc < 2 || argc > 4) {
		printf("Usage: %s logname [offset]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc >= 3) {
		offset = atoi(argv[2]);
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	while (1) {
		status = rpccli_eventlog_ReadEventLogW(cli, mem_ctx,
						       &handle,
						       flags,
						       offset,
						       number_of_bytes,
						       data,
						       &sent_size,
						       &real_size);
		if (NT_STATUS_EQUAL(status, NT_STATUS_BUFFER_TOO_SMALL) &&
		    real_size > 0 ) {
			number_of_bytes = real_size;
			data = talloc_array(mem_ctx, uint8_t, real_size);
			continue;
		}

		number_of_bytes = 0;

		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		{
			enum ndr_err_code ndr_err;
			DATA_BLOB blob;
			struct eventlog_Record rec;

			blob = data_blob_const(data, sent_size);

			ndr_err = ndr_pull_struct_blob_all(&blob, mem_ctx, NULL,
							   &rec,
							   (ndr_pull_flags_fn_t)ndr_pull_eventlog_Record);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				status = ndr_map_error2ntstatus(ndr_err);
				goto done;
			}

			NDR_PRINT_DEBUG(eventlog_Record, &rec);
		}

		offset++;
	}

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}

static NTSTATUS cmd_eventlog_numrecords(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					int argc,
					const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;
	uint32_t number = 0;

	if (argc != 2) {
		printf("Usage: %s logname\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_eventlog_GetNumRecords(cli, mem_ctx,
					       &handle,
					       &number);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	printf("number of records: %d\n", number);

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}

static NTSTATUS cmd_eventlog_oldestrecord(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;
	uint32_t oldest_entry = 0;

	if (argc != 2) {
		printf("Usage: %s logname\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_eventlog_GetOldestRecord(cli, mem_ctx,
						 &handle,
						 &oldest_entry);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	printf("oldest entry: %d\n", oldest_entry);

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}

static NTSTATUS cmd_eventlog_reportevent(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 int argc,
					 const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;

	uint16_t num_of_strings = 1;
	uint32_t data_size = 0;
	struct lsa_String servername;
	struct lsa_String *strings;
	uint8_t *data = NULL;
	uint32_t record_number = 0;
	time_t time_written = 0;

	if (argc != 2) {
		printf("Usage: %s logname\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	strings = talloc_array(mem_ctx, struct lsa_String, num_of_strings);
	if (!strings) {
		return NT_STATUS_NO_MEMORY;
	}

	init_lsa_String(&strings[0], "test event written by rpcclient\n");
	init_lsa_String(&servername, NULL);

	status = rpccli_eventlog_ReportEventW(cli, mem_ctx,
					      &handle,
					      time(NULL),
					      EVENTLOG_INFORMATION_TYPE,
					      0, /* event_category */
					      0, /* event_id */
					      num_of_strings,
					      data_size,
					      &servername,
					      NULL, /* user_sid */
					      &strings,
					      data,
					      0, /* flags */
					      &record_number,
					      &time_written);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	printf("entry: %d written at %s\n", record_number,
		http_timestring(talloc_tos(), time_written));

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}

static NTSTATUS cmd_eventlog_reporteventsource(struct rpc_pipe_client *cli,
					       TALLOC_CTX *mem_ctx,
					       int argc,
					       const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;

	uint16_t num_of_strings = 1;
	uint32_t data_size = 0;
	struct lsa_String servername, sourcename;
	struct lsa_String *strings;
	uint8_t *data = NULL;
	uint32_t record_number = 0;
	time_t time_written = 0;

	if (argc != 2) {
		printf("Usage: %s logname\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	strings = talloc_array(mem_ctx, struct lsa_String, num_of_strings);
	if (!strings) {
		return NT_STATUS_NO_MEMORY;
	}

	init_lsa_String(&strings[0], "test event written by rpcclient\n");
	init_lsa_String(&servername, NULL);
	init_lsa_String(&sourcename, "rpcclient");

	status = rpccli_eventlog_ReportEventAndSourceW(cli, mem_ctx,
						       &handle,
						       time(NULL),
						       EVENTLOG_INFORMATION_TYPE,
						       0, /* event_category */
						       0, /* event_id */
						       &sourcename,
						       num_of_strings,
						       data_size,
						       &servername,
						       NULL, /* user_sid */
						       &strings,
						       data,
						       0, /* flags */
						       &record_number,
						       &time_written);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	printf("entry: %d written at %s\n", record_number,
		http_timestring(talloc_tos(), time_written));

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}

static NTSTATUS cmd_eventlog_registerevsource(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv)
{
	NTSTATUS status;
	struct policy_handle log_handle;
	struct lsa_String module_name, reg_module_name;
	struct eventlog_OpenUnknown0 unknown0;

	unknown0.unknown0 = 0x005c;
	unknown0.unknown1 = 0x0001;

	if (argc != 2) {
		printf("Usage: %s logname\n", argv[0]);
		return NT_STATUS_OK;
	}

	init_lsa_String(&module_name, "rpcclient");
	init_lsa_String(&reg_module_name, NULL);

	status = rpccli_eventlog_RegisterEventSourceW(cli, mem_ctx,
						      &unknown0,
						      &module_name,
						      &reg_module_name,
						      1, /* major_version */
						      1, /* minor_version */
						      &log_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

 done:
	rpccli_eventlog_DeregisterEventSource(cli, mem_ctx, &log_handle);

	return status;
}

static NTSTATUS cmd_eventlog_backuplog(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv)
{
	NTSTATUS status;
	struct policy_handle handle;
	struct lsa_String backup_filename;
	const char *tmp;

	if (argc != 3) {
		printf("Usage: %s logname backupname\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = get_eventlog_handle(cli, mem_ctx, argv[1], &handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	tmp = talloc_asprintf(mem_ctx, "\\??\\%s", argv[2]);
	if (!tmp) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	init_lsa_String(&backup_filename, tmp);

	status = rpccli_eventlog_BackupEventLogW(cli, mem_ctx,
						 &handle,
						 &backup_filename);

 done:
	rpccli_eventlog_CloseEventLog(cli, mem_ctx, &handle);

	return status;
}


struct cmd_set eventlog_commands[] = {
	{ "EVENTLOG" },
	{ "eventlog_readlog",		RPC_RTYPE_NTSTATUS,	cmd_eventlog_readlog,		NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Read Eventlog", "" },
	{ "eventlog_numrecord",		RPC_RTYPE_NTSTATUS,	cmd_eventlog_numrecords,	NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Get number of records", "" },
	{ "eventlog_oldestrecord",	RPC_RTYPE_NTSTATUS,	cmd_eventlog_oldestrecord,	NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Get oldest record", "" },
	{ "eventlog_reportevent",	RPC_RTYPE_NTSTATUS,	cmd_eventlog_reportevent,	NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Report event", "" },
	{ "eventlog_reporteventsource",	RPC_RTYPE_NTSTATUS,	cmd_eventlog_reporteventsource,	NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Report event and source", "" },
	{ "eventlog_registerevsource",	RPC_RTYPE_NTSTATUS,	cmd_eventlog_registerevsource,	NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Register event source", "" },
	{ "eventlog_backuplog",		RPC_RTYPE_NTSTATUS,	cmd_eventlog_backuplog,		NULL,	&ndr_table_eventlog.syntax_id,	NULL,	"Backup Eventlog File", "" },
	{ NULL }
};

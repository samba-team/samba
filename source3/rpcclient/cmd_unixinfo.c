/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "rpcclient.h"
#include "../librpc/gen_ndr/ndr_unixinfo_c.h"
#include "libcli/security/dom_sid.h"

static NTSTATUS cmd_unixinfo_uidtosid(
	struct rpc_pipe_client *cli,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	uint64_t uid = 0;
	struct dom_sid sid = { .sid_rev_num = 0, };
	struct dom_sid_buf buf;
	NTSTATUS status, result;

	if (argc != 2) {
		printf("Usage: %s [uid]\n", argv[0]);
		return NT_STATUS_OK;
	}
	uid = atoi(argv[1]);

	status = dcerpc_unixinfo_UidToSid(b, mem_ctx, uid, &sid, &result);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"dcerpc_unixinfo_UidToSid failed: %s\n",
			nt_errstr(status));
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		fprintf(stderr,
			"dcerpc_unixinfo_UidToSid returned: %s\n",
			nt_errstr(result));
		status = result;
		goto done;
	}

	printf("UidToSid(%"PRIu64")=%s\n",
	       uid,
	       dom_sid_str_buf(&sid, &buf));

done:
	return status;
}

static NTSTATUS cmd_unixinfo_getpwuid(
	struct rpc_pipe_client *cli,
	TALLOC_CTX *mem_ctx,
	int argc,
	const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	uint32_t count = 1;
	uint64_t uids = 0;
	struct unixinfo_GetPWUidInfo infos = { .homedir = NULL, };
	NTSTATUS status, result;

	if (argc != 2) {
		printf("Usage: %s [uid]\n", argv[0]);
		return NT_STATUS_OK;
	}
	uids = atoi(argv[1]);

	status = dcerpc_unixinfo_GetPWUid(
		b, mem_ctx, &count, &uids, &infos, &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"dcerpc_unixinfo_GetPWUid failed: %s\n",
			nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(result)) {
		fprintf(stderr,
			"dcerpc_unixinfo_GetPWUid returned: %s\n",
			nt_errstr(result));
		return result;
	}

	printf("status=%s, homedir=%s, shell=%s\n",
	       nt_errstr(infos.status),
	       infos.homedir,
	       infos.shell);

done:
	return status;
}

/* List of commands exported by this module */

struct cmd_set unixinfo_commands[] = {

	{
		.name = "UNIXINFO",
	},

	{
		.name               = "getpwuid",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_unixinfo_getpwuid,
		.wfn                = NULL,
		.table              = &ndr_table_unixinfo,
		.rpc_pipe           = NULL,
		.description        = "Get shell and homedir",
		.usage              = "",
	},
	{
		.name               = "uidtosid",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_unixinfo_uidtosid,
		.wfn                = NULL,
		.table              = &ndr_table_unixinfo,
		.rpc_pipe           = NULL,
		.description        = "Convert uid to sid",
		.usage              = "",
	},
	{
		.name = NULL
	},
};

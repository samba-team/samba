/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Volker Lendecke 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpcclient.h"

static NTSTATUS cmd_unixinfo_uid2sid(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	uid_t uid;
	DOM_SID sid;
	NTSTATUS result;

	if (argc != 2) {
		printf("Usage: %s uid\n", argv[0]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	uid = atoi(argv[1]);
	result = rpccli_unixinfo_UidToSid(cli, mem_ctx, uid, &sid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	printf("%s\n", sid_string_static(&sid));

done:
	return result;
}

static NTSTATUS cmd_unixinfo_sid2uid(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	uint64_t uid;
	DOM_SID sid;
	NTSTATUS result;

	if (argc != 2) {
		printf("Usage: %s sid\n", argv[0]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!string_to_sid(&sid, argv[1])) {
		result = NT_STATUS_INVALID_SID;
		goto done;
	}

	result = rpccli_unixinfo_SidToUid(cli, mem_ctx, sid, &uid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	printf("%llu\n", (unsigned long long)uid);

done:
	return result;
}

static NTSTATUS cmd_unixinfo_gid2sid(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	gid_t gid;
	DOM_SID sid;
	NTSTATUS result;

	if (argc != 2) {
		printf("Usage: %s gid\n", argv[0]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	gid = atoi(argv[1]);

	result = rpccli_unixinfo_GidToSid(cli, mem_ctx, gid, &sid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	printf("%s\n", sid_string_static(&sid));

done:
	return result;
}

static NTSTATUS cmd_unixinfo_sid2gid(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	uint64_t gid;
	DOM_SID sid;
	NTSTATUS result;

	if (argc != 2) {
		printf("Usage: %s sid\n", argv[0]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!string_to_sid(&sid, argv[1])) {
		result = NT_STATUS_INVALID_SID;
		goto done;
	}

	result = rpccli_unixinfo_SidToGid(cli, mem_ctx, sid, &gid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	printf("%llu\n", (unsigned long long)gid);

done:
	return result;
}

static NTSTATUS cmd_unixinfo_getpwuid(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      int argc, const char **argv)
{
	uint64_t *uids;
	unsigned int i, num_uids;
	struct unixinfo_GetPWUidInfo *info;
	NTSTATUS result;

	if (argc < 2) {
		printf("Usage: %s uid [uid2 uid3 ...]\n", argv[0]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_uids = argc-1;
	uids = TALLOC_ARRAY(mem_ctx, uint64_t, num_uids);

	if (uids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_uids; i++) {
		uids[i] = atoi(argv[i+1]);
	}

	result = rpccli_unixinfo_GetPWUid(cli, mem_ctx, &num_uids, uids,
					  &info);

	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	for (i=0; i<num_uids; i++) {
		if (NT_STATUS_IS_OK(info[i].status)) {
			printf("%llu:%s:%s\n", (unsigned long long)uids[i],
			       info[i].homedir, info[i].shell);
		} else {
			printf("%llu:%s\n", (unsigned long long)uids[i],
			       nt_errstr(info[i].status));
		}
	}

	return NT_STATUS_OK;
}

/* List of commands exported by this module */

struct cmd_set unixinfo_commands[] = {

	{ "UNIXINFO" },

	{ "uid2sid", RPC_RTYPE_NTSTATUS, cmd_unixinfo_uid2sid, NULL,
	  PI_UNIXINFO, NULL, "Convert a uid to a sid", "" },
	{ "sid2uid", RPC_RTYPE_NTSTATUS, cmd_unixinfo_sid2uid, NULL,
	  PI_UNIXINFO, NULL, "Convert a sid to a uid", "" },
	{ "gid2sid", RPC_RTYPE_NTSTATUS, cmd_unixinfo_gid2sid, NULL,
	  PI_UNIXINFO, NULL, "Convert a gid to a sid", "" },
	{ "sid2gid", RPC_RTYPE_NTSTATUS, cmd_unixinfo_sid2gid, NULL,
	  PI_UNIXINFO, NULL, "Convert a sid to a gid", "" },
	{ "getpwuid", RPC_RTYPE_NTSTATUS, cmd_unixinfo_getpwuid, NULL,
	  PI_UNIXINFO, NULL, "Get passwd info", "" },
	{ NULL }
};

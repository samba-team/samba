/*
   Unix SMB/CIFS implementation.
   RPC Spotlight client

   Copyright (C) Ralph Boehme 2018

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
#include "libsmb/libsmb.h"
#include "../librpc/gen_ndr/ndr_mdssvc_c.h"
#include "../rpc_server/mdssvc/mdssvc.h"
#include "../rpc_server/mdssvc/dalloc.h"
#include "../rpc_server/mdssvc/marshalling.h"

static NTSTATUS cmd_mdssvc_fetch_properties(
			struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			int argc, const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	uint32_t device_id = 0x2f000045;
	uint32_t unkn1 = 23;
	uint32_t unkn2 = 0;
	struct policy_handle share_handle;
	char share_path[1025];
	uint32_t mds_status;
	uint32_t flags;	     /* server always returns 0x6b000001 ? */
	uint32_t unkn3;	     /* server always returns 0 ? */
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	ssize_t len;
	uint32_t max_fragment_size = 64 * 1024;
	DALLOC_CTX *d, *mds_reply;
	uint64_t *uint64var;
	sl_array_t *array1, *array2;
	uint32_t unkn4;
	int result;
	bool ok;

	if (argc != 3) {
		printf("Usage: %s SHARENAME MOUNTPATH\n", argv[0]);
		return NT_STATUS_OK;
	}

	status = dcerpc_mdssvc_open(b, mem_ctx,
				    &device_id,
				    &unkn1,
				    &unkn2,
				    argv[2],
				    argv[1],
				    share_path,
				    &share_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dcerpc_mdssvc_unknown1(b, mem_ctx,
					&share_handle,
					0,
					device_id,
					unkn1,
					0,
					geteuid(),
					getegid(),
					&mds_status,
					&flags,
					&unkn3);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	mds_reply = dalloc_new(mem_ctx);
	if (mds_reply == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	array1 = dalloc_zero(d, sl_array_t);
	if (array1 == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	array2 = dalloc_zero(d, sl_array_t);
	if (array2 == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = dalloc_stradd(array2, "fetchPropertiesForContext:");
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	uint64var = talloc_zero_array(mem_ctx, uint64_t, 2);
	if (uint64var == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	talloc_set_name(uint64var, "uint64_t *");

	result = dalloc_add(array2, &uint64var[0], uint64_t *);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	result = dalloc_add(array1, array2, sl_array_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	result = dalloc_add(d, array1, sl_array_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	request_blob.spotlight_blob = talloc_array(mem_ctx, uint8_t, max_fragment_size);
	if (request_blob.spotlight_blob == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	request_blob.size = max_fragment_size;

	response_blob.spotlight_blob = talloc_array(mem_ctx, uint8_t, max_fragment_size);
	if (response_blob.spotlight_blob == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	response_blob.size = max_fragment_size;

	len = sl_pack(d, (char *)request_blob.spotlight_blob, request_blob.size);
	if (len == -1) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	request_blob.length = len;
	request_blob.size = len;

	status =  dcerpc_mdssvc_cmd(b, mem_ctx,
				    &share_handle,
				    0,
				    device_id,
				    23,
				    0,
				    0x6b000001,
				    request_blob,
				    0,
				    max_fragment_size,
				    1,
				    max_fragment_size,
				    0,
				    0,
				    &mds_status,
				    &response_blob,
				    &unkn4);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	ok = sl_unpack(mds_reply, (char *)response_blob.spotlight_blob,
		       response_blob.length);
	if (!ok) {
		DEBUG(1, ("error unpacking Spotlight RPC blob\n"));
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	DEBUG(0, ("%s", dalloc_dump(mds_reply, 0)));

done:
	return status;
}

static NTSTATUS cmd_mdssvc_fetch_attributes(
			struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			int argc, const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	NTSTATUS status;
	uint32_t device_id = 0x2f000045;
	uint32_t unkn1 = 23;
	uint32_t unkn2 = 0;
	struct policy_handle share_handle;
	char share_path[1025];
	uint32_t mds_status;
	uint32_t flags;	     /* server always returns 0x6b000001 ? */
	uint32_t unkn3;	     /* server always returns 0 ? */
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	ssize_t len;
	uint32_t max_fragment_size = 64 * 1024;
	DALLOC_CTX *d, *mds_reply;
	uint64_t *uint64var;
	sl_array_t *array;
	sl_array_t *cmd_array;
	sl_array_t *attr_array;
	sl_cnids_t *cnids;
	uint64_t cnid;
	uint32_t unkn4;
	int result;
	bool ok;

	if (argc != 4) {
		printf("Usage: %s SHARENAME MOUNTPATH CNID\n", argv[0]);
		return NT_STATUS_OK;
	}

	ok = conv_str_u64(argv[3], &cnid);
	if (!ok) {
		printf("Failed to parse: %s\n", argv[3]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_mdssvc_open(b, mem_ctx,
				    &device_id,
				    &unkn1,
				    &unkn2,
				    argv[2],
				    argv[1],
				    share_path,
				    &share_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dcerpc_mdssvc_unknown1(b, mem_ctx,
					&share_handle,
					0,
					device_id,
					unkn1,
					0,
					geteuid(),
					getegid(),
					&mds_status,
					&flags,
					&unkn3);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	array = dalloc_zero(d, sl_array_t);
	if (array == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = dalloc_add(d, array, sl_array_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	cmd_array = dalloc_zero(d, sl_array_t);
	if (cmd_array == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = dalloc_add(array, cmd_array, sl_array_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	result = dalloc_stradd(cmd_array,
			       "fetchAttributes:forOIDArray:context:");
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	uint64var = talloc_zero_array(mem_ctx, uint64_t, 2);
	if (uint64var == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	talloc_set_name(uint64var, "uint64_t *");
	uint64var[0] = 0x500a;
	uint64var[1] = 0;

	result = dalloc_add(cmd_array, &uint64var[0], uint64_t *);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	attr_array = dalloc_zero(d, sl_array_t);
	if (attr_array == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = dalloc_add(array, attr_array, sl_array_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	result = dalloc_stradd(attr_array, "kMDItemPath");
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	/* CNIDs */
	cnids = talloc_zero(array, sl_cnids_t);
	if (cnids == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	cnids->ca_cnids = dalloc_new(cnids);
	if (cnids->ca_cnids == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	cnids->ca_unkn1 = 0xadd;
	cnids->ca_context = 0x6b000020;

	result = dalloc_add_copy(cnids->ca_cnids, &cnid, uint64_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	result = dalloc_add(array, cnids, sl_cnids_t);
	if (result != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	request_blob.spotlight_blob = talloc_array(mem_ctx,
						   uint8_t,
						   max_fragment_size);
	if (request_blob.spotlight_blob == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	request_blob.size = max_fragment_size;

	response_blob.spotlight_blob = talloc_array(mem_ctx,
						    uint8_t,
						    max_fragment_size);
	if (response_blob.spotlight_blob == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	response_blob.size = max_fragment_size;

	len = sl_pack(d, (char *)request_blob.spotlight_blob, request_blob.size);
	if (len == -1) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	request_blob.length = len;
	request_blob.size = len;

	status = dcerpc_mdssvc_cmd(b, mem_ctx,
				   &share_handle,
				   0,
				   device_id,
				   23,
				   0,
				   0x6b000001,
				   request_blob,
				   0,
				   max_fragment_size,
				   1,
				   max_fragment_size,
				   0,
				   0,
				   &mds_status,
				   &response_blob,
				   &unkn4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_mdssvc_cmd failed: %s\n", nt_errstr(status));
		goto done;
	}

	if (response_blob.length == 0) {
		printf("mdssvc returned empty response\n");
		status = NT_STATUS_RPC_PROTOCOL_ERROR;
		goto done;
	}

	mds_reply = dalloc_new(mem_ctx);
	if (mds_reply == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ok = sl_unpack(mds_reply, (char *)response_blob.spotlight_blob,
		       response_blob.length);
	if (!ok) {
		printf("Unpacking Spotlight RPC blob failed\n");
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	printf("%s", dalloc_dump(mds_reply, 0));

done:
	return status;
}

/* List of commands exported by this module */

struct cmd_set spotlight_commands[] = {

	{
		.name = "MDSSVC"
	},
	{
		.name = "fetch_properties",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_mdssvc_fetch_properties,
		.table = &ndr_table_mdssvc,
		.description = "Fetch connection properties",
		.usage = "",
	},
	{
		.name = "fetch_attributes",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_mdssvc_fetch_attributes,
		.table = &ndr_table_mdssvc,
		.description = "Fetch attributes for a CNID",
		.usage = "",
	},
	{0}
};

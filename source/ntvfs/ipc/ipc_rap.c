/* 
   Unix SMB/CIFS implementation.
   RAP handlers

   Copyright (C) Volker Lendecke 2004

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

#define NERR_Success 0
#define NERR_badpass 86
#define NERR_notsupported 50

struct rap_string_heap {
	TALLOC_CTX *mem_ctx;
	int offset;
	int num_strings;
	const char **strings;
};

struct rap_heap_save {
	int offset, num_strings;
};

static void rap_heap_save(struct rap_string_heap *heap,
			  struct rap_heap_save *save)
{
	save->offset = heap->offset;
	save->num_strings = heap->num_strings;
}

static void rap_heap_restore(struct rap_string_heap *heap,
			     struct rap_heap_save *save)
{
	heap->offset = save->offset;
	heap->num_strings = save->num_strings;
}

struct rap_call {
	TALLOC_CTX *mem_ctx;
	uint16 callno;
	const char *paramdesc;
	const char *datadesc;

	uint16 status;
	uint16 convert;

	uint16 rcv_paramlen, rcv_datalen;

	struct ndr_push *ndr_push_param;
	struct ndr_push *ndr_push_data;
	struct rap_string_heap *heap;

	struct ndr_pull *ndr_pull_param;
	struct ndr_pull *ndr_pull_data;
};

#define RAPNDR_FLAGS (LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM);

static struct rap_call *new_rap_srv_call(TALLOC_CTX *mem_ctx,
					 struct smb_trans2 *trans)
{
	struct rap_call *call;

	call = talloc_p(mem_ctx, struct rap_call);

	if (call == NULL)
		return NULL;

	ZERO_STRUCTP(call);

	call->mem_ctx = mem_ctx;

	call->ndr_pull_param = ndr_pull_init_blob(&trans->in.params, mem_ctx);
	call->ndr_pull_param->flags = RAPNDR_FLAGS;

	call->ndr_pull_data = ndr_pull_init_blob(&trans->in.data, mem_ctx);
	call->ndr_pull_data->flags = RAPNDR_FLAGS;

	call->heap = talloc_p(mem_ctx, struct rap_string_heap);

	if (call->heap == NULL)
		return NULL;

	ZERO_STRUCTP(call->heap);

	call->heap->mem_ctx = mem_ctx;

	return call;
}

static NTSTATUS rap_srv_pull_word(struct rap_call *call, uint16 *result)
{
	if (*call->paramdesc++ != 'W')
		return NT_STATUS_INVALID_PARAMETER;

	return ndr_pull_uint16(call->ndr_pull_param, result);
}

static NTSTATUS rap_srv_pull_dword(struct rap_call *call, uint32 *result)
{
	if (*call->paramdesc++ != 'D')
		return NT_STATUS_INVALID_PARAMETER;

	return ndr_pull_uint32(call->ndr_pull_param, result);
}

static NTSTATUS rap_srv_pull_string(struct rap_call *call, const char **result)
{
	char paramdesc = *call->paramdesc++;

	if (paramdesc == 'O') {
		*result = NULL;
		return NT_STATUS_OK;
	}

	if (paramdesc != 'z')
		return NT_STATUS_INVALID_PARAMETER;

	return ndr_pull_string(call->ndr_pull_param, NDR_SCALARS, result);
}

static NTSTATUS rap_srv_pull_bufsize(struct rap_call *call, uint16 *bufsize)
{
	NTSTATUS result;

	if ( (*call->paramdesc++ != 'r') || (*call->paramdesc++ != 'L') )
		return NT_STATUS_INVALID_PARAMETER;

	result = ndr_pull_uint16(call->ndr_pull_param, bufsize);

	if (!NT_STATUS_IS_OK(result))
		return result;

	call->heap->offset = *bufsize;

	return NT_STATUS_OK;
}

static NTSTATUS rap_srv_pull_expect_multiple(struct rap_call *call)
{
	if ( (*call->paramdesc++ != 'e') || (*call->paramdesc++ != 'h') )
		return NT_STATUS_INVALID_PARAMETER;

	return NT_STATUS_OK;
}

static NTSTATUS rap_push_string(struct ndr_push *data_push,
				struct rap_string_heap *heap,
				const char *str)
{
	size_t space;

	if (str == NULL)
		str = "";

	space = strlen(str)+1;

	if (heap->offset < space)
		return NT_STATUS_BUFFER_TOO_SMALL;

	heap->offset -= space;

	NDR_CHECK(ndr_push_uint16(data_push, heap->offset));
	NDR_CHECK(ndr_push_uint16(data_push, 0));

	heap->strings = talloc_realloc_p(heap->mem_ctx,
					 heap->strings,
					 const char *,
					 heap->num_strings + 1);

	if (heap->strings == NULL)
		return NT_STATUS_NO_MEMORY;

	heap->strings[heap->num_strings] = str;
	heap->num_strings += 1;

	return NT_STATUS_OK;
}

#define NDR_OK(call) do { result = call; \
			     if (NT_STATUS_EQUAL(result, NT_STATUS_BUFFER_TOO_SMALL)) \
				goto buffer_overflow; \
                             if (!NT_STATUS_IS_OK(result)) \
				goto done; \
                        } while (0)

static NTSTATUS _rap_netshareenum(struct smbsrv_request *req,
				  struct rap_call *call)
{
	struct rap_NetShareEnum r;
	NTSTATUS result;

	NDR_OK(rap_srv_pull_word(call, &r.in.level));
	NDR_OK(rap_srv_pull_bufsize(call, &r.in.bufsize));
	NDR_OK(rap_srv_pull_expect_multiple(call));

	switch(r.in.level) {
	case 0:
		if (strcmp(call->datadesc, "B13") != 0)
			return NT_STATUS_INVALID_PARAMETER;
		break;
	case 1:
		if (strcmp(call->datadesc, "B13BWz") != 0)
			return NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
		break;
	}

	result = rap_netshareenum(req, &r);

	if (!NT_STATUS_IS_OK(result))
		return result;

	for (r.out.count = 0; r.out.count < r.out.available; r.out.count++) {

		int i = r.out.count;
		struct ndr_push_save data_save;
		struct rap_heap_save heap_save;

		ndr_push_save(call->ndr_push_data, &data_save);
		rap_heap_save(call->heap, &heap_save);

		switch(r.in.level) {
		case 0:
			NDR_OK(ndr_push_bytes(call->ndr_push_data,
					      r.out.info[i].info0.name,
					      sizeof(r.out.info[i].info0.name)));
			break;
		case 1:
			NDR_OK(ndr_push_bytes(call->ndr_push_data,
					      r.out.info[i].info1.name,
					      sizeof(r.out.info[i].info1.name)));
			NDR_OK(ndr_push_uint8(call->ndr_push_data,
					      r.out.info[i].info1.pad));
			NDR_OK(ndr_push_uint16(call->ndr_push_data,
					       r.out.info[i].info1.type));

			NDR_OK(rap_push_string(call->ndr_push_data,
					       call->heap,
					       r.out.info[i].info1.comment));

			break;
		}

		if (call->ndr_push_data->offset > call->heap->offset) {

	buffer_overflow:

			ndr_push_restore(call->ndr_push_data, &data_save);
			rap_heap_restore(call->heap, &heap_save);
			break;
		}
	}

	call->status = r.out.status;

	NDR_CHECK(ndr_push_uint16(call->ndr_push_param, r.out.count));
	NDR_CHECK(ndr_push_uint16(call->ndr_push_param, r.out.available));

	result = NT_STATUS_OK;

 done:
	return result;
}

static NTSTATUS _rap_netserverenum2(struct smbsrv_request *req,
				    struct rap_call *call)
{
	struct rap_NetServerEnum2 r;
	NTSTATUS result;

	NDR_OK(rap_srv_pull_word(call, &r.in.level));
	NDR_OK(rap_srv_pull_bufsize(call, &r.in.bufsize));
	NDR_OK(rap_srv_pull_expect_multiple(call));
	NDR_OK(rap_srv_pull_dword(call, &r.in.servertype));
	NDR_OK(rap_srv_pull_string(call, &r.in.domain));

	switch(r.in.level) {
	case 0:
		if (strcmp(call->datadesc, "B16") != 0)
			return NT_STATUS_INVALID_PARAMETER;
		break;
	case 1:
		if (strcmp(call->datadesc, "B16BBDz") != 0)
			return NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
		break;
	}

	result = rap_netserverenum2(req, &r);

	if (!NT_STATUS_IS_OK(result))
		return result;

	for (r.out.count = 0; r.out.count < r.out.available; r.out.count++) {

		int i = r.out.count;
		struct ndr_push_save data_save;
		struct rap_heap_save heap_save;

		ndr_push_save(call->ndr_push_data, &data_save);
		rap_heap_save(call->heap, &heap_save);

		switch(r.in.level) {
		case 0:
			NDR_OK(ndr_push_bytes(call->ndr_push_data,
					      r.out.info[i].info0.name,
					      sizeof(r.out.info[i].info0.name)));
			break;
		case 1:
			NDR_OK(ndr_push_bytes(call->ndr_push_data,
					      r.out.info[i].info1.name,
					      sizeof(r.out.info[i].info1.name)));
			NDR_OK(ndr_push_uint8(call->ndr_push_data,
					      r.out.info[i].info1.version_major));
			NDR_OK(ndr_push_uint8(call->ndr_push_data,
					      r.out.info[i].info1.version_minor));
			NDR_OK(ndr_push_uint32(call->ndr_push_data,
					       r.out.info[i].info1.servertype));

			NDR_OK(rap_push_string(call->ndr_push_data,
					       call->heap,
					       r.out.info[i].info1.comment));

			break;
		}

		if (call->ndr_push_data->offset > call->heap->offset) {

	buffer_overflow:

			ndr_push_restore(call->ndr_push_data, &data_save);
			rap_heap_restore(call->heap, &heap_save);
			break;
		}
	}

	call->status = r.out.status;

	NDR_CHECK(ndr_push_uint16(call->ndr_push_param, r.out.count));
	NDR_CHECK(ndr_push_uint16(call->ndr_push_param, r.out.available));

	result = NT_STATUS_OK;

 done:
	return result;
}

static NTSTATUS api_Unsupported(struct smbsrv_request *req,
				struct rap_call *call)
{
	call->status = NERR_notsupported;
	call->convert = 0;
	return NT_STATUS_OK;
}

#define RAP_NetShareEnum 0
#define RAP_NetServerEnum2 104

static const struct
{
	const char *name;
	int id;
	NTSTATUS (*fn)(struct smbsrv_request *req, struct rap_call *call);
} api_commands[] = {
	{"NetShareEnum", RAP_NetShareEnum, _rap_netshareenum },
	{"NetServerEnum2", RAP_NetServerEnum2, _rap_netserverenum2 },
	{NULL, -1, api_Unsupported}
};

NTSTATUS ipc_rap_call(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	int i;
	NTSTATUS result;
	struct rap_call *call;
	DATA_BLOB result_param, result_data;
	struct ndr_push *final_param;
	struct ndr_push *final_data;

	call = new_rap_srv_call(req, trans);

	if (call == NULL)
		return NT_STATUS_NO_MEMORY;

	NDR_CHECK(ndr_pull_uint16(call->ndr_pull_param, &call->callno));
	NDR_CHECK(ndr_pull_string(call->ndr_pull_param, NDR_SCALARS,
				  &call->paramdesc));
	NDR_CHECK(ndr_pull_string(call->ndr_pull_param, NDR_SCALARS,
				  &call->datadesc));

	call->ndr_push_param = ndr_push_init_ctx(req);
	call->ndr_push_data = ndr_push_init_ctx(req);

	if ((call->ndr_push_param == NULL) || (call->ndr_push_data == NULL))
		return NT_STATUS_NO_MEMORY;

	call->ndr_push_param->flags = RAPNDR_FLAGS;
	call->ndr_push_data->flags = RAPNDR_FLAGS;

	result = NT_STATUS_NOT_IMPLEMENTED;

	for (i=0; api_commands[i].name != NULL; i++) {
		if (api_commands[i].id == call->callno) {
			DEBUG(5, ("Running RAP call %s\n",
				  api_commands[i].name));
			result = api_commands[i].fn(req, call);
			break;
		}
	}

	if (!NT_STATUS_IS_OK(result))
		return result;

	result_param = ndr_push_blob(call->ndr_push_param);
	result_data = ndr_push_blob(call->ndr_push_data);

	final_param = ndr_push_init_ctx(req);
	final_data = ndr_push_init_ctx(req);

	if ((final_param == NULL) || (final_data == NULL))
		return NT_STATUS_NO_MEMORY;

	final_param->flags = RAPNDR_FLAGS;
	final_data->flags = RAPNDR_FLAGS;

	NDR_CHECK(ndr_push_uint16(final_param, call->status));
	NDR_CHECK(ndr_push_uint16(final_param,
				  call->heap->offset - result_data.length));
	NDR_CHECK(ndr_push_bytes(final_param, result_param.data,
				 result_param.length));

	NDR_CHECK(ndr_push_bytes(final_data, result_data.data,
				 result_data.length));

	for (i=call->heap->num_strings-1; i>=0; i--)
		NDR_CHECK(ndr_push_string(final_data, NDR_SCALARS,
					  call->heap->strings[i]));

	trans->out.setup_count = 0;
	trans->out.setup = NULL;
	trans->out.params = ndr_push_blob(final_param);
	trans->out.data = ndr_push_blob(final_data);

	return result;
}

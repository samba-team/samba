/* 
   Unix SMB/CIFS implementation.
   test suite for various RAP operations
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

struct rap_call {
	TALLOC_CTX *mem_ctx;
	uint16 callno;
	char *paramdesc;
	const char *datadesc;

	uint16 status;
	uint16 convert;
	
	uint16 rcv_paramlen, rcv_datalen;

	struct ndr_push *ndr_push_param;
	struct ndr_push *ndr_push_data;
	struct ndr_pull *ndr_pull_param;
	struct ndr_pull *ndr_pull_data;
};

#define RAPNDR_FLAGS (LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM);

static struct rap_call *new_rap_cli_call(uint16 callno)
{
	struct rap_call *call;
	TALLOC_CTX *mem_ctx = talloc_init("rap_call");

	if (mem_ctx == NULL)
		return NULL;

	call = talloc_p(mem_ctx, struct rap_call);

	if (call == NULL)
		return NULL;

	ZERO_STRUCTP(call);

	call->callno = callno;
	call->rcv_paramlen = 4;
	call->mem_ctx = mem_ctx;

	call->ndr_push_param = ndr_push_init_ctx(mem_ctx);
	call->ndr_push_param->flags = RAPNDR_FLAGS;

	call->ndr_push_data = ndr_push_init_ctx(mem_ctx);
	call->ndr_push_data->flags = RAPNDR_FLAGS;

	return call;
}

static void destroy_rap_call(struct rap_call *call)
{
	talloc_destroy(call->mem_ctx);
}

static void rap_cli_push_paramdesc(struct rap_call *call, char desc)
{
	int len = 0;

	if (call->paramdesc != NULL)
		len = strlen(call->paramdesc);

	call->paramdesc = talloc_realloc(call->mem_ctx,
					 call->paramdesc,
					 len+2);
	call->paramdesc[len] = desc;
	call->paramdesc[len+1] = '\0';
}

static void rap_cli_push_word(struct rap_call *call, uint16 val)
{
	rap_cli_push_paramdesc(call, 'W');
	ndr_push_uint16(call->ndr_push_param, val);
}

static void rap_cli_push_dword(struct rap_call *call, uint32 val)
{
	rap_cli_push_paramdesc(call, 'D');
	ndr_push_uint32(call->ndr_push_param, val);
}

static void rap_cli_push_rcvbuf(struct rap_call *call, int len)
{
	rap_cli_push_paramdesc(call, 'r');
	rap_cli_push_paramdesc(call, 'L');
	ndr_push_uint16(call->ndr_push_param, len);
	call->rcv_datalen = len;
}

static void rap_cli_expect_multiple_entries(struct rap_call *call)
{
	rap_cli_push_paramdesc(call, 'e');
	rap_cli_push_paramdesc(call, 'h');
	call->rcv_paramlen += 4; /* uint16 entry count, uint16 total */
}

static void rap_cli_push_string(struct rap_call *call, const char *str)
{
	if (str == NULL) {
		rap_cli_push_paramdesc(call, 'O');
		return;
	}
	rap_cli_push_paramdesc(call, 'z');
	ndr_push_string(call->ndr_push_param, NDR_SCALARS, str);
}

static void rap_cli_expect_format(struct rap_call *call, const char *format)
{
	call->datadesc = format;
}

static NTSTATUS rap_pull_string(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr,
				uint16 convert, char **dest)
{
	uint16 string_offset;
	uint16 ignore;
	char *p;
	size_t len;

	NDR_CHECK(ndr_pull_uint16(ndr, &string_offset));
	NDR_CHECK(ndr_pull_uint16(ndr, &ignore));

	string_offset -= convert;

	if (string_offset+1 > ndr->data_size)
		return NT_STATUS_INVALID_PARAMETER;

	p = ndr->data + string_offset;
	len = strnlen(p, ndr->data_size-string_offset);

	if ( string_offset + len + 1 >  ndr->data_size )
		return NT_STATUS_INVALID_PARAMETER;

	*dest = talloc_zero(mem_ctx, len+1);
	pull_ascii(*dest, p, len+1, len, 0);

	return NT_STATUS_OK;
}

static NTSTATUS rap_cli_do_call(struct smbcli_state *cli, TALLOC_CTX *mem_ctx,
				struct rap_call *call)
{
	NTSTATUS result;
	DATA_BLOB param_blob;
	struct ndr_push *params;
	struct smb_trans2 trans;

	params = ndr_push_init_ctx(mem_ctx);

	if (params == NULL)
		return NT_STATUS_NO_MEMORY;

	params->flags = RAPNDR_FLAGS;

	trans.in.max_param = call->rcv_paramlen;
	trans.in.max_data = call->rcv_datalen;
	trans.in.max_setup = 0;
	trans.in.flags = 0;
	trans.in.timeout = 0;
	trans.in.setup_count = 0;
	trans.in.setup = NULL;
	trans.in.trans_name = "\\PIPE\\LANMAN";

	NDR_CHECK(ndr_push_uint16(params, call->callno));
	NDR_CHECK(ndr_push_string(params, NDR_SCALARS, call->paramdesc));
	NDR_CHECK(ndr_push_string(params, NDR_SCALARS, call->datadesc));

	param_blob = ndr_push_blob(call->ndr_push_param);
	NDR_CHECK(ndr_push_bytes(params, param_blob.data,
				 param_blob.length));

	trans.in.params = ndr_push_blob(params);
	trans.in.data = data_blob(NULL, 0);

	result = smb_raw_trans(cli->tree, call->mem_ctx, &trans);

	if (!NT_STATUS_IS_OK(result))
		return result;

	call->ndr_pull_param = ndr_pull_init_blob(&trans.out.params,
						  call->mem_ctx);
	call->ndr_pull_param->flags = RAPNDR_FLAGS;

	call->ndr_pull_data = ndr_pull_init_blob(&trans.out.data,
						 call->mem_ctx);
	call->ndr_pull_data->flags = RAPNDR_FLAGS;

	return result;
}

#define NDR_OK(call) do { NTSTATUS _status; \
                             _status = call; \
                             if (!NT_STATUS_IS_OK(_status)) \
				goto done; \
                        } while (0)

static NTSTATUS smbcli_rap_netshareenum(struct smbcli_state *cli,
				     TALLOC_CTX *mem_ctx,
				     struct rap_NetShareEnum *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_cli_call(0);

	if (call == NULL)
		return NT_STATUS_NO_MEMORY;

	rap_cli_push_word(call, r->in.level); /* Level */
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_multiple_entries(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "B13");
		break;
	case 1:
		rap_cli_expect_format(call, "B13BWz");
		break;
	}

	result = rap_cli_do_call(cli, mem_ctx, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.status));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.convert));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.count));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.available));

	r->out.info = talloc_array_p(mem_ctx, union rap_shareenum_info,
				     r->out.count);

	if (r->out.info == NULL)
		return NT_STATUS_NO_MEMORY;

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      r->out.info[i].info0.name, 13));
			break;
		case 1:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      r->out.info[i].info1.name, 13));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.pad, 1));
			NDR_OK(ndr_pull_uint16(call->ndr_pull_data,
					       &r->out.info[i].info1.type));
			NDR_OK(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
			break;
		}
	}

	result = NT_STATUS_OK;

 done:
	destroy_rap_call(call);

	return result;
}

static BOOL test_netshareenum(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct rap_NetShareEnum r;
	int i;

	r.in.level = 1;
	r.in.bufsize = 8192;

	if (!NT_STATUS_IS_OK(smbcli_rap_netshareenum(cli, mem_ctx, &r)))
		return False;

	for (i=0; i<r.out.count; i++) {
		printf("%s %d %s\n", r.out.info[i].info1.name,
		       r.out.info[i].info1.type,
		       r.out.info[i].info1.comment);
	}

	return True;
}

static NTSTATUS smbcli_rap_netserverenum2(struct smbcli_state *cli,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetServerEnum2 *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_cli_call(104);

	if (call == NULL)
		return NT_STATUS_NO_MEMORY;

	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_multiple_entries(call);
	rap_cli_push_dword(call, r->in.servertype);
	rap_cli_push_string(call, r->in.domain);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "B16");
		break;
	case 1:
		rap_cli_expect_format(call, "B16BBDz");
		break;
	}

	result = rap_cli_do_call(cli, mem_ctx, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.status));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.convert));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.count));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, &r->out.available));

	r->out.info = talloc_array_p(mem_ctx, union rap_server_info,
				     r->out.count);

	if (r->out.info == NULL)
		return NT_STATUS_NO_MEMORY;

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      r->out.info[i].info0.name, 16));
			break;
		case 1:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      r->out.info[i].info1.name, 16));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_major, 1));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_minor, 1));
			NDR_OK(ndr_pull_uint32(call->ndr_pull_data,
					       &r->out.info[i].info1.servertype));
			NDR_OK(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
		}
	}

	result = NT_STATUS_OK;

 done:
	destroy_rap_call(call);

	return result;
}

static BOOL test_netserverenum(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct rap_NetServerEnum2 r;
	int i;

	r.in.level = 0;
	r.in.bufsize = 8192;
	r.in.servertype = 0xffffffff;
	r.in.servertype = 0x80000000;
	r.in.domain = NULL;

	if (!NT_STATUS_IS_OK(smbcli_rap_netserverenum2(cli, mem_ctx, &r)))
		return False;

	for (i=0; i<r.out.count; i++) {
		switch (r.in.level) {
		case 0:
			printf("%s\n", r.out.info[i].info0.name);
			break;
		case 1:
			printf("%s %x %s\n", r.out.info[i].info1.name,
			       r.out.info[i].info1.servertype,
			       r.out.info[i].info1.comment);
			break;
		}
	}

	return True;
}



static BOOL test_rap(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	BOOL res = True;

	if (!test_netserverenum(cli, mem_ctx))
		res = False;

	if (!test_netshareenum(cli, mem_ctx))
		res = False;

	return res;
}

BOOL torture_raw_rap(int dummy)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_rap");

	if (!test_rap(cli, mem_ctx)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_destroy(mem_ctx);
	return ret;
}

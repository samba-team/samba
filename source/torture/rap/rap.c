/* 
   Unix SMB/CIFS implementation.
   test suite for various RAP operations
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Tim Potter 2005
   
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
#include "libcli/libcli.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "libcli/rap/rap.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "librpc/ndr/libndr.h"

struct rap_call {
	uint16_t callno;
	char *paramdesc;
	const char *datadesc;

	uint16_t status;
	uint16_t convert;
	
	uint16_t rcv_paramlen, rcv_datalen;

	struct ndr_push *ndr_push_param;
	struct ndr_push *ndr_push_data;
	struct ndr_pull *ndr_pull_param;
	struct ndr_pull *ndr_pull_data;
};

#define RAPNDR_FLAGS (LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM);

static struct rap_call *new_rap_cli_call(TALLOC_CTX *mem_ctx, uint16_t callno)
{
	struct rap_call *call;

	call = talloc(mem_ctx, struct rap_call);

	if (call == NULL)
		return NULL;

	call->callno = callno;
	call->rcv_paramlen = 4;

	call->paramdesc = NULL;
	call->datadesc = NULL;

	call->ndr_push_param = ndr_push_init_ctx(mem_ctx);
	call->ndr_push_param->flags = RAPNDR_FLAGS;

	call->ndr_push_data = ndr_push_init_ctx(mem_ctx);
	call->ndr_push_data->flags = RAPNDR_FLAGS;

	return call;
}

static void rap_cli_push_paramdesc(struct rap_call *call, char desc)
{
	int len = 0;

	if (call->paramdesc != NULL)
		len = strlen(call->paramdesc);

	call->paramdesc = talloc_realloc(call,
					 call->paramdesc,
					 char,
					 len+2);

	call->paramdesc[len] = desc;
	call->paramdesc[len+1] = '\0';
}

static void rap_cli_push_word(struct rap_call *call, uint16_t val)
{
	rap_cli_push_paramdesc(call, 'W');
	ndr_push_uint16(call->ndr_push_param, NDR_SCALARS, val);
}

static void rap_cli_push_dword(struct rap_call *call, uint32_t val)
{
	rap_cli_push_paramdesc(call, 'D');
	ndr_push_uint32(call->ndr_push_param, NDR_SCALARS, val);
}

static void rap_cli_push_rcvbuf(struct rap_call *call, int len)
{
	rap_cli_push_paramdesc(call, 'r');
	rap_cli_push_paramdesc(call, 'L');
	ndr_push_uint16(call->ndr_push_param, NDR_SCALARS, len);
	call->rcv_datalen = len;
}

static void rap_cli_expect_multiple_entries(struct rap_call *call)
{
	rap_cli_push_paramdesc(call, 'e');
	rap_cli_push_paramdesc(call, 'h');
	call->rcv_paramlen += 4; /* uint16_t entry count, uint16_t total */
}

static void rap_cli_expect_word(struct rap_call *call)
{
	rap_cli_push_paramdesc(call, 'h');
	call->rcv_paramlen += 2;
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
				uint16_t convert, char **dest)
{
	uint16_t string_offset;
	uint16_t ignore;
	const char *p;
	size_t len;

	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &string_offset));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &ignore));

	string_offset -= convert;

	if (string_offset+1 > ndr->data_size)
		return NT_STATUS_INVALID_PARAMETER;

	p = (const char *)(ndr->data + string_offset);
	len = strnlen(p, ndr->data_size-string_offset);

	if ( string_offset + len + 1 >  ndr->data_size )
		return NT_STATUS_INVALID_PARAMETER;

	*dest = talloc_zero_size(mem_ctx, len+1);
	pull_string(*dest, p, len+1, len, STR_ASCII);

	return NT_STATUS_OK;
}

static NTSTATUS rap_cli_do_call(struct smbcli_state *cli, struct rap_call *call)
{
	NTSTATUS result;
	DATA_BLOB param_blob;
	struct ndr_push *params;
	struct smb_trans2 trans;

	params = ndr_push_init_ctx(call);

	if (params == NULL)
		return NT_STATUS_NO_MEMORY;

	params->flags = RAPNDR_FLAGS;

	trans.in.max_param = call->rcv_paramlen;
	trans.in.max_data = smb_raw_max_trans_data(cli->tree, call->rcv_paramlen);
	trans.in.max_setup = 0;
	trans.in.flags = 0;
	trans.in.timeout = 0;
	trans.in.setup_count = 0;
	trans.in.setup = NULL;
	trans.in.trans_name = "\\PIPE\\LANMAN";

	NDR_CHECK(ndr_push_uint16(params, NDR_SCALARS, call->callno));
	if (call->paramdesc)
		NDR_CHECK(ndr_push_string(params, NDR_SCALARS, call->paramdesc));
	if (call->datadesc)
		NDR_CHECK(ndr_push_string(params, NDR_SCALARS, call->datadesc));

	param_blob = ndr_push_blob(call->ndr_push_param);
	NDR_CHECK(ndr_push_bytes(params, param_blob.data,
				 param_blob.length));

	trans.in.params = ndr_push_blob(params);
	trans.in.data = data_blob(NULL, 0);

	result = smb_raw_trans(cli->tree, call, &trans);

	if (!NT_STATUS_IS_OK(result))
		return result;

	call->ndr_pull_param = ndr_pull_init_blob(&trans.out.params, call);
	call->ndr_pull_param->flags = RAPNDR_FLAGS;

	call->ndr_pull_data = ndr_pull_init_blob(&trans.out.data, call);
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

	call = new_rap_cli_call(NULL, RAP_WshareEnum);

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

	result = rap_cli_do_call(cli, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_array(mem_ctx, union rap_shareenum_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      (uint8_t *)r->out.info[i].info0.name, 13));
			break;
		case 1:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      (uint8_t *)r->out.info[i].info1.name, 13));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      (uint8_t *)&r->out.info[i].info1.pad, 1));
			NDR_OK(ndr_pull_uint16(call->ndr_pull_data,
					       NDR_SCALARS, &r->out.info[i].info1.type));
			NDR_OK(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
			break;
		}
	}

	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

static BOOL test_netshareenum(struct smbcli_state *cli)
{
	struct rap_NetShareEnum r;
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(cli);

	r.in.level = 1;
	r.in.bufsize = 8192;

	if (!NT_STATUS_IS_OK(smbcli_rap_netshareenum(cli, tmp_ctx, &r)))
		return False;

	for (i=0; i<r.out.count; i++) {
		printf("%s %d %s\n", r.out.info[i].info1.name,
		       r.out.info[i].info1.type,
		       r.out.info[i].info1.comment);
	}

	talloc_free(tmp_ctx);

	return True;
}

static NTSTATUS smbcli_rap_netserverenum2(struct smbcli_state *cli,
					  TALLOC_CTX *mem_ctx,
					  struct rap_NetServerEnum2 *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_cli_call(mem_ctx, RAP_NetServerEnum2);

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

	result = rap_cli_do_call(cli, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_array(mem_ctx, union rap_server_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      (uint8_t *)r->out.info[i].info0.name, 16));
			break;
		case 1:
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      (uint8_t *)r->out.info[i].info1.name, 16));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_major, 1));
			NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_minor, 1));
			NDR_OK(ndr_pull_uint32(call->ndr_pull_data,
					       NDR_SCALARS, &r->out.info[i].info1.servertype));
			NDR_OK(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
		}
	}

	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

static BOOL test_netserverenum(struct smbcli_state *cli)
{
	struct rap_NetServerEnum2 r;
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(cli);

	r.in.level = 0;
	r.in.bufsize = 8192;
	r.in.servertype = 0xffffffff;
	r.in.servertype = 0x80000000;
	r.in.domain = NULL;

	if (!NT_STATUS_IS_OK(smbcli_rap_netserverenum2(cli, tmp_ctx, &r)))
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

	talloc_free(tmp_ctx);

	return True;
}

NTSTATUS smbcli_rap_netservergetinfo(struct smbcli_state *cli,
				     TALLOC_CTX *mem_ctx,
				     struct rap_WserverGetInfo *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, RAP_WserverGetInfo))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_word(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "B16");
		break;
	case 1:
		rap_cli_expect_format(call, "B16BBDz");
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	result = rap_cli_do_call(cli, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_OK(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	switch(r->in.level) {
	case 0:
		NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
				      (uint8_t *)r->out.info.info0.name, 16));
		break;
	case 1:
		NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
				      (uint8_t *)r->out.info.info1.name, 16));
		NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
				      &r->out.info.info1.version_major, 1));
		NDR_OK(ndr_pull_bytes(call->ndr_pull_data,
				      &r->out.info.info1.version_minor, 1));
		NDR_OK(ndr_pull_uint32(call->ndr_pull_data,
				       NDR_SCALARS, &r->out.info.info1.servertype));
		NDR_OK(rap_pull_string(mem_ctx, call->ndr_pull_data,
				       r->out.convert,
				       &r->out.info.info1.comment));
	}
 done:
	talloc_free(call);
	return result;
}

static BOOL test_netservergetinfo(struct smbcli_state *cli)
{
	struct rap_WserverGetInfo r;
	BOOL res = True;
	TALLOC_CTX *mem_ctx;

	if (!(mem_ctx = talloc_new(cli))) {
		return False;
	}

	r.in.bufsize = 0xffff;

	r.in.level = 0;
	res &= NT_STATUS_IS_OK(smbcli_rap_netservergetinfo(cli, mem_ctx, &r));
	r.in.level = 1;
	res &= NT_STATUS_IS_OK(smbcli_rap_netservergetinfo(cli, mem_ctx, &r));

	talloc_free(mem_ctx);
	return res;
}

static BOOL test_rap(struct smbcli_state *cli)
{
	BOOL res = True;

	res &= test_netserverenum(cli);
	res &= test_netshareenum(cli);
	res &= test_netservergetinfo(cli);

	return res;
}

BOOL torture_rap_basic(struct torture_context *torture)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}

	mem_ctx = talloc_init("torture_rap_basic");

	if (!test_rap(cli)) {
		ret = False;
	}

	torture_close_connection(cli);
	talloc_free(mem_ctx);

	return ret;
}

BOOL torture_rap_scan(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	struct smbcli_state *cli;
	int callno;

	mem_ctx = talloc_init("torture_rap_scan");

	if (!torture_open_connection(&cli, 0)) {
		return False;
	}
	
	for (callno = 0; callno < 0xffff; callno++) {
		struct rap_call *call = new_rap_cli_call(mem_ctx, callno);
		NTSTATUS result;

		result = rap_cli_do_call(cli, call);

		if (!NT_STATUS_EQUAL(result, NT_STATUS_INVALID_PARAMETER))
			continue;

		printf("callno %d is RAP call\n", callno);
	}

	torture_close_connection(cli);

	return True;
}

NTSTATUS torture_rap_init(void)
{
	register_torture_op("RAP-BASIC", torture_rap_basic);
	register_torture_op("SCAN-RAP",  torture_rap_scan);

	return NT_STATUS_OK;
}

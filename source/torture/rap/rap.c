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

/*
struct rap_server_info_0 {
	char name[16];
};

struct rap_server_info_1 {
        char name[16];
        uint8 version_major;
        uint8 version_minor;
        uint32 type;
        const char *comment_or_master_browser;
};

union rap_server_info {
	struct rap_server_info0 info0;
	struct rap_server_info1 info1;
};

struct rap_NetServerEnum2 {
	struct {
		uint16 level;
		uint32 servertype;
		const char *domain;
	} in;

	struct {
		union rap_serverinfo *info;
		int num_entries;
	} out;
};

  unsigned short NetServerEnum2 (
    [in] uint16 level,
    [out,switch_is(level)] union rap_serverinfo info[],
    [in] uint16 servertype;
    [in] const char *domain;
    );
*/

struct rap_call {
	TALLOC_CTX *mem_ctx;
	uint16 callno;
	char *paramdesc;
	const char *datadesc;

	struct smb_trans2 trans;

	uint16 status;
	uint16 convert;

	int out_param_offset, out_data_offset;
};

static struct rap_call *new_rap_call(uint16 callno)
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
	call->trans.in.max_param = 4;	/* uint16 error, uint16 "convert" */
	call->mem_ctx = mem_ctx;

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

	call->paramdesc = talloc_realloc(call->mem_ctx, call->paramdesc,
					 len+2);
	call->paramdesc[len] = desc;
	call->paramdesc[len+1] = '\0';
}

static void rap_cli_push_param_word(struct rap_call *call, uint16 val)
{
	DATA_BLOB *params = &call->trans.in.params;

	params->data = talloc_realloc(call->mem_ctx, params->data,
				      params->length + sizeof(val));
	SSVAL(params->data, params->length, val);
	params->length += sizeof(val);
}

static void rap_cli_push_param_dword(struct rap_call *call, uint32 val)
{
	DATA_BLOB *params = &call->trans.in.params;

	params->data = talloc_realloc(call->mem_ctx, params->data,
				      params->length + sizeof(val));
	SIVAL(params->data, params->length, val);
	params->length += sizeof(val);
}

static void rap_cli_push_param_string(struct rap_call *call, const char *str)
{
	size_t len = strlen(str);
	DATA_BLOB *params = &call->trans.in.params;

	params->data = talloc_realloc(call->mem_ctx, params->data,
				      params->length + len + 1);
	memcpy(params->data+params->length, str, len+1);
	params->length += (len+1);
}
	
static void rap_cli_push_word(struct rap_call *call, uint16 val)
{
	rap_cli_push_paramdesc(call, 'W');
	rap_cli_push_param_word(call, val);
}

static void rap_cli_push_dword(struct rap_call *call, uint32 val)
{
	rap_cli_push_paramdesc(call, 'D');
	rap_cli_push_param_dword(call, val);
}

static void rap_cli_push_rcvbuf(struct rap_call *call, int len)
{
	rap_cli_push_paramdesc(call, 'r');
	rap_cli_push_paramdesc(call, 'L');
	rap_cli_push_param_word(call, len);
	call->trans.in.max_data = len;
}

static void rap_cli_expect_multiple_entries(struct rap_call *call)
{
	rap_cli_push_paramdesc(call, 'e');
	rap_cli_push_paramdesc(call, 'h');
	call->trans.in.max_param += 4;	/* uint16 entry count, uint16 total */
}

static void rap_cli_push_string(struct rap_call *call, const char *str)
{
	if (str == NULL) {
		rap_cli_push_paramdesc(call, 'O');
		return;
	}
	rap_cli_push_paramdesc(call, 'z');
	rap_cli_push_param_string(call, str);
}

static void rap_cli_expect_format(struct rap_call *call, const char *format)
{
	call->datadesc = format;
}

static BOOL bytes_available(DATA_BLOB *blob, int *offset, int size)
{
	if (*offset < 0)
		return False;

	if ( (*offset + size) > blob->length ) {
		*offset = -1;
		return False;
	}

	return True;
}

static BOOL rap_pull_word(DATA_BLOB *blob, int *offset, uint16 *val)
{
	if (!bytes_available(blob, offset, sizeof(*val)))
		return False;

	*val = SVAL(blob->data, *offset);
	*offset += sizeof(*val);
	return True;
}

static BOOL rap_pull_dword(DATA_BLOB *blob, int *offset, uint32 *val)
{
	if (!bytes_available(blob, offset, sizeof(*val)))
		return False;

	*val = IVAL(blob->data, *offset);
	*offset += sizeof(*val);
	return True;
}

static BOOL rap_pull_bytes(DATA_BLOB *blob, int *offset, char *dest,
			   int length)
{
	if (!bytes_available(blob, offset, length))
		return False;

	memcpy(dest, blob->data+*offset, length);
	*offset += length;
	return True;
}

static BOOL rap_pull_string(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, int *offset,
			    uint16 convert, char **dest)
{
	uint16 string_offset;
	uint16 ignore;
	char *p;
	size_t len;

	if (!rap_pull_word(blob, offset, &string_offset))
		return False;

	if (!rap_pull_word(blob, offset, &ignore))
		return False;

	string_offset -= convert;

	if (string_offset+1 > blob->length)
		return False;

	p = blob->data + string_offset;
	len = strnlen(p, blob->length-string_offset);

	if ( string_offset + len + 1 >  blob->length ) {
		*offset = -1;
		return False;
	}

	*dest = talloc_zero(mem_ctx, len+1);
	pull_ascii(*dest, p, len+1, len, 0);

	return True;
}

static NTSTATUS rap_cli_do_call(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				struct rap_call *call)
{
	int paramlen;
	char *p;
	NTSTATUS result;
	DATA_BLOB params;

	call->trans.in.max_setup = 0;
	call->trans.in.flags = 0;
	call->trans.in.timeout = 0;
	call->trans.in.setup_count = 0;
	call->trans.in.setup = NULL;
	call->trans.in.trans_name = "\\PIPE\\LANMAN";

	paramlen = 2 + 		/* uint16 command */
		strlen(call->paramdesc) + 1 +
		strlen(call->datadesc) + 1 +
		call->trans.in.params.length;

	params = data_blob_talloc(call->mem_ctx, NULL, paramlen);

	p = params.data;

	SSVAL(p, 0, call->callno);
	p += 2;

	memcpy(p, call->paramdesc, strlen(call->paramdesc)+1);
	p += strlen(p)+1;

	memcpy(p, call->datadesc, strlen(call->datadesc)+1);
	p += strlen(p)+1;

	memcpy(p, call->trans.in.params.data, call->trans.in.params.length);

	call->trans.in.params = params;
	call->trans.in.data = data_blob(NULL, 0);

	result = smb_raw_trans(cli->tree, call->mem_ctx, &call->trans);

	if (!NT_STATUS_IS_OK(result))
		return result;

	return result;
}

struct rap_shareenum_info_0 {
	char name[13];
};

struct rap_shareenum_info_1 {
	char name[13];
	char pad;
	uint16 type;
	char *comment;
};

union rap_shareenum_info {
	struct rap_shareenum_info_0 info0;
	struct rap_shareenum_info_1 info1;
};

struct rap_NetShareEnum {
	struct {
		uint16 level;
		uint16 bufsize;
	} in;

	struct {
		uint16 status;
		uint16 convert;
		uint16 count;
		uint16 available;
		union rap_shareenum_info *info;
	} out;
};

static NTSTATUS cli_rap_netshareenum(struct cli_state *cli,
				     TALLOC_CTX *mem_ctx,
				     struct rap_NetShareEnum *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_call(0);

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

	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.status);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.convert);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.count);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.available);

	if (call->out_param_offset < 0) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	r->out.info = talloc_array_p(mem_ctx, union rap_shareenum_info,
				     r->out.count);

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       r->out.info[i].info0.name, 13);
			break;
		case 1:
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       r->out.info[i].info1.name, 13);
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       &r->out.info[i].info1.pad, 1);
			rap_pull_word(&call->trans.out.data,
				      &call->out_data_offset,
				      &r->out.info[i].info1.type);
			rap_pull_string(mem_ctx,
					&call->trans.out.data,
					&call->out_data_offset,
					r->out.convert,
					&r->out.info[i].info1.comment);
		}
	}

	result = NT_STATUS_OK;

	if (call->out_data_offset < 0) {
		result = NT_STATUS_INVALID_PARAMETER;
	}

 done:
	destroy_rap_call(call);

	return result;
}

static BOOL test_netshareenum(struct cli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct rap_NetShareEnum r;
	int i;

	r.in.level = 1;
	r.in.bufsize = 8192;

	if (!NT_STATUS_IS_OK(cli_rap_netshareenum(cli, mem_ctx, &r)))
		return False;

	for (i=0; i<r.out.count; i++) {
		printf("%s %d %s\n", r.out.info[i].info1.name,
		       r.out.info[i].info1.type,
		       r.out.info[i].info1.comment);
	}

	return True;
}

struct rap_server_info_0 {
	char name[16];
};

struct rap_server_info_1 {
        char     name[16];
        uint8_t  version_major;
        uint8_t  version_minor;
        uint32_t servertype;
        char    *comment;
};

union rap_server_info {
	struct rap_server_info_0 info0;
	struct rap_server_info_1 info1;
};

struct rap_NetServerEnum2 {
	struct {
		uint16 level;
		uint16 bufsize;
		uint32 servertype;
		char *domain;
	} in;

	struct {
		uint16 status;
		uint16 convert;
		uint16 count;
		uint16 available;
		union rap_server_info *info;
	} out;
};
		
static NTSTATUS cli_rap_netserverenum2(struct cli_state *cli,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetServerEnum2 *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_call(104);

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

	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.status);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.convert);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.count);
	rap_pull_word(&call->trans.out.params, &call->out_param_offset,
		      &r->out.available);

	if (call->out_param_offset < 0) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	r->out.info = talloc_array_p(mem_ctx, union rap_server_info,
				     r->out.count);

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       r->out.info[i].info0.name, 16);
			break;
		case 1:
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       r->out.info[i].info1.name, 16);
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       &r->out.info[i].info1.version_major, 1);
			rap_pull_bytes(&call->trans.out.data,
				       &call->out_data_offset,
				       &r->out.info[i].info1.version_minor, 1);
			rap_pull_dword(&call->trans.out.data,
				       &call->out_data_offset,
				       &r->out.info[i].info1.servertype);
			rap_pull_string(mem_ctx,
					&call->trans.out.data,
					&call->out_data_offset,
					r->out.convert,
					&r->out.info[i].info1.comment);
		}
	}

	result = NT_STATUS_OK;

	if (call->out_data_offset < 0) {
		result = NT_STATUS_INVALID_PARAMETER;
	}

 done:
	destroy_rap_call(call);

	return result;
}

static BOOL test_netserverenum(struct cli_state *cli, TALLOC_CTX *mem_ctx)
{
	struct rap_NetServerEnum2 r;
	int i;

	r.in.level = 0;
	r.in.bufsize = 8192;
	r.in.servertype = 0xffffffff;
	r.in.servertype = 0x80000000;
	r.in.domain = NULL;

	if (!NT_STATUS_IS_OK(cli_rap_netserverenum2(cli, mem_ctx, &r)))
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



static BOOL test_rap(struct cli_state *cli, TALLOC_CTX *mem_ctx)
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
	struct cli_state *cli;
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

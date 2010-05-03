/* 
   Unix SMB/CIFS implementation.
   test suite for various RAP operations
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Tim Potter 2005
   Copyright (C) Jelmer Vernooij 2007
   
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
#include "libcli/libcli.h"
#include "torture/smbtorture.h"
#include "torture/util.h"
#include "../librpc/gen_ndr/ndr_rap.h"
#include "librpc/ndr/libndr.h"
#include "param/param.h"
#include "torture/rap/proto.h"

#define RAP_GOTO(call) do { \
	NTSTATUS _status; \
	_status = call; \
	if (!NT_STATUS_IS_OK(_status)) { \
		result = _status; \
		goto done; \
	} \
} while (0)

#define RAP_RETURN(call) do { \
	NTSTATUS _status; \
	_status = call; \
	if (!NT_STATUS_IS_OK(_status)) { \
		return _status; \
	} \
} while (0)


#define NDR_GOTO(call) do { \
	enum ndr_err_code _ndr_err; \
	_ndr_err = call; \
	if (!NDR_ERR_CODE_IS_SUCCESS(_ndr_err)) { \
		result = ndr_map_error2ntstatus(_ndr_err); \
		goto done; \
	} \
} while (0)

#define NDR_RETURN(call) do { \
	enum ndr_err_code _ndr_err; \
	_ndr_err = call; \
	if (!NDR_ERR_CODE_IS_SUCCESS(_ndr_err)) { \
		return ndr_map_error2ntstatus(_ndr_err); \
	} \
} while (0)

struct rap_call {
	uint16_t callno;
	char *paramdesc;
	const char *datadesc;
	const char *auxdatadesc;

	uint16_t status;
	uint16_t convert;
	
	uint16_t rcv_paramlen, rcv_datalen;

	struct ndr_push *ndr_push_param;
	struct ndr_push *ndr_push_data;
	struct ndr_pull *ndr_pull_param;
	struct ndr_pull *ndr_pull_data;
};

#define RAPNDR_FLAGS (LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM);

static struct rap_call *new_rap_cli_call(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint16_t callno)
{
	struct rap_call *call;

	call = talloc(mem_ctx, struct rap_call);

	if (call == NULL)
		return NULL;

	call->callno = callno;
	call->rcv_paramlen = 4;

	call->paramdesc = NULL;
	call->datadesc = NULL;
	call->auxdatadesc = NULL;

	call->ndr_push_param = ndr_push_init_ctx(mem_ctx, iconv_convenience);
	call->ndr_push_param->flags = RAPNDR_FLAGS;

	call->ndr_push_data = ndr_push_init_ctx(mem_ctx, iconv_convenience);
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

static void rap_cli_push_sendbuf(struct rap_call *call, int len)
{
	rap_cli_push_paramdesc(call, 's');
	rap_cli_push_paramdesc(call, 'T');
	ndr_push_uint16(call->ndr_push_param, NDR_SCALARS, len);
	call->rcv_datalen = len;
}

static void rap_cli_push_param(struct rap_call *call, uint16_t val)
{
	rap_cli_push_paramdesc(call, 'P');
	ndr_push_uint16(call->ndr_push_param, NDR_SCALARS, val);
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

static void rap_cli_expect_extra_format(struct rap_call *call, const char *format)
{
	call->auxdatadesc = format;
}

static NTSTATUS rap_pull_string(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr,
				uint16_t convert, const char **dest)
{
	uint16_t string_offset;
	uint16_t ignore;
	const char *p;
	size_t len;

	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &string_offset));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &ignore));

	string_offset -= convert;

	if (string_offset+1 > ndr->data_size)
		return NT_STATUS_INVALID_PARAMETER;

	p = (const char *)(ndr->data + string_offset);
	len = strnlen(p, ndr->data_size-string_offset);

	if ( string_offset + len + 1 >  ndr->data_size )
		return NT_STATUS_INVALID_PARAMETER;

	*dest = talloc_zero_array(mem_ctx, char, len+1);
	pull_string((char *)*dest, p, len+1, len, STR_ASCII);

	return NT_STATUS_OK;
}

static NTSTATUS rap_cli_do_call(struct smbcli_tree *tree, 
				struct smb_iconv_convenience *iconv_convenience,
				struct rap_call *call)
{
	NTSTATUS result;
	DATA_BLOB param_blob;
	struct ndr_push *params;
	struct smb_trans2 trans;

	params = ndr_push_init_ctx(call, iconv_convenience);

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

	NDR_RETURN(ndr_push_uint16(params, NDR_SCALARS, call->callno));
	if (call->paramdesc)
		NDR_RETURN(ndr_push_string(params, NDR_SCALARS, call->paramdesc));
	if (call->datadesc)
		NDR_RETURN(ndr_push_string(params, NDR_SCALARS, call->datadesc));

	param_blob = ndr_push_blob(call->ndr_push_param);
	NDR_RETURN(ndr_push_bytes(params, param_blob.data,
				 param_blob.length));

	if (call->auxdatadesc)
		NDR_RETURN(ndr_push_string(params, NDR_SCALARS, call->auxdatadesc));

	trans.in.params = ndr_push_blob(params);
	trans.in.data = data_blob(NULL, 0);

	result = smb_raw_trans(tree, call, &trans);

	if (!NT_STATUS_IS_OK(result))
		return result;

	call->ndr_pull_param = ndr_pull_init_blob(&trans.out.params, call,
						  iconv_convenience);
	call->ndr_pull_param->flags = RAPNDR_FLAGS;

	call->ndr_pull_data = ndr_pull_init_blob(&trans.out.data, call,
						 iconv_convenience);
	call->ndr_pull_data->flags = RAPNDR_FLAGS;

	return result;
}


static NTSTATUS smbcli_rap_netshareenum(struct smbcli_tree *tree,
					struct smb_iconv_convenience *iconv_convenience,
					TALLOC_CTX *mem_ctx,
					struct rap_NetShareEnum *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_cli_call(tree, iconv_convenience, RAP_WshareEnum);

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

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetShareEnum, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_array(mem_ctx, union rap_share_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
						r->out.info[i].info0.share_name, 13));
			break;
		case 1:
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
						r->out.info[i].info1.share_name, 13));
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
					        &r->out.info[i].info1.reserved1, 1));
			NDR_GOTO(ndr_pull_uint16(call->ndr_pull_data,
					       NDR_SCALARS, &r->out.info[i].info1.share_type));
			RAP_GOTO(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
			break;
		}
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetShareEnum, r);
	}
	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

static bool test_netshareenum(struct torture_context *tctx, 
			      struct smbcli_state *cli)
{
	struct rap_NetShareEnum r;
	int i;

	r.in.level = 1;
	r.in.bufsize = 8192;

	torture_assert_ntstatus_ok(tctx, 
		smbcli_rap_netshareenum(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r), "");

	for (i=0; i<r.out.count; i++) {
		printf("%s %d %s\n", r.out.info[i].info1.share_name,
		       r.out.info[i].info1.share_type,
		       r.out.info[i].info1.comment);
	}

	return true;
}

static NTSTATUS smbcli_rap_netserverenum2(struct smbcli_tree *tree,
					  struct smb_iconv_convenience *iconv_convenience, 
					  TALLOC_CTX *mem_ctx,
					  struct rap_NetServerEnum2 *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_NetServerEnum2);

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

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetServerEnum2, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_array(mem_ctx, union rap_server_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
						r->out.info[i].info0.name, 16));
			break;
		case 1:
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
						r->out.info[i].info1.name, 16));
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_major, 1));
			NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
					      &r->out.info[i].info1.version_minor, 1));
			NDR_GOTO(ndr_pull_uint32(call->ndr_pull_data,
					       NDR_SCALARS, &r->out.info[i].info1.servertype));
			RAP_GOTO(rap_pull_string(mem_ctx, call->ndr_pull_data,
					       r->out.convert,
					       &r->out.info[i].info1.comment));
		}
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetServerEnum2, r);
	}

	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

static bool test_netserverenum(struct torture_context *tctx, 
			       struct smbcli_state *cli)
{
	struct rap_NetServerEnum2 r;
	int i;

	r.in.level = 0;
	r.in.bufsize = 8192;
	r.in.servertype = 0xffffffff;
	r.in.servertype = 0x80000000;
	r.in.domain = NULL;

	torture_assert_ntstatus_ok(tctx, 
		   smbcli_rap_netserverenum2(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r), "");

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

	return true;
}

NTSTATUS smbcli_rap_netservergetinfo(struct smbcli_tree *tree,
					      struct smb_iconv_convenience *iconv_convenience, 
				     TALLOC_CTX *mem_ctx,
				     struct rap_WserverGetInfo *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WserverGetInfo))) {
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

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_WserverGetInfo, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	switch(r->in.level) {
	case 0:
		NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
					r->out.info.info0.name, 16));
		break;
	case 1:
		NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
					r->out.info.info1.name, 16));
		NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
				      &r->out.info.info1.version_major, 1));
		NDR_GOTO(ndr_pull_bytes(call->ndr_pull_data,
				      &r->out.info.info1.version_minor, 1));
		NDR_GOTO(ndr_pull_uint32(call->ndr_pull_data,
				       NDR_SCALARS, &r->out.info.info1.servertype));
		RAP_GOTO(rap_pull_string(mem_ctx, call->ndr_pull_data,
				       r->out.convert,
				       &r->out.info.info1.comment));
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_WserverGetInfo, r);
	}
 done:
	talloc_free(call);
	return result;
}

static NTSTATUS rap_pull_rap_JobInfo0(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintJobInfo0 *r)
{
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobID));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_JobInfo1(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintJobInfo1 *r)
{
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobID));
	NDR_RETURN(ndr_pull_charset(ndr, NDR_SCALARS, &r->UserName, 21, sizeof(uint8_t), CH_DOS));
	NDR_RETURN(ndr_pull_uint8(ndr, NDR_SCALARS, &r->Pad));
	NDR_RETURN(ndr_pull_charset(ndr, NDR_SCALARS, &r->NotifyName, 16, sizeof(uint8_t), CH_DOS));
	NDR_RETURN(ndr_pull_charset(ndr, NDR_SCALARS, &r->DataType, 10, sizeof(uint8_t), CH_DOS));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintParameterString));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobPosition));
	NDR_RETURN(ndr_pull_rap_PrintJStatusCode(ndr, NDR_SCALARS, &r->JobStatus));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->JobStatusString));
	NDR_RETURN(ndr_pull_time_t(ndr, NDR_SCALARS, &r->TimeSubmitted));
	NDR_RETURN(ndr_pull_uint32(ndr, NDR_SCALARS, &r->JobSize));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->JobCommentString));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_JobInfo2(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintJobInfo2 *r)
{
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobID));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->Priority));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->UserName));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobPosition));
	NDR_RETURN(ndr_pull_rap_PrintJStatusCode(ndr, NDR_SCALARS, &r->JobStatus));
	NDR_RETURN(ndr_pull_time_t(ndr, NDR_SCALARS, &r->TimeSubmitted));
	NDR_RETURN(ndr_pull_uint32(ndr, NDR_SCALARS, &r->JobSize));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->JobCommentString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DocumentName));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_JobInfo3(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintJobInfo3 *r)
{
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobID));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->Priority));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->UserName));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->JobPosition));
	NDR_RETURN(ndr_pull_rap_PrintJStatusCode(ndr, NDR_SCALARS, &r->JobStatus));
	NDR_RETURN(ndr_pull_time_t(ndr, NDR_SCALARS, &r->TimeSubmitted));
	NDR_RETURN(ndr_pull_uint32(ndr, NDR_SCALARS, &r->JobSize));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->JobCommentString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DocumentName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->NotifyName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DataType));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintParameterString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->StatusString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->QueueName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintProcessorName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintProcessorParams));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DriverName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DriverDataOffset));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrinterNameOffset));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue0(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue0 *r)
{
	NDR_RETURN(ndr_pull_charset(ndr, NDR_SCALARS, &r->PrintQName, 13, sizeof(uint8_t), CH_DOS));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue1(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue1 *r)
{
	NDR_RETURN(ndr_pull_charset(ndr, NDR_SCALARS, &r->PrintQName, 13, sizeof(uint8_t), CH_DOS));
	NDR_RETURN(ndr_pull_uint8(ndr, NDR_SCALARS, &r->Pad1));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->Priority));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->StartTime));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->UntilTime));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->SeparatorPageFilename));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintProcessorDllName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintDestinationsName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintParameterString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->CommentString));
	NDR_RETURN(ndr_pull_rap_PrintQStatusCode(ndr, NDR_SCALARS, &r->PrintQStatus));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->PrintJobCount));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue2(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue2 *r)
{
	int i;
	RAP_RETURN(rap_pull_rap_PrintQueue1(mem_ctx, ndr, convert, &r->queue));
	r->job = talloc_zero_array(mem_ctx, struct rap_PrintJobInfo1, r->queue.PrintJobCount);
	if (r->job == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0; i < r->queue.PrintJobCount; i++) {
		RAP_RETURN(rap_pull_rap_JobInfo1(mem_ctx, ndr, convert, &r->job[i]));
	}

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue3(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue3 *r)
{
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintQueueName));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->Priority));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->StartTime));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->UntilTime));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->Pad));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->SeparatorPageFilename));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintProcessorDllName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintParameterString));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->CommentString));
	NDR_RETURN(ndr_pull_rap_PrintQStatusCode(ndr, NDR_SCALARS, &r->PrintQStatus));
	NDR_RETURN(ndr_pull_uint16(ndr, NDR_SCALARS, &r->PrintJobCount));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->Printers));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->DriverName));
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintDriverData));

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue4(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue4 *r)
{
	int i;
	RAP_RETURN(rap_pull_rap_PrintQueue3(mem_ctx, ndr, convert, &r->queue));
	r->job = talloc_zero_array(mem_ctx, struct rap_PrintJobInfo2, r->queue.PrintJobCount);
	if (r->job == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0; i < r->queue.PrintJobCount; i++) {
		RAP_RETURN(rap_pull_rap_JobInfo2(mem_ctx, ndr, convert, &r->job[i]));
	}

	return NT_STATUS_OK;
}

static NTSTATUS rap_pull_rap_PrintQueue5(TALLOC_CTX *mem_ctx, struct ndr_pull *ndr, uint16_t convert, struct rap_PrintQueue5 *r)
{
	RAP_RETURN(rap_pull_string(mem_ctx, ndr, convert, &r->PrintQueueName));

	return NT_STATUS_OK;
}

NTSTATUS smbcli_rap_netprintqenum(struct smbcli_tree *tree,
				  struct smb_iconv_convenience *iconv_convenience,
				  TALLOC_CTX *mem_ctx,
				  struct rap_NetPrintQEnum *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintQEnum))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_multiple_entries(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "B13");
		break;
	case 1:
		rap_cli_expect_format(call, "B13BWWWzzzzzWW");
		break;
	case 2:
		rap_cli_expect_format(call, "B13BWWWzzzzzWN");
		rap_cli_expect_extra_format(call, "WB21BB16B10zWWzDDz");
		break;
	case 3:
		rap_cli_expect_format(call, "zWWWWzzzzWWzzl");
		break;
	case 4:
		rap_cli_expect_format(call, "zWWWWzzzzWNzzl");
		rap_cli_expect_extra_format(call, "WWzWWDDzz");
		/* no mention of extra format in MS-RAP */
		break;
	case 5:
		rap_cli_expect_format(call, "z");
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintQEnum, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_zero_array(mem_ctx, union rap_printq_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			result = rap_pull_rap_PrintQueue0(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info0);
			break;
		case 1:
			result = rap_pull_rap_PrintQueue1(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info1);
			break;
		case 2:
			result = rap_pull_rap_PrintQueue2(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info2);
			break;
		case 3:
			result = rap_pull_rap_PrintQueue3(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info3);
			break;
		case 4:
			result = rap_pull_rap_PrintQueue4(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info4);
			break;
		case 5:
			result = rap_pull_rap_PrintQueue5(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info5);
			break;
		}
	}

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintQEnum, r);
	}

	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintqgetinfo(struct smbcli_tree *tree,
				     struct smb_iconv_convenience *iconv_convenience,
				     TALLOC_CTX *mem_ctx,
				     struct rap_NetPrintQGetInfo *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintQGetInfo))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_string(call, r->in.PrintQueueName);
	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_word(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "B13");
		break;
	case 1:
		rap_cli_expect_format(call, "B13BWWWzzzzzWW");
		break;
	case 2:
		rap_cli_expect_format(call, "B13BWWWzzzzzWN");
		break;
	case 3:
		rap_cli_expect_format(call, "zWWWWzzzzWWzzl");
		break;
	case 4:
		rap_cli_expect_format(call, "zWWWWzzzzWNzzl");
		break;
	case 5:
		rap_cli_expect_format(call, "z");
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintQGetInfo, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	switch(r->in.level) {
	case 0:
		result = rap_pull_rap_PrintQueue0(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info0);
		break;
	case 1:
		result = rap_pull_rap_PrintQueue1(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info1);
		break;
	case 2:
		result = rap_pull_rap_PrintQueue2(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info2);
		break;
	case 3:
		result = rap_pull_rap_PrintQueue3(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info3);
		break;
	case 4:
		result = rap_pull_rap_PrintQueue4(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info4);
		break;
	case 5:
		result = rap_pull_rap_PrintQueue5(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info5);
		break;
	}

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintQGetInfo, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobpause(struct smbcli_tree *tree,
				     struct smb_iconv_convenience *iconv_convenience,
				     TALLOC_CTX *mem_ctx,
				     struct rap_NetPrintJobPause *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobPause))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.JobID);

	rap_cli_expect_format(call, "W");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobPause, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobPause, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobcontinue(struct smbcli_tree *tree,
					struct smb_iconv_convenience *iconv_convenience,
					TALLOC_CTX *mem_ctx,
					struct rap_NetPrintJobContinue *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobContinue))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.JobID);

	rap_cli_expect_format(call, "W");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobContinue, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobContinue, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobdelete(struct smbcli_tree *tree,
				      struct smb_iconv_convenience *iconv_convenience,
				      TALLOC_CTX *mem_ctx,
				      struct rap_NetPrintJobDelete *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobDel))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.JobID);

	rap_cli_expect_format(call, "W");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobDelete, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobDelete, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintqueuepause(struct smbcli_tree *tree,
				       struct smb_iconv_convenience *iconv_convenience,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetPrintQueuePause *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintQPause))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_string(call, r->in.PrintQueueName);

	rap_cli_expect_format(call, "");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintQueuePause, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintQueuePause, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintqueueresume(struct smbcli_tree *tree,
					struct smb_iconv_convenience *iconv_convenience,
					TALLOC_CTX *mem_ctx,
					struct rap_NetPrintQueueResume *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintQContinue))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_string(call, r->in.PrintQueueName);

	rap_cli_expect_format(call, "");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintQueueResume, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintQueueResume, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintqueuepurge(struct smbcli_tree *tree,
				       struct smb_iconv_convenience *iconv_convenience,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetPrintQueuePurge *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintQPurge))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_string(call, r->in.PrintQueueName);

	rap_cli_expect_format(call, "");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintQueuePurge, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintQueuePurge, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobenum(struct smbcli_tree *tree,
				    struct smb_iconv_convenience *iconv_convenience,
				    TALLOC_CTX *mem_ctx,
				    struct rap_NetPrintJobEnum *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int i;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobEnum))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_string(call, r->in.PrintQueueName);
	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_multiple_entries(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "W");
		break;
	case 1:
		rap_cli_expect_format(call, "WB21BB16B10zWWzDDz");
		break;
	case 2:
		rap_cli_expect_format(call, "WWzWWDDzz");
		break;
	case 3:
		rap_cli_expect_format(call, "WWzWWDDzzzzzzzzzzlz");
		break;
	case 4:
		rap_cli_expect_format(call, "WWzWWDDzzzzzDDDDDDD");
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobEnum, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.count));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	r->out.info = talloc_zero_array(mem_ctx, union rap_printj_info, r->out.count);

	if (r->out.info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	result = NT_STATUS_OK;

	for (i=0; i<r->out.count; i++) {
		switch(r->in.level) {
		case 0:
			result = rap_pull_rap_JobInfo0(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info0);
			break;
		case 1:
			result = rap_pull_rap_JobInfo1(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info1);
			break;
		case 2:
			result = rap_pull_rap_JobInfo2(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info2);
			break;
		case 3:
			result = rap_pull_rap_JobInfo3(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info[i].info3);
			break;
		}
	}

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobEnum, r);
	}

	result = NT_STATUS_OK;

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobgetinfo(struct smbcli_tree *tree,
				       struct smb_iconv_convenience *iconv_convenience,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetPrintJobGetInfo *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobGetInfo))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.JobID);
	rap_cli_push_word(call, r->in.level);
	rap_cli_push_rcvbuf(call, r->in.bufsize);
	rap_cli_expect_word(call);

	switch(r->in.level) {
	case 0:
		rap_cli_expect_format(call, "W");
		break;
	case 1:
		rap_cli_expect_format(call, "WB21BB16B10zWWzDDz");
		break;
	case 2:
		rap_cli_expect_format(call, "WWzWWDDzz");
		break;
	case 3:
		rap_cli_expect_format(call, "WWzWWDDzzzzzzzzzzlz");
		break;
	case 4:
		rap_cli_expect_format(call, "WWzWWDDzzzzzDDDDDDD");
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobGetInfo, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.available));

	switch(r->in.level) {
	case 0:
		result = rap_pull_rap_JobInfo0(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info0);
		break;
	case 1:
		result = rap_pull_rap_JobInfo1(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info1);
		break;
	case 2:
		result = rap_pull_rap_JobInfo2(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info2);
		break;
	case 3:
		result = rap_pull_rap_JobInfo3(mem_ctx, call->ndr_pull_data, r->out.convert, &r->out.info.info3);
		break;
	default:
		result = NT_STATUS_NOT_IMPLEMENTED;
		break;
	}


	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobGetInfo, r);
	}

 done:
	talloc_free(call);
	return result;
}

NTSTATUS smbcli_rap_netprintjobsetinfo(struct smbcli_tree *tree,
				       struct smb_iconv_convenience *iconv_convenience,
				       TALLOC_CTX *mem_ctx,
				       struct rap_NetPrintJobSetInfo *r)
{
	struct rap_call *call;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (!(call = new_rap_cli_call(mem_ctx, iconv_convenience, RAP_WPrintJobSetInfo))) {
		return NT_STATUS_NO_MEMORY;
	}

	rap_cli_push_word(call, r->in.JobID);
	rap_cli_push_word(call, r->in.level);
	rap_cli_push_sendbuf(call, r->in.bufsize);
	rap_cli_push_param(call, r->in.ParamNum);

	switch (r->in.ParamNum) {
	case RAP_PARAM_JOBNUM:
	case RAP_PARAM_JOBPOSITION:
	case RAP_PARAM_JOBSTATUS:
		NDR_GOTO(ndr_push_uint16(call->ndr_push_param, NDR_SCALARS, r->in.Param.value));
		break;
	case RAP_PARAM_USERNAME:
	case RAP_PARAM_NOTIFYNAME:
	case RAP_PARAM_DATATYPE:
	case RAP_PARAM_PARAMETERS_STRING:
	case RAP_PARAM_JOBSTATUSSTR:
	case RAP_PARAM_JOBCOMMENT:
		NDR_GOTO(ndr_push_string(call->ndr_push_param, NDR_SCALARS, r->in.Param.string));
		break;
	case RAP_PARAM_TIMESUBMITTED:
	case RAP_PARAM_JOBSIZE:
		NDR_GOTO(ndr_push_uint32(call->ndr_push_param, NDR_SCALARS, r->in.Param.value4));
		break;
	default:
		result = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	/* not really sure if this is correct */
	rap_cli_expect_format(call, "WB21BB16B10zWWzDDz");

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_IN_DEBUG(rap_NetPrintJobSetInfo, r);
	}

	result = rap_cli_do_call(tree, iconv_convenience, call);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = NT_STATUS_INVALID_PARAMETER;

	NDR_GOTO(ndr_pull_rap_status(call->ndr_pull_param, NDR_SCALARS, &r->out.status));
	NDR_GOTO(ndr_pull_uint16(call->ndr_pull_param, NDR_SCALARS, &r->out.convert));

	result = NT_STATUS_OK;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_OUT_DEBUG(rap_NetPrintJobSetInfo, r);
	}

 done:
	talloc_free(call);
	return result;
}

static bool test_netservergetinfo(struct torture_context *tctx, 
				  struct smbcli_state *cli)
{
	struct rap_WserverGetInfo r;
	bool res = true;

	r.in.bufsize = 0xffff;

	r.in.level = 0;
	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netservergetinfo(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"rap_netservergetinfo level 0 failed");

	if (torture_setting_bool(tctx, "samba3", false)) {
		torture_skip(tctx, "skipping netservergetinfo level 1 against samba3");
	}

	r.in.level = 1;
	torture_assert_ntstatus_ok(tctx,
		smbcli_rap_netservergetinfo(cli->tree, lp_iconv_convenience(tctx->lp_ctx), tctx, &r),
		"rap_netservergetinfo level 1 failed");

	return res;
}

bool torture_rap_scan(struct torture_context *torture, struct smbcli_state *cli)
{
	int callno;

	for (callno = 0; callno < 0xffff; callno++) {
		struct rap_call *call = new_rap_cli_call(torture, lp_iconv_convenience(torture->lp_ctx), callno);
		NTSTATUS result;

		result = rap_cli_do_call(cli->tree, lp_iconv_convenience(torture->lp_ctx), call);

		if (!NT_STATUS_EQUAL(result, NT_STATUS_INVALID_PARAMETER))
			continue;

		printf("callno %d is RAP call\n", callno);
	}

	return true;
}

NTSTATUS torture_rap_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "RAP");
	struct torture_suite *suite_basic = torture_suite_create(suite, "BASIC");

	torture_suite_add_suite(suite, suite_basic);
	torture_suite_add_suite(suite, torture_rap_rpc(suite));
	torture_suite_add_suite(suite, torture_rap_printing(suite));

	torture_suite_add_1smb_test(suite_basic, "netserverenum", 
				    test_netserverenum);
	torture_suite_add_1smb_test(suite_basic, "netshareenum",
				    test_netshareenum);
	torture_suite_add_1smb_test(suite_basic, "netservergetinfo",
				    test_netservergetinfo);

	torture_suite_add_1smb_test(suite, "SCAN", torture_rap_scan);

	suite->description = talloc_strdup(suite, 
						"Remote Administration Protocol tests");

	torture_register_suite(suite);

	return NT_STATUS_OK;
}

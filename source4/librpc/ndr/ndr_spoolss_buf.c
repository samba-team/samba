/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling spoolss subcontext buffer structures

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Tim Potter 2003
   
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
#include "librpc/gen_ndr/ndr_spoolss.h"

#define NDR_SPOOLSS_PUSH_ENUM_OUT(fn,type) do { \
	DATA_BLOB buffer;\
	if (r->out.info) {\
		int i;\
		struct ndr_push *ndr2;\
\
		ndr2 = ndr_push_init_ctx(ndr);\
		if (!ndr2) {\
			return NT_STATUS_NO_MEMORY;\
		}\
\
		for (i=0;i<r->out.count;i++) {\
			ndr2->data += ndr2->offset;\
			ndr2->offset = 0;\
			NDR_CHECK(ndr_push_set_switch_value(ndr2, &(*r->out.info)[i], r->in.level)); \
			NDR_CHECK(ndr_push_##type(ndr2, NDR_SCALARS|NDR_BUFFERS, &(*r->out.info)[i]));\
		}\
		if (*r->in.buf_size >= ndr2->offset) {\
			buffer = data_blob_const(ndr2->data, ndr2->offset);\
		} else {\
			r->out.info = NULL;\
			r->out.count = 0;\
			r->out.result = WERR_INSUFFICIENT_BUFFER;\
		}\
		*r->out.buf_size = ndr2->offset;\
	}\
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->out.info));\
	if (r->out.info) {\
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, buffer));\
	}\
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->out.buf_size));\
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->out.count));\
	NDR_CHECK(ndr_push_WERROR(ndr, NDR_SCALARS, r->out.result));\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM_OUT(fn,type) do { \
	int i;\
	DATA_BLOB buffer;\
	struct ndr_pull *ndr2;\
\
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_info));\
	if (_ptr_info) {\
		NDR_ALLOC(ndr, r->out.info);\
	} else {\
		r->out.info = NULL;\
	}\
	if (r->out.info) {\
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, &buffer));\
		*r->out.info = NULL;\
	}\
	if (ndr->flags & LIBNDR_FLAG_REF_ALLOC) {\
		NDR_ALLOC(ndr, r->out.buf_size);\
	}\
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->out.buf_size));\
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->out.count));\
	NDR_CHECK(ndr_pull_WERROR(ndr, NDR_SCALARS, &r->out.result));\
\
	if (r->out.info == NULL && r->out.count) {\
		return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE,\
				      #fn ": r->out.count[%d] but r->out.info == NULL\n",\
				      r->out.count);\
	}\
\
	if (r->out.info && r->out.count) {\
		ndr2 = ndr_pull_init_blob(&buffer, ndr);\
		if (!ndr2) return NT_STATUS_NO_MEMORY;\
		NDR_ALLOC_N(ndr2, *r->out.info, r->out.count);\
		for (i=0;i<r->out.count;i++) {\
			ndr2->data += ndr2->offset;\
			ndr2->offset = 0;\
			NDR_CHECK(ndr_pull_set_switch_value(ndr2, &(*r->out.info)[i], r->in.level)); \
			NDR_CHECK(ndr_pull_##type(ndr2, NDR_SCALARS|NDR_BUFFERS, &(*r->out.info)[i]));\
		}\
	}\
} while(0)

#define NDR_SPOOLSS_PRINT_ENUM_OUT(fn,type) do { \
	ndr_print_struct(ndr, "out", #fn);\
	ndr->depth++;\
	ndr_print_ptr(ndr, "info", r->out.info);\
	ndr->depth++;\
	if (r->out.info) {\
		int i;\
		ndr->print(ndr, "%s: ARRAY(%d)", "info", r->out.count);\
		ndr->depth++;\
		for (i=0;i<r->out.count;i++) {\
			char *idx=NULL;\
			asprintf(&idx, "[%d]", i);\
			if (idx) {\
				ndr_print_set_switch_value(ndr, &((*r->out.info)[i]), r->in.level); \
				ndr_print_##type(ndr, idx, &((*r->out.info)[i]));\
				free(idx);\
			}\
		}\
		ndr->depth--;\
	}\
	ndr->depth--;\
	ndr_print_ptr(ndr, "buf_size", r->out.buf_size);\
	ndr->depth++;\
	ndr_print_uint32(ndr, "buf_size", *r->out.buf_size);\
	ndr->depth--;\
	ndr_print_uint32(ndr, "count", r->out.count);\
	ndr_print_WERROR(ndr, "result", r->out.result);\
	ndr->depth--;\
} while(0)

/*
  spoolss_EnumPrinters
*/
NTSTATUS ndr_push_spoolss_EnumPrinters(struct ndr_push *ndr, int flags, struct spoolss_EnumPrinters *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.flags));
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.server));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.server) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.server));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumPrinters,spoolss_PrinterInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrinters(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinters *r)
{
	uint32_t _ptr_server;
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.flags));
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_server));
	if (_ptr_server) {
		NDR_ALLOC(ndr, r->in.server);
	} else {
		r->in.server = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.server) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.server));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumPrinters,spoolss_PrinterInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumPrinters(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumPrinters *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumPrinters");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumPrinters");
		ndr->depth++;
		ndr_print_spoolss_EnumPrinterFlags(ndr, "flags", r->in.flags);
		ndr_print_ptr(ndr, "server", r->in.server);
		ndr->depth++;
		if (r->in.server) {
			ndr_print_string(ndr, "server", r->in.server);
		}
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumPrinters,spoolss_PrinterInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumJobs
*/
NTSTATUS ndr_push_spoolss_EnumJobs(struct ndr_push *ndr, int flags, struct spoolss_EnumJobs *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	NDR_CHECK(ndr_push_policy_handle(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.handle));
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.firstjob));
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.numjobs));
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumJobs,spoolss_JobInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumJobs(struct ndr_pull *ndr, int flags, struct spoolss_EnumJobs *r)
{
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	NDR_ALLOC(ndr, r->in.handle);
	NDR_CHECK(ndr_pull_policy_handle(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.handle));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.firstjob));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.numjobs));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumJobs,spoolss_JobInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumJobs(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumJobs *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumJobs");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumJobs");
		ndr->depth++;
		ndr_print_ptr(ndr, "handle", r->in.handle);
		ndr->depth++;
		ndr_print_policy_handle(ndr, "handle", r->in.handle);
		ndr->depth--;
		ndr_print_uint32(ndr, "firstjob", r->in.firstjob);
		ndr_print_uint32(ndr, "numjobs", r->in.numjobs);
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumJobs,spoolss_JobInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumPrinterDrivers
*/
NTSTATUS ndr_push_spoolss_EnumPrinterDrivers(struct ndr_push *ndr, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.server));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.server) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.server));
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.environment));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.environment) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.environment));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumPrinterDrivers,spoolss_DriverInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrinterDrivers(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	uint32_t _ptr_server;
	uint32_t _ptr_environment;
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_server));
	if (_ptr_server) {
		NDR_ALLOC(ndr, r->in.server);
	} else {
		r->in.server = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.server) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.server));
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_environment));
	if (_ptr_environment) {
		NDR_ALLOC(ndr, r->in.environment);
	} else {
		r->in.environment = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.environment) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.environment));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumPrinterDrivers,spoolss_DriverInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumPrinterDrivers(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumPrinterDrivers");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumPrinterDrivers");
		ndr->depth++;
		ndr_print_ptr(ndr, "server", r->in.server);
		ndr->depth++;
		if (r->in.server) {
			ndr_print_string(ndr, "server", r->in.server);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "environment", r->in.environment);
		ndr->depth++;
		if (r->in.environment) {
			ndr_print_string(ndr, "environment", r->in.environment);
		}
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumPrinterDrivers,spoolss_DriverInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumForms
*/
NTSTATUS ndr_push_spoolss_EnumForms(struct ndr_push *ndr, int flags, struct spoolss_EnumForms *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	NDR_CHECK(ndr_push_policy_handle(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.handle));
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumForms,spoolss_FormInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumForms(struct ndr_pull *ndr, int flags, struct spoolss_EnumForms *r)
{
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	NDR_ALLOC(ndr, r->in.handle);
	NDR_CHECK(ndr_pull_policy_handle(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.handle));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumForms,spoolss_FormInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumForms(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumForms *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumForms");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumForms");
		ndr->depth++;
		ndr_print_ptr(ndr, "handle", r->in.handle);
		ndr->depth++;
		ndr_print_policy_handle(ndr, "handle", r->in.handle);
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumForms,spoolss_FormInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumPorts
*/
NTSTATUS ndr_push_spoolss_EnumPorts(struct ndr_push *ndr, int flags, struct spoolss_EnumPorts *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.servername));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumPorts,spoolss_PortInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPorts(struct ndr_pull *ndr, int flags, struct spoolss_EnumPorts *r)
{
	uint32_t _ptr_servername;
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_servername));
	if (_ptr_servername) {
		NDR_ALLOC(ndr, r->in.servername);
	} else {
		r->in.servername = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumPorts,spoolss_PortInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumPorts(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumPorts *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumPorts");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumPorts");
		ndr->depth++;
		ndr_print_ptr(ndr, "servername", r->in.servername);
		ndr->depth++;
		if (r->in.servername) {
			ndr_print_string(ndr, "servername", r->in.servername);
		}
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumPorts,spoolss_PortInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumMonitors
*/
NTSTATUS ndr_push_spoolss_EnumMonitors(struct ndr_push *ndr, int flags, struct spoolss_EnumMonitors *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.servername));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumMonitors,spoolss_MonitorInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumMonitors(struct ndr_pull *ndr, int flags, struct spoolss_EnumMonitors *r)
{
	uint32_t _ptr_servername;
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_servername));
	if (_ptr_servername) {
		NDR_ALLOC(ndr, r->in.servername);
	} else {
		r->in.servername = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumMonitors,spoolss_MonitorInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumMonitors(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumMonitors *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumMonitors");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumMonitors");
		ndr->depth++;
		ndr_print_ptr(ndr, "servername", r->in.servername);
		ndr->depth++;
		if (r->in.servername) {
			ndr_print_string(ndr, "servername", r->in.servername);
		}
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumMonitors,spoolss_MonitorInfo);
	}
	ndr->depth--;
}

/*
  spoolss_EnumPrintProcessors
*/
NTSTATUS ndr_push_spoolss_EnumPrintProcessors(struct ndr_push *ndr, int flags, struct spoolss_EnumPrintProcessors *r)
{
	if (!(flags & NDR_IN)) goto ndr_out;

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.servername));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.environment));
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.environment) {
		NDR_CHECK(ndr_push_string(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.environment));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.level));
	NDR_CHECK(ndr_push_unique_ptr(ndr, r->in.buffer));
	if (r->in.buffer) {
		NDR_CHECK(ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buffer));
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, *r->in.buf_size));
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PUSH_ENUM_OUT(spoolss_EnumPrintProcessors,spoolss_PrintProcessorInfo);

	done:
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrintProcessors(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrintProcessors *r)
{
	uint32_t _ptr_servername;
	uint32_t _ptr_environment;
	uint32_t _ptr_buffer;
	uint32_t _ptr_info;
	if (!(flags & NDR_IN)) goto ndr_out;

	ZERO_STRUCT(r->out);

	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_servername));
	if (_ptr_servername) {
		NDR_ALLOC(ndr, r->in.servername);
	} else {
		r->in.servername = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.servername) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.servername));
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_environment));
	if (_ptr_environment) {
		NDR_ALLOC(ndr, r->in.environment);
	} else {
		r->in.environment = NULL;
	}
	ndr->flags = _flags_save_string;
	}
	{ uint32_t _flags_save_string = ndr->flags;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_LEN4);
	if (r->in.environment) {
		NDR_CHECK(ndr_pull_string(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.environment));
	}
	ndr->flags = _flags_save_string;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, &r->in.level));
	NDR_CHECK(ndr_pull_unique_ptr(ndr, &_ptr_buffer));
	if (_ptr_buffer) {
		NDR_ALLOC(ndr, r->in.buffer);
	} else {
		r->in.buffer = NULL;
	}
	if (r->in.buffer) {
		NDR_CHECK(ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buffer));
	}
	NDR_ALLOC(ndr, r->in.buf_size);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS|NDR_BUFFERS, r->in.buf_size));
	NDR_ALLOC(ndr, r->out.buf_size);
	*r->out.buf_size = *r->in.buf_size;
	ndr_out:
	if (!(flags & NDR_OUT)) goto done;

	NDR_SPOOLSS_PULL_ENUM_OUT(spoolss_EnumPrintProcessors,spoolss_PrintProcessorInfo);

	done:

	return NT_STATUS_OK;
}

void ndr_print_spoolss_EnumPrintProcessors(struct ndr_print *ndr, const char *name, int flags, struct spoolss_EnumPrintProcessors *r)
{
	ndr_print_struct(ndr, name, "spoolss_EnumPrintProcessors");
	ndr->depth++;
	if (flags & NDR_SET_VALUES) {
		ndr->flags |= LIBNDR_PRINT_SET_VALUES;
	}
	if (flags & NDR_IN) {
		ndr_print_struct(ndr, "in", "spoolss_EnumPrintProcessors");
		ndr->depth++;
		ndr_print_ptr(ndr, "servername", r->in.servername);
		ndr->depth++;
		if (r->in.servername) {
			ndr_print_string(ndr, "servername", r->in.servername);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "environment", r->in.environment);
		ndr->depth++;
		if (r->in.environment) {
			ndr_print_string(ndr, "environment", r->in.environment);
		}
		ndr->depth--;
		ndr_print_uint32(ndr, "level", r->in.level);
		ndr_print_ptr(ndr, "buffer", r->in.buffer);
		ndr->depth++;
		if (r->in.buffer) {
			ndr_print_DATA_BLOB(ndr, "buffer", *r->in.buffer);
		}
		ndr->depth--;
		ndr_print_ptr(ndr, "buf_size", r->in.buf_size);
		ndr->depth++;
		ndr_print_uint32(ndr, "buf_size", *r->in.buf_size);
		ndr->depth--;
		ndr->depth--;
	}
	if (flags & NDR_OUT) {
		NDR_SPOOLSS_PRINT_ENUM_OUT(spoolss_EnumPrintProcessors,spoolss_PrintProcessorInfo);
	}
	ndr->depth--;
}

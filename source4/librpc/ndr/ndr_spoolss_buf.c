/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling spoolss subcontext buffer structures

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Tim Potter 2003
   
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
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "param/param.h"

#define NDR_SPOOLSS_PUSH_ENUM_IN(fn) do { \
	if (!r->in.buffer && r->in.offered != 0) {\
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,\
			"SPOOLSS Buffer: r->in.offered[%u] but there's no buffer",\
			(unsigned)r->in.offered);\
	} else if (r->in.buffer && r->in.buffer->length != r->in.offered) {\
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,\
			"SPOOLSS Buffer: r->in.offered[%u] doesn't match length of r->in.buffer[%u]",\
			(unsigned)r->in.offered, (unsigned)r->in.buffer->length);\
	}\
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.offered	= r->in.offered;\
	NDR_CHECK(ndr_push__##fn(ndr, flags, &_r));\
} while(0)

#define NDR_SPOOLSS_PUSH_ENUM_OUT(fn) do { \
	struct ndr_push *_ndr_info;\
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.offered	= r->in.offered;\
	_r.out.info	= NULL;\
	_r.out.needed	= r->out.needed;\
	_r.out.count	= r->out.count;\
	_r.out.result	= r->out.result;\
	if (r->out.info && !r->in.buffer) {\
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,\
			"SPOOLSS Buffer: r->out.info but there's no r->in.buffer");\
	}\
	if (r->in.buffer) {\
		DATA_BLOB _data_blob_info;\
		_ndr_info = ndr_push_init_ctx(ndr, ndr->iconv_convenience);\
		NDR_ERR_HAVE_NO_MEMORY(_ndr_info);\
		_ndr_info->flags= ndr->flags;\
		if (r->out.info) {\
			struct __##fn __r;\
			__r.in.level	= r->in.level;\
			__r.in.count	= r->out.count;\
			__r.out.info	= r->out.info;\
			NDR_CHECK(ndr_push___##fn(_ndr_info, flags, &__r)); \
		}\
		if (r->in.offered > _ndr_info->offset) {\
			uint32_t _padding_len = r->in.offered - _ndr_info->offset;\
			NDR_CHECK(ndr_push_zero(_ndr_info, _padding_len));\
		} else if (r->in.offered < _ndr_info->offset) {\
			return ndr_push_error(ndr, NDR_ERR_BUFSIZE,\
				"SPOOLSS Buffer: r->in.offered[%u] doesn't match length of out buffer[%u]!",\
				(unsigned)r->in.offered, (unsigned)_ndr_info->offset);\
		}\
		_data_blob_info = ndr_push_blob(_ndr_info);\
		_r.out.info	= &_data_blob_info;\
	}\
	NDR_CHECK(ndr_push__##fn(ndr, flags, &_r));\
} while(0)

#define NDR_SPOOLSS_PUSH_ENUM(fn,in,out) do { \
	struct _##fn _r;\
	if (flags & NDR_IN) {\
		in;\
		NDR_SPOOLSS_PUSH_ENUM_IN(fn);\
	}\
	if (flags & NDR_OUT) {\
		out;\
		NDR_SPOOLSS_PUSH_ENUM_OUT(fn);\
	}\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM_IN(fn) do { \
	ZERO_STRUCT(r->out);\
	NDR_CHECK(ndr_pull__##fn(ndr, flags, &_r));\
	r->in.level	= _r.in.level;\
	r->in.buffer	= _r.in.buffer;\
	r->in.offered	= _r.in.offered;\
	r->out.needed	= _r.out.needed;\
	if (!r->in.buffer && r->in.offered != 0) {\
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,\
			"SPOOLSS Buffer: r->in.offered[%u] but there's no buffer",\
			(unsigned)r->in.offered);\
	} else if (r->in.buffer && r->in.buffer->length != r->in.offered) {\
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,\
			"SPOOLSS Buffer: r->in.offered[%u] doesn't match length of r->in.buffer[%u]",\
			(unsigned)r->in.offered, (unsigned)r->in.buffer->length);\
	}\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM_OUT(fn) do { \
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.offered	= r->in.offered;\
	_r.out.needed	= r->out.needed;\
	NDR_CHECK(ndr_pull__##fn(ndr, flags, &_r));\
	r->out.info	= NULL;\
	r->out.needed	= _r.out.needed;\
	r->out.count	= _r.out.count;\
	r->out.result	= _r.out.result;\
	if (_r.out.info) {\
		struct ndr_pull *_ndr_info = ndr_pull_init_blob(_r.out.info, ndr, ndr->iconv_convenience);\
		NDR_ERR_HAVE_NO_MEMORY(_ndr_info);\
		_ndr_info->flags= ndr->flags;\
		if (r->in.offered != _ndr_info->data_size) {\
			return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,\
				"SPOOLSS Buffer: offered[%u] doesn't match length of buffer[%u]",\
				(unsigned)r->in.offered, (unsigned)_ndr_info->data_size);\
		}\
		if (r->out.needed <= _ndr_info->data_size) {\
			struct __##fn __r;\
			__r.in.level	= r->in.level;\
			__r.in.count	= r->out.count;\
			__r.out.info	= NULL;\
			NDR_CHECK(ndr_pull___##fn(_ndr_info, flags, &__r));\
			r->out.info	= __r.out.info;\
		}\
	}\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM(fn,in,out) do { \
	struct _##fn _r;\
	if (flags & NDR_IN) {\
		out;\
		NDR_SPOOLSS_PULL_ENUM_IN(fn);\
		in;\
	}\
	if (flags & NDR_OUT) {\
		out;\
		NDR_SPOOLSS_PULL_ENUM_OUT(fn);\
	}\
} while(0)

#define _NDR_CHECK_UINT32(call) do {\
	enum ndr_err_code _ndr_err; \
        _ndr_err = call; \
	if (!NDR_ERR_CODE_IS_SUCCESS(_ndr_err)) { \
        	return 0; \
	}\
} while (0)

/* TODO: set _ndr_info->flags correct */
#define NDR_SPOOLSS_SIZE_ENUM(fn) do { \
	struct __##fn __r;\
	DATA_BLOB _data_blob_info;\
	struct ndr_push *_ndr_info = ndr_push_init_ctx(mem_ctx, iconv_convenience);\
	if (!_ndr_info) return 0;\
	_ndr_info->flags|=0;\
	__r.in.level	= level;\
	__r.in.count	= count;\
	__r.out.info	= info;\
	_NDR_CHECK_UINT32(ndr_push___##fn(_ndr_info, NDR_OUT, &__r)); \
	_data_blob_info = ndr_push_blob(_ndr_info);\
	return _data_blob_info.length;\
} while(0)

/*
  spoolss_EnumPrinters
*/
enum ndr_err_code ndr_push_spoolss_EnumPrinters(struct ndr_push *ndr, int flags, const struct spoolss_EnumPrinters *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrinters,{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	},{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumPrinters(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinters *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrinters,{
		r->in.flags	= _r.in.flags;
		r->in.server	= _r.in.server;
	},{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumPrinters_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_PrinterInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumPrinters);
}

/*
  spoolss_EnumJobs
*/
enum ndr_err_code ndr_push_spoolss_EnumJobs(struct ndr_push *ndr, int flags, const struct spoolss_EnumJobs *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumJobs,{
		_r.in.handle	= r->in.handle;
		_r.in.firstjob	= r->in.firstjob;
		_r.in.numjobs	= r->in.numjobs;
	},{
		_r.in.handle	= r->in.handle;
		_r.in.firstjob	= r->in.firstjob;
		_r.in.numjobs	= r->in.numjobs;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumJobs(struct ndr_pull *ndr, int flags, struct spoolss_EnumJobs *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumJobs,{
		r->in.handle	= _r.in.handle;
		r->in.firstjob	= _r.in.firstjob;
		r->in.numjobs	= _r.in.numjobs;
	},{
		_r.in.handle	= r->in.handle;
		_r.in.firstjob	= r->in.firstjob;
		_r.in.numjobs	= r->in.numjobs;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumJobss_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_JobInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumJobs);
}

/*
  spoolss_EnumPrinterDrivers
*/
enum ndr_err_code ndr_push_spoolss_EnumPrinterDrivers(struct ndr_push *ndr, int flags, const struct spoolss_EnumPrinterDrivers *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrinterDrivers,{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	},{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumPrinterDrivers(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrinterDrivers,{
		r->in.server		= _r.in.server;
		r->in.environment	= _r.in.environment;
	},{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumPrinterDrivers_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_DriverInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumPrinterDrivers);
}

/*
  spoolss_EnumForms
*/
enum ndr_err_code ndr_push_spoolss_EnumForms(struct ndr_push *ndr, int flags, const struct spoolss_EnumForms *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumForms,{
		_r.in.handle	= r->in.handle;
	},{
		_r.in.handle	= r->in.handle;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumForms(struct ndr_pull *ndr, int flags, struct spoolss_EnumForms *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumForms,{
		r->in.handle	= _r.in.handle;
	},{
		_r.in.handle	= r->in.handle;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumForms_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_FormInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumForms);
}

/*
  spoolss_EnumPorts
*/
enum ndr_err_code ndr_push_spoolss_EnumPorts(struct ndr_push *ndr, int flags, const struct spoolss_EnumPorts *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPorts,{
		_r.in.servername= r->in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumPorts(struct ndr_pull *ndr, int flags, struct spoolss_EnumPorts *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPorts,{
		r->in.servername= _r.in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumPorts_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_PortInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumPorts);
}

/*
  spoolss_EnumMonitors
*/
enum ndr_err_code ndr_push_spoolss_EnumMonitors(struct ndr_push *ndr, int flags, const struct spoolss_EnumMonitors *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumMonitors,{
		_r.in.servername= r->in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumMonitors(struct ndr_pull *ndr, int flags, struct spoolss_EnumMonitors *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumMonitors,{
		r->in.servername= _r.in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumMonitors_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, uint32_t level, uint32_t count, union spoolss_MonitorInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumMonitors);
}

/*
  spoolss_EnumPrintProcessors
*/
enum ndr_err_code ndr_push_spoolss_EnumPrintProcessors(struct ndr_push *ndr, int flags, const struct spoolss_EnumPrintProcessors *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrintProcessors,{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	},{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	});
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_EnumPrintProcessors(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrintProcessors *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrintProcessors,{
		r->in.servername	= _r.in.servername;
		r->in.environment	= _r.in.environment;
	},{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	});
	return NDR_ERR_SUCCESS;
}

uint32_t ndr_size_spoolss_EnumPrinterProcessors_info(TALLOC_CTX *mem_ctx, struct smb_iconv_convenience *iconv_convenience, 
													 uint32_t level, uint32_t count, union spoolss_PrintProcessorInfo *info)
{
	NDR_SPOOLSS_SIZE_ENUM(spoolss_EnumPrintProcessors);
}

/*
  spoolss_GetPrinterData
*/
enum ndr_err_code ndr_push_spoolss_GetPrinterData(struct ndr_push *ndr, int flags, const struct spoolss_GetPrinterData *r)
{
	struct _spoolss_GetPrinterData _r;
	if (flags & NDR_IN) {
		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.offered	= r->in.offered;
		NDR_CHECK(ndr_push__spoolss_GetPrinterData(ndr, flags, &_r));
	}
	if (flags & NDR_OUT) {
		struct ndr_push *_ndr_info;
		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.offered	= r->in.offered;
		_r.out.type	= r->out.type;
		_r.out.data	= data_blob(NULL, 0);
		_r.out.needed	= r->out.needed;
		_r.out.result	= r->out.result;
		{
			struct __spoolss_GetPrinterData __r;
			_ndr_info = ndr_push_init_ctx(ndr, ndr->iconv_convenience);
			NDR_ERR_HAVE_NO_MEMORY(_ndr_info);
			_ndr_info->flags= ndr->flags;
			__r.in.type	= r->out.type;
			__r.out.data	= r->out.data;
			NDR_CHECK(ndr_push___spoolss_GetPrinterData(_ndr_info, flags, &__r));
			if (r->in.offered > _ndr_info->offset) {
				uint32_t _padding_len = r->in.offered - _ndr_info->offset;
				NDR_CHECK(ndr_push_zero(_ndr_info, _padding_len));
			}
			_r.out.data = ndr_push_blob(_ndr_info);
		}
		NDR_CHECK(ndr_push__spoolss_GetPrinterData(ndr, flags, &_r));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_spoolss_GetPrinterData(struct ndr_pull *ndr, int flags, struct spoolss_GetPrinterData *r)
{
	struct _spoolss_GetPrinterData _r;
	if (flags & NDR_IN) {
		ZERO_STRUCT(r->out);

		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.offered	= r->in.offered;
		_r.out.type	= r->out.type;
		_r.out.data	= data_blob(NULL,0),
		_r.out.needed	= r->out.needed;
		NDR_CHECK(ndr_pull__spoolss_GetPrinterData(ndr, flags, &_r));
		r->in.handle	= _r.in.handle;
		r->in.value_name= _r.in.value_name;
		r->in.offered	= _r.in.offered;
		r->out.needed	= _r.out.needed;
	}
	if (flags & NDR_OUT) {
		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.offered	= r->in.offered;
		_r.out.type	= r->out.type;
		_r.out.data	= data_blob(NULL,0),
		_r.out.needed	= r->out.needed;
		_r.out.result	= r->out.result;
		NDR_CHECK(ndr_pull__spoolss_GetPrinterData(ndr, flags, &_r));
		r->out.type	= _r.out.type;
		ZERO_STRUCT(r->out.data);
		r->out.needed	= _r.out.needed;
		r->out.result	= _r.out.result;
		if (_r.out.data.length != r->in.offered) {
			return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
				"SPOOLSS Buffer: r->in.offered[%u] doesn't match length of out buffer[%u]",
				(unsigned)r->in.offered, (unsigned)_r.out.data.length);
		}
		if (_r.out.data.length > 0 && r->out.needed <= _r.out.data.length) {
			struct __spoolss_GetPrinterData __r;
			struct ndr_pull *_ndr_data = ndr_pull_init_blob(&_r.out.data, ndr, ndr->iconv_convenience);
			NDR_ERR_HAVE_NO_MEMORY(_ndr_data);
			_ndr_data->flags= ndr->flags;
			__r.in.type	= r->out.type;
			__r.out.data	= r->out.data;
			NDR_CHECK(ndr_pull___spoolss_GetPrinterData(_ndr_data, flags, &__r));
			r->out.data	= __r.out.data;
		} else {
			r->out.type	= SPOOLSS_PRINTER_DATA_TYPE_NULL;
		}
	}
	return NDR_ERR_SUCCESS;
}

/*
  spoolss_SetPrinterData
*/
enum ndr_err_code ndr_push_spoolss_SetPrinterData(struct ndr_push *ndr, int flags, const struct spoolss_SetPrinterData *r)
{
	struct _spoolss_SetPrinterData _r;
	if (flags & NDR_IN) {
		struct ndr_push *_ndr_data;
		struct __spoolss_SetPrinterData __r;
		DATA_BLOB _data_blob_data;

		_ndr_data = ndr_push_init_ctx(ndr, ndr->iconv_convenience);
		NDR_ERR_HAVE_NO_MEMORY(_ndr_data);
		_ndr_data->flags= ndr->flags;

		__r.in.type	= r->in.type;
		__r.out.data	= r->in.data;
		NDR_CHECK(ndr_push___spoolss_SetPrinterData(_ndr_data, NDR_OUT, &__r));
		_data_blob_data = ndr_push_blob(_ndr_data);

		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.type	= r->in.type;
		_r.in.data	= _data_blob_data;
		_r.in._offered	= _data_blob_data.length;
		_r.out.result	= r->out.result;
		NDR_CHECK(ndr_push__spoolss_SetPrinterData(ndr, flags, &_r));
	}
	if (flags & NDR_OUT) {
		_r.in.handle	= r->in.handle;
		_r.in.value_name= r->in.value_name;
		_r.in.type	= r->in.type;
		_r.in.data	= data_blob(NULL,0),
		_r.in._offered	= r->in._offered;
		_r.out.result	= r->out.result;
		NDR_CHECK(ndr_push__spoolss_SetPrinterData(ndr, flags, &_r));
	}
	return NDR_ERR_SUCCESS;
}

uint32_t _ndr_size_spoolss_DeviceMode(struct spoolss_DeviceMode *devmode, struct smb_iconv_convenience *ic, uint32_t flags)
{
	if (!devmode) return 0;
	return ndr_size_spoolss_DeviceMode(devmode,ic,flags);
}

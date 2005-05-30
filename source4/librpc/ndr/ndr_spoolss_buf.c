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

#define NDR_SPOOLSS_PUSH_ENUM_IN(fn) do { \
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.buf_size	= r->in.buf_size;\
	NDR_CHECK(ndr_push__##fn(ndr, flags, &_r));\
} while(0)

#define NDR_SPOOLSS_PUSH_ENUM_OUT(fn) do { \
	struct ndr_push *_ndr_info;\
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.buf_size	= r->in.buf_size;\
	_r.out.buffer	= NULL;\
	_r.out.buf_size	= r->out.buf_size;\
	_r.out.count	= r->out.count;\
	_r.out.result	= r->out.result;\
	if (r->out.info) {\
		struct __##fn __r;\
		DATA_BLOB _data_blob_info;\
		_ndr_info = ndr_push_init_ctx(ndr);\
		if (!_ndr_info) return NT_STATUS_NO_MEMORY;\
		__r.in.level	= r->in.level;\
		__r.in.count	= r->out.count;\
		__r.out.info	= r->out.info;\
		NDR_CHECK(ndr_push___##fn(_ndr_info, flags, &__r)); \
		_data_blob_info = ndr_push_blob(_ndr_info);\
		_r.out.buffer	= &_data_blob_info;\
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
	r->in.buf_size	= _r.in.buf_size;\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM_OUT(fn) do { \
	struct ndr_pull *_ndr_info;\
	_r.in.level	= r->in.level;\
	_r.in.buffer	= r->in.buffer;\
	_r.in.buf_size	= r->in.buf_size;\
	_r.out.buf_size	= r->out.buf_size;\
	NDR_CHECK(ndr_pull__##fn(ndr, flags, &_r));\
	r->out.info	= NULL;\
	r->out.buf_size = _r.out.buf_size;\
	r->out.count	= _r.out.count;\
	r->out.result	= _r.out.result;\
	if (_r.out.buffer) {\
		struct __##fn __r;\
		_ndr_info = ndr_pull_init_blob(_r.out.buffer, ndr);\
		if (!_ndr_info) return NT_STATUS_NO_MEMORY;\
		__r.in.level	= r->in.level;\
		__r.in.count	= r->out.count;\
		__r.out.info	= NULL;\
		NDR_CHECK(ndr_pull___##fn(_ndr_info, flags, &__r));\
		r->out.info	= __r.out.info;\
	}\
} while(0)

#define NDR_SPOOLSS_PULL_ENUM(fn,in,out) do { \
	struct _##fn _r;\
	if (flags & NDR_IN) {\
		in;\
		NDR_SPOOLSS_PULL_ENUM_IN(fn);\
	}\
	if (flags & NDR_OUT) {\
		out;\
		NDR_SPOOLSS_PULL_ENUM_OUT(fn);\
	}\
} while(0)

/*
  spoolss_EnumPrinters
*/
NTSTATUS ndr_push_spoolss_EnumPrinters(struct ndr_push *ndr, int flags, struct spoolss_EnumPrinters *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrinters,{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	},{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrinters(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinters *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrinters,{
		r->in.flags	= _r.in.flags;
		r->in.server	= _r.in.server;
	},{
		_r.in.flags	= r->in.flags;
		_r.in.server	= r->in.server;
	});
	return NT_STATUS_OK;
}

/*
  spoolss_EnumJobs
*/
NTSTATUS ndr_push_spoolss_EnumJobs(struct ndr_push *ndr, int flags, struct spoolss_EnumJobs *r)
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
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumJobs(struct ndr_pull *ndr, int flags, struct spoolss_EnumJobs *r)
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
	return NT_STATUS_OK;
}

/*
  spoolss_EnumPrinterDrivers
*/
NTSTATUS ndr_push_spoolss_EnumPrinterDrivers(struct ndr_push *ndr, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrinterDrivers,{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	},{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrinterDrivers(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrinterDrivers *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrinterDrivers,{
		r->in.server		= _r.in.server;
		r->in.environment	= _r.in.environment;
	},{
		_r.in.server		= r->in.server;
		_r.in.environment	= r->in.environment;
	});
	return NT_STATUS_OK;
}

/*
  spoolss_EnumForms
*/
NTSTATUS ndr_push_spoolss_EnumForms(struct ndr_push *ndr, int flags, struct spoolss_EnumForms *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumForms,{
		_r.in.handle	= r->in.handle;
	},{
		_r.in.handle	= r->in.handle;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumForms(struct ndr_pull *ndr, int flags, struct spoolss_EnumForms *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumForms,{
		r->in.handle	= _r.in.handle;
	},{
		_r.in.handle	= r->in.handle;
	});
	return NT_STATUS_OK;
}

/*
  spoolss_EnumPorts
*/
NTSTATUS ndr_push_spoolss_EnumPorts(struct ndr_push *ndr, int flags, struct spoolss_EnumPorts *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPorts,{
		_r.in.servername= r->in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPorts(struct ndr_pull *ndr, int flags, struct spoolss_EnumPorts *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPorts,{
		r->in.servername= _r.in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NT_STATUS_OK;
}

/*
  spoolss_EnumMonitors
*/
NTSTATUS ndr_push_spoolss_EnumMonitors(struct ndr_push *ndr, int flags, struct spoolss_EnumMonitors *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumMonitors,{
		_r.in.servername= r->in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumMonitors(struct ndr_pull *ndr, int flags, struct spoolss_EnumMonitors *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumMonitors,{
		r->in.servername= _r.in.servername;
	},{
		_r.in.servername= r->in.servername;
	});
	return NT_STATUS_OK;
}

/*
  spoolss_EnumPrintProcessors
*/
NTSTATUS ndr_push_spoolss_EnumPrintProcessors(struct ndr_push *ndr, int flags, struct spoolss_EnumPrintProcessors *r)
{
	NDR_SPOOLSS_PUSH_ENUM(spoolss_EnumPrintProcessors,{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	},{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	});
	return NT_STATUS_OK;
}

NTSTATUS ndr_pull_spoolss_EnumPrintProcessors(struct ndr_pull *ndr, int flags, struct spoolss_EnumPrintProcessors *r)
{
	NDR_SPOOLSS_PULL_ENUM(spoolss_EnumPrintProcessors,{
		r->in.servername	= r->in.servername;
		r->in.environment	= r->in.environment;
	},{
		_r.in.servername	= r->in.servername;
		_r.in.environment	= r->in.environment;
	});
	return NT_STATUS_OK;
}

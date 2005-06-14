/* 
   Unix SMB/CIFS implementation.

   endpoint server for the spoolss pipe

   Copyright (C) Tim Potter 2004
   Copyright (C) Stefan Metzmacher 2005
   
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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "rpc_server/common/common.h"
#include "rpc_server/spoolss/dcesrv_spoolss.h"
#include "lib/socket/socket.h"
#include "smbd/service_stream.h"

#define SPOOLSS_BUFFER_SIZE(fn,level,count,info) \
	ndr_size_##fn##_info(dce_call, level, count, info)

#define SPOOLSS_BUFFER_OK(val_true,val_false) ((r->in.offered >= r->out.needed)?val_true:val_false)

/* 
  spoolss_EnumPrinters 
*/
static WERROR spoolss_EnumPrinters(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinters *r)
{
	void *spoolss_ctx;
	struct ldb_message **msgs;
	int count;
	int i;
	union spoolss_PrinterInfo *info;

	spoolss_ctx = spoolssdb_connect();
	W_ERROR_HAVE_NO_MEMORY(spoolss_ctx);

	count = spoolssdb_search(spoolss_ctx, mem_ctx, NULL, &msgs, NULL,
			       "(&(objectclass=printer))");
	spoolssdb_close(spoolss_ctx);

	if (count == 0) return WERR_OK;
	if (count < 0) return WERR_GENERAL_FAILURE;

	info = talloc_array(mem_ctx, union spoolss_PrinterInfo, count);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch(r->in.level) {
	case 1:
		for (i = 0; i < count; i++) {
			info[i].info1.flags		= samdb_result_uint(msgs[i], "flags", 0);

			info[i].info1.name		= samdb_result_string(msgs[i], "name", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info1.name);

			info[i].info1.description	= samdb_result_string(msgs[i], "description", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info1.description);

			info[i].info1.comment		= samdb_result_string(msgs[i], "comment", NULL);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinters, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 2:
		for (i = 0; i < count; i++) {
			info[i].info2.servername	= samdb_result_string(msgs[i], "servername", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.servername);

			info[i].info2.printername	= samdb_result_string(msgs[i], "printername", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.printername);

			info[i].info2.sharename		= samdb_result_string(msgs[i], "sharename", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.sharename);

			info[i].info2.portname		= samdb_result_string(msgs[i], "portname", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.portname);

			info[i].info2.drivername	= samdb_result_string(msgs[i], "drivername", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.drivername);

			info[i].info2.comment		= samdb_result_string(msgs[i], "comment", NULL);

			info[i].info2.location		= samdb_result_string(msgs[i], "location", NULL);

			info[i].info2.devmode		= NULL;

			info[i].info2.sepfile		= samdb_result_string(msgs[i], "sepfile", NULL);

			info[i].info2.printprocessor	= samdb_result_string(msgs[i], "printprocessor", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.printprocessor);

			info[i].info2.datatype		= samdb_result_string(msgs[i], "datatype", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.datatype);

			info[i].info2.parameters	= samdb_result_string(msgs[i], "parameters", NULL);

			info[i].info2.secdesc		= NULL;

			info[i].info2.attributes	= samdb_result_uint(msgs[i], "attributes", 0);
			info[i].info2.priority		= samdb_result_uint(msgs[i], "priority", 0);
			info[i].info2.defaultpriority	= samdb_result_uint(msgs[i], "defaultpriority", 0);
			info[i].info2.starttime		= samdb_result_uint(msgs[i], "starttime", 0);
			info[i].info2.untiltime		= samdb_result_uint(msgs[i], "untiltime", 0);
			info[i].info2.status		= samdb_result_uint(msgs[i], "status", 0);
			info[i].info2.cjobs		= samdb_result_uint(msgs[i], "cjobs", 0);
			info[i].info2.averageppm	= samdb_result_uint(msgs[i], "averageppm", 0);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinters, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 4:
		for (i = 0; i < count; i++) {
			info[i].info4.printername	= samdb_result_string(msgs[i], "printername", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.printername);

			info[i].info4.servername	= samdb_result_string(msgs[i], "servername", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.servername);

			info[i].info4.attributes	= samdb_result_uint(msgs[i], "attributes", 0);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinters, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 5:
		for (i = 0; i < count; i++) {
			info[i].info5.printername	= samdb_result_string(msgs[i], "name", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info5.printername);

			info[i].info5.portname		= samdb_result_string(msgs[i], "port", "");
			W_ERROR_HAVE_NO_MEMORY(info[i].info5.portname);

			info[i].info5.attributes	= samdb_result_uint(msgs[i], "attributes", 0);
			info[i].info5.device_not_selected_timeout = samdb_result_uint(msgs[i], "device_not_selected_timeout", 0);
			info[i].info5.transmission_retry_timeout  = samdb_result_uint(msgs[i], "transmission_retry_timeout", 0);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinters, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	}

	return WERR_UNKNOWN_LEVEL;
}

static WERROR spoolss_OpenPrinterEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_OpenPrinterEx *r);
/* 
  spoolss_OpenPrinter 
*/
static WERROR spoolss_OpenPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_OpenPrinter *r)
{
	WERROR status;
	struct spoolss_OpenPrinterEx *r2;

	r2 = talloc(mem_ctx, struct spoolss_OpenPrinterEx);
	W_ERROR_HAVE_NO_MEMORY(r2);

	r2->in.printername	= r->in.printername;
	r2->in.datatype		= r->in.datatype;
	r2->in.devmode_ctr	= r->in.devmode_ctr;
	r2->in.access_mask	= r->in.access_mask;
	r2->in.level		= 1;
	r2->in.userlevel.level1	= NULL;

	r2->out.handle		= r->out.handle;

	/* TODO: we should take care about async replies here,
	         if spoolss_OpenPrinterEx() would be async!
	 */
	status = spoolss_OpenPrinterEx(dce_call, mem_ctx, r2);

	r->out.handle		= r2->out.handle;

	return status;
}


/* 
  spoolss_SetJob 
*/
static WERROR spoolss_SetJob(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SetJob *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetJob 
*/
static WERROR spoolss_GetJob(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetJob *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumJobs 
*/
static WERROR spoolss_EnumJobs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumJobs *r)
{
	return WERR_OK;
}


/* 
  spoolss_AddPrinter 
*/
static WERROR spoolss_AddPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinter 
*/
static WERROR spoolss_DeletePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_SetPrinter 
*/
static WERROR spoolss_SetPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SetPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetPrinter 
*/
static WERROR spoolss_GetPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPrinterDriver 
*/
static WERROR spoolss_AddPrinterDriver(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrinterDriver *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrinterDrivers 
*/
static WERROR spoolss_EnumPrinterDrivers(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinterDrivers *r)
{
	union spoolss_DriverInfo *info;
	int count;
	int i;

	count = 0;

	if (count == 0) return WERR_OK;
	if (count < 0) return WERR_GENERAL_FAILURE;

	info = talloc_array(mem_ctx, union spoolss_DriverInfo, count);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case 1:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 2:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 3:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 4:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 5:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 6:
		for (i=0; i < count; i++) {
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPrinterDrivers, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  spoolss_GetPrinterDriver 
*/
static WERROR spoolss_GetPrinterDriver(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinterDriver *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetPrinterDriverDirectory 
*/
static WERROR spoolss_GetPrinterDriverDirectory(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinterDriverDirectory *r)
{
	union spoolss_DriverDirectoryInfo *info;
	const char *prefix;
	const char *postfix;

	/*
	 * NOTE: normally r->in.level is 1, but both w2k3 and nt4 sp6a
	 *        are ignoring the r->in.level completely, so we do :-)
	 */
       
	/*
	 * TODO: check the server name is ours
	 * - if it's a invalid UNC then return WERR_INVALID_NAME
	 * - if it's the wrong host name return WERR_INVALID_PARAM
	 * - if it's "" then we need to return a local WINDOWS path
	 */
	if (strcmp("", r->in.server) == 0) {
		prefix = "C:\\DRIVERS";
	} else {
		prefix = talloc_asprintf(mem_ctx, "%s\\print$", r->in.server);
		W_ERROR_HAVE_NO_MEMORY(prefix);
	}

	if (strcmp(SPOOLSS_ARCHITECTURE_NT_X86, r->in.environment) == 0) {
		postfix = "W32X86";
	} else {
		return WERR_INVALID_ENVIRONMENT;
	}

	info = talloc(mem_ctx, union spoolss_DriverDirectoryInfo);
	W_ERROR_HAVE_NO_MEMORY(info);

	info->info1.directory_name	= talloc_asprintf(mem_ctx, "%s\\%s", prefix, postfix);
	W_ERROR_HAVE_NO_MEMORY(info->info1.directory_name);

	r->out.needed	= ndr_size_spoolss_DriverDirectoryInfo(info, r->in.level, 0);
	r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
	return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
}


/* 
  spoolss_DeletePrinterDriver 
*/
static WERROR spoolss_DeletePrinterDriver(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterDriver *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPrintProcessor 
*/
static WERROR spoolss_AddPrintProcessor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrintProcessor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrintProcessors 
*/
static WERROR spoolss_EnumPrintProcessors(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrintProcessors *r)
{
	return WERR_OK;
}


/* 
  spoolss_GetPrintProcessorDirectory 
*/
static WERROR spoolss_GetPrintProcessorDirectory(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrintProcessorDirectory *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_StartDocPrinter 
*/
static WERROR spoolss_StartDocPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_StartDocPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_StartPagePrinter 
*/
static WERROR spoolss_StartPagePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_StartPagePrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_WritePrinter 
*/
static WERROR spoolss_WritePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_WritePrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EndPagePrinter 
*/
static WERROR spoolss_EndPagePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EndPagePrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AbortPrinter 
*/
static WERROR spoolss_AbortPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AbortPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ReadPrinter 
*/
static WERROR spoolss_ReadPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ReadPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EndDocPrinter 
*/
static WERROR spoolss_EndDocPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EndDocPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddJob 
*/
static WERROR spoolss_AddJob(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddJob *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ScheduleJob 
*/
static WERROR spoolss_ScheduleJob(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ScheduleJob *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetPrinterData 
*/
static WERROR spoolss_GetPrinterData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinterData *r)
{
	struct dcesrv_handle *h;
	WERROR status = WERR_INVALID_PARAM;
	enum spoolss_PrinterDataType type = SPOOLSS_PRINTER_DATA_TYPE_NULL;
	union spoolss_PrinterData data;

	DCESRV_PULL_HANDLE_WERR(h, r->in.handle, DCESRV_HANDLE_ANY);

	if (h->wire_handle.handle_type == SPOOLSS_HANDLE_SERVER) {
		/* TODO: do access check here */

		if (strcmp("W3SvcInstalled", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("BeepEnabled", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("EventLog", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("NetPopup", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("NetPopupToComputer", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("MajorVersion", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 3;
			status		= WERR_OK;
		} else if (strcmp("MinorVersion", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 0;
			status		= WERR_OK;
		} else if (strcmp("DefaultSpoolDirectory", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_STRING;
			data.string	= "C:\\PRINTERS";
			status		= WERR_OK;
		} else if (strcmp("Architecture", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_STRING;
			data.string	= SPOOLSS_ARCHITECTURE_NT_X86;
			status		= WERR_OK;
		} else if (strcmp("DsPresent", r->in.value_name) == 0) {
			type		= SPOOLSS_PRINTER_DATA_TYPE_UINT32;
			data.value	= 1;
			status		= WERR_OK;
		}
	}

	if (W_ERROR_IS_OK(status)) {
		r->out.needed	= ndr_size_spoolss_PrinterData(&data, type, 0);
		r->out.type	= SPOOLSS_BUFFER_OK(type, SPOOLSS_PRINTER_DATA_TYPE_NULL);
		r->out.data	= SPOOLSS_BUFFER_OK(data, data);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_MORE_DATA);
	}

	return status;
}


/* 
  spoolss_SetPrinterData 
*/
static WERROR spoolss_SetPrinterData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SetPrinterData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_WaitForPrinterChange 
*/
static WERROR spoolss_WaitForPrinterChange(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_WaitForPrinterChange *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ClosePrinter 
*/
static WERROR spoolss_ClosePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ClosePrinter *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE_WERR(h, r->in.handle, DCESRV_HANDLE_ANY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return WERR_OK;
}


/* 
  spoolss_AddForm 
*/
static WERROR spoolss_AddForm(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddForm *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeleteForm 
*/
static WERROR spoolss_DeleteForm(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeleteForm *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetForm 
*/
static WERROR spoolss_GetForm(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetForm *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_SetForm 
*/
static WERROR spoolss_SetForm(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SetForm *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumForms 
*/
static WERROR spoolss_EnumForms(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumForms *r)
{
	union spoolss_FormInfo *info;
	int count;
	int i;
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE_WERR(h, r->in.handle, DCESRV_HANDLE_ANY);

	count = 1;

	if (count == 0) return WERR_OK;
	if (count < 0) return WERR_GENERAL_FAILURE;

	info = talloc_array(mem_ctx, union spoolss_FormInfo, count);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case 1:
		for (i=0; i < count; i++) {
			info[i].info1.flags		= SPOOLSS_FORM_PRINTER;

			info[i].info1.form_name		= talloc_strdup(mem_ctx, "Letter");
			W_ERROR_HAVE_NO_MEMORY(info[i].info1.form_name);

			info[i].info1.size.width	= 0x34b5c;
			info[i].info1.size.height	= 0x44368;

			info[i].info1.area.left		= 0;
			info[i].info1.area.top		= 0;
			info[i].info1.area.right	= 0x34b5c;
			info[i].info1.area.bottom	= 0x44368;
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumForms, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  spoolss_EnumPorts 
*/
static WERROR spoolss_EnumPorts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPorts *r)
{
	union spoolss_PortInfo *info;
	int count;
	int i;

	count = 1;

	if (count == 0) return WERR_OK;
	if (count < 0) return WERR_GENERAL_FAILURE;

	info = talloc_array(mem_ctx, union spoolss_PortInfo, count);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case 1:
		for (i=0; i < count; i++) {
			info[i].info1.port_name	= talloc_strdup(mem_ctx, "Samba Printer Port");
			W_ERROR_HAVE_NO_MEMORY(info[i].info1.port_name);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPorts, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 2:
		for (i=0; i < count; i++) {
			info[i].info2.port_name		= talloc_strdup(mem_ctx, "Samba Printer Port");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.port_name);

			info[i].info2.monitor_name	= talloc_strdup(mem_ctx, "Local Monitor");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.monitor_name);

			info[i].info2.description	= talloc_strdup(mem_ctx, "Local Port");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.description);

			info[i].info2.port_type		= SPOOLSS_PORT_TYPE_WRITE;
			info[i].info2.reserved		= 0;
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumPorts, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  spoolss_EnumMonitors 
*/
static WERROR spoolss_EnumMonitors(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumMonitors *r)
{
	union spoolss_MonitorInfo *info;
	int count;
	int i;

	count = 1;

	if (count == 0) return WERR_OK;
	if (count < 0) return WERR_GENERAL_FAILURE;

	info = talloc_array(mem_ctx, union spoolss_MonitorInfo, count);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case 1:
		for (i=0; i < count; i++) {
			info[i].info1.monitor_name	= talloc_strdup(mem_ctx, "Standard TCP/IP Port");
			W_ERROR_HAVE_NO_MEMORY(info[i].info1.monitor_name);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumMonitors, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	case 2:
		for (i=0; i < count; i++) {
			info[i].info2.monitor_name	= talloc_strdup(mem_ctx, "Standard TCP/IP Port");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.monitor_name);

			info[i].info2.environment	= talloc_strdup(mem_ctx, SPOOLSS_ARCHITECTURE_NT_X86);
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.environment);

			info[i].info2.dll_name		= talloc_strdup(mem_ctx, "tcpmon.dll");
			W_ERROR_HAVE_NO_MEMORY(info[i].info2.dll_name);
		}
		r->out.needed	= SPOOLSS_BUFFER_SIZE(spoolss_EnumMonitors, r->in.level, count, info);
		r->out.info	= SPOOLSS_BUFFER_OK(info, NULL);
		r->out.count	= SPOOLSS_BUFFER_OK(count, 0);
		return SPOOLSS_BUFFER_OK(WERR_OK, WERR_INSUFFICIENT_BUFFER);
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  spoolss_AddPort 
*/
static WERROR spoolss_AddPort(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPort *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  spoolss_ConfigurePort 
*/
static WERROR spoolss_ConfigurePort(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ConfigurePort *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePort 
*/
static WERROR spoolss_DeletePort(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePort *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_CreatePrinterIC 
*/
static WERROR spoolss_CreatePrinterIC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_CreatePrinterIC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_PlayGDIScriptOnPrinterIC 
*/
static WERROR spoolss_PlayGDIScriptOnPrinterIC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_PlayGDIScriptOnPrinterIC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterIC 
*/
static WERROR spoolss_DeletePrinterIC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterIC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPrinterConnection 
*/
static WERROR spoolss_AddPrinterConnection(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrinterConnection *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterConnection 
*/
static WERROR spoolss_DeletePrinterConnection(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterConnection *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_PrinterMessageBox 
*/
static WERROR spoolss_PrinterMessageBox(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_PrinterMessageBox *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddMonitor 
*/
static WERROR spoolss_AddMonitor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddMonitor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeleteMonitor 
*/
static WERROR spoolss_DeleteMonitor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeleteMonitor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrintProcessor 
*/
static WERROR spoolss_DeletePrintProcessor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrintProcessor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPrintProvidor 
*/
static WERROR spoolss_AddPrintProvidor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrintProvidor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrintProvidor 
*/
static WERROR spoolss_DeletePrintProvidor(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrintProvidor *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrintProcDataTypes 
*/
static WERROR spoolss_EnumPrintProcDataTypes(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrintProcDataTypes *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ResetPrinter 
*/
static WERROR spoolss_ResetPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ResetPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetPrinterDriver2 
*/
static WERROR spoolss_GetPrinterDriver2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinterDriver2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_FindFirstPrinterChangeNotification 
*/
static WERROR spoolss_FindFirstPrinterChangeNotification(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_FindFirstPrinterChangeNotification *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_FindNextPrinterChangeNotification 
*/
static WERROR spoolss_FindNextPrinterChangeNotification(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_FindNextPrinterChangeNotification *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_FindClosePrinterNotify 
*/
static WERROR spoolss_FindClosePrinterNotify(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_FindClosePrinterNotify *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_RouterFindFirstPrinterChangeNotificationOld 
*/
static WERROR spoolss_RouterFindFirstPrinterChangeNotificationOld(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RouterFindFirstPrinterChangeNotificationOld *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ReplyOpenPrinter 
*/
static WERROR spoolss_ReplyOpenPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ReplyOpenPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_RouterReplyPrinter 
*/
static WERROR spoolss_RouterReplyPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RouterReplyPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ReplyClosePrinter 
*/
static WERROR spoolss_ReplyClosePrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ReplyClosePrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPortEx 
*/
static WERROR spoolss_AddPortEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPortEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_RouterFindFirstPrinterChangeNotification 
*/
static WERROR spoolss_RouterFindFirstPrinterChangeNotification(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RouterFindFirstPrinterChangeNotification *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_SpoolerInit 
*/
static WERROR spoolss_SpoolerInit(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SpoolerInit *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_ResetPrinterEx 
*/
static WERROR spoolss_ResetPrinterEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_ResetPrinterEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_RemoteFindFirstPrinterChangeNotifyEx 
*/
static WERROR spoolss_RemoteFindFirstPrinterChangeNotifyEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RemoteFindFirstPrinterChangeNotifyEx *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  spoolss_RouterRefreshPrinterChangeNotification 
*/
static WERROR spoolss_RouterRefreshPrinterChangeNotification(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RouterRefreshPrinterChangeNotification *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_RemoteFindNextPrinterChangeNotifyEx 
*/
static WERROR spoolss_RemoteFindNextPrinterChangeNotifyEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_RemoteFindNextPrinterChangeNotifyEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_44 
*/
static WERROR spoolss_44(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_44 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


static WERROR spoolss_OpenPrinterEx_server(struct dcesrv_call_state *dce_call, 
					   TALLOC_CTX *mem_ctx,
					   struct spoolss_OpenPrinterEx *r,
					   const char *server_name)
{
	struct spoolss_handle_server *state;
	struct dcesrv_handle *handle;
	BOOL ret;

	/* Check printername is our name or our ip address
	 */
	ret = strequal(server_name, lp_netbios_name());
	if (!ret) {
		const char *ip = socket_get_my_addr(dce_call->conn->srv_conn->socket, mem_ctx);
		W_ERROR_HAVE_NO_MEMORY(ip);

		ret = strequal(server_name, ip);
		if (!ret) {
			return WERR_INVALID_PRINTER_NAME;
		}
	}

	/* TODO: do access check here */

	handle = dcesrv_handle_new(dce_call->context, SPOOLSS_HANDLE_SERVER);
	W_ERROR_HAVE_NO_MEMORY(handle);

	state = talloc(handle, struct spoolss_handle_server);
	W_ERROR_HAVE_NO_MEMORY(state);

	handle->data = state;

	state->access_mask = r->in.access_mask;

	*r->out.handle	= handle->wire_handle;

	return WERR_OK;	
}

static WERROR spoolss_OpenPrinterEx_port(struct dcesrv_call_state *dce_call, 
					 TALLOC_CTX *mem_ctx,
					 struct spoolss_OpenPrinterEx *r,
					 const char *server_name,
					 const char *port_name)
{
	DEBUG(1, ("looking for port [%s] (server[%s])\n", port_name, server_name));

	return WERR_INVALID_PRINTER_NAME;
}

static WERROR spoolss_OpenPrinterEx_monitor(struct dcesrv_call_state *dce_call, 
					    TALLOC_CTX *mem_ctx,
					    struct spoolss_OpenPrinterEx *r,
					    const char *server_name,
					    const char *monitor_name)
{
	if (strequal("Standard TCP/IP Port", monitor_name)) {
		struct dcesrv_handle *handle;

		handle = dcesrv_handle_new(dce_call->context, SPOOLSS_HANDLE_MONITOR);
		W_ERROR_HAVE_NO_MEMORY(handle);

		handle->data = NULL;

		*r->out.handle	= handle->wire_handle;

		return WERR_OK;	
	}

	DEBUG(1, ("looking for monitor [%s] (server[%s])\n", monitor_name, server_name));

	return WERR_INVALID_PRINTER_NAME;
}

static WERROR spoolss_OpenPrinterEx_printer(struct dcesrv_call_state *dce_call, 
					    TALLOC_CTX *mem_ctx,
					    struct spoolss_OpenPrinterEx *r,
					    const char *server_name,
					    const char *printer_name)
{
	DEBUG(3, ("looking for printer [%s] (server[%s])\n", printer_name, server_name));

	return WERR_INVALID_PRINTER_NAME;
}

/* 
  spoolss_OpenPrinterEx 
*/
static WERROR spoolss_OpenPrinterEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_OpenPrinterEx *r)
{
	char *p;
	char *server = NULL;
	const char *object = r->in.printername;
	ZERO_STRUCTP(r->out.handle);

	/* no printername is there it's like open server */
	if (!r->in.printername) {
		return spoolss_OpenPrinterEx_server(dce_call, mem_ctx, r, NULL);
	}

	/* just "\\" is invalid */
	if (strequal(r->in.printername, "\\\\")) {
		return WERR_INVALID_PRINTER_NAME;
	}

	if (strncmp(r->in.printername, "\\\\", 2) == 0) {
		server = talloc_strdup(mem_ctx, r->in.printername + 2);
		W_ERROR_HAVE_NO_MEMORY(server);

		/* here we know we have "\\" in front not followed
		 * by '\0', now see if we have another "\" in the string
		 */
		p = strchr_m(server, '\\');
		if (!p) {
			/* there's no other "\", so it's ("\\%s",server)
			 */
			return spoolss_OpenPrinterEx_server(dce_call, mem_ctx, r, server);
		}
		/* here we know that we have ("\\%s\",server),
		 * if we have '\0' as next then it's an invalid name
		 * otherwise the printer_name
		 */
		p[0] = '\0';
		/* everything that follows is the printer name */
		p++;
		object = p;

		/* just "" as server is invalid */
		if (strequal(server, "")) {
			DEBUG(2,("OpenPrinterEx invalid print server: [%s][%s][%s]\n", r->in.printername, server, object));
			return WERR_INVALID_PRINTER_NAME;
		}
	}

	/* just "" is invalid */
	if (strequal(object, "")) {
		DEBUG(2,("OpenPrinterEx invalid object: [%s][%s][%s]\n", r->in.printername, server, object));
		return WERR_INVALID_PRINTER_NAME;
	}

	DEBUG(3,("OpenPrinterEx object: [%s][%s][%s]\n", r->in.printername, server, object));

#define XCV_PORT ",XcvPort "
#define XCV_MONITOR ",XcvMonitor "
	if (strncmp(object, XCV_PORT, strlen(XCV_PORT)) == 0) {
		object += strlen(XCV_PORT);

		/* just "" is invalid */
		if (strequal(object, "")) {
			DEBUG(2,("OpenPrinterEx invalid port: [%s][%s][%s]\n", r->in.printername, server, object));
			return WERR_INVALID_PRINTER_NAME;
		}

		return spoolss_OpenPrinterEx_port(dce_call, mem_ctx, r, server, object);
	} else if (strncmp(object, XCV_MONITOR, strlen(XCV_MONITOR)) == 0) {
		object += strlen(XCV_MONITOR);

		/* just "" is invalid */
		if (strequal(object, "")) {
			DEBUG(2,("OpenPrinterEx invalid monitor: [%s][%s][%s]\n", r->in.printername, server, object));
			return WERR_INVALID_PRINTER_NAME;
		}

		return spoolss_OpenPrinterEx_monitor(dce_call, mem_ctx, r, server, object);
	}

	return spoolss_OpenPrinterEx_printer(dce_call, mem_ctx, r, server, object);
}

/* 
  spoolss_AddPrinterEx 
*/
static WERROR spoolss_AddPrinterEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrinterEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_47 
*/
static WERROR spoolss_47(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_47 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrinterData 
*/
static WERROR spoolss_EnumPrinterData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinterData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterData 
*/
static WERROR spoolss_DeletePrinterData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_4a 
*/
static WERROR spoolss_4a(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_4a *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_4b 
*/
static WERROR spoolss_4b(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_4b *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_4c 
*/
static WERROR spoolss_4c(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_4c *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_SetPrinterDataEx 
*/
static WERROR spoolss_SetPrinterDataEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_SetPrinterDataEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_GetPrinterDataEx 
*/
static WERROR spoolss_GetPrinterDataEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_GetPrinterDataEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrinterDataEx 
*/
static WERROR spoolss_EnumPrinterDataEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinterDataEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPrinterKey 
*/
static WERROR spoolss_EnumPrinterKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinterKey *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterDataEx 
*/
static WERROR spoolss_DeletePrinterDataEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterDataEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterKey 
*/
static WERROR spoolss_DeletePrinterKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterKey *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_53 
*/
static WERROR spoolss_53(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_53 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_DeletePrinterDriverEx 
*/
static WERROR spoolss_DeletePrinterDriverEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_DeletePrinterDriverEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_55 
*/
static WERROR spoolss_55(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_55 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_56 
*/
static WERROR spoolss_56(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_56 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_57 
*/
static WERROR spoolss_57(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_57 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_58 
*/
static WERROR spoolss_58(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_58 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPrinterDriverEx 
*/
static WERROR spoolss_AddPrinterDriverEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPrinterDriverEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5a 
*/
static WERROR spoolss_5a(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5a *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5b 
*/
static WERROR spoolss_5b(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5b *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5c 
*/
static WERROR spoolss_5c(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5c *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5d 
*/
static WERROR spoolss_5d(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5d *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5e 
*/
static WERROR spoolss_5e(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5e *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_5f 
*/
static WERROR spoolss_5f(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_5f *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_spoolss_s.c"

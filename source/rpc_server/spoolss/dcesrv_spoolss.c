/* 
   Unix SMB/CIFS implementation.

   endpoint server for the spoolss pipe

   Copyright (C) Tim Potter 2004
   
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
#include "rpc_server/common/common.h"

/* 
  spoolss_EnumPrinters 
*/
static WERROR spoolss_EnumPrinters(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPrinters *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_OpenPrinter 
*/
static WERROR spoolss_OpenPrinter(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_OpenPrinter *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumPorts 
*/
static WERROR spoolss_EnumPorts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumPorts *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_EnumMonitors 
*/
static WERROR spoolss_EnumMonitors(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_EnumMonitors *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  spoolss_AddPort 
*/
static WERROR spoolss_AddPort(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_AddPort *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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


/* 
  spoolss_OpenPrinterEx 
*/
static WERROR spoolss_OpenPrinterEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct spoolss_OpenPrinterEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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

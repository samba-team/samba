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
#include "rpc_server/spoolss/dcesrv_spoolss.h"

static WERROR spoolss_EnumPrinters(struct dcesrv_call_state *dce_call, 
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_EnumPrinters *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_OpenPrinter(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx, 
				  struct spoolss_OpenPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SetJob(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx, 
			     struct spoolss_SetJob *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetJob(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx, 
			     struct spoolss_GetJob *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumJobs(struct dcesrv_call_state *dce_call,
			       TALLOC_CTX *mem_ctx, 
			       struct spoolss_EnumJobs *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrinter(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_AddPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinter(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, 
				    struct spoolss_DeletePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SetPrinter(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_SetPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinter(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_GetPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrinterDriver(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_AddPrinterDriver *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrinterDrivers(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx, 
					 struct spoolss_EnumPrinterDrivers *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinterDriver(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_GetPrinterDriver *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinterDriverDirectory(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_GetPrinterDriverDirectory *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterDriver(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrinterDriver *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrintProcessor(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_AddPrintProcessor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrintProcessors(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_EnumPrintProcessors *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrintProcessorDirectory(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_GetPrintProcessorDirectory *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_StartDocPrinter(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx, 
				      struct spoolss_StartDocPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_StartPagePrinter(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_StartPagePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_WritePrinter(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_WritePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EndPagePrinter(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx, 
				     struct spoolss_EndPagePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AbortPrinter(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_AbortPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ReadPrinter(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx, 
				  struct spoolss_ReadPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EndDocPrinter(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, 
				    struct spoolss_EndDocPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddJob(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx, 
			     struct spoolss_AddJob *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ScheduleJob(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx, 
				  struct spoolss_ScheduleJob *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinterData(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx, 
				     struct spoolss_GetPrinterData *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SetPrinterData(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx, 
				     struct spoolss_SetPrinterData *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_WaitForPrinterChange(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_WaitForPrinterChange *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ClosePrinter(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_ClosePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddForm(struct dcesrv_call_state *dce_call,
			      TALLOC_CTX *mem_ctx, 
			      struct spoolss_AddForm *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeleteForm(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_DeleteForm *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetForm(struct dcesrv_call_state *dce_call,
			      TALLOC_CTX *mem_ctx, 
			      struct spoolss_GetForm *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SetForm(struct dcesrv_call_state *dce_call,
			      TALLOC_CTX *mem_ctx, 
			      struct spoolss_SetForm *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumForms(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx, 
				struct spoolss_EnumForms *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPorts(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx, 
				struct spoolss_EnumPorts *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumMonitors(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_EnumMonitors *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPort(struct dcesrv_call_state *dce_call,
			      TALLOC_CTX *mem_ctx, 
			      struct spoolss_AddPort *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ConfigurePort(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, 
				    struct spoolss_ConfigurePort *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePort(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_DeletePort *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_CreatePrinterIC(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx, 
				      struct spoolss_CreatePrinterIC *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_PlayGDIScriptOnPrinterIC(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_PlayGDIScriptOnPrinterIC *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterIC(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx, 
				      struct spoolss_DeletePrinterIC *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrinterConnection(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_AddPrinterConnection *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterConnection(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrinterConnection *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_PrinterMessageBox(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_PrinterMessageBox *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddMonitor(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx, 
				 struct spoolss_AddMonitor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeleteMonitor(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, 
				    struct spoolss_DeleteMonitor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrintProcessor(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrintProcessor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrintProvidor(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_AddPrintProvidor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrintProvidor(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrintProvidor *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrintProcDataTypes(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_EnumPrintProcDataTypes *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ResetPrinter(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_ResetPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinterDriver2(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_GetPrinterDriver2 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_FindFirstPrinterChangeNotification(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_FindFirstPrinterChangeNotification *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_FindNextPrinterChangeNotification(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_FindNextPrinterChangeNotification *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_FindClosePrinterNotify(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_FindClosePrinterNotify *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RouterFindFirstPrinterChangeNotificationOld(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_RouterFindFirstPrinterChangeNotificationOld *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ReplyOpenPrinter(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_ReplyOpenPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RouterReplyPrinter(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx, 
					 struct spoolss_RouterReplyPrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ReplyClosePrinter(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_ReplyClosePrinter *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPortEx(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx, 
				struct spoolss_AddPortEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RouterFindFirstPrinterChangeNotification(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_RouterFindFirstPrinterChangeNotification *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SpoolerInit(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx, 
				  struct spoolss_SpoolerInit *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_ResetPrinterEx(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx, 
				     struct spoolss_ResetPrinterEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RemoteFindFirstPrinterChangeNotifyEx(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_RemoteFindFirstPrinterChangeNotifyEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RouterRefreshPrinterChangeNotification(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_RouterRefreshPrinterChangeNotification *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_RemoteFindNextPrinterChangeNotifyEx(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_RemoteFindNextPrinterChangeNotifyEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_44(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_44 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_OpenPrinterEx(struct dcesrv_call_state *dce_call,
				    TALLOC_CTX *mem_ctx, 
				    struct spoolss_OpenPrinterEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrinterEx(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx, 
				   struct spoolss_AddPrinterEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_47(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_47 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrinterData(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx, 
				      struct spoolss_EnumPrinterData *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterData(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_DeletePrinterData *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_4a(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_4a *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_4b(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_4b *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_4c(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_4c *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_SetPrinterDataEx(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_SetPrinterDataEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_GetPrinterDataEx(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_GetPrinterDataEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrinterDataEx(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx, 
					struct spoolss_EnumPrinterDataEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_EnumPrinterKey(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx, 
				     struct spoolss_EnumPrinterKey *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterDataEx(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrinterDataEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterKey(struct dcesrv_call_state *dce_call,
				       TALLOC_CTX *mem_ctx, 
				       struct spoolss_DeletePrinterKey *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_53(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_53 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_DeletePrinterDriverEx(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx, 
	struct spoolss_DeletePrinterDriverEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_55(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_55 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_56(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_56 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_57(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_57 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_58(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_58 *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_AddPrinterDriverEx(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx, 
					 struct spoolss_AddPrinterDriverEx *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5a(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5a *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5b(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5b *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5c(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5c *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5d(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5d *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5e(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5e *r)
{
	return WERR_BADFUNC;
}

static WERROR spoolss_5f(struct dcesrv_call_state *dce_call,
			 TALLOC_CTX *mem_ctx, 
			 struct spoolss_5f *r)
{
	return WERR_BADFUNC;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_spoolss_s.c"

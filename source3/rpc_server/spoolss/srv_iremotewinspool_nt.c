/*
   Unix SMB/CIFS implementation.

   endpoint server for the iremotewinspool pipe

   Copyright (C) YOUR NAME HERE YEAR

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
#include "ntdomain.h"
#include "librpc/gen_ndr/ndr_winspool.h"
#include "librpc/gen_ndr/ndr_winspool_scompat.h"

/****************************************************************
 _winspool_AsyncOpenPrinter
****************************************************************/

WERROR _winspool_AsyncOpenPrinter(struct pipes_struct *p,
				  struct winspool_AsyncOpenPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddPrinter
****************************************************************/

WERROR _winspool_AsyncAddPrinter(struct pipes_struct *p,
				 struct winspool_AsyncAddPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetJob
****************************************************************/

WERROR _winspool_AsyncSetJob(struct pipes_struct *p,
			     struct winspool_AsyncSetJob *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetJob
****************************************************************/

WERROR _winspool_AsyncGetJob(struct pipes_struct *p,
			     struct winspool_AsyncGetJob *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumJobs
****************************************************************/

WERROR _winspool_AsyncEnumJobs(struct pipes_struct *p,
			       struct winspool_AsyncEnumJobs *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddJob
****************************************************************/

WERROR _winspool_AsyncAddJob(struct pipes_struct *p,
			     struct winspool_AsyncAddJob *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncScheduleJob
****************************************************************/

WERROR _winspool_AsyncScheduleJob(struct pipes_struct *p,
				  struct winspool_AsyncScheduleJob *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinter
****************************************************************/

WERROR _winspool_AsyncDeletePrinter(struct pipes_struct *p,
				    struct winspool_AsyncDeletePrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetPrinter
****************************************************************/

WERROR _winspool_AsyncSetPrinter(struct pipes_struct *p,
				 struct winspool_AsyncSetPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinter
****************************************************************/

WERROR _winspool_AsyncGetPrinter(struct pipes_struct *p,
				 struct winspool_AsyncGetPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncStartDocPrinter
****************************************************************/

WERROR _winspool_AsyncStartDocPrinter(struct pipes_struct *p,
				      struct winspool_AsyncStartDocPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncStartPagePrinter
****************************************************************/

WERROR _winspool_AsyncStartPagePrinter(struct pipes_struct *p,
				       struct winspool_AsyncStartPagePrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncWritePrinter
****************************************************************/

WERROR _winspool_AsyncWritePrinter(struct pipes_struct *p,
				   struct winspool_AsyncWritePrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEndPagePrinter
****************************************************************/

WERROR _winspool_AsyncEndPagePrinter(struct pipes_struct *p,
				     struct winspool_AsyncEndPagePrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEndDocPrinter
****************************************************************/

WERROR _winspool_AsyncEndDocPrinter(struct pipes_struct *p,
				    struct winspool_AsyncEndDocPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAbortPrinter
****************************************************************/

WERROR _winspool_AsyncAbortPrinter(struct pipes_struct *p,
				   struct winspool_AsyncAbortPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinterData
****************************************************************/

WERROR _winspool_AsyncGetPrinterData(struct pipes_struct *p,
				     struct winspool_AsyncGetPrinterData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinterDataEx
****************************************************************/

WERROR _winspool_AsyncGetPrinterDataEx(struct pipes_struct *p,
				       struct winspool_AsyncGetPrinterDataEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetPrinterData
****************************************************************/

WERROR _winspool_AsyncSetPrinterData(struct pipes_struct *p,
				     struct winspool_AsyncSetPrinterData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetPrinterDataEx
****************************************************************/

WERROR _winspool_AsyncSetPrinterDataEx(struct pipes_struct *p,
				       struct winspool_AsyncSetPrinterDataEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncClosePrinter
****************************************************************/

WERROR _winspool_AsyncClosePrinter(struct pipes_struct *p,
				   struct winspool_AsyncClosePrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddForm
****************************************************************/

WERROR _winspool_AsyncAddForm(struct pipes_struct *p,
			      struct winspool_AsyncAddForm *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeleteForm
****************************************************************/

WERROR _winspool_AsyncDeleteForm(struct pipes_struct *p,
				 struct winspool_AsyncDeleteForm *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetForm
****************************************************************/

WERROR _winspool_AsyncGetForm(struct pipes_struct *p,
			      struct winspool_AsyncGetForm *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetForm
****************************************************************/

WERROR _winspool_AsyncSetForm(struct pipes_struct *p,
			      struct winspool_AsyncSetForm *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumForms
****************************************************************/

WERROR _winspool_AsyncEnumForms(struct pipes_struct *p,
				struct winspool_AsyncEnumForms *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinterDriver
****************************************************************/

WERROR _winspool_AsyncGetPrinterDriver(struct pipes_struct *p,
				       struct winspool_AsyncGetPrinterDriver *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrinterData
****************************************************************/

WERROR _winspool_AsyncEnumPrinterData(struct pipes_struct *p,
				      struct winspool_AsyncEnumPrinterData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrinterDataEx
****************************************************************/

WERROR _winspool_AsyncEnumPrinterDataEx(struct pipes_struct *p,
					struct winspool_AsyncEnumPrinterDataEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrinterKey
****************************************************************/

WERROR _winspool_AsyncEnumPrinterKey(struct pipes_struct *p,
				     struct winspool_AsyncEnumPrinterKey *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterData
****************************************************************/

WERROR _winspool_AsyncDeletePrinterData(struct pipes_struct *p,
					struct winspool_AsyncDeletePrinterData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterDataEx
****************************************************************/

WERROR _winspool_AsyncDeletePrinterDataEx(struct pipes_struct *p,
					  struct winspool_AsyncDeletePrinterDataEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterKey
****************************************************************/

WERROR _winspool_AsyncDeletePrinterKey(struct pipes_struct *p,
				       struct winspool_AsyncDeletePrinterKey *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncXcvData
****************************************************************/

WERROR _winspool_AsyncXcvData(struct pipes_struct *p,
			      struct winspool_AsyncXcvData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSendRecvBidiData
****************************************************************/

WERROR _winspool_AsyncSendRecvBidiData(struct pipes_struct *p,
				       struct winspool_AsyncSendRecvBidiData *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncCreatePrinterIC
****************************************************************/

WERROR _winspool_AsyncCreatePrinterIC(struct pipes_struct *p,
				      struct winspool_AsyncCreatePrinterIC *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncPlayGdiScriptOnPrinterIC
****************************************************************/

WERROR _winspool_AsyncPlayGdiScriptOnPrinterIC(struct pipes_struct *p,
					       struct winspool_AsyncPlayGdiScriptOnPrinterIC *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterIC
****************************************************************/

WERROR _winspool_AsyncDeletePrinterIC(struct pipes_struct *p,
				      struct winspool_AsyncDeletePrinterIC *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrinters
****************************************************************/

WERROR _winspool_AsyncEnumPrinters(struct pipes_struct *p,
				   struct winspool_AsyncEnumPrinters *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddPrinterDriver
****************************************************************/

WERROR _winspool_AsyncAddPrinterDriver(struct pipes_struct *p,
				       struct winspool_AsyncAddPrinterDriver *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrinterDrivers
****************************************************************/

WERROR _winspool_AsyncEnumPrinterDrivers(struct pipes_struct *p,
					 struct winspool_AsyncEnumPrinterDrivers *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinterDriverDirectory
****************************************************************/

WERROR _winspool_AsyncGetPrinterDriverDirectory(struct pipes_struct *p,
						struct winspool_AsyncGetPrinterDriverDirectory *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterDriver
****************************************************************/

WERROR _winspool_AsyncDeletePrinterDriver(struct pipes_struct *p,
					  struct winspool_AsyncDeletePrinterDriver *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterDriverEx
****************************************************************/

WERROR _winspool_AsyncDeletePrinterDriverEx(struct pipes_struct *p,
					    struct winspool_AsyncDeletePrinterDriverEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddPrintProcessor
****************************************************************/

WERROR _winspool_AsyncAddPrintProcessor(struct pipes_struct *p,
					struct winspool_AsyncAddPrintProcessor *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrintProcessors
****************************************************************/

WERROR _winspool_AsyncEnumPrintProcessors(struct pipes_struct *p,
					  struct winspool_AsyncEnumPrintProcessors *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrintProcessorDirectory
****************************************************************/

WERROR _winspool_AsyncGetPrintProcessorDirectory(struct pipes_struct *p,
						 struct winspool_AsyncGetPrintProcessorDirectory *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPorts
****************************************************************/

WERROR _winspool_AsyncEnumPorts(struct pipes_struct *p,
				struct winspool_AsyncEnumPorts *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumMonitors
****************************************************************/

WERROR _winspool_AsyncEnumMonitors(struct pipes_struct *p,
				   struct winspool_AsyncEnumMonitors *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddPort
****************************************************************/

WERROR _winspool_AsyncAddPort(struct pipes_struct *p,
			      struct winspool_AsyncAddPort *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetPort
****************************************************************/

WERROR _winspool_AsyncSetPort(struct pipes_struct *p,
			      struct winspool_AsyncSetPort *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddMonitor
****************************************************************/

WERROR _winspool_AsyncAddMonitor(struct pipes_struct *p,
				 struct winspool_AsyncAddMonitor *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeleteMonitor
****************************************************************/

WERROR _winspool_AsyncDeleteMonitor(struct pipes_struct *p,
				    struct winspool_AsyncDeleteMonitor *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrintProcessor
****************************************************************/

WERROR _winspool_AsyncDeletePrintProcessor(struct pipes_struct *p,
					   struct winspool_AsyncDeletePrintProcessor *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPrintProcessorDatatypes
****************************************************************/

WERROR _winspool_AsyncEnumPrintProcessorDatatypes(struct pipes_struct *p,
						  struct winspool_AsyncEnumPrintProcessorDatatypes *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncAddPerMachineConnection
****************************************************************/

WERROR _winspool_AsyncAddPerMachineConnection(struct pipes_struct *p,
					      struct winspool_AsyncAddPerMachineConnection *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePerMachineConnection
****************************************************************/

WERROR _winspool_AsyncDeletePerMachineConnection(struct pipes_struct *p,
						 struct winspool_AsyncDeletePerMachineConnection *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumPerMachineConnections
****************************************************************/

WERROR _winspool_AsyncEnumPerMachineConnections(struct pipes_struct *p,
						struct winspool_AsyncEnumPerMachineConnections *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_SyncRegisterForRemoteNotifications
****************************************************************/

HRESULT _winspool_SyncRegisterForRemoteNotifications(struct pipes_struct *p,
						     struct winspool_SyncRegisterForRemoteNotifications *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_SyncUnRegisterForRemoteNotifications
****************************************************************/

HRESULT _winspool_SyncUnRegisterForRemoteNotifications(struct pipes_struct *p,
						       struct winspool_SyncUnRegisterForRemoteNotifications *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_SyncRefreshRemoteNotifications
****************************************************************/

HRESULT _winspool_SyncRefreshRemoteNotifications(struct pipes_struct *p,
						 struct winspool_SyncRefreshRemoteNotifications *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetRemoteNotifications
****************************************************************/

HRESULT _winspool_AsyncGetRemoteNotifications(struct pipes_struct *p,
					      struct winspool_AsyncGetRemoteNotifications *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncInstallPrinterDriverFromPackage
****************************************************************/

HRESULT _winspool_AsyncInstallPrinterDriverFromPackage(struct pipes_struct *p,
						       struct winspool_AsyncInstallPrinterDriverFromPackage *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncUploadPrinterDriverPackage
****************************************************************/

HRESULT _winspool_AsyncUploadPrinterDriverPackage(struct pipes_struct *p,
						  struct winspool_AsyncUploadPrinterDriverPackage *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetCorePrinterDrivers
****************************************************************/

HRESULT _winspool_AsyncGetCorePrinterDrivers(struct pipes_struct *p,
					     struct winspool_AsyncGetCorePrinterDrivers *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncCorePrinterDriverInstalled
****************************************************************/

HRESULT _winspool_AsyncCorePrinterDriverInstalled(struct pipes_struct *p,
						  struct winspool_AsyncCorePrinterDriverInstalled *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetPrinterDriverPackagePath
****************************************************************/

HRESULT _winspool_AsyncGetPrinterDriverPackagePath(struct pipes_struct *p,
						   struct winspool_AsyncGetPrinterDriverPackagePath *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeletePrinterDriverPackage
****************************************************************/

HRESULT _winspool_AsyncDeletePrinterDriverPackage(struct pipes_struct *p,
						  struct winspool_AsyncDeletePrinterDriverPackage *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return HRES_ERROR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncReadPrinter
****************************************************************/

WERROR _winspool_AsyncReadPrinter(struct pipes_struct *p,
				  struct winspool_AsyncReadPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncResetPrinter
****************************************************************/

WERROR _winspool_AsyncResetPrinter(struct pipes_struct *p,
				   struct winspool_AsyncResetPrinter *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncGetJobNamedPropertyValue
****************************************************************/

WERROR _winspool_AsyncGetJobNamedPropertyValue(struct pipes_struct *p,
					       struct winspool_AsyncGetJobNamedPropertyValue *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncSetJobNamedProperty
****************************************************************/

WERROR _winspool_AsyncSetJobNamedProperty(struct pipes_struct *p,
					  struct winspool_AsyncSetJobNamedProperty *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncDeleteJobNamedProperty
****************************************************************/

WERROR _winspool_AsyncDeleteJobNamedProperty(struct pipes_struct *p,
					     struct winspool_AsyncDeleteJobNamedProperty *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncEnumJobNamedProperties
****************************************************************/

WERROR _winspool_AsyncEnumJobNamedProperties(struct pipes_struct *p,
					     struct winspool_AsyncEnumJobNamedProperties *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}


/****************************************************************
 _winspool_AsyncLogJobInfoForBranchOffice
****************************************************************/

WERROR _winspool_AsyncLogJobInfoForBranchOffice(struct pipes_struct *p,
						struct winspool_AsyncLogJobInfoForBranchOffice *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/*
   Unix SMB/CIFS implementation.

   Copyright (C) Guenther Deschner 2016

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
#include "librpc/gen_ndr/ndr_winspool.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "rpc_server/spoolss/iremotewinspool_util.h"

#define _PAR_MAPPING(NAME)	{ .iremotewinspool_opcode = NDR_WINSPOOL_ASYNC ##NAME, .spoolss_opcode = NDR_SPOOLSS_ ##NAME }
#define _PAR_MAPPING_EX(NAME)	{ .iremotewinspool_opcode = NDR_WINSPOOL_ASYNC ##NAME, .spoolss_opcode = NDR_SPOOLSS_ ##NAME## EX }
#define _PAR_MAPPING_2(NAME)	{ .iremotewinspool_opcode = NDR_WINSPOOL_ASYNC ##NAME, .spoolss_opcode = NDR_SPOOLSS_ ##NAME## 2 }

struct {
	int iremotewinspool_opcode;
	int spoolss_opcode;
} proxy_table[] = {

	/* 3.1.4.1. Printer Management Methods */

	_PAR_MAPPING_EX(OPENPRINTER),
	_PAR_MAPPING_EX(ADDPRINTER),
	_PAR_MAPPING(DELETEPRINTER),
	_PAR_MAPPING(SETPRINTER),
	_PAR_MAPPING(GETPRINTER),
	_PAR_MAPPING(GETPRINTERDATA),
	_PAR_MAPPING(GETPRINTERDATAEX),
	_PAR_MAPPING(SETPRINTERDATA),
	_PAR_MAPPING(SETPRINTERDATAEX),
	_PAR_MAPPING(CLOSEPRINTER),
	_PAR_MAPPING(ENUMPRINTERDATA),
	_PAR_MAPPING(ENUMPRINTERDATAEX),
	_PAR_MAPPING(ENUMPRINTERKEY),
	_PAR_MAPPING(DELETEPRINTERDATA),
	_PAR_MAPPING(DELETEPRINTERDATAEX),
	_PAR_MAPPING(DELETEPRINTERKEY),
	_PAR_MAPPING(SENDRECVBIDIDATA),
	_PAR_MAPPING(CREATEPRINTERIC),
	_PAR_MAPPING(PLAYGDISCRIPTONPRINTERIC),
	_PAR_MAPPING(DELETEPRINTERIC),
	_PAR_MAPPING(ENUMPRINTERS),
	_PAR_MAPPING(ADDPERMACHINECONNECTION),
	_PAR_MAPPING(DELETEPERMACHINECONNECTION),
	_PAR_MAPPING(ENUMPERMACHINECONNECTIONS),
	_PAR_MAPPING(RESETPRINTER),

	/* 3.1.4.2. Printer Driver Management Methods */

	_PAR_MAPPING_2(GETPRINTERDRIVER),
	_PAR_MAPPING_EX(ADDPRINTERDRIVER),
	_PAR_MAPPING(ENUMPRINTERDRIVERS),
	_PAR_MAPPING(GETPRINTERDRIVERDIRECTORY),
	_PAR_MAPPING(DELETEPRINTERDRIVER),
	_PAR_MAPPING(DELETEPRINTERDRIVEREX),
	/* No mapping for: RpcAsyncInstallPrinterDriverFromPackage */
	/* No mapping for: RpcAsyncUploadPrinterDriverPackage */
	_PAR_MAPPING(GETCOREPRINTERDRIVERS),
	/* No mapping for: RpcAsyncCorePrinterDriverInstalled */
	_PAR_MAPPING(GETPRINTERDRIVERPACKAGEPATH),
	/* No mapping for: RpcAsyncDeletePrinterDriverPackage */

	/* 3.1.4.3. Printer Port Management Methods */

	_PAR_MAPPING(XCVDATA),
	_PAR_MAPPING(ENUMPORTS),
	_PAR_MAPPING_EX(ADDPORT),
	_PAR_MAPPING(SETPORT),

	/* 3.1.4.4. Printer Processor Management Methods */

	_PAR_MAPPING(ADDPRINTPROCESSOR),
	_PAR_MAPPING(ENUMPRINTPROCESSORS),
	_PAR_MAPPING(GETPRINTPROCESSORDIRECTORY),
	_PAR_MAPPING(DELETEPRINTPROCESSOR),
	_PAR_MAPPING(ENUMPRINTPROCESSORDATATYPES),

	/* 3.1.4.5. Port Monitor Management Methods */

	_PAR_MAPPING(ENUMMONITORS),
	_PAR_MAPPING(ADDMONITOR),
	_PAR_MAPPING(DELETEMONITOR),

	/* 3.1.4.6. Form Management Methods */

	_PAR_MAPPING(ADDFORM),
	_PAR_MAPPING(DELETEFORM),
	_PAR_MAPPING(GETFORM),
	_PAR_MAPPING(SETFORM),
	_PAR_MAPPING(ENUMFORMS),

	/* 3.1.4.7. Job Management Methods */

	_PAR_MAPPING(SETJOB),
	_PAR_MAPPING(GETJOB),
	_PAR_MAPPING(ENUMJOBS),
	_PAR_MAPPING(ADDJOB),
	_PAR_MAPPING(SCHEDULEJOB),

	/* 3.1.4.8. Job Printing Methods */

	_PAR_MAPPING(STARTDOCPRINTER),
	_PAR_MAPPING(STARTPAGEPRINTER),
	_PAR_MAPPING(WRITEPRINTER),
	_PAR_MAPPING(ENDPAGEPRINTER),
	_PAR_MAPPING(ENDDOCPRINTER),
	_PAR_MAPPING(ABORTPRINTER),
	_PAR_MAPPING(READPRINTER),

	/* 3.1.4.9. Printing Related Notification Methods */

	/* No mapping for: RpcSyncRegisterForRemoteNotifications */
	/* No mapping for: RpcSyncUnRegisterForRemoteNotifications */
	/* No mapping for: RpcSyncRefreshRemoteNotifications */
	/* No mapping for: RpcAsyncGetRemoteNotifications */

	/* 3.1.4.10. Job Named Property Management Methods */

	_PAR_MAPPING(GETJOBNAMEDPROPERTYVALUE),
	_PAR_MAPPING(SETJOBNAMEDPROPERTY),
	_PAR_MAPPING(DELETEJOBNAMEDPROPERTY),
	_PAR_MAPPING(ENUMJOBNAMEDPROPERTIES),

	/* 3.1.4.11. Branch Office Remote Logging Methods */

	_PAR_MAPPING(LOGJOBINFOFORBRANCHOFFICE),
};

bool iremotewinspool_map_opcode(uint16_t opcode,
				uint16_t *proxy_opcode)
{
	int i;

	for (i = 0; i <ARRAY_SIZE(proxy_table); i++) {
		if (proxy_table[i].iremotewinspool_opcode == opcode) {
			*proxy_opcode = proxy_table[i].spoolss_opcode;
			return true;
		}
	}

	return false;
}

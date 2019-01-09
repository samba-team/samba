/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) 2013-2016 Guenther Deschner <gd@samba.org>

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
#include "rpcclient.h"
#include "../librpc/gen_ndr/ndr_winspool.h"
#include "libsmb/libsmb.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "rpc_client/init_spoolss.h"

/****************************************************************************
****************************************************************************/

static WERROR cmd_iremotewinspool_async_open_printer(struct rpc_pipe_client *cli,
						     TALLOC_CTX *mem_ctx,
						     int argc, const char **argv)
{
	NTSTATUS status;
	WERROR werror;
	struct policy_handle hnd;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct spoolss_UserLevelCtr client_info_ctr;
	struct spoolss_UserLevel1 level1;
	uint32_t access_mask = PRINTER_ALL_ACCESS;
	struct dcerpc_binding_handle *b = cli->binding_handle;
	struct GUID uuid;
	struct winspool_AsyncOpenPrinter r;
	struct cli_credentials *creds = gensec_get_credentials(cli->auth->auth_ctx);

	if (argc < 2) {
		printf("Usage: %s <printername> [access_mask]\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 3) {
		sscanf(argv[2], "%x", &access_mask);
	}

	status = GUID_from_string(IREMOTEWINSPOOL_OBJECT_GUID, &uuid);
	if (!NT_STATUS_IS_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ZERO_STRUCT(devmode_ctr);

        werror = spoolss_init_spoolss_UserLevel1(mem_ctx,
						 cli_credentials_get_username(creds),
						 &level1);
	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}

	level1.processor = PROCESSOR_ARCHITECTURE_AMD64;

	client_info_ctr.level = 1;
	client_info_ctr.user_info.level1 = &level1;

	r.in.pPrinterName	= argv[1];
	r.in.pDatatype		= "RAW";
	r.in.pDevModeContainer	= &devmode_ctr;
	r.in.AccessRequired	= access_mask;
	r.in.pClientInfo	= &client_info_ctr;
	r.out.pHandle		= &hnd;

	/* Open the printer handle */

	status = dcerpc_binding_handle_call(b,
					    &uuid,
					    &ndr_table_iremotewinspool,
					    NDR_WINSPOOL_ASYNCOPENPRINTER,
					    mem_ctx,
					    &r);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	if (!W_ERROR_IS_OK(r.out.result)) {
		return r.out.result;
	}

	printf("Printer %s opened successfully\n", argv[1]);

	return WERR_OK;
}

static WERROR cmd_iremotewinspool_async_core_printer_driver_installed(struct rpc_pipe_client *cli,
								      TALLOC_CTX *mem_ctx,
								      int argc, const char **argv)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *b = cli->binding_handle;
	struct GUID uuid, core_printer_driver_guid;
	struct winspool_AsyncCorePrinterDriverInstalled r;
	const char *guid_str = SPOOLSS_CORE_PRINT_PACKAGE_FILES_XPSDRV;
	const char *architecture = SPOOLSS_ARCHITECTURE_x64;
	int32_t pbDriverInstalled;

	if (argc > 4) {
		printf("Usage: %s <CORE_PRINTER_DRIVER_GUID> [architecture]\n", argv[0]);
		return WERR_OK;
	}

	if (argc >= 2) {
		guid_str = argv[1];
	}

	if (argc >= 3) {
		architecture = argv[2];
	}

	status = GUID_from_string(IREMOTEWINSPOOL_OBJECT_GUID, &uuid);
	if (!NT_STATUS_IS_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	status = GUID_from_string(guid_str, &core_printer_driver_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	r.in.pszServer		= NULL;
	r.in.pszEnvironment	= architecture;
	r.in.CoreDriverGUID	= core_printer_driver_guid;
	r.in.ftDriverDate	= 0;
	r.in.dwlDriverVersion	= 0;
	r.out.pbDriverInstalled	= &pbDriverInstalled;

	status = dcerpc_binding_handle_call(b,
					    &uuid,
					    &ndr_table_iremotewinspool,
					    NDR_WINSPOOL_ASYNCCOREPRINTERDRIVERINSTALLED,
					    mem_ctx,
					    &r);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	if (!HRES_IS_OK(r.out.result)) {
		return W_ERROR(WIN32_FROM_HRESULT(r.out.result));
	}

	printf("Core Printer Driver %s is%s installed\n", guid_str,
		*r.out.pbDriverInstalled ? "" : " NOT");

	return WERR_OK;
}

/* List of commands exported by this module */
struct cmd_set iremotewinspool_commands[] = {

	{
		.name = "IRemoteWinspool",
	},

	{
		.name               = "winspool_AsyncOpenPrinter",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_iremotewinspool_async_open_printer,
		.table              = &ndr_table_iremotewinspool,
		.rpc_pipe           = NULL,
		.description        = "Open printer handle",
		.usage              = "",
	},

	{
		.name               = "winspool_AsyncCorePrinterDriverInstalled",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_iremotewinspool_async_core_printer_driver_installed,
		.table              = &ndr_table_iremotewinspool,
		.rpc_pipe           = NULL,
		.description        = "Query Core Printer Driver Installed",
		.usage              = "",
	},

	{
		.name = NULL,
	},
};

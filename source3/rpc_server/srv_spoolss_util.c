/*
 *  Unix SMB/CIFS implementation.
 *
 *  SPOOLSS RPC Pipe server / winreg client routines
 *
 *  Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "srv_spoolss_util.h"
#include "../librpc/gen_ndr/srv_winreg.h"
#include "../librpc/gen_ndr/cli_winreg.h"

/**
 * @internal
 *
 * @brief Connect to the interal winreg server and open the given printer key.
 *
 * The function will create the needed subkeys if they don't exist.
 *
 * @param[in]  mem_ctx       The memory context to use.
 *
 * @param[in]  server_info   The supplied server info.
 *
 * @param[out] winreg_pipe   A pointer for the winreg rpc client pipe.
 *
 * @param[in]  name          The name of the printer.
 *
 * @param[in]  key           The key to open.
 *
 * @param[in]  create_key    Set to true if the key should be created if it
 *                           doesn't exist.
 *
 * @param[in]  access_mask   The access mask to open the key.
 *
 * @param[out] hive_handle   A policy handle for the opened hive.
 *
 * @param[out] key_handle    A policy handle for the opened key.
 *
 * @return                   WERR_OK on success, the corresponding DOS error
 *                           code if something gone wrong.
 */
static WERROR winreg_printer_openkey(TALLOC_CTX *mem_ctx,
			      struct auth_serversupplied_info *server_info,
			      struct rpc_pipe_client **winreg_pipe,
			      const char *name,
			      const char *key,
			      bool create_key,
			      uint32_t access_mask,
			      struct policy_handle *hive_handle,
			      struct policy_handle *key_handle)
{
	struct rpc_pipe_client *pipe_handle;
	struct winreg_String wkey, wkeyclass;
	char *keyname;
	NTSTATUS status;
	WERROR result = WERR_OK;

	/* create winreg connection */
	status = rpc_pipe_open_internal(mem_ctx,
					&ndr_table_winreg.syntax_id,
					rpc_winreg_dispatch,
					server_info,
					&pipe_handle);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_openkey: Could not connect to winreg_pipe: %s\n",
			  nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	status = rpccli_winreg_OpenHKLM(pipe_handle,
					mem_ctx,
					NULL,
					access_mask,
					hive_handle,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_openkey: Could not open HKLM hive: %s\n",
			  nt_errstr(status)));
		talloc_free(pipe_handle);
		if (!W_ERROR_IS_OK(result)) {
			return result;
		}
		return ntstatus_to_werror(status);
	}

	if (key && *key) {
		keyname = talloc_asprintf(mem_ctx,
				    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\%s\\%s",
				    name,
				    key);
	} else {
		keyname = talloc_asprintf(mem_ctx,
				    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\%s",
				    name);
	}
	if (keyname == NULL) {
		talloc_free(pipe_handle);
		return WERR_NOMEM;
	}

	ZERO_STRUCT(wkey);
	wkey.name = keyname;

	if (create_key) {
		enum winreg_CreateAction action = REG_ACTION_NONE;

		ZERO_STRUCT(wkeyclass);
		wkeyclass.name = "";

		status = rpccli_winreg_CreateKey(pipe_handle,
						 mem_ctx,
						 hive_handle,
						 wkey,
						 wkeyclass,
						 0,
						 access_mask,
						 NULL,
						 key_handle,
						 &action,
						 &result);
		switch (action) {
			case REG_ACTION_NONE:
				DEBUG(8, ("winreg_printer_openkey:createkey did nothing -- huh?\n"));
				break;
			case REG_CREATED_NEW_KEY:
				DEBUG(8, ("winreg_printer_openkey: createkey created %s\n", keyname));
				break;
			case REG_OPENED_EXISTING_KEY:
				DEBUG(8, ("winreg_printer_openkey: createkey opened existing %s\n", keyname));
				break;
		}
	} else {
		status = rpccli_winreg_OpenKey(pipe_handle,
					       mem_ctx,
					       hive_handle,
					       wkey,
					       0,
					       access_mask,
					       key_handle,
					       &result);
	}
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(pipe_handle);
		if (!W_ERROR_IS_OK(result)) {
			return result;
		}
		return ntstatus_to_werror(status);
	}

	*winreg_pipe = pipe_handle;

	return WERR_OK;
}

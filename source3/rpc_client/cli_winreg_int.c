/*
 *  Unix SMB/CIFS implementation.
 *
 *  WINREG internal client routines
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
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
#include "../librpc/gen_ndr/ndr_winreg_c.h"
#include "rpc_client/cli_winreg_int.h"
#include "rpc_server/rpc_ncacn_np.h"

NTSTATUS dcerpc_winreg_int_hklm_openkey(TALLOC_CTX *mem_ctx,
					const struct auth_serversupplied_info *server_info,
					struct messaging_context *msg_ctx,
					struct dcerpc_binding_handle **h,
					const char *key,
					bool create_key,
					uint32_t access_mask,
					struct policy_handle *hive_handle,
					struct policy_handle *key_handle,
					WERROR *pwerr)
{
	static struct client_address client_id;
	struct dcerpc_binding_handle *binding_handle;
	struct winreg_String wkey, wkeyclass;
	NTSTATUS status;
	WERROR result = WERR_OK;

	strlcpy(client_id.addr, "127.0.0.1", sizeof(client_id.addr));
	client_id.name = "127.0.0.1";

	status = rpcint_binding_handle(mem_ctx,
				       &ndr_table_winreg,
				       &client_id,
				       server_info,
				       msg_ctx,
				       &binding_handle);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_winreg_int_openkey: Could not connect to winreg pipe: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = dcerpc_winreg_OpenHKLM(binding_handle,
					mem_ctx,
					NULL,
					access_mask,
					hive_handle,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(binding_handle);
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(binding_handle);
		*pwerr = result;
		return status;
	}

	ZERO_STRUCT(wkey);
	wkey.name = key;

	if (create_key) {
		enum winreg_CreateAction action = REG_ACTION_NONE;

		ZERO_STRUCT(wkeyclass);
		wkeyclass.name = "";

		status = dcerpc_winreg_CreateKey(binding_handle,
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
				DEBUG(8, ("dcerpc_winreg_int_openkey: createkey"
					  " did nothing -- huh?\n"));
				break;
			case REG_CREATED_NEW_KEY:
				DEBUG(8, ("dcerpc_winreg_int_openkey: createkey"
					  " created %s\n", key));
				break;
			case REG_OPENED_EXISTING_KEY:
				DEBUG(8, ("dcerpc_winreg_int_openkey: createkey"
					  " opened existing %s\n", key));
				break;
		}
	} else {
		status = dcerpc_winreg_OpenKey(binding_handle,
					       mem_ctx,
					       hive_handle,
					       wkey,
					       0,
					       access_mask,
					       key_handle,
					       &result);
	}
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(binding_handle);
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		talloc_free(binding_handle);
		*pwerr = result;
		return status;
	}

	*h = binding_handle;

	return status;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */

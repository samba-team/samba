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
#include "rpc_server/rpc_ncacn_np.h"
#include "../lib/tsocket/tsocket.h"
#include "../librpc/gen_ndr/ndr_winreg.h"

WERROR winreg_printer_binding_handle(TALLOC_CTX *mem_ctx,
				     const struct auth_serversupplied_info *session_info,
				     struct messaging_context *msg_ctx,
				     struct dcerpc_binding_handle **winreg_binding_handle)
{
	struct tsocket_address *local;
	NTSTATUS status;
	int rc;

	rc = tsocket_address_inet_from_strings(mem_ctx,
					       "ip",
					       "127.0.0.1",
					       0,
					       &local);
	if (rc < 0) {
		return WERR_NOMEM;
	}

	status = rpcint_binding_handle(mem_ctx,
				       &ndr_table_winreg,
				       local,
				       session_info,
				       msg_ctx,
				       winreg_binding_handle);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("winreg_printer_binding_handle: Could not connect to winreg pipe: %s\n",
			  nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	return WERR_OK;
}

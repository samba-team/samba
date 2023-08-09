/*
 *  Unix SMB/CIFS implementation.
 *
 *  Copyright (C) 2023 Stefan Metzmacher
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
#include "rpc_worker.h"
#include "librpc/gen_ndr/ndr_witness.h"
#include "librpc/gen_ndr/ndr_witness_scompat.h"

static size_t witness_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_witness,
	};

	if (!lp_clustering()) {
		/*
		 * Without clustering there's no need for witness.
		 */
		*pifaces = NULL;
		return 0;
	}

	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static NTSTATUS witness_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };
	char *principal = NULL;
	NTSTATUS status;

	if (!lp_clustering()) {
		/*
		 * Without clustering there's no need for witness.
		 */
		*_ep_servers = NULL;
		*_num_ep_servers = 0;
		return NT_STATUS_OK;
	}

	principal = talloc_asprintf(talloc_tos(),
				    "cifs/%s",
				    lp_netbios_name());
	if (principal == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcesrv_auth_type_principal_register(dce_ctx,
						     DCERPC_AUTH_TYPE_NTLMSSP,
						     principal);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = dcesrv_auth_type_principal_register(dce_ctx,
						     DCERPC_AUTH_TYPE_SPNEGO,
						     principal);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (lp_security() == SEC_ADS) {
		status = dcesrv_auth_type_principal_register(dce_ctx,
							     DCERPC_AUTH_TYPE_KRB5,
							     principal);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	TALLOC_FREE(principal);

	/*
	 * We prefer NDR64 for witness,
	 * as it's a very simple protocol and
	 * we support it from the beginning,
	 * which means it's well tested.
	 */
	dce_ctx->preferred_transfer = &ndr_transfer_syntax_ndr64;

	ep_servers[0] = witness_get_ep_server();

	*_ep_servers = ep_servers;
	*_num_ep_servers = ARRAY_SIZE(ep_servers);
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_witness",
		5,
		60,
		witness_interfaces,
		witness_servers,
		NULL);
}

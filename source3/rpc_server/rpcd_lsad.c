/*
 *  Unix SMB/CIFS implementation.
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
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_lsa_scompat.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_samr_scompat.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_scompat.h"
#include "librpc/gen_ndr/ndr_dssetup.h"
#include "librpc/gen_ndr/ndr_dssetup_scompat.h"
#include "source3/include/auth.h"
#include "source3/include/secrets.h"

static size_t lsad_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_lsarpc,
		&ndr_table_samr,
		&ndr_table_dssetup,
		/*
		 * This last item is truncated from the list by the
		 * num_ifaces -= 1 below for the fileserver.  Take
		 * care when adding new services.
		 */
		&ndr_table_netlogon,
	};
	size_t num_ifaces = ARRAY_SIZE(ifaces);

	switch(lp_server_role()) {
	case ROLE_STANDALONE:
	case ROLE_DOMAIN_MEMBER:
		/* no netlogon for non-dc */
		num_ifaces -= 1;
		break;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * All these services are provided by the 'samba'
		 * binary from source4, not this code which is the
		 * source3 / NT4-like "classic" DC implementation
		 */
		num_ifaces = 0;
		break;
	default:
		break;
	}

	*pifaces = ifaces;
	return num_ifaces;
}

static NTSTATUS lsad_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[4] = { NULL, };
	size_t num_servers = ARRAY_SIZE(ep_servers);
	NTSTATUS status;
	bool ok;

	ep_servers[0] = lsarpc_get_ep_server();
	ep_servers[1] = samr_get_ep_server();
	ep_servers[2] = dssetup_get_ep_server();
	ep_servers[3] = netlogon_get_ep_server();

	ok = secrets_init();
	if (!ok) {
		DBG_ERR("secrets_init() failed\n");
		exit(1);
	}

	status = dcesrv_register_default_auth_types_machine_principal(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch(lp_server_role()) {
	case ROLE_STANDALONE:
	case ROLE_DOMAIN_MEMBER:
		/* no netlogon for non-dc */
		num_servers -= 1;
		break;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * All these services are provided by the 'samba'
		 * binary from source4, not this code which is the
		 * source3 / NT4-like "classic" DC implementation
		 */
		num_servers = 0;
		break;
	default:
		/*
		 * As DC we also register schannel with an
		 * empty principal
		 */
		status = dcesrv_auth_type_principal_register(dce_ctx,
							     DCERPC_AUTH_TYPE_SCHANNEL,
							     "");
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;
	}

	*_ep_servers = ep_servers;
	*_num_ep_servers = num_servers;
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_lsad",
		5,
		60,
		lsad_interfaces,
		lsad_servers,
		NULL);
}

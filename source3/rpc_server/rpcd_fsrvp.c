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
#include "librpc/gen_ndr/ndr_fsrvp.h"
#include "librpc/gen_ndr/ndr_fsrvp_scompat.h"

static size_t fsrvp_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_FileServerVssAgent,
	};

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		/*
		 * For now, don't do shadow copies on the AD DC. This
		 * might change in the future, but there's a
		 * recommendation to split DCs from file servers.
		 *
		 * But then we need to put the snap logic into the ad
		 * dc testenv's smb.conf.
		 */
		*pifaces = NULL;
		return 0;
	}

	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static size_t fsrvp_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		*_ep_servers = NULL;
		return 0;
	}

	lp_load_with_shares(get_dyn_CONFIGFILE());

	ep_servers[0] = FileServerVssAgent_get_ep_server();

	*_ep_servers = ep_servers;
	return ARRAY_SIZE(ep_servers);
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_fsrvp",
		5,
		60,
		fsrvp_interfaces,
		fsrvp_servers,
		NULL);
}

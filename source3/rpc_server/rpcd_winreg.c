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
#include "librpc/gen_ndr/ndr_winreg.h"
#include "librpc/gen_ndr/ndr_winreg_scompat.h"
#include "source3/registry/reg_init_full.h"

static size_t winreg_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_winreg,
	};
	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static size_t winreg_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };
	WERROR werr;

	ep_servers[0] = winreg_get_ep_server();

	werr = registry_init_full();
	if (!W_ERROR_IS_OK(werr)) {
		DBG_ERR("registry_init_full() failed: %s\n",
			win_errstr(werr));
		exit(1);
	}

	lp_load_with_shares(get_dyn_CONFIGFILE());

	*_ep_servers = ep_servers;
	return ARRAY_SIZE(ep_servers);
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_winreg",
		5,
		60,
		winreg_interfaces,
		winreg_servers,
		NULL);
}

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

#include "replace.h"
#include "rpc_worker.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_epmapper_scompat.h"

static size_t epmapper_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_epmapper,
	};
	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static size_t epmapper_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[] = { NULL };

	ep_servers[0] = epmapper_get_ep_server();

	*_ep_servers = ep_servers;
	return ARRAY_SIZE(ep_servers);
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_epmapper",
		1,
		10,
		epmapper_interfaces,
		epmapper_servers,
		NULL);
}

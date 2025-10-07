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
#include "source3/locking/proto.h"
#include "source3/smbd/proto.h"
#include "rpc_worker.h"
#include "librpc/gen_ndr/ndr_mdssvc.h"
#include "librpc/gen_ndr/ndr_mdssvc_scompat.h"

static size_t mdssvc_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_mdssvc,
	};

	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static NTSTATUS mdssvc_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };
	bool ok;

	lp_load_with_shares(get_dyn_CONFIGFILE());

	ok = posix_locking_init(false);
	if (!ok) {
		DBG_ERR("posix_locking_init() failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	mangle_reset_cache();

	ep_servers[0] = mdssvc_get_ep_server();

	*_ep_servers = ep_servers;
	*_num_ep_servers = ARRAY_SIZE(ep_servers);
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_mdssvc",
		5,
		60,
		mdssvc_interfaces,
		mdssvc_servers,
		NULL);
}

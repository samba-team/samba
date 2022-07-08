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
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "librpc/gen_ndr/ndr_spoolss_scompat.h"
#include "source3/locking/share_mode_lock.h"
#include "source3/printing/queue_process.h"
#include "source3/include/messages.h"
#include "source3/include/secrets.h"
#include "source3/smbd/proto.h"

static size_t spoolss_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_spoolss,
	};
	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static size_t spoolss_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };
	struct messaging_context *msg_ctx = global_messaging_context();
	struct tevent_context *ev_ctx = messaging_tevent_context(msg_ctx);
	bool ok;

	ep_servers[0] = spoolss_get_ep_server();

	ok = secrets_init();
	if (!ok) {
		DBG_ERR("secrets_init() failed\n");
		exit(1);
	}

	ok = locking_init();
	if (!ok) {
		DBG_ERR("locking_init() failed\n");
		exit(1);
	}

	lp_load_with_shares(get_dyn_CONFIGFILE());

	ok = printing_subsystem_init(ev_ctx, msg_ctx, dce_ctx);
	if (!ok) {
		DBG_WARNING("printing_subsystem_init() failed\n");
		exit(1);
	}

	mangle_reset_cache();

	*_ep_servers = ep_servers;
	return ARRAY_SIZE(ep_servers);
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_spoolss",
		5,
		60,
		spoolss_interfaces,
		spoolss_servers,
		NULL);
}

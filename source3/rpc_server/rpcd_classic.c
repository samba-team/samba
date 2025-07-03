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
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "librpc/gen_ndr/ndr_srvsvc_scompat.h"
#include "librpc/gen_ndr/ndr_dfs.h"
#include "librpc/gen_ndr/ndr_dfs_scompat.h"
#include "librpc/gen_ndr/ndr_wkssvc.h"
#include "librpc/gen_ndr/ndr_wkssvc_scompat.h"
#include "librpc/gen_ndr/ndr_svcctl.h"
#include "librpc/gen_ndr/ndr_svcctl_scompat.h"
#include "librpc/gen_ndr/ndr_ntsvcs.h"
#include "librpc/gen_ndr/ndr_ntsvcs_scompat.h"
#include "librpc/gen_ndr/ndr_eventlog.h"
#include "librpc/gen_ndr/ndr_eventlog_scompat.h"
#include "librpc/gen_ndr/ndr_initshutdown.h"
#include "librpc/gen_ndr/ndr_initshutdown_scompat.h"
#include "source3/include/secrets.h"
#include "locking/share_mode_lock.h"
#include "source3/smbd/proto.h"

static size_t classic_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_srvsvc,
		&ndr_table_netdfs,
		&ndr_table_initshutdown,
		&ndr_table_svcctl,
		&ndr_table_ntsvcs,
		&ndr_table_eventlog,
		&ndr_table_wkssvc,
	};
	size_t num_ifaces = ARRAY_SIZE(ifaces);

	*pifaces = ifaces;
	return num_ifaces;

}

static NTSTATUS classic_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[7] = { NULL };
	size_t num_servers = ARRAY_SIZE(ep_servers);
	NTSTATUS status;
	bool ok;

	ep_servers[0] = srvsvc_get_ep_server();
	ep_servers[1] = netdfs_get_ep_server();
	ep_servers[2] = initshutdown_get_ep_server();
	ep_servers[3] = svcctl_get_ep_server();
	ep_servers[4] = ntsvcs_get_ep_server();
	ep_servers[5] = eventlog_get_ep_server();
	ep_servers[6] = wkssvc_get_ep_server();

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

	status = share_info_db_init();
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_info_db_init failed: %s\n", nt_errstr(status));
		exit(1);
	}

	lp_load_with_shares(get_dyn_CONFIGFILE());

	mangle_reset_cache();

	status = dcesrv_register_default_auth_types_machine_principal(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
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
		"rpcd_classic",
		5,
		60,
		classic_interfaces,
		classic_servers,
		NULL);
}

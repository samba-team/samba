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
#include "param/loadparm.h"
#include "libds/common/roles.h"

static size_t epmapper_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_epmapper,
	};
	size_t num_ifaces = ARRAY_SIZE(ifaces);

	switch(lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * On the AD DC epmapper is provided by the 'samba'
		 * binary from source4/
		 */
		num_ifaces = 0;
		break;
	default:
		break;
	}

	*pifaces = ifaces;
	return num_ifaces;
}

static NTSTATUS epmapper_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[] = { NULL };
	size_t num_servers = ARRAY_SIZE(ep_servers);
	NTSTATUS status;

	/*
	 * Windows Server 2022 registers the following auth_types
	 * all with an empty principal name:
	 *
	 *  principle name for proto 9 (spnego) is ''
	 *  principle name for proto 10 (ntlmssp) is ''
	 *  principle name for proto 14 is ''
	 *  principle name for proto 16 (gssapi_krb5) is ''
	 *  principle name for proto 22 is ''
	 *  principle name for proto 30 is ''
	 *  principle name for proto 31 is ''
	 *
	 * We only register what we also support.
	 */
	status = dcesrv_register_default_auth_types(dce_ctx, "");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ep_servers[0] = epmapper_get_ep_server();

	switch(lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * On the AD DC epmapper is provided by the 'samba'
		 * binary from source4/
		 */
		num_servers = 0;
		break;
	default:
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
		"rpcd_epmapper",
		1,
		10,
		epmapper_interfaces,
		epmapper_servers,
		NULL);
}

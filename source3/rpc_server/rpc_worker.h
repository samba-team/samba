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

#ifndef __RPC_WORKER_H__
#define __RPC_WORKER_H__

#include "replace.h"
#include "librpc/rpc/dcesrv_core.h"

int rpc_worker_main(
	int argc,
	const char *argv[],
	const char *daemon_config_name,
	int num_workers,
	int idle_seconds,
	size_t (*get_interfaces)(
		const struct ndr_interface_table ***ifaces,
		void *private_data),
	size_t (*get_servers)(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server ***ep_servers,
		void *private_data),
	void *private_data);

#endif /* __RPC_WORKER_H__ */

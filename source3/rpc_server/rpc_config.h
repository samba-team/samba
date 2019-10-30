/*
 *  Unix SMB/CIFS implementation.
 *
 *  SMBD RPC service config
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *  Copyright (C) 2011      Simo Sorce <idra@samba.org>
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

#ifndef _RPC_CONFIG_H
#define _RPC_CONFIG_H

enum rpc_service_mode_e {
	RPC_SERVICE_MODE_DISABLED = 0,
	RPC_SERVICE_MODE_EMBEDDED,
	RPC_SERVICE_MODE_EXTERNAL
};

/**
 * @brief Get the mode in which service pipes are configured.
 *
 * @param name		Name of the service
 *
 * @return The actual configured mode.
 */
enum rpc_service_mode_e rpc_service_mode(const char *name);

#define rpc_epmapper_mode() rpc_service_mode("epmapper")
#define rpc_spoolss_mode() rpc_service_mode("spoolss")
#define rpc_lsarpc_mode() rpc_service_mode("lsarpc")
#define rpc_samr_mode() rpc_service_mode("samr")
#define rpc_netlogon_mode() rpc_service_mode("netlogon")
#define rpc_fssagentrpc_mode() rpc_service_mode("fssagentrpc")
#define rpc_mdssvc_mode() rpc_service_mode("mdssvc")



enum rpc_daemon_type_e {
	RPC_DAEMON_DISABLED = 0,
	RPC_DAEMON_EMBEDDED,
	RPC_DAEMON_FORK
};

/**
 * @brief Get the mode in which a server is started.
 *
 * @param name		Name of the rpc server
 *
 * @return The actual configured type.
 */
enum rpc_daemon_type_e rpc_daemon_type(const char *name);

#define rpc_epmapper_daemon() rpc_daemon_type("epmd")
#define rpc_spoolss_daemon() rpc_daemon_type("spoolssd")
#define rpc_lsasd_daemon() rpc_daemon_type("lsasd")
#define rpc_fss_daemon() rpc_daemon_type("fssd")
#define rpc_mdssd_daemon() rpc_daemon_type("mdssd")

struct dcesrv_context;
struct dcesrv_context *global_dcesrv_context(void);
void global_dcesrv_context_free(void);

#endif /* _RPC_CONFIG_H */

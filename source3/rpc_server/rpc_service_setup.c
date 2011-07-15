/*
 *  Unix SMB/CIFS implementation.
 *
 *  SMBD RPC service callbacks
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
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
#include "ntdomain.h"

#include "../librpc/gen_ndr/ndr_epmapper_c.h"
#include "../librpc/gen_ndr/srv_epmapper.h"
#include "../librpc/gen_ndr/srv_srvsvc.h"
#include "../librpc/gen_ndr/srv_winreg.h"
#include "../librpc/gen_ndr/srv_dfs.h"
#include "../librpc/gen_ndr/srv_dssetup.h"
#include "../librpc/gen_ndr/srv_echo.h"
#include "../librpc/gen_ndr/srv_eventlog.h"
#include "../librpc/gen_ndr/srv_initshutdown.h"
#include "../librpc/gen_ndr/srv_lsa.h"
#include "../librpc/gen_ndr/srv_netlogon.h"
#include "../librpc/gen_ndr/srv_ntsvcs.h"
#include "../librpc/gen_ndr/srv_samr.h"
#include "../librpc/gen_ndr/srv_spoolss.h"
#include "../librpc/gen_ndr/srv_svcctl.h"
#include "../librpc/gen_ndr/srv_wkssvc.h"

#include "printing/nt_printing_migrate_internal.h"
#include "rpc_server/eventlog/srv_eventlog_reg.h"
#include "rpc_server/svcctl/srv_svcctl_reg.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "rpc_server/svcctl/srv_svcctl_nt.h"

#include "librpc/rpc/dcerpc_ep.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/epmapper/srv_epmapper.h"

enum rpc_service_mode_e rpc_epmapper_mode(void)
{
	const char *rpcsrv_type;
	enum rpc_service_mode_e state;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "daemon");

	if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		state = RPC_SERVICE_MODE_EXTERNAL;
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		state = RPC_SERVICE_MODE_DAEMON;
	} else {
		state = RPC_SERVICE_MODE_DISABLED;
	}

	return state;
}

enum rpc_service_mode_e rpc_spoolss_mode(void)
{
	const char *rpcsrv_type;
	enum rpc_service_mode_e state;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "spoolss",
					   "embedded");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		state = RPC_SERVICE_MODE_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		state = RPC_SERVICE_MODE_EXTERNAL;
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		state = RPC_SERVICE_MODE_DAEMON;
	} else {
		state = RPC_SERVICE_MODE_DISABLED;
	}

	return state;
}

enum rpc_service_mode_e rpc_lsarpc_mode(void)
{
	const char *rpcsrv_type;
	enum rpc_service_mode_e mode;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "lsarpc",
					   "embedded");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		mode = RPC_SERVICE_MODE_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		mode = RPC_SERVICE_MODE_EXTERNAL;
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		mode = RPC_SERVICE_MODE_DAEMON;
	} else {
		mode = RPC_SERVICE_MODE_DISABLED;
	}

	return mode;
}

enum rpc_service_mode_e rpc_samr_mode(void)
{
	const char *rpcsrv_type;
	enum rpc_service_mode_e mode;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "samr",
					   "embedded");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		mode = RPC_SERVICE_MODE_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		mode = RPC_SERVICE_MODE_EXTERNAL;
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		mode = RPC_SERVICE_MODE_DAEMON;
	} else {
		mode = RPC_SERVICE_MODE_DISABLED;
	}

	return mode;
}

enum rpc_service_mode_e rpc_netlogon_mode(void)
{
	const char *rpcsrv_type;
	enum rpc_service_mode_e mode;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "netlogon",
					   "embedded");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		mode = RPC_SERVICE_MODE_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		mode = RPC_SERVICE_MODE_EXTERNAL;
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		mode = RPC_SERVICE_MODE_DAEMON;
	} else {
		mode = RPC_SERVICE_MODE_DISABLED;
	}

	return mode;
}

static bool rpc_setup_epmapper(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx)
{
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = rpc_epmapper_init(NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_winreg(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_winreg;
	const char *pipe_name = "winreg";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_winreg_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_srvsvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_srvsvc;
	const char *pipe_name = "srvsvc";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_srvsvc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_lsarpc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_lsarpc;
	const char *pipe_name = "lsarpc";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	enum rpc_service_mode_e lsarpc_mode = rpc_lsarpc_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_lsarpc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (lsarpc_mode == RPC_SERVICE_MODE_EMBEDDED &&
	    epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_samr(struct tevent_context *ev_ctx,
			   struct messaging_context *msg_ctx,
			   const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_samr;
	const char *pipe_name = "samr";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	enum rpc_service_mode_e samr_mode = rpc_samr_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_samr_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (samr_mode == RPC_SERVICE_MODE_EMBEDDED &&
	    epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_netlogon(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx,
			       const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_netlogon;
	const char *pipe_name = "netlogon";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	enum rpc_service_mode_e netlogon_mode = rpc_netlogon_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_netlogon_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (netlogon_mode == RPC_SERVICE_MODE_EMBEDDED &&
	    epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_netdfs(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_netdfs;
	const char *pipe_name = "netdfs";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_netdfs_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

#ifdef DEVELOPER
static bool rpc_setup_rpcecho(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_rpcecho;
	const char *pipe_name = "rpcecho";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_rpcecho_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}
#endif

static bool rpc_setup_dssetup(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_dssetup;
	const char *pipe_name = "dssetup";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_dssetup_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_wkssvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct dcerpc_binding_vector *v)
{
	const struct ndr_interface_table *t = &ndr_table_wkssvc;
	const char *pipe_name = "wkssvc";
	struct dcerpc_binding_vector *v2;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;
	bool ok;

	status = rpc_wkssvc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		v2 = dcerpc_binding_vector_dup(talloc_tos(), v);
		if (v2 == NULL) {
			return false;
		}

		status = dcerpc_binding_vector_replace_iface(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v2, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v2);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool spoolss_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx =
		talloc_get_type_abort(ptr, struct messaging_context);
	bool ok;

	/*
	 * Migrate the printers first.
	 */
	ok = nt_printing_tdb_migrate(msg_ctx);
	if (!ok) {
		return false;
	}

	return true;
}

static bool spoolss_shutdown_cb(void *ptr)
{
	srv_spoolss_cleanup();

	return true;
}

static bool rpc_setup_spoolss(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_spoolss;
	struct rpc_srv_callbacks spoolss_cb;
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e spoolss_mode = rpc_spoolss_mode();
	NTSTATUS status;

	if (_lp_disable_spoolss() ||
	    spoolss_mode == RPC_SERVICE_MODE_DISABLED) {
		return true;
	}

	if (spoolss_mode == RPC_SERVICE_MODE_EMBEDDED) {
		spoolss_cb.init         = spoolss_init_cb;
		spoolss_cb.shutdown     = spoolss_shutdown_cb;
		spoolss_cb.private_data = msg_ctx;

		status = rpc_spoolss_init(&spoolss_cb);
	} else if (spoolss_mode == RPC_SERVICE_MODE_EXTERNAL ||
		   spoolss_mode == RPC_SERVICE_MODE_DAEMON) {
		status = rpc_spoolss_init(NULL);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (spoolss_mode == RPC_SERVICE_MODE_EMBEDDED) {
		enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();

		if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
			status = dcerpc_binding_vector_new(talloc_tos(), &v);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}

			status = dcerpc_binding_vector_add_np_default(t, v);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}

			status = rpc_ep_register(ev_ctx,
						 msg_ctx,
						 t,
						 v);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
		}
	}

	return true;
}

static bool svcctl_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx =
		talloc_get_type_abort(ptr, struct messaging_context);
	bool ok;

	/* initialize the control hooks */
	init_service_op_table();

	ok = svcctl_init_winreg(msg_ctx);
	if (!ok) {
		return false;
	}

	return true;
}

static bool svcctl_shutdown_cb(void *ptr)
{
	shutdown_service_op_table();

	return true;
}

static bool rpc_setup_svcctl(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_svcctl;
	const char *pipe_name = "svcctl";
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	struct rpc_srv_callbacks svcctl_cb;
	NTSTATUS status;
	bool ok;

	svcctl_cb.init         = svcctl_init_cb;
	svcctl_cb.shutdown     = svcctl_shutdown_cb;
	svcctl_cb.private_data = msg_ctx;

	status = rpc_svcctl_init(&svcctl_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = dcerpc_binding_vector_new(talloc_tos(), &v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		ok = setup_dcerpc_ncalrpc_socket(ev_ctx,
						 msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		status = dcerpc_binding_vector_add_unix(t, v, pipe_name);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_ntsvcs(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_ntsvcs;
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;

	status = rpc_ntsvcs_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = dcerpc_binding_vector_new(talloc_tos(), &v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool eventlog_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx =
		talloc_get_type_abort(ptr, struct messaging_context);
	bool ok;

	ok = eventlog_init_winreg(msg_ctx);
	if (!ok) {
		return false;
	}

	return true;
}

static bool rpc_setup_eventlog(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_eventlog;
	struct rpc_srv_callbacks eventlog_cb;
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;

	eventlog_cb.init         = eventlog_init_cb;
	eventlog_cb.shutdown     = NULL;
	eventlog_cb.private_data = msg_ctx;

	status = rpc_eventlog_init(&eventlog_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = dcerpc_binding_vector_new(talloc_tos(), &v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool rpc_setup_initshutdown(struct tevent_context *ev_ctx,
				   struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_initshutdown;
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;

	status = rpc_initshutdown_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = dcerpc_binding_vector_new(talloc_tos(), &v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = dcerpc_binding_vector_add_np_default(t, v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

bool dcesrv_ep_setup(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx)
{
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	struct dcerpc_binding_vector *v;
	const char *rpcsrv_type;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool ok;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return false;
	}

	status = dcerpc_binding_vector_new(tmp_ctx,
					   &v);
	if (!NT_STATUS_IS_OK(status)) {
		ok = false;
		goto done;
	}

	ok = rpc_setup_epmapper(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "tcpip",
					   "no");

	if ((strcasecmp_m(rpcsrv_type, "yes") == 0 ||
	     strcasecmp_m(rpcsrv_type, "true") == 0)
	    && epm_mode != RPC_SERVICE_MODE_DISABLED) {
		status = rpc_setup_tcpip_sockets(ev_ctx,
						 msg_ctx,
						 &ndr_table_winreg,
						 v,
						 0);
		if (!NT_STATUS_IS_OK(status)) {
			ok = false;
			goto done;
		}
	}

	ok = rpc_setup_winreg(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_srvsvc(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_lsarpc(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_samr(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_netlogon(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_netdfs(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

#ifdef DEVELOPER
	ok = rpc_setup_rpcecho(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}
#endif

	ok = rpc_setup_dssetup(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_wkssvc(ev_ctx, msg_ctx, v);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_spoolss(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_svcctl(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_ntsvcs(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_eventlog(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_initshutdown(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

done:
	talloc_free(tmp_ctx);
	return ok;
}

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */

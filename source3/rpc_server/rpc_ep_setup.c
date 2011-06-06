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

#include "rpc_server/rpc_ep_setup.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/epmapper/srv_epmapper.h"

struct dcesrv_ep_context {
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
};

static uint16_t _open_sockets(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      struct ndr_syntax_id syntax_id,
			      uint16_t port)
{
	uint32_t num_ifs = iface_count();
	uint32_t i;
	uint16_t p = 0;

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/*
		 * We have been given an interfaces line, and been told to only
		 * bind to those interfaces. Create a socket per interface and
		 * bind to only these.
		 */

		/* Now open a listen socket for each of the interfaces. */
		for(i = 0; i < num_ifs; i++) {
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);

			p = setup_dcerpc_ncacn_tcpip_socket(ev_ctx,
							    msg_ctx,
							    ifss,
							    port);
			if (p == 0) {
				return 0;
			}
			port = p;
		}
	} else {
		const char *sock_addr = lp_socket_address();
		const char *sock_ptr;
		char *sock_tok;

		if (strequal(sock_addr, "0.0.0.0") ||
		    strequal(sock_addr, "::")) {
#if HAVE_IPV6
			sock_addr = "::,0.0.0.0";
#else
			sock_addr = "0.0.0.0";
#endif
		}

		for (sock_ptr = sock_addr;
		     next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,");
		    ) {
			struct sockaddr_storage ss;

			/* open an incoming socket */
			if (!interpret_string_addr(&ss,
						   sock_tok,
						   AI_NUMERICHOST|AI_PASSIVE)) {
				continue;
			}

			p = setup_dcerpc_ncacn_tcpip_socket(ev_ctx,
							    msg_ctx,
							    &ss,
							    port);
			if (p == 0) {
				return 0;
			}
			port = p;
		}
	}

	return p;
}

static bool epmapper_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	uint16_t port;

	port = _open_sockets(ep_ctx->ev_ctx,
			     ep_ctx->msg_ctx,
			     ndr_table_epmapper.syntax_id,
			     135);
	if (port == 135) {
		return true;
	}

	return false;
}

static bool epmapper_shutdown_cb(void *ptr)
{
	srv_epmapper_cleanup();

	return true;
}

static bool winreg_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_winreg.syntax_id;
	const char *pipe_name = "winreg";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}
		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_winreg,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool srvsvc_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_srvsvc.syntax_id;
	const char *pipe_name = "srvsvc";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_srvsvc,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool lsarpc_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_lsarpc.syntax_id;
	const char *pipe_name = "lsarpc";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_lsarpc,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool samr_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_samr.syntax_id;
	const char *pipe_name = "samr";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_samr,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool netlogon_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_netlogon.syntax_id;
	const char *pipe_name = "netlogon";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_netlogon,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool spoolss_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;
	bool ok;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	/*
	 * Migrate the printers first.
	 */
	ok = nt_printing_tdb_migrate(ep_ctx->msg_ctx);
	if (!ok) {
		return false;
	}

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_spoolss,
					 "spoolss",
					 0);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool spoolss_shutdown_cb(void *ptr)
{
	srv_spoolss_cleanup();

	return true;
}

static bool svcctl_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;
	bool ok;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	ok = svcctl_init_winreg(ep_ctx->msg_ctx);
	if (!ok) {
		return false;
	}

	/* initialize the control hooks */
	init_service_op_table();

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_svcctl,
					 "svcctl",
					 0);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool svcctl_shutdown_cb(void *ptr)
{
	shutdown_service_op_table();

	return true;
}

static bool ntsvcs_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_ntsvcs,
					 "ntsvcs",
					 0);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool eventlog_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;
	bool ok;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	ok = eventlog_init_winreg(ep_ctx->msg_ctx);
	if (!ok) {
		return false;
	}

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_eventlog,
					 "eventlog",
					 0);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool initshutdown_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_initshutdown,
					 "initshutdown",
					 0);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

#ifdef DEVELOPER
static bool rpcecho_init_cb(void *ptr) {
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     ndr_table_rpcecho.syntax_id,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_rpcecho,
					 "rpcecho",
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

#endif

static bool netdfs_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_netdfs.syntax_id;
	const char *pipe_name = "netdfs";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");
	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_netdfs,
					 pipe_name,
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool dssetup_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_dssetup.syntax_id;
	const char *pipe_name = "dssetup";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_dssetup,
					 "dssetup",
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

static bool wkssvc_init_cb(void *ptr)
{
	struct dcesrv_ep_context *ep_ctx =
		talloc_get_type_abort(ptr, struct dcesrv_ep_context);
	struct ndr_syntax_id abstract_syntax = ndr_table_wkssvc.syntax_id;
	const char *pipe_name = "wkssvc";
	const char *rpcsrv_type;
	uint16_t port;

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");
	if (strcasecmp_m(rpcsrv_type, "embedded") == 0 ||
	    strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		NTSTATUS status;
		bool ok;

		ok = setup_dcerpc_ncalrpc_socket(ep_ctx->ev_ctx,
						 ep_ctx->msg_ctx,
						 pipe_name,
						 NULL);
		if (!ok) {
			return false;
		}

		port = _open_sockets(ep_ctx->ev_ctx,
				     ep_ctx->msg_ctx,
				     abstract_syntax,
				     0);
		if (port == 0) {
			return false;
		}

		status = rpc_ep_register(ep_ctx->ev_ctx,
					 ep_ctx->msg_ctx,
					 &ndr_table_wkssvc,
					 "wkssvc",
					 port);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	}

	return true;
}

bool dcesrv_ep_setup(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx)
{
	struct dcesrv_ep_context *ep_ctx;

	struct rpc_srv_callbacks epmapper_cb;

	struct rpc_srv_callbacks winreg_cb;
	struct rpc_srv_callbacks srvsvc_cb;

	struct rpc_srv_callbacks lsarpc_cb;
	struct rpc_srv_callbacks samr_cb;
	struct rpc_srv_callbacks netlogon_cb;

	struct rpc_srv_callbacks spoolss_cb;
	struct rpc_srv_callbacks svcctl_cb;
	struct rpc_srv_callbacks ntsvcs_cb;
	struct rpc_srv_callbacks eventlog_cb;
	struct rpc_srv_callbacks initshutdown_cb;
	struct rpc_srv_callbacks netdfs_cb;
#ifdef DEVELOPER
	struct rpc_srv_callbacks rpcecho_cb;
#endif
	struct rpc_srv_callbacks dssetup_cb;
	struct rpc_srv_callbacks wkssvc_cb;

	const char *rpcsrv_type;

	ep_ctx = talloc(ev_ctx, struct dcesrv_ep_context);
	if (ep_ctx == NULL) {
		return false;
	}

	ep_ctx->ev_ctx = ev_ctx;
	ep_ctx->msg_ctx = msg_ctx;

	/* start endpoint mapper only if enabled */
	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "epmapper",
					   "none");
	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		epmapper_cb.init         = epmapper_init_cb;
		epmapper_cb.shutdown     = epmapper_shutdown_cb;
		epmapper_cb.private_data = ep_ctx;

		if (!NT_STATUS_IS_OK(rpc_epmapper_init(&epmapper_cb))) {
			return false;
		}
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0) {
		if (!NT_STATUS_IS_OK(rpc_epmapper_init(NULL))) {
			return false;
		}
	}

	winreg_cb.init         = winreg_init_cb;
	winreg_cb.shutdown     = NULL;
	winreg_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_winreg_init(&winreg_cb))) {
		return false;
	}

	srvsvc_cb.init         = srvsvc_init_cb;
	srvsvc_cb.shutdown     = NULL;
	srvsvc_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_srvsvc_init(&srvsvc_cb))) {
		return false;
	}


	lsarpc_cb.init         = lsarpc_init_cb;
	lsarpc_cb.shutdown     = NULL;
	lsarpc_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_lsarpc_init(&lsarpc_cb))) {
		return false;
	}

	samr_cb.init         = samr_init_cb;
	samr_cb.shutdown     = NULL;
	samr_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_samr_init(&samr_cb))) {
		return false;
	}

	netlogon_cb.init         = netlogon_init_cb;
	netlogon_cb.shutdown     = NULL;
	netlogon_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_netlogon_init(&netlogon_cb))) {
		return false;
	}

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server",
					   "spoolss",
					   "embedded");
	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		spoolss_cb.init         = spoolss_init_cb;
		spoolss_cb.shutdown     = spoolss_shutdown_cb;
		spoolss_cb.private_data = ep_ctx;
		if (!NT_STATUS_IS_OK(rpc_spoolss_init(&spoolss_cb))) {
			return false;
		}
	} else if (strcasecmp_m(rpcsrv_type, "daemon") == 0 ||
		   strcasecmp_m(rpcsrv_type, "external") == 0) {
		if (!NT_STATUS_IS_OK(rpc_spoolss_init(NULL))) {
			return false;
		}
	}

	svcctl_cb.init         = svcctl_init_cb;
	svcctl_cb.shutdown     = svcctl_shutdown_cb;
	svcctl_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_svcctl_init(&svcctl_cb))) {
		return false;
	}

	ntsvcs_cb.init         = ntsvcs_init_cb;
	ntsvcs_cb.shutdown     = NULL;
	ntsvcs_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_ntsvcs_init(&ntsvcs_cb))) {
		return false;
	}

	eventlog_cb.init         = eventlog_init_cb;
	eventlog_cb.shutdown     = NULL;
	eventlog_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_eventlog_init(&eventlog_cb))) {
		return false;
	}

	initshutdown_cb.init         = initshutdown_init_cb;
	initshutdown_cb.shutdown     = NULL;
	initshutdown_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_initshutdown_init(&initshutdown_cb))) {
		return false;
	}

	netdfs_cb.init         = netdfs_init_cb;
	netdfs_cb.shutdown     = NULL;
	netdfs_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_netdfs_init(&netdfs_cb))) {
		return false;
	}

#ifdef DEVELOPER
	rpcecho_cb.init         = rpcecho_init_cb;
	rpcecho_cb.shutdown     = NULL;
	rpcecho_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_rpcecho_init(&rpcecho_cb))) {
		return false;
	}
#endif

	dssetup_cb.init         = dssetup_init_cb;
	dssetup_cb.shutdown     = NULL;
	dssetup_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_dssetup_init(&dssetup_cb))) {
		return false;
	}

	wkssvc_cb.init         = wkssvc_init_cb;
	wkssvc_cb.shutdown     = NULL;
	wkssvc_cb.private_data = ep_ctx;
	if (!NT_STATUS_IS_OK(rpc_wkssvc_init(&wkssvc_cb))) {
		return false;
	}

	return true;
}

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */

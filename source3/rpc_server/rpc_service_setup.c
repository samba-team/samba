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

#include "librpc/gen_ndr/ndr_winreg_scompat.h"
#include "librpc/gen_ndr/ndr_srvsvc_scompat.h"
#include "librpc/gen_ndr/ndr_lsa_scompat.h"
#include "librpc/gen_ndr/ndr_samr_scompat.h"
#include "librpc/gen_ndr/ndr_netlogon_scompat.h"
#include "librpc/gen_ndr/ndr_dfs_scompat.h"
#include "librpc/gen_ndr/ndr_echo_scompat.h"
#include "librpc/gen_ndr/ndr_dssetup_scompat.h"
#include "librpc/gen_ndr/ndr_wkssvc_scompat.h"
#include "librpc/gen_ndr/ndr_spoolss_scompat.h"
#include "librpc/gen_ndr/ndr_svcctl_scompat.h"
#include "librpc/gen_ndr/ndr_ntsvcs_scompat.h"
#include "librpc/gen_ndr/ndr_eventlog_scompat.h"
#include "librpc/gen_ndr/ndr_initshutdown_scompat.h"

#include "printing/nt_printing_migrate_internal.h"
#include "rpc_server/eventlog/srv_eventlog_reg.h"
#include "rpc_server/svcctl/srv_svcctl_reg.h"
#include "rpc_server/spoolss/srv_spoolss_nt.h"
#include "rpc_server/svcctl/srv_svcctl_nt.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "rpc_server/rpc_sock_helper.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_ep_register.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_config.h"
#include "rpc_server/rpc_modules.h"
#include "rpc_server/epmapper/srv_epmapper.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static_decl_rpc;

/* Common routine for embedded RPC servers */
NTSTATUS rpc_setup_embedded(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    const struct ndr_interface_table *t,
			    const char *pipe_name)
{
	struct dcerpc_binding_vector *v;
	enum rpc_service_mode_e epm_mode = rpc_epmapper_mode();
	NTSTATUS status;

	/* Registration of ncacn_np services is problematic.  The
	 * ev_ctx passed in here is passed down to all children of the
	 * smbd process, and if the end point mapper ever goes away,
	 * they will all attempt to re-register.  But we want to test
	 * the code for now, so it is enabled in on environment in
	 * make test */
	if (epm_mode != RPC_SERVICE_MODE_DISABLED && 
	    (lp_parm_bool(-1, "rpc_server", "register_embedded_np", false))) {
		status = dcerpc_binding_vector_new(talloc_tos(), &v);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dcerpc_binding_vector_add_np_default(t, v);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = rpc_ep_register(ev_ctx,
					 msg_ctx,
					 t,
					 v);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_create_endpoint_sockets(struct tevent_context *ev_ctx,
					struct messaging_context *msg_ctx,
					struct dcesrv_context *dce_ctx,
					struct dcesrv_endpoint *e,
					struct dcerpc_binding_vector *bvec,
					struct pf_listen_fd *listen_fds,
					int *listen_fds_size)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(e->ep_description);
	char *binding = NULL;
	NTSTATUS status;

	binding = dcerpc_binding_string(dce_ctx, e->ep_description);
	if (binding == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Creating endpoint '%s'\n", binding);

	switch (transport) {
	case NCALRPC:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	case NCACN_IP_TCP:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	case NCACN_NP:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	default:
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

	/* Build binding string again as the endpoint may have changed by
	 * dcesrv_create_<transport>_socket functions */
	TALLOC_FREE(binding);
	binding = dcerpc_binding_string(dce_ctx, e->ep_description);
	if (binding == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(status)) {
		struct dcesrv_if_list *iface = NULL;
		DBG_ERR("Failed to create '%s' sockets for ", binding);
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(DBGLVL_ERR, ("'%s' ", iface->iface->name));
		}
		DEBUGADD(DBGLVL_ERR, (": %s\n", nt_errstr(status)));
		return status;
	} else {
		struct dcesrv_if_list *iface = NULL;
		DBG_INFO("Successfully listening on '%s' for ", binding);
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(DBGLVL_INFO, ("'%s' ", iface->iface->name));
		}
		DEBUGADD(DBGLVL_INFO, ("\n"));
	}

	TALLOC_FREE(binding);

	return status;
}

NTSTATUS dcesrv_setup_endpoint_sockets(struct tevent_context *ev_ctx,
				       struct messaging_context *msg_ctx,
				       struct dcesrv_context *dce_ctx,
				       struct dcesrv_endpoint *e,
				       struct dcerpc_binding_vector *bvec,
				       dcerpc_ncacn_termination_fn term_fn,
				       void *term_data)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(e->ep_description);
	char *binding = NULL;
	NTSTATUS status;

	binding = dcerpc_binding_string(dce_ctx, e->ep_description);
	if (binding == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("Setting up endpoint '%s'\n", binding);

	switch (transport) {
	case NCALRPC:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	case NCACN_IP_TCP:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	case NCACN_NP:
		/* TODO */
		status = NT_STATUS_OK;
		break;

	default:
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

	/* Build binding string again as the endpoint may have changed by
	 * dcesrv_create_<transport>_socket functions */
	TALLOC_FREE(binding);
	binding = dcerpc_binding_string(dce_ctx, e->ep_description);
	if (binding == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(status)) {
		struct dcesrv_if_list *iface = NULL;
		DBG_ERR("Failed to setup '%s' sockets for ", binding);
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(DBGLVL_ERR, ("'%s' ", iface->iface->name));
		}
		DEBUGADD(DBGLVL_ERR, (": %s\n", nt_errstr(status)));
		return status;
	} else {
		struct dcesrv_if_list *iface = NULL;
		DBG_INFO("Successfully listening on '%s' for ", binding);
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(DBGLVL_INFO, ("'%s' ", iface->iface->name));
		}
		DEBUGADD(DBGLVL_INFO, ("\n"));
	}

	TALLOC_FREE(binding);

	return status;
}

static NTSTATUS rpc_setup_winreg(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_winreg;
	const char *pipe_name = "winreg";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = winreg_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'winreg' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_srvsvc(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_srvsvc;
	const char *pipe_name = "srvsvc";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = srvsvc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'srvsvc' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_lsarpc(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_lsarpc;
	const char *pipe_name = "lsarpc";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = lsarpc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'lsarpc' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED ||
	    lsasd_type != RPC_DAEMON_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_samr(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_samr;
	const char *pipe_name = "samr";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = samr_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'samr' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED ||
	    lsasd_type != RPC_DAEMON_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_netlogon(struct tevent_context *ev_ctx,
				   struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_netlogon;
	const char *pipe_name = "netlogon";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = netlogon_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'netlogon' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED ||
	    lsasd_type != RPC_DAEMON_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_netdfs(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_netdfs;
	const char *pipe_name = "netdfs";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = netdfs_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'netdfs' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

#ifdef DEVELOPER
static NTSTATUS rpc_setup_rpcecho(struct tevent_context *ev_ctx,
				  struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_rpcecho;
	const char *pipe_name = "rpcecho";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = rpcecho_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'rpcecho' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
#endif

static NTSTATUS rpc_setup_dssetup(struct tevent_context *ev_ctx,
				  struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_dssetup;
	const char *pipe_name = "dssetup";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = dssetup_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'dssetup' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_wkssvc(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_wkssvc;
	const char *pipe_name = "wkssvc";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = wkssvc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'wkssvc' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server: "
			"%s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_spoolss(struct tevent_context *ev_ctx,
				  struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_spoolss;
	enum rpc_daemon_type_e spoolss_type = rpc_spoolss_daemon();
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	if (lp__disable_spoolss()) {
		return NT_STATUS_OK;
	}

	/* Register the endpoint server in DCERPC core */
	ep_server = spoolss_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'spoolss' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED ||
	    spoolss_type != RPC_DAEMON_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server"
			": %s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_svcctl(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_svcctl;
	const char *pipe_name = "svcctl";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = svcctl_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'svcctl' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server"
			": %s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_ntsvcs(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_ntsvcs;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = ntsvcs_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'ntsvcs' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server"
			": %s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_eventlog(struct tevent_context *ev_ctx,
				   struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_eventlog;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = eventlog_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'eventlog' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint server"
			": %s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_setup_initshutdown(struct tevent_context *ev_ctx,
				       struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_initshutdown;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	/* Register the endpoint server in DCERPC core */
	ep_server = initshutdown_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get 'initshutdown' endpoint server\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	service_mode = rpc_service_mode(ep_server->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return NT_STATUS_OK;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register '%s' endpoint "
			"server: %s\n", ep_server->name, nt_errstr(status));
		return status;
	}

	status = rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_init(TALLOC_CTX *mem_ctx,
		     struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     struct dcesrv_context *dce_ctx)
{
	TALLOC_CTX *tmp_ctx;
	bool ok;
	init_module_fn *mod_init_fns = NULL;
	NTSTATUS status;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_INFO("Registering DCE/RPC endpoint servers\n");

	status = rpc_setup_winreg(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_srvsvc(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_lsarpc(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_samr(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_netlogon(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_netdfs(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

#ifdef DEVELOPER
	status = rpc_setup_rpcecho(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
#endif

	status = rpc_setup_dssetup(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_wkssvc(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_spoolss(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_svcctl(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_ntsvcs(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_eventlog(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_setup_initshutdown(ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	DBG_INFO("Initializing DCE/RPC modules\n");

	/* Initialize static subsystems */
	static_init_rpc(NULL);

	/* Initialize shared modules */
	mod_init_fns = load_samba_modules(tmp_ctx, "rpc");
	if ((mod_init_fns == NULL) && (errno != ENOENT)) {
		/*
		 * ENOENT means the directory doesn't exist which can happen if
		 * all modules are static. So ENOENT is ok, everything else is
		 * not ok.
		 */
		DBG_ERR("Loading shared DCE/RPC modules failed [%s]\n",
			strerror(errno));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ok = run_init_functions(NULL, mod_init_fns);
	if (!ok) {
		DBG_ERR("Initializing shared DCE/RPC modules failed\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* The RPC module setup function has to register the endpoint server */
	ok = setup_rpc_modules(ev_ctx, msg_ctx);
	if (!ok) {
		DBG_ERR("Shared DCE/RPC modules setup failed\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	status = dcesrv_init_registered_ep_servers(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init DCE/RPC endpoint servers: %s\n",
			nt_errstr(status));
		goto done;
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */

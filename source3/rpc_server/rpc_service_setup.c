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
#include "rpc_server/rpc_config.h"
#include "rpc_server/epmapper/srv_epmapper.h"

/* Common routine for embedded RPC servers */
static bool rpc_setup_embedded(struct tevent_context *ev_ctx,
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

static bool rpc_setup_winreg(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_winreg;
	const char *pipe_name = "winreg";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_winreg_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_srvsvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_srvsvc;
	const char *pipe_name = "srvsvc";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_srvsvc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_lsarpc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_lsarpc;
	const char *pipe_name = "lsarpc";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED || lsasd_type != RPC_DAEMON_EMBEDDED) {
		return true;
	}

	status = rpc_lsarpc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_samr(struct tevent_context *ev_ctx,
			   struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_samr;
	const char *pipe_name = "samr";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED || lsasd_type != RPC_DAEMON_EMBEDDED) {
		return true;
	}

	status = rpc_samr_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_netlogon(struct tevent_context *ev_ctx,
			       struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_netlogon;
	const char *pipe_name = "netlogon";
	enum rpc_daemon_type_e lsasd_type = rpc_lsasd_daemon();
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED || lsasd_type != RPC_DAEMON_EMBEDDED) {
		return true;
	}

	status = rpc_netlogon_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_netdfs(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_netdfs;
	const char *pipe_name = "netdfs";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_netdfs_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

#ifdef DEVELOPER
static bool rpc_setup_rpcecho(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_rpcecho;
	const char *pipe_name = "rpcecho";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_rpcecho_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}
#endif

static bool rpc_setup_dssetup(struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_dssetup;
	const char *pipe_name = "dssetup";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_dssetup_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_wkssvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_wkssvc;
	const char *pipe_name = "wkssvc";
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_wkssvc_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
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
	enum rpc_daemon_type_e spoolss_type = rpc_spoolss_daemon();
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);

	if (lp__disable_spoolss()) {
		return true;
	}

	if (service_mode != RPC_SERVICE_MODE_EMBEDDED || spoolss_type != RPC_DAEMON_EMBEDDED) {
		return true;
	}

	spoolss_cb.init         = spoolss_init_cb;
	spoolss_cb.shutdown     = spoolss_shutdown_cb;
	spoolss_cb.private_data = msg_ctx;

	status = rpc_spoolss_init(&spoolss_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
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
	struct rpc_srv_callbacks svcctl_cb;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	svcctl_cb.init         = svcctl_init_cb;
	svcctl_cb.shutdown     = svcctl_shutdown_cb;
	svcctl_cb.private_data = msg_ctx;

	status = rpc_svcctl_init(&svcctl_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static bool rpc_setup_ntsvcs(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_ntsvcs;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_ntsvcs_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
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
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	eventlog_cb.init         = eventlog_init_cb;
	eventlog_cb.shutdown     = NULL;
	eventlog_cb.private_data = msg_ctx;

	status = rpc_eventlog_init(&eventlog_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
}

static bool rpc_setup_initshutdown(struct tevent_context *ev_ctx,
				   struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_initshutdown;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	if (service_mode != RPC_SERVICE_MODE_EMBEDDED) {
		return true;
	}

	status = rpc_initshutdown_init(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, NULL);
}

bool dcesrv_ep_setup(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx)
{
	TALLOC_CTX *tmp_ctx;
	bool ok;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return false;
	}

	ok = rpc_setup_winreg(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_srvsvc(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_lsarpc(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_samr(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_netlogon(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_netdfs(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

#ifdef DEVELOPER
	ok = rpc_setup_rpcecho(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}
#endif

	ok = rpc_setup_dssetup(ev_ctx, msg_ctx);
	if (!ok) {
		goto done;
	}

	ok = rpc_setup_wkssvc(ev_ctx, msg_ctx);
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

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

#include "printing/nt_printing_migrate.h"
#include "rpc_server/srv_eventlog_reg.h"
#include "rpc_server/srv_svcctl_reg.h"

#include "librpc/rpc/dcerpc_ep.h"

#include "rpc_server/srv_rpc_register.h"

static NTSTATUS _rpc_ep_register(const struct ndr_interface_table *iface,
				 const char *name)
{
	struct dcerpc_binding_vector *v = NULL;
	NTSTATUS status;
	const char *rpcsrv_type;

	/* start endpoint mapper only if enabled */
	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server", "epmapper",
					   "none");
	if (StrCaseCmp(rpcsrv_type, "none") == 0) {
		return NT_STATUS_OK;
	}

	status = dcerpc_binding_vector_create(talloc_tos(),
					      iface,
					      &v);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_ep_register(iface,
				    v,
				    &iface->syntax_id.uuid,
				    name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

static NTSTATUS _rpc_ep_unregister(const struct ndr_interface_table *iface)
{
	struct dcerpc_binding_vector *v = NULL;
	NTSTATUS status;
	const char *rpcsrv_type;

	/* start endpoint mapper only if enabled */
	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server", "epmapper",
					   "none");
	if (StrCaseCmp(rpcsrv_type, "none") == 0) {
		return NT_STATUS_OK;
	}

	status = dcerpc_binding_vector_create(talloc_tos(),
					      iface,
					      &v);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_ep_unregister(iface,
				      v,
				      &iface->syntax_id.uuid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

static bool winreg_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_winreg, "winreg"));
}

static bool winreg_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_winreg));
}

static bool srvsvc_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_srvsvc, "srvsvc"));
}

static bool srvsvc_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_srvsvc));
}

static bool lsarpc_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_lsarpc, "lsarpc"));
}

static bool lsarpc_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_lsarpc));
}

static bool samr_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_samr, "samr"));
}

static bool samr_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_samr));
}

static bool netlogon_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_netlogon, "netlogon"));
}

static bool netlogon_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_netlogon));
}

static bool spoolss_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		ptr, struct messaging_context);
	NTSTATUS status;
	bool ok;

	/*
	 * Migrate the printers first.
	 */
	ok = nt_printing_tdb_migrate(msg_ctx);
	if (!ok) {
		return false;
	}

	status =_rpc_ep_register(&ndr_table_spoolss, "spoolss");
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}



static bool spoolss_shutdown_cb(void *ptr)
{
	srv_spoolss_cleanup();

	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_spoolss));
}

static bool svcctl_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		ptr, struct messaging_context);
	bool ok;

	ok = svcctl_init_winreg(msg_ctx);
	if (!ok) {
		return false;
	}

	/* initialize the control hooks */
	init_service_op_table();

	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_svcctl, "svcctl"));
}

static bool svcctl_shutdown_cb(void *ptr)
{
	shutdown_service_op_table();

	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_svcctl));
}

static bool ntsvcs_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_ntsvcs, "ntsvcs"));
}

static bool ntsvcs_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_ntsvcs));
}

static bool eventlog_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx = talloc_get_type_abort(
		ptr, struct messaging_context);
	NTSTATUS status;

	status =_rpc_ep_register(&ndr_table_eventlog,
				 "eventlog");
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return eventlog_init_winreg(msg_ctx);
}

static bool eventlog_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_eventlog));
}

static bool initshutdown_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_initshutdown,
						"initshutdown"));
}

static bool initshutdown_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_initshutdown));
}

static bool rpcecho_init_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_rpcecho, "rpcecho"));
}

static bool rpcecho_shutdown_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_rpcecho));
}

static bool netdfs_init_cb(void *ptr)
{
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_netdfs, "netdfs"));
}

static bool netdfs_shutdown_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_netdfs));
}

static bool dssetup_init_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_dssetup, "dssetup"));
}

static bool dssetup_shutdown_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_dssetup));
}

static bool wkssvc_init_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_register(&ndr_table_wkssvc, "wkssvc"));
}

static bool wkssvc_shutdown_cb(void *ptr) {
	return NT_STATUS_IS_OK(_rpc_ep_unregister(&ndr_table_wkssvc));
}

bool srv_rpc_register(struct messaging_context *msg_ctx) {
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
	struct rpc_srv_callbacks rpcecho_cb;
	struct rpc_srv_callbacks dssetup_cb;
	struct rpc_srv_callbacks wkssvc_cb;

	const char *rpcsrv_type;

	/* start endpoint mapper only if enabled */
	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server", "epmapper",
					   "none");
	if (StrCaseCmp(rpcsrv_type, "embedded") == 0) {
		if (!NT_STATUS_IS_OK(rpc_epmapper_init(NULL))) {
			return false;
		}
	}

	winreg_cb.init         = winreg_init_cb;
	winreg_cb.shutdown     = winreg_shutdown_cb;
	winreg_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_winreg_init(&winreg_cb))) {
		return false;
	}

	srvsvc_cb.init         = srvsvc_init_cb;
	srvsvc_cb.shutdown     = srvsvc_shutdown_cb;
	srvsvc_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_srvsvc_init(&srvsvc_cb))) {
		return false;
	}


	lsarpc_cb.init         = lsarpc_init_cb;
	lsarpc_cb.shutdown     = lsarpc_shutdown_cb;
	lsarpc_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_lsarpc_init(&lsarpc_cb))) {
		return false;
	}

	samr_cb.init         = samr_init_cb;
	samr_cb.shutdown     = samr_shutdown_cb;
	samr_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_samr_init(&samr_cb))) {
		return false;
	}

	netlogon_cb.init         = netlogon_init_cb;
	netlogon_cb.shutdown     = netlogon_shutdown_cb;
	netlogon_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_netlogon_init(&netlogon_cb))) {
		return false;
	}

	spoolss_cb.init         = spoolss_init_cb;
	spoolss_cb.shutdown     = spoolss_shutdown_cb;
	spoolss_cb.private_data = msg_ctx;
	if (!NT_STATUS_IS_OK(rpc_spoolss_init(&spoolss_cb))) {
		return false;
	}


	svcctl_cb.init         = svcctl_init_cb;
	svcctl_cb.shutdown     = svcctl_shutdown_cb;
	svcctl_cb.private_data = msg_ctx;
	if (!NT_STATUS_IS_OK(rpc_svcctl_init(&svcctl_cb))) {
		return false;
	}

	ntsvcs_cb.init         = ntsvcs_init_cb;
	ntsvcs_cb.shutdown     = ntsvcs_shutdown_cb;
	ntsvcs_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_ntsvcs_init(&ntsvcs_cb))) {
		return false;
	}

	eventlog_cb.init         = eventlog_init_cb;
	eventlog_cb.shutdown     = eventlog_shutdown_cb;
	eventlog_cb.private_data = msg_ctx;
	if (!NT_STATUS_IS_OK(rpc_eventlog_init(&eventlog_cb))) {
		return false;
	}

	initshutdown_cb.init         = initshutdown_init_cb;
	initshutdown_cb.shutdown     = initshutdown_shutdown_cb;
	initshutdown_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_initshutdown_init(&initshutdown_cb))) {
		return false;
	}

	netdfs_cb.init         = netdfs_init_cb;
	netdfs_cb.shutdown     = netdfs_shutdown_cb;
	netdfs_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_netdfs_init(&netdfs_cb))) {
		return false;
	}
#ifdef DEVELOPER

	rpcecho_cb.init         = rpcecho_init_cb;
	rpcecho_cb.shutdown     = rpcecho_shutdown_cb;
	rpcecho_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_rpcecho_init(&rpcecho_cb))) {
		return false;
	}
#endif

	dssetup_cb.init         = dssetup_init_cb;
	dssetup_cb.shutdown     = dssetup_shutdown_cb;
	dssetup_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_dssetup_init(&dssetup_cb))) {
		return false;
	}

	wkssvc_cb.init         = wkssvc_init_cb;
	wkssvc_cb.shutdown     = wkssvc_shutdown_cb;
	wkssvc_cb.private_data = NULL;
	if (!NT_STATUS_IS_OK(rpc_wkssvc_init(&wkssvc_cb))) {
		return false;
	}

	return true;
}

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */

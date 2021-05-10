/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines for mdssvc
 *  Copyright (C) Ralph Boehme 2014
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
#include "messages.h"
#include "ntdomain.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_config.h"
#include "rpc_server/rpc_modules.h"
#include "rpc_server/mdssvc/srv_mdssvc_nt.h"
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "gen_ndr/auth.h"
#include "mdssvc.h"
#include "smbd/globals.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_mdssvc.h"
#include "librpc/gen_ndr/ndr_mdssvc_scompat.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static bool rpc_setup_mdssvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_mdssvc;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	enum rpc_daemon_type_e mdssvc_type = rpc_mdssd_daemon();
	bool external = service_mode != RPC_SERVICE_MODE_EMBEDDED ||
			mdssvc_type != RPC_DAEMON_EMBEDDED;
	bool in_mdssd = external && am_parent == NULL;
	const struct dcesrv_endpoint_server *ep_server = NULL;

	if (external && !in_mdssd) {
		return true;
	}

	ep_server = mdssvc_get_ep_server();
	if (ep_server == NULL) {
		DBG_ERR("Failed to get endpoint server\n");
		return false;
	}

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to register 'mdssvc' endpoint "
			"server: %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

static struct rpc_module_fns rpc_module_mdssvc_fns = {
	.setup = rpc_setup_mdssvc,
};

static_decl_rpc;
NTSTATUS rpc_mdssvc_module_init(TALLOC_CTX *mem_ctx)
{
	DBG_DEBUG("Registering mdsvc RPC service\n");

	return register_rpc_module(&rpc_module_mdssvc_fns, "mdssvc");
}

static NTSTATUS create_mdssvc_policy_handle(TALLOC_CTX *mem_ctx,
					    struct pipes_struct *p,
					    int snum,
					    const char *sharename,
					    const char *path,
					    struct policy_handle *handle)
{
	struct mds_ctx *mds_ctx;

	ZERO_STRUCTP(handle);

	mds_ctx = mds_init_ctx(mem_ctx,
			       messaging_tevent_context(p->msg_ctx),
			       p->msg_ctx,
			       p->session_info,
			       snum,
			       sharename,
			       path);
	if (mds_ctx == NULL) {
		DEBUG(1, ("error in mds_init_ctx for: %s\n", path));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!create_policy_hnd(p, handle, 0, mds_ctx)) {
		talloc_free(mds_ctx);
		ZERO_STRUCTP(handle);
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

void _mdssvc_open(struct pipes_struct *p, struct mdssvc_open *r)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int snum;
	char *outpath = discard_const_p(char, r->out.share_path);
	char *path;
	NTSTATUS status;

	DBG_DEBUG("[%s]\n", r->in.share_name);

	*r->out.device_id = *r->in.device_id;
	*r->out.unkn2 = *r->in.unkn2;
	*r->out.unkn3 = *r->in.unkn3;
	outpath[0] = '\0';

	snum = lp_servicenumber(r->in.share_name);
	if (!VALID_SNUM(snum)) {
		return;
	}

	path = lp_path(talloc_tos(), lp_sub, snum);
	if (path == NULL) {
		DBG_ERR("Couldn't create policy handle for %s\n",
			r->in.share_name);
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	status = create_mdssvc_policy_handle(p->mem_ctx, p,
					     snum,
					     r->in.share_name,
					     path,
					     r->out.handle);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Couldn't create policy handle for %s\n",
			r->in.share_name);
		talloc_free(path);
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	strlcpy(outpath, path, 1024);
	talloc_free(path);
	return;
}

static bool is_zero_policy_handle(const struct policy_handle *h)
{
	struct GUID zero_uuid = {0};

	if (h->handle_type != 0) {
		return false;
	}
	if (!GUID_equal(&h->uuid, &zero_uuid)) {
		return false;
	}
	return true;
}

void _mdssvc_unknown1(struct pipes_struct *p, struct mdssvc_unknown1 *r)
{
	struct mds_ctx *mds_ctx;
	NTSTATUS status;

	mds_ctx = find_policy_by_hnd(p,
				     r->in.handle,
				     DCESRV_HANDLE_ANY,
				     struct mds_ctx,
				     &status);
	if (!NT_STATUS_IS_OK(status)) {
		if (is_zero_policy_handle(r->in.handle)) {
			p->fault_state = 0;
		} else {
			p->fault_state = DCERPC_NCA_S_PROTO_ERROR;
		}
		*r->out.status = 0;
		*r->out.flags = 0;
		*r->out.unkn7 = 0;
		return;
	}

	DEBUG(10, ("%s: path: %s\n", __func__, mds_ctx->spath));

	*r->out.status = 0;
	*r->out.flags = 0x6b000001;
	*r->out.unkn7 = 0;

	return;
}

void _mdssvc_cmd(struct pipes_struct *p, struct mdssvc_cmd *r)
{
	bool ok;
	char *rbuf;
	struct mds_ctx *mds_ctx;
	NTSTATUS status;

	mds_ctx = find_policy_by_hnd(p,
				     r->in.handle,
				     DCESRV_HANDLE_ANY,
				     struct mds_ctx,
				     &status);
	if (!NT_STATUS_IS_OK(status)) {
		if (is_zero_policy_handle(r->in.handle)) {
			p->fault_state = 0;
		} else {
			p->fault_state = DCERPC_NCA_S_PROTO_ERROR;
		}
		r->out.response_blob->size = 0;
		*r->out.fragment = 0;
		*r->out.unkn9 = 0;
		return;
	}

	DEBUG(10, ("%s: path: %s\n", __func__, mds_ctx->spath));

	ok = security_token_is_sid(p->session_info->security_token,
				   &mds_ctx->sid);
	if (!ok) {
		struct dom_sid_buf buf;
		DBG_WARNING("not the same sid: %s\n",
			    dom_sid_str_buf(&mds_ctx->sid, &buf));
		p->fault_state = DCERPC_FAULT_ACCESS_DENIED;
		return;
	}

	if (geteuid() != mds_ctx->uid) {
		DEBUG(0, ("uid mismatch: %d/%d\n", geteuid(), mds_ctx->uid));
		smb_panic("uid mismatch");
	}

	if (r->in.request_blob.size > MAX_SL_FRAGMENT_SIZE) {
		DEBUG(1, ("%s: request size too large\n", __func__));
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	if (r->in.request_blob.length > MAX_SL_FRAGMENT_SIZE) {
		DEBUG(1, ("%s: request length too large\n", __func__));
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	if (r->in.max_fragment_size1 > MAX_SL_FRAGMENT_SIZE) {
		DEBUG(1, ("%s: request fragment size too large: %u\n",
			  __func__, (unsigned)r->in.max_fragment_size1));
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	rbuf = talloc_zero_array(p->mem_ctx, char, r->in.max_fragment_size1);
	if (rbuf == NULL) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}
	r->out.response_blob->spotlight_blob = (uint8_t *)rbuf;
	r->out.response_blob->size = r->in.max_fragment_size1;

	/* We currently don't use fragmentation at the mdssvc RPC layer */
	*r->out.fragment = 0;

	ok = mds_dispatch(mds_ctx, &r->in.request_blob, r->out.response_blob);
	if (ok) {
		*r->out.unkn9 = 0;
	} else {
		/* FIXME: just interpolating from AFP, needs verification */
		*r->out.unkn9 = UINT32_MAX;
	}

	return;
}

void _mdssvc_close(struct pipes_struct *p, struct mdssvc_close *r)
{
	struct mds_ctx *mds_ctx;
	NTSTATUS status;

	mds_ctx = find_policy_by_hnd(p,
				     r->in.in_handle,
				     DCESRV_HANDLE_ANY,
				     struct mds_ctx,
				     &status);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("invalid handle\n");
		if (is_zero_policy_handle(r->in.in_handle)) {
			p->fault_state = 0;
		} else {
			p->fault_state = DCERPC_NCA_S_PROTO_ERROR;
		}
		return;
	}

	DBG_DEBUG("Close mdssvc handle for path: %s\n", mds_ctx->spath);
	TALLOC_FREE(mds_ctx);

	*r->out.out_handle = *r->in.in_handle;
	close_policy_hnd(p, r->in.in_handle);

	*r->out.status = 0;

	return;
}

static NTSTATUS mdssvc__op_init_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server);

static NTSTATUS mdssvc__op_shutdown_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server);

#define DCESRV_INTERFACE_MDSSVC_INIT_SERVER \
	mdssvc_init_server

#define DCESRV_INTERFACE_MDSSVC_SHUTDOWN_SERVER \
	mdssvc_shutdown_server

static NTSTATUS mdssvc_init_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	bool ok;

	ok = mds_init(msg_ctx);
	if (!ok) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return mdssvc__op_init_server(dce_ctx, ep_server);
}

static NTSTATUS mdssvc_shutdown_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	mds_shutdown();

	return mdssvc__op_shutdown_server(dce_ctx, ep_server);
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_mdssvc_scompat.c"

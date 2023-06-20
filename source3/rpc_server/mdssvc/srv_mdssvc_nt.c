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
#include "rpc_server/rpc_config.h"
#include "rpc_server/mdssvc/srv_mdssvc_nt.h"
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "gen_ndr/auth.h"
#include "mdssvc.h"
#include "smbd/globals.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_mdssvc.h"
#include "librpc/gen_ndr/ndr_mdssvc_scompat.h"
#include "lib/global_contexts.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static NTSTATUS create_mdssvc_policy_handle(TALLOC_CTX *mem_ctx,
					    struct pipes_struct *p,
					    int snum,
					    const char *sharename,
					    const char *path,
					    struct policy_handle *handle)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct mds_ctx *mds_ctx;
	NTSTATUS status;

	ZERO_STRUCTP(handle);

	status = mds_init_ctx(mem_ctx,
			      messaging_tevent_context(p->msg_ctx),
			      p->msg_ctx,
			      session_info,
			      snum,
			      sharename,
			      path,
			      &mds_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("mds_init_ctx() path [%s] failed: %s\n",
			  path, nt_errstr(status));
		return status;
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
	if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_VOLUME)) {
		ZERO_STRUCTP(r->out.handle);
		talloc_free(path);
		return;
	}
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
		if (ndr_policy_handle_empty(r->in.handle)) {
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
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	bool ok;
	struct mds_ctx *mds_ctx;
	NTSTATUS status;

	mds_ctx = find_policy_by_hnd(p,
				     r->in.handle,
				     DCESRV_HANDLE_ANY,
				     struct mds_ctx,
				     &status);
	if (!NT_STATUS_IS_OK(status)) {
		if (ndr_policy_handle_empty(r->in.handle)) {
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

	ok = security_token_is_sid(session_info->security_token,
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
		if (ndr_policy_handle_empty(r->in.in_handle)) {
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

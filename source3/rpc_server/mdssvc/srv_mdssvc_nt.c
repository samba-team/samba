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
#include "ntdomain.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_config.h"
#include "rpc_server/rpc_modules.h"
#include "rpc_server/mdssvc/srv_mdssvc_nt.h"
#include "../librpc/gen_ndr/srv_mdssvc.h"
#include "libcli/security/security_token.h"
#include "gen_ndr/auth.h"
#include "mdssvc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static bool mdssvc_init_cb(void *ptr)
{
	struct messaging_context *msg_ctx =
		talloc_get_type_abort(ptr, struct messaging_context);
	bool ok;

	ok = init_service_mdssvc(msg_ctx);
	if (!ok) {
		return false;
	}

	return true;
}

static bool mdssvc_shutdown_cb(void *ptr)
{
	shutdown_service_mdssvc();

	return true;
}

static bool rpc_setup_mdssvc(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx)
{
	const struct ndr_interface_table *t = &ndr_table_mdssvc;
	const char *pipe_name = "mdssvc";
	struct rpc_srv_callbacks mdssvc_cb;
	NTSTATUS status;
	enum rpc_service_mode_e service_mode = rpc_service_mode(t->name);
	enum rpc_daemon_type_e mdssvc_type = rpc_mdssd_daemon();

	mdssvc_cb.init         = mdssvc_init_cb;
	mdssvc_cb.shutdown     = mdssvc_shutdown_cb;
	mdssvc_cb.private_data = msg_ctx;

	status = rpc_mdssvc_init(&mdssvc_cb);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (service_mode != RPC_SERVICE_MODE_EMBEDDED
	    || mdssvc_type != RPC_DAEMON_EMBEDDED) {
		return true;
	}

	return rpc_setup_embedded(ev_ctx, msg_ctx, t, pipe_name);
}

static struct rpc_module_fns rpc_module_mdssvc_fns = {
	.setup = rpc_setup_mdssvc,
	.init = rpc_mdssvc_init,
	.shutdown = rpc_mdssvc_shutdown,
};

static_decl_rpc;
NTSTATUS rpc_mdssvc_module_init(TALLOC_CTX *mem_ctx)
{
	DBG_DEBUG("Registering mdsvc RPC service\n");

	return register_rpc_module(&rpc_module_mdssvc_fns, "mdssvc");
}


bool init_service_mdssvc(struct messaging_context *msg_ctx)
{
	return mds_init(msg_ctx);
}

bool shutdown_service_mdssvc(void)
{
	return mds_shutdown();
}

static NTSTATUS create_mdssvc_policy_handle(TALLOC_CTX *mem_ctx,
					    struct pipes_struct *p,
					    const char *path,
					    struct policy_handle *handle)
{
	struct mds_ctx *mds_ctx;

	ZERO_STRUCTP(handle);

	mds_ctx = mds_init_ctx(mem_ctx, p->session_info, path);
	if (mds_ctx == NULL) {
		DEBUG(1, ("error in mds_init_ctx for: %s\n", path));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!create_policy_hnd(p, handle, mds_ctx)) {
		talloc_free(mds_ctx);
		ZERO_STRUCTP(handle);
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

void _mdssvc_open(struct pipes_struct *p, struct mdssvc_open *r)
{
	int snum;
	char *path;
	NTSTATUS status;

	DEBUG(10, ("%s: [%s]\n", __func__, r->in.share_name));

	snum = lp_servicenumber(r->in.share_name);
	if (!VALID_SNUM(snum)) {
		p->fault_state = DCERPC_FAULT_CANT_PERFORM;
		return;
	}

	if (lp_spotlight(snum)) {
		DEBUG(10, ("Spotlight enabled: %s\n", r->in.share_name));

		path = lp_path(talloc_tos(), snum);
		if (path == NULL) {
			DEBUG(1, ("Couldn't create policy handle for %s\n",
				  r->in.share_name));
			p->fault_state = DCERPC_FAULT_CANT_PERFORM;
			return;
		}

		status = create_mdssvc_policy_handle(p->mem_ctx, p, path,
						     r->out.handle);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Couldn't create policy handle for %s\n",
				  r->in.share_name));
			talloc_free(path);
			p->fault_state = DCERPC_FAULT_CANT_PERFORM;
			return;
		}

		strlcpy(discard_const_p(char, r->out.share_path), path, 1024);
		talloc_free(path);
		*r->out.device_id = *r->in.device_id;
	}

	*r->out.unkn2 = 0x17;
	*r->out.unkn3 = 0;

	return;
}

void _mdssvc_unknown1(struct pipes_struct *p, struct mdssvc_unknown1 *r)
{
	struct mds_ctx *mds_ctx;

	if (!find_policy_by_hnd(p, &r->in.handle, (void **)(void *)&mds_ctx)) {
		DEBUG(1, ("%s: invalid handle\n", __func__));
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

	if (!find_policy_by_hnd(p, &r->in.handle, (void **)(void *)&mds_ctx)) {
		DEBUG(1, ("%s: invalid handle\n", __func__));
		return;
	}

	DEBUG(10, ("%s: path: %s\n", __func__, mds_ctx->spath));

	ok = security_token_is_sid(p->session_info->security_token,
				   &mds_ctx->sid);
	if (!ok) {
		DEBUG(1,("%s: not the same sid: %s\n", __func__,
			 sid_string_tos(&mds_ctx->sid)));
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

	ok = mds_dispatch(mds_ctx, &r->in.request_blob, r->out.response_blob);
	if (ok) {
		*r->out.status = 0;
		*r->out.unkn9 = 0;
	} else {
		/* FIXME: just interpolating from AFP, needs verification */
		*r->out.status = UINT32_MAX;
		*r->out.unkn9 = UINT32_MAX;
	}

	return;
}

void _mdssvc_close(struct pipes_struct *p, struct mdssvc_close *r)
{
	struct mds_ctx *mds_ctx;

	if (!find_policy_by_hnd(p, &r->in.in_handle, (void **)(void *)&mds_ctx)) {
		DEBUG(1, ("%s: invalid handle\n", __func__));
		return;
	}

	DEBUG(10, ("%s: path: %s\n", __func__, mds_ctx->spath));

	close_policy_hnd(p, &r->in.in_handle);

	ZERO_STRUCTP(r->out.out_handle);
	*r->out.status = 0;

	return;
}

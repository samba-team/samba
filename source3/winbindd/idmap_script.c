/*
   Unix SMB/CIFS implementation.

   idmap script backend, used for Samba setups where you need to map SIDs to
   specific UIDs/GIDs.

   Copyright (C) Richard Sharpe 2014.

   This is heavily based upon idmap_tdb2.c, which is:

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/filesys.h"
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "../libcli/security/dom_sid.h"
#include "lib/util_file.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_script_context {
	const char *script; /* script to provide idmaps */
};

/*
  run a script to perform a mapping

  The script should accept the following command lines:

      SIDTOID S-1-xxxx -> XID:<id> | ERR:<str>
      SIDTOID S-1-xxxx -> UID:<id> | ERR:<str>
      SIDTOID S-1-xxxx -> GID:<id> | ERR:<str>
      IDTOSID XID xxxx -> SID:<sid> | ERR:<str>
      IDTOSID UID xxxx -> SID:<sid> | ERR:<str>
      IDTOSID GID xxxx -> SID:<sid> | ERR:<str>

  where XID means both a UID and a GID. This is the case for ID_TYPE_BOTH.

  TODO: Needs more validation ... like that we got a UID when we asked for one.
 */

struct idmap_script_xid2sid_state {
	char **argl;
	size_t idx;
	uint8_t *out;
};

static void idmap_script_xid2sid_done(struct tevent_req *subreq);

static struct tevent_req *idmap_script_xid2sid_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct unixid xid, const char *script, size_t idx)
{
	struct tevent_req *req, *subreq;
	struct idmap_script_xid2sid_state *state;
	char key;

	req = tevent_req_create(mem_ctx, &state,
				struct idmap_script_xid2sid_state);
	if (req == NULL) {
		return NULL;
	}
	state->idx = idx;

	switch (xid.type) {
	    case ID_TYPE_UID:
		    key = 'U';
		    break;
	    case ID_TYPE_GID:
		    key = 'G';
		    break;
	    case ID_TYPE_BOTH:
		    key = 'X';
		    break;
	    default:
		    DBG_WARNING("INVALID unix ID type: 0x02%x\n", xid.type);
		    tevent_req_error(req, EINVAL);
		    return tevent_req_post(req, ev);
	}

	state->argl = talloc_zero_array(state,
					char *,
					5);
	if (tevent_req_nomem(state->argl, req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[0] = talloc_strdup(state->argl, script);
	if (tevent_req_nomem(state->argl[0], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[1] = talloc_strdup(state->argl, "IDTOSID");
	if (tevent_req_nomem(state->argl[1], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[2] = talloc_asprintf(state->argl, "%cID", key);
	if (tevent_req_nomem(state->argl[2], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[3] = talloc_asprintf(state->argl, "%lu",
				(unsigned long)xid.id);
	if (tevent_req_nomem(state->argl[3], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[4] = NULL;

	subreq = file_ploadv_send(state, ev, state->argl, 1024);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, idmap_script_xid2sid_done, req);
	return req;
}

static void idmap_script_xid2sid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct idmap_script_xid2sid_state *state = tevent_req_data(
		req, struct idmap_script_xid2sid_state);
	int ret;

	ret = file_ploadv_recv(subreq, state, &state->out);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

static int idmap_script_xid2sid_recv(struct tevent_req *req, size_t *idx,
				     enum id_mapping *status,
				     struct dom_sid *sid)
{
	struct idmap_script_xid2sid_state *state = tevent_req_data(
		req, struct idmap_script_xid2sid_state);
	char *out = (char *)state->out;
	size_t out_size = talloc_get_size(out);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	if (out_size == 0) {
		goto unmapped;
	}
	if (state->out[out_size-1] != '\0') {
		goto unmapped;
	}

	*idx = state->idx;

	if ((strncmp(out, "SID:S-", 6) != 0) ||
	    !dom_sid_parse(out+4, sid)) {
		DBG_WARNING("Bad sid from script: %s\n", out);
		goto unmapped;
	}

	*status = ID_MAPPED;
	return 0;

unmapped:
	*sid = (struct dom_sid) {0};
	*status = ID_UNMAPPED;
	return 0;
}

struct idmap_script_xids2sids_state {
	struct id_map **ids;
	size_t num_ids;
	size_t num_done;
};

static void idmap_script_xids2sids_done(struct tevent_req *subreq);

static struct tevent_req *idmap_script_xids2sids_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct id_map **ids, size_t num_ids, const char *script)
{
	struct tevent_req *req;
	struct idmap_script_xids2sids_state *state;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct idmap_script_xids2sids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ids = ids;
	state->num_ids = num_ids;

	if (state->num_ids == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_ids; i++) {
		struct tevent_req *subreq;

		subreq = idmap_script_xid2sid_send(
			state, ev, ids[i]->xid, script, i);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, idmap_script_xids2sids_done,
					req);
	}

	return req;
}

static void idmap_script_xids2sids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct idmap_script_xids2sids_state *state = tevent_req_data(
		req, struct idmap_script_xids2sids_state);
	size_t idx = 0;
	enum id_mapping status = ID_UNKNOWN;
	struct dom_sid sid = {0};
	int ret;

	ret = idmap_script_xid2sid_recv(subreq, &idx, &status, &sid);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	if (idx >= state->num_ids) {
		tevent_req_error(req, EINVAL);
		return;
	}

	state->ids[idx]->status = status;

	state->ids[idx]->sid = dom_sid_dup(state->ids, &sid);
	if (tevent_req_nomem(state->ids[idx]->sid, req)) {
		return;
	}

	state->num_done += 1;

	if (state->num_done >= state->num_ids) {
		tevent_req_done(req);
	}
}

static int idmap_script_xids2sids_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static int idmap_script_xids2sids(struct id_map **ids, size_t num_ids,
				  const char *script)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret = ENOMEM;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = idmap_script_xids2sids_send(frame, ev, ids, num_ids, script);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		ret = errno;
		goto fail;
	}
	ret = idmap_script_xids2sids_recv(req);
fail:
	TALLOC_FREE(frame);
	return ret;
}

static NTSTATUS idmap_script_unixids_to_sids(struct idmap_domain *dom,
					     struct id_map **ids)
{
	struct idmap_script_context *ctx = talloc_get_type_abort(
		dom->private_data, struct idmap_script_context);
	int ret;
	size_t i, num_ids, num_mapped;

	DEBUG(10, ("%s called ...\n", __func__));
	/* Init status to avoid surprise ... */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}
	num_ids = i;

	ret = idmap_script_xids2sids(ids, num_ids, ctx->script);
	if (ret != 0) {
		DBG_DEBUG("idmap_script_xids2sids returned %s\n",
			  strerror(ret));
		return map_nt_error_from_unix(ret);
	}

	num_mapped = 0;

	for (i = 0; ids[i]; i++) {
		if (ids[i]->status == ID_MAPPED) {
			num_mapped += 1;
		}
	}

	if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (num_mapped < num_ids) {
		return STATUS_SOME_UNMAPPED;
	}
	return NT_STATUS_OK;
}

struct idmap_script_sid2xid_state {
	char **argl;
	size_t idx;
	uint8_t *out;
};

static void idmap_script_sid2xid_done(struct tevent_req *subreq);

static struct tevent_req *idmap_script_sid2xid_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const struct dom_sid *sid, const char *script, size_t idx)
{
	struct tevent_req *req, *subreq;
	struct idmap_script_sid2xid_state *state;
	struct dom_sid_buf sidbuf;

	req = tevent_req_create(mem_ctx, &state,
				struct idmap_script_sid2xid_state);
	if (req == NULL) {
		return NULL;
	}
	state->idx = idx;

	state->argl = talloc_zero_array(state,
					char *,
					4);
	if (tevent_req_nomem(state->argl, req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[0] = talloc_strdup(state->argl, script);
	if (tevent_req_nomem(state->argl[0], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[1] = talloc_strdup(state->argl, "SIDTOID");
	if (tevent_req_nomem(state->argl[1], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[2] = talloc_asprintf(state->argl, "%s",
			dom_sid_str_buf(sid, &sidbuf));
	if (tevent_req_nomem(state->argl[2], req)) {
		return tevent_req_post(req, ev);
	}
	state->argl[3] = NULL;

	subreq = file_ploadv_send(state, ev, state->argl, 1024);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, idmap_script_sid2xid_done, req);
	return req;
}

static void idmap_script_sid2xid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct idmap_script_sid2xid_state *state = tevent_req_data(
		req, struct idmap_script_sid2xid_state);
	int ret;

	ret = file_ploadv_recv(subreq, state, &state->out);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

static int idmap_script_sid2xid_recv(struct tevent_req *req,
				     size_t *idx, enum id_mapping *status,
				     struct unixid *xid)
{
	struct idmap_script_sid2xid_state *state = tevent_req_data(
		req, struct idmap_script_sid2xid_state);
	char *out = (char *)state->out;
	size_t out_size = talloc_get_size(out);
	unsigned long v;
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	if (out_size == 0) {
		goto unmapped;
	}
	if (state->out[out_size-1] != '\0') {
		goto unmapped;
	}

	*idx = state->idx;

	if (sscanf(out, "XID:%lu\n", &v) == 1) {
		*xid = (struct unixid) { .id = v, .type = ID_TYPE_BOTH };
	} else if (sscanf(out, "UID:%lu\n", &v) == 1) {
		*xid = (struct unixid) { .id = v, .type = ID_TYPE_UID };
	} else if (sscanf(out, "GID:%lu\n", &v) == 1) {
		*xid = (struct unixid) { .id = v, .type = ID_TYPE_GID };
	} else {
		goto unmapped;
	}

	*status = ID_MAPPED;
	return 0;

unmapped:
	*xid = (struct unixid) { .id = UINT32_MAX,
				 .type = ID_TYPE_NOT_SPECIFIED };
	*status = ID_UNMAPPED;
	return 0;
}

struct idmap_script_sids2xids_state {
	struct id_map **ids;
	size_t num_ids;
	size_t num_done;
};

static void idmap_script_sids2xids_done(struct tevent_req *subreq);

static struct tevent_req *idmap_script_sids2xids_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct id_map **ids, size_t num_ids, const char *script)
{
	struct tevent_req *req;
	struct idmap_script_sids2xids_state *state;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct idmap_script_sids2xids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ids = ids;
	state->num_ids = num_ids;

	if (state->num_ids == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_ids; i++) {
		struct tevent_req *subreq;

		subreq = idmap_script_sid2xid_send(
			state, ev, ids[i]->sid, script, i);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, idmap_script_sids2xids_done,
					req);
	}

	return req;
}

static void idmap_script_sids2xids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct idmap_script_sids2xids_state *state = tevent_req_data(
		req, struct idmap_script_sids2xids_state);
	size_t idx = 0;
	enum id_mapping status = ID_UNKNOWN;
	struct unixid xid = { .id = UINT32_MAX,
			      .type = ID_TYPE_NOT_SPECIFIED };
	int ret;

	ret = idmap_script_sid2xid_recv(subreq, &idx, &status, &xid);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	if (idx >= state->num_ids) {
		tevent_req_error(req, EINVAL);
		return;
	}

	state->ids[idx]->status = status;
	state->ids[idx]->xid = xid;

	state->num_done += 1;

	if (state->num_done >= state->num_ids) {
		tevent_req_done(req);
	}
}

static int idmap_script_sids2xids_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static int idmap_script_sids2xids(struct id_map **ids, size_t num_ids,
				  const char *script)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret = ENOMEM;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = idmap_script_sids2xids_send(frame, ev, ids, num_ids, script);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll(req, ev)) {
		ret = errno;
		goto fail;
	}
	ret = idmap_script_sids2xids_recv(req);
fail:
	TALLOC_FREE(frame);
	return ret;
}

static NTSTATUS idmap_script_sids_to_unixids(struct idmap_domain *dom,
					     struct id_map **ids)
{
	struct idmap_script_context *ctx = talloc_get_type_abort(
		dom->private_data, struct idmap_script_context);
	int ret;
	size_t i, num_ids, num_mapped;

	DEBUG(10, ("%s called ...\n", __func__));
	/* Init status to avoid surprise ... */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}
	num_ids = i;

	ret = idmap_script_sids2xids(ids, num_ids, ctx->script);
	if (ret != 0) {
		DBG_DEBUG("idmap_script_sids2xids returned %s\n",
			  strerror(ret));
		return map_nt_error_from_unix(ret);
	}

	num_mapped = 0;

	for (i=0; i<num_ids; i++) {
		struct id_map *map = ids[i];

		if ((map->status == ID_MAPPED) &&
		    !idmap_unix_id_is_in_range(map->xid.id, dom)) {
			DBG_INFO("Script returned id (%u) out of range "
				 "(%u - %u). Filtered!\n",
				 map->xid.id, dom->low_id, dom->high_id);
			map->status = ID_UNMAPPED;
		}

		if (map->status == ID_MAPPED) {
			num_mapped += 1;
		}
	}

	if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (num_mapped < num_ids) {
		return STATUS_SOME_UNMAPPED;
	}
	return NT_STATUS_OK;
}

/*
 *   Initialise idmap_script database.
 */
static NTSTATUS idmap_script_db_init(struct idmap_domain *dom)
{
	NTSTATUS ret;
	struct idmap_script_context *ctx;
	const char * idmap_script = NULL;
	const char *ctx_script = NULL;

	DEBUG(10, ("%s called ...\n", __func__));

	ctx = talloc_zero(dom, struct idmap_script_context);
	if (!ctx) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ctx_script = idmap_config_const_string(dom->name, "script", NULL);

	/* Do we even need to handle this? */
	idmap_script = lp_parm_const_string(-1, "idmap", "script", NULL);
	if (idmap_script != NULL) {
		DEBUG(0, ("Warning: 'idmap:script' is deprecated. "
			  " Please use 'idmap config * : script' instead!\n"));
	}

	if (strequal(dom->name, "*") && ctx_script == NULL) {
		/* fall back to idmap:script for backwards compatibility */
		ctx_script = idmap_script;
	}

	if (ctx_script) {
		DEBUG(1, ("using idmap script '%s'\n", ctx->script));
		/*
		 * We must ensure this memory is owned by ctx.
		 * The ctx_script const pointer is a pointer into
		 * the config file data and may become invalid
		 * on config file reload. BUG: 13956
		 */
		ctx->script = talloc_strdup(ctx, ctx_script);
		if (ctx->script == NULL) {
			ret = NT_STATUS_NO_MEMORY;
			goto failed;
		}
	}

	dom->private_data = ctx;
	dom->read_only = true; /* We do not allocate!*/

	return NT_STATUS_OK;

failed:
	talloc_free(ctx);
	return ret;
}

static struct idmap_methods db_methods = {
	.init            = idmap_script_db_init,
	.unixids_to_sids = idmap_script_unixids_to_sids,
	.sids_to_unixids = idmap_script_sids_to_unixids,
};

static_decl_idmap;
NTSTATUS idmap_script_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "script", &db_methods);
}

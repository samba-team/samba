/*
   Unix SMB/CIFS implementation.

   Async helpers for blocking functions

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Gerald Carter 2006
   Copyright (C) Simo Sorce 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"
#include "../libcli/security/security.h"
#include "passdb/lookup_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static struct winbindd_child static_idmap_child;

/*
 * Map idmap ranges to domain names, taken from smb.conf. This is
 * stored in the parent winbind and used to assemble xids2sids/sids2xids calls
 * into per-idmap-domain chunks.
 */
static struct wb_parent_idmap_config static_parent_idmap_config;

struct winbindd_child *idmap_child(void)
{
	return &static_idmap_child;
}

bool is_idmap_child(const struct winbindd_child *child)
{
	if (child == &static_idmap_child) {
		return true;
	}

	return false;
}

pid_t idmap_child_pid(void)
{
	return static_idmap_child.pid;
}

struct dcerpc_binding_handle *idmap_child_handle(void)
{
	/*
	 * The caller needs to use wb_parent_idmap_setup_send/recv
	 * before talking to the idmap child!
	 */
	SMB_ASSERT(static_parent_idmap_config.num_doms > 0);
	return static_idmap_child.binding_handle;
}

static const struct winbindd_child_dispatch_table idmap_dispatch_table[] = {
	{
		.name		= "PING",
		.struct_cmd	= WINBINDD_PING,
		.struct_fn	= winbindd_dual_ping,
	},{
		.name		= "NDRCMD",
		.struct_cmd	= WINBINDD_DUAL_NDRCMD,
		.struct_fn	= winbindd_dual_ndrcmd,
	},{
		.name		= NULL,
	}
};

void init_idmap_child(void)
{
	setup_child(NULL, &static_idmap_child,
		    idmap_dispatch_table,
		    "log.winbindd", "idmap");
}

struct wb_parent_idmap_setup_state {
	struct tevent_context *ev;
	struct wb_parent_idmap_config *cfg;
	size_t dom_idx;
};

static void wb_parent_idmap_setup_cleanup(struct tevent_req *req,
					  enum tevent_req_state req_state)
{
	struct wb_parent_idmap_setup_state *state =
		tevent_req_data(req,
		struct wb_parent_idmap_setup_state);

	if (req_state == TEVENT_REQ_DONE) {
		state->cfg = NULL;
		return;
	}

	if (state->cfg == NULL) {
		return;
	}

	state->cfg->num_doms = 0;
	TALLOC_FREE(state->cfg->doms);
	state->cfg = NULL;
}

static void wb_parent_idmap_setup_queue_wait_done(struct tevent_req *subreq);
static bool wb_parent_idmap_setup_scan_config(const char *domname,
					      void *private_data);
static void wb_parent_idmap_setup_lookupname_next(struct tevent_req *req);
static void wb_parent_idmap_setup_lookupname_done(struct tevent_req *subreq);

struct tevent_req *wb_parent_idmap_setup_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev)
{
	struct tevent_req *req = NULL;
	struct wb_parent_idmap_setup_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_parent_idmap_setup_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct wb_parent_idmap_setup_state) {
		.ev = ev,
		.cfg = &static_parent_idmap_config,
		.dom_idx = 0,
	};

	if (state->cfg->queue == NULL) {
		state->cfg->queue = tevent_queue_create(NULL,
						"wb_parent_idmap_config_queue");
		if (tevent_req_nomem(state->cfg->queue, req)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = tevent_queue_wait_send(state, state->ev, state->cfg->queue);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				wb_parent_idmap_setup_queue_wait_done,
				req);

	return req;
}

static void wb_parent_idmap_setup_queue_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct wb_parent_idmap_setup_state *state =
		tevent_req_data(req,
		struct wb_parent_idmap_setup_state);
	bool ok;

	/*
	 * Note we don't call TALLOC_FREE(subreq) here in order to block the
	 * queue until tevent_req_received() in wb_parent_idmap_setup_recv()
	 * will destroy it implicitly.
	 */
	ok = tevent_queue_wait_recv(subreq);
	if (!ok) {
		DBG_ERR("tevent_queue_wait_recv() failed\n");
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (state->cfg->num_doms != 0) {
		/*
		 * If we're not the first one we're done.
		 */
		tevent_req_done(req);
		return;
	}

	/*
	 * From this point we start changing state->cfg,
	 * which is &static_parent_idmap_config,
	 * so we better setup a cleanup function
	 * to undo the changes on failure.
	 */
	tevent_req_set_cleanup_fn(req, wb_parent_idmap_setup_cleanup);

	/*
	 * Put the passdb idmap domain first. We always need to try
	 * there first.
	 */
	state->cfg->doms = talloc_zero_array(NULL,
					     struct wb_parent_idmap_config_dom,
					     1);
	if (tevent_req_nomem(state->cfg->doms, req)) {
		return;
	}
	state->cfg->doms[0].low_id = 0;
	state->cfg->doms[0].high_id = UINT_MAX;
	state->cfg->doms[0].name = talloc_strdup(state->cfg->doms,
						 get_global_sam_name());
	if (tevent_req_nomem(state->cfg->doms[0].name, req)) {
		return;
	}
	state->cfg->num_doms += 1;

	lp_scan_idmap_domains(wb_parent_idmap_setup_scan_config, req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}

	wb_parent_idmap_setup_lookupname_next(req);
}

static bool wb_parent_idmap_setup_scan_config(const char *domname,
					      void *private_data)
{
	struct tevent_req *req =
		talloc_get_type_abort(private_data,
		struct tevent_req);
	struct wb_parent_idmap_setup_state *state =
		tevent_req_data(req,
		struct wb_parent_idmap_setup_state);
	struct wb_parent_idmap_config_dom *map = NULL;
	size_t i;
	const char *range;
	unsigned low_id, high_id;
	int ret;

	range = idmap_config_const_string(domname, "range", NULL);
	if (range == NULL) {
		DBG_DEBUG("No range for domain %s found\n", domname);
		return false;
	}

	ret = sscanf(range, "%u - %u", &low_id, &high_id);
	if (ret != 2) {
		DBG_DEBUG("Invalid range spec \"%s\" for domain %s\n",
			  range, domname);
		return false;
	}

	if (low_id > high_id) {
		DBG_DEBUG("Invalid range %u - %u for domain %s\n",
			  low_id, high_id, domname);
		return false;
	}

	for (i=0; i<state->cfg->num_doms; i++) {
		if (strequal(domname, state->cfg->doms[i].name)) {
			map = &state->cfg->doms[i];
			break;
		}
	}

	if (map == NULL) {
		struct wb_parent_idmap_config_dom *tmp;
		char *name;

		name = talloc_strdup(state, domname);
		if (name == NULL) {
			DBG_ERR("talloc failed\n");
			return false;
		}

		tmp = talloc_realloc(
			NULL, state->cfg->doms, struct wb_parent_idmap_config_dom,
			state->cfg->num_doms+1);
		if (tmp == NULL) {
			DBG_ERR("talloc failed\n");
			return false;
		}
		state->cfg->doms = tmp;

		map = &state->cfg->doms[state->cfg->num_doms];
		state->cfg->num_doms += 1;
		ZERO_STRUCTP(map);
		map->name = talloc_move(state->cfg->doms, &name);
	}

	map->low_id = low_id;
	map->high_id = high_id;

	return false;
}

static void wb_parent_idmap_setup_lookupname_next(struct tevent_req *req)
{
	struct wb_parent_idmap_setup_state *state =
		tevent_req_data(req,
		struct wb_parent_idmap_setup_state);
	struct wb_parent_idmap_config_dom *dom =
		&state->cfg->doms[state->dom_idx];
	struct tevent_req *subreq = NULL;

 next_domain:
	if (state->dom_idx == state->cfg->num_doms) {
		tevent_req_done(req);
		return;
	}

	if (strequal(dom->name, "*")) {
		state->dom_idx++;
		goto next_domain;
	}

	subreq = wb_lookupname_send(state,
				    state->ev,
				    dom->name,
				    dom->name,
				    "",
				    LOOKUP_NAME_NO_NSS);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wb_parent_idmap_setup_lookupname_done,
				req);
}

static void wb_parent_idmap_setup_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct wb_parent_idmap_setup_state *state =
		tevent_req_data(req,
		struct wb_parent_idmap_setup_state);
	struct wb_parent_idmap_config_dom *dom =
		&state->cfg->doms[state->dom_idx];
	enum lsa_SidType type;
	NTSTATUS status;

	status = wb_lookupname_recv(subreq, &dom->sid, &type);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Lookup domain name '%s' failed '%s'\n",
			dom->name,
			nt_errstr(status));

		state->dom_idx++;
		wb_parent_idmap_setup_lookupname_next(req);
		return;
	}

	if (type != SID_NAME_DOMAIN) {
		struct dom_sid_buf buf;

		DBG_ERR("SID %s for idmap domain name '%s' "
			"not a domain SID\n",
			dom_sid_str_buf(&dom->sid, &buf),
			dom->name);

		ZERO_STRUCT(dom->sid);
	}

	state->dom_idx++;
	wb_parent_idmap_setup_lookupname_next(req);

	return;
}

NTSTATUS wb_parent_idmap_setup_recv(struct tevent_req *req,
				    const struct wb_parent_idmap_config **_cfg)
{
	const struct wb_parent_idmap_config *cfg = &static_parent_idmap_config;
	NTSTATUS status;

	*_cfg = NULL;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	/*
	 * Note state->cfg is already set to NULL by
	 * wb_parent_idmap_setup_cleanup()
	 */
	*_cfg = cfg;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

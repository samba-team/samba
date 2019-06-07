/*
   CTDB IP takeover helper

   Copyright (C) Martin Schwenke  2016

   Based on ctdb_recovery_helper.c
   Copyright (C) Amitay Isaacs  2015

   and ctdb_takeover.c
   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Martin Schwenke  2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/strv.h"
#include "lib/util/strv_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"
#include "client/client.h"

#include "common/logging.h"

#include "server/ipalloc.h"

static int takeover_timeout = 9;

#define TIMEOUT()	timeval_current_ofs(takeover_timeout, 0)

/*
 * Utility functions
 */

static bool generic_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

static enum ipalloc_algorithm
determine_algorithm(const struct ctdb_tunable_list *tunables)
{
	switch (tunables->ip_alloc_algorithm) {
	case 0:
		return IPALLOC_DETERMINISTIC;
	case 1:
		return IPALLOC_NONDETERMINISTIC;
	case 2:
		return IPALLOC_LCP2;
	default:
		return IPALLOC_LCP2;
	};
}

/**********************************************************************/

struct get_public_ips_state {
	uint32_t *pnns;
	int count;
	struct ctdb_public_ip_list *ips;
	uint32_t *ban_credits;
};

static void get_public_ips_done(struct tevent_req *subreq);

static struct tevent_req *get_public_ips_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnns,
				int count, int num_nodes,
				uint32_t *ban_credits,
				bool available_only)
{
	struct tevent_req *req, *subreq;
	struct get_public_ips_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct get_public_ips_state);
	if (req == NULL) {
		return NULL;
	}

	state->pnns = pnns;
	state->count = count;
	state->ban_credits = ban_credits;

	state->ips  = talloc_zero_array(state,
					struct ctdb_public_ip_list,
					num_nodes);
	if (tevent_req_nomem(state->ips, req)) {
		return tevent_req_post(req, ev);
	}

	/* Short circuit if no nodes being asked for IPs */
	if (state->count == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ctdb_req_control_get_public_ips(&request, available_only);
	subreq = ctdb_client_control_multi_send(mem_ctx, ev, client,
						state->pnns,
						state->count,
						TIMEOUT(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, get_public_ips_done, req);

	return req;
}

static void get_public_ips_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct get_public_ips_state *state = tevent_req_data(
		req, struct get_public_ips_state);
	struct ctdb_reply_control **reply;
	int *err_list;
	int ret, i;
	bool status, found_errors;

	status = ctdb_client_control_multi_recv(subreq, &ret, state, &err_list,
						&reply);
	TALLOC_FREE(subreq);
	if (! status) {
		for (i = 0; i < state->count; i++) {
			if (err_list[i] != 0) {
				uint32_t pnn = state->pnns[i];

				D_ERR("control GET_PUBLIC_IPS failed on "
				      "node %u, ret=%d\n", pnn, err_list[i]);

				state->ban_credits[pnn]++;
			}
		}

		tevent_req_error(req, ret);
		return;
	}

	found_errors = false;
	for (i = 0; i < state->count; i++) {
		uint32_t pnn;
		struct ctdb_public_ip_list *ips;

		pnn = state->pnns[i];
		ret = ctdb_reply_control_get_public_ips(reply[i], state->ips,
							&ips);
		if (ret != 0) {
			D_ERR("control GET_PUBLIC_IPS failed on "
			      "node %u\n", pnn);
			state->ban_credits[pnn]++;
			found_errors = true;
			continue;
		}

		D_INFO("Fetched public IPs from node %u\n", pnn);
		state->ips[pnn] = *ips;
	}

	if (found_errors) {
		tevent_req_error(req, EIO);
		return;
	}

	talloc_free(reply);

	tevent_req_done(req);
}

static bool get_public_ips_recv(struct tevent_req *req, int *perr,
				TALLOC_CTX *mem_ctx,
				struct ctdb_public_ip_list **ips)
{
	struct get_public_ips_state *state = tevent_req_data(
		req, struct get_public_ips_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	*ips = talloc_steal(mem_ctx, state->ips);

	return true;
}

/**********************************************************************/

struct release_ip_state {
	int num_sent;
	int num_replies;
	int num_fails;
	int err_any;
	uint32_t *ban_credits;
};

struct release_ip_one_state {
	struct tevent_req *req;
	uint32_t *pnns;
	int count;
	const char *ip_str;
};

static void release_ip_done(struct tevent_req *subreq);

static struct tevent_req *release_ip_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  uint32_t *pnns,
					  int count,
					  struct timeval timeout,
					  struct public_ip_list *all_ips,
					  uint32_t *ban_credits)
{
	struct tevent_req *req, *subreq;
	struct release_ip_state *state;
	struct ctdb_req_control request;
	struct public_ip_list *tmp_ip;

	req = tevent_req_create(mem_ctx, &state, struct release_ip_state);
	if (req == NULL) {
		return NULL;
	}

	state->num_sent = 0;
	state->num_replies = 0;
	state->num_fails = 0;
	state->ban_credits = ban_credits;

	/* Send a RELEASE_IP to all nodes that should not be hosting
	 * each IP.  For each IP, all but one of these will be
	 * redundant.  However, the redundant ones are used to tell
	 * nodes which node should be hosting the IP so that commands
	 * like "ctdb ip" can display a particular nodes idea of who
	 * is hosting what. */
	for (tmp_ip = all_ips; tmp_ip != NULL; tmp_ip = tmp_ip->next) {
		struct release_ip_one_state *substate;
		struct ctdb_public_ip ip;
		int i;

		substate = talloc_zero(state, struct release_ip_one_state);
		if (tevent_req_nomem(substate, req)) {
			return tevent_req_post(req, ev);
		}

		substate->pnns = talloc_zero_array(substate, uint32_t, count);
		if (tevent_req_nomem(substate->pnns, req)) {
			return tevent_req_post(req, ev);
		}

		substate->count = 0;
		substate->req = req;

		substate->ip_str  = ctdb_sock_addr_to_string(substate,
							     &tmp_ip->addr,
							     false);
		if (tevent_req_nomem(substate->ip_str, req)) {
			return tevent_req_post(req, ev);
		}

		for (i = 0; i < count; i++) {
			uint32_t pnn = pnns[i];

			/* Skip this node if IP is not known */
			if (! bitmap_query(tmp_ip->known_on, pnn)) {
				continue;
			}

			/* If pnn is not the node that should be
			 * hosting the IP then add it to the list of
			 * nodes that need to do a release. */
			if (tmp_ip->pnn != pnn) {
				substate->pnns[substate->count] = pnn;
				substate->count++;
			}
		}

		if (substate->count == 0) {
			/* No releases to send for this address... */
			TALLOC_FREE(substate);
			continue;
		}

		ip.pnn = tmp_ip->pnn;
		ip.addr = tmp_ip->addr;
		ctdb_req_control_release_ip(&request, &ip);
		subreq = ctdb_client_control_multi_send(state, ev, client,
							substate->pnns,
							substate->count,
							timeout,/* cumulative */
							&request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, release_ip_done, substate);

		state->num_sent++;
	}

	/* None sent, finished... */
	if (state->num_sent == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void release_ip_done(struct tevent_req *subreq)
{
	struct release_ip_one_state *substate = tevent_req_callback_data(
		subreq, struct release_ip_one_state);
	struct tevent_req *req = substate->req;
	struct release_ip_state *state = tevent_req_data(
		req, struct release_ip_state);
	int ret, i;
	int *err_list;
	bool status, found_errors;

	status = ctdb_client_control_multi_recv(subreq, &ret, state,
						&err_list, NULL);
	TALLOC_FREE(subreq);

	if (status) {
		D_INFO("RELEASE_IP %s succeeded on %d nodes\n",
		       substate->ip_str, substate->count);
		goto done;
	}

	/* Get some clear error messages out of err_list and count
	 * banning credits
	 */
	found_errors = false;
	for (i = 0; i < substate->count; i++) {
		int err = err_list[i];
		if (err != 0) {
			uint32_t pnn = substate->pnns[i];

			D_ERR("RELEASE_IP %s failed on node %u, "
			      "ret=%d\n", substate->ip_str, pnn, err);

			state->ban_credits[pnn]++;
			state->err_any = err;
			found_errors = true;
		}
	}
	if (! found_errors) {
		D_ERR("RELEASE_IP %s internal error, ret=%d\n",
		      substate->ip_str, ret);
		state->err_any = EIO;
	}

	state->num_fails++;

done:
	talloc_free(substate);

	state->num_replies++;

	if (state->num_replies < state->num_sent) {
		/* Not all replies received, don't go further */
		return;
	}

	if (state->num_fails > 0) {
		tevent_req_error(req, state->err_any);
		return;
	}

	tevent_req_done(req);
}

static bool release_ip_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/**********************************************************************/

struct take_ip_state {
	int num_sent;
	int num_replies;
	int num_fails;
	int err_any;
	uint32_t *ban_credits;
};

struct take_ip_one_state {
	struct tevent_req *req;
	uint32_t pnn;
	const char *ip_str;
};

static void take_ip_done(struct tevent_req *subreq);

static struct tevent_req *take_ip_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       struct timeval timeout,
				       struct public_ip_list *all_ips,
				       uint32_t *ban_credits)
{
	struct tevent_req *req, *subreq;
	struct take_ip_state *state;
	struct ctdb_req_control request;
	struct public_ip_list *tmp_ip;

	req = tevent_req_create(mem_ctx, &state, struct take_ip_state);
	if (req == NULL) {
		return NULL;
	}

	state->num_sent = 0;
	state->num_replies = 0;
	state->num_fails = 0;
	state->ban_credits = ban_credits;

	/* For each IP, send a TAKOVER_IP to the node that should be
	 * hosting it.  Many of these will often be redundant (since
	 * the allocation won't have changed) but they can be useful
	 * to recover from inconsistencies. */
	for (tmp_ip = all_ips; tmp_ip != NULL; tmp_ip = tmp_ip->next) {
		struct take_ip_one_state *substate;
		struct ctdb_public_ip ip;

		if (tmp_ip->pnn == CTDB_UNKNOWN_PNN) {
			/* IP will be unassigned */
			continue;
		}

		substate = talloc_zero(state, struct take_ip_one_state);
		if (tevent_req_nomem(substate, req)) {
			return tevent_req_post(req, ev);
		}

		substate->req = req;
		substate->pnn = tmp_ip->pnn;

		substate->ip_str  = ctdb_sock_addr_to_string(substate,
							     &tmp_ip->addr,
							     false);
		if (tevent_req_nomem(substate->ip_str, req)) {
			return tevent_req_post(req, ev);
		}

		ip.pnn = tmp_ip->pnn;
		ip.addr = tmp_ip->addr;
		ctdb_req_control_takeover_ip(&request, &ip);
		subreq = ctdb_client_control_send(
					state, ev, client, tmp_ip->pnn,
					timeout, /* cumulative */
					&request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, take_ip_done, substate);

		state->num_sent++;
	}

	/* None sent, finished... */
	if (state->num_sent == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void take_ip_done(struct tevent_req *subreq)
{
	struct take_ip_one_state *substate = tevent_req_callback_data(
		subreq, struct take_ip_one_state);
	struct tevent_req *req = substate->req;
	struct ctdb_reply_control *reply;
	struct take_ip_state *state = tevent_req_data(
		req, struct take_ip_state);
	int ret = 0;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);

	if (! status) {
		D_ERR("TAKEOVER_IP %s failed to node %u, ret=%d\n",
		      substate->ip_str, substate->pnn, ret);
		goto fail;
	}

	ret = ctdb_reply_control_takeover_ip(reply);
	if (ret != 0) {
		D_ERR("TAKEOVER_IP %s failed on node %u, ret=%d\n",
		      substate->ip_str, substate->pnn, ret);
		goto fail;
	}

	D_INFO("TAKEOVER_IP %s succeeded on node %u\n",
	       substate->ip_str, substate->pnn);
	goto done;

fail:
	state->ban_credits[substate->pnn]++;
	state->num_fails++;
	state->err_any = ret;

done:
	talloc_free(substate);

	state->num_replies++;

	if (state->num_replies < state->num_sent) {
		/* Not all replies received, don't go further */
		return;
	}

	if (state->num_fails > 0) {
		tevent_req_error(req, state->err_any);
		return;
	}

	tevent_req_done(req);
}

static bool take_ip_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/**********************************************************************/

struct ipreallocated_state {
	uint32_t *pnns;
	int count;
	uint32_t *ban_credits;
};

static void ipreallocated_done(struct tevent_req *subreq);

static struct tevent_req *ipreallocated_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct ctdb_client_context *client,
					     uint32_t *pnns,
					     int count,
					     struct timeval timeout,
					     uint32_t *ban_credits)
{
	struct tevent_req *req, *subreq;
	struct ipreallocated_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct ipreallocated_state);
	if (req == NULL) {
		return NULL;
	}

	state->pnns = pnns;
	state->count = count;
	state->ban_credits = ban_credits;

	ctdb_req_control_ipreallocated(&request);
	subreq = ctdb_client_control_multi_send(state, ev, client,
						pnns, count,
						timeout, /* cumulative */
						&request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ipreallocated_done, req);

	return req;
}

static void ipreallocated_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ipreallocated_state *state = tevent_req_data(
		req, struct ipreallocated_state);
	int *err_list = NULL;
	int ret, i;
	bool status, found_errors;

	status = ctdb_client_control_multi_recv(subreq, &ret, state,
						&err_list, NULL);
	TALLOC_FREE(subreq);

	if (status) {
		D_INFO("IPREALLOCATED succeeded on %d nodes\n", state->count);
		tevent_req_done(req);
		return;
	}

	/* Get some clear error messages out of err_list and count
	 * banning credits
	 */
	found_errors = false;
	for (i = 0; i < state->count; i++) {
		int err = err_list[i];
		if (err != 0) {
			uint32_t pnn = state->pnns[i];

			D_ERR("IPREALLOCATED failed on node %u, ret=%d\n",
			      pnn, err);

			state->ban_credits[pnn]++;
			found_errors = true;
		}
	}

	if (! found_errors) {
		D_ERR("IPREALLOCATED internal error, ret=%d\n", ret);
	}

	tevent_req_error(req, ret);
}

static bool ipreallocated_recv(struct tevent_req *req, int *perr)
{
	return generic_recv(req, perr);
}

/**********************************************************************/

/*
 * Recalculate the allocation of public IPs to nodes and have the
 * nodes host their allocated addresses.
 *
 * - Get tunables
 * - Get nodemap
 * - Initialise IP allocation state.  Pass:
 *   + algorithm to be used;
 *   + various tunables (NoIPTakeover, NoIPFailback)
 *   + list of nodes to force rebalance (internal structure, currently
 *     no way to fetch, only used by LCP2 for nodes that have had new
 *     IP addresses added).
 * - Set IP flags for IP allocation based on node map
 * - Retrieve known and available IP addresses (done separately so
 *   values can be faked in unit testing)
 * - Use ipalloc_set_public_ips() to set known and available IP
 *   addresses for allocation
 * - If cluster can't host IP addresses then jump to IPREALLOCATED
 * - Run IP allocation algorithm
 * - Send RELEASE_IP to all nodes for IPs they should not host
 * - Send TAKE_IP to all nodes for IPs they should host
 * - Send IPREALLOCATED to all nodes
 */

struct takeover_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct timeval timeout;
	unsigned int num_nodes;
	uint32_t *pnns_connected;
	int num_connected;
	uint32_t *pnns_active;
	int num_active;
	uint32_t destnode;
	uint32_t *force_rebalance_nodes;
	struct ctdb_tunable_list *tun_list;
	struct ipalloc_state *ipalloc_state;
	struct ctdb_public_ip_list *known_ips;
	struct public_ip_list *all_ips;
	uint32_t *ban_credits;
};

static void takeover_tunables_done(struct tevent_req *subreq);
static void takeover_nodemap_done(struct tevent_req *subreq);
static void takeover_known_ips_done(struct tevent_req *subreq);
static void takeover_avail_ips_done(struct tevent_req *subreq);
static void takeover_release_ip_done(struct tevent_req *subreq);
static void takeover_take_ip_done(struct tevent_req *subreq);
static void takeover_ipreallocated(struct tevent_req *req);
static void takeover_ipreallocated_done(struct tevent_req *subreq);
static void takeover_failed(struct tevent_req *subreq, int ret);
static void takeover_failed_done(struct tevent_req *subreq);

static struct tevent_req *takeover_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint32_t *force_rebalance_nodes)
{
	struct tevent_req *req, *subreq;
	struct takeover_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state, struct takeover_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->force_rebalance_nodes = force_rebalance_nodes;
	state->destnode = ctdb_client_pnn(client);

	ctdb_req_control_get_all_tunables(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, takeover_tunables_done, req);

	return req;
}

static void takeover_tunables_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	struct ctdb_reply_control *reply;
	struct ctdb_req_control request;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_all_tunables(reply, state,
						  &state->tun_list);
	if (ret != 0) {
		D_ERR("control GET_ALL_TUNABLES failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(reply);

	takeover_timeout = state->tun_list->takeover_timeout;

	ctdb_req_control_get_nodemap(&request);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  state->destnode, TIMEOUT(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, takeover_nodemap_done, req);
}

static void takeover_nodemap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret;
	struct ctdb_node_map *nodemap;
	const char *ptr;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("control GET_NODEMAP failed to node %u, ret=%d\n",
			state->destnode, ret);
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_get_nodemap(reply, state, &nodemap);
	if (ret != 0) {
		D_ERR("control GET_NODEMAP failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	state->num_nodes = nodemap->num;

	state->num_connected = list_of_connected_nodes(nodemap,
						       CTDB_UNKNOWN_PNN, state,
						       &state->pnns_connected);
	if (state->num_connected <= 0) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	state->num_active = list_of_active_nodes(nodemap,
						 CTDB_UNKNOWN_PNN, state,
						 &state->pnns_active);
	if (state->num_active <= 0) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	/* Default timeout for early jump to IPREALLOCATED.  See below
	 * for explanation of 3 times...
	 */
	state->timeout = timeval_current_ofs(3 * takeover_timeout, 0);

	state->ban_credits = talloc_zero_array(state, uint32_t,
					       state->num_nodes);
	if (tevent_req_nomem(state->ban_credits, req)) {
		return;
	}

	ptr = getenv("CTDB_DISABLE_IP_FAILOVER");
	if (ptr != NULL) {
		/* IP failover is completely disabled so just send out
		 * ipreallocated event.
		 */
		takeover_ipreallocated(req);
		return;
	}

	state->ipalloc_state =
		ipalloc_state_init(
			state, state->num_nodes,
			determine_algorithm(state->tun_list),
			(state->tun_list->no_ip_takeover != 0),
			(state->tun_list->no_ip_failback != 0),
			state->force_rebalance_nodes);
	if (tevent_req_nomem(state->ipalloc_state, req)) {
		return;
	}

	subreq = get_public_ips_send(state, state->ev, state->client,
				     state->pnns_connected, state->num_connected,
				     state->num_nodes, state->ban_credits,
				     false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, takeover_known_ips_done, req);
}

static void takeover_known_ips_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	int ret;
	bool status;
	uint32_t *pnns = NULL;
	int count, i;

	status = get_public_ips_recv(subreq, &ret, state, &state->known_ips);
	TALLOC_FREE(subreq);

	if (! status) {
		D_ERR("Failed to fetch known public IPs\n");
		takeover_failed(req, ret);
		return;
	}

	/* Get available IPs from active nodes that actually have known IPs */

	pnns = talloc_zero_array(state, uint32_t, state->num_active);
	if (tevent_req_nomem(pnns, req)) {
		return;
	}

	count = 0;
	for (i = 0; i < state->num_active; i++) {
		uint32_t pnn = state->pnns_active[i];

		/* If pnn has IPs then fetch available IPs from it */
		if (state->known_ips[pnn].num > 0) {
			pnns[count] = pnn;
			count++;
		}
	}

	subreq = get_public_ips_send(state, state->ev, state->client,
				     pnns, count,
				     state->num_nodes, state->ban_credits,
				     true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, takeover_avail_ips_done, req);
}

static void takeover_avail_ips_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	bool status;
	int ret;
	struct ctdb_public_ip_list *available_ips;

	status = get_public_ips_recv(subreq, &ret, state, &available_ips);
	TALLOC_FREE(subreq);

	if (! status) {
		D_ERR("Failed to fetch available public IPs\n");
		takeover_failed(req, ret);
		return;
	}

	ipalloc_set_public_ips(state->ipalloc_state,
			       state->known_ips, available_ips);

	if (! ipalloc_can_host_ips(state->ipalloc_state)) {
		D_NOTICE("No nodes available to host public IPs yet\n");
		takeover_ipreallocated(req);
		return;
	}

	/* Do the IP reassignment calculations */
	state->all_ips = ipalloc(state->ipalloc_state);
	if (tevent_req_nomem(state->all_ips, req)) {
		return;
	}

	/* Each of the following stages (RELEASE_IP, TAKEOVER_IP,
	 * IPREALLOCATED) notionally has a timeout of TakeoverTimeout
	 * seconds.  However, RELEASE_IP can take longer due to TCP
	 * connection killing, so sometimes needs more time.
	 * Therefore, use a cumulative timeout of TakeoverTimeout * 3
	 * seconds across all 3 stages.  No explicit expiry checks are
	 * needed before each stage because tevent is smart enough to
	 * fire the timeouts even if they are in the past.  Initialise
	 * this here so it explicitly covers the stages we're
	 * interested in but, in particular, not the time taken by the
	 * ipalloc().
	 */
	state->timeout = timeval_current_ofs(3 * takeover_timeout, 0);

	subreq = release_ip_send(state, state->ev, state->client,
				 state->pnns_connected, state->num_connected,
				 state->timeout, state->all_ips,
				 state->ban_credits);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, takeover_release_ip_done, req);
}

static void takeover_release_ip_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	int ret;
	bool status;

	status = release_ip_recv(subreq, &ret);
	TALLOC_FREE(subreq);

	if (! status) {
		takeover_failed(req, ret);
		return;
	}

	/* All released, now for takeovers */

	subreq = take_ip_send(state, state->ev, state->client,
			      state->timeout, state->all_ips,
			      state->ban_credits);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, takeover_take_ip_done, req);
}

static void takeover_take_ip_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret = 0;
	bool status;

	status = take_ip_recv(subreq, &ret);
	TALLOC_FREE(subreq);

	if (! status) {
		takeover_failed(req, ret);
		return;
	}

	takeover_ipreallocated(req);
}

static void takeover_ipreallocated(struct tevent_req *req)
{
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	struct tevent_req *subreq;

	subreq = ipreallocated_send(state, state->ev, state->client,
				    state->pnns_connected,
				    state->num_connected,
				    state->timeout,
				    state->ban_credits);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, takeover_ipreallocated_done, req);
}

static void takeover_ipreallocated_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = ipreallocated_recv(subreq, &ret);
	TALLOC_FREE(subreq);

	if (! status) {
		takeover_failed(req, ret);
		return;
	}

	tevent_req_done(req);
}

struct takeover_failed_state {
	struct tevent_req *req;
	int ret;
};

void takeover_failed(struct tevent_req *req, int ret)
{
	struct takeover_state *state = tevent_req_data(
		req, struct takeover_state);
	struct tevent_req *subreq;
	uint32_t max_pnn = CTDB_UNKNOWN_PNN;
	unsigned int max_credits = 0;
	uint32_t pnn;

	/* Check that bans are enabled */
	if (state->tun_list->enable_bans == 0) {
		tevent_req_error(req, ret);
		return;
	}

	for (pnn = 0; pnn < state->num_nodes; pnn++) {
		if (state->ban_credits[pnn] > max_credits) {
			max_pnn = pnn;
			max_credits = state->ban_credits[pnn];
		}
	}

	if (max_credits > 0) {
		struct ctdb_req_message message;
		struct takeover_failed_state *substate;

		D_WARNING("Assigning banning credits to node %u\n", max_pnn);

		substate = talloc_zero(state, struct takeover_failed_state);
		if (tevent_req_nomem(substate, req)) {
			return;
		}
		substate->req = req;
		substate->ret = ret;

		message.srvid = CTDB_SRVID_BANNING;
		message.data.pnn = max_pnn;

		subreq = ctdb_client_message_send(
			state, state->ev, state->client,
			ctdb_client_pnn(state->client),
			&message);
		if (subreq == NULL) {
			D_ERR("failed to assign banning credits\n");
			tevent_req_error(req, ret);
			return;
		}
		tevent_req_set_callback(subreq, takeover_failed_done, substate);
	} else {
		tevent_req_error(req, ret);
	}
}

static void takeover_failed_done(struct tevent_req *subreq)
{
	struct takeover_failed_state *substate = tevent_req_callback_data(
		subreq, struct takeover_failed_state);
	struct tevent_req *req = substate->req;
	int ret;
	bool status;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("failed to assign banning credits, ret=%d\n", ret);
	}

	ret = substate->ret;
	talloc_free(substate);
	tevent_req_error(req, ret);
}

static void takeover_recv(struct tevent_req *req, int *perr)
{
	generic_recv(req, perr);
}

static uint32_t *parse_node_list(TALLOC_CTX *mem_ctx, const char* s)
{
	char *strv = NULL;
	int num, i, ret;
	char *t;
	uint32_t *nodes;

	ret = strv_split(mem_ctx, &strv, s, ",");
	if (ret != 0) {
		D_ERR("out of memory\n");
		return NULL;
	}

	num = strv_count(strv);

	nodes = talloc_array(mem_ctx, uint32_t, num);
	if (nodes == NULL) {
		D_ERR("out of memory\n");
		return NULL;
	}

	t = NULL;
	for (i = 0; i < num; i++) {
		t = strv_next(strv, t);
		nodes[i] = atoi(t);
	}

	return nodes;
}

static void usage(const char *progname)
{
	fprintf(stderr,
		"\nUsage: %s <output-fd> <ctdb-socket-path> "
		"[<force-rebalance-nodes>]\n",
		progname);
}

/*
 * Arguments - write fd, socket path
 */
int main(int argc, const char *argv[])
{
	int write_fd;
	const char *sockpath;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	int ret;
	struct tevent_req *req;
	uint32_t *force_rebalance_nodes = NULL;

	if (argc < 3 || argc > 4) {
		usage(argv[0]);
		exit(1);
	}

	write_fd = atoi(argv[1]);
	sockpath = argv[2];

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_new() failed\n");
		ret = ENOMEM;
		goto done;
	}

	if (argc == 4) {
		force_rebalance_nodes = parse_node_list(mem_ctx, argv[3]);
		if (force_rebalance_nodes == NULL) {
			usage(argv[0]);
			ret = EINVAL;
			goto done;
		}
	}

	ret = logging_init(mem_ctx, NULL, NULL, "ctdb-takeover");
	if (ret != 0) {
		fprintf(stderr,
			"ctdb-takeover: Unable to initialize logging\n");
		goto done;
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		D_ERR("tevent_context_init() failed\n");
		ret = ENOMEM;
		goto done;
	}

	ret = ctdb_client_init(mem_ctx, ev, sockpath, &client);
	if (ret != 0) {
		D_ERR("ctdb_client_init() failed, ret=%d\n", ret);
		goto done;
	}

	req = takeover_send(mem_ctx, ev, client, force_rebalance_nodes);
	if (req == NULL) {
		D_ERR("takeover_send() failed\n");
		ret = 1;
		goto done;
	}

	if (! tevent_req_poll(req, ev)) {
		D_ERR("tevent_req_poll() failed\n");
		ret = 1;
		goto done;
	}

	takeover_recv(req, &ret);
	TALLOC_FREE(req);
	if (ret != 0) {
		D_ERR("takeover run failed, ret=%d\n", ret);
	}

done:
	sys_write_v(write_fd, &ret, sizeof(ret));

	talloc_free(mem_ctx);
	return ret;
}

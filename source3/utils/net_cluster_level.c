/*
 * Samba Unix/Linux SMB client library
 * Interface to the cluster functional level
 * Copyright (C) Stefan Metzmacher 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "net.h"
#include "lib/cluster_support.h"
#include "librpc/gen_ndr/ndr_cluster_level.h"
#ifdef CLUSTER_SUPPORT
#include "ctdb/protocol/protocol.h"
#include "ctdbd_conn.h"
#include "messages.h"
#include "messages_ctdb.h"
#include "lib/cluster_level_db.h"
#endif /* CLUSTER_SUPPORT */

static int net_cluster_level_features(struct net_context *c,
				      int argc,
				      const char **argv)
{
	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel features\n");
		return -1;
	}

	if (c->opt_json) {
		d_printf("--json not supported yet!\n");
		return -1;
	}

	d_printf("%s", cluster_support_features());
	return 0;
}

static int net_cluster_level_show(struct net_context *c,
				  int argc,
				  const char **argv)
{
#ifdef CLUSTER_SUPPORT
	struct ctdbd_connection *ctdb_conn = NULL;
	const struct cluster_level_active *active_level = NULL;

	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel show\n");
		return -1;
	}

	if (!lp_clustering()) {
		goto nocluster;
	}

	if (c->msg_ctx == NULL) {
		d_printf("'net clusterlevel show' needs to run as root.\n");
		return -1;
	}

	if (c->opt_json) {
		d_printf("--json not supported yet!\n");
		return -1;
	}

	ctdb_conn = messaging_ctdb_connection();
	if (ctdb_conn == NULL) {
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	active_level = ctdbd_conn_get_cluster_level(ctdb_conn);
	if (active_level == NULL) {
		d_printf("Unable to get active cluster functional level.\n");
		return -1;
	}

	d_printf("Active cluster functional level: %"PRIu32".%"PRIu32"\n",
		 active_level->major,
		 active_level->minor);

	return 0;
nocluster:
#endif /* CLUSTER_SUPPORT */
	d_printf("'net clusterlevel show' needs to run on a cluster.\n");
	return -1;
}

#ifdef CLUSTER_SUPPORT
struct net_cluster_level_showall_state {
	struct ctdbd_connection *ctdb_conn;
	const struct cluster_level_active *active_level;
	uint32_t total_nodes_count;
	uint32_t total_highest_count;
	struct cluster_level_active highest_level;
};

static NTSTATUS net_cluster_level_showall_cb(
		uint32_t total_nodes_count,
		const struct cluster_level_db_nodes_foreach_node *node,
		void *private_data)
{
	struct net_cluster_level_showall_state *state =
		(struct net_cluster_level_showall_state *)private_data;
	uint32_t i;

	SMB_ASSERT(node->nf != NULL);
	SMB_ASSERT(node->supported_ranges != NULL);

	if (state->total_nodes_count == 0) {
		state->total_nodes_count = total_nodes_count;
	} else {
		SMB_ASSERT(state->total_nodes_count == total_nodes_count);
	}

	d_printf("Node[%"PRIu32"] supported_ranges[%"PRIu32"]\n",
		 node->nf->pnn, node->supported_ranges->num_ranges);

	for (i = 0; i < node->supported_ranges->num_ranges; i++) {
		const struct cluster_level_range *range =
			&node->supported_ranges->ranges[i];

		d_printf("    supported_range: "
			 "%"PRIu32".%"PRIu32" -> %"PRIu32".%"PRIu32"\n",
			 range->major, range->minor_min,
			 range->major, range->minor_max);
	}

	if (node->supported_ranges->num_ranges > 0) {
		const struct cluster_level_range *range =
			&node->supported_ranges->ranges[0];
		bool reset_highest = false;

		if (range->major > state->highest_level.major) {
			reset_highest = true;
		}
		if (range->major == state->highest_level.major &&
		    range->minor_max > state->highest_level.minor)
		{
			reset_highest = true;
		}

		if (reset_highest) {
			state->highest_level.major = range->major;
			state->highest_level.minor = range->minor_max;
			state->total_highest_count = 0;
		}

		if (range->major == state->highest_level.major &&
		    range->minor_max == state->highest_level.minor)
		{
			state->total_highest_count += 1;
		}
	}

	return NT_STATUS_OK;
}
#endif /* CLUSTER_SUPPORT */

static int net_cluster_level_showall(struct net_context *c,
				     int argc,
				     const char **argv)
{
#ifdef CLUSTER_SUPPORT
	struct net_cluster_level_showall_state state = {
		.active_level = NULL,
	};
	NTSTATUS status;
	bool upgrade = false;

	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel showall\n");
		return -1;
	}

	if (!lp_clustering()) {
		goto nocluster;
	}

	if (c->msg_ctx == NULL) {
		d_printf("'net clusterlevel showall' needs to run as root.\n");
		return -1;
	}

	if (c->opt_json) {
		d_printf("--json not supported yet!\n");
		return -1;
	}

	state.ctdb_conn = messaging_ctdb_connection();
	if (state.ctdb_conn == NULL) {
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	state.active_level = ctdbd_conn_get_cluster_level(state.ctdb_conn);
	if (state.active_level == NULL) {
		d_printf("Unable to get active cluster functional level.\n");
		return -1;
	}

	status = cluster_level_db_nodes_foreach(state.ctdb_conn,
						net_cluster_level_showall_cb,
						&state);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Unable to iterate nodes - %s.\n", nt_errstr(status));
		return -1;
	}

	d_printf("Active cluster functional level: %"PRIu32".%"PRIu32"\n",
		 state.active_level->major,
		 state.active_level->minor);

	if (state.highest_level.major > state.active_level->major) {
		upgrade = true;
	}
	if (state.highest_level.major == state.active_level->major &&
	    state.highest_level.minor > state.active_level->minor)
	{
		upgrade = true;
	}

	if (upgrade && state.total_highest_count == state.total_nodes_count) {
		d_printf("Upgrade possible to cluster functional level: "
			 "%"PRIu32".%"PRIu32"\n",
			 state.highest_level.major,
			 state.highest_level.minor);
	} else if (upgrade) {
		d_printf("Highest supported cluster functional level: "
			 "%"PRIu32".%"PRIu32"\n",
			 state.highest_level.major,
			 state.highest_level.minor);
	}

	return 0;
nocluster:
#endif /* CLUSTER_SUPPORT */
	d_printf("'net clusterlevel showall' needs to run on a cluster.\n");
	return -1;
}

static int net_cluster_level_upgrade(struct net_context *c,
				     int argc,
				     const char **argv)
{
#ifdef CLUSTER_SUPPORT
	struct ctdbd_connection *ctdb_conn;
	struct cluster_level_db_upgrade_req req = {
		.in = {
			.dry_run = true,
		}
	};
	NTSTATUS expected_status;
	NTSTATUS status;

	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel upgrade "
			 "[--test] [--apply]\n");
		return -1;
	}

	if (c->opt_testmode != 0 && c->opt_apply != 0) {
		d_printf("Usage: net clusterlevel upgrade "
			 "[--test] [--apply]\n");
		d_printf("Only one of --test or --apply is allowed!\n");
		return -1;
	} else if (c->opt_apply != 0) {
		req.in.dry_run = false;
		expected_status = NT_STATUS_OK;
	} else { /* --test is also the default */
		req.in.dry_run = true;
		expected_status = NT_STATUS_NOT_COMMITTED;
	}

	if (!lp_clustering()) {
		goto nocluster;
	}

	if (c->msg_ctx == NULL) {
		d_printf("'net clusterlevel upgrade' needs to run as root.\n");
		return -1;
	}

	if (c->opt_json) {
		d_printf("--json not supported yet!\n");
		return -1;
	}

	ctdb_conn = messaging_ctdb_connection();
	if (ctdb_conn == NULL) {
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	status = cluster_level_db_upgrade(ctdb_conn, c->msg_ctx, &req);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ALREADY_COMMITTED)) {
		d_printf("Already at active cluster functional level: "
			 "%"PRIu32".%"PRIu32"\n",
			 req.out.old_level.major,
			 req.out.old_level.minor);
		return -1;
	}
	if (!NT_STATUS_EQUAL(status, expected_status)) {
		d_printf("Unable to upgrade - error_vnn=%"PRIu32" %s.\n",
			 req.out.error_vnn, nt_errstr(status));
		return -1;
	}

	d_printf("%s from cluster functional level "
		 "%"PRIu32".%"PRIu32" to %"PRIu32".%"PRIu32"\n",
		 req.in.dry_run ? "Upgrade possible" : "Upgraded",
		 req.out.old_level.major, req.out.old_level.minor,
		 req.out.new_level.major, req.out.new_level.minor);
	if (req.in.dry_run) {
		d_printf("Use 'net clusterlevel upgrade --apply' "
			 "to perform the upgrade.\n");
	}

	return 0;
nocluster:
#endif /* CLUSTER_SUPPORT */
	d_printf("'net clusterlevel upgrade' needs to run on a cluster.\n");
	return -1;
}

int net_cluster_level(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"features",
			net_cluster_level_features,
			NET_TRANSPORT_LOCAL,
			N_("List the supported build features"),
			N_("net clusterlevel features\n")
		},
		{
			"show",
			net_cluster_level_show,
			NET_TRANSPORT_LOCAL,
			N_("Show the currently active cluster functional level"),
			N_("net clusterlevel show\n")
		},
		{
			"showall",
			net_cluster_level_showall,
			NET_TRANSPORT_LOCAL,
			N_("Show details about the whole cluster"),
			N_("net clusterlevel showall\n")
		},
		{
			"upgrade",
			net_cluster_level_upgrade,
			NET_TRANSPORT_LOCAL,
			N_("Upgrade the cluster functional level "
			   "to the highest supported level."),
			N_("net clusterlevel upgrade [--test] [--apply]\n")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net clusterlevel", func);
}

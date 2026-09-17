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

#ifdef HAVE_JANSSON
#include "lib/util/tjson.h"
#endif			   /* HAVE_JANSSON */

static int net_cluster_level_features(struct net_context *c,
				      int argc,
				      const char **argv)
{
	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel features [--json]\n");
		return -1;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_CTX *frame = talloc_stackframe();
		const struct cluster_level_ranges
			*ranges = cluster_level_supported_ranges();
		struct tjson *result = tjson_new_object(frame);
		struct tjson *ranges_arr = tjson_new_array(frame);
		char *json_str = NULL;
		uint32_t i;

		tjson_add_bool(result,
			       "cluster_support",
			       cluster_support_available());
#ifdef CTDB_SOCKET
		tjson_add_string(result, "ctdb_socket", CTDB_SOCKET);
#endif /* CTDB_SOCKET */
#ifdef CTDB_PROTOCOL
		tjson_add_int(result, "ctdb_protocol", CTDB_PROTOCOL);
#endif /* CTDB_PROTOCOL */

		for (i = 0; i < ranges->num_ranges; i++) {
			const struct cluster_level_range
				*range = &ranges->ranges[i];
			struct tjson *r = tjson_new_object(frame);

			tjson_add_int(r, "major", range->major);
			tjson_add_int(r, "minor_min", range->minor_min);
			tjson_add_int(r, "minor_max", range->minor_max);
			tjson_add_object(ranges_arr, NULL, &r);
		}

		tjson_add_object(result, "supported_ranges", &ranges_arr);

		json_str = tjson_to_string(frame, result);
		if (json_str == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
		d_printf("%s\n", json_str);
		TALLOC_FREE(frame);
		return 0;
	}
#else  /* HAVE_JANSSON */
	if (c->opt_json) {
		d_fprintf(stderr, "JSON support not available\n");
		return -1;
	}
#endif /* HAVE_JANSSON */

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
		d_printf("Usage: net clusterlevel show [--json]\n");
		return -1;
	}

	if (!lp_clustering()) {
		goto nocluster;
	}

	if (c->msg_ctx == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"'net clusterlevel show' needs "
				 "to run as root.\"}\n");
			return -1;
		}
#endif
		d_printf("'net clusterlevel show' needs to run as root.\n");
		return -1;
	}

	ctdb_conn = messaging_ctdb_connection();
	if (ctdb_conn == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"Unable to connect to local "
				 "ctdbd.\"}\n");
			return -1;
		}
#endif
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	active_level = ctdbd_conn_get_cluster_level(ctdb_conn);
	if (active_level == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"Unable to get active cluster "
				 "functional level.\"}\n");
			return -1;
		}
#endif
		d_printf("Unable to get active cluster functional level.\n");
		return -1;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_CTX *frame = talloc_stackframe();
		struct tjson *result = tjson_new_object(frame);
		struct tjson *active_obj = tjson_new_object(frame);
		char *json_str = NULL;

		tjson_add_int(active_obj, "major", active_level->major);
		tjson_add_int(active_obj, "minor", active_level->minor);
		tjson_add_object(result, "active_level", &active_obj);

		json_str = tjson_to_string(frame, result);
		if (json_str == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
		d_printf("%s\n", json_str);
		TALLOC_FREE(frame);
		return 0;
	}
#else  /* HAVE_JANSSON */
	if (c->opt_json) {
		d_fprintf(stderr, "JSON support not available\n");
		return -1;
	}
#endif /* HAVE_JANSSON */

	d_printf("Active cluster functional level: %"PRIu32".%"PRIu32"\n",
		 active_level->major,
		 active_level->minor);

	return 0;
nocluster:
#endif /* CLUSTER_SUPPORT */
#ifdef HAVE_JANSSON
	if (c->opt_json) {
		d_printf("{\"error\":\"'net clusterlevel show' needs "
			 "to run on a cluster.\"}\n");
		return -1;
	}
#endif
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
#ifdef HAVE_JANSSON
	struct tjson *nodes_json;
#endif			    /* HAVE_JANSSON */
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

#ifdef HAVE_JANSSON
	if (state->nodes_json != NULL) {
		TALLOC_CTX *frame = talloc_stackframe();
		struct tjson *node_obj = tjson_new_object(frame);
		struct tjson *ranges_arr = tjson_new_array(frame);

		tjson_add_int(node_obj, "pnn", node->nf->pnn);

		for (i = 0; i < node->supported_ranges->num_ranges; i++) {
			const struct cluster_level_range
				*range = &node->supported_ranges->ranges[i];
			struct tjson *range_obj = tjson_new_object(frame);

			tjson_add_int(range_obj, "major", range->major);
			tjson_add_int(range_obj,
				      "minor_min",
				      range->minor_min);
			tjson_add_int(range_obj,
				      "minor_max",
				      range->minor_max);
			tjson_add_object(ranges_arr, NULL, &range_obj);
		}

		tjson_add_object(node_obj, "supported_ranges", &ranges_arr);
		tjson_add_object(state->nodes_json, NULL, &node_obj);

		TALLOC_FREE(frame);

		if (tjson_has_error(state->nodes_json)) {
			return NT_STATUS_NO_MEMORY;
		}

		goto update_highest;
	}
#endif /* HAVE_JANSSON */

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

#ifdef HAVE_JANSSON
update_highest:
#endif /* HAVE_JANSSON */
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
#ifdef HAVE_JANSSON
	TALLOC_CTX *frame = NULL;
#endif /* HAVE_JANSSON */
	NTSTATUS status;
	bool upgrade = false;

	if (c->display_usage || argc != 0) {
		d_printf("Usage: net clusterlevel showall [--json]\n");
		return -1;
	}

	if (!lp_clustering()) {
		goto nocluster;
	}

	if (c->msg_ctx == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"'net clusterlevel showall' "
				 "needs to run as root.\"}\n");
			return -1;
		}
#endif
		d_printf("'net clusterlevel showall' needs to run as root.\n");
		return -1;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		frame = talloc_stackframe();
		state.nodes_json = tjson_new_array(frame);
		if (state.nodes_json == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
	}
#else  /* HAVE_JANSSON */
	if (c->opt_json) {
		d_fprintf(stderr, "JSON support not available\n");
		return -1;
	}
#endif /* HAVE_JANSSON */

	state.ctdb_conn = messaging_ctdb_connection();
	if (state.ctdb_conn == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			TALLOC_FREE(frame);
			d_printf("{\"error\":\"Unable to connect to local "
				 "ctdbd.\"}\n");
			return -1;
		}
#endif
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	state.active_level = ctdbd_conn_get_cluster_level(state.ctdb_conn);
	if (state.active_level == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			TALLOC_FREE(frame);
			d_printf("{\"error\":\"Unable to get active cluster "
				 "functional level.\"}\n");
			return -1;
		}
#endif
		d_printf("Unable to get active cluster functional level.\n");
		return -1;
	}

	status = cluster_level_db_nodes_foreach(state.ctdb_conn,
						net_cluster_level_showall_cb,
						&state);
	if (!NT_STATUS_IS_OK(status)) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			TALLOC_FREE(frame);
			d_printf("{\"error\":\"Unable to iterate nodes - "
				 "%s.\"}\n",
				 nt_errstr(status));
			return -1;
		}
#endif
		d_printf("Unable to iterate nodes - %s.\n", nt_errstr(status));
		return -1;
	}

	if (state.highest_level.major > state.active_level->major) {
		upgrade = true;
	}
	if (state.highest_level.major == state.active_level->major &&
	    state.highest_level.minor > state.active_level->minor)
	{
		upgrade = true;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		struct tjson *result = tjson_new_object(frame);
		struct tjson *active_obj = tjson_new_object(frame);
		bool upgrade_possible = upgrade &&
					(state.total_highest_count ==
					 state.total_nodes_count);
		char *json_str = NULL;

		tjson_add_int(active_obj, "major", state.active_level->major);
		tjson_add_int(active_obj, "minor", state.active_level->minor);
		tjson_add_object(result, "active_level", &active_obj);
		tjson_add_object(result, "nodes", &state.nodes_json);
		tjson_add_bool(result, "upgrade_possible", upgrade_possible);

		if (upgrade) {
			struct tjson *highest_obj = tjson_new_object(frame);

			tjson_add_int(highest_obj,
				      "major",
				      state.highest_level.major);
			tjson_add_int(highest_obj,
				      "minor",
				      state.highest_level.minor);
			tjson_add_object(result,
					 "highest_level",
					 &highest_obj);
		}

		json_str = tjson_to_string(frame, result);
		if (json_str == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
		d_printf("%s\n", json_str);
		TALLOC_FREE(frame);
		return 0;
	}
#endif /* HAVE_JANSSON */

	d_printf("Active cluster functional level: %" PRIu32 ".%" PRIu32 "\n",
		 state.active_level->major,
		 state.active_level->minor);

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
#ifdef HAVE_JANSSON
	if (c->opt_json) {
		d_printf("{\"error\":\"'net clusterlevel showall' needs "
			 "to run on a cluster.\"}\n");
		return -1;
	}
#endif
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
			 "[--test] [--apply] [--json]\n");
		return -1;
	}

	if (c->opt_testmode != 0 && c->opt_apply != 0) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"Only one of --test or "
				 "--apply is allowed.\"}\n");
			return -1;
		}
#endif
		d_printf("Usage: net clusterlevel upgrade "
			 "[--test] [--apply] [--json]\n");
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
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"'net clusterlevel upgrade' "
				 "needs to run as root.\"}\n");
			return -1;
		}
#endif
		d_printf("'net clusterlevel upgrade' needs to run as root.\n");
		return -1;
	}

#ifndef HAVE_JANSSON
	if (c->opt_json) {
		d_fprintf(stderr, "JSON support not available\n");
		return -1;
	}
#endif /* ! HAVE_JANSSON */

	ctdb_conn = messaging_ctdb_connection();
	if (ctdb_conn == NULL) {
#ifdef HAVE_JANSSON
		if (c->opt_json) {
			d_printf("{\"error\":\"Unable to connect to local "
				 "ctdbd.\"}\n");
			return -1;
		}
#endif
		d_printf("Unable to connect to local ctdbd.\n");
		return -1;
	}

	status = cluster_level_db_upgrade(ctdb_conn, c->msg_ctx, &req);

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_CTX *frame = talloc_stackframe();
		struct tjson *result = tjson_new_object(frame);
		const char *status_str = NULL;
		char *json_str = NULL;
		int ret_val;

		if (NT_STATUS_EQUAL(status, NT_STATUS_ALREADY_COMMITTED)) {
			status_str = "already_current";
			ret_val = -1;
		} else if (!NT_STATUS_EQUAL(status, expected_status)) {
			status_str = "error";
			ret_val = -1;
		} else {
			status_str = req.in.dry_run ? "dry_run_ok"
						    : "upgraded";
			ret_val = 0;
		}

		tjson_add_bool(result, "dry_run", req.in.dry_run);
		tjson_add_string(result, "status", status_str);

		if (!NT_STATUS_EQUAL(status, expected_status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_ALREADY_COMMITTED))
		{
			tjson_add_int(result, "error_vnn", req.out.error_vnn);
			tjson_add_string(result,
					 "error_status",
					 nt_errstr(status));
		} else {
			struct tjson *old_obj = tjson_new_object(frame);
			struct tjson *new_obj = tjson_new_object(frame);

			tjson_add_int(old_obj,
				      "major",
				      req.out.old_level.major);
			tjson_add_int(old_obj,
				      "minor",
				      req.out.old_level.minor);
			tjson_add_object(result, "old_level", &old_obj);

			if (!NT_STATUS_EQUAL(status,
					     NT_STATUS_ALREADY_COMMITTED))
			{
				tjson_add_int(new_obj,
					      "major",
					      req.out.new_level.major);
				tjson_add_int(new_obj,
					      "minor",
					      req.out.new_level.minor);
				tjson_add_object(result,
						 "new_level",
						 &new_obj);
			}
		}

		json_str = tjson_to_string(frame, result);
		if (json_str == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
		d_printf("%s\n", json_str);
		TALLOC_FREE(frame);
		return ret_val;
	}
#endif /* HAVE_JANSSON */

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
#ifdef HAVE_JANSSON
	if (c->opt_json) {
		d_printf("{\"error\":\"'net clusterlevel upgrade' needs "
			 "to run on a cluster.\"}\n");
		return -1;
	}
#endif
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
			N_("net clusterlevel features [--json]\n")
		},
		{
			"show",
			net_cluster_level_show,
			NET_TRANSPORT_LOCAL,
			N_("Show the currently active cluster functional level"),
			N_("net clusterlevel show [--json]\n")
		},
		{
			"showall",
			net_cluster_level_showall,
			NET_TRANSPORT_LOCAL,
			N_("Show details about the whole cluster"),
			N_("net clusterlevel showall [--json]\n")
		},
		{
			"upgrade",
			net_cluster_level_upgrade,
			NET_TRANSPORT_LOCAL,
			N_("Upgrade the cluster functional level "
			   "to the highest supported level."),
			N_("net clusterlevel upgrade [--test] [--apply] [--json]\n")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net clusterlevel", func);
}

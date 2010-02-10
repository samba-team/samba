/*
   Unix SMB/CIFS implementation.

   KCC service

   Copyright (C) Crístian Deives 2010

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
#include "dsdb/samdb/samdb.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_misc.h"

#define NTDSTRANSPORT_OPT_IGNORE_SCHEDULES 0x00000001
#define NTDSTRANSPORT_OPT_BRIDGES_REQUIRED 0x00000002

/** replication parameters of a graph edge */
struct kcctpl_repl_info {
	int cost;
	int interval;
	int options;
	uint8_t schedule[84];
};

/** color of a vertex */
enum kcctpl_color { RED, BLACK, WHITE };

/** a GUID array list */
struct GUID_list {
	struct GUID *data;
	unsigned int count;
};

/** a vertex in the site graph */
struct kcctpl_vertex {
	struct GUID id;
	struct GUID_list edge_ids;
	enum kcctpl_color color;
	struct GUID_list accept_red_red;
	struct GUID_list accept_black;
	struct kcctpl_repl_info repl_info;
	int dist_to_red;

	/* Dijkstra data */
	struct GUID root_id;
	bool demoted;

	/* Kruskal data */
	struct GUID component_id;
	int component_index;
};

/** fully connected subgraph of vertices */
struct kcctpl_multi_edge {
	struct GUID id;
	struct GUID_list vertex_ids;
	struct GUID type;
	struct kcctpl_repl_info repl_info;
	bool directed;
};

/** set of transitively connected kcc_multi_edge's. all edges within the set
 * have the same type. */
struct kcctpl_multi_edge_set {
	struct GUID id;
	struct GUID_list edge_ids;
};

/** a vertices array list */
struct kcctpl_vertex_list {
	struct kcctpl_vertex *data;
	unsigned int count;
};

/** an edges linked list */
struct kcctpl_multi_edge_list {
	struct kcctpl_multi_edge *data;
	unsigned int count;
};

/** an edge sets linked list */
struct kcctpl_multi_edge_set_list {
	struct kcctpl_multi_edge_set *data;
	unsigned int count;
};

/** a site graph */
struct kcctpl_graph {
	struct kcctpl_vertex_list vertices;
	struct kcctpl_multi_edge_list edges;
	struct kcctpl_multi_edge_set_list edge_sets;
};

/** path found in the graph between two non-white vertices */
struct kcctpl_internal_edge {
	struct GUID v1id, v2id;
	bool red_red;
	struct kcctpl_repl_info repl_info;
	struct GUID type;
};

/**
 * find a graph edge based on its GUID.
 */
static struct kcctpl_multi_edge *kcctpl_find_edge_by_guid(struct kcctpl_graph *graph,
							  struct GUID guid)
{
	unsigned int i;

	for (i = 0; i < graph->edges.count; i++) {
		if (GUID_compare(&graph->edges.data[i].id, &guid) == 0) {
			return &graph->edges.data[i];
		}
	}
	return NULL;
}
/**
 * create a kcctpl_graph instance.
 */
static NTSTATUS kcctpl_create_graph(TALLOC_CTX *mem_ctx,
				    struct GUID_list *guids,
				    struct kcctpl_graph **_graph)
{
	struct kcctpl_graph *graph;
	unsigned int i;

	graph = talloc_zero(mem_ctx, struct kcctpl_graph);
	NT_STATUS_HAVE_NO_MEMORY(graph);

	graph->vertices.count = guids->count;
	graph->vertices.data = talloc_zero_array(graph, struct kcctpl_vertex,
						 guids->count);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(graph->vertices.data, graph);

	qsort(guids->data, guids->count, sizeof(struct GUID),
	      QSORT_CAST GUID_compare);

	for (i = 0; i < guids->count; i++) {
		graph->vertices.data[i].id = guids->data[i];
	}

	*_graph = graph;
	return NT_STATUS_OK;
}

/**
 * create a kcctpl_multi_edge instance.
 */
static NTSTATUS kcctpl_create_edge(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				   struct GUID type,
				   struct ldb_message *site_link,
				   struct kcctpl_multi_edge **_edge)
{
	struct kcctpl_multi_edge *edge;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	const char * const attrs[] = { "siteList", NULL };
	int ret;
	struct ldb_message_element *el;
	unsigned int i;
	struct ldb_val val;

	edge = talloc(mem_ctx, struct kcctpl_multi_edge);
	NT_STATUS_HAVE_NO_MEMORY(edge);

	edge->id = samdb_result_guid(site_link, "objectGUID");

	tmp_ctx = talloc_new(mem_ctx);
	ret = ldb_search(ldb, tmp_ctx, &res, NULL, LDB_SCOPE_BASE, attrs,
			 "objectGUID=%s", GUID_string(tmp_ctx, &edge->id));
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("failed to find siteLink object %s: %s\n",
			  GUID_string(tmp_ctx, &edge->id), ldb_strerror(ret)));
		talloc_free(edge);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (res->count == 0) {
		DEBUG(0, ("failed to find siteLink object %s\n",
			  GUID_string(tmp_ctx, &edge->id)));
		talloc_free(edge);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	el = ldb_msg_find_element(res->msgs[0], "siteList");
	edge->vertex_ids.count = el->num_values;
	edge->vertex_ids.data = talloc_array(edge, struct GUID, el->num_values);
	if (!edge->vertex_ids.data) {
		talloc_free(edge);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < el->num_values; i++) {
		struct ldb_dn *dn;
		struct GUID guid;

		val = el->values[i];
		dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &val);
		ret = dsdb_find_guid_by_dn(ldb, dn, &guid);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("failed to find objectGUID for object %s: "
				  "%s\n", ldb_dn_get_linearized(dn),
				  ldb_strerror(ret)));
			talloc_free(edge);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		edge->vertex_ids.data = talloc_realloc(edge,
						       edge->vertex_ids.data,
						       struct GUID,
						       edge->vertex_ids.count + 1);
		if (!edge->vertex_ids.data) {
			talloc_free(edge);
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		edge->vertex_ids.data[edge->vertex_ids.count] = guid;
		edge->vertex_ids.count++;
	}

	edge->repl_info.cost = samdb_result_int64(site_link, "cost", 0);
	edge->repl_info.options = samdb_result_int64(site_link, "options", 0);
	edge->repl_info.interval = samdb_result_int64(site_link, "replInterval",
						      0);
	/* val = ldb_msg_find_ldb_val(site_link, "schedule");
	edge->repl_info.schedule = val->data; */
	edge->type = type;
	edge->directed = false;

	*_edge = edge;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/**
 * create a kcctpl_multi_edge_set instance containing edges for all siteLink
 * objects.
 */
static NTSTATUS kcctpl_create_auto_edge_set(struct kcctpl_graph *graph,
					    struct GUID type,
					    struct ldb_result *res_site_link,
					    struct kcctpl_multi_edge_set **_set)
{
	struct kcctpl_multi_edge_set *set;
	unsigned int i;

	set = talloc_zero(graph, struct kcctpl_multi_edge_set);
	NT_STATUS_HAVE_NO_MEMORY(set);

	for (i = 0; i < res_site_link->count; i++) {
		struct GUID site_link_guid;
		struct kcctpl_multi_edge *edge;

		site_link_guid = samdb_result_guid(res_site_link->msgs[i],
						   "objectGUID");
		edge = kcctpl_find_edge_by_guid(graph, site_link_guid);
		if (!edge) {
			TALLOC_CTX *tmp_ctx = talloc_new(graph);
			DEBUG(0, ("failed to find a graph edge with ID=%s\n",
				  GUID_string(tmp_ctx, &site_link_guid)));
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (GUID_compare(&edge->type, &type) == 0) {
			set->edge_ids.data = talloc_realloc(set,
							    set->edge_ids.data,
							    struct GUID,
							    set->edge_ids.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set->edge_ids.data,
							  set);
			set->edge_ids.data[set->edge_ids.count] = site_link_guid;
			set->edge_ids.count++;
		}
	}

	*_set = set;
	return NT_STATUS_OK;
}

/**
 * create a kcctpl_multi_edge_set instance.
 */
static NTSTATUS kcctpl_create_edge_set(struct ldb_context *ldb,
				       struct kcctpl_graph *graph,
				       struct GUID type,
				       struct ldb_message *bridge,
				       struct kcctpl_multi_edge_set **_set)
{
	struct kcctpl_multi_edge_set *set;
	struct ldb_message_element *el;
	unsigned int i;

	set = talloc_zero(graph, struct kcctpl_multi_edge_set);
	NT_STATUS_HAVE_NO_MEMORY(set);

	set->id = samdb_result_guid(bridge, "objectGUID");

	el = ldb_msg_find_element(bridge, "siteLinkList");
	for (i = 0; i < el->num_values; i++) {
		struct ldb_val val;
		TALLOC_CTX *tmp_ctx;
		struct ldb_dn *dn;
		struct GUID site_link_guid;
		int ret;
		struct kcctpl_multi_edge *edge;

		val = el->values[i];
		tmp_ctx = talloc_new(graph);
		dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &val);
		if (!ldb_dn_validate(dn)) {
			DEBUG(0, ("invalid DN in siteLinkList attr of %s\n",
				  GUID_string(tmp_ctx, &set->id)));
			talloc_free(set);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ret = dsdb_find_guid_by_dn(ldb, dn, &site_link_guid);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("failed to find objectGUID for object %s: "
				  "%s\n", ldb_dn_get_linearized(dn),
				  ldb_strerror(ret)));
			talloc_free(set);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		edge = kcctpl_find_edge_by_guid(graph, site_link_guid);
		if (!edge) {
			DEBUG(0, ("failed to find a graph edge with ID=%s\n",
				  GUID_string(tmp_ctx, &site_link_guid)));
			talloc_free(set);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		talloc_free(tmp_ctx);

		if (GUID_compare(&edge->type, &type) == 0) {
			set->edge_ids.data = talloc_realloc(set,
							    set->edge_ids.data,
							    struct GUID,
							    set->edge_ids.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set->edge_ids.data,
							  set);
			set->edge_ids.data[set->edge_ids.count] = site_link_guid;
			set->edge_ids.count++;
		}
	}

	*_set = set;
	return NT_STATUS_OK;
}

/**
 * set up a kcctpl_graph, populated with a kcctpl_vertex for each site object, a
 * kcctpl_multi_edge for each siteLink object, and a kcctpl_multi_edge_set for
 * each siteLinkBridge object (or implied siteLinkBridge).
 */
static NTSTATUS kcctpl_setup_graph(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				   struct kcctpl_graph **_graph)
{
	struct kcctpl_graph *graph;
	struct ldb_dn *config_dn, *base_dn;
	TALLOC_CTX *tmp_ctx;
	bool ok;
	struct ldb_result *res;
	const char * const site_link_attrs[] = { "objectGUID", NULL };
	const char * const inter_site_transport_attrs[] = { "objectGUID",
							    "distinguishedName",
							    NULL };
	const char * const attrs[] = { "objectGUID", "cost", "options",
				       "replInterval", "schedule", NULL };
	const char * const site_link_bridge_attrs[] = { "objectGUID",
							"siteLinkList",
							NULL };
	int ret;
	struct GUID_list vertex_ids;
	unsigned int i;
	NTSTATUS status;

	config_dn = samdb_config_dn(ldb);
	if (!config_dn) {
		DEBUG(0, ("failed to find our own Config DN\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	tmp_ctx = talloc_new(mem_ctx);
	base_dn = ldb_dn_copy(tmp_ctx, config_dn);
	if (!base_dn) {
		DEBUG(0, ("failed to copy Config DN %s\n",
			  ldb_dn_get_linearized(config_dn)));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ok = ldb_dn_add_child_fmt(base_dn, "CN=Sites");
	if (!ok) {
		if (ldb_dn_validate(base_dn)) {
			DEBUG(0, ("failed to format DN %s\n",
				  ldb_dn_get_linearized(base_dn)));
		}
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
			 site_link_attrs, "objectClass=siteLink");
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("failed to find siteLink objects under %s: %s\n",
			  ldb_dn_get_linearized(base_dn), ldb_strerror(ret)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ZERO_STRUCT(vertex_ids);
	for (i = 0; i < res->count; i++) {
		struct GUID guid;

		guid = samdb_result_guid(res->msgs[i], "objectGUID");
		vertex_ids.data = talloc_realloc(tmp_ctx, vertex_ids.data,
						 struct GUID,
						 vertex_ids.count + 1);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(vertex_ids.data, tmp_ctx);
		vertex_ids.data[vertex_ids.count] = guid;
		vertex_ids.count++;
	}

	status = kcctpl_create_graph(mem_ctx, &vertex_ids, &graph);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("failed to create graph: %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return status;
	}

	/* get site of local DC */

	ok = ldb_dn_add_child_fmt(base_dn, "CN=Inter-Site Transports");
	if (!ok) {
		if (ldb_dn_validate(base_dn)) {
			DEBUG(0, ("failed to format DN %s\n",
				  ldb_dn_get_linearized(base_dn)));
		}
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
			inter_site_transport_attrs,
			"objectClass=interSiteTransport");
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("failed to find interSiteTransport objects under %s: "
			  "%s\n", ldb_dn_get_linearized(base_dn),
			  ldb_strerror(ret)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *transport;
		struct ldb_result *res_site_link;
		struct GUID transport_guid;
		unsigned int j;
		int options;

		transport = res->msgs[i];

		base_dn = samdb_result_dn(ldb, tmp_ctx, transport,
					  "distinguishedName", NULL);
		if (!base_dn) {
			DEBUG(0, ("failed to find DN for interSiteTransport "
				  "object\n"));
			talloc_free(graph);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		// TODO: don't need to ldb_search again; search in res.
		ret = ldb_search(ldb, tmp_ctx, &res_site_link, base_dn,
				 LDB_SCOPE_SUBTREE, attrs,
				 "objectClass=siteLink");
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("failed to find siteLink objects under %s: "
				  "%s\n", ldb_dn_get_linearized(base_dn),
				  ldb_strerror(ret)));
			talloc_free(graph);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		transport_guid = samdb_result_guid(transport, "objectGUID");
		for (j = 0; j < res_site_link->count; j++) {
			struct kcctpl_multi_edge *edge;

			status = kcctpl_create_edge(ldb, graph, transport_guid,
						    res_site_link->msgs[j],
						    &edge);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(0, ("failed to create edge: %s\n",
					  nt_errstr(status)));
				talloc_free(graph);
				talloc_free(tmp_ctx);
				return status;
			}

			graph->edges.data = talloc_realloc(graph,
							   graph->edges.data,
							   struct kcctpl_multi_edge,
							   graph->edges.count + 1);
			if (!graph->edges.data) {
				talloc_free(graph);
				talloc_free(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}
			graph->edges.data[graph->edges.count] = *edge;
			graph->edges.count++;
		}

		options = samdb_result_int64(transport, "options", 0);
		if ((options & NTDSTRANSPORT_OPT_BRIDGES_REQUIRED) == 0) {
			struct kcctpl_multi_edge_set *edge_set;

			status = kcctpl_create_auto_edge_set(graph,
							     transport_guid,
							     res_site_link,
							     &edge_set);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(0, ("failed to create edge set: %s\n",
					  nt_errstr(status)));
				talloc_free(graph);
				talloc_free(tmp_ctx);
				return status;
			}

			graph->edge_sets.data = talloc_realloc(graph,
							       graph->edge_sets.data,
							       struct kcctpl_multi_edge_set,
							       graph->edge_sets.count + 1);
			if (!graph->edge_sets.data) {
				talloc_free(graph);
				talloc_free(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}
			graph->edge_sets.data[graph->edge_sets.count] = *edge_set;
			graph->edge_sets.count++;
		} else {
			ret = ldb_search(ldb, tmp_ctx, &res_site_link, base_dn,
					 LDB_SCOPE_SUBTREE,
					 site_link_bridge_attrs,
					 "objectClass=siteLinkBridge");
			if (ret != LDB_SUCCESS) {
				DEBUG(0, ("failed to find siteLinkBridge "
					  "objects under %s: %s\n",
					  ldb_dn_get_linearized(base_dn),
					  ldb_strerror(ret)));
				talloc_free(graph);
				talloc_free(tmp_ctx);
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			for (j = 0; j < res_site_link->count; j++) {
				struct ldb_message *bridge;
				struct kcctpl_multi_edge_set *edge_set;

				bridge = res_site_link->msgs[j];
				status = kcctpl_create_edge_set(ldb, graph,
								transport_guid,
								bridge,
								&edge_set);
				if (NT_STATUS_IS_ERR(status)) {
					DEBUG(0, ("failed to create edge set: "
						  "%s\n", nt_errstr(status)));
					talloc_free(graph);
					talloc_free(tmp_ctx);
					return status;
				}

				graph->edge_sets.data = talloc_realloc(graph,
								       graph->edge_sets.data,
								       struct kcctpl_multi_edge_set,
								       graph->edge_sets.count + 1);
				if (!graph->edge_sets.data) {
					talloc_free(graph);
					talloc_free(tmp_ctx);
					return NT_STATUS_NO_MEMORY;
				}
				graph->edge_sets.data[graph->edge_sets.count] = *edge_set;
				graph->edge_sets.count++;
			}
		}
	}

	*_graph = graph;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

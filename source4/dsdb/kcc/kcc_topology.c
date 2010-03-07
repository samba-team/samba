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

#define FLAG_CR_NTDS_DOMAIN 0x00000002

#define NTDSSETTINGS_OPT_W2K3_BRIDGES_REQUIRED 0x00001000

#define NTDSTRANSPORT_OPT_BRIDGES_REQUIRED 0x00000002

/** replication parameters of a graph edge */
struct kcctpl_repl_info {
	uint32_t cost;
	uint32_t interval;
	uint32_t options;
	uint8_t schedule[84];
};

/** color of a vertex */
enum kcctpl_color { RED, BLACK, WHITE };

/** a GUID array list */
struct GUID_list {
	struct GUID *data;
	uint32_t count;
};

/** a vertex in the site graph */
struct kcctpl_vertex {
	struct GUID id;
	struct GUID_list edge_ids;
	enum kcctpl_color color;
	struct GUID_list accept_red_red;
	struct GUID_list accept_black;
	struct kcctpl_repl_info repl_info;
	uint32_t dist_to_red;

	/* Dijkstra data */
	struct GUID root_id;
	bool demoted;

	/* Kruskal data */
	struct GUID component_id;
	uint32_t component_index;
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
	uint32_t count;
};

/** an edges array list */
struct kcctpl_multi_edge_list {
	struct kcctpl_multi_edge *data;
	uint32_t count;
};

/** an edge sets array list */
struct kcctpl_multi_edge_set_list {
	struct kcctpl_multi_edge_set *data;
	uint32_t count;
};

/** a site graph */
struct kcctpl_graph {
	struct kcctpl_vertex_list vertices;
	struct kcctpl_multi_edge_list edges;
	struct kcctpl_multi_edge_set_list edge_sets;
};

/** path found in the graph between two non-white vertices */
struct kcctpl_internal_edge {
	struct GUID v1id;
	struct GUID v2id;
	bool red_red;
	struct kcctpl_repl_info repl_info;
	struct GUID type;
};

/** an internal edges array list */
struct kcctpl_internal_edge_list {
	struct kcctpl_internal_edge *data;
	uint32_t count;
};

/** an LDB messages array list */
struct message_list {
	struct ldb_message *data;
	uint32_t count;
};

/**
 * find a graph vertex based on its GUID.
 */
static struct kcctpl_vertex *kcctpl_find_vertex_by_guid(struct kcctpl_graph *graph,
							struct GUID guid)
{
	uint32_t i;

	for (i = 0; i < graph->vertices.count; i++) {
		if (GUID_equal(&graph->vertices.data[i].id, &guid)) {
			return &graph->vertices.data[i];
		}
	}

	return NULL;
}

/**
 * find a graph edge based on its GUID.
 */
static struct kcctpl_multi_edge *kcctpl_find_edge_by_guid(struct kcctpl_graph *graph,
							  struct GUID guid)
{
	uint32_t i;

	for (i = 0; i < graph->edges.count; i++) {
		if (GUID_equal(&graph->edges.data[i].id, &guid)) {
			return &graph->edges.data[i];
		}
	}

	return NULL;
}

/**
 * find a graph edge that contains a vertex with the specified GUID. the first
 * occurrence will be returned.
 */
static struct kcctpl_multi_edge *kcctpl_find_edge_by_vertex_guid(struct kcctpl_graph *graph,
								 struct GUID guid)
{
	uint32_t i;

	for (i = 0; i < graph->edges.count; i++) {
		struct kcctpl_multi_edge *edge;
		uint32_t j;

		edge = &graph->edges.data[i];

		for (j = 0; j < edge->vertex_ids.count; j++) {
			struct GUID vertex_guid = edge->vertex_ids.data[j];

			struct GUID *p = &guid;

			if (GUID_equal(&vertex_guid, p)) {
				return edge;
			}
		}
	}

	return NULL;
}

/**
 * get the Transports DN
 * (CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=<domain>).
 */
static struct ldb_dn *kcctpl_transports_dn(struct ldb_context *ldb,
					   TALLOC_CTX *mem_ctx)
{
	struct ldb_dn *sites_dn;
	bool ok;

	sites_dn = samdb_sites_dn(ldb, mem_ctx);
	if (!sites_dn) {
		return NULL;
	}

	ok = ldb_dn_add_child_fmt(sites_dn, "CN=Inter-Site Transports");
	if (!ok) {
		talloc_free(sites_dn);
		return NULL;
	}

	return sites_dn;
}
/**
 * get the domain local site object.
 */
static struct ldb_message *kcctpl_local_site(struct ldb_context *ldb,
					     TALLOC_CTX *mem_ctx)
{
	int ret;
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *sites_dn;
	struct ldb_result *res;
	const char * const attrs[] = { "objectGUID", "options", NULL };

	tmp_ctx = talloc_new(ldb);

	sites_dn = samdb_sites_dn(ldb, tmp_ctx);
	if (!sites_dn) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, sites_dn, LDB_SCOPE_SUBTREE, attrs,
			 "objectClass=site");

	if (ret != LDB_SUCCESS || res->count == 0) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	talloc_steal(mem_ctx, res);
	talloc_free(tmp_ctx);
	return res->msgs[0];
}

/**
 * create a kcctpl_graph instance.
 */
static NTSTATUS kcctpl_create_graph(TALLOC_CTX *mem_ctx,
				    struct GUID_list guids,
				    struct kcctpl_graph **_graph)
{
	struct kcctpl_graph *graph;
	uint32_t i;

	graph = talloc_zero(mem_ctx, struct kcctpl_graph);
	NT_STATUS_HAVE_NO_MEMORY(graph);

	graph->vertices.count = guids.count;
	graph->vertices.data = talloc_zero_array(graph, struct kcctpl_vertex,
						 guids.count);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(graph->vertices.data, graph);

	TYPESAFE_QSORT(guids.data, guids.count, GUID_compare);

	for (i = 0; i < guids.count; i++) {
		graph->vertices.data[i].id = guids.data[i];
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
	struct ldb_dn *sites_dn;
	struct ldb_result *res;
	const char * const attrs[] = { "siteList", NULL };
	int ret;
	struct ldb_message_element *el;
	uint32_t i;
	struct ldb_val val;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	edge = talloc_zero(tmp_ctx, struct kcctpl_multi_edge);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(edge, tmp_ctx);

	edge->id = samdb_result_guid(site_link, "objectGUID");

	sites_dn = samdb_sites_dn(ldb, tmp_ctx);
	if (!sites_dn) {
		DEBUG(1, (__location__ ": failed to find our own Sites DN\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, sites_dn, LDB_SCOPE_SUBTREE, attrs,
			 "objectGUID=%s", GUID_string(tmp_ctx, &edge->id));
	if (ret != LDB_SUCCESS) {
		DEBUG(1, (__location__ ": failed to find siteLink object %s: "
			  "%s\n", GUID_string(tmp_ctx, &edge->id),
			  ldb_strerror(ret)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (res->count == 0) {
		DEBUG(1, (__location__ ": failed to find siteLink object %s\n",
			  GUID_string(tmp_ctx, &edge->id)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	el = ldb_msg_find_element(res->msgs[0], "siteList");
	if (!el) {
		DEBUG(1, (__location__ ": failed to find siteList attribute of "
			  "object %s\n",
			  ldb_dn_get_linearized(res->msgs[0]->dn)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	edge->vertex_ids.data = talloc_array(edge, struct GUID, el->num_values);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(edge->vertex_ids.data, tmp_ctx);
	edge->vertex_ids.count = el->num_values;

	for (i = 0; i < el->num_values; i++) {
		struct ldb_dn *dn;
		struct GUID guid;

		val = el->values[i];
		dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &val);
		if (!dn) {
			DEBUG(1, (__location__ ": failed to read a DN from "
				  "siteList attribute of %s\n",
				  ldb_dn_get_linearized(res->msgs[0]->dn)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		ret = dsdb_find_guid_by_dn(ldb, dn, &guid);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, (__location__ ": failed to find objectGUID "
				  "for object %s: %s\n",
				  ldb_dn_get_linearized(dn),
				  ldb_strerror(ret)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		edge->vertex_ids.data[i] = guid;
	}

	edge->repl_info.cost = samdb_result_int64(site_link, "cost", 0);
	edge->repl_info.options = samdb_result_int64(site_link, "options", 0);
	edge->repl_info.interval = samdb_result_int64(site_link,
						      "replInterval", 0);
	/* TODO: edge->repl_info.schedule = site_link!schedule */
	edge->type = type;
	edge->directed = false;

	*_edge = talloc_steal(mem_ctx, edge);
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
	TALLOC_CTX *tmp_ctx;
	uint32_t i;

	tmp_ctx = talloc_new(graph);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	set = talloc_zero(tmp_ctx, struct kcctpl_multi_edge_set);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set, tmp_ctx);

	for (i = 0; i < res_site_link->count; i++) {
		struct GUID site_link_guid;
		struct kcctpl_multi_edge *edge;

		site_link_guid = samdb_result_guid(res_site_link->msgs[i],
						   "objectGUID");
		edge = kcctpl_find_edge_by_guid(graph, site_link_guid);
		if (!edge) {
			DEBUG(1, (__location__ ": failed to find a graph edge "
				  "with ID=%s\n",
				  GUID_string(tmp_ctx, &site_link_guid)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (GUID_equal(&edge->type, &type)) {
			struct GUID *new_data;

			new_data = talloc_realloc(set, set->edge_ids.data,
						  struct GUID,
						  set->edge_ids.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[set->edge_ids.count] = site_link_guid;
			set->edge_ids.data = new_data;
			set->edge_ids.count++;
		}
	}

	*_set = talloc_steal(graph, set);
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
	TALLOC_CTX *tmp_ctx;
	struct ldb_message_element *el;
	uint32_t i;

	tmp_ctx = talloc_new(ldb);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	set = talloc_zero(tmp_ctx, struct kcctpl_multi_edge_set);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set, tmp_ctx);

	set->id = samdb_result_guid(bridge, "objectGUID");

	el = ldb_msg_find_element(bridge, "siteLinkList");
	if (!el) {
		DEBUG(1, (__location__ ": failed to find siteLinkList "
			  "attribute of object %s\n",
			  ldb_dn_get_linearized(bridge->dn)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	for (i = 0; i < el->num_values; i++) {
		struct ldb_val val;
		struct ldb_dn *dn;
		struct GUID site_link_guid;
		int ret;
		struct kcctpl_multi_edge *edge;

		val = el->values[i];
		dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &val);
		if (!dn) {
			DEBUG(1, (__location__ ": failed to read a DN from "
				  "siteList attribute of %s\n",
				  ldb_dn_get_linearized(bridge->dn)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ret = dsdb_find_guid_by_dn(ldb, dn, &site_link_guid);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, (__location__ ": failed to find objectGUID "
				  "for object %s: %s\n",
				  ldb_dn_get_linearized(dn),
				  ldb_strerror(ret)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		edge = kcctpl_find_edge_by_guid(graph, site_link_guid);
		if (!edge) {
			DEBUG(1, (__location__ ": failed to find a graph edge "
				  "with ID=%s\n",
				  GUID_string(tmp_ctx, &site_link_guid)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (GUID_equal(&edge->type, &type)) {
			struct GUID *new_data;

			new_data = talloc_realloc(set, set->edge_ids.data,
						  struct GUID,
						  set->edge_ids.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[set->edge_ids.count] = site_link_guid;
			set->edge_ids.data = new_data;
			set->edge_ids.count++;
		}
	}

	*_set = talloc_steal(graph, set);
	talloc_free(tmp_ctx);
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
	struct ldb_dn *sites_dn, *transports_dn;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	const char * const transport_attrs[] = { "objectGUID", NULL };
	const char * const site_attrs[] = { "objectGUID", "options", NULL };
	const char * const attrs[] = { "objectGUID", "cost", "options",
				       "replInterval", "schedule", NULL };
	const char * const site_link_bridge_attrs[] = { "objectGUID",
							"siteLinkList",
							NULL };
	int ret;
	struct GUID_list vertex_ids;
	uint32_t i;
	NTSTATUS status;
	struct ldb_message *site;
	uint64_t site_opts;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	sites_dn = samdb_sites_dn(ldb, tmp_ctx);
	if (!sites_dn) {
		DEBUG(1, (__location__ ": failed to find our own Sites DN\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, sites_dn, LDB_SCOPE_SUBTREE,
			 site_attrs, "objectClass=site");
	if (ret != LDB_SUCCESS) {
		DEBUG(1, (__location__ ": failed to find site objects under "
			  "%s: %s\n", ldb_dn_get_linearized(sites_dn),
			  ldb_strerror(ret)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ZERO_STRUCT(vertex_ids);
	for (i = 0; i < res->count; i++) {
		struct GUID guid, *new_data;

		guid = samdb_result_guid(res->msgs[i], "objectGUID");

		new_data = talloc_realloc(tmp_ctx, vertex_ids.data, struct GUID,
					  vertex_ids.count + 1);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
		new_data[vertex_ids.count] = guid;
		vertex_ids.data = new_data;
		vertex_ids.count++;
	}

	status = kcctpl_create_graph(tmp_ctx, vertex_ids, &graph);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, (__location__ ": failed to create graph: %s\n",
			  nt_errstr(status)));

		talloc_free(tmp_ctx);
		return status;
	}

	site = kcctpl_local_site(ldb, tmp_ctx);
	if (!site) {
		DEBUG(1, (__location__ ": failed to find our own local DC's "
			  "site\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	site_opts = samdb_result_int64(site, "options", 0);

	transports_dn = kcctpl_transports_dn(ldb, tmp_ctx);
	if (!transports_dn) {
		DEBUG(1, (__location__ ": failed to find our own Inter-Site "
			  "Transports DN\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_search(ldb, tmp_ctx, &res, transports_dn, LDB_SCOPE_ONELEVEL,
			transport_attrs, "objectClass=interSiteTransport");
	if (ret != LDB_SUCCESS) {
		DEBUG(1, (__location__ ": failed to find interSiteTransport "
			  "objects under %s: %s\n",
			  ldb_dn_get_linearized(transports_dn),
			  ldb_strerror(ret)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *transport;
		struct ldb_result *res_site_link;
		struct GUID transport_guid;
		unsigned int j;
		uint64_t transport_opts;

		transport = res->msgs[i];

		ret = ldb_search(ldb, tmp_ctx, &res_site_link, transport->dn,
				 LDB_SCOPE_SUBTREE, attrs,
				 "objectClass=siteLink");
		if (ret != LDB_SUCCESS) {
			DEBUG(1, (__location__ ": failed to find siteLink "
				  "objects under %s: %s\n",
				  ldb_dn_get_linearized(transport->dn),
				  ldb_strerror(ret)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		transport_guid = samdb_result_guid(transport, "objectGUID");
		for (j = 0; j < res_site_link->count; j++) {
			struct kcctpl_multi_edge *edge, *new_data;

			status = kcctpl_create_edge(ldb, graph, transport_guid,
						    res_site_link->msgs[j],
						    &edge);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(1, (__location__ ": failed to create "
					  "edge: %s\n", nt_errstr(status)));
				talloc_free(tmp_ctx);
				return status;
			}

			new_data = talloc_realloc(graph, graph->edges.data,
						  struct kcctpl_multi_edge,
						  graph->edges.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[graph->edges.count] = *edge;
			graph->edges.data = new_data;
			graph->edges.count++;
		}

		transport_opts = samdb_result_int64(transport, "options", 0);
		if (!(transport_opts & NTDSTRANSPORT_OPT_BRIDGES_REQUIRED) &&
		    !(site_opts & NTDSSETTINGS_OPT_W2K3_BRIDGES_REQUIRED)) {
			struct kcctpl_multi_edge_set *edge_set, *new_data;

			status = kcctpl_create_auto_edge_set(graph,
							     transport_guid,
							     res_site_link,
							     &edge_set);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(1, (__location__ ": failed to create "
					  "edge set: %s\n", nt_errstr(status)));
				talloc_free(tmp_ctx);
				return status;
			}

			new_data = talloc_realloc(graph, graph->edge_sets.data,
						  struct kcctpl_multi_edge_set,
						  graph->edge_sets.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[graph->edge_sets.count] = *edge_set;
			graph->edge_sets.data = new_data;
			graph->edge_sets.count++;
		} else {
			ret = ldb_search(ldb, tmp_ctx, &res_site_link,
					 transport->dn, LDB_SCOPE_SUBTREE,
					 site_link_bridge_attrs,
					 "objectClass=siteLinkBridge");
			if (ret != LDB_SUCCESS) {
				DEBUG(1, (__location__ ": failed to find "
					  "siteLinkBridge objects under %s: "
					  "%s\n",
					  ldb_dn_get_linearized(transport->dn),
					  ldb_strerror(ret)));

				talloc_free(tmp_ctx);
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			for (j = 0; j < res_site_link->count; j++) {
				struct ldb_message *bridge;
				struct kcctpl_multi_edge_set *edge_set,
							     *new_data;

				bridge = res_site_link->msgs[j];
				status = kcctpl_create_edge_set(ldb, graph,
								transport_guid,
								bridge,
								&edge_set);
				if (NT_STATUS_IS_ERR(status)) {
					DEBUG(1, (__location__ ": failed to "
						  "create edge set: %s\n",
						  nt_errstr(status)));

					talloc_free(tmp_ctx);
					return status;
				}

				new_data = talloc_realloc(graph,
							  graph->edge_sets.data,
							  struct kcctpl_multi_edge_set,
							  graph->edge_sets.count + 1);
				NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data,
								  tmp_ctx);
				new_data[graph->edge_sets.count] = *edge_set;
				graph->edge_sets.data = new_data;
				graph->edge_sets.count++;
			}
		}
	}

	*_graph = talloc_steal(mem_ctx, graph);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/**
 * get a bridgehead DC.
 */
static NTSTATUS kcctpl_get_bridgehead_dc(struct ldb_context *ldb,
					 TALLOC_CTX *mem_ctx,
					 struct GUID site_guid,
					 struct ldb_message *cross_ref,
					 struct ldb_message *transport,
					 bool partial_replica_okay,
					 bool detect_failed_dcs,
					 struct ldb_message **_dsa)
{
	return NT_STATUS_OK;
}

/*
 * color each vertex to indicate which kinds of NC replicas it contains.
 */
static NTSTATUS kcctpl_color_vertices(struct ldb_context *ldb,
				      struct kcctpl_graph *graph,
				      struct ldb_message *cross_ref,
				      bool detect_failed_dcs,
				      bool *_found_failed_dcs)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *sites_dn;
	bool found_failed_dcs, partial_replica_okay;
	uint32_t i;
	struct ldb_message *site;
	struct ldb_result *res;
	int ret, cr_flags;
	struct GUID site_guid;
	struct kcctpl_vertex *site_vertex;

	found_failed_dcs = false;

	tmp_ctx = talloc_new(ldb);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	sites_dn = samdb_sites_dn(ldb, tmp_ctx);
	if (!sites_dn) {
		DEBUG(1, (__location__ ": failed to find our own Sites DN\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	for (i = 0; i < graph->vertices.count; i++) {
		struct kcctpl_vertex *vertex;
		struct ldb_dn *nc_name;
		/* TODO: set 'attrs' with its corresponding values */
		const char * const attrs[] = { NULL };

		vertex = &graph->vertices.data[i];

		ret = ldb_search(ldb, tmp_ctx, &res, sites_dn,
				 LDB_SCOPE_SUBTREE, attrs, "objectGUID=%s",
				 GUID_string(tmp_ctx, &vertex->id));
		if (ret != LDB_SUCCESS) {
			DEBUG(1, (__location__ ": failed to find site object "
				  "%s: %s\n", GUID_string(tmp_ctx, &vertex->id),
				  ldb_strerror(ret)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		if (res->count == 0) {
			DEBUG(1, (__location__ ": failed to find site object "
				  "%s\n", GUID_string(tmp_ctx, &vertex->id)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		site = res->msgs[0];

		nc_name = samdb_result_dn(ldb, tmp_ctx, cross_ref,
					  "nCName", NULL);
		if (!nc_name) {
			DEBUG(1, (__location__ ": failed to find nCName "
				  "attribute of object %s\n",
				  ldb_dn_get_linearized(cross_ref->dn)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (true) { /* TODO: site contains 1+ DCs with full replicas of
			       'nc_name' */
			vertex->color = RED;
		} else if (true) { /* TODO: site contains 1+ partial replicas of
				      'nc_name' */
			vertex->color = BLACK;
		} else {
			vertex->color = WHITE;
		}
	}

	site = kcctpl_local_site(ldb, tmp_ctx);
	if (!site) {
		DEBUG(1, (__location__ ": failed to find our own local DC's "
			  "site\n"));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	site_guid = samdb_result_guid(site, "objectGUID");

	site_vertex = kcctpl_find_vertex_by_guid(graph, site_guid);
	if (!site_vertex) {
		DEBUG(1, (__location__ ": failed to find a vertex edge with "
			  "GUID=%s\n", GUID_string(tmp_ctx, &site_guid)));

		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	partial_replica_okay = (site_vertex->color == BLACK);

	cr_flags = samdb_result_int64(cross_ref, "systemFlags", 0);

	for (i = 0; i < graph->vertices.count; i++) {
		struct kcctpl_vertex *vertex;
		struct ldb_dn *transports_dn;
		const char * const attrs[] = { "objectGUID", "name",
					       "transportAddressAttribute",
					       NULL };
		uint32_t j;

		vertex = &graph->vertices.data[i];

		transports_dn = kcctpl_transports_dn(ldb, tmp_ctx);
		if (!transports_dn) {
			DEBUG(1, (__location__ ": failed to find our own "
				  "Inter-Site Transports DN\n"));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ret = ldb_search(ldb, tmp_ctx, &res, transports_dn,
				 LDB_SCOPE_ONELEVEL, attrs,
				 "objectClass=interSiteTransport");
		if (ret != LDB_SUCCESS) {
			DEBUG(1, (__location__ ": failed to find "
				  "interSiteTransport objects under %s: %s\n",
				  ldb_dn_get_linearized(transports_dn),
				  ldb_strerror(ret)));

			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		for (j = 0; j < res->count; j++) {
			struct ldb_message *transport, *bridgehead;
			const char *transport_name;
			struct GUID transport_guid, *new_data;
			NTSTATUS status;

			transport = res->msgs[j];

			transport_name = samdb_result_string(transport,
							     "name", NULL);
			if (!transport_name) {
				DEBUG(1, (__location__ ": failed to find name "
					  "attribute of object %s\n",
					  ldb_dn_get_linearized(transport->dn)));

				talloc_free(tmp_ctx);
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			transport_guid = samdb_result_guid(transport,
							   "objectGUID");

			if (site_vertex->color == RED &&
			    strncmp(transport_name, "IP", 2) != 0 &&
			    (cr_flags & FLAG_CR_NTDS_DOMAIN)) {
				continue;
			}

			if (!kcctpl_find_edge_by_vertex_guid(graph,
							     vertex->id)) {
				continue;
			}

			status = kcctpl_get_bridgehead_dc(ldb, tmp_ctx,
							  site_vertex->id,
							  cross_ref, transport,
							  partial_replica_okay,
							  detect_failed_dcs,
							  &bridgehead);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(1, (__location__ ": failed to get a "
					  "bridgehead DC: %s\n",
					  nt_errstr(status)));

				talloc_free(tmp_ctx);
				return status;
			}
			if (!bridgehead) {
				found_failed_dcs = true;
				continue;
			}

			new_data = talloc_realloc(vertex,
						  vertex->accept_red_red.data,
						  struct GUID,
						  vertex->accept_red_red.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[vertex->accept_red_red.count + 1] = transport_guid;
			vertex->accept_red_red.data = new_data;
			vertex->accept_red_red.count++;

			new_data = talloc_realloc(vertex,
						  vertex->accept_black.data,
						  struct GUID,
						  vertex->accept_black.count + 1);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(new_data, tmp_ctx);
			new_data[vertex->accept_black.count + 1] = transport_guid;
			vertex->accept_black.data = new_data;
			vertex->accept_black.count++;
		}
	}

	*_found_failed_dcs = found_failed_dcs;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
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

#ifndef WSP_ES_CONV_H
#define WSP_ES_CONV_H

#include <jansson.h>
#include "wsp_backend.h"

void initialise_elastic_conv(void);
struct query_conv_ops *es_wsp_conv_ops(void);
struct memcache;
struct auth_session_info;

/* rows specific data (used in conversion routines) */
struct es_row_data {
	struct memcache *id_cache;
	const char* share;
	const char* share_path;
	uint32_t *rowid_generator;
};

/*
 * Row specific context data passed to
 * conversion function (see backend_to_wsp_fn)
 */
struct row_conv_data {
	struct conn_wrap *conn_wrap;
	bool is_folder_result;
	const char *row_url; /* raw url from index */
	/* url with segments after the netbios name.( mangled if nesessary )*/
	const char *row_relative_share_path;
	struct es_row_data *row_data;
};

struct conv_call_ctx {
	struct row_conv_data *row_conv_data;
	void *private_data;
};
/*
 * a set of maps and data that are needed by the logic that parses the
 * binary wsp query message consisting of wsp restrictions in order to
 * convert it into an elasticsearch query.
 */
struct elastic_json_mapping {
	struct query_conv_ops *es_conv_ops;
	json_t *kind_map;
	int num_props;
	struct es_detail *prop_to_es_map; /* wsp_to_es_map */
};

struct es_query_ctx {
	struct wspd_client_state *client_state;
	const char *share_scope;
	struct memcache *id_cache;
	struct elastic_json_mapping *json_config;
};


struct es_detail {
	const char *wsp_id;
	const char *type;
	const char *elastic_id;
	const char *elastic_to_wsp_fn_name;
	void *elastic_to_wsp_call_ctx;
	backend_to_wsp_fn elastic_to_wsp_fn;
	const char *wsp_to_elastic_fn_name;
	void *wsp_to_elastic_call_ctx;
	wsp_to_backend_val_fn wsp_to_elastic_fn;
};

bool can_access_url(struct conn_wrap *conn_wrap,
		    const char *url);

/* needed for python specific */
struct es_query_ctx *create_wsp_to_es_data(TALLOC_CTX* ctx);

const char * get_propvalueforworkid_query(TALLOC_CTX *ctx,
                        struct memcache *id_cache,
			const char* indexname,
                        uint32_t workid,
                        struct wsp_cfullpropspec *propspec,
                        struct binding_result_mapper *mapper,
			struct backend_selected_cols *backend_cols);

#endif /* WSP_ES_CONV_H */

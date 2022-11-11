/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
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

#ifndef WSP_BACKEND_H
#define WSP_BACKEND_H

#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "wsp_abs_if.h"
#include "libcli/util/hresult.h"

struct connection_struct;
struct wsp_crestrictionarray;

/*
 * Union to describe basic types transferred from
 * backend
 */

union backend_value {
        const char *string;
        uint64_t integer;
        uint16_t boolean;
        uint64_t double_val;
};

/*
 * Columns to be returned by backend (identified by id/name)
 */
struct backend_selected_cols {
        int cols;
        const char **backend_ids;
};

/*
 * function to convert from backend value to WSP type/value
 */
typedef HRESULT (*backend_to_wsp_fn)(TALLOC_CTX *ctx,
			void *calling_ctx,
                        struct wsp_cbasestoragevariant *out_val,
                        int type, /* backend type */
                        uint32_t vtypeout, /* wsp col type to convert to*/
                        void *backend_val);

/*
 * convert an incoming wsp value to a backend indexer string
 * e.g convert a file path (which is a url with format
 * file://$NETBIOS_NAME/$SHARE_NAME/relative_path
 * To a system path url
 */

struct wsp_crestriction;
typedef HRESULT (*wsp_to_backend_val_fn) (TALLOC_CTX *ctx,
                       void *calling_ctx,
                       struct wsp_crestriction *restriction,
                       bool escape,
                       const char **output);

/*
 * Mapping information for columns
 */
struct map_data {
        uint32_t col_with_value; /* index of column with value */
        uint32_t vtype;          /* type of value in column */
        void *calling_ctx;       /* private data to pass to conversion */
				 /* function */
        backend_to_wsp_fn convert_fn; /* function to convert the value */
				      /* located at col[col_with_value] */
};

/*
 * array of mapping information (for each column)
 */
struct binding_result_mapper {
        uint32_t ncols;
        struct map_data *map_data;
};

struct prop_data {
	struct prop_detail {
		const char *wsp_prop;
		const char *backend_prop;
		const char *conv_fn;
	} *detail;
	int num;
};

struct col_conv_list_item {
	struct col_conv_list_item *prev, *next;
	const char* col_conv_name;
	void *calling_ctx;
	backend_to_wsp_fn conv_fn;
};

struct column_mapper {
	struct col_conv_list_item *prop_conv_list;
};

struct memcache;
/*
 * Builds a text query based on the WSP
 * information contained in select_cols, restrictarray
 * pidmapper, sorting
 * Returns;
 *    + the share we are searching in 'share_search_scope'
 *    + backend specific query string
 *    + where_str (backend specific string representing
 *      the restriction set we would expect to store/retrieve
 *      associated with by 'whereid'.
 *
 */
typedef HRESULT (*bld_query_fn)(TALLOC_CTX *ctx,
		struct wspd_client_state *state,
		struct wsp_ccolumnset *select_cols,
		struct wsp_crestrictionarray *restrictarray,
		struct wsp_cpidmapper *pidmapper,
		struct wsp_csortset *sorting,
		struct backend_selected_cols *backend_cols,
		bool convert_props,
		const char **share_search_scope,
		const char **fullquery,
		const char **where_str);

/*
 * construct 'mapper' from 'backend_cols'
 * 'mapper' contains the information needed to convert
 * from 'backend' columns to WSP columns requested by
 * the client.
 */
typedef bool (*bld_mapper_fn)(TALLOC_CTX *ctx,
		struct wsp_ctablecolumn *columns,
		uint32_t ncols,
		struct backend_selected_cols *backend_cols,
		struct binding_result_mapper *mapper);

/*
 * Returns 'true' if successfully retrieved query restriction information
 * and assocaiated share associated with 'where_id'.
 */
typedef bool (*bld_lookup_where_id)(TALLOC_CTX *mem_ctx,
		struct wspd_client_state *state,
		uint32_t where_id,
		const char **restriction_exp,
		const char **share_out);

const char *get_backend_conv_fn_name(const char *wsp_prop,
			struct prop_data *prop_data);

backend_to_wsp_fn get_property_conv(struct column_mapper *mapper,
			const char *name);

void *get_property_calling_ctx(struct column_mapper *mapper,
			       const char *name);

const char *get_backend_prop_name(const char *wsp_prop,
				  struct prop_data *prop_data);
/*
 * Backend specific operations for
 *   + creating query (from WSP inputs)
 *   + building a mapper that can convert the backend result
 *     columns to requested WSP columns
 */
struct query_conv_ops {
	bld_mapper_fn bld_mapper;
	bld_query_fn bld_query;
	bld_lookup_where_id bld_lookup_whereid;
};

/*
 * register backends by id
 */
bool register_backend_impl(int backend_id,
			struct query_conv_ops *ops,
			struct wsp_abstract_interface *backend_if);

/*
 * return query_conv_ops for backend id
 */
struct query_conv_ops *get_query_conv_ops(int backend);

/*
 * return abstract_inferface for id
 */
struct wsp_abstract_interface *get_backend_impl(int backend);

#endif

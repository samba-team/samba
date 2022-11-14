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

#include "includes.h"
#include "wsp_es_conv.h"
#include "wsp_backend.h"

/*
 * list of names and associated backend value to
 * wsp value functions.
 * For example, when we wish to return the System.ItemURL
 * property we would synthesis that from the elasticsearch
 * file.url property, the conversion would involve
 * converting the system file url into a url matching
 * FILE://NETBIOSNAME/SHARE/xyz where xyz is the relative path
 * from the associated share mount, additionally the relative path
 * will be mangled.
 * The list below is a set of predefined functions for some standard
 * mapping of elasticsearch property to wsp property values
 */

static struct property_conv_data {
	const char *name;
	backend_to_wsp_fn conv_fn;
} backend_to_wsp[] = {
};

/* replace existing or add new col conv function */
static bool add_property_conv(struct column_mapper *mapper,
		const char *conv_name,
		backend_to_wsp_fn conv_fn)
{
	struct col_conv_list_item *item = NULL;

	for (item = mapper->prop_conv_list; item != NULL; item = item->next) {
		if (strequal(item->col_conv_name, conv_name)) {
			break;
		}
	}
	if (item == NULL) {
		item = talloc_zero(mapper, struct col_conv_list_item);
		if (item == NULL) {
			return false;
		}
		DLIST_ADD_END(mapper->prop_conv_list, item);
	}

	item->col_conv_name = conv_name;
	item->conv_fn = conv_fn;

	return true;
}

static struct column_mapper *init_convert_map(TALLOC_CTX *ctx,
				const char *mapper_name)
{
	struct column_mapper *mapper = NULL;
	int i;

	mapper = talloc_zero(ctx, struct column_mapper);
	if (mapper == NULL) {
		DBG_ERR("out of memory\n");
		return mapper;
	}
	for (i = 0; i < ARRAY_SIZE(backend_to_wsp); i++) {
		add_property_conv(mapper,
			backend_to_wsp[i].name,
			backend_to_wsp[i].conv_fn);
	}
	/* add default conv functions */
	return mapper;
}

void initialise_elastic_conv(void)
{
	register_backend_impl(WSP_BACKEND_ELASTIC,
			es_wsp_conv_ops(),
			NULL);
}

static bool build_es_mapper(TALLOC_CTX *ctx,
		struct wsp_ctablecolumn *columns,
		uint32_t ncols,
		struct backend_selected_cols *selected_cols,
		struct binding_result_mapper *mapper)
{
	/* map of name => wsp_to_backend conversion functions */
	struct column_mapper *col_conversions = NULL;

	col_conversions = init_convert_map(ctx, "elastic");
	if (col_conversions == NULL) {
		DBG_ERR("Failed to initialise default conversions\n");
		return false;
	}

	return true;
}

struct query_conv_ops *es_wsp_conv_ops(void)
{
	static struct query_conv_ops ops = {
		.bld_mapper = build_es_mapper,
		.bld_query = NULL,
		.bld_lookup_whereid = NULL,
	};
	return &ops;
}

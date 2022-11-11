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

#include "includes.h"
#include "wsp_backend.h"

struct backend_info {
	struct backend_info *prev, *next;
	int id;
	struct query_conv_ops *ops;
	struct wsp_abstract_interface *backend_if;
};

static struct backend_info *backend_map = NULL;

static struct backend_info *find_backend(int backend)
{
	struct backend_info *item = NULL;

	for (item = backend_map; item; item = item->next) {
		if (item->id == backend) {
			return item;
		}
	}
	return NULL;
}

bool register_backend_impl(int backend_id,
			struct query_conv_ops *ops,
			struct wsp_abstract_interface *backend_if)
{
	struct backend_info *item = NULL;

	/* see if it exists already */
	if (find_backend(backend_id)) {
		DBG_ERR("WSP backend %d already registered\n",
			backend_id);
		return false;
	}

	item = talloc_zero(NULL, struct backend_info);
	if (item == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}
	item->id = backend_id;
	item->ops = ops;
	item->backend_if = backend_if;
	DLIST_ADD_END(backend_map, item);

	return true;
}

/*
 * Think about maybe incorporating a more dynamic backend
 * infra e.g. discovery of shared libraries to be loaded
 * and find a specific symbol.
 * At the moment though lets just deal with (pre)defined backends
 */

struct wsp_abstract_interface *get_backend_impl(int backend_id)
{
	struct backend_info *backend_info = NULL;

	backend_info = find_backend(backend_id);
	if (backend_info == NULL) {
		return NULL;
	}
	return backend_info->backend_if;
}

struct query_conv_ops *get_query_conv_ops(int backend_id)
{
	struct backend_info *backend_info = NULL;

	backend_info = find_backend(backend_id);
	if (backend_info == NULL) {
		return NULL;
	}
	return backend_info->ops;
}

const char *get_backend_conv_fn_name(const char *wsp_prop,
			struct prop_data *prop_data)
{
	int i;

	for (i = 0; i < prop_data->num; i++) {
		if (strequal(wsp_prop, prop_data->detail[i].wsp_prop)) {
			return prop_data->detail[i].conv_fn;
		}
	}
	return NULL;
}

backend_to_wsp_fn get_property_conv(struct column_mapper *mapper,
			const char *name)
{
	struct col_conv_list_item *item = NULL;

	for (item = mapper->prop_conv_list; item != NULL; item = item->next) {
		if (strequal(item->col_conv_name, name)) {
			return item->conv_fn;
		}
	}
	return NULL;
}

void *get_property_calling_ctx(struct column_mapper *mapper,
			       const char *name)
{
        struct col_conv_list_item *item = NULL;

	for (item = mapper->prop_conv_list; item != NULL; item = item->next) {
                if (strequal(item->col_conv_name, name)) {
                        return item->calling_ctx;
                }
        }
        return NULL;
}


const char *get_backend_prop_name(const char *wsp_prop,
				  struct prop_data *prop_data)
{
	int i;

	for (i = 0; i < prop_data->num; i++) {
		if (strequal(wsp_prop, prop_data->detail[i].wsp_prop)) {
			return prop_data->detail[i].backend_prop;
		}
	}
	return NULL;
}

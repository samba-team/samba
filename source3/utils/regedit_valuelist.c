/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2012
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

#include "regedit_valuelist.h"
#include "lib/registry/registry.h"

static void value_list_free_items(ITEM **items)
{
	size_t i;
	ITEM *item;
	struct value_item *vitem;

	if (items == NULL) {
		return;
	}

	for (i = 0; items[i] != NULL; ++i) {
		item = items[i];
		vitem = item_userptr(item);
		SMB_ASSERT(vitem != NULL);
		free_item(item);
	}

	talloc_free(items);
}

static int value_list_free(struct value_list *vl)
{
	if (vl->menu) {
		unpost_menu(vl->menu);
		free_menu(vl->menu);
	}
	if (vl->empty && vl->empty[0]) {
		free_item(vl->empty[0]);
	}
	value_list_free_items(vl->items);

	return 0;
}

struct value_list *value_list_new(TALLOC_CTX *ctx, WINDOW *orig, int nlines,
				  int ncols, int begin_y, int begin_x)
{
	static const char *empty = "(no values)";
	static const char *empty_desc = "";
	struct value_list *vl;

	vl = talloc_zero(ctx, struct value_list);
	if (vl == NULL) {
		return NULL;
	}

	talloc_set_destructor(vl, value_list_free);

	vl->empty = talloc_zero_array(vl, ITEM *, 2);
	if (vl->empty == NULL) {
		goto fail;
	}
	vl->empty[0] = new_item(empty, empty_desc);
	if (vl->empty[0] == NULL) {
		goto fail;
	}

	vl->window = orig;
	vl->sub_window = derwin(orig, nlines, ncols, begin_y, begin_x);

	vl->menu = new_menu(vl->empty);
	if (vl->menu == NULL) {
		goto fail;
	}

	set_menu_format(vl->menu, nlines, 1);
	set_menu_win(vl->menu, vl->window);
	set_menu_sub(vl->menu, vl->sub_window);
	menu_opts_on(vl->menu, O_SHOWDESC);
	set_menu_mark(vl->menu, "* ");

	return vl;

fail:
	talloc_free(vl);

	return NULL;
}

static uint32_t get_num_values(TALLOC_CTX *ctx, const struct registry_key *key)
{
	const char *classname;
	uint32_t num_subkeys;
	uint32_t num_values;
	NTTIME last_change_time;
	uint32_t max_subkeynamelen;
	uint32_t max_valnamelen;
	uint32_t max_valbufsize;
	WERROR rv;

	rv = reg_key_get_info(ctx, key, &classname, &num_subkeys,
			      &num_values, &last_change_time,
			      &max_subkeynamelen, &max_valnamelen,
			      &max_valbufsize);

	if (W_ERROR_IS_OK(rv)) {
		return num_values;
	}

	return 0;
}

void value_list_show(struct value_list *vl)
{
	post_menu(vl->menu);
}

static WERROR append_data_summary(struct value_item *vitem)
{
	char *tmp;

/* This is adapted from print_registry_value() in net_registry_util.c */

	switch(vitem->type) {
	case REG_DWORD: {
		uint32_t v = 0;
		if (vitem->data.length >= 4) {
			v = IVAL(vitem->data.data, 0);
		}
		tmp = talloc_asprintf_append(vitem->value_desc, "(0x%x)", v);
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		const char *s;

		if (!pull_reg_sz(vitem, &vitem->data, &s)) {
			break;
		}
		tmp = talloc_asprintf_append(vitem->value_desc, "(\"%s\")", s);
		break;
	}
	case REG_MULTI_SZ: {
		size_t i;
		const char **a;

		if (!pull_reg_multi_sz(vitem, &vitem->data, &a)) {
			break;
		}
		tmp = vitem->value_desc;
		for (i = 0; a[i] != NULL; ++i) {
			tmp = talloc_asprintf_append(tmp, "\"%s\" ", a[i]);
			if (tmp == NULL) {
				return WERR_NOMEM;
			}
		}
		break;
	}
	case REG_BINARY:
		tmp = talloc_asprintf_append(vitem->value_desc, "(%d bytes)",
					     (int)vitem->data.length);
		break;
	default:
		tmp = talloc_asprintf_append(vitem->value_desc,
					     "(<unprintable>)");
		break;
	}

	if (tmp == NULL) {
		return WERR_NOMEM;
	}

	vitem->value_desc = tmp;

	return WERR_OK;
}

WERROR value_list_load(struct value_list *vl, struct registry_key *key)
{
	uint32_t n_values;
	uint32_t idx;
	struct value_item *vitem;
	ITEM **new_items;
	WERROR rv;

	unpost_menu(vl->menu);

	n_values = get_num_values(vl, key);
	if (n_values == 0) {
		set_menu_items(vl->menu, vl->empty);
		return WERR_OK;
	}

	new_items = talloc_zero_array(vl, ITEM *, n_values + 1);
	if (new_items == NULL) {
		return WERR_NOMEM;
	}

	for (idx = 0; idx < n_values; ++idx) {
		vitem = talloc_zero(new_items, struct value_item);
		if (vitem == NULL) {
			return WERR_NOMEM;
		}

		rv = reg_key_get_value_by_index(vitem, key, idx,
						&vitem->value_name,
						&vitem->type,
						&vitem->data);

		if (!W_ERROR_IS_OK(rv)) {
			talloc_free(vitem);
			return rv;
		}

		vitem->value_desc = talloc_asprintf(vitem, "%-8s",
			str_regtype(vitem->type));
		if (vitem->value_desc == NULL) {
			talloc_free(vitem);
			return rv;
		}

		rv = append_data_summary(vitem);
		if (!W_ERROR_IS_OK(rv)) {
			talloc_free(vitem);
			return rv;
		}

		new_items[idx] = new_item(vitem->value_name,
					  vitem->value_desc);
		set_item_userptr(new_items[idx], vitem);
	}

	set_menu_items(vl->menu, new_items);
	value_list_free_items(vl->items);
	vl->items = new_items;

	return WERR_OK;
}

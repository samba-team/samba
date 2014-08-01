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

#include "includes.h"
#include "regedit.h"
#include "regedit_valuelist.h"
#include "regedit_list.h"
#include "lib/registry/registry.h"

#define HEADING_X 3

static int value_list_free(struct value_list *vl)
{
	if (vl->panel) {
		del_panel(vl->panel);
	}
	if (vl->sub) {
		delwin(vl->sub);
	}
	if (vl->window) {
		delwin(vl->window);
	}

	return 0;
}

static const char *vl_get_column_header(const void *data, unsigned col)
{
	switch (col) {
	case 0:
		return "Name";
	case 1:
		return "Type";
	case 2:
		return "Data";
	}

	return "???";
}

static const void *vl_get_first_row(const void *data)
{
	const struct value_list *vl;

	if (data) {
		vl = talloc_get_type_abort(data, struct value_list);
		if (vl->nvalues) {
			return &vl->values[0];
		}
	}

	return NULL;
}

static const void *vl_get_next_row(const void *data, const void *row)
{
	const struct value_list *vl;
	const struct value_item *value = row;

	SMB_ASSERT(data != NULL);
	SMB_ASSERT(value != NULL);
	vl = talloc_get_type_abort(data, struct value_list);
	if (value == &vl->values[vl->nvalues - 1]) {
		return NULL;
	}

	return value + 1;
}

static const void *vl_get_prev_row(const void *data, const void *row)
{
	const struct value_list *vl;
	const struct value_item *value = row;

	SMB_ASSERT(data != NULL);
	SMB_ASSERT(value != NULL);
	vl = talloc_get_type_abort(data, struct value_list);
	if (value == &vl->values[0]) {
		return NULL;
	}

	return value - 1;
}

static const char *vl_get_item_label(const void *row, unsigned col)
{
	const struct value_item *value = row;

	SMB_ASSERT(value != NULL);
	SMB_ASSERT(value->value_name != NULL);
	switch (col) {
	case 0:
		return value->value_name;
	case 1:
		return str_regtype(value->type);
	case 2:
		if (value->value) {
			return value->value;
		}
		return "";
	}

	return "???";
}

static struct multilist_accessors vl_accessors = {
	.get_column_header = vl_get_column_header,
	.get_first_row = vl_get_first_row,
	.get_next_row = vl_get_next_row,
	.get_prev_row = vl_get_prev_row,
	.get_item_label = vl_get_item_label
};

struct value_list *value_list_new(TALLOC_CTX *ctx, int nlines, int ncols,
				  int begin_y, int begin_x)
{
	struct value_list *vl;

	vl = talloc_zero(ctx, struct value_list);
	if (vl == NULL) {
		return NULL;
	}

	talloc_set_destructor(vl, value_list_free);

	vl->window = newwin(nlines, ncols, begin_y, begin_x);
	if (vl->window == NULL) {
		goto fail;
	}
	vl->sub = subwin(vl->window, nlines - 2, ncols - 2,
			 begin_y + 1, begin_x + 1);
	if (vl->sub == NULL) {
		goto fail;
	}
	box(vl->window, 0, 0);
	mvwprintw(vl->window, 0, HEADING_X, "Value");

	vl->panel = new_panel(vl->window);
	if (vl->panel == NULL) {
		goto fail;
	}

	vl->list = multilist_new(vl, vl->sub, &vl_accessors, 3);
	if (vl->list == NULL) {
		goto fail;
	}

	return vl;

fail:
	talloc_free(vl);

	return NULL;
}

void value_list_set_selected(struct value_list *vl, bool select)
{
	attr_t attr = A_NORMAL;

	if (select) {
		attr = A_REVERSE;
	}
	mvwchgat(vl->window, 0, HEADING_X, 5, attr, 0, NULL);
}

void value_list_resize(struct value_list *vl, int nlines, int ncols,
		       int begin_y, int begin_x)
{
	WINDOW *nwin, *nsub;

	nwin = newwin(nlines, ncols, begin_y, begin_x);
	if (nwin == NULL) {
		return;
	}
	nsub = subwin(nwin, nlines - 2, ncols - 2, begin_y + 1, begin_x + 1);
	if (nsub == NULL) {
		delwin(nwin);
		return;
	}
	replace_panel(vl->panel, nwin);
	delwin(vl->sub);
	delwin(vl->window);
	vl->window = nwin;
	vl->sub = nsub;
	box(vl->window, 0, 0);
	mvwprintw(vl->window, 0, HEADING_X, "Value");
	multilist_set_window(vl->list, vl->sub);
	value_list_show(vl);
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
	multilist_refresh(vl->list);
	touchwin(vl->window);
	wnoutrefresh(vl->window);
	wnoutrefresh(vl->sub);
}

static bool string_is_printable(const char *s)
{
	const char *p;

	for (p = s; *p; ++p) {
		if (!isprint(*p)) {
			return false;
		}
	}

	return true;
}

static WERROR append_data_summary(TALLOC_CTX *ctx, struct value_item *vitem)
{
	char *tmp = NULL;

/* This is adapted from print_registry_value() in net_registry_util.c */

	switch(vitem->type) {
	case REG_DWORD: {
		uint32_t v = 0;
		if (vitem->data.length >= 4) {
			v = IVAL(vitem->data.data, 0);
		}
		tmp = talloc_asprintf(ctx, "0x%08x (%u)", v, v);
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		const char *s;

		if (!pull_reg_sz(ctx, &vitem->data, &s)) {
			break;
		}
		vitem->unprintable = !string_is_printable(s);
		if (vitem->unprintable) {
			tmp = talloc_asprintf(ctx, "(unprintable)");
		} else {
			tmp = talloc_asprintf(ctx, "%s", s);
		}
		break;
	}
	case REG_MULTI_SZ: {
		size_t i, len;
		const char **a;
		const char *val;

		if (!pull_reg_multi_sz(ctx, &vitem->data, &a)) {
			break;
		}
		for (len = 0; a[len] != NULL; ++len) {
		}
		tmp = talloc_asprintf(ctx, "(%u) ", (unsigned)len);
		if (tmp == NULL) {
			return WERR_NOMEM;
		}
		for (i = 0; i < len; ++i) {
			if (!string_is_printable(a[i])) {
				val = "(unprintable)";
				vitem->unprintable = true;
			} else {
				val = a[i];
			}
			if (i == len - 1) {
				tmp = talloc_asprintf_append(tmp,
							     "[%u]=\"%s\"",
							     (unsigned)i, val);
			} else {
				tmp = talloc_asprintf_append(tmp,
							     "[%u]=\"%s\", ",
							     (unsigned)i, val);
			}
			if (tmp == NULL) {
				return WERR_NOMEM;
			}
		}
		break;
	}
	case REG_BINARY:
		tmp = talloc_asprintf(ctx, "(%d bytes)",
				      (int)vitem->data.length);
		break;
	default:
		tmp = talloc_asprintf(ctx, "(unknown)");
		break;
	}

	if (tmp == NULL) {
		return WERR_NOMEM;
	}

	vitem->value = tmp;

	return WERR_OK;
}

static int vitem_cmp(struct value_item *a, struct value_item *b)
{
	return strcmp(a->value_name, b->value_name);
}

/* load only the value names into memory to enable searching */
WERROR value_list_load_quick(struct value_list *vl, struct registry_key *key)
{
	uint32_t nvalues;
	uint32_t idx;
	struct value_item *vitem, *new_items;
	WERROR rv;

	multilist_set_data(vl->list, NULL);
	vl->nvalues = 0;
	TALLOC_FREE(vl->values);

	nvalues = get_num_values(vl, key);
	if (nvalues == 0) {
		return WERR_OK;
	}

	new_items = talloc_zero_array(vl, struct value_item, nvalues);
	if (new_items == NULL) {
		return WERR_NOMEM;
	}

	for (idx = 0; idx < nvalues; ++idx) {
		vitem = &new_items[idx];
		rv = reg_key_get_value_by_index(new_items, key, idx,
						&vitem->value_name,
						&vitem->type,
						&vitem->data);
		if (!W_ERROR_IS_OK(rv)) {
			talloc_free(new_items);
			return rv;
		}
	}

	TYPESAFE_QSORT(new_items, nvalues, vitem_cmp);
	vl->nvalues = nvalues;
	vl->values = new_items;

	return rv;
}

/* sync up the UI with the list */
WERROR value_list_sync(struct value_list *vl)
{
	uint32_t idx;
	WERROR rv;

	for (idx = 0; idx < vl->nvalues; ++idx) {
		rv = append_data_summary(vl->values, &vl->values[idx]);
		if (!W_ERROR_IS_OK(rv)) {
			return rv;
		}
	}

	rv = multilist_set_data(vl->list, vl);
	if (W_ERROR_IS_OK(rv)) {
		multilist_refresh(vl->list);
	}

	return rv;
}

WERROR value_list_load(struct value_list *vl, struct registry_key *key)
{
	WERROR rv;

	rv = value_list_load_quick(vl, key);
	if (!W_ERROR_IS_OK(rv)) {
		return rv;
	}

	rv = value_list_sync(vl);

	return rv;
}

struct value_item *value_list_find_next_item(struct value_list *vl,
					     struct value_item *vitem,
					     const char *s,
					     regedit_search_match_fn_t match)
{
	struct value_item *end;

	if (!vl->values) {
		return NULL;
	}

	if (vitem) {
		++vitem;
	} else {
		vitem = &vl->values[0];
	}

	for (end = &vl->values[vl->nvalues]; vitem < end; ++vitem) {
		if (match(vitem->value_name, s)) {
			return vitem;
		}
	}

	return NULL;
}

struct value_item *value_list_find_prev_item(struct value_list *vl,
					     struct value_item *vitem,
					     const char *s,
					     regedit_search_match_fn_t match)
{
	struct value_item *end;

	if (!vl->values) {
		return NULL;
	}

	if (vitem) {
		--vitem;
	} else {
		vitem = &vl->values[vl->nvalues - 1];
	}

	for (end = &vl->values[-1]; vitem > end; --vitem) {
		if (match(vitem->value_name, s)) {
			return vitem;
		}
	}

	return NULL;
}

struct value_item *value_list_get_current_item(struct value_list *vl)
{
	return discard_const_p(struct value_item,
			       multilist_get_current_row(vl->list));
}

void value_list_set_current_item_by_name(struct value_list *vl,
					 const char *name)
{
	size_t i;

	for (i = 0; i < vl->nvalues; ++i) {
		if (strequal(vl->values[i].value_name, name)) {
			multilist_set_current_row(vl->list, &vl->values[i]);
			return;
		}
	}
}

void value_list_set_current_item(struct value_list *vl,
				 const struct value_item *item)
{
	multilist_set_current_row(vl->list, item);
}

void value_list_driver(struct value_list *vl, int c)
{
	multilist_driver(vl->list, c);
}

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

#ifndef _REGEDIT_VALUELIST_H_
#define _REGEDIT_VALUELIST_H_

#include <ncurses.h>
#include <panel.h>

struct registry_key;

struct value_item {
	uint32_t type;
	DATA_BLOB data;
	const char *value_name;
	char *value;
	bool unprintable;
};

struct multilist;

struct value_list {
	WINDOW *window;
	WINDOW *sub;
	PANEL *panel;
	size_t nvalues;
	struct value_item *values;
	struct multilist *list;
};
struct value_list *value_list_new(TALLOC_CTX *ctx, int nlines, int ncols,
				  int begin_y, int begin_x);
void value_list_show(struct value_list *vl);
void value_list_set_selected(struct value_list *vl, bool select);
const char **value_list_load_names(TALLOC_CTX *ctx, struct registry_key *key);
WERROR value_list_load(struct value_list *vl, struct registry_key *key);
void value_list_resize(struct value_list *vl, int nlines, int ncols,
		       int begin_y, int begin_x);
struct value_item *value_list_get_current_item(struct value_list *vl);
void value_list_set_current_item(struct value_list *vl,
				 const struct value_item *item);
void value_list_set_current_item_by_name(struct value_list *vl,
					 const char *name);
void value_list_driver(struct value_list *vl, int c);

WERROR value_list_load_quick(struct value_list *vl, struct registry_key *key);
WERROR value_list_sync(struct value_list *vl);
struct value_item *value_list_find_next_item(struct value_list *vl,
					     struct value_item *vitem,
					     const char *s,
					     regedit_search_match_fn_t match);
struct value_item *value_list_find_prev_item(struct value_list *vl,
					     struct value_item *vitem,
					     const char *s,
					     regedit_search_match_fn_t match);

#endif

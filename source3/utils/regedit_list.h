/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2014
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

#ifndef _REGEDIT_LIST_H_
#define _REGEDIT_LIST_H_

#include "includes.h"
#include <ncurses.h>

struct multilist_accessors {
	/* (optional) return the column header for col */
	const char *(*get_column_header)(const void *data, unsigned col);

	/* return a pointer to the first row of data */
	const void *(*get_first_row)(const void *data);

	/* (optional) return a count of all data rows */
	size_t (*get_row_count)(const void *data);

	/* return the next row or NULL if there aren't any more */
	const void *(*get_next_row)(const void *data, const void *row);

	/* (optional) return the previous row or NULL if row is on top. */
	const void *(*get_prev_row)(const void *data, const void *row);

	/* (optional) return row n of data */
	const void *(*get_row_n)(const void *data, size_t n);

	/* return the label for row and col */
	const char *(*get_item_label)(const void *row, unsigned col);

	/* (optional) return a prefix string to be prepended to an item's
	   label. */
	const char *(*get_item_prefix)(const void *row, unsigned col);
};

struct multilist_column {
	size_t width;
	unsigned int align_right:1;
};

struct multilist;

struct multilist *multilist_new(TALLOC_CTX *ctx, WINDOW *window,
				const struct multilist_accessors *cb,
				unsigned ncol);
struct multilist_column *multilist_column_config(struct multilist *list,
						 unsigned col);
WERROR multilist_set_window(struct multilist *list, WINDOW *window);
const void *multilist_get_data(struct multilist *list);
WERROR multilist_set_data(struct multilist *list, const void *data);
void multilist_refresh(struct multilist *list);

enum {
	ML_CURSOR_UP,
	ML_CURSOR_DOWN,
	ML_CURSOR_PGUP,
	ML_CURSOR_PGDN,
	ML_CURSOR_HOME,
	ML_CURSOR_END
};
void multilist_driver(struct multilist *list, int c);
const void *multilist_get_current_row(struct multilist *list);
void multilist_set_current_row(struct multilist *list, const void *row);

#endif

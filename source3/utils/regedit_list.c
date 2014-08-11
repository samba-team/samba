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

#include "regedit_list.h"
#include "regedit.h"

struct multilist {
	WINDOW *window;
	WINDOW *pad;

	unsigned window_height;
	unsigned window_width;
	unsigned start_row;
	unsigned cursor_row;

	unsigned ncols;
	struct multilist_column *columns;

	const void *data;
	unsigned nrows;
	const void *current_row;
	const struct multilist_accessors *cb;
};

/* data getters */
static const void *data_get_first_row(struct multilist *list)
{
	SMB_ASSERT(list->cb->get_first_row);
	return list->cb->get_first_row(list->data);
}

static const void *data_get_next_row(struct multilist *list, const void *row)
{
	SMB_ASSERT(list->cb->get_next_row);
	return list->cb->get_next_row(list->data, row);
}

static const void *data_get_prev_row(struct multilist *list, const void *row)
{
	const void *tmp, *next;

	if (list->cb->get_prev_row) {
		return list->cb->get_prev_row(list->data, row);
	}

	tmp = data_get_first_row(list);
	if (tmp == row) {
		return NULL;
	}

	for (; tmp && (next = data_get_next_row(list, tmp)) != row;
	     tmp = next) {
	}

	SMB_ASSERT(tmp != NULL);

	return tmp;
}

static unsigned data_get_row_count(struct multilist *list)
{
	unsigned i;
	const void *row;

	if (list->cb->get_row_count)
		return list->cb->get_row_count(list->data);

	for (i = 0, row = data_get_first_row(list);
	     row != NULL;
	     ++i, row = data_get_next_row(list, row)) {
	}

	return i;
}

static const void *data_get_row_n(struct multilist *list, size_t n)
{
	unsigned i;
	const void *row;

	if (list->cb->get_row_n)
		return list->cb->get_row_n(list->data, n);

	for (i = 0, row = data_get_first_row(list);
	     i < n && row != NULL;
	     ++i, row = data_get_next_row(list, row)) {
	}

	return row;
}

static const char *data_get_column_header(struct multilist *list, unsigned col)
{
	SMB_ASSERT(list->cb->get_column_header);
	return list->cb->get_column_header(list->data, col);
}

static const char *data_get_item_label(struct multilist *list, const void *row,
				       unsigned col)
{
	SMB_ASSERT(list->cb->get_item_label);
	return list->cb->get_item_label(row, col);
}

static const char *data_get_item_prefix(struct multilist *list, const void *row,
					unsigned col)
{
	if (list->cb->get_item_prefix)
		return list->cb->get_item_prefix(row, col);
	return "";
}

static int multilist_free(struct multilist *list)
{
	if (list->pad) {
		delwin(list->pad);
	}

	return 0;
}

struct multilist *multilist_new(TALLOC_CTX *ctx, WINDOW *window,
				const struct multilist_accessors *cb,
				unsigned ncol)
{
	struct multilist *list;

	SMB_ASSERT(ncol > 0);

	list = talloc_zero(ctx, struct multilist);
	if (list == NULL) {
		return NULL;
	}
	talloc_set_destructor(list, multilist_free);

	list->cb = cb;
	list->ncols = ncol;
	list->columns = talloc_zero_array(list, struct multilist_column, ncol);
	if (list->columns == NULL) {
		talloc_free(list);
		return NULL;
	}
	multilist_set_window(list, window);

	return list;
}

struct multilist_column *multilist_column_config(struct multilist *list,
						 unsigned col)
{
	SMB_ASSERT(col < list->ncols);
	return &list->columns[col];
}

static void put_padding(WINDOW *win, size_t col_width, size_t item_len)
{
	size_t amt;

	SMB_ASSERT(item_len <= col_width);

	amt = col_width - item_len;
	while (amt--) {
		waddch(win, ' ');
	}
}

static void put_item(struct multilist *list, WINDOW *win, unsigned col,
		     const char *item, int attr)
{
	bool append_sep = true;
	unsigned i;
	size_t len;
	struct multilist_column *col_info;
	bool trim = false;

	SMB_ASSERT(col < list->ncols);
	SMB_ASSERT(item != NULL);

	if (col == list->ncols - 1) {
		append_sep = false;
	}
	col_info = &list->columns[col];

	len = strlen(item);
	if (len > col_info->width) {
		len = col_info->width;
		trim = true;
	}

	if (col_info->align_right) {
		put_padding(win, col_info->width, len);
	}
	for (i = 0; i < len; ++i) {
		if (i == len - 1 && trim) {
			waddch(win, '~' | attr);
		} else {
			waddch(win, item[i] | attr);
		}
	}
	if (!col_info->align_right) {
		put_padding(win, col_info->width, len);
	}

	if (append_sep) {
		waddch(win, ' ');
		waddch(win, '|');
		waddch(win, ' ');
	}
}

static void put_header(struct multilist *list)
{
	unsigned col;
	const char *header;

	if (!list->cb->get_column_header) {
		return;
	}

	wmove(list->window, 0, 0);
	for (col = 0; col < list->ncols; ++col) {
		header = data_get_column_header(list, col);
		SMB_ASSERT(header != NULL);
		put_item(list, list->window, col, header,
			 A_BOLD | COLOR_PAIR(PAIR_YELLOW_BLUE));
	}
}

static WERROR put_data(struct multilist *list)
{
	const void *row;
	int ypos;
	unsigned col;
	const char *prefix, *item;
	char *tmp;

	for (ypos = 0, row = data_get_first_row(list);
	     row != NULL;
	     row = data_get_next_row(list, row), ++ypos) {
		wmove(list->pad, ypos, 0);
		for (col = 0; col < list->ncols; ++col) {
			prefix = data_get_item_prefix(list, row, col);
			SMB_ASSERT(prefix != NULL);
			item = data_get_item_label(list, row, col);
			SMB_ASSERT(item != NULL);
			tmp = talloc_asprintf(list, "%s%s", prefix, item);
			if (tmp == NULL) {
				return WERR_NOMEM;
			}
			put_item(list, list->pad, col, tmp, 0);
			talloc_free(tmp);
		}
	}

	return WERR_OK;
}

#define MIN_WIDTH 3
static struct multilist_column *find_widest_column(struct multilist *list)
{
	unsigned col;
	struct multilist_column *colp;

	SMB_ASSERT(list->ncols > 0);
	colp = &list->columns[0];

	for (col = 1; col < list->ncols; ++col) {
		if (list->columns[col].width > colp->width) {
			colp = &list->columns[col];
		}
	}

	if (colp->width < MIN_WIDTH) {
		return NULL;
	}

	return colp;
}

static WERROR calc_column_widths(struct multilist *list)
{
	const void *row;
	unsigned col;
	size_t len;
	const char *item;
	size_t width, total_width, overflow;
	struct multilist_column *colp;

	/* calculate the maximum widths for each column */
	for (col = 0; col < list->ncols; ++col) {
		len = 0;
		if (list->cb->get_column_header) {
			item = data_get_column_header(list, col);
			len = strlen(item);
		}
		list->columns[col].width = len;
	}

	for (row = data_get_first_row(list);
	     row != NULL;
	     row = data_get_next_row(list, row)) {
		for (col = 0; col < list->ncols; ++col) {
			item = data_get_item_prefix(list, row, col);
			SMB_ASSERT(item != NULL);
			len = strlen(item);

			item = data_get_item_label(list, row, col);
			SMB_ASSERT(item != NULL);
			len += strlen(item);
			if (len > list->columns[col].width) {
				list->columns[col].width = len;
			}
		}
	}

	/* calculate row width */
	for (width = 0, col = 0; col < list->ncols; ++col) {
		width += list->columns[col].width;
	}
	/* width including column spacing and separations */
	total_width = width + (list->ncols - 1) * 3;
	/* if everything fits, we're done */
	if (total_width <= list->window_width) {
		return WERR_OK;
	}

	overflow = total_width - list->window_width;

	/* attempt to trim as much as possible to fit all the columns to
	   the window */
	while (overflow && (colp = find_widest_column(list))) {
		colp->width--;
		overflow--;
	}

	return WERR_OK;
}

static void highlight_current_row(struct multilist *list)
{
	mvwchgat(list->pad, list->cursor_row, 0, -1, A_REVERSE, 0, NULL);
}

static void unhighlight_current_row(struct multilist *list)
{
	mvwchgat(list->pad, list->cursor_row, 0, -1, A_NORMAL, 0, NULL);
}

const void *multilist_get_data(struct multilist *list)
{
	return list->data;
}

WERROR multilist_set_data(struct multilist *list, const void *data)
{
	WERROR rv;

	SMB_ASSERT(list->window != NULL);
	list->data = data;

	calc_column_widths(list);

	if (list->pad) {
		delwin(list->pad);
	}
	/* construct a pad that is exactly the width of the window, and
	   as tall as required to fit all data rows. */
	list->nrows = data_get_row_count(list);
	list->pad = newpad(MAX(list->nrows, 1), list->window_width);
	if (list->pad == NULL) {
		return WERR_NOMEM;
	}

	/* add the column headers to the window and render all rows to
	   the pad. */
	werase(list->window);
	put_header(list);
	rv = put_data(list);
	if (!W_ERROR_IS_OK(rv)) {
		return rv;
	}

	/* initialize the cursor */
	list->start_row = 0;
	list->cursor_row = 0;
	list->current_row = data_get_first_row(list);
	highlight_current_row(list);

	return WERR_OK;
}

static int get_window_height(struct multilist *list)
{
	int height;

	height = list->window_height;
	if (list->cb->get_column_header) {
		height--;
	}

	return height;
}

static void fix_start_row(struct multilist *list)
{
	int height;

	/* adjust start_row so that the cursor appears on the screen */

	height = get_window_height(list);
	if (list->cursor_row < list->start_row) {
		list->start_row = list->cursor_row;
	} else if (list->cursor_row >= list->start_row + height) {
		list->start_row = list->cursor_row - height + 1;
	}
	if (list->nrows > height && list->nrows - list->start_row < height) {
		list->start_row = list->nrows - height;
	}
}

WERROR multilist_set_window(struct multilist *list, WINDOW *window)
{
	int maxy, maxx;
	bool rerender = false;

	getmaxyx(window, maxy, maxx);

	/* rerender pad if window width is different. */
	if (list->data && maxx != list->window_width) {
		rerender = true;
	}

	list->window = window;
	list->window_width = maxx;
	list->window_height = maxy;
	list->start_row = 0;
	if (rerender) {
		const void *row = multilist_get_current_row(list);
		WERROR rv = multilist_set_data(list, list->data);
		if (W_ERROR_IS_OK(rv) && row) {
			multilist_set_current_row(list, row);
		}
		return rv;
	} else {
		put_header(list);
		fix_start_row(list);
	}

	return WERR_OK;
}

void multilist_refresh(struct multilist *list)
{
	int window_start_row, height;

	if (list->nrows == 0) {
		return;
	}

	/* copy from pad, starting at start_row, to the window, accounting
	   for the column header (if present). */
	height = MIN(list->window_height, list->nrows);
	window_start_row = 0;
	if (list->cb->get_column_header) {
		window_start_row = 1;
		if (height < list->window_height) {
			height++;
		}
	}
	copywin(list->pad, list->window, list->start_row, 0,
		window_start_row, 0, height - 1, list->window_width - 1,
		false);
}

void multilist_driver(struct multilist *list, int c)
{
	unsigned page;
	const void *tmp;

	if (list->nrows == 0) {
		return;
	}

	switch (c) {
	case ML_CURSOR_UP:
		if (list->cursor_row == 0) {
			return;
		}
		unhighlight_current_row(list);
		list->cursor_row--;
		tmp = data_get_prev_row(list, list->current_row);
		break;
	case ML_CURSOR_DOWN:
		if (list->cursor_row == list->nrows - 1) {
			return;
		}
		unhighlight_current_row(list);
		list->cursor_row++;
		tmp = data_get_next_row(list, list->current_row);
		break;
	case ML_CURSOR_PGUP:
		if (list->cursor_row == 0) {
			return;
		}
		unhighlight_current_row(list);
		page = get_window_height(list);
		if (page > list->cursor_row) {
			list->cursor_row = 0;
		} else {
			list->cursor_row -= page;
			list->start_row -= page;
		}
		tmp = data_get_row_n(list, list->cursor_row);
		break;
	case ML_CURSOR_PGDN:
		if (list->cursor_row == list->nrows - 1) {
			return;
		}
		unhighlight_current_row(list);
		page = get_window_height(list);
		if (page > list->nrows - list->cursor_row - 1) {
			list->cursor_row = list->nrows - 1;
		} else {
			list->cursor_row += page;
			list->start_row += page;
		}
		tmp = data_get_row_n(list, list->cursor_row);
		break;
	case ML_CURSOR_HOME:
		if (list->cursor_row == 0) {
			return;
		}
		unhighlight_current_row(list);
		list->cursor_row = 0;
		tmp = data_get_row_n(list, list->cursor_row);
		break;
	case ML_CURSOR_END:
		if (list->cursor_row == list->nrows - 1) {
			return;
		}
		unhighlight_current_row(list);
		list->cursor_row = list->nrows - 1;
		tmp = data_get_row_n(list, list->cursor_row);
		break;
	}

	SMB_ASSERT(tmp);
	list->current_row = tmp;
	highlight_current_row(list);
	fix_start_row(list);
}

const void *multilist_get_current_row(struct multilist *list)
{
	return list->current_row;
}

void multilist_set_current_row(struct multilist *list, const void *row)
{
	unsigned i;
	const void *tmp;

	for (i = 0, tmp = data_get_first_row(list);
	     tmp != NULL;
	     ++i, tmp = data_get_next_row(list, tmp)) {
		if (tmp == row) {
			unhighlight_current_row(list);
			list->cursor_row = i;
			list->current_row = row;
			highlight_current_row(list);
			fix_start_row(list);
			return;
		}
	}
}

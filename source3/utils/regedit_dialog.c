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
#include "regedit_dialog.h"
#include <stdarg.h>

static int dialog_free(struct dialog *dia)
{
	if (dia->window) {
		delwin(dia->window);
	}
	if (dia->sub_window) {
		delwin(dia->sub_window);
	}
	if (dia->panel) {
		del_panel(dia->panel);
	}
	if (dia->choices) {
		unpost_menu(dia->choices);
		free_menu(dia->choices);
	}
	if (dia->choice_items) {
		ITEM **it;
		for (it = dia->choice_items; *it != NULL; ++it) {
			free_item(*it);
		}
	}

	return 0;
}

struct dialog *dialog_new(TALLOC_CTX *ctx, const char *title, int nlines,
			  int ncols, int y, int x)
{
	struct dialog *dia;

	dia = talloc_zero(ctx, struct dialog);
	if (dia == NULL) {
		return NULL;
	}

	talloc_set_destructor(dia, dialog_free);

	dia->window = newwin(nlines, ncols, y, x);
	if (dia->window == NULL) {
		goto fail;
	}

	box(dia->window, 0, 0);
	mvwaddstr(dia->window, 0, 1, title);

	/* body of the dialog within the box outline */
	dia->sub_window = derwin(dia->window, nlines - 2, ncols - 2, 1, 1);
	if (dia->sub_window == NULL) {
		goto fail;
	}

	dia->panel = new_panel(dia->window);
	if (dia->panel == NULL) {
		goto fail;
	}

	return dia;

fail:
	talloc_free(dia);

	return NULL;

}

static void center_dialog_above_window(WINDOW *below, int *nlines, int *ncols,
				       int *y, int *x)
{
	int maxy, maxx;
	int centery, centerx;

	getmaxyx(below, maxy, maxx);

	centery = maxy / 2;
	centerx = maxx / 2;
	*y = 0;
	*x = 0;

	if (*nlines > maxy) {
		*nlines = maxy;
	}
	if (*ncols > maxx) {
		*ncols = maxx;
	}

	if (*nlines < centery) {
		*y = centery - *nlines;
	}
	if (*ncols < centerx) {
		*x = centerx - *ncols;
	}
}

struct dialog *dialog_center_new(TALLOC_CTX *ctx, const char *title, int nlines,
				 int ncols, WINDOW *below)
{
	int y, x;

	center_dialog_above_window(below, &nlines, &ncols, &y, &x);

	return dialog_new(ctx, title, nlines, ncols, y, x);
}

struct dialog *dialog_choice_new(TALLOC_CTX *ctx, const char *title,
				 const char **choices, int nlines,
				 int ncols, int y, int x)
{
	size_t nchoices, i;
	struct dialog *dia;

	dia = dialog_new(ctx, title, nlines, ncols, y, x);
	if (dia == NULL) {
		return NULL;
	}

	dia->menu_window = derwin(dia->sub_window, 1, ncols - 3,
				  nlines - 3, 0);
	if (dia->menu_window == NULL) {
		goto fail;
	}

	for (nchoices = 0; choices[nchoices] != NULL; ++nchoices)
		;
	dia->choice_items = talloc_zero_array(dia, ITEM *, nchoices + 1);
	if (dia->choice_items == NULL) {
		goto fail;
	}
	for (i = 0; i < nchoices; ++i) {
		char *desc = talloc_strdup(dia, choices[i]);
		if (desc == NULL) {
			goto fail;
		}
		dia->choice_items[i] = new_item(desc, desc);
		if (dia->choice_items[i] == NULL) {
			goto fail;
		}
		/* store choice index */
		set_item_userptr(dia->choice_items[i], (void*)(uintptr_t)i);
	}

	dia->choices = new_menu(dia->choice_items);
	if (dia->choices == NULL) {
		goto fail;
	}

	set_menu_format(dia->choices, 1, ncols);
	set_menu_win(dia->choices, dia->sub_window);
	set_menu_sub(dia->choices, dia->menu_window);
	menu_opts_off(dia->choices, O_SHOWDESC);
	set_menu_mark(dia->choices, "* ");
	post_menu(dia->choices);
	wmove(dia->sub_window, 0, 0);

	return dia;

fail:
	talloc_free(dia);

	return NULL;
}

struct dialog *dialog_choice_center_new(TALLOC_CTX *ctx, const char *title,
					const char **choices, int nlines,
					int ncols, WINDOW *below)
{
	int y, x;

	center_dialog_above_window(below, &nlines, &ncols, &y, &x);

	return dialog_choice_new(ctx, title, choices, nlines, ncols, y, x);
}

struct dialog *dialog_confirm_new(TALLOC_CTX *ctx, const char *title,
				  WINDOW *below, const char *msg, ...)
{
	va_list ap;
	struct dialog *dia;
	char *str;
	const char *choices[] = {
		"Ok",
		"Cancel",
		NULL
	};
	int width;

	va_start(ap, msg);
	str = talloc_vasprintf(ctx, msg, ap);
	va_end(ap);
	if (str == NULL) {
		return NULL;
	}

	width = strlen(str) + 2;

	dia = dialog_choice_center_new(ctx, title, choices, 5, width, below);
	if (dia == NULL) {
		return NULL;
	}

	waddstr(dia->sub_window, str);
	talloc_free(str);

	return dia;
}

void dialog_set_cb(struct dialog *dia, dialogfn fn, void *arg)
{
	dia->dialogcb = fn;
	dia->dialogarg = arg;
}

void dialog_driver(struct dialog *dia, enum dialog_op op)
{
	switch (op) {
	case DIALOG_LEFT:
		menu_driver(dia->choices, REQ_LEFT_ITEM);
		break;
	case DIALOG_RIGHT:
		menu_driver(dia->choices, REQ_RIGHT_ITEM);
		break;
	case DIALOG_ENTER:
		if (dia->dialogcb) {
			ITEM *item;
			int selection;

			item = current_item(dia->choices);
			selection = (int)(uintptr_t)item_userptr(item);
			dia->dialogcb(dia, selection, dia->dialogarg);
		}
		break;
	}
}

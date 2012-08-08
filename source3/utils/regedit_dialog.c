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
#include "regedit_valuelist.h"
#include "util_reg.h"
#include "lib/registry/registry.h"
#include <stdarg.h>
#include <form.h>

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

static int handle_menu_input(MENU *menu, int c)
{
	ITEM *item;

	switch (c) {
	case KEY_LEFT:
		menu_driver(menu, REQ_LEFT_ITEM);
		break;
	case KEY_RIGHT:
		menu_driver(menu, REQ_RIGHT_ITEM);
		break;
	case KEY_ENTER:
	case '\n':
		item = current_item(menu);
		return (int)(uintptr_t)item_userptr(item);
	}

	return -1;
}

int dialog_modal_loop(struct dialog *dia)
{
	int c;
	int selection = -1;

	keypad(dia->window, true);
	update_panels();
	doupdate();

	while (selection == -1) {
		c = wgetch(dia->window);
		selection = handle_menu_input(dia->choices, c);
		update_panels();
		doupdate();
	}

	talloc_free(dia);

	return selection;
}

static void handle_form_input(FORM *frm, int c)
{
	switch (c) {
	case '\n':
		form_driver(frm, REQ_NEW_LINE);
		break;
	case KEY_UP:
		form_driver(frm, REQ_UP_CHAR);
		break;
	case KEY_DOWN:
		form_driver(frm, REQ_DOWN_CHAR);
		break;
	case '\b':
	case KEY_BACKSPACE:
		form_driver(frm, REQ_DEL_PREV);
		break;
	case KEY_LEFT:
		form_driver(frm, REQ_LEFT_CHAR);
		break;
	case KEY_RIGHT:
		form_driver(frm, REQ_RIGHT_CHAR);
		break;
	default:
		form_driver(frm, c);
		break;
	}
}

#define MAX_FIELDS 8

enum input_section {
	IN_NAME,
	IN_DATA,
	IN_MENU
};

struct edit_dialog {
	struct dialog *dia;
	WINDOW *input_win;
	FORM *input;
	FIELD *field[MAX_FIELDS];
	enum input_section section;
};

static int edit_dialog_free(struct edit_dialog *edit)
{
	if (edit->input) {
		unpost_form(edit->input);
	}
	if (edit->field[0]) {
		free_field(edit->field[0]);
	}
	if (edit->field[1]) {
		free_field(edit->field[1]);
	}
	delwin(edit->input_win);

	return 0;
}

static WERROR fill_value_buffer(struct edit_dialog *edit,
			        const struct value_item *vitem)
{
	char *tmp;

	switch (vitem->type) {
	case REG_DWORD: {
		uint32_t v = 0;
		if (vitem->data.length >= 4) {
			v = IVAL(vitem->data.data, 0);
		}
		tmp = talloc_asprintf(edit, "0x%x", v);
		if (tmp == NULL) {
			return WERR_NOMEM;
		}
		set_field_buffer(edit->field[1], 0, tmp);
		talloc_free(tmp);
		set_field_type(edit->field[1], TYPE_REGEXP,
			       "^ *([0-9]+|0[xX][0-9a-fA-F]+) *$");
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		const char *s;

		if (!pull_reg_sz(edit, &vitem->data, &s)) {
			return WERR_NOMEM;
		}
		set_field_buffer(edit->field[1], 0, s);
		break;
	}
	case REG_MULTI_SZ: {
		const char **p, **a;
		char *buf = NULL;

		if (!pull_reg_multi_sz(edit, &vitem->data, &a)) {
			return WERR_NOMEM;
		}
		for (p = a; *p != NULL; ++p) {
			if (buf == NULL) {
				buf = talloc_asprintf(edit, "%s\n", *p);
			} else {
				buf = talloc_asprintf_append(buf, "%s\n", *p);
			}
			if (buf == NULL) {
				return WERR_NOMEM;
			}
		}
		set_field_buffer(edit->field[1], 0, buf);
		talloc_free(buf);
	}

	}

	return WERR_OK;
}

static char *string_trim_n(TALLOC_CTX *ctx, const char *buf, size_t n)
{
	char *str;

	str = talloc_strndup(ctx, buf, n);

	if (str) {
		trim_string(str, " ", " ");
	}

	return str;
}

static char *string_trim(TALLOC_CTX *ctx, const char *buf)
{
	char *str;

	str = talloc_strdup(ctx, buf);

	if (str) {
		trim_string(str, " ", " ");
	}

	return str;
}

static WERROR set_value(struct edit_dialog *edit, struct registry_key *key,
			uint32_t type)
{
	WERROR rv;
	DATA_BLOB blob;
	const char *buf = field_buffer(edit->field[1], 0);
	char *name = string_trim(edit, field_buffer(edit->field[0], 0));

	if (!buf) {
		return WERR_OK;
	}
	if (!field_status(edit->field[1])) {
		return WERR_OK;
	}

	switch (type) {
	case REG_DWORD: {
		uint32_t val;
		int base = 10;

		if (buf[0] == '0' && tolower(buf[1]) == 'x') {
			base = 16;
		}

		val = strtoul(buf, NULL, base);
		blob = data_blob_talloc(edit, NULL, sizeof(val));
		SIVAL(blob.data, 0, val);
		rv = WERR_OK;
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		char *str = string_trim(edit, buf);
		if (!str || !push_reg_sz(edit, &blob, str)) {
			rv = WERR_NOMEM;
		}
		break;
	}
	case REG_MULTI_SZ: {
		int rows, cols, max;
		const char **arr;
		size_t i;

		dynamic_field_info(edit->field[1], &rows, &cols, &max);

		arr = talloc_zero_array(edit, const char *, rows + 1);
		if (arr == NULL) {
			return WERR_NOMEM;
		}
		for (i = 0; *buf; ++i, buf += cols) {
			SMB_ASSERT(i < rows);
			arr[i] = string_trim_n(edit, buf, cols);
		}
		if (!push_reg_multi_sz(edit, &blob, arr)) {
			rv = WERR_NOMEM;
		}
		break;
	}
	}

	rv = reg_val_set(key, name, type, blob);

	return rv;
}

static void section_down(struct edit_dialog *edit)
{
	switch (edit->section) {
	case IN_NAME:
		if (form_driver(edit->input, REQ_VALIDATION) == E_OK) {
			edit->section = IN_DATA;
			set_current_field(edit->input, edit->field[1]);
		}
		break;
	case IN_DATA:
		if (form_driver(edit->input, REQ_VALIDATION) == E_OK) {
			edit->section = IN_MENU;
			menu_driver(edit->dia->choices, REQ_FIRST_ITEM);
		}
		break;
	case IN_MENU:
		edit->section = IN_NAME;
		set_current_field(edit->input, edit->field[0]);
		break;
	}
}

static void section_up(struct edit_dialog *edit)
{
	switch (edit->section) {
	case IN_NAME:
		if (form_driver(edit->input, REQ_VALIDATION) == E_OK) {
			edit->section = IN_MENU;
			menu_driver(edit->dia->choices, REQ_FIRST_ITEM);
		}
		break;
	case IN_DATA:
		if (form_driver(edit->input, REQ_VALIDATION) == E_OK) {
			edit->section = IN_NAME;
			set_current_field(edit->input, edit->field[0]);
		}
		break;
	case IN_MENU:
		edit->section = IN_DATA;
		set_current_field(edit->input, edit->field[1]);
		break;
	}
}

WERROR dialog_edit_value(TALLOC_CTX *ctx, struct registry_key *key, uint32_t type,
		      const struct value_item *vitem, WINDOW *below)
{
	struct edit_dialog *edit;
	const char *choices[] = {
		"Ok",
		"Cancel",
		NULL
	};
	char *title;
	int nlines, ncols, val_rows;
	WERROR rv = WERR_NOMEM;
	int selection;

	edit = talloc_zero(ctx, struct edit_dialog);
	if (edit == NULL) {
		return rv;
	}
	talloc_set_destructor(edit, edit_dialog_free);

	title = talloc_asprintf(edit, "Edit %s value", str_regtype(vitem->type));
	if (title == NULL) {
		goto finish;
	}

	nlines = 9;
	if (vitem->type == REG_MULTI_SZ) {
		nlines += 4;
	}
	ncols = 50;
	edit->dia = dialog_choice_center_new(edit, title, choices, nlines,
					     ncols, below);
	talloc_free(title);
	if (edit->dia == NULL) {
		goto finish;
	}

	/* name */
	edit->field[0] = new_field(1, ncols - 4, 1, 1, 0, 0);
	if (edit->field[0] == NULL) {
		goto finish;
	}

	/* data */
	val_rows = 1;
	if (vitem->type == REG_MULTI_SZ) {
		val_rows += 4;
	}
	edit->field[1] = new_field(val_rows, ncols - 4, 4, 1, 0, 0);
	if (edit->field[1] == NULL) {
		goto finish;
	}
	set_field_back(edit->field[0], A_REVERSE);
	set_field_back(edit->field[1], A_REVERSE);
	field_opts_off(edit->field[0], O_BLANK | O_AUTOSKIP | O_STATIC);
	field_opts_off(edit->field[1], O_BLANK | O_AUTOSKIP | O_STATIC | O_WRAP);

	if (vitem) {
		set_field_buffer(edit->field[0], 0, vitem->value_name);
		field_opts_off(edit->field[0], O_EDIT);
		fill_value_buffer(edit, vitem);
	}

	edit->input = new_form(edit->field);
	if (edit->input == NULL) {
		goto finish;
	}
	form_opts_off(edit->input, O_NL_OVERLOAD | O_BS_OVERLOAD);

	edit->input_win = derwin(edit->dia->sub_window, nlines - 3, ncols - 3, 0, 0);
	if (edit->input_win == NULL) {
		goto finish;
	}

	set_form_win(edit->input, edit->dia->sub_window);
	set_form_sub(edit->input, edit->input_win);
	post_form(edit->input);
	mvwprintw(edit->dia->sub_window, 0, 0, "Name");
	mvwprintw(edit->dia->sub_window, 3, 0, "Data");

	keypad(edit->dia->window, true);
	update_panels();
	doupdate();

	edit->section = IN_NAME;

	while (1) {
		int c = wgetch(edit->dia->window);
		if (c == '\t') {
			section_down(edit);
			continue;
		} else if (c == KEY_BTAB) {
			section_up(edit);
			continue;
		}

		if (edit->section == IN_NAME || edit->section == IN_DATA) {
			handle_form_input(edit->input, c);
		} else {
			selection = handle_menu_input(edit->dia->choices, c);
			if (selection != -1) {
				goto finish;
			}
		}

		update_panels();
		doupdate();
	}

finish:
	if (selection == DIALOG_OK) {
		rv = set_value(edit, key, type);
	}

	talloc_free(edit);

	return rv;
}

int dialog_select_type(TALLOC_CTX *ctx, int *type, WINDOW *below)
{
	struct dialog *dia;
	const char *choices[] = {
		"OK",
		"Cancel",
		NULL
	};
	const char *reg_types[] = {
		"REG_DWORD",
		"REG_SZ",
		"REG_EXPAND_SZ",
		"REG_MULTI_SZ",
	};
#define NTYPES (sizeof(reg_types) / sizeof(const char*))
	ITEM **item;
	MENU *list;
	WINDOW *type_win;
	int sel = -1;
	size_t i;

	dia = dialog_choice_center_new(ctx, "New Value", choices, 10, 20,
				       below);
	if (dia == NULL) {
		return -1;
	}

	mvwprintw(dia->sub_window, 0, 0, "Choose type:");
	type_win = derwin(dia->sub_window, 6, 18, 1, 0);
	if (type_win == NULL) {
		goto finish;
	}

	item = talloc_zero_array(dia, ITEM *, NTYPES + 1);
	if (item == NULL) {
		goto finish;
	}

	for (i = 0; i < NTYPES; ++i) {
		int t = regtype_by_string(reg_types[i]);

		item[i] = new_item(reg_types[i], reg_types[i]);
		if (item[i] == NULL) {
			goto finish;
		}
		set_item_userptr(item[i], (void*)(uintptr_t)t);
	}

	list = new_menu(item);
	if (list == NULL) {
		goto finish;
	}

	set_menu_format(list, 7, 1);
	set_menu_win(list, dia->sub_window);
	set_menu_sub(list, type_win);
	menu_opts_off(list, O_SHOWDESC);
	set_menu_mark(list, "* ");
	post_menu(list);

	keypad(dia->window, true);
	update_panels();
	doupdate();

	while (sel == -1) {
		ITEM *it;
		int c = wgetch(dia->window);

		switch (c) {
		case KEY_UP:
			menu_driver(list, REQ_UP_ITEM);
			break;
		case KEY_DOWN:
			menu_driver(list, REQ_DOWN_ITEM);
			break;
		case KEY_LEFT:
			menu_driver(dia->choices, REQ_LEFT_ITEM);
			break;
		case KEY_RIGHT:
			menu_driver(dia->choices, REQ_RIGHT_ITEM);
			break;
		case '\n':
		case KEY_ENTER:
			it = current_item(list);
			*type = (int)(uintptr_t)item_userptr(it);
			it = current_item(dia->choices);
			sel = (int)(uintptr_t)item_userptr(it);
			break;
		}
	}

finish:
	if (list) {
		unpost_menu(list);
		free_menu(list);
	}
	if (item) {
		ITEM **it;
		for (it = item; *it; ++it) {
			free_item(*it);
		}
	}
	if (type_win) {
		delwin(type_win);
	}
	talloc_free(dia);

	return sel;
}

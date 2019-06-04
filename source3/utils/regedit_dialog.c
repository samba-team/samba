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
#include "regedit_dialog.h"
#include "regedit_valuelist.h"
#include "regedit_hexedit.h"
#include "util_reg.h"
#include "lib/registry/registry.h"
#include <stdarg.h>
#include <form.h>

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

static int dialog_free(struct dialog *dia)
{
	dialog_destroy(dia);

	return 0;
}

static bool default_validator(struct dialog *dia, struct dialog_section *sect,
			      void *arg)
{
	return true;
}

struct dialog *dialog_new(TALLOC_CTX *ctx, short color, const char *title,
			  int y, int x)
{
	struct dialog *dia;

	dia = talloc_zero(ctx, struct dialog);
	if (dia == NULL) {
		return NULL;
	}

	talloc_set_destructor(dia, dialog_free);

	dia->title = talloc_strdup(dia, title);
	if (dia->title == NULL) {
		goto fail;
	}
	dia->x = x;
	dia->y = y;
	dia->color = color;
	dia->submit = default_validator;

	return dia;

fail:
	talloc_free(dia);

	return NULL;

}

void dialog_set_submit_cb(struct dialog *dia, dialog_submit_cb cb, void *arg)
{
	dia->submit = cb;
	dia->submit_arg = arg;
}

static void center_above_window(int *nlines, int *ncols, int *y, int *x)
{
	int centery, centerx;

	centery = LINES / 2;
	centerx = COLS / 2;
	*y = 0;
	*x = 0;

	if (*nlines > LINES) {
		*nlines = LINES;
	}
	if (*ncols > COLS) {
		*ncols = COLS;
	}

	if (*nlines/2 < centery) {
		*y = centery - *nlines / 2;
	}
	if (*ncols/2 < centerx) {
		*x = centerx - *ncols / 2;
	}
}

void dialog_section_destroy(struct dialog_section *section)
{
	if (section->ops->destroy) {
		section->ops->destroy(section);
	}
	if (section->window) {
		delwin(section->window);
		section->window = NULL;
	}
}

void dialog_section_init(struct dialog_section *section,
			 const struct dialog_section_ops *ops,
			 int nlines, int ncols)
{
	section->ops = ops;
	section->nlines = nlines;
	section->ncols = ncols;
}

const char *dialog_section_get_name(struct dialog_section *section)
{
	return section->name;
}

void dialog_section_set_name(struct dialog_section *section, const char *name)
{
	TALLOC_FREE(section->name);
	section->name = talloc_strdup(section, name);
}

void dialog_section_set_justify(struct dialog_section *section,
				enum section_justify justify)
{
	section->justify = justify;
}

/* append a section to the dialog's circular list */
void dialog_append_section(struct dialog *dia,
		           struct dialog_section *section)
{
	SMB_ASSERT(section != NULL);

	if (!dia->head_section) {
		dia->head_section = section;
	}
	if (dia->tail_section) {
		dia->tail_section->next = section;
	}
	section->prev = dia->tail_section;
	section->next = dia->head_section;
	dia->head_section->prev = section;
	dia->tail_section = section;
}

struct dialog_section *dialog_find_section(struct dialog *dia, const char *name)
{
	struct dialog_section *section = dia->head_section;

	do {
		if (section->name && strequal(section->name, name)) {
			return section;
		}
		section = section->next;
	} while (section != dia->head_section);

	return NULL;
}

static void section_on_input(struct dialog *dia, int c)
{
	struct dialog_section *section = dia->current_section;

	if (!section->ops->on_input) {
		return;
	}
	section->ops->on_input(dia, section, c);
}

static bool section_on_tab(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_tab) {
		return false;
	}
	return section->ops->on_tab(dia, section);
}

static bool section_on_btab(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_btab) {
		return false;
	}
	return section->ops->on_btab(dia, section);
}

static bool section_on_up(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_up) {
		return false;
	}
	return section->ops->on_up(dia, section);
}

static bool section_on_down(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_down) {
		return false;
	}
	return section->ops->on_down(dia, section);
}

static bool section_on_left(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_left) {
		return false;
	}
	return section->ops->on_left(dia, section);
}

static bool section_on_right(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_right) {
		return false;
	}
	return section->ops->on_right(dia, section);
}

static enum dialog_action section_on_enter(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (!section || !section->ops->on_enter) {
		return DIALOG_OK;
	}
	return section->ops->on_enter(dia, section);
}

static bool section_on_focus(struct dialog *dia, bool forward)
{
	struct dialog_section *section = dia->current_section;

	if (!section->ops->on_focus) {
		return false;
	}
	return section->ops->on_focus(dia, section, forward);
}

static void section_on_leave_focus(struct dialog *dia)
{
	struct dialog_section *section = dia->current_section;

	if (section->ops->on_leave_focus) {
		section->ops->on_leave_focus(dia, section);
	}
}

static void section_set_next_focus(struct dialog *dia)
{
	section_on_leave_focus(dia);

	do {
		dia->current_section = dia->current_section->next;
	} while (!section_on_focus(dia, true));
}

static void section_set_previous_focus(struct dialog *dia)
{
	section_on_leave_focus(dia);

	do {
		dia->current_section = dia->current_section->prev;
	} while (!section_on_focus(dia, false));
}

WERROR dialog_create(struct dialog *dia)
{
	WERROR rv = WERR_OK;
	int row, col;
	int nlines, ncols;
	struct dialog_section *section;

	nlines = 0;
	ncols = 0;
	SMB_ASSERT(dia->head_section != NULL);

	/* calculate total size based on sections */
	section = dia->head_section;
	do {
		nlines += section->nlines;
		ncols = MAX(ncols, section->ncols);
		section = section->next;
	} while (section != dia->head_section);

	/* fill in widths for sections that expand */
	section = dia->head_section;
	do {
		if (section->ncols < 0) {
			section->ncols = ncols;
		}
		section = section->next;
	} while (section != dia->head_section);

	/* create window for dialog */
	nlines += 4;
	ncols += 6;
	dia->pad = newpad(nlines, ncols);
	if (dia->pad == NULL) {
		rv = WERR_NOT_ENOUGH_MEMORY;
		goto fail;
	}
	dia->centered = false;
	if (dia->y < 0 || dia->x < 0) {
		dia->centered = true;
		center_above_window(&nlines, &ncols, &dia->y, &dia->x);
	}
	dia->window = newwin(nlines, ncols, dia->y, dia->x);
	if (dia->window == NULL) {
		rv = WERR_NOT_ENOUGH_MEMORY;
		goto fail;
	}
	dia->panel = new_panel(dia->window);
	if (dia->panel == NULL) {
		rv = WERR_NOT_ENOUGH_MEMORY;
		goto fail;
	}

	/* setup color and border */
	getmaxyx(dia->pad, nlines, ncols);
	wbkgdset(dia->pad, ' ' | COLOR_PAIR(dia->color));
	wclear(dia->pad);
	mvwhline(dia->pad, 1, 2, 0, ncols - 4);
	mvwhline(dia->pad, nlines - 2, 2, 0, ncols - 4);
	mvwvline(dia->pad, 2, 1, 0, nlines - 4);
	mvwvline(dia->pad, 2, ncols - 2, 0, nlines - 4);
	mvwaddch(dia->pad, 1, 1, ACS_ULCORNER);
	mvwaddch(dia->pad, 1, ncols - 2, ACS_URCORNER);
	mvwaddch(dia->pad, nlines - 2, 1, ACS_LLCORNER);
	mvwaddch(dia->pad, nlines - 2, ncols - 2, ACS_LRCORNER);
	col = ncols / 2 - MIN(strlen(dia->title) + 2, ncols) / 2;
	mvwprintw(dia->pad, 1, col, " %s ", dia->title);

	/* create subwindows for each section */
	row = 2;
	section = dia->head_section;
	do {
		col = 3;

		switch (section->justify) {
		case SECTION_JUSTIFY_LEFT:
			break;
		case SECTION_JUSTIFY_CENTER:
			col += (ncols - 6)/ 2 - section->ncols / 2;
			break;
		case SECTION_JUSTIFY_RIGHT:
			break;
		}

		section->window = subpad(dia->pad, section->nlines,
					 section->ncols, row, col);
		if (section->window == NULL) {
			rv = WERR_NOT_ENOUGH_MEMORY;
			goto fail;
		}
		SMB_ASSERT(section->ops->create != NULL);
		rv = section->ops->create(dia, section);
		row += section->nlines;
		section = section->next;
	} while (section != dia->head_section && W_ERROR_IS_OK(rv));

	dia->current_section = dia->head_section;
	section_set_next_focus(dia);

fail:
	return rv;
}

void dialog_show(struct dialog *dia)
{
	int nlines, ncols;
	int pad_y, pad_x;
	int y, x;
	int rv;

	touchwin(dia->pad);
	getmaxyx(dia->window, nlines, ncols);
	getmaxyx(dia->pad, pad_y, pad_x);
	y = 0;
	if (pad_y > nlines) {
		y = (pad_y - nlines) / 2;
	}
	x = 0;
	if (pad_x > ncols) {
		x = (pad_x - ncols) / 2;
	}
	rv = copywin(dia->pad, dia->window, y, x, 0, 0,
		     nlines - 1, ncols - 1, false);
	SMB_ASSERT(rv == OK);

	getyx(dia->pad, pad_y, pad_x);
	wmove(dia->window, pad_y - y, pad_x - x);
	touchwin(dia->window);
	wnoutrefresh(dia->window);
}

void dialog_destroy(struct dialog *dia)
{
	struct dialog_section *section;

	section = dia->head_section;
	do {
		dialog_section_destroy(section);
		section = section->next;
	} while (section != dia->head_section);

	if (dia->panel) {
		del_panel(dia->panel);
		dia->panel = NULL;
	}
	if (dia->window) {
		delwin(dia->window);
		dia->window = NULL;
	}
}

static int dialog_getch(struct dialog *dia)
{
	int c;

	c = regedit_getch();
	if (c == KEY_RESIZE) {
		int nlines, ncols, y, x;
		int pad_nlines, pad_ncols;
		int win_nlines, win_ncols;

		getmaxyx(dia->window, win_nlines, win_ncols);
		getmaxyx(dia->pad, pad_nlines, pad_ncols);
		getbegyx(dia->window, y, x);

		nlines = pad_nlines;
		ncols = pad_ncols;

		if (dia->centered) {
			center_above_window(&nlines, &ncols, &y, &x);
		} else {
			if (nlines + y > LINES) {
				if (nlines > LINES) {
					y = 0;
				} else {
					y = LINES - nlines;
				}
			}
			if (ncols + x > COLS) {
				if (ncols > COLS) {
					x = 0;
				} else {
					x = COLS - ncols;
				}
			}
		}
		if (nlines != win_nlines || ncols != win_ncols) {
			wresize(dia->window, nlines, ncols);
			replace_panel(dia->panel, dia->window);
		}
		move_panel(dia->panel, y, x);
	}

	return c;
}

bool dialog_handle_input(struct dialog *dia, WERROR *err,
			 enum dialog_action *action)
{
	int c;

	*err = WERR_OK;

	c = dialog_getch(dia);

	switch (c) {
	case '\t':
		if (!section_on_tab(dia)) {
			section_set_next_focus(dia);
		}
		break;
	case KEY_BTAB:
		if (!section_on_btab(dia)) {
			section_set_previous_focus(dia);
		}
		break;
	case KEY_UP:
		if (!section_on_up(dia)) {
			section_set_previous_focus(dia);
		}
		break;
	case KEY_DOWN:
		if (!section_on_down(dia)) {
			section_set_next_focus(dia);
		}
		break;
	case KEY_LEFT:
		if (!section_on_left(dia)) {
			section_set_previous_focus(dia);
		}
		break;
	case KEY_RIGHT:
		if (!section_on_right(dia)) {
			section_set_next_focus(dia);
		}
		break;
	case '\n':
	case KEY_ENTER:
		*action = section_on_enter(dia);
		switch (*action) {
		case DIALOG_IGNORE:
			break;
		case DIALOG_CANCEL:
			return false;
		case DIALOG_OK:
			return !dia->submit(dia, dia->current_section,
					    dia->submit_arg);
		}
		break;
	case 27: /* ESC */
		return false;
	default:
		section_on_input(dia, c);
		break;
	}

	return true;
}

void dialog_modal_loop(struct dialog *dia, WERROR *err,
		       enum dialog_action *action)
{
	do {
		dialog_show(dia);
		update_panels();
		doupdate();
	} while (dialog_handle_input(dia, err, action));
}

/* text label */
struct dialog_section_label {
	struct dialog_section section;
	char **text;
};

static WERROR label_create(struct dialog *dia, struct dialog_section *section)
{
	int row;
	struct dialog_section_label *label =
		talloc_get_type_abort(section, struct dialog_section_label);

	for (row = 0; row < section->nlines; ++row) {
		mvwaddstr(section->window, row, 0, label->text[row]);
	}

	return WERR_OK;
}

struct dialog_section_ops label_ops = {
	.create = label_create,
};

static int label_free(struct dialog_section_label *label)
{
	dialog_section_destroy(&label->section);
	return 0;
}

struct dialog_section *dialog_section_label_new_va(TALLOC_CTX *ctx,
						   const char *msg, va_list ap)
{
	struct dialog_section_label *label;
	char *tmp, *ptmp, *line, *saveptr;
	int nlines, ncols;

	label = talloc_zero(ctx, struct dialog_section_label);
	if (label == NULL) {
		return NULL;
	}
	talloc_set_destructor(label, label_free);
	tmp = talloc_vasprintf(label, msg, ap);
	if (tmp == NULL) {
		goto fail;
	}

	for (nlines = 0, ncols = 0, ptmp = tmp;
	     (line = strtok_r(ptmp, "\n", &saveptr)) != NULL;
	     ++nlines) {
		ptmp = NULL;
		label->text = talloc_realloc(label, label->text,
					     char *, nlines + 1);
		if (label->text == NULL) {
			goto fail;
		}
		ncols = MAX(ncols, strlen(line));
		label->text[nlines] = talloc_strdup(label->text, line);
		if (label->text[nlines] == NULL) {
			goto fail;
		}
	}
	talloc_free(tmp);
	dialog_section_init(&label->section, &label_ops, nlines, ncols);

	return &label->section;

fail:
	talloc_free(label);
	return NULL;
}

struct dialog_section *dialog_section_label_new(TALLOC_CTX *ctx,
						const char *msg, ...)
{
	va_list ap;
	struct dialog_section *rv;

	va_start(ap, msg);
	rv = dialog_section_label_new_va(ctx, msg, ap);
	va_end(ap);

	return rv;
}

/* horizontal separator */
struct dialog_section_hsep {
	struct dialog_section section;
	int sep;
};

static WERROR hsep_create(struct dialog *dia, struct dialog_section *section)
{
	int y, x;
	struct dialog_section_hsep *hsep =
		talloc_get_type_abort(section, struct dialog_section_hsep);

	whline(section->window, hsep->sep, section->ncols);

	if (hsep->sep == 0 || hsep->sep == ACS_HLINE) {
		/* change the border characters around this section to
		   tee chars */
		getparyx(section->window, y, x);
		mvwaddch(dia->pad, y, x - 1, ACS_HLINE);
		mvwaddch(dia->pad, y, x - 2, ACS_LTEE);
		mvwaddch(dia->pad, y, x + section->ncols, ACS_HLINE);
		mvwaddch(dia->pad, y, x + section->ncols + 1, ACS_RTEE);
	}

	return WERR_OK;
}

struct dialog_section_ops hsep_ops = {
	.create = hsep_create
};

static int hsep_free(struct dialog_section_hsep *hsep)
{
	dialog_section_destroy(&hsep->section);
	return 0;
}

struct dialog_section *dialog_section_hsep_new(TALLOC_CTX *ctx, int sep)
{
	struct dialog_section_hsep *hsep;

	hsep = talloc_zero(ctx, struct dialog_section_hsep);
	if (hsep) {
		talloc_set_destructor(hsep, hsep_free);
		dialog_section_init(&hsep->section, &hsep_ops, 1, -1);
		hsep->sep = sep;
	}

	return &hsep->section;
}

/* text input field */
struct dialog_section_text_field {
	struct dialog_section section;
	unsigned opts;
	FIELD *field[2];
	FORM *form;
	int length;
};

static int get_cursor_col(struct dialog_section_text_field *field)
{
	int col;

	col = field->form->curcol + field->form->begincol;

	return col;
}

static WERROR text_field_create(struct dialog *dia,
				struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	text_field->field[0] = new_field(section->nlines, section->ncols,
				         0, 0, 0, 0);
	if (text_field->field[0] == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	set_field_back(text_field->field[0], A_REVERSE);
	set_field_opts(text_field->field[0], text_field->opts);

	text_field->form = new_form(text_field->field);
	if (text_field->form == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	set_form_win(text_field->form, dia->window);
	set_form_sub(text_field->form, section->window);
	set_current_field(text_field->form, text_field->field[0]);
	post_form(text_field->form);

	return WERR_OK;
}

static void text_field_destroy(struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	if (text_field->form) {
		unpost_form(text_field->form);
		free_form(text_field->form);
		text_field->form = NULL;
	}
	if (text_field->field[0]) {
		free_field(text_field->field[0]);
		text_field->field[0] = NULL;
	}
}

static void text_field_on_input(struct dialog *dia,
				struct dialog_section *section,
				int c)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	switch (c) {
	case KEY_BACKSPACE:
		if (text_field->length) {
			text_field->length--;
		}
		form_driver(text_field->form, REQ_DEL_PREV);
		break;
	case '\x7f':
	case KEY_DC:
		if (text_field->length) {
			text_field->length--;
		}
		form_driver(text_field->form, REQ_DEL_CHAR);
		break;
	default:
		text_field->length++;
		form_driver(text_field->form, c);
		break;
	}
}

static bool text_field_on_up(struct dialog *dia,
			     struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	if (section->nlines > 1) {
		form_driver(text_field->form, REQ_UP_CHAR);
		return true;
	}
	return false;
}

static bool text_field_on_down(struct dialog *dia,
			       struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	if (section->nlines > 1) {
		form_driver(text_field->form, REQ_DOWN_CHAR);
		return true;
	}
	return false;
}

static bool text_field_on_left(struct dialog *dia,
			       struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	form_driver(text_field->form, REQ_LEFT_CHAR);

	return true;
}

static bool text_field_on_right(struct dialog *dia,
			        struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	if (section->nlines > 1 ||
	    get_cursor_col(text_field) < text_field->length) {
		form_driver(text_field->form, REQ_RIGHT_CHAR);
	}

	return true;
}

static enum dialog_action text_field_on_enter(struct dialog *dia,
					      struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	if (section->nlines > 1) {
		text_field->length += text_field->form->cols;
		form_driver(text_field->form, REQ_NEW_LINE);
		return DIALOG_IGNORE;
	}

	return DIALOG_OK;
}

static bool text_field_on_focus(struct dialog *dia,
				struct dialog_section *section, bool forward)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	pos_form_cursor(text_field->form);

	return true;
}

struct dialog_section_ops text_field_ops = {
	.create = text_field_create,
	.destroy = text_field_destroy,
	.on_input = text_field_on_input,
	.on_up = text_field_on_up,
	.on_down = text_field_on_down,
	.on_left = text_field_on_left,
	.on_right = text_field_on_right,
	.on_enter = text_field_on_enter,
	.on_focus = text_field_on_focus
};

static int text_field_free(struct dialog_section_text_field *text_field)
{
	dialog_section_destroy(&text_field->section);
	return 0;
}

struct dialog_section *dialog_section_text_field_new(TALLOC_CTX *ctx,
						     int height, int width)
{
	struct dialog_section_text_field *text_field;

	text_field = talloc_zero(ctx, struct dialog_section_text_field);
	if (text_field == NULL) {
		return NULL;
	}
	talloc_set_destructor(text_field, text_field_free);
	dialog_section_init(&text_field->section, &text_field_ops,
			    height, width);
	text_field->opts = O_ACTIVE | O_PUBLIC | O_EDIT | O_VISIBLE | O_NULLOK;

	return &text_field->section;
}

const char *dialog_section_text_field_get(TALLOC_CTX *ctx,
					  struct dialog_section *section)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	form_driver(text_field->form, REQ_VALIDATION);

	return string_trim(ctx, field_buffer(text_field->field[0], 0));
}

void dialog_section_text_field_set(struct dialog_section *section,
				   const char *s)
{
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	text_field->length = strlen(s);
	set_field_buffer(text_field->field[0], 0, s);
}

const char **dialog_section_text_field_get_lines(TALLOC_CTX *ctx,
						 struct dialog_section *section)
{
	int rows, cols, max;
	const char **arr;
	size_t i;
	const char *buf;
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	form_driver(text_field->form, REQ_VALIDATION);
	buf = field_buffer(text_field->field[0], 0);

	dynamic_field_info(text_field->field[0], &rows, &cols, &max);

	arr = talloc_zero_array(ctx, const char *, rows + 1);
	if (arr == NULL) {
		return NULL;
	}
	for (i = 0; *buf; ++i, buf += cols) {
		SMB_ASSERT(i < rows);
		arr[i] = string_trim_n(arr, buf, cols);
	}

	return arr;
}

WERROR dialog_section_text_field_set_lines(TALLOC_CTX *ctx,
					   struct dialog_section *section,
					   const char **array)
{
	int rows, cols, max;
	size_t padding, length, idx;
	const char **arrayp;
	char *buf = NULL;
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	dynamic_field_info(text_field->field[0], &rows, &cols, &max);
	/* try to fit each string on it's own line. each line
	   needs to be padded with whitespace manually, since
	   ncurses fields do not have newlines. */
	for (idx = 0, arrayp = array; *arrayp != NULL; ++arrayp) {
		length = MIN(strlen(*arrayp), cols);
		padding = cols - length;
		buf = talloc_realloc(ctx, buf, char,
				     talloc_array_length(buf) +
				     length + padding + 1);
		if (buf == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		memcpy(&buf[idx], *arrayp, length);
		idx += length;
		memset(&buf[idx], ' ', padding);
		idx += padding;
		buf[idx] = '\0';
	}

	set_field_buffer(text_field->field[0], 0, buf);
	talloc_free(buf);

	return WERR_OK;
}

bool dialog_section_text_field_get_int(struct dialog_section *section,
				       long long *out)
{
	bool rv;
	const char *buf;
	char *endp;
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	form_driver(text_field->form, REQ_VALIDATION);

	buf = string_trim(section, field_buffer(text_field->field[0], 0));
	if (buf == NULL) {
		return false;
	}
	*out = strtoll(buf, &endp, 0);
	rv = true;
	if (endp == buf || endp == NULL || endp[0] != '\0') {
		rv = false;
	}

	return rv;
}


bool dialog_section_text_field_get_uint(struct dialog_section *section,
				        unsigned long long *out)
{
	const char *buf;
	int error = 0;
	struct dialog_section_text_field *text_field =
		talloc_get_type_abort(section, struct dialog_section_text_field);

	form_driver(text_field->form, REQ_VALIDATION);

	buf = string_trim(section, field_buffer(text_field->field[0], 0));
	if (buf == NULL) {
		return false;
	}
	*out = smb_strtoull(buf, NULL, 0, &error, SMB_STR_FULL_STR_CONV);
	if (error != 0) {
		return false;
	}

	return true;
}

/* hex editor field */
struct dialog_section_hexedit {
	struct dialog_section section;
	struct hexedit *buf;
};

#define HEXEDIT_MIN_SIZE 1
static WERROR hexedit_create(struct dialog *dia,
				struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit->buf = hexedit_new(dia, section->window, NULL,
				   HEXEDIT_MIN_SIZE);
	if (hexedit->buf == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	hexedit_refresh(hexedit->buf);

	return WERR_OK;
}

static void hexedit_destroy(struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	if (hexedit->buf) {
		TALLOC_FREE(hexedit->buf);
	}
}

static void hexedit_on_input(struct dialog *dia,
				struct dialog_section *section,
				int c)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	switch (c) {
	case KEY_BACKSPACE:
		hexedit_driver(hexedit->buf, HE_BACKSPACE);
		break;
	case '\x7f':
	case KEY_DC:
		hexedit_driver(hexedit->buf, HE_DELETE);
		break;
	default:
		hexedit_driver(hexedit->buf, c);
		break;
	}
}

static bool hexedit_on_up(struct dialog *dia,
			     struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit_driver(hexedit->buf, HE_CURSOR_UP);

	return true;
}

static bool hexedit_on_down(struct dialog *dia,
			       struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit_driver(hexedit->buf, HE_CURSOR_DOWN);

	return true;
}

static bool hexedit_on_left(struct dialog *dia,
			       struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit_driver(hexedit->buf, HE_CURSOR_LEFT);

	return true;
}

static bool hexedit_on_right(struct dialog *dia,
			        struct dialog_section *section)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit_driver(hexedit->buf, HE_CURSOR_RIGHT);

	return true;
}

static enum dialog_action hexedit_on_enter(struct dialog *dia,
					      struct dialog_section *section)
{
	return DIALOG_IGNORE;
}

static bool hexedit_on_focus(struct dialog *dia,
				struct dialog_section *section, bool forward)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	hexedit_set_cursor(hexedit->buf);

	return true;
}

struct dialog_section_ops hexedit_ops = {
	.create = hexedit_create,
	.destroy = hexedit_destroy,
	.on_input = hexedit_on_input,
	.on_up = hexedit_on_up,
	.on_down = hexedit_on_down,
	.on_left = hexedit_on_left,
	.on_right = hexedit_on_right,
	.on_enter = hexedit_on_enter,
	.on_focus = hexedit_on_focus
};

static int hexedit_free(struct dialog_section_hexedit *hexedit)
{
	dialog_section_destroy(&hexedit->section);
	return 0;
}

struct dialog_section *dialog_section_hexedit_new(TALLOC_CTX *ctx, int height)
{
	struct dialog_section_hexedit *hexedit;

	hexedit = talloc_zero(ctx, struct dialog_section_hexedit);
	if (hexedit == NULL) {
		return NULL;
	}
	talloc_set_destructor(hexedit, hexedit_free);
	dialog_section_init(&hexedit->section, &hexedit_ops,
			    height, LINE_WIDTH);

	return &hexedit->section;
}

WERROR dialog_section_hexedit_set_buf(struct dialog_section *section,
				      const void *data, size_t size)
{
	WERROR rv;
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	SMB_ASSERT(hexedit->buf != NULL);

	rv = hexedit_set_buf(hexedit->buf, data, size);
	if (W_ERROR_IS_OK(rv)) {
		hexedit_refresh(hexedit->buf);
		hexedit_set_cursor(hexedit->buf);
	}

	return rv;
}

void dialog_section_hexedit_get_buf(struct dialog_section *section,
				    const void **data, size_t *size)
{
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	SMB_ASSERT(hexedit->buf != NULL);
	*data = hexedit_get_buf(hexedit->buf);
	*size = hexedit_get_buf_len(hexedit->buf);
}

WERROR dialog_section_hexedit_resize(struct dialog_section *section,
				     size_t size)
{
	WERROR rv;
	struct dialog_section_hexedit *hexedit =
		talloc_get_type_abort(section, struct dialog_section_hexedit);

	SMB_ASSERT(hexedit->buf != NULL);
	rv = hexedit_resize_buffer(hexedit->buf, size);
	if (W_ERROR_IS_OK(rv)) {
		hexedit_refresh(hexedit->buf);
	}

	return rv;
}


/* button box */
struct dialog_section_buttons {
	struct dialog_section section;
	struct button_spec *spec;
	int current_button;
};

static void buttons_unhighlight(struct dialog_section_buttons *buttons)
{
	short pair;
	attr_t attr;

	/*
	 *  Some GCC versions will complain if the macro version of
	 *  wattr_get is used. So we should enforce the use of the
	 *  function instead. See:
	 *  http://lists.gnu.org/archive/html/bug-ncurses/2013-12/msg00017.html
	 */
	(wattr_get)(buttons->section.window, &attr, &pair, NULL);
	mvwchgat(buttons->section.window, 0, 0, -1, A_NORMAL, pair, NULL);
	wnoutrefresh(buttons->section.window);
}

static void buttons_highlight(struct dialog_section_buttons *buttons)
{
	struct button_spec *spec = &buttons->spec[buttons->current_button];
	short pair;
	attr_t attr;

	/*
	 *  Some GCC versions will complain if the macro version of
	 *  wattr_get is used. So we should enforce the use of the
	 *  function instead. See:
	 *  http://lists.gnu.org/archive/html/bug-ncurses/2013-12/msg00017.html
	 */
	(wattr_get)(buttons->section.window, &attr, &pair, NULL);
	mvwchgat(buttons->section.window, 0, 0, -1, A_NORMAL, pair, NULL);
	mvwchgat(buttons->section.window, 0, spec->col,
		 strlen(spec->label), A_REVERSE, pair, NULL);
	wmove(buttons->section.window, 0, spec->col + 2);
	wcursyncup(buttons->section.window);
	wnoutrefresh(buttons->section.window);
}

static bool buttons_highlight_next(struct dialog_section_buttons *buttons)
{
	if (buttons->current_button < talloc_array_length(buttons->spec) - 1) {
		buttons->current_button++;
		buttons_highlight(buttons);
		return true;
	}
	return false;
}

static bool buttons_highlight_previous(struct dialog_section_buttons *buttons)
{
	if (buttons->current_button > 0) {
		buttons->current_button--;
		buttons_highlight(buttons);
		return true;
	}
	return false;
}

static WERROR buttons_create(struct dialog *dia,
				struct dialog_section *section)
{
	size_t i, nbuttons;
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);

	nbuttons = talloc_array_length(buttons->spec);
	for (i = 0; i < nbuttons; ++i) {
		struct button_spec *spec = &buttons->spec[i];
		mvwaddstr(section->window, 0, spec->col, spec->label);
	}

	buttons->current_button = 0;

	return WERR_OK;
}

static bool buttons_on_btab(struct dialog *dia, struct dialog_section *section)
{
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);

	return buttons_highlight_previous(buttons);
}

static bool buttons_on_tab(struct dialog *dia, struct dialog_section *section)
{
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);

	return buttons_highlight_next(buttons);
}

static enum dialog_action buttons_on_enter(struct dialog *dia,
					   struct dialog_section *section)
{
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);
	struct button_spec *spec = &buttons->spec[buttons->current_button];

	if (spec->on_enter) {
		return spec->on_enter(dia, section);
	}

	return spec->action;
}

static bool buttons_on_focus(struct dialog *dia,
				struct dialog_section *section,
				bool forward)
{
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);

	if (forward) {
		buttons->current_button = 0;
	} else {
		buttons->current_button = talloc_array_length(buttons->spec) - 1;
	}
	buttons_highlight(buttons);

	return true;
}

static void buttons_on_leave_focus(struct dialog *dia,
				struct dialog_section *section)
{
	struct dialog_section_buttons *buttons =
		talloc_get_type_abort(section, struct dialog_section_buttons);
	buttons_unhighlight(buttons);
}

struct dialog_section_ops buttons_ops = {
	.create = buttons_create,
	.on_tab = buttons_on_tab,
	.on_btab = buttons_on_btab,
	.on_up = buttons_on_btab,
	.on_down = buttons_on_tab,
	.on_left = buttons_on_btab,
	.on_right = buttons_on_tab,
	.on_enter = buttons_on_enter,
	.on_focus = buttons_on_focus,
	.on_leave_focus = buttons_on_leave_focus
};

static int buttons_free(struct dialog_section_buttons *buttons)
{
	dialog_section_destroy(&buttons->section);
	return 0;
}

struct dialog_section *dialog_section_buttons_new(TALLOC_CTX *ctx,
						  const struct button_spec *spec)
{
	struct dialog_section_buttons *buttons;
	size_t i, nbuttons;
	int width;

	buttons = talloc_zero(ctx, struct dialog_section_buttons);
	if (buttons == NULL) {
		return NULL;
	}
	talloc_set_destructor(buttons, buttons_free);

	for (nbuttons = 0; spec[nbuttons].label; ++nbuttons) {
	}
	buttons->spec = talloc_zero_array(buttons, struct button_spec, nbuttons);
	if (buttons->spec == NULL) {
		goto fail;
	}

	for (width = 0, i = 0; i < nbuttons; ++i) {
		buttons->spec[i] = spec[i];
		buttons->spec[i].label = talloc_asprintf(buttons->spec,
							 "[ %s ]",
						         spec[i].label);
		if (!buttons->spec[i].label) {
			goto fail;
		}

		buttons->spec[i].col = width;
		width += strlen(buttons->spec[i].label);
		if (i != nbuttons - 1) {
			++width;
		}
	}

	dialog_section_init(&buttons->section, &buttons_ops, 1, width);

	return &buttons->section;

fail:
	talloc_free(buttons);
	return NULL;
}

/* options */
struct dialog_section_options {
	struct dialog_section section;
	struct option_spec *spec;
	int current_option;
	bool single_select;
};

static void options_unhighlight(struct dialog_section_options *options)
{
	short pair;
	attr_t attr;
	size_t row;

	/*
	 *  Some GCC versions will complain if the macro version of
	 *  wattr_get is used. So we should enforce the use of the
	 *  function instead. See:
	 *  http://lists.gnu.org/archive/html/bug-ncurses/2013-12/msg00017.html
	 */
	(wattr_get)(options->section.window, &attr, &pair, NULL);
	for (row = 0; row < options->section.nlines; ++row) {
		mvwchgat(options->section.window, row, 0, -1, A_NORMAL, pair, NULL);
	}
	wnoutrefresh(options->section.window);
}

static void options_highlight(struct dialog_section_options *options)
{
	struct option_spec *spec = &options->spec[options->current_option];
	short pair;
	attr_t attr;
	size_t row;

	/*
	 *  Some GCC versions will complain if the macro version of
	 *  wattr_get is used. So we should enforce the use of the
	 *  function instead. See:
	 *  http://lists.gnu.org/archive/html/bug-ncurses/2013-12/msg00017.html
	 */
	(wattr_get)(options->section.window, &attr, &pair, NULL);
	for (row = 0; row < options->section.nlines; ++row) {
		mvwchgat(options->section.window, row, 0, -1, A_NORMAL, pair, NULL);
	}
	mvwchgat(options->section.window, spec->row, spec->col,
		 strlen(spec->label), A_REVERSE, pair, NULL);
	wmove(options->section.window, spec->row, spec->col + 4);
	wcursyncup(options->section.window);
	wnoutrefresh(options->section.window);
}

static void options_render_state(struct dialog_section_options *options)
{
	size_t i, noptions;

	noptions = talloc_array_length(options->spec);
	for (i = 0; i < noptions; ++i) {
		struct option_spec *spec = &options->spec[i];
		char c = ' ';
		if (*spec->state)
			c = 'x';
		mvwaddch(options->section.window,
			 spec->row, spec->col + 1, c);
		wnoutrefresh(options->section.window);
	}
}

static bool options_highlight_next(struct dialog_section_options *options)
{
	if (options->current_option < talloc_array_length(options->spec) - 1) {
		options->current_option++;
		options_highlight(options);
		return true;
	}
	return false;
}

static bool options_highlight_previous(struct dialog_section_options *options)
{
	if (options->current_option > 0) {
		options->current_option--;
		options_highlight(options);
		return true;
	}
	return false;
}

static WERROR options_create(struct dialog *dia,
			     struct dialog_section *section)
{
	size_t i, noptions;
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);

	noptions = talloc_array_length(options->spec);
	for (i = 0; i < noptions; ++i) {
		struct option_spec *spec = &options->spec[i];
		mvwaddstr(section->window, spec->row, spec->col,
			  spec->label);
	}

	options->current_option = 0;
	options_render_state(options);

	return WERR_OK;
}

static bool options_on_btab(struct dialog *dia, struct dialog_section *section)
{
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);

	return options_highlight_previous(options);
}

static bool options_on_tab(struct dialog *dia, struct dialog_section *section)
{
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);

	return options_highlight_next(options);
}

static void options_on_input(struct dialog *dia, struct dialog_section *section, int c)
{
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);

	if (c == ' ') {
		struct option_spec *spec = &options->spec[options->current_option];
		if (options->single_select) {
			size_t i, noptions;
			noptions = talloc_array_length(options->spec);
			for (i = 0; i < noptions; ++i) {
				*(options->spec[i].state) = false;
			}
		}
		*spec->state = !*spec->state;
		options_unhighlight(options);
		options_render_state(options);
		options_highlight(options);
	}
}

static enum dialog_action options_on_enter(struct dialog *dia, struct dialog_section *section)
{
	options_on_input(dia, section, ' ');
	return DIALOG_OK;
}

static bool options_on_focus(struct dialog *dia,
				struct dialog_section *section,
				bool forward)
{
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);

	if (forward) {
		options->current_option = 0;
	} else {
		options->current_option = talloc_array_length(options->spec) - 1;
	}
	options_highlight(options);

	return true;
}

static void options_on_leave_focus(struct dialog *dia,
				struct dialog_section *section)
{
	struct dialog_section_options *options =
		talloc_get_type_abort(section, struct dialog_section_options);
	options_unhighlight(options);
}

struct dialog_section_ops options_ops = {
	.create = options_create,
	.on_tab = options_on_tab,
	.on_btab = options_on_btab,
	.on_up = options_on_btab,
	.on_down = options_on_tab,
	.on_left = options_on_btab,
	.on_right = options_on_tab,
	.on_input = options_on_input,
	.on_enter = options_on_enter,
	.on_focus = options_on_focus,
	.on_leave_focus = options_on_leave_focus
};

static int options_free(struct dialog_section_options *options)
{
	dialog_section_destroy(&options->section);
	return 0;
}

struct dialog_section *dialog_section_options_new(TALLOC_CTX *ctx,
						  const struct option_spec *spec,
						  int maxcol, bool single_select)
{
	struct dialog_section_options *options;
	size_t i, noptions;
	int width, maxwidth, maxrows;

	options = talloc_zero(ctx, struct dialog_section_options);
	if (options == NULL) {
		return NULL;
	}
	talloc_set_destructor(options, options_free);

	for (noptions = 0; spec[noptions].label; ++noptions) {
	}
	options->spec = talloc_zero_array(options, struct option_spec, noptions);
	if (options->spec == NULL) {
		goto fail;
	}

	maxrows = noptions / maxcol;
	if (noptions % maxcol) {
		++maxrows;
	}

	for (width = 0, maxwidth = 0, i = 0; i < noptions; ++i) {
		options->spec[i] = spec[i];
		options->spec[i].label = talloc_asprintf(options->spec,
							 "[ ] %s",
						         spec[i].label);
		if (!options->spec[i].label) {
			goto fail;
		}

		options->spec[i].col = maxwidth;
		options->spec[i].row = i % maxrows;
		width = MAX(strlen(options->spec[i].label), width);
		if (options->spec[i].row == maxrows - 1 || i == noptions - 1) {
			maxwidth += width + 1;
			width = 0;
		}
	}

	dialog_section_init(&options->section, &options_ops, maxrows, maxwidth - 1);
	options->single_select = single_select;

	return &options->section;

fail:
	talloc_free(options);
	return NULL;
}


enum input_type {
	DLG_IN_LONG,
	DLG_IN_ULONG,
	DLG_IN_STR,
};

struct input_req {
	TALLOC_CTX *ctx;
	enum input_type type;
	union {
		void *out;
		unsigned long *out_ulong;
		long *out_long;
		const char **out_str;
	} out;
};

static bool input_on_submit(struct dialog *dia, struct dialog_section *section,
			    void *arg)
{
	struct input_req *req = arg;
	struct dialog_section *data;
	unsigned long long out_ulong;
	long long out_long;

	data = dialog_find_section(dia, "input");

	switch (req->type) {
	case DLG_IN_LONG:
		if (!dialog_section_text_field_get_int(data, &out_long)) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Input must be a number.");
			return false;
		}
		if (out_long < LONG_MIN || out_long > LONG_MAX) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Number is out of range.");
			return false;
		}
		*req->out.out_long = out_long;
		break;
	case DLG_IN_ULONG:
		if (!dialog_section_text_field_get_uint(data, &out_ulong)) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Input must be a number greater than zero.");
			return false;
		}
		if (out_ulong > ULONG_MAX) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Number is out of range.");
			return false;
		}
		*req->out.out_ulong = out_ulong;
		break;
	case DLG_IN_STR:
		*req->out.out_str = dialog_section_text_field_get(req->ctx, data);
		break;
	}

	return true;
}

static int dialog_input_internal(TALLOC_CTX *ctx, void *output,
				 enum input_type type,
				 const char *title,
				 const char *msg, va_list ap)
				 PRINTF_ATTRIBUTE(5,0);

static int dialog_input_internal(TALLOC_CTX *ctx, void *output,
				 enum input_type type,
				 const char *title,
				 const char *msg, va_list ap)
{
	WERROR err;
	struct input_req req;
	enum dialog_action action;
	struct dialog *dia;
	struct dialog_section *section;
	struct button_spec spec[] = {
		{.label = "OK", .action = DIALOG_OK},
		{.label = "Cancel", .action = DIALOG_CANCEL},
		{ 0 }
	};

	req.ctx = ctx;
	req.type = type;
	req.out.out = output;
	*req.out.out_str = NULL;

	dia = dialog_new(ctx, PAIR_BLACK_CYAN, title, -1, -1);
	dialog_set_submit_cb(dia, input_on_submit, &req);
	section = dialog_section_label_new_va(dia, msg, ap);
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, ' ');
	dialog_append_section(dia, section);
	section = dialog_section_text_field_new(dia, 1, -1);
	dialog_section_set_name(section, "input");
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	section = dialog_section_buttons_new(dia, spec);
	dialog_section_set_justify(section, SECTION_JUSTIFY_CENTER);
	dialog_append_section(dia, section);

	dialog_create(dia);
	dialog_show(dia);
	dialog_modal_loop(dia, &err, &action);
	talloc_free(dia);

	return action;
}

int dialog_input(TALLOC_CTX *ctx, const char **output, const char *title,
		 const char *msg, ...)
{
	va_list ap;
	int rv;

	va_start(ap, msg);
	rv = dialog_input_internal(ctx, output, DLG_IN_STR, title, msg, ap);
	va_end(ap);

	return rv;
}

int dialog_input_ulong(TALLOC_CTX *ctx, unsigned long *output,
		       const char *title, const char *msg, ...)
{
	va_list ap;
	int rv;

	va_start(ap, msg);
	rv = dialog_input_internal(ctx, output, DLG_IN_ULONG, title, msg, ap);
	va_end(ap);

	return rv;
}

int dialog_input_long(TALLOC_CTX *ctx, long *output,
		      const char *title, const char *msg, ...)
{
	va_list ap;
	int rv;

	va_start(ap, msg);
	rv = dialog_input_internal(ctx, output, DLG_IN_LONG, title, msg, ap);
	va_end(ap);

	return rv;
}

int dialog_notice(TALLOC_CTX *ctx, enum dialog_type type,
		  const char *title, const char *msg, ...)
{
	va_list ap;
	WERROR err;
	enum dialog_action action;
	struct dialog *dia;
	struct dialog_section *section;
	struct button_spec spec[3];

	memset(&spec, '\0', sizeof(spec));
	spec[0].label = "OK";
	spec[0].action = DIALOG_OK;
	if (type == DIA_CONFIRM) {
		spec[1].label = "Cancel";
		spec[1].action = DIALOG_CANCEL;
	}

	dia = dialog_new(ctx, PAIR_BLACK_CYAN, title, -1, -1);
	va_start(ap, msg);
	section = dialog_section_label_new_va(dia, msg, ap);
	va_end(ap);
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	section = dialog_section_buttons_new(dia, spec);
	dialog_section_set_justify(section, SECTION_JUSTIFY_CENTER);
	dialog_append_section(dia, section);

	dialog_create(dia);
	dialog_show(dia);
	dialog_modal_loop(dia, &err, &action);
	talloc_free(dia);

	return action;
}


struct edit_req {
	uint32_t type;
	uint32_t mode;
	struct registry_key *key;
	const struct value_item *vitem;
};

static WERROR fill_value_buffer(struct dialog *dia, struct edit_req *edit)
{
	char *tmp;
	struct dialog_section *data;

	if (edit->vitem == NULL) {
		return WERR_OK;
	}

	data = dialog_find_section(dia, "data");
	SMB_ASSERT(data != NULL);

	switch (edit->mode) {
	case REG_DWORD: {
		uint32_t v = 0;
		if (edit->vitem->data.length >= 4) {
			v = IVAL(edit->vitem->data.data, 0);
		}
		tmp = talloc_asprintf(dia, "%u", (unsigned)v);
		if (tmp == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		dialog_section_text_field_set(data, tmp);
		talloc_free(tmp);
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		const char *s;

		if (!pull_reg_sz(dia, &edit->vitem->data, &s)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		dialog_section_text_field_set(data, s);
		break;
	}
	case REG_MULTI_SZ: {
		const char **array;

		if (!pull_reg_multi_sz(dia, &edit->vitem->data, &array)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		return dialog_section_text_field_set_lines(dia, data, array);
	}
	case REG_BINARY:
	default:
		return dialog_section_hexedit_set_buf(data,
						      edit->vitem->data.data,
						      edit->vitem->data.length);
	}

	return WERR_OK;
}

static bool value_exists(TALLOC_CTX *ctx, const struct registry_key *key,
			 const char *name)
{
	uint32_t type;
	DATA_BLOB blob;
	WERROR rv;

	rv = reg_key_get_value_by_name(ctx, key, name, &type, &blob);

	return W_ERROR_IS_OK(rv);
}

static bool edit_on_submit(struct dialog *dia, struct dialog_section *section,
			   void *arg)
{
	struct edit_req *edit = arg;
	WERROR rv;
	DATA_BLOB blob;
	const char *name;
	struct dialog_section *name_section, *data;

	name_section = dialog_find_section(dia, "name");
	if (name_section) {
		name = dialog_section_text_field_get(dia, name_section);
		if (*name == '\0') {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Value name must not be blank.");
			return false;
		}
		if (value_exists(dia, edit->key, name)) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "Value named \"%s\" already exists.",
				      name);
			return false;
		}
	} else {
		SMB_ASSERT(edit->vitem);
		name = edit->vitem->value_name;
	}
	SMB_ASSERT(name);

	data = dialog_find_section(dia, "data");
	SMB_ASSERT(data != NULL);

	rv = WERR_OK;
	switch (edit->mode) {
	case REG_DWORD: {
		unsigned long long v;
		uint32_t val;

		if (!dialog_section_text_field_get_uint(data, &v)) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "REG_DWORD value must be an integer.");
			return false;
		}
		if (v > UINT32_MAX) {
			dialog_notice(dia, DIA_ALERT, "Error",
				      "REG_DWORD value must less than %lu.",
				      (unsigned long)UINT32_MAX);
			return false;
		}
		val = (uint32_t)v;
		blob = data_blob_talloc(dia, NULL, sizeof(val));
		SIVAL(blob.data, 0, val);
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		const char *buf;

		buf = dialog_section_text_field_get(dia, data);
		if (!buf || !push_reg_sz(dia, &blob, buf)) {
			rv = WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	}
	case REG_MULTI_SZ: {
		const char **lines;

		lines = dialog_section_text_field_get_lines(dia, data);
		if (!lines || !push_reg_multi_sz(dia, &blob, lines)) {
			rv = WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	}
	case REG_BINARY: {
		const void *buf;
		size_t len;

		dialog_section_hexedit_get_buf(data, &buf, &len);
		blob = data_blob_talloc(dia, buf, len);
		break;
	}
	}

	if (W_ERROR_IS_OK(rv)) {
		rv = reg_val_set(edit->key, name, edit->type, blob);
	}

	if (!W_ERROR_IS_OK(rv)) {
		const char *msg = get_friendly_werror_msg(rv);
		dialog_notice(dia, DIA_ALERT, "Error",
			      "Error saving value:\n%s", msg);

		return false;
	}

	return true;

}

static enum dialog_action edit_on_resize(struct dialog *dia,
					  struct dialog_section *section)
{
	struct dialog_section *data;
	unsigned long size;
	int rv;

	data = dialog_find_section(dia, "data");
	rv = dialog_input_ulong(dia, &size, "Resize", "Enter size of buffer");
	if (rv == DIALOG_OK) {
		dialog_section_hexedit_resize(data, size);
	}

	return DIALOG_IGNORE;
}

int dialog_edit_value(TALLOC_CTX *ctx, struct registry_key *key,
		      uint32_t type, const struct value_item *vitem,
		      bool force_binary, WERROR *err,
		      const char **name)
{
	enum dialog_action action;
	struct dialog *dia;
	struct dialog_section *section;
	struct edit_req edit;
	struct button_spec buttons[] = {
		{.label = "OK", .action = DIALOG_OK},
		{.label = "Cancel", .action = DIALOG_CANCEL},
		{ 0 }
	};
	struct button_spec buttons_hexedit[] = {
		{.label = "OK", .action = DIALOG_OK},
		{.label = "Resize Buffer", .on_enter = edit_on_resize},
		{.label = "Cancel", .action = DIALOG_CANCEL},
		{ 0 }
	};


	edit.key = key;
	edit.vitem = vitem;
	edit.type = type;
	edit.mode = type;
	if (force_binary || (vitem && vitem->unprintable)) {
		edit.mode = REG_BINARY;
	}

	dia = dialog_new(ctx, PAIR_BLACK_CYAN, "Edit Value", -1, -1);
	dialog_set_submit_cb(dia, edit_on_submit, &edit);

	section = dialog_section_label_new(dia, "Type");
	dialog_append_section(dia, section);
	section = dialog_section_label_new(dia, "%s",
					   str_regtype(type));
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, ' ');
	dialog_append_section(dia, section);

	section = dialog_section_label_new(dia, "Name");
	dialog_append_section(dia, section);
	if (vitem) {
		section = dialog_section_label_new(dia, "%s",
						   vitem->value_name);
	} else {
		section = dialog_section_text_field_new(dia, 1, 50);
		dialog_section_set_name(section, "name");
	}
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, ' ');
	dialog_append_section(dia, section);

	section = dialog_section_label_new(dia, "Data");
	dialog_append_section(dia, section);

	switch (edit.mode) {
	case REG_DWORD:
	case REG_SZ:
	case REG_EXPAND_SZ:
		section = dialog_section_text_field_new(dia, 1, 50);
		break;
	case REG_MULTI_SZ:
		section = dialog_section_text_field_new(dia, 10, 50);
		break;
	case REG_BINARY:
	default:
		section = dialog_section_hexedit_new(dia, 10);
		break;
	}

	dialog_section_set_name(section, "data");
	dialog_append_section(dia, section);

	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	if (edit.mode == REG_BINARY) {
		section = dialog_section_buttons_new(dia, buttons_hexedit);
	} else {
		section = dialog_section_buttons_new(dia, buttons);
	}
	dialog_section_set_justify(section, SECTION_JUSTIFY_CENTER);
	dialog_append_section(dia, section);

	dialog_create(dia);

	*err = fill_value_buffer(dia, &edit);
	if (!W_ERROR_IS_OK(*err)) {
		return DIALOG_CANCEL;
	}

	dialog_show(dia);
	dialog_modal_loop(dia, err, &action);

	if (action == DIALOG_OK && name) {
		if (vitem) {
			*name = talloc_strdup(ctx, vitem->value_name);
		} else if ((section = dialog_find_section(dia, "name"))) {
			*name = dialog_section_text_field_get(ctx, section);
		}
	}

	talloc_free(dia);

	return action;
}

int dialog_select_type(TALLOC_CTX *ctx, int *type)
{
	WERROR err;
	enum dialog_action action;
	struct dialog *dia;
	struct dialog_section *section;
	const char *reg_types[] = {
		"REG_BINARY",
		"REG_DWORD",
		"REG_EXPAND_SZ",
		"REG_MULTI_SZ",
		"REG_SZ"
	};
	#define NTYPES ARRAY_SIZE(reg_types)
	struct button_spec spec[] = {
		{.label = "OK", .action = DIALOG_OK},
		{.label = "Cancel", .action = DIALOG_CANCEL},
		{ 0 }
	};
	bool flags[NTYPES] = { true };
	struct option_spec opsec[NTYPES + 1];
	unsigned i;

	memset(&opsec, '\0', sizeof(opsec));
	for (i = 0; i < NTYPES; ++i) {
		opsec[i].label = reg_types[i];
		opsec[i].state = &flags[i];
	}

	dia = dialog_new(ctx, PAIR_BLACK_CYAN, "New Value", -1, -1);

	section = dialog_section_label_new(dia, "Select type for new value:");
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, ' ');
	dialog_append_section(dia, section);
	section = dialog_section_options_new(dia, opsec, 2, true);
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	section = dialog_section_buttons_new(dia, spec);
	dialog_section_set_justify(section, SECTION_JUSTIFY_CENTER);
	dialog_append_section(dia, section);

	dialog_create(dia);
	dialog_show(dia);

	dialog_modal_loop(dia, &err, &action);
	if (action == DIALOG_OK) {
		for (i = 0; i < NTYPES; ++i) {
			if (flags[i]) {
				*type = regtype_by_string(reg_types[i]);
				break;
			}
		}
	}

	talloc_free(dia);

	return action;
}

struct search_req {
	TALLOC_CTX *ctx;
	struct regedit_search_opts *opts;
};

static bool search_on_submit(struct dialog *dia, struct dialog_section *section,
			     void *arg)
{
	struct search_req *search = arg;
	struct dialog_section *query;

	query = dialog_find_section(dia, "query");
	SMB_ASSERT(query != NULL);

	if (!search->opts->search_key && !search->opts->search_value) {
		dialog_notice(dia, DIA_ALERT, "Error",
			      "Must search a key and/or a value");
		return false;
	}

	talloc_free(discard_const(search->opts->query));
	search->opts->query = dialog_section_text_field_get(search->ctx, query);
	SMB_ASSERT(search->opts->query != NULL);
	if (search->opts->query[0] == '\0') {
		dialog_notice(dia, DIA_ALERT, "Error",
			      "Query must not be blank.");
		return false;
	}

	return true;
}

int dialog_search_input(TALLOC_CTX *ctx, struct regedit_search_opts *opts)
{
	WERROR err;
	enum dialog_action action;
	struct dialog *dia;
	struct dialog_section *section, *query;
	struct search_req search;
	struct button_spec spec[] = {
		{.label = "Search", .action = DIALOG_OK},
		{.label = "Cancel", .action = DIALOG_CANCEL},
		{ 0 }
	};
	struct option_spec search_opts[] = {
		{.label = "Search Keys", .state = &opts->search_key},
		{.label = "Search Values", .state = &opts->search_value},
		{.label = "Recursive", .state = &opts->search_recursive},
		{.label = "Case Sensitive", .state = &opts->search_case},
		{ 0 }
	};

	if (!opts->search_key && !opts->search_value) {
		opts->search_key = true;
	}

	search.ctx = ctx;
	search.opts = opts;
	dia = dialog_new(ctx, PAIR_BLACK_CYAN, "Search", -1, -1);
	dialog_set_submit_cb(dia, search_on_submit, &search);
	section = dialog_section_label_new(dia, "Query");
	dialog_append_section(dia, section);
	query = dialog_section_text_field_new(dia, 1, -1);
	dialog_section_set_name(query, "query");
	dialog_append_section(dia, query);
	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	section = dialog_section_options_new(dia, search_opts, 2, false);
	dialog_append_section(dia, section);
	section = dialog_section_hsep_new(dia, 0);
	dialog_append_section(dia, section);
	section = dialog_section_buttons_new(dia, spec);
	dialog_section_set_justify(section, SECTION_JUSTIFY_CENTER);
	dialog_append_section(dia, section);

	dialog_create(dia);
	if (opts->query) {
		dialog_section_text_field_set(query, opts->query);
	}

	dialog_modal_loop(dia, &err, &action);
	talloc_free(dia);

	return action;
}

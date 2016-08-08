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

#ifndef _REGEDIT_DIALOG_H_
#define _REGEDIT_DIALOG_H_

#include <ncurses.h>
#include <panel.h>
#include <menu.h>

struct dialog;
struct dialog_section;

/* dialog submit cb. return true to close dialog, false to keep
   it open */
typedef bool (*dialog_submit_cb)(struct dialog *, struct dialog_section *,
				 void *);

struct dialog {
	char *title;
	WINDOW *window;
	WINDOW *pad;
	PANEL *panel;
	int x;
	int y;
	short color;
	bool centered;
	dialog_submit_cb submit;
	void *submit_arg;
	struct dialog_section *head_section;
	struct dialog_section *tail_section;
	struct dialog_section *current_section;
};

enum dialog_action {
	DIALOG_IGNORE,
	DIALOG_OK,
	DIALOG_CANCEL
};

struct dialog_section_ops {
	/* create section */
	WERROR (*create)(struct dialog *, struct dialog_section *);

	/* (optional) cleanup the section */
	void (*destroy)(struct dialog_section *);

	/* (optional) handle character input */
	void (*on_input)(struct dialog *, struct dialog_section *, int c);

	/* (optional) handle a tab character. return true if section dealt
	   with the tab internally, or false to advance focus to
	   the next dialog section. */
	bool (*on_tab)(struct dialog *, struct dialog_section *);

	/* (optional) handle a btab character. return true if section dealt
	   with the tab internally, or false to move focus to
	   the previous dialog section. */
	bool (*on_btab)(struct dialog *, struct dialog_section *);

	/* */
	bool (*on_up)(struct dialog *, struct dialog_section *);

	/* */
	bool (*on_down)(struct dialog *, struct dialog_section *);

	/* */
	bool (*on_left)(struct dialog *, struct dialog_section *);

	/* */
	bool (*on_right)(struct dialog *, struct dialog_section *);

	/* (optional) handle enter key. return DIALOG_OK to submit
	   dialog, DIALOG_CANCEL to close dialog, or DIALOG_IGNORE to
	   handle the enter internally. */
	enum dialog_action (*on_enter)(struct dialog *,
				       struct dialog_section *);

	/* (optional) called when this section is about to take focus. forward
	   is set to true when focus has landed here from forward traversal,
	   such as from a tab. return true to accept focus, false to pass to an
	   adjacent section. */
	bool (*on_focus)(struct dialog *, struct dialog_section *, bool forward);

	/* (optional) called when focus is leaving this section */
	void (*on_leave_focus)(struct dialog *, struct dialog_section *);
};

enum section_justify {
	SECTION_JUSTIFY_LEFT,
	SECTION_JUSTIFY_CENTER,
	SECTION_JUSTIFY_RIGHT,
};

struct dialog_section {
	char *name;
	int nlines;
	int ncols;
	WINDOW *window;
	enum section_justify justify;
	const struct dialog_section_ops *ops;
	struct dialog_section *next;
	struct dialog_section *prev;
};

struct dialog *dialog_new(TALLOC_CTX *ctx, short color,
			  const char *title, int y, int x);

void dialog_section_destroy(struct dialog_section *section);
void dialog_section_init(struct dialog_section *section,
			 const struct dialog_section_ops *ops,
			 int nlines, int ncols);

void dialog_section_set_name(struct dialog_section *section, const char *name);
const char *dialog_section_get_name(struct dialog_section *section);
void dialog_section_set_justify(struct dialog_section *section,
				enum section_justify justify);

void dialog_append_section(struct dialog *dia,
		           struct dialog_section *section);
struct dialog_section *dialog_find_section(struct dialog *dia,
					   const char *name);

WERROR dialog_create(struct dialog *dia);
void dialog_show(struct dialog *dia);
void dialog_destroy(struct dialog *dia);
void dialog_set_submit_cb(struct dialog *dia, dialog_submit_cb cb, void *arg);
bool dialog_handle_input(struct dialog *dia, WERROR *err,
			 enum dialog_action *action);
void dialog_modal_loop(struct dialog *dia, WERROR *err,
		       enum dialog_action *action);

struct dialog_section *dialog_section_label_new_va(TALLOC_CTX *ctx,
						   const char *msg,
						   va_list ap)
						   PRINTF_ATTRIBUTE(2,0);
struct dialog_section *dialog_section_label_new(TALLOC_CTX *ctx,
						const char *msg, ...)
						PRINTF_ATTRIBUTE(2,3);

struct dialog_section *dialog_section_hsep_new(TALLOC_CTX *ctx, int sep);


struct dialog_section *dialog_section_text_field_new(TALLOC_CTX *ctx,
						     int height, int width);
const char *dialog_section_text_field_get(TALLOC_CTX *ctx,
					  struct dialog_section *section);
const char **dialog_section_text_field_get_lines(TALLOC_CTX *ctx,
						 struct dialog_section *section);
bool dialog_section_text_field_get_int(struct dialog_section *section,
				       long long *out);
bool dialog_section_text_field_get_uint(struct dialog_section *section,
				        unsigned long long *out);
void dialog_section_text_field_set(struct dialog_section *section,
				   const char *s);
WERROR dialog_section_text_field_set_lines(TALLOC_CTX *ctx,
					   struct dialog_section *section,
					   const char **array);

struct dialog_section *dialog_section_hexedit_new(TALLOC_CTX *ctx, int height);
WERROR dialog_section_hexedit_set_buf(struct dialog_section *section,
				      const void *data, size_t size);
void dialog_section_hexedit_get_buf(struct dialog_section *section,
				    const void **data, size_t *size);
WERROR dialog_section_hexedit_resize(struct dialog_section *section,
				     size_t size);

struct button_spec {
	const char *label;
	enum dialog_action (*on_enter)(struct dialog *,
				       struct dialog_section *);
	enum dialog_action action;

	/* internal */
	int col;
};
struct dialog_section *dialog_section_buttons_new(TALLOC_CTX *ctx,
						  const struct button_spec *spec);

struct option_spec {
	const char *label;
	bool *state;

	/* internal */
	int col;
	int row;
};
struct dialog_section *dialog_section_options_new(TALLOC_CTX *ctx,
						  const struct option_spec *spec,
						  int maxcol, bool single_select);

enum dialog_type {
	DIA_ALERT,
	DIA_CONFIRM
};

int dialog_notice(TALLOC_CTX *ctx, enum dialog_type type,
		  const char *title, const char *msg, ...)
		  PRINTF_ATTRIBUTE(4,5);

int dialog_input(TALLOC_CTX *ctx, const char **output, const char *title,
		 const char *msg, ...) PRINTF_ATTRIBUTE(4,5);
int dialog_input_long(TALLOC_CTX *ctx, long *output,
		      const char *title, const char *msg, ...)
		      PRINTF_ATTRIBUTE(4,5);
int dialog_input_ulong(TALLOC_CTX *ctx, unsigned long *output,
		       const char *title, const char *msg, ...)
		       PRINTF_ATTRIBUTE(4,5);

struct registry_key;
struct value_item;

int dialog_edit_value(TALLOC_CTX *ctx, struct registry_key *key,
		      uint32_t type, const struct value_item *vitem,
		      bool force_binary, WERROR *err,
		      const char **name);

int dialog_select_type(TALLOC_CTX *ctx, int *type);

struct regedit_search_opts;

int dialog_search_input(TALLOC_CTX *ctx, struct regedit_search_opts *opts);

#endif

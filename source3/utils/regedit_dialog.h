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

struct dialog {
	WINDOW *window;
	WINDOW *sub_window;
	WINDOW *menu_window;
	PANEL *panel;
	MENU *choices;
	ITEM **choice_items;
};

struct dialog *dialog_new(TALLOC_CTX *ctx, const char *title, int nlines,
			  int ncols, int y, int x);

struct dialog *dialog_center_new(TALLOC_CTX *ctx, const char *title, int nlines,
				 int ncols, WINDOW *below);

struct dialog *dialog_choice_new(TALLOC_CTX *ctx, const char *title,
				 const char **choices, int nlines, int ncols,
				 int y, int x);

struct dialog *dialog_choice_center_new(TALLOC_CTX *ctx, const char *title,
					const char **choices, int nlines,
					int ncols, WINDOW *below);

struct dialog *dialog_confirm_new(TALLOC_CTX *ctx, const char *title,
				  WINDOW *below, const char *msg, ...);

enum dialog_selection {
	DIALOG_OK = 0,
	DIALOG_CANCEL = 1
};

int dialog_modal_loop(struct dialog *dia);

struct registry_key;
struct value_item;

int dialog_edit_value(TALLOC_CTX *ctx, struct registry_key *key, const struct value_item *vitem, WINDOW *below);
#endif

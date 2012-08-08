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
#include "popt_common.h"
#include "lib/util/data_blob.h"
#include "lib/registry/registry.h"
#include "regedit.h"
#include "regedit_treeview.h"
#include "regedit_valuelist.h"
#include "regedit_dialog.h"
#include <ncurses.h>
#include <menu.h>
#include <panel.h>

struct regedit {
	WINDOW *main_window;
	PANEL *main_panel;
	WINDOW *path_label;
	WINDOW *key_label;
	WINDOW *value_label;
	struct value_list *vl;
	struct tree_view *keys;
	bool tree_input;
};

/* load all available hives */
static struct tree_node *load_hives(TALLOC_CTX *mem_ctx,
				    struct registry_context *ctx)
{
	const char *hives[] = {
		"HKEY_CLASSES_ROOT",
		"HKEY_CURRENT_USER",
		"HKEY_LOCAL_MACHINE",
		"HKEY_PERFORMANCE_DATA",
		"HKEY_USERS",
		"HKEY_CURRENT_CONFIG",
		"HKEY_DYN_DATA",
		"HKEY_PERFORMANCE_TEXT",
		"HKEY_PERFORMANCE_NLSTEXT",
		NULL
	};
	struct tree_node *root, *prev, *node;
	struct registry_key *key;
	WERROR rv;
	size_t i;

	root = NULL;
	prev = NULL;

	for (i = 0; hives[i] != NULL; ++i) {
		rv = reg_get_predefined_key_by_name(ctx, hives[i], &key);
		if (!W_ERROR_IS_OK(rv)) {
			continue;
		}

		node = tree_node_new(mem_ctx, NULL, hives[i], key);
		if (node == NULL) {
			return NULL;
		}

		if (root == NULL) {
			root = node;
		}
		if (prev) {
			tree_node_append(prev, node);
		}
		prev = node;
	}

	return root;
}

static void print_heading(WINDOW *win, bool selected, const char *str)
{
	if (selected) {
		wattron(win, A_REVERSE);
	} else {
		wattroff(win, A_REVERSE);
	}
	wmove(win, 0, 0);
	wclrtoeol(win);
	waddstr(win, str);
	wnoutrefresh(win);
	wrefresh(win);
}

static void handle_tree_input(struct regedit *regedit, int c)
{
	struct tree_node *node;

	switch (c) {
	case KEY_DOWN:
		menu_driver(regedit->keys->menu, REQ_DOWN_ITEM);
		node = item_userptr(current_item(regedit->keys->menu));
		value_list_load(regedit->vl, node->key);
		break;
	case KEY_UP:
		menu_driver(regedit->keys->menu, REQ_UP_ITEM);
		node = item_userptr(current_item(regedit->keys->menu));
		value_list_load(regedit->vl, node->key);
		break;
	case '\n':
	case KEY_ENTER:
	case KEY_RIGHT:
		node = item_userptr(current_item(regedit->keys->menu));
		if (node && tree_node_has_children(node)) {
			tree_node_load_children(node);
			tree_node_print_path(regedit->path_label,
					     node->child_head);
			tree_view_update(regedit->keys, node->child_head);
			value_list_load(regedit->vl, node->child_head->key);
		}
		break;
	case KEY_LEFT:
		node = item_userptr(current_item(regedit->keys->menu));
		if (node && node->parent) {
			tree_node_print_path(regedit->path_label, node->parent);
			node = tree_node_first(node->parent);
			tree_view_update(regedit->keys, node);
			value_list_load(regedit->vl, node->key);
		}
		break;
	case 'd':
	case 'D': {
		struct dialog *dia;
		int sel;

		node = item_userptr(current_item(regedit->keys->menu));
		dia = dialog_confirm_new(regedit, "Delete Key",
					 regedit->main_window,
					 "Really delete key \"%s\"?",
					 node->name);
		sel = dialog_modal_loop(dia);
		mvwprintw(regedit->main_window, 1, 0, "Sel: %d", sel);
		/* TODO */
		break;
	}
	}

	tree_view_show(regedit->keys);
	value_list_show(regedit->vl);
}

static void handle_value_input(struct regedit *regedit, int c)
{
	struct value_item *vitem;

	switch (c) {
	case KEY_DOWN:
		menu_driver(regedit->vl->menu, REQ_DOWN_ITEM);
		break;
	case KEY_UP:
		menu_driver(regedit->vl->menu, REQ_UP_ITEM);
		break;
	case '\n':
	case KEY_ENTER:
		vitem = item_userptr(current_item(regedit->vl->menu));
		if (vitem) {
			struct tree_node *node;
			node = item_userptr(current_item(regedit->keys->menu));
			dialog_edit_value(regedit, node->key, vitem->type,
					  vitem, regedit->main_window);
			value_list_load(regedit->vl, node->key);
		}
		break;
	case 'n':
	case 'N': {
		int new_type;

		if (dialog_select_type(regedit, &new_type, regedit->main_window) == DIALOG_OK) {
			mvwprintw(regedit->main_window, 1, 0, "Item: %s (%d)", str_regtype(new_type), new_type);
		}
		break;
	}
	case 'd':
	case 'D':
		vitem = item_userptr(current_item(regedit->vl->menu));
		if (vitem) {
			struct dialog *dia;
			int sel;

			dia = dialog_confirm_new(regedit, "Delete Value",
						 regedit->main_window,
						 "Really delete value \"%s\"?",
						 vitem->value_name);
			sel = dialog_modal_loop(dia);
			mvwprintw(regedit->main_window, 1, 0, "Sel: %d", sel);
		}
		break;
	}

	value_list_show(regedit->vl);
}

static void handle_main_input(struct regedit *regedit, int c)
{
	switch (c) {
	case '\t':
		regedit->tree_input = !regedit->tree_input;
		print_heading(regedit->key_label, regedit->tree_input == true,
			      "Keys");
		print_heading(regedit->value_label, regedit->tree_input == false,
			      "Values");
		break;
	default:
		if (regedit->tree_input) {
			handle_tree_input(regedit, c);
		} else {
			handle_value_input(regedit, c);
		}
	}
}

/* test navigating available hives */
static void display_test_window(TALLOC_CTX *mem_ctx,
				struct registry_context *ctx)
{
	struct regedit *regedit;
	struct tree_node *root;
	int c;

	initscr();
	start_color();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);

	regedit = talloc_zero(mem_ctx, struct regedit);
	SMB_ASSERT(regedit != NULL);

	regedit->main_window = newwin(25, 80, 0, 0);
	SMB_ASSERT(regedit->main_window != NULL);

	keypad(regedit->main_window, TRUE);

	mvwprintw(regedit->main_window, 0, 0, "Path: ");
	regedit->path_label = derwin(regedit->main_window, 1, 65, 0, 6);
	wprintw(regedit->path_label, "/");

	root = load_hives(regedit, ctx);
	SMB_ASSERT(root != NULL);

	regedit->key_label = derwin(regedit->main_window, 1, 10, 2, 0);
	regedit->value_label = derwin(regedit->main_window, 1, 10, 2, 25);

	print_heading(regedit->key_label, true, "Keys");
	regedit->keys = tree_view_new(regedit, root, regedit->main_window,
				      15, 24, 3, 0);
	SMB_ASSERT(regedit->keys != NULL);

	print_heading(regedit->value_label, false, "Values");
	regedit->vl = value_list_new(regedit, regedit->main_window,
				     15, 40, 3, 25);
	SMB_ASSERT(regedit->vl != NULL);

	regedit->tree_input = true;

	tree_view_show(regedit->keys);
	value_list_show(regedit->vl);

	regedit->main_panel = new_panel(regedit->main_window);
	SMB_ASSERT(regedit->main_panel != NULL);

	update_panels();
	doupdate();
	while ((c = wgetch(regedit->main_window)) != 'q') {
		handle_main_input(regedit, c);
		update_panels();
		doupdate();
	}

	endwin();
}

int main(int argc, char **argv)
{
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		/* ... */
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};
	int opt;
	poptContext pc;
	struct user_auth_info *auth_info;
	TALLOC_CTX *frame;
	struct registry_context *ctx;
	WERROR rv;

	talloc_enable_leak_report_full();

	frame = talloc_stackframe();

	setup_logging("regedit", DEBUG_DEFAULT_STDERR);
	lp_set_cmdline("log level", "0");

	/* process options */
	auth_info = user_auth_info_init(frame);
	if (auth_info == NULL) {
		exit(1);
	}
	popt_common_set_auth_info(auth_info);
	pc = poptGetContext("regedit", argc, (const char **)argv, long_options, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		/* TODO */
	}

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		DEBUG(0, ("ERROR loading config file...\n"));
		exit(1);
	}

	/* some simple tests */

	rv = reg_open_samba3(frame, &ctx);
	if (!W_ERROR_IS_OK(rv)) {
		TALLOC_FREE(frame);

		return 1;
	}

	display_test_window(frame, ctx);

	//talloc_report_full(frame, stdout);

	TALLOC_FREE(frame);

	return 0;
}

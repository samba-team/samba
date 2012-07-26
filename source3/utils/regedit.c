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
#include <ncurses.h>
#include <menu.h>

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

static void handle_tree_input(struct tree_view *view, struct value_list *vl,
			      WINDOW *path, int c)
{
	struct tree_node *node;

	switch (c) {
	case KEY_DOWN:
		menu_driver(view->menu, REQ_DOWN_ITEM);
		node = item_userptr(current_item(view->menu));
		value_list_load(vl, node->key);
		break;
	case KEY_UP:
		menu_driver(view->menu, REQ_UP_ITEM);
		node = item_userptr(current_item(view->menu));
		value_list_load(vl, node->key);
		break;
	case '\n':
	case KEY_ENTER:
	case KEY_RIGHT:
		node = item_userptr(current_item(view->menu));
		if (node && tree_node_has_children(node)) {
			tree_node_load_children(node);
			tree_node_print_path(path, node->child_head);
			tree_view_update(view, node->child_head);
			value_list_load(vl, node->child_head->key);
		}
		break;
	case KEY_LEFT:
		node = item_userptr(current_item(view->menu));
		if (node && node->parent) {
			tree_node_print_path(path, node->parent);
			node = tree_node_first(node->parent);
			tree_view_update(view, node);
			value_list_load(vl, node->key);
		}
		break;
	}
}

static void handle_value_input(struct value_list *vl, int c)
{
	switch (c) {
	case KEY_DOWN:
		menu_driver(vl->menu, REQ_DOWN_ITEM);
		break;
	case KEY_UP:
		menu_driver(vl->menu, REQ_UP_ITEM);
		break;
	case KEY_ENTER:
		break;
	}
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

/* test navigating available hives */
static void display_test_window(TALLOC_CTX *mem_ctx,
				struct registry_context *ctx)
{
	WINDOW *main_window, *path_label;
	WINDOW *key_label, *value_label;
	struct value_list *vl;
	struct tree_view *view;
	struct tree_node *root;
	bool tree_view_input = true;
	int c;

	initscr();
	start_color();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);

	main_window = newwin(25, 80, 0, 0);
	SMB_ASSERT(main_window != NULL);

	keypad(main_window, TRUE);

	mvwprintw(main_window, 0, 0, "Path: ");
	path_label = derwin(main_window, 1, 65, 0, 6);
	wprintw(path_label, "/");

	root = load_hives(mem_ctx, ctx);
	SMB_ASSERT(root != NULL);

	key_label = derwin(main_window, 1, 10, 2, 0);
	value_label = derwin(main_window, 1, 10, 2, 25);

	print_heading(key_label, true, "Keys");
	view = tree_view_new(mem_ctx, root, main_window, 15, 24, 3, 0);
	SMB_ASSERT(view != NULL);

	print_heading(value_label, false, "Values");
	vl = value_list_new(mem_ctx, main_window, 15, 40, 3, 25);
	SMB_ASSERT(vl != NULL);

	refresh();
	tree_view_show(view);
	value_list_show(vl);

	while ((c = wgetch(main_window)) != 'q') {
		switch (c) {
		case '\t':
			tree_view_input = !tree_view_input;
			print_heading(key_label, tree_view_input == true,
				      "Keys");
			print_heading(value_label, tree_view_input == false,
				      "Values");
			break;
		default:
			if (tree_view_input) {
				handle_tree_input(view, vl, path_label, c);
			} else {
				handle_value_input(vl, c);
			}
		}

		tree_view_show(view);
		value_list_show(vl);
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
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	display_test_window(frame, ctx);

	//talloc_report_full(frame, stdout);

	TALLOC_FREE(frame);

	return 0;
}

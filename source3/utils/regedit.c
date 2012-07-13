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
#include <ncurses.h>
#include <menu.h>

/* test navigating HKLM hierarchy */
static void display_test_window(TALLOC_CTX *mem_ctx, struct registry_context *ctx)
{
	WINDOW *tree_window;
	struct tree_view *view;
	struct tree_node *root, *node;
	struct registry_key *key;
	int c;
	WERROR rv;

	initscr();
	start_color();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);

	tree_window = newwin(25, 80, 0, 0);

	keypad(tree_window, TRUE);

	rv = reg_get_predefined_key_by_name(ctx, "HKEY_LOCAL_MACHINE", &key);
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	root = tree_node_new(mem_ctx, NULL, "HKEY_LOCAL_MACHINE", key);
	SMB_ASSERT(root != NULL);

	view = tree_view_new(mem_ctx, root, tree_window, 15, 40, 3, 0);
	SMB_ASSERT(root != NULL);
	refresh();
	tree_view_show(view);

	while ((c = wgetch(tree_window)) != 'q') {
		switch (c) {
		case KEY_DOWN:
			menu_driver(view->menu, REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(view->menu, REQ_UP_ITEM);
			break;
		case KEY_RIGHT:
			node = item_userptr(current_item(view->menu));
			if (node && tree_node_has_children(node)) {
				tree_node_load_children(node);
				tree_view_update(view, node->child_head);
			}
			break;
		case KEY_LEFT:
			node = item_userptr(current_item(view->menu));
			if (node && node->parent) {
				tree_view_update(view,
					tree_node_first(node->parent));
			}
			break;
		}
		tree_view_show(view);
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
	lp_load_global(get_dyn_CONFIGFILE());

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

	/* some simple tests */

	rv = reg_open_samba3(frame, &ctx);
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	display_test_window(frame, ctx);

	//talloc_report_full(frame, stdout);

	TALLOC_FREE(frame);

	return 0;
}

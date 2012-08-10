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

static void add_reg_key(struct regedit *regedit, struct tree_node *node,
			bool subkey)
{
	char *name;
	const char *msg;

	if (!subkey && !node->parent) {
		return;
	}

	msg = "Enter name of new key";
	if (subkey) {
		msg = "Enter name of new subkey";
	}
	dialog_input(regedit, &name, "New Key", regedit->main_window, msg);
	if (name) {
		WERROR rv;
		struct registry_key *new_key;
		struct tree_node *new_node;
		struct tree_node *list;
		struct tree_node *parent;

		if (subkey) {
			parent = node;
			list = node->child_head;
		} else {
			parent = node->parent;
			list = tree_node_first(node);
			SMB_ASSERT(list != NULL);
		}
		rv = reg_key_add_name(regedit, parent->key, name,
				      NULL, NULL, &new_key);
		if (W_ERROR_IS_OK(rv)) {
			/* The list of subkeys may not be present in
			   cache yet, so if not, don't bother allocating
			   a new node for the key. */
			if (list) {
				new_node = tree_node_new(parent, parent,
							 name, new_key);
				SMB_ASSERT(new_node);
				tree_node_append_last(list, new_node);
			}

			list = tree_node_first(node);
			tree_view_clear(regedit->keys);
			tree_view_update(regedit->keys, list);
		} else {
			dialog_notice(regedit, DIA_ALERT, "New Key",
				      regedit->main_window,
				      "Failed to create key.");
		}
		talloc_free(name);
	}
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
	case 'n':
	case 'N':
		node = item_userptr(current_item(regedit->keys->menu));
		add_reg_key(regedit, node, false);
		break;
	case 's':
	case 'S':
		node = item_userptr(current_item(regedit->keys->menu));
		add_reg_key(regedit, node, true);
		break;
	case 'd':
	case 'D': {
		int sel;

		node = item_userptr(current_item(regedit->keys->menu));
		if (!node->parent) {
			break;
		}
		sel = dialog_notice(regedit, DIA_CONFIRM,
				    "Delete Key",
				     regedit->main_window,
				     "Really delete key \"%s\"?",
				     node->name);
		if (sel == DIALOG_OK) {
			WERROR rv;
			struct tree_node *pop;
			struct tree_node *parent = node->parent;

			rv = reg_key_del(node, parent->key, node->name);
			if (W_ERROR_IS_OK(rv)) {
				tree_view_clear(regedit->keys);
				pop = tree_node_pop(&node);
				tree_node_free_recursive(pop);
				node = parent->child_head;
				if (node == NULL) {
					node = tree_node_first(parent);
					tree_node_print_path(regedit->path_label,
							     node);
				}
				tree_view_update(regedit->keys, node);
				value_list_load(regedit->vl, node->key);
			} else {
				dialog_notice(regedit, DIA_ALERT, "Delete Key",
					      regedit->main_window,
					      "Failed to delete key.");
			}
		}
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
		int sel;

		sel = dialog_select_type(regedit, &new_type,
					 regedit->main_window);
		if (sel == DIALOG_OK) {
			struct tree_node *node;
			node = item_userptr(current_item(regedit->keys->menu));
			dialog_edit_value(regedit, node->key, new_type, NULL,
					  regedit->main_window);
			value_list_load(regedit->vl, node->key);
		}
		break;
	}
	case 'd':
	case 'D':
		vitem = item_userptr(current_item(regedit->vl->menu));
		if (vitem) {
			int sel;

			sel = dialog_notice(regedit, DIA_CONFIRM,
					    "Delete Value",
					     regedit->main_window,
					     "Really delete value \"%s\"?",
					     vitem->value_name);
			if (sel == DIALOG_OK) {
				ITEM *it = current_item(regedit->keys->menu);
				struct tree_node *node = item_userptr(it);
				reg_del_value(regedit, node->key,
					      vitem->value_name);
				value_list_load(regedit->vl, node->key);
			}


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

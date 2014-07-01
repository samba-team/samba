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
#include "regedit_list.h"
#include <ncurses.h>
#include <menu.h>
#include <panel.h>

#define KEY_START_X 	0
#define KEY_START_Y 	1
#define KEY_WIDTH 	(COLS / 4)
#define KEY_HEIGHT	(LINES - KEY_START_Y - 2)
#define VAL_START_X 	KEY_WIDTH
#define VAL_START_Y 	1
#define VAL_WIDTH 	(COLS - KEY_WIDTH)
#define VAL_HEIGHT	(LINES - VAL_START_Y - 2)

#define HELP1_START_Y	(LINES - 2)
#define HELP1_START_X	0
#define HELP1_WIDTH	(LINES)
#define HELP2_START_Y	(LINES - 1)
#define HELP2_START_X	0
#define HELP2_WIDTH	(LINES)
#define PATH_START_Y 	0
#define PATH_START_X 	6
#define PATH_MAX_Y	(COLS - 1)
#define PATH_WIDTH	(COLS - 6)
#define PATH_WIDTH_MAX	1024

struct regedit {
	struct registry_context *registry_context;
	WINDOW *main_window;
	WINDOW *path_label;
	size_t path_len;
	struct value_list *vl;
	struct tree_view *keys;
	bool tree_input;
	struct regedit_search_opts active_search;
};

static struct regedit *regedit_main = NULL;

static void show_path(struct regedit *regedit)
{
	int start_pad = 0;
	int start_win = PATH_START_X;

	if (PATH_START_X + regedit->path_len > COLS) {
		start_pad = 3 + PATH_START_X + regedit->path_len - COLS;
		mvprintw(PATH_START_Y, start_win, "...");
		start_win += 3;
	}
	copywin(regedit->path_label, regedit->main_window, 0, start_pad,
		PATH_START_Y, start_win, PATH_START_Y, PATH_MAX_Y, false);

	mvchgat(0, 0, COLS, A_BOLD, PAIR_YELLOW_CYAN, NULL);
}

static void print_path(struct regedit *regedit, struct tree_node *node)
{
	regedit->path_len = tree_node_print_path(regedit->path_label, node);
	show_path(regedit);
}

/* load all available hives */
static struct tree_node *load_hives(struct regedit *regedit)
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
		rv = reg_get_predefined_key_by_name(regedit->registry_context,
						    hives[i], &key);
		if (!W_ERROR_IS_OK(rv)) {
			continue;
		}

		node = tree_node_new(regedit, NULL, hives[i], key);
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

static void print_help(struct regedit *regedit)
{
	const char *khelp = "[n] New Key [s] New Subkey [d] Del Key "
			    "[LEFT] Ascend [RIGHT] Descend";
	const char *vhelp = "[n] New Value [d] Del Value [ENTER] Edit "
			    "[b] Edit binary";
	const char *msg = "KEYS";
	const char *help = khelp;
	const char *genhelp = "[TAB] Switch sections [q] Quit "
			      "[UP] List up [DOWN] List down "
			      "[/] Search [x] Next";
	int i, pad;

	if (!regedit->tree_input) {
		msg = "VALUES";
		help = vhelp;
	}

	move(HELP1_START_Y, HELP1_START_X);
	clrtoeol();
	attron(COLOR_PAIR(PAIR_BLACK_CYAN));
	mvaddstr(HELP1_START_Y, HELP1_START_X, help);
	pad = COLS - strlen(msg) - strlen(help);
	for (i = 0; i < pad; ++i) {
		addch(' ');
	}
	attroff(COLOR_PAIR(PAIR_BLACK_CYAN));
	attron(COLOR_PAIR(PAIR_YELLOW_CYAN) | A_BOLD);
	addstr(msg);
	attroff(COLOR_PAIR(PAIR_YELLOW_CYAN) | A_BOLD);

	move(HELP2_START_Y, HELP2_START_X);
	clrtoeol();
	mvaddstr(HELP2_START_Y, HELP2_START_X, genhelp);
}

static void print_heading(struct regedit *regedit)
{
	if (regedit->tree_input) {
		tree_view_set_selected(regedit->keys, true);
		value_list_set_selected(regedit->vl, false);
	} else {
		tree_view_set_selected(regedit->keys, false);
		value_list_set_selected(regedit->vl, true);
	}

	print_help(regedit);
}

static void load_values(struct regedit *regedit)
{
	struct tree_node *node;

	node = tree_view_get_current_node(regedit->keys);
	value_list_load(regedit->vl, node->key);
}

static void add_reg_key(struct regedit *regedit, struct tree_node *node,
			bool subkey)
{
	const char *name;
	const char *msg;

	if (!subkey && !node->parent) {
		return;
	}

	msg = "Enter name of new key";
	if (subkey) {
		msg = "Enter name of new subkey";
	}
	dialog_input(regedit, &name, "New Key", msg);
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
				tree_node_insert_sorted(list, new_node);
			} else {
				/* Reopen the parent key to make sure the
				   new subkey will be noticed. */
				tree_node_reopen_key(parent);
			}

			list = tree_node_first(node);
			tree_view_clear(regedit->keys);
			tree_view_update(regedit->keys, list);
			if (!subkey) {
				node = new_node;
			}
			tree_view_set_current_node(regedit->keys, node);
		} else {
			msg = get_friendly_werror_msg(rv);
			dialog_notice(regedit, DIA_ALERT, "New Key",
				      "Failed to create key: %s", msg);
		}
		talloc_free(discard_const(name));
	}
}

static WERROR next_depth_first(struct tree_node **node)
{
	WERROR rv = WERR_OK;

	SMB_ASSERT(node != NULL && *node != NULL);

	if (tree_node_has_children(*node)) {
		/* 1. If the node has children, go to the first one. */
		rv = tree_node_load_children(*node);
		if (W_ERROR_IS_OK(rv)) {
			SMB_ASSERT((*node)->child_head != NULL);
			*node = (*node)->child_head;
		}
	} else if ((*node)->next) {
		/* 2. If there's a node directly after this one, go there */
		*node = (*node)->next;
	} else {
		/* 3. Otherwise, go up the hierarchy to find the next one */
		do {
			*node = (*node)->parent;
			if (*node && (*node)->next) {
				*node = (*node)->next;
				break;
			}
		} while (*node);
	}

	return rv;
}

static WERROR regedit_search_next(struct regedit *regedit)
{
	WERROR rv;
	struct regedit_search_opts *opts = &regedit->active_search;

	if (opts->search_recursive) {
		rv = next_depth_first(&opts->node);
		if (!W_ERROR_IS_OK(rv)) {
			return rv;
		}
	} else {
		opts->node = opts->node->next;
	}

	return WERR_OK;
}

static WERROR regedit_search(struct regedit *regedit)
{
	struct regedit_search_opts *opts;
	struct tree_node *found;
	WERROR rv;

	opts = &regedit->active_search;

	if (!opts->query || !opts->match) {
		return WERR_OK;
	}

	SMB_ASSERT(opts->search_key || opts->search_value);

	for (found = NULL; opts->node && !found; ) {
		if (opts->search_key &&
		    opts->match(opts->node->name, opts->query)) {
			found = opts->node;
		}
		if (opts->search_value) {
			/* TODO
			rv = regedit_search_value(regedit);
			if (W_ERROR_IS_OK(rv)) {
				found = opts->node;
			} else if (!W_ERROR_EQUAL(rv, WERR_NO_MORE_ITEMS)) {
				return rv;
			}
			*/
		}
		rv = regedit_search_next(regedit);
		if (!W_ERROR_IS_OK(rv)) {
			return rv;
		}
	}

	if (found) {
		/* Put the cursor on the node that was found */
		if (!tree_view_is_node_visible(regedit->keys, found)) {
			tree_view_update(regedit->keys,
					 tree_node_first(found));
			print_path(regedit, found);
		}
		tree_view_set_current_node(regedit->keys, found);
		load_values(regedit);
		tree_view_show(regedit->keys);
		value_list_show(regedit->vl);
	} else {
		beep();
	}

	return WERR_OK;
}

static void handle_tree_input(struct regedit *regedit, int c)
{
	struct tree_node *node;

	switch (c) {
	case KEY_DOWN:
		tree_view_driver(regedit->keys, ML_CURSOR_DOWN);
		load_values(regedit);
		break;
	case KEY_UP:
		tree_view_driver(regedit->keys, ML_CURSOR_UP);
		load_values(regedit);
		break;
	case '\n':
	case KEY_ENTER:
	case KEY_RIGHT:
		node = tree_view_get_current_node(regedit->keys);
		if (node && tree_node_has_children(node)) {
			WERROR rv;

			rv = tree_node_load_children(node);
			if (W_ERROR_IS_OK(rv)) {
				print_path(regedit, node->child_head);
				tree_view_update(regedit->keys, node->child_head);
				value_list_load(regedit->vl, node->child_head->key);
			} else {
				const char *msg = get_friendly_werror_msg(rv);
				dialog_notice(regedit, DIA_ALERT, "Loading Subkeys",
					      "Failed to load subkeys: %s", msg);
			}
		}
		break;
	case KEY_LEFT:
		node = tree_view_get_current_node(regedit->keys);
		if (node && node->parent) {
			print_path(regedit, node->parent);
			node = node->parent;
			tree_view_update(regedit->keys, tree_node_first(node));
			tree_view_set_current_node(regedit->keys, node);
			value_list_load(regedit->vl, node->key);
		}
		break;
	case 'n':
	case 'N':
		node = tree_view_get_current_node(regedit->keys);
		add_reg_key(regedit, node, false);
		break;
	case 's':
	case 'S':
		node = tree_view_get_current_node(regedit->keys);
		add_reg_key(regedit, node, true);
		break;
	case 'd':
	case 'D': {
		int sel;

		node = tree_view_get_current_node(regedit->keys);
		if (!node->parent) {
			break;
		}
		sel = dialog_notice(regedit, DIA_CONFIRM,
				    "Delete Key",
				     "Really delete key \"%s\"?",
				     node->name);
		if (sel == DIALOG_OK) {
			WERROR rv;
			struct tree_node *pop;
			struct tree_node *parent = node->parent;

			rv = reg_key_del(node, parent->key, node->name);
			if (W_ERROR_IS_OK(rv)) {
				tree_node_reopen_key(parent);
				tree_view_clear(regedit->keys);
				pop = tree_node_pop(&node);
				talloc_free(pop);
				node = parent->child_head;
				if (node == NULL) {
					node = tree_node_first(parent);
					print_path(regedit, node);
				}
				tree_view_update(regedit->keys, node);
				value_list_load(regedit->vl, node->key);
			} else {
				const char *msg = get_friendly_werror_msg(rv);
				dialog_notice(regedit, DIA_ALERT, "Delete Key",
					      "Failed to delete key: %s", msg);
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
	bool binmode = false;

	switch (c) {
	case KEY_DOWN:
		value_list_driver(regedit->vl, ML_CURSOR_DOWN);
		break;
	case KEY_UP:
		value_list_driver(regedit->vl, ML_CURSOR_UP);
		break;
	case 'b':
	case 'B':
		binmode = true;
		/* Falthrough... */
	case '\n':
	case KEY_ENTER:
		vitem = value_list_get_current_item(regedit->vl);
		if (vitem) {
			struct tree_node *node;
			node = tree_view_get_current_node(regedit->keys);
			dialog_edit_value(regedit, node->key, vitem->type,
					  vitem, binmode);
			tree_node_reopen_key(node);
			value_list_load(regedit->vl, node->key);
		}
		break;
	case 'n':
	case 'N': {
		int new_type;
		int sel;

		sel = dialog_select_type(regedit, &new_type);
		if (sel == DIALOG_OK) {
			struct tree_node *node;
			node = tree_view_get_current_node(regedit->keys);
			dialog_edit_value(regedit, node->key, new_type, NULL,
					  false);
			tree_node_reopen_key(node);
			value_list_load(regedit->vl, node->key);
		}
		break;
	}
	case 'd':
	case 'D':
		vitem = value_list_get_current_item(regedit->vl);
		if (vitem) {
			int sel;

			sel = dialog_notice(regedit, DIA_CONFIRM,
					    "Delete Value",
					     "Really delete value \"%s\"?",
					     vitem->value_name);
			if (sel == DIALOG_OK) {
				struct tree_node *node;
				node = tree_view_get_current_node(regedit->keys);
				reg_del_value(regedit, node->key,
					      vitem->value_name);
				tree_node_reopen_key(node);
				value_list_load(regedit->vl, node->key);
			}
		}
		break;
	}

	value_list_show(regedit->vl);
}

static bool find_substring(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) != NULL;
}

static bool find_substring_nocase(const char *haystack, const char *needle)
{
	return strcasestr(haystack, needle) != NULL;
}

static void handle_main_input(struct regedit *regedit, int c)
{
	switch (c) {
	case 18: { /* CTRL-R */
		struct tree_node *root, *node;
		const char **path;

		node = tree_view_get_current_node(regedit->keys);
		path = tree_node_get_path(regedit, node);

		root = load_hives(regedit);
		tree_view_set_root(regedit->keys, root);
		tree_view_set_path(regedit->keys, path);
		node = tree_view_get_current_node(regedit->keys);
		value_list_load(regedit->vl, node->key);
		tree_view_show(regedit->keys);
		value_list_show(regedit->vl);
		print_path(regedit, node);
		talloc_free(discard_const(path));
		break;
	}
	case 'f':
	case 'F':
	case '/': {
		int rv;
		struct regedit_search_opts *opts;

		opts = &regedit->active_search;
		if (opts->query) {
			talloc_free(discard_const(opts->query));
		}
		rv = dialog_search_input(regedit, opts);
		if (rv == DIALOG_OK) {
			SMB_ASSERT(opts->query != NULL);
			opts->match = find_substring;
			opts->node = regedit->keys->root;
			if (opts->search_nocase) {
				opts->match = find_substring_nocase;
			}
			if (opts->search_relative) {
				opts->node =
				     tree_view_get_current_node(regedit->keys);
			}
			regedit_search(regedit);
		}
		break;
	}
	case 'x':
	case 'X':
		regedit_search(regedit);
		break;
	case '\t':
		regedit->tree_input = !regedit->tree_input;
		print_heading(regedit);
		break;
	default:
		if (regedit->tree_input) {
			handle_tree_input(regedit, c);
		} else {
			handle_value_input(regedit, c);
		}
	}
}

int regedit_getch(void)
{
	int c;

	SMB_ASSERT(regedit_main);

	c = getch();
	if (c == KEY_RESIZE) {
		tree_view_resize(regedit_main->keys, KEY_HEIGHT, KEY_WIDTH,
				 KEY_START_Y, KEY_START_X);
		value_list_resize(regedit_main->vl, VAL_HEIGHT, VAL_WIDTH,
				  VAL_START_Y, VAL_START_X);
		print_heading(regedit_main);
		show_path(regedit_main);
	}

	return c;
}

static void display_window(TALLOC_CTX *mem_ctx, struct registry_context *ctx)
{
	struct regedit *regedit;
	struct tree_node *root;
	bool colors;
	int key;

	initscr();

	cbreak();
	noecho();

	colors = has_colors();
	if (colors) {
		start_color();
		use_default_colors();
		assume_default_colors(COLOR_WHITE, COLOR_BLUE);
		init_pair(PAIR_YELLOW_CYAN, COLOR_YELLOW, COLOR_CYAN);
		init_pair(PAIR_BLACK_CYAN, COLOR_BLACK, COLOR_CYAN);
		init_pair(PAIR_YELLOW_BLUE, COLOR_YELLOW, COLOR_BLUE);
	}

	regedit = talloc_zero(mem_ctx, struct regedit);
	SMB_ASSERT(regedit != NULL);
	regedit_main = regedit;

	regedit->registry_context = ctx;
	regedit->main_window = stdscr;
	keypad(regedit->main_window, TRUE);

	mvwprintw(regedit->main_window, 0, 0, "Path: ");
	regedit->path_label = newpad(1, PATH_WIDTH_MAX);
	SMB_ASSERT(regedit->path_label);
	wprintw(regedit->path_label, "/");
	show_path(regedit_main);

	root = load_hives(regedit);
	SMB_ASSERT(root != NULL);

	regedit->keys = tree_view_new(regedit, root, KEY_HEIGHT, KEY_WIDTH,
				      KEY_START_Y, KEY_START_X);
	SMB_ASSERT(regedit->keys != NULL);

	regedit->vl = value_list_new(regedit, VAL_HEIGHT, VAL_WIDTH,
				     VAL_START_Y, VAL_START_X);
	SMB_ASSERT(regedit->vl != NULL);

	regedit->tree_input = true;
	print_heading(regedit);

	tree_view_show(regedit->keys);
	load_values(regedit);
	value_list_show(regedit->vl);

	update_panels();
	doupdate();

	do {
		key = regedit_getch();

		handle_main_input(regedit, key);
		update_panels();
		doupdate();
	} while (key != 'q' || key == 'Q');

	endwin();
}

int main(int argc, const char **argv)
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

	frame = talloc_stackframe();

	setup_logging("regedit", DEBUG_DEFAULT_STDERR);
	lp_set_cmdline("log level", "0");

	/* process options */
	auth_info = user_auth_info_init(frame);
	if (auth_info == NULL) {
		exit(1);
	}
	popt_common_set_auth_info(auth_info);
	pc = poptGetContext("regedit", argc, argv, long_options, 0);

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

	display_window(frame, ctx);

	TALLOC_FREE(frame);

	return 0;
}

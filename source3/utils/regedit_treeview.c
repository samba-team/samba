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

#include "regedit_treeview.h"
#include "lib/registry/registry.h"

#define HEADING_X 3

struct tree_node *tree_node_new(TALLOC_CTX *ctx, struct tree_node *parent,
				const char *name, struct registry_key *key)
{
	struct tree_node *node;

	node = talloc_zero(ctx, struct tree_node);
	if (!node) {
		return NULL;
	}

	node->name = talloc_strdup(node, name);
	if (!node->name) {
		talloc_free(node);
		return NULL;
	}

	node->key = talloc_steal(node, key);

	if (parent) {
		/* Check if this node is the first descendant of parent. */
		if (!parent->child_head) {
			parent->child_head = node;
		}
		node->parent = parent;
	}

	return node;
}

void tree_node_append(struct tree_node *left, struct tree_node *right)
{
	if (left->next) {
		right->next = left->next;
		left->next->previous = right;
	}
	left->next = right;
	right->previous = left;
}

void tree_node_append_last(struct tree_node *list, struct tree_node *node)
{
	tree_node_append(tree_node_last(list), node);
}

struct tree_node *tree_node_pop(struct tree_node **plist)
{
	struct tree_node *node;

	node = *plist;

	if (node == NULL)
		return NULL;

	*plist = node->previous;
	if (*plist == NULL) {
		*plist = node->next;
	}
	if (node->previous) {
		node->previous->next = node->next;
	}
	if (node->next) {
		node->next->previous = node->previous;
	}
	if (node->parent && node->parent->child_head == node) {
		node->parent->child_head = node->next;
	}
	node->next = NULL;
	node->previous = NULL;

	return node;
}

struct tree_node *tree_node_first(struct tree_node *list)
{
	/* Grab the first node in this list from the parent if available. */
	if (list->parent) {
		return list->parent->child_head;
	}

	while (list && list->previous) {
		list = list->previous;
	}

	return list;
}

struct tree_node *tree_node_last(struct tree_node *list)
{
	while (list && list->next) {
		list = list->next;
	}

	return list;
}

static uint32_t get_num_subkeys(struct tree_node *node)
{
	const char *classname;
	uint32_t num_subkeys;
	uint32_t num_values;
	NTTIME last_change_time;
	uint32_t max_subkeynamelen;
	uint32_t max_valnamelen;
	uint32_t max_valbufsize;
	WERROR rv;

	rv = reg_key_get_info(node, node->key, &classname, &num_subkeys,
			      &num_values, &last_change_time,
			      &max_subkeynamelen, &max_valnamelen,
			      &max_valbufsize);

	if (W_ERROR_IS_OK(rv)) {
		return num_subkeys;
	}

	return 0;
}

bool tree_node_has_children(struct tree_node *node)
{
	if (node->child_head) {
		return true;
	}

	return get_num_subkeys(node) > 0;
}

static int node_cmp(struct tree_node **a, struct tree_node **b)
{
	return strcmp((*a)->name, (*b)->name);
}

void tree_node_insert_sorted(struct tree_node *list, struct tree_node *node)
{
	list = tree_node_first(list);

	if (node_cmp(&list, &node) >= 0) {
		tree_node_append(node, list);
		if (list->parent) {
			list->parent->child_head = node;
		}
		return;
	}

	while (list->next && node_cmp(&list->next, &node) < 0) {
		list = list->next;
	}

	tree_node_append(list, node);
}

WERROR tree_node_load_children(struct tree_node *node)
{
	struct registry_key *key;
	const char *key_name, *klass;
	NTTIME modified;
	uint32_t i, nsubkeys;
	WERROR rv;
	struct tree_node *prev, **array;

	/* does this node already have it's children loaded? */
	if (node->child_head)
		return WERR_OK;

	nsubkeys = get_num_subkeys(node);
	if (nsubkeys == 0)
		return WERR_OK;

	array = talloc_zero_array(node, struct tree_node *, nsubkeys);
	if (array == NULL) {
		return WERR_NOMEM;
	}

	for (i = 0; i < nsubkeys; ++i) {
		rv = reg_key_get_subkey_by_index(node, node->key, i,
						 &key_name, &klass,
						 &modified);
		if (!W_ERROR_IS_OK(rv)) {
			goto finish;
		}

		rv = reg_open_key(node, node->key, key_name, &key);
		if (!W_ERROR_IS_OK(rv)) {
			goto finish;
		}

		array[i] = tree_node_new(node, node, key_name, key);
		if (array[i] == NULL) {
			rv = WERR_NOMEM;
			goto finish;
		}
	}

	TYPESAFE_QSORT(array, nsubkeys, node_cmp);

	for (i = 1, prev = array[0]; i < nsubkeys; ++i) {
		tree_node_append(prev, array[i]);
		prev = array[i];
	}
	node->child_head = array[0];

	rv = WERR_OK;

finish:
	if (!W_ERROR_IS_OK(rv)) {
		for (i = 0; i < nsubkeys; ++i) {
			talloc_free(array[i]);
		}
		node->child_head = NULL;
	}
	talloc_free(array);

	return rv;
}

void tree_node_free_recursive(struct tree_node *list)
{
	struct tree_node *node;

	if (list == NULL) {
		return;
	}

	while ((node = tree_node_pop(&list)) != NULL) {
		if (node->child_head) {
			tree_node_free_recursive(node->child_head);
		}
		node->child_head = NULL;
		talloc_free(node);
	}
}

static void tree_view_free_current_items(ITEM **items)
{
	size_t i;
	struct tree_node *node;
	ITEM *item;

	if (items == NULL) {
		return;
	}

	for (i = 0; items[i] != NULL; ++i) {
		item = items[i];
		node = item_userptr(item);
		if (node && node->label) {
			talloc_free(node->label);
			node->label = NULL;
		}
		free_item(item);
	}

	talloc_free(items);
}

void tree_view_clear(struct tree_view *view)
{
	unpost_menu(view->menu);
	set_menu_items(view->menu, view->empty);
	tree_view_free_current_items(view->current_items);
	view->current_items = NULL;
}

WERROR tree_view_update(struct tree_view *view, struct tree_node *list)
{
	ITEM **items;
	struct tree_node *node;
	size_t i, n_items;

	if (list == NULL) {
		list = view->root;
	}
	for (n_items = 0, node = list; node != NULL; node = node->next) {
		n_items++;
	}

	items = talloc_zero_array(view, ITEM *, n_items + 1);
	if (items == NULL) {
		return WERR_NOMEM;
	}

	for (i = 0, node = list; node != NULL; ++i, node = node->next) {
		char prefix = ' ';

		/* Add a '+' marker to indicate that the item has
		   descendants. */
		if (tree_node_has_children(node)) {
			prefix = '+';
		}

		SMB_ASSERT(node->label == NULL);
		node->label = talloc_asprintf(node, "%c%s", prefix, node->name);
		if (node->label == NULL) {
			goto fail;
		}

		items[i] = new_item(node->label, node->name);
		set_item_userptr(items[i], node);
	}

	unpost_menu(view->menu);
	set_menu_items(view->menu, items);
	tree_view_free_current_items(view->current_items);
	view->current_items = items;

	return WERR_OK;

fail:
	tree_view_free_current_items(items);

	return WERR_NOMEM;
}

/* is this node in the current level? */
bool tree_view_is_node_visible(struct tree_view *view, struct tree_node *node)
{
	struct tree_node *first;

	first = item_userptr(view->current_items[0]);

	return first->parent == node->parent;
}

void tree_view_set_current_node(struct tree_view *view, struct tree_node *node)
{
	ITEM **it;

	for (it = view->current_items; *it; ++it) {
		if (item_userptr(*it) == node) {
			set_current_item(view->menu, *it);
			return;
		}
	}
}

struct tree_node *tree_view_get_current_node(struct tree_view *view)
{
	return item_userptr(current_item(view->menu));
}

void tree_view_set_selected(struct tree_view *view, bool select)
{
	attr_t attr = A_NORMAL;

	if (select) {
		attr = A_REVERSE;
	}
	mvwchgat(view->window, 0, HEADING_X, 3, attr, 0, NULL);
}

void tree_view_show(struct tree_view *view)
{
	post_menu(view->menu);
}

static int tree_view_free(struct tree_view *view)
{
	if (view->menu) {
		unpost_menu(view->menu);
		free_menu(view->menu);
	}
	if (view->empty[0]) {
		free_item(view->empty[0]);
	}
	if (view->panel) {
		del_panel(view->panel);
	}
	if (view->sub) {
		delwin(view->sub);
	}
	if (view->window) {
		delwin(view->window);
	}
	tree_view_free_current_items(view->current_items);
	tree_node_free_recursive(view->root);

	return 0;
}

struct tree_view *tree_view_new(TALLOC_CTX *ctx, struct tree_node *root,
				int nlines, int ncols, int begin_y,
				int begin_x)
{
	struct tree_view *view;
	static const char *dummy = "(empty)";

	view = talloc_zero(ctx, struct tree_view);
	if (view == NULL) {
		return NULL;
	}

	talloc_set_destructor(view, tree_view_free);

	view->empty[0] = new_item(dummy, dummy);
	if (view->empty[0] == NULL) {
		goto fail;
	}
	view->window = newwin(nlines, ncols, begin_y, begin_x);
	if (view->window == NULL) {
		goto fail;
	}
	view->sub = subwin(view->window, nlines - 2, ncols - 2,
			   begin_y + 1, begin_x + 1);
	if (view->sub == NULL) {
		goto fail;
	}
	box(view->window, 0, 0);
	mvwprintw(view->window, 0, HEADING_X, "Key");

	view->panel = new_panel(view->window);
	if (view->panel == NULL) {
		goto fail;
	}
	view->root = root;

	view->menu = new_menu(view->empty);
	if (view->menu == NULL) {
		goto fail;
	}
	set_menu_format(view->menu, nlines, 1);
	set_menu_win(view->menu, view->window);
	set_menu_sub(view->menu, view->sub);
	menu_opts_off(view->menu, O_SHOWDESC);
	set_menu_mark(view->menu, "* ");

	tree_view_update(view, root);

	return view;

fail:
	talloc_free(view);

	return NULL;
}

void tree_view_resize(struct tree_view *view, int nlines, int ncols,
			     int begin_y, int begin_x)
{
	WINDOW *nwin, *nsub;

	unpost_menu(view->menu);
	nwin = newwin(nlines, ncols, begin_y, begin_x);
	nsub = subwin(nwin, nlines - 2, ncols - 2, begin_y + 1, begin_x + 1);
	replace_panel(view->panel, nwin);
	delwin(view->sub);
	delwin(view->window);
	view->window = nwin;
	view->sub = nsub;
	box(view->window, 0, 0);
	mvwprintw(view->window, 0, HEADING_X, "Key");
	set_menu_format(view->menu, nlines, 1);
	set_menu_win(view->menu, view->window);
	set_menu_sub(view->menu, view->sub);
	post_menu(view->menu);
}

static void print_path_recursive(WINDOW *label, struct tree_node *node,
				 size_t *len)
{
	if (node->parent)
		print_path_recursive(label, node->parent, len);

	wprintw(label, "%s/", node->name);
	*len += 1 + strlen(node->name);
}

/* print the path of node to label */
size_t tree_node_print_path(WINDOW *label, struct tree_node *node)
{
	size_t len = 1;

	if (node == NULL)
		return 0;

	werase(label);
	wprintw(label, "/");

	if (node->parent)
		print_path_recursive(label, node->parent, &len);

	return len;
}

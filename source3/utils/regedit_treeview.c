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
#include "regedit_list.h"
#include "lib/registry/registry.h"

#define HEADING_X 3

static int tree_node_free(struct tree_node *node)
{
	DEBUG(9, ("tree_node_free('%s', %p)\n", node->name, node));
	return 0;
}

struct tree_node *tree_node_new(TALLOC_CTX *ctx, struct tree_node *parent,
				const char *name, struct registry_key *key)
{
	struct tree_node *node;

	node = talloc_zero(ctx, struct tree_node);
	if (!node) {
		return NULL;
	}
	talloc_set_destructor(node, tree_node_free);
	DEBUG(9, ("tree_node_new('%s', %p)\n", name, node));

	node->name = talloc_strdup(node, name);
	if (!node->name) {
		talloc_free(node);
		return NULL;
	}

	if (key) {
		node->key = talloc_steal(node, key);
	}

	if (parent) {
		/* Check if this node is the first descendant of parent. */
		if (!parent->child_head) {
			parent->child_head = node;
		}
		node->parent = parent;
	}

	return node;
}

/* prepare a root node with all available hives as children */
struct tree_node *tree_node_new_root(TALLOC_CTX *ctx,
				     struct registry_context *regctx)
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

	root = tree_node_new(ctx, NULL, "ROOT", NULL);
	if (root == NULL) {
		return NULL;
	}
	prev = NULL;

	for (i = 0; hives[i] != NULL; ++i) {
		rv = reg_get_predefined_key_by_name(regctx, hives[i], &key);
		if (!W_ERROR_IS_OK(rv)) {
			continue;
		}

		node = tree_node_new(root, root, hives[i], key);
		if (node == NULL) {
			return NULL;
		}
		if (prev) {
			tree_node_append(prev, node);
		}
		prev = node;
	}

	return root;
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

WERROR tree_node_reopen_key(struct registry_context *ctx,
			    struct tree_node *node)
{
	SMB_ASSERT(node->parent != NULL);
	SMB_ASSERT(node->name != NULL);
	TALLOC_FREE(node->key);

	if (tree_node_is_top_level(node)) {
		WERROR rv;
		struct registry_key *key;
		rv = reg_get_predefined_key_by_name(ctx, node->name, &key);
		if (W_ERROR_IS_OK(rv)) {
			node->key = talloc_steal(node, key);
		}
		return rv;
	}

	return reg_open_key(node, node->parent->key, node->name, &node->key);
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
	uint32_t i, nsubkeys, count;
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

	for (count = 0, i = 0; i < nsubkeys; ++i) {
		rv = reg_key_get_subkey_by_index(node, node->key, i,
						 &key_name, &klass,
						 &modified);
		if (!W_ERROR_IS_OK(rv)) {
			goto finish;
		}

		rv = reg_open_key(node, node->key, key_name, &key);
		if (!W_ERROR_IS_OK(rv)) {
			continue;
		}

		array[count] = tree_node_new(array, node, key_name, key);
		if (array[count] == NULL) {
			rv = WERR_NOMEM;
			goto finish;
		}
		++count;
	}

	if (count) {
		TYPESAFE_QSORT(array, count, node_cmp);

		for (i = 1, prev = array[0]; i < count; ++i) {
			talloc_steal(node, array[i]);
			tree_node_append(prev, array[i]);
			prev = array[i];
		}
		node->child_head = talloc_steal(node, array[0]);

		rv = WERR_OK;
	}

finish:
	talloc_free(array);

	return rv;
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

static WERROR prev_depth_first(struct tree_node **node)
{
	WERROR rv = WERR_OK;

	SMB_ASSERT(node != NULL && *node != NULL);

	if ((*node)->previous) {
		*node = (*node)->previous;
		while (tree_node_has_children(*node)) {
			rv = tree_node_load_children(*node);
			if (W_ERROR_IS_OK(rv)) {
				SMB_ASSERT((*node)->child_head != NULL);
				*node = tree_node_last((*node)->child_head);
			}
		}
	} else if (!tree_node_is_top_level(*node)) {
		*node = (*node)->parent;
	} else {
		*node = NULL;
	}

	return rv;
}

bool tree_node_next(struct tree_node **node, bool depth, WERROR *err)
{
	*err = WERR_OK;

	if (*node == NULL) {
		return false;
	}

	if (depth) {
		*err = next_depth_first(node);
	} else {
		*node = (*node)->next;
	}

	return *node != NULL && W_ERROR_IS_OK(*err);
}

bool tree_node_prev(struct tree_node **node, bool depth, WERROR *err)
{
	*err = WERR_OK;

	if (*node == NULL) {
		return false;
	}

	if (depth) {
		*err = prev_depth_first(node);
	} else {
		*node = (*node)->previous;
	}

	return *node != NULL && W_ERROR_IS_OK(*err);
}

void tree_view_clear(struct tree_view *view)
{
	multilist_set_data(view->list, NULL);
}

WERROR tree_view_set_root(struct tree_view *view, struct tree_node *root)
{
	multilist_set_data(view->list, NULL);
	talloc_free(view->root);
	view->root = root;
	return tree_view_update(view, root->child_head);
}

WERROR tree_view_set_path(struct tree_view *view, const char **path)
{
	struct tree_node *top, *node;
	WERROR rv;

	top = view->root->child_head;
	while (*path) {
		for (node = top; node != NULL; node = node->next) {
			if (strcmp(*path, node->name) == 0) {
				if (path[1] && tree_node_has_children(node)) {
					rv = tree_node_load_children(node);
					if (!W_ERROR_IS_OK(rv)) {
						return rv;
					}
					SMB_ASSERT(node->child_head);
					top = node->child_head;
					break;
				} else {
					tree_view_update(view, top);
					tree_view_set_current_node(view, node);
					return WERR_OK;
				}
			}
		}
		++path;
	}

	return WERR_OK;
}

WERROR tree_view_update(struct tree_view *view, struct tree_node *list)
{
	WERROR rv;

	rv = multilist_set_data(view->list, list);
	if (W_ERROR_IS_OK(rv)) {
		multilist_refresh(view->list);
	}

	return rv;
}

/* is this node in the current level? */
bool tree_view_is_node_visible(struct tree_view *view, struct tree_node *node)
{
	const struct tree_node *first;

	first = multilist_get_data(view->list);

	return first && first->parent == node->parent;
}

void tree_view_set_current_node(struct tree_view *view, struct tree_node *node)
{
	multilist_set_current_row(view->list, node);
}

struct tree_node *tree_view_get_current_node(struct tree_view *view)
{
	const void *row = multilist_get_current_row(view->list);
	return talloc_get_type_abort(row, struct tree_node);
}

void tree_view_driver(struct tree_view *view, int c)
{
	multilist_driver(view->list, c);
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
	multilist_refresh(view->list);
	touchwin(view->window);
	wnoutrefresh(view->window);
	wnoutrefresh(view->sub);
}

static int tree_view_free(struct tree_view *view)
{
	if (view->panel) {
		del_panel(view->panel);
	}
	if (view->sub) {
		delwin(view->sub);
	}
	if (view->window) {
		delwin(view->window);
	}

	return 0;
}

static const char *tv_get_column_header(const void *data, unsigned col)
{
	SMB_ASSERT(col == 0);
	return "Name";
}

static const void *tv_get_first_row(const void *data)
{
	if (data == NULL) {
		return NULL;
	}

	return talloc_get_type_abort(data, struct tree_node);
}

static const void *tv_get_next_row(const void *data, const void *row)
{
	const struct tree_node *node;
	SMB_ASSERT(row != NULL);
	node = talloc_get_type_abort(row, struct tree_node);
	return node->next;
}

static const void *tv_get_prev_row(const void *data, const void *row)
{
	const struct tree_node *node;
	SMB_ASSERT(row != NULL);
	node = talloc_get_type_abort(row, struct tree_node);
	return node->previous;
}

static const char *tv_get_item_prefix(const void *row, unsigned col)
{
	struct tree_node *node;

	SMB_ASSERT(col == 0);
	SMB_ASSERT(row != NULL);
	node = talloc_get_type_abort(row, struct tree_node);
	if (tree_node_has_children(node)) {
		return "+";
	}
	return " ";
}

static const char *tv_get_item_label(const void *row, unsigned col)
{
	const struct tree_node *node;
	SMB_ASSERT(col == 0);
	SMB_ASSERT(row != NULL);
	node = talloc_get_type_abort(row, struct tree_node);
	return node->name;
}

static struct multilist_accessors tv_accessors = {
	.get_column_header = tv_get_column_header,
	.get_first_row = tv_get_first_row,
	.get_next_row = tv_get_next_row,
	.get_prev_row = tv_get_prev_row,
	.get_item_prefix = tv_get_item_prefix,
	.get_item_label = tv_get_item_label
};

struct tree_view *tree_view_new(TALLOC_CTX *ctx, struct tree_node *root,
				int nlines, int ncols, int begin_y,
				int begin_x)
{
	struct tree_view *view;

	view = talloc_zero(ctx, struct tree_view);
	if (view == NULL) {
		return NULL;
	}

	talloc_set_destructor(view, tree_view_free);

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

	view->list = multilist_new(view, view->sub, &tv_accessors, 1);
	if (view->list == NULL) {
		goto fail;
	}
	tree_view_update(view, root->child_head);

	return view;

fail:
	talloc_free(view);

	return NULL;
}

void tree_view_resize(struct tree_view *view, int nlines, int ncols,
		      int begin_y, int begin_x)
{
	WINDOW *nwin, *nsub;

	nwin = newwin(nlines, ncols, begin_y, begin_x);
	if (nwin == NULL) {
		return;
	}
	nsub = subwin(nwin, nlines - 2, ncols - 2, begin_y + 1, begin_x + 1);
	if (nsub == NULL) {
		delwin(nwin);
		return;
	}
	replace_panel(view->panel, nwin);
	delwin(view->sub);
	delwin(view->window);
	view->window = nwin;
	view->sub = nsub;
	box(view->window, 0, 0);
	mvwprintw(view->window, 0, HEADING_X, "Key");
	multilist_set_window(view->list, view->sub);
	tree_view_show(view);
}

const char **tree_node_get_path(TALLOC_CTX *ctx, struct tree_node *node)
{
	const char **array;
	size_t nitems, index;
	struct tree_node *p;

	for (nitems = 0, p = node; !tree_node_is_root(p); p = p->parent) {
		++nitems;
	}

	array = talloc_zero_array(ctx, const char *, nitems + 1);
	if (array == NULL) {
		return NULL;
	}

	for (index = nitems - 1, p = node;
	     !tree_node_is_root(p);
	     p = p->parent, --index) {
		array[index] = talloc_strdup(array, p->name);
		if (array[index] == NULL) {
			talloc_free(discard_const(array));
			return NULL;
		}
	}

	return array;
}

/* print the path of node to label */
size_t tree_node_print_path(WINDOW *label, struct tree_node *node)
{
	size_t len = 1;
	const char **path;
	TALLOC_CTX *frame;

	if (node == NULL)
		return 0;

	werase(label);
	wprintw(label, "/");

	if (tree_node_is_top_level(node))
		return 0;

	frame = talloc_stackframe();
	path = tree_node_get_path(frame, node->parent);

	while (*path) {
		len += strlen(*path) + 1;
		wprintw(label, "%s/", *path);
		++path;
	}

	talloc_free(frame);

	return len;
}

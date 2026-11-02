/*
   a talloc based red-black tree

   Copyright (C) Ronnie Sahlberg  2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include <talloc.h>

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/rb_tree.h"

#define NO_MEMORY_FATAL(p) do { if (!(p)) { \
          DEBUG(DEBUG_CRIT,("Out of memory for %s at %s\n", #p, __location__)); \
	  exit(10); \
	  }} while (0)

static inline trbt_node_t *trbt_rb2node(struct rb_node *rb)
{
	void *p = (char *)rb - offsetof(trbt_node_t, rb);

	return (trbt_node_t *)p;
}

/*
  destroy a tree and remove all its nodes
 */
static int tree_destructor(trbt_tree_t *tree)
{
	struct rb_node *rb = NULL;

	if (tree == NULL) {
		return 0;
	}

	if (tree->root.rb_node == NULL) {
		return 0;
	}

	/*
	 * Traverse the tree, remove the node destructor and steal the
	 * node to the tree. talloc frees the tree's children after
	 * this destructor returns. We don't want to use the existing
	 * destructor for the node since that will remove the nodes
	 * one by one from the tree. Since the entire tree will be
	 * completely destroyed we don't care if it is inconsistent or
	 * unbalanced while freeing the individual nodes.
	 */
	for (rb = rb_first(&tree->root); rb != NULL; rb = rb_next(rb)) {
		trbt_node_t *node = trbt_rb2node(rb);

		talloc_set_destructor(node, NULL);
		talloc_steal(tree, node);
	}

	return 0;
}


/* create a red black tree */
trbt_tree_t *
trbt_create(TALLOC_CTX *memctx, uint32_t flags)
{
	trbt_tree_t *tree;

	tree = talloc_zero(memctx, trbt_tree_t);
	NO_MEMORY_FATAL(tree);

	/* If the tree is freed, we must walk over all entries and steal the
	   node from the stored data pointer and release the node.
	   Note, when we free the tree  we only free the tree and not any of
	   the data stored in the tree.
	*/
	talloc_set_destructor(tree, tree_destructor);
	tree->flags = flags;

	return tree;
}

/*
  destroy a node and remove it from its tree
 */
static int node_destructor(trbt_node_t *node)
{
	trbt_tree_t *tree = node->tree;

	rb_erase(&node->rb, &tree->root);

	if ((tree->flags & TRBT_AUTOFREE) && (tree->root.rb_node == NULL)) {
		talloc_free(tree);
	}

	return 0;
}

static inline trbt_node_t *trbt_create_node(trbt_tree_t *tree,
					    uint32_t key,
					    void *data)
{
	trbt_node_t *node = NULL;

	/*
	 * Let this node hang off data so that it is removed when data
	 * is freed
	 */
	node = talloc(data, trbt_node_t);
	NO_MEMORY_FATAL(node);

	*node = (trbt_node_t){
		.tree = tree,
		.key32 = key,
		.data = data,
	};

	talloc_set_destructor(node, node_destructor);

	return node;
}

/*
 * Find the node with the given key.
 * If there is no such node return NULL and set *parent and *link to where
 * a new node has to be linked in. parent and link may be NULL.
 */
static trbt_node_t *trbt_find(trbt_tree_t *tree,
			      uint32_t key,
			      struct rb_node **parent,
			      struct rb_node ***link)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *pa = NULL;

	while (*p != NULL) {
		trbt_node_t *node = trbt_rb2node(*p);

		if (key == node->key32) {
			return node;
		}
		pa = *p;
		if (key < node->key32) {
			p = &(*p)->rb_left;
		} else {
			p = &(*p)->rb_right;
		}
	}

	if (parent != NULL) {
		*parent = pa;
	}
	if (link != NULL) {
		*link = p;
	}
	return NULL;
}

/* insert a new node in the tree.
   if there is already a node with a matching key in the tree
   we replace it with the new data and return a pointer to the old data
   in case the caller wants to take any special action
 */
void *
trbt_insert32(trbt_tree_t *tree, uint32_t key, void *data)
{
	trbt_node_t *node = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;

	node = trbt_find(tree, key, &parent, &link);
	if (node != NULL) {
		void *old_data = NULL;

		/* this node already exists, replace data and return the
		   old data
		 */
		old_data = node->data;
		node->data = data;
		/*
		 * Let the node now be owned by the new data
		 * so the node is freed when the new data is released
		 */
		talloc_steal(node->data, node);

		return old_data;
	}

	node = trbt_create_node(tree, key, data);
	rb_link_node(&node->rb, parent, link);
	rb_insert_color(&node->rb, &tree->root);
	return NULL;
}

void *
trbt_lookup32(trbt_tree_t *tree, uint32_t key)
{
	trbt_node_t *node = NULL;

	node = trbt_find(tree, key, NULL, NULL);
	if (node == NULL) {
		return NULL;
	}
	return node->data;
}


/* This deletes a node from the tree.
   Note that this does not release the data that the node points to
*/
void
trbt_delete32(trbt_tree_t *tree, uint32_t key)
{
	trbt_node_t *node = NULL;

	node = trbt_find(tree, key, NULL, NULL);
	if (node == NULL) {
		return;
	}

	/* The node destructor unlinks the node from the tree */
	talloc_free(node);
}


void
trbt_insert32_callback(trbt_tree_t *tree, uint32_t key, void *(*callback)(void *param, void *data), void *param)
{
	trbt_node_t *node = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;

	node = trbt_find(tree, key, &parent, &link);
	if (node != NULL) {
		/* this node already exists, replace it
		 */
		node->data = callback(param, node->data);
		talloc_steal(node->data, node);

		return;
	}

	node = trbt_create_node(tree, key, callback(param, NULL));
	rb_link_node(&node->rb, parent, link);
	rb_insert_color(&node->rb, &tree->root);
}


struct trbt_array_param {
	void *(*callback)(void *param, void *data);
	void *param;
	uint32_t keylen;
	uint32_t *key;
	trbt_tree_t *tree;
};
static void *array_insert_callback(void *p, void *data)
{
	struct trbt_array_param *param = (struct trbt_array_param *)p;
	trbt_tree_t *tree = NULL;


	/* if keylen has reached 0 we are done and can call the users
	   callback function with the users parameters
	*/
	if (param->keylen == 0) {
		return param->callback(param->param, data);
	}


	/* keylen is not zero yes so we must create/process more subtrees */
	/* if data is NULL this means we did not yet have a subtree here
	   and we must create one.
	*/
	if (data == NULL) {
		/* create a new subtree and hang it off our current tree
		   set it to autofree so that the tree is freed when
		   the last node in it has been released.
		*/
		tree = trbt_create(param->tree, TRBT_AUTOFREE);
	} else {
		/* we already have a subtree for this path */
		tree = (trbt_tree_t *)data;
	}

	trbt_insertarray32_callback(tree, param->keylen, param->key, param->callback, param->param);

	/* now return either the old tree we got in *data or the new tree
	   we created to our caller so he can update his pointer in his
	   tree to point to our subtree
	*/
	return tree;
}



/* insert into the tree using an array of uint32 as a key */
void
trbt_insertarray32_callback(trbt_tree_t *tree, uint32_t keylen, uint32_t *key, void *(*cb)(void *param, void *data), void *pm)
{
	struct trbt_array_param tap;

	/* keylen-1 and key[1]  since the call to insert32 will consume the
	   first part of the key.
	*/
	tap.callback= cb;
	tap.param   = pm;
	tap.keylen  = keylen-1;
	tap.key     = &key[1];
	tap.tree    = tree;

	trbt_insert32_callback(tree, key[0], array_insert_callback, &tap);
}

/* lookup the tree using an array of uint32 as a key */
void *
trbt_lookuparray32(trbt_tree_t *tree, uint32_t keylen, uint32_t *key)
{
	/* if keylen is 1 we can do a regular lookup and return this to the
	   user
	*/
	if (keylen == 1) {
		return trbt_lookup32(tree, key[0]);
	}

	/* we need to lookup the next subtree */
	tree = trbt_lookup32(tree, key[0]);
	if (tree == NULL) {
		/* the key does not exist, return NULL */
		return NULL;
	}

	/* now lookup the next part of the key in our new tree */
	return trbt_lookuparray32(tree, keylen-1, &key[1]);
}

/* traverse the tree using an array of uint32 as a key */
int trbt_traversearray32(trbt_tree_t *tree,
			 uint32_t keylen,
			 int (*callback)(void *param, void *data),
			 void *param)
{
	struct rb_node *rb = NULL;
	struct rb_node *next = NULL;

	if (tree == NULL) {
		return 0;
	}

	/*
	 * The callbacks might free the data and with it the node, so
	 * determine the next node before calling out.
	 */
	for (rb = rb_first(&tree->root); rb != NULL; rb = next) {
		trbt_node_t *node = trbt_rb2node(rb);
		int ret;

		next = rb_next(rb);

		/*
		 * if keylen is 1 this means we can just call the callback
		 * otherwise we must pull the next subtree and traverse that
		 * one as well
		 */
		if (keylen == 1) {
			ret = callback(param, node->data);
		} else {
			ret = trbt_traversearray32(node->data,
						   keylen - 1,
						   callback,
						   param);
		}
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

/* this function will return the first node in a tree where
   the key is an array of uint32_t
*/
void *
trbt_findfirstarray32(trbt_tree_t *tree, uint32_t keylen)
{
	struct rb_node *rb = NULL;
	trbt_node_t *node = NULL;

	if (keylen < 1) {
		return NULL;
	}

	if (tree == NULL) {
		return NULL;
	}

	rb = rb_first(&tree->root);
	if (rb == NULL) {
		return NULL;
	}
	node = trbt_rb2node(rb);

	/* we found our node so return the data */
	if (keylen == 1) {
		return node->data;
	}

	/* we are still traversing subtrees so find the first node in the
	   next level of trees
	*/
	return trbt_findfirstarray32(node->data, keylen-1);
}

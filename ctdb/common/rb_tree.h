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



#define TRBT_RED		0x00
#define TRBT_BLACK		0x01
typedef struct _trbt_node_t {
	struct _trbt_tree_t *tree;
	struct _trbt_node_t *parent;
	struct _trbt_node_t *left;
	struct _trbt_node_t *right;
	uint32_t rb_color;
	uint32_t key32;
	void *data;
} trbt_node_t;

typedef struct _trbt_tree_t {
	trbt_node_t *tree;
} trbt_tree_t;



/* Create a RB tree */
trbt_tree_t *trbt_create(TALLOC_CTX *memctx);

/* Lookup a node in the tree and return a pointer to data or NULL */
void *trbt_lookup32(trbt_tree_t *tree, uint32_t key);

/* Insert a new node into the tree. If there was already a node with this
   key the pointer to the previous data is returned.
   The tree will talloc_steal() the data inserted into the tree .
*/
void *trbt_insert32(trbt_tree_t *tree, uint32_t key, void *data);

/* Delete a node from the tree and free all data associated with it */
void trbt_delete32(trbt_tree_t *tree, uint32_t key);



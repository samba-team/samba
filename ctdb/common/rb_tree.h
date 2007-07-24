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




trbt_tree_t *trbt_create(TALLOC_CTX *memctx);
void *trbt_lookup32(trbt_tree_t *tree, uint32_t key);
int trbt_insert32(trbt_tree_t *tree, uint32_t key, void *data);
void trbt_delete32(trbt_tree_t *tree, uint32_t key);



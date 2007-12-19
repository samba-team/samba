/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around red-black trees
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rbtree.h"

struct db_rbt_ctx {
	struct rb_root tree;
};

struct db_rbt_rec {
	struct db_rbt_ctx *db_ctx;
	struct db_rbt_node *node;
};

/* The structure that ends up in the tree */

struct db_rbt_node {
	struct rb_node rb_node;
	size_t keysize, valuesize;

	/*
	 * key and value are appended implicitly, "data" is only here as a
	 * target for offsetof()
	 */

	char data[];
};

/*
 * dissect a db_rbt_node into its implicit key and value parts
 */

static void db_rbt_parse_node(struct db_rbt_node *node,
			      TDB_DATA *key, TDB_DATA *value)
{
	key->dptr = ((uint8 *)node) + offsetof(struct db_rbt_node, data);
	key->dsize = node->keysize;
	value->dptr = key->dptr + node->keysize;
	value->dsize = node->valuesize;
}

static NTSTATUS db_rbt_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_rbt_rec *rec_priv = talloc_get_type_abort(
		rec->private_data, struct db_rbt_rec);

	struct db_rbt_node *node;

	struct rb_node ** p;
	struct rb_node * parent;

	TDB_DATA this_key, this_val;

	if (rec_priv->node != NULL) {

		/*
		 * The record was around previously
		 */

		db_rbt_parse_node(rec_priv->node, &this_key, &this_val);

		SMB_ASSERT(this_key.dsize == rec->key.dsize);
		SMB_ASSERT(memcmp(this_key.dptr, rec->key.dptr,
				  this_key.dsize) == 0);

		if (this_val.dsize >= data.dsize) {
			/*
			 * The new value fits into the old space
			 */
			memcpy(this_val.dptr, data.dptr, data.dsize);
			rec_priv->node->valuesize = data.dsize;
			return NT_STATUS_OK;
		}

		/*
		 * We need to delete the key from the tree and start fresh,
		 * there's not enough space in the existing record
		 */

		rb_erase(&rec_priv->node->rb_node, &rec_priv->db_ctx->tree);

		/*
		 * Keep the existing node around for a while: If the record
		 * existed before, we reference the key data in there.
		 */
	}

	node = (struct db_rbt_node *)SMB_MALLOC(
		offsetof(struct db_rbt_node, data) + rec->key.dsize
		+ data.dsize);

	if (node == NULL) {
		SAFE_FREE(rec_priv->node);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(node->rb_node);

	node->keysize = rec->key.dsize;
	node->valuesize = data.dsize;

	db_rbt_parse_node(node, &this_key, &this_val);

	memcpy(this_key.dptr, rec->key.dptr, node->keysize);
	SAFE_FREE(rec_priv->node);

	memcpy(this_val.dptr, data.dptr, node->valuesize);

	parent = NULL;
	p = &rec_priv->db_ctx->tree.rb_node;

	while (*p) {
		struct db_rbt_node *r;
		TDB_DATA search_key, search_val;
		int res;

		parent = (*p);

		r = (struct db_rbt_node *)
			((char *)(*p) - offsetof(struct db_rbt_node, rb_node));

		db_rbt_parse_node(r, &search_key, &search_val);

		res = memcmp(this_key.dptr, search_key.dptr,
			     MIN(this_key.dsize, search_key.dsize));

		if ((res < 0)
		    || ((res == 0)
			&& (this_key.dsize < search_key.dsize))) {
			p = &(*p)->rb_left;
		}
		else if ((res > 0)
			 || ((res == 0)
			     && (this_key.dsize > search_key.dsize))) {
			p = &(*p)->rb_right;
		}
		else {
			smb_panic("someone messed with the tree");
		}
	}

	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &rec_priv->db_ctx->tree);

	return NT_STATUS_OK;
}

static NTSTATUS db_rbt_delete(struct db_record *rec)
{
	struct db_rbt_rec *rec_priv = talloc_get_type_abort(
		rec->private_data, struct db_rbt_rec);

	if (rec_priv->node == NULL) {
		return NT_STATUS_OK;
	}

	rb_erase(&rec_priv->node->rb_node, &rec_priv->db_ctx->tree);
	SAFE_FREE(rec_priv->node);

	return NT_STATUS_OK;
}

static struct db_record *db_rbt_fetch_locked(struct db_context *db_ctx,
					     TALLOC_CTX *mem_ctx,
					     TDB_DATA key)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db_ctx->private_data, struct db_rbt_ctx);

	struct db_rbt_rec *rec_priv;
	struct db_record *result;
	struct rb_node *n;

	result = talloc(mem_ctx, struct db_record);

	if (result == NULL) {
		return NULL;
	}

	rec_priv = talloc(result, struct db_rbt_rec);

	if (rec_priv == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	rec_priv->db_ctx = ctx;

	result->store = db_rbt_store;
	result->delete_rec = db_rbt_delete;
	result->private_data = rec_priv;

	n = ctx->tree.rb_node;

	while (n != NULL) {
		struct db_rbt_node *r;
		TDB_DATA search_key, search_val;
		int res;

		r = (struct db_rbt_node *)
			((char *)n - offsetof(struct db_rbt_node, rb_node));

		db_rbt_parse_node(r, &search_key, &search_val);

		res = memcmp(key.dptr, search_key.dptr,
			     MIN(key.dsize, search_key.dsize));

		if ((res < 0)
		    || ((res == 0) && (key.dsize < search_key.dsize))) {
			n = n->rb_left;
		}
		else if ((res > 0)
			 || ((res == 0) && (key.dsize > search_key.dsize))) {
			n = n->rb_right;
		}
		else {
			rec_priv->node = r;
			result->key = search_key;
			result->value = search_val;
			return result;
		}
	}

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8_t *)talloc_memdup(
		result, key.dptr, key.dsize);

	if (result->key.dptr == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	rec_priv->node = NULL;
	result->value.dsize = 0;
	result->value.dptr = NULL;
	return result;
}

static int db_rbt_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
			TDB_DATA key, TDB_DATA *data)
{
	struct db_record *rec;

	if (!(rec = db->fetch_locked(db, mem_ctx, key))) {
		return -1;
	}

	data->dsize = rec->value.dsize;
	data->dptr = (uint8 *)talloc_memdup(mem_ctx, rec->value.dptr,
					    rec->value.dsize);
	TALLOC_FREE(rec);
	return 0;
}


static int db_rbt_traverse(struct db_context *db,
			   int (*f)(struct db_record *db,
				    void *private_data),
			   void *private_data)
{
	return -1;
}

static int db_rbt_get_seqnum(struct db_context *db)
{
	return 0;
}

struct db_context *db_open_rbt(TALLOC_CTX *mem_ctx)
{
	struct db_context *result;

	result = talloc(mem_ctx, struct db_context);

	if (result == NULL) {
		return NULL;
	}

	result->private_data = TALLOC_ZERO_P(result, struct db_rbt_ctx);

	if (result->private_data == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	result->fetch_locked = db_rbt_fetch_locked;
	result->fetch = db_rbt_fetch;
	result->traverse = db_rbt_traverse;
	result->traverse_read = db_rbt_traverse;
	result->get_seqnum = db_rbt_get_seqnum;

	return result;
}

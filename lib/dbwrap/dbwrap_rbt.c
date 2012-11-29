/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around red-black trees
   Copyright (C) Volker Lendecke 2007, 2008

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_rbt.h"
#include "../lib/util/rbtree.h"

#define DBWRAP_RBT_ALIGN(_size_) (((_size_)+15)&~15)

struct db_rbt_ctx {
	struct rb_root tree;
};

struct db_rbt_rec {
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

	char data[1];
};

/*
 * Hide the ugly pointer calculations in a function
 */

static struct db_rbt_node *db_rbt2node(struct rb_node *node)
{
	return (struct db_rbt_node *)
		((char *)node - offsetof(struct db_rbt_node, rb_node));
}

/*
 * Compare two keys
 */

static int db_rbt_compare(TDB_DATA a, TDB_DATA b)
{
	int res;

	res = memcmp(a.dptr, b.dptr, MIN(a.dsize, b.dsize));

	if ((res < 0) || ((res == 0) && (a.dsize < b.dsize))) {
		return -1;
	}
	if ((res > 0) || ((res == 0) && (a.dsize > b.dsize))) {
		return 1;
	}
	return 0;
}

/*
 * dissect a db_rbt_node into its implicit key and value parts
 */

static void db_rbt_parse_node(struct db_rbt_node *node,
			      TDB_DATA *key, TDB_DATA *value)
{
	key->dptr = ((uint8_t *)node) + offsetof(struct db_rbt_node, data);
	key->dsize = node->keysize;
	value->dptr = key->dptr + node->keysize;
	value->dsize = node->valuesize;
}

static NTSTATUS db_rbt_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_rbt_ctx *db_ctx = talloc_get_type_abort(
		rec->db->private_data, struct db_rbt_ctx);
	struct db_rbt_rec *rec_priv = (struct db_rbt_rec *)rec->private_data;
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
	}

	node = (struct db_rbt_node *)talloc_size(db_ctx,
		offsetof(struct db_rbt_node, data) + rec->key.dsize
		+ data.dsize);

	if (node == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (rec_priv->node != NULL) {
		/*
		 * We need to delete the key from the tree and start fresh,
		 * there's not enough space in the existing record
		 */

		rb_erase(&rec_priv->node->rb_node, &db_ctx->tree);

		/*
		 * Keep the existing node around for a while: If the record
		 * existed before, we reference the key data in there.
		 */
	}

	ZERO_STRUCT(node->rb_node);

	node->keysize = rec->key.dsize;
	node->valuesize = data.dsize;

	db_rbt_parse_node(node, &this_key, &this_val);

	memcpy(this_key.dptr, rec->key.dptr, node->keysize);
	TALLOC_FREE(rec_priv->node);
	rec_priv->node = node;

	memcpy(this_val.dptr, data.dptr, node->valuesize);

	parent = NULL;
	p = &db_ctx->tree.rb_node;

	while (*p) {
		struct db_rbt_node *r;
		TDB_DATA search_key, search_val;
		int res;

		parent = (*p);

		r = db_rbt2node(*p);

		db_rbt_parse_node(r, &search_key, &search_val);

		res = db_rbt_compare(this_key, search_key);

		if (res == -1) {
			p = &(*p)->rb_left;
		}
		else if (res == 1) {
			p = &(*p)->rb_right;
		}
		else {
			smb_panic("someone messed with the tree");
		}
	}

	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &db_ctx->tree);

	return NT_STATUS_OK;
}

static NTSTATUS db_rbt_delete(struct db_record *rec)
{
	struct db_rbt_ctx *db_ctx = talloc_get_type_abort(
		rec->db->private_data, struct db_rbt_ctx);
	struct db_rbt_rec *rec_priv = (struct db_rbt_rec *)rec->private_data;

	if (rec_priv->node == NULL) {
		return NT_STATUS_OK;
	}

	rb_erase(&rec_priv->node->rb_node, &db_ctx->tree);
	TALLOC_FREE(rec_priv->node);

	return NT_STATUS_OK;
}

static NTSTATUS db_rbt_store_deny(struct db_record *rec, TDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_rbt_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

struct db_rbt_search_result {
	TDB_DATA key;
	TDB_DATA val;
	struct db_rbt_node* node;
};

static bool db_rbt_search_internal(struct db_context *db, TDB_DATA key,
				   struct db_rbt_search_result *result)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);

	struct rb_node *n;
	bool found = false;
	struct db_rbt_node *r = NULL;
	TDB_DATA search_key, search_val;

	n = ctx->tree.rb_node;

	while (n != NULL) {
		int res;

		r = db_rbt2node(n);

		db_rbt_parse_node(r, &search_key, &search_val);

		res = db_rbt_compare(key, search_key);

		if (res == -1) {
			n = n->rb_left;
		}
		else if (res == 1) {
			n = n->rb_right;
		}
		else {
			found = true;
			break;
		}
	}
	if (result != NULL) {
		if (found) {
			result->key = search_key;
			result->val = search_val;
			result->node = r;
		} else {
			ZERO_STRUCT(*result);
		}
	}
	return found;
}

static struct db_record *db_rbt_fetch_locked(struct db_context *db_ctx,
					     TALLOC_CTX *mem_ctx,
					     TDB_DATA key)
{
	struct db_rbt_rec *rec_priv;
	struct db_record *result;
	size_t size;
	bool found;
	struct db_rbt_search_result res;

	found = db_rbt_search_internal(db_ctx, key, &res);

	/*
	 * In this low-level routine, play tricks to reduce the number of
	 * tallocs to one. Not recommened for general use, but here it pays
	 * off.
	 */

	size = DBWRAP_RBT_ALIGN(sizeof(struct db_record))
		+ sizeof(struct db_rbt_rec);

	if (!found) {
		/*
		 * We need to keep the key around for later store
		 */
		size += key.dsize;
	}

	result = (struct db_record *)talloc_size(mem_ctx, size);
	if (result == NULL) {
		return NULL;
	}

	rec_priv = (struct db_rbt_rec *)
		((char *)result + DBWRAP_RBT_ALIGN(sizeof(struct db_record)));

	result->store = db_rbt_store;
	result->delete_rec = db_rbt_delete;
	result->private_data = rec_priv;

	rec_priv->node = res.node;
	result->value  = res.val;

	if (found) {
		result->key = res.key;
	}
	else {
		result->key.dptr = (uint8_t *)
			((char *)rec_priv + sizeof(*rec_priv));
		result->key.dsize = key.dsize;
		memcpy(result->key.dptr, key.dptr, key.dsize);
	}

	return result;
}

static int db_rbt_exists(struct db_context *db, TDB_DATA key)
{
	return db_rbt_search_internal(db, key, NULL);
}

static int db_rbt_wipe(struct db_context *db)
{
	struct db_rbt_ctx *old_ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	struct db_rbt_ctx *new_ctx = talloc_zero(db, struct db_rbt_ctx);
	if (new_ctx == NULL) {
		return -1;
	}
	db->private_data = new_ctx;
	talloc_free(old_ctx);
	return 0;
}

static NTSTATUS db_rbt_parse_record(struct db_context *db, TDB_DATA key,
				    void (*parser)(TDB_DATA key, TDB_DATA data,
						   void *private_data),
				    void *private_data)
{
	struct db_rbt_search_result res;
	bool found = db_rbt_search_internal(db, key, &res);

	if (!found) {
		return NT_STATUS_NOT_FOUND;
	}
	parser(res.key, res.val, private_data);
	return NT_STATUS_OK;
}

static int db_rbt_traverse_internal(struct db_context *db,
				    struct rb_node *n,
				    int (*f)(struct db_record *db,
					     void *private_data),
				    void *private_data, uint32_t* count,
				    bool rw)
{
	struct rb_node *rb_right;
	struct rb_node *rb_left;
	struct db_record rec;
	struct db_rbt_rec rec_priv;
	int ret;

	if (n == NULL) {
		return 0;
	}

	rb_left = n->rb_left;
	rb_right = n->rb_right;

	ret = db_rbt_traverse_internal(db, rb_left, f, private_data, count, rw);
	if (ret != 0) {
		return ret;
	}

	rec_priv.node = db_rbt2node(n);
	/* n might be altered by the callback function */
	n = NULL;

	ZERO_STRUCT(rec);
	rec.db = db;
	rec.private_data = &rec_priv;
	if (rw) {
		rec.store = db_rbt_store;
		rec.delete_rec = db_rbt_delete;
	} else {
		rec.store = db_rbt_store_deny;
		rec.delete_rec = db_rbt_delete_deny;
	}
	db_rbt_parse_node(rec_priv.node, &rec.key, &rec.value);

	ret = f(&rec, private_data);
	(*count) ++;
	if (ret != 0) {
		return ret;
	}

	if (rec_priv.node != NULL) {
		/*
		 * If the current record is still there
		 * we should take the current rb_right.
		 */
		rb_right = rec_priv.node->rb_node.rb_right;
	}

	return db_rbt_traverse_internal(db, rb_right, f, private_data, count, rw);
}

static int db_rbt_traverse(struct db_context *db,
			   int (*f)(struct db_record *db,
				    void *private_data),
			   void *private_data)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	uint32_t count = 0;

	int ret = db_rbt_traverse_internal(db, ctx->tree.rb_node,
					   f, private_data, &count,
					   true /* rw */);
	if (ret != 0) {
		return -1;
	}
	if (count > INT_MAX) {
		return -1;
	}
	return count;
}

static int db_rbt_traverse_read(struct db_context *db,
				int (*f)(struct db_record *db,
					 void *private_data),
				void *private_data)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	uint32_t count = 0;

	int ret = db_rbt_traverse_internal(db, ctx->tree.rb_node,
					   f, private_data, &count,
					   false /* rw */);
	if (ret != 0) {
		return -1;
	}
	if (count > INT_MAX) {
		return -1;
	}
	return count;
}

static int db_rbt_get_seqnum(struct db_context *db)
{
	return 0;
}

static int db_rbt_trans_dummy(struct db_context *db)
{
	/*
	 * Transactions are pretty pointless in-memory, just return success.
	 */
	return 0;
}

static void db_rbt_id(struct db_context *db, const uint8_t **id, size_t *idlen)
{
	*id = (uint8_t *)db;
	*idlen = sizeof(struct db_context *);
}

struct db_context *db_open_rbt(TALLOC_CTX *mem_ctx)
{
	struct db_context *result;

	result = talloc_zero(mem_ctx, struct db_context);

	if (result == NULL) {
		return NULL;
	}

	result->private_data = talloc_zero(result, struct db_rbt_ctx);

	if (result->private_data == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	result->fetch_locked = db_rbt_fetch_locked;
	result->traverse = db_rbt_traverse;
	result->traverse_read = db_rbt_traverse_read;
	result->get_seqnum = db_rbt_get_seqnum;
	result->transaction_start = db_rbt_trans_dummy;
	result->transaction_commit = db_rbt_trans_dummy;
	result->transaction_cancel = db_rbt_trans_dummy;
	result->exists = db_rbt_exists;
	result->wipe = db_rbt_wipe;
	result->parse_record = db_rbt_parse_record;
	result->id = db_rbt_id;
	result->name = "dbwrap rbt";

	return result;
}

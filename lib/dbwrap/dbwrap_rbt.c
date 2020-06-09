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
#include "../lib/util/dlinklist.h"

#define DBWRAP_RBT_ALIGN(_size_) (((_size_)+15)&~15)

struct db_rbt_ctx {
	struct rb_root tree;
	struct db_rbt_node *nodes;
	size_t traverse_read;
	struct db_rbt_node **traverse_nextp;
};

struct db_rbt_rec {
	struct db_rbt_node *node;
};

/* The structure that ends up in the tree */

struct db_rbt_node {
	struct rb_node rb_node;
	size_t keysize, valuesize;
	struct db_rbt_node *prev, *next;
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
	size_t key_offset, value_offset;

	key_offset = DBWRAP_RBT_ALIGN(sizeof(struct db_rbt_node));
	key->dptr = ((uint8_t *)node) + key_offset;
	key->dsize = node->keysize;

	value_offset = DBWRAP_RBT_ALIGN(node->keysize);
	value->dptr = key->dptr + value_offset;
	value->dsize = node->valuesize;
}

static ssize_t db_rbt_reclen(size_t keylen, size_t valuelen)
{
	size_t len, tmp;

	len = DBWRAP_RBT_ALIGN(sizeof(struct db_rbt_node));

	tmp = DBWRAP_RBT_ALIGN(keylen);
	if (tmp < keylen) {
		goto overflow;
	}

	len += tmp;
	if (len < tmp) {
		goto overflow;
	}

	len += valuelen;
	if (len < valuelen) {
		goto overflow;
	}

	return len;
overflow:
	return -1;
}

static NTSTATUS db_rbt_storev(struct db_record *rec,
			      const TDB_DATA *dbufs, int num_dbufs, int flag)
{
	struct db_rbt_ctx *db_ctx = talloc_get_type_abort(
		rec->db->private_data, struct db_rbt_ctx);
	struct db_rbt_rec *rec_priv = (struct db_rbt_rec *)rec->private_data;
	struct db_rbt_node *node;

	struct rb_node ** p;
	struct rb_node *parent = NULL;
	struct db_rbt_node *parent_node = NULL;

	ssize_t reclen;
	TDB_DATA data, this_key, this_val;
	void *to_free = NULL;

	if (db_ctx->traverse_read > 0) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if ((flag == TDB_INSERT) && (rec_priv->node != NULL)) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if ((flag == TDB_MODIFY) && (rec_priv->node == NULL)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (num_dbufs == 1) {
		data = dbufs[0];
	} else {
		data = dbwrap_merge_dbufs(rec, dbufs, num_dbufs);
		if (data.dptr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		to_free = data.dptr;
	}

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
			TALLOC_FREE(to_free);
			return NT_STATUS_OK;
		}
	}

	reclen = db_rbt_reclen(rec->key.dsize, data.dsize);
	if (reclen == -1) {
		TALLOC_FREE(to_free);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	node = talloc_zero_size(db_ctx, reclen);
	if (node == NULL) {
		TALLOC_FREE(to_free);
		return NT_STATUS_NO_MEMORY;
	}

	if (rec_priv->node != NULL) {
		if (db_ctx->traverse_nextp != NULL) {
			if (*db_ctx->traverse_nextp == rec_priv->node) {
				*db_ctx->traverse_nextp = node;
			}
		}

		/*
		 * We need to delete the key from the tree and start fresh,
		 * there's not enough space in the existing record
		 */

		rb_erase(&rec_priv->node->rb_node, &db_ctx->tree);
		DLIST_REMOVE(db_ctx->nodes, rec_priv->node);

		/*
		 * Keep the existing node around for a while: If the record
		 * existed before, we reference the key data in there.
		 */
	}

	node->keysize = rec->key.dsize;
	node->valuesize = data.dsize;

	db_rbt_parse_node(node, &this_key, &this_val);

	memcpy(this_key.dptr, rec->key.dptr, node->keysize);
	TALLOC_FREE(rec_priv->node);
	rec_priv->node = node;

	if (node->valuesize > 0) {
		memcpy(this_val.dptr, data.dptr, node->valuesize);
	}

	parent = NULL;
	p = &db_ctx->tree.rb_node;

	while (*p) {
		struct db_rbt_node *r;
		TDB_DATA search_key, search_val;
		int res;

		r = db_rbt2node(*p);

		parent = (*p);
		parent_node = r;

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
	DLIST_ADD_AFTER(db_ctx->nodes, node, parent_node);
	rb_insert_color(&node->rb_node, &db_ctx->tree);

	TALLOC_FREE(to_free);

	return NT_STATUS_OK;
}

static NTSTATUS db_rbt_delete(struct db_record *rec)
{
	struct db_rbt_ctx *db_ctx = talloc_get_type_abort(
		rec->db->private_data, struct db_rbt_ctx);
	struct db_rbt_rec *rec_priv = (struct db_rbt_rec *)rec->private_data;

	if (db_ctx->traverse_read > 0) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}

	if (rec_priv->node == NULL) {
		return NT_STATUS_OK;
	}

	if (db_ctx->traverse_nextp != NULL) {
		if (*db_ctx->traverse_nextp == rec_priv->node) {
			*db_ctx->traverse_nextp = rec_priv->node->next;
		}
	}

	rb_erase(&rec_priv->node->rb_node, &db_ctx->tree);
	DLIST_REMOVE(db_ctx->nodes, rec_priv->node);
	TALLOC_FREE(rec_priv->node);

	return NT_STATUS_OK;
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
	TDB_DATA search_key = { 0 };
	TDB_DATA search_val = { 0 };

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

	result->storev = db_rbt_storev;
	result->delete_rec = db_rbt_delete;
	result->private_data = rec_priv;

	rec_priv->node = res.node;
	result->value  = res.val;
	result->value_valid = true;

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
				    int (*f)(struct db_record *db,
					     void *private_data),
				    void *private_data, uint32_t* count,
				    bool rw)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	struct db_rbt_node *cur = NULL;
	struct db_rbt_node *next = NULL;
	int ret;

	for (cur = ctx->nodes; cur != NULL; cur = next) {
		struct db_record rec;
		struct db_rbt_rec rec_priv;

		rec_priv.node = cur;
		next = rec_priv.node->next;

		ZERO_STRUCT(rec);
		rec.db = db;
		rec.private_data = &rec_priv;
		rec.storev = db_rbt_storev;
		rec.delete_rec = db_rbt_delete;
		db_rbt_parse_node(rec_priv.node, &rec.key, &rec.value);
		rec.value_valid = true;

		if (rw) {
			ctx->traverse_nextp = &next;
		}
		ret = f(&rec, private_data);
		(*count) ++;
		if (rw) {
			ctx->traverse_nextp = NULL;
		}
		if (ret != 0) {
			return ret;
		}
		if (rec_priv.node != NULL) {
			next = rec_priv.node->next;
		}
	}

	return 0;
}

static int db_rbt_traverse_read(struct db_context *db,
				int (*f)(struct db_record *db,
					 void *private_data),
				void *private_data)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	uint32_t count = 0;
	int ret;

	ctx->traverse_read++;
	ret = db_rbt_traverse_internal(db,
				       f, private_data, &count,
				       false /* rw */);
	ctx->traverse_read--;
	if (ret != 0) {
		return -1;
	}
	if (count > INT_MAX) {
		return -1;
	}
	return count;
}

static int db_rbt_traverse(struct db_context *db,
			   int (*f)(struct db_record *db,
				    void *private_data),
			   void *private_data)
{
	struct db_rbt_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_rbt_ctx);
	uint32_t count = 0;
	int ret;

	if (ctx->traverse_nextp != NULL) {
		return -1;
	};

	if (ctx->traverse_read > 0) {
		return db_rbt_traverse_read(db, f, private_data);
	}

	ret = db_rbt_traverse_internal(db,
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

static size_t db_rbt_id(struct db_context *db, uint8_t *id, size_t idlen)
{
	if (idlen >= sizeof(struct db_context *)) {
		memcpy(id, &db, sizeof(struct db_context *));
	}
	return sizeof(struct db_context *);
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

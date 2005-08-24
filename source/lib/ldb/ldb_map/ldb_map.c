/* 
   ldb database library - map backend

   Copyright (C) Jelmer Vernooij 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_private.h"
#include "lib/ldb/ldb_map/ldb_map.h"

struct map_private {
	struct ldb_map_mappings *mappings;
};

static struct ldb_dn *ldb_map_dn(struct ldb_module *module, const struct ldb_dn *dn)
{
	/* FIXME */
	return NULL;
}

static char *ldb_map_expression(struct ldb_module *module, const char *expr)
{
	/* FIXME */
	return NULL;
}

static const char **ldb_map_attrs(struct ldb_module *module, const char *const attrs[])
{
	/* FIXME */
	return NULL;
}

static struct ldb_message *ldb_map_message_incoming(struct ldb_module *module, const struct ldb_message *mi)
{
	/* FIXME */
	return NULL;
}

static struct ldb_message *ldb_map_message_outgoing(struct ldb_module *module, const struct ldb_message *mi)
{
	/* FIXME */
	return NULL;
}

/*
  rename a record
*/
static int map_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct ldb_dn *n_olddn, *n_newdn;
	int ret;
	
	n_olddn = ldb_map_dn(module, olddn);
	n_newdn = ldb_map_dn(module, newdn);

	ret = ldb_next_rename_record(module, n_olddn, n_newdn);

	talloc_free(n_olddn);
	talloc_free(n_newdn);
	
	return ret;
}

/*
  delete a record
*/
static int map_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ldb_dn *newdn;
	int ret;

	newdn = ldb_map_dn(module, dn);

	ret = ldb_next_delete_record(module, newdn);

	talloc_free(newdn);

	return ret;
}


/*
  search for matching records
*/
static int map_search(struct ldb_module *module, const struct ldb_dn *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	char *newexpr;
	int ret;
	const char **newattrs;
	struct ldb_dn *new_base;
	struct ldb_message **newres;
	int i;

	newexpr = ldb_map_expression(module, expression);
	newattrs = ldb_map_attrs(module, attrs); 
	new_base = ldb_map_dn(module, base);

	ret = ldb_next_search(module, new_base, scope, newexpr, newattrs, &newres);

	talloc_free(new_base);
	talloc_free(newexpr);
	talloc_free(newattrs);

	for (i = 0; i < ret; i++) {
		*res[i] = ldb_map_message_incoming(module, newres[i]);
		talloc_free(newres[i]);
	}

	return ret;
}

/*
  add a record
*/
static int map_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *nmsg = ldb_map_message_outgoing(module, msg);
	int ret;

	ret = ldb_next_add_record(module, nmsg);

	talloc_free(nmsg);

	return ret;
}


/*
  search for matching records using a ldb_parse_tree
*/
static int map_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs, struct ldb_message ***res)
{
	struct map_private *privdat = module->private_data;
	char *expression;
	int ret;

	expression = ldb_filter_from_tree(privdat, tree);
	if (expression == NULL) {
		return -1;
	}
	ret = map_search(module, base, scope, expression, attrs, res);
	talloc_free(expression);
	return ret;
}

/*
  modify a record
*/
static int map_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *nmsg = ldb_map_message_outgoing(module, msg);
	int ret;

	ret = ldb_next_modify_record(module, nmsg);

	talloc_free(nmsg);

	return ret;
}

static int map_lock(struct ldb_module *module, const char *lockname)
{
	return ldb_next_named_lock(module, lockname);
}

static int map_unlock(struct ldb_module *module, const char *lockname)
{
	return ldb_next_named_unlock(module, lockname);
}

/*
  return extended error information
*/
static const char *map_errstring(struct ldb_module *module)
{
	return ldb_next_errstring(module);
}

static const struct ldb_module_ops map_ops = {
	.name          = "map",
	.search        = map_search,
	.search_bytree = map_search_bytree,
	.add_record    = map_add,
	.modify_record = map_modify,
	.delete_record = map_delete,
	.rename_record = map_rename,
	.named_lock    = map_lock,
	.named_unlock  = map_unlock,
	.errstring     = map_errstring
};

/* the init function */
struct ldb_module *ldb_map_init(struct ldb_context *ldb, struct ldb_map_mappings *mappings, const char *options[])
{
	struct ldb_module *ctx;
	struct map_private *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct map_private);
	if (!data) {
		talloc_free(ctx);
		return NULL;
	}

	data->mappings = mappings;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &map_ops;

	return ctx;
}

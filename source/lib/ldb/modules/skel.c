/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

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

/*
 *  Name: ldb
 *
 *  Component: ldb skel module
 *
 *  Description: example module
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

/* close */
static int skel_close(struct ldb_module *module)
{
	return ldb_next_close(module);
}

/* search */
static int skel_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	return ldb_next_search(module, base, scope, expression, attrs, res); 
}

/* search_free */
static int skel_search_free(struct ldb_module *module, struct ldb_message **res)
{
	return ldb_next_search_free(module, res);
}

/* add_record */
static int skel_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	return ldb_next_add_record(module, msg);
}

/* modify_record */
static int skel_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	return ldb_next_modify_record(module, msg);
}

/* delete_record */
static int skel_delete_record(struct ldb_module *module, const char *dn)
{
	return ldb_next_delete_record(module, dn);
}

/* rename_record */
static int skel_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	return ldb_next_rename_record(module, olddn, newdn);
}

/* return extended error information */
static const char *skel_errstring(struct ldb_module *module)
{
	return ldb_next_errstring(module);
}

static void skel_cache_free(struct ldb_module *module)
{
	ldb_next_cache_free(module);
}

static const struct ldb_module_ops skel_ops = {
	"skel",
	skel_close, 
	skel_search,
	skel_search_free,
	skel_add_record,
	skel_modify_record,
	skel_delete_record,
	skel_rename_record,
	skel_errstring,
	skel_cache_free
};

#ifdef HAVE_DLOPEN
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *skel_plugin_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;

	ctx = (struct ldb_module *)malloc(sizeof(struct ldb_module));
	if (!ctx)
		return NULL;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->private_data = NULL;
	ctx->ops = &skel_ops;

	return ctx;
}

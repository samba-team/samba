/* 
   ldb database module

   Copyright (C) Stefan Metzmacher 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb winsdb module
 *
 *  Description: verify winsdb records before they're written to disk
 *
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsdb.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"

/* add_record: do things with the sambaPassword attribute */
static int wins_ldb_verify(struct ldb_module *module, struct ldb_request *req, const struct ldb_message *msg)
{
	struct winsdb_handle *h = talloc_get_type(ldb_get_opaque(module->ldb, "winsdb_handle"),
						  struct winsdb_handle);
	char *error = NULL;

	if (!h) {
		error = talloc_strdup(module, "WINS_LDB: INTERNAL ERROR: no winsdb_handle present!");
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "%s", error);
		ldb_set_errstring(module->ldb, error);
		return LDB_ERR_OTHER;
	}

	switch (h->caller) {
	case WINSDB_HANDLE_CALLER_NBTD:
	case WINSDB_HANDLE_CALLER_WREPL:
		/* we trust our nbt and wrepl code ... */
		return ldb_next_request(module, req);

	case WINSDB_HANDLE_CALLER_ADMIN:
		error = talloc_strdup(module, "WINS_LDB: TODO verify add/modify for WINSDB_HANDLE_CALLER_ADMIN");
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "%s\n", error);
		return ldb_next_request(module, req);
	}

	return LDB_ERR_OTHER;
}

static int wins_ldb_request(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;

	switch (req->operation) {
	case LDB_REQ_ADD:
		msg = req->op.add.message;
		break;

	case LDB_REQ_MODIFY:
		msg = req->op.mod.message;
		break;

	default:
		goto call_next;
	}

	if (ldb_dn_is_special(msg->dn)) goto call_next;

	return wins_ldb_verify(module, req, msg);

call_next:
	return ldb_next_request(module, req);	
}

static const struct ldb_module_ops wins_ldb_ops = {
	.name          = "wins_ldb",
	.request       = wins_ldb_request
};


/* the init function */
struct ldb_module *wins_ldb_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;
	struct winsdb_handle *h;
	const char *owner;
	int ret;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx) return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &wins_ldb_ops;

	owner = lp_parm_string(-1, "winsdb", "local_owner");
	if (!owner) {
		owner = iface_n_ip(0);
		if (!owner) {
			owner = "0.0.0.0";
		}
	}

	h = talloc(ctx, struct winsdb_handle);
	if (!h) goto failed;
	h->ldb		= ldb;
	h->caller	= WINSDB_HANDLE_CALLER_ADMIN;
	h->local_owner	= talloc_strdup(h, owner);
	if (!h->local_owner) goto failed;

	ret = ldb_set_opaque(ldb, "winsdb_handle", h);
	if (ret != LDB_SUCCESS) goto failed;

	return ctx;

failed:
	talloc_free(ctx);
	return NULL;
}

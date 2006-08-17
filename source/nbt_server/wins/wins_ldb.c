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
#include "system/network.h"
#include "lib/socket/netif.h"

static int wins_ldb_verify(struct ldb_module *module, struct ldb_request *req)
{
	struct winsdb_handle *h = talloc_get_type(ldb_get_opaque(module->ldb, "winsdb_handle"),
						  struct winsdb_handle);
	const struct ldb_message *msg;

	switch (req->operation) {
	case LDB_ADD:
		msg = req->op.add.message;
		break;
		
	case LDB_MODIFY:
		msg = req->op.mod.message;
		break;

	default:
		return ldb_next_request(module, req);
	}

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	if (!h) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL, "%s", "WINS_LDB: INTERNAL ERROR: no winsdb_handle present!");
		return LDB_ERR_OTHER;
	}

	switch (h->caller) {
	case WINSDB_HANDLE_CALLER_NBTD:
	case WINSDB_HANDLE_CALLER_WREPL:
		/* we trust our nbt and wrepl code ... */
		return ldb_next_request(module, req);

	case WINSDB_HANDLE_CALLER_ADMIN:
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "%s\n", "WINS_LDB: TODO verify add/modify for WINSDB_HANDLE_CALLER_ADMIN");
		return ldb_next_request(module, req);
	}

	return LDB_ERR_OTHER;
}

static int wins_ldb_init(struct ldb_module *ctx)
{
	struct winsdb_handle *h;
	const char *owner;

	ctx->private_data = NULL;

	owner = lp_parm_string(-1, "winsdb", "local_owner");
	if (!owner) {
		owner = iface_n_ip(0);
		if (!owner) {
			owner = "0.0.0.0";
		}
	}

	h = talloc(ctx, struct winsdb_handle);
	if (!h) goto failed;
	h->ldb		= ctx->ldb;
	h->caller	= WINSDB_HANDLE_CALLER_ADMIN;
	h->local_owner	= talloc_strdup(h, owner);
	if (!h->local_owner) goto failed;

	return ldb_set_opaque(ctx->ldb, "winsdb_handle", h);

failed:
	talloc_free(h);
	return LDB_ERR_OTHER;
}

static const struct ldb_module_ops wins_ldb_ops = {
	.name          = "wins_ldb",
	.add           = wins_ldb_verify,
	.modify        = wins_ldb_verify,
	.init_context  = wins_ldb_init
};


/* the init function */
int wins_ldb_module_init(void)
{
	return ldb_register_module(&wins_ldb_ops);
}

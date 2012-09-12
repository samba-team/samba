/*
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007-2012

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

/*
 *  Name: ldb
 *
 *  Component: ldb secrets_tdb_sync module
 *
 *  Description: Update secrets.tdb whenever the matching secret record changes
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb_module.h"
#include "lib/util/dlinklist.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "auth/kerberos/kerberos_srv_keytab.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "param/secrets.h"
#include "source3/include/secrets.h"
#include "lib/dbwrap/dbwrap.h"
#include "dsdb/samdb/samdb.h"

struct dn_list {
	struct ldb_message *msg;
	bool do_delete;
	struct dn_list *prev, *next;
};

struct secrets_tdb_sync_private {
	struct dn_list *changed_dns;
	struct db_context *secrets_tdb;
};

struct secrets_tdb_sync_ctx {
	struct ldb_module *module;
	struct ldb_request *req;

	struct ldb_dn *dn;
	bool do_delete;

	struct ldb_reply *op_reply;
	bool found;
};

static struct secrets_tdb_sync_ctx *secrets_tdb_sync_ctx_init(struct ldb_module *module,
						struct ldb_request *req)
{
	struct secrets_tdb_sync_ctx *ac;

	ac = talloc_zero(req, struct secrets_tdb_sync_ctx);
	if (ac == NULL) {
		ldb_oom(ldb_module_get_ctx(module));
		return NULL;
	}

	ac->module = module;
	ac->req = req;

	return ac;
}

/* FIXME: too many semi-async searches here for my taste, direct and indirect as
 * cli_credentials_set_secrets() performs a sync ldb search.
 * Just hope we are lucky and nothing breaks (using the tdb backend masks a lot
 * of async issues). -SSS
 */
static int add_modified(struct ldb_module *module, struct ldb_dn *dn, bool do_delete,
			struct ldb_request *parent)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct secrets_tdb_sync_private *data = talloc_get_type(ldb_module_get_private(module), struct secrets_tdb_sync_private);
	struct dn_list *item;
	char *filter;
	struct ldb_result *res;
	int ret;

	filter = talloc_asprintf(data,
				 "(&(objectClass=primaryDomain)(flatname=*))");
	if (!filter) {
		return ldb_oom(ldb);
	}

	ret = dsdb_module_search(module, data, &res,
				 dn, LDB_SCOPE_BASE, NULL,
				 DSDB_FLAG_NEXT_MODULE, parent,
				 "%s", filter);
	talloc_free(filter);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (res->count != 1) {
		/* if it's not a primaryDomain then we don't have anything to update */
		talloc_free(res);
		return LDB_SUCCESS;
	}

	item = talloc(data->changed_dns? (void *)data->changed_dns: (void *)data, struct dn_list);
	if (!item) {
		talloc_free(res);
		return ldb_oom(ldb);
	}

	item->msg = talloc_steal(item, res->msgs[0]);
	item->do_delete = do_delete;
	talloc_free(res);

	DLIST_ADD_END(data->changed_dns, item, struct dn_list *);
	return LDB_SUCCESS;
}

static int ust_search_modified(struct secrets_tdb_sync_ctx *ac);

static int secrets_tdb_sync_op_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct secrets_tdb_sync_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct secrets_tdb_sync_ctx);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb, "Invalid request type!\n");
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ac->do_delete) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);
	}

	ac->op_reply = talloc_steal(ac, ares);

	ret = ust_search_modified(ac);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int ust_del_op(struct secrets_tdb_sync_ctx *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ret = ldb_build_del_req(&down_req, ldb, ac,
				ac->dn,
				ac->req->controls,
				ac, secrets_tdb_sync_op_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(ac->module, down_req);
}

static int ust_search_modified_callback(struct ldb_request *req,
					struct ldb_reply *ares)
{
	struct secrets_tdb_sync_ctx *ac;
	int ret;

	ac = talloc_get_type(req->context, struct secrets_tdb_sync_ctx);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		ac->found = true;
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:

		if (ac->found) {
			/* do the dirty sync job here :/ */
			ret = add_modified(ac->module, ac->dn, ac->do_delete, ac->req);
		}

		if (ac->do_delete) {
			ret = ust_del_op(ac);
			if (ret != LDB_SUCCESS) {
				return ldb_module_done(ac->req,
							NULL, NULL, ret);
			}
			break;
		}

		return ldb_module_done(ac->req, ac->op_reply->controls,
					ac->op_reply->response, LDB_SUCCESS);
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int ust_search_modified(struct secrets_tdb_sync_ctx *ac)
{
	struct ldb_context *ldb;
	static const char * const no_attrs[] = { NULL };
	struct ldb_request *search_req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	ret = ldb_build_search_req(&search_req, ldb, ac,
				   ac->dn, LDB_SCOPE_BASE,
				   "(&(objectClass=kerberosSecret)"
				     "(privateKeytab=*))", no_attrs,
				   NULL,
				   ac, ust_search_modified_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(ac->module, search_req);
}


/* add */
static int secrets_tdb_sync_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct secrets_tdb_sync_ctx *ac;
	struct ldb_request *down_req;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ac = secrets_tdb_sync_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	ac->dn = req->op.add.message->dn;

	ret = ldb_build_add_req(&down_req, ldb, ac,
				req->op.add.message,
				req->controls,
				ac, secrets_tdb_sync_op_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

/* modify */
static int secrets_tdb_sync_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct secrets_tdb_sync_ctx *ac;
	struct ldb_request *down_req;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ac = secrets_tdb_sync_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	ac->dn = req->op.mod.message->dn;

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				req->op.mod.message,
				req->controls,
				ac, secrets_tdb_sync_op_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

/* delete */
static int secrets_tdb_sync_delete(struct ldb_module *module, struct ldb_request *req)
{
	struct secrets_tdb_sync_ctx *ac;

	ac = secrets_tdb_sync_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb_module_get_ctx(module));
	}

	ac->dn = req->op.del.dn;
	ac->do_delete = true;

	return ust_search_modified(ac);
}

/* rename */
static int secrets_tdb_sync_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct secrets_tdb_sync_ctx *ac;
	struct ldb_request *down_req;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ac = secrets_tdb_sync_ctx_init(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	ac->dn = req->op.rename.newdn;

	ret = ldb_build_rename_req(&down_req, ldb, ac,
				req->op.rename.olddn,
				req->op.rename.newdn,
				req->controls,
				ac, secrets_tdb_sync_op_callback,
				req);
	LDB_REQ_SET_LOCATION(down_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

/* prepare for a commit */
static int secrets_tdb_sync_prepare_commit(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct secrets_tdb_sync_private *data = talloc_get_type(ldb_module_get_private(module),
								struct secrets_tdb_sync_private);
	struct dn_list *p;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(data);
	if (!tmp_ctx) {
		ldb_oom(ldb);
		goto fail;
	}

	for (p=data->changed_dns; p; p = p->next) {
		const struct ldb_val *whenChanged = ldb_msg_find_ldb_val(p->msg, "whenChanged");
		time_t lct = 0;
		bool ret;

		if (whenChanged) {
			ldb_val_to_time(whenChanged, &lct);
		}

		ret = secrets_store_machine_pw_sync(ldb_msg_find_attr_as_string(p->msg, "secret", NULL),
						    ldb_msg_find_attr_as_string(p->msg, "priorSecret", NULL),

						    ldb_msg_find_attr_as_string(p->msg, "flatname", NULL),
						    ldb_msg_find_attr_as_string(p->msg, "realm", NULL),
						    ldb_msg_find_attr_as_string(p->msg, "saltPrincipal", NULL),
						    (uint32_t)ldb_msg_find_attr_as_int(p->msg, "msDS-SupportedEncryptionTypes", ENC_ALL_TYPES),
						    samdb_result_dom_sid(tmp_ctx, p->msg, "objectSid"),

						    lct,
						    p->do_delete);
		if (ret == false) {
			ldb_asprintf_errstring(ldb, "Failed to update secrets.tdb from entry %s in %s",
					       ldb_dn_get_linearized(p->msg->dn),
					       (const char *)ldb_get_opaque(ldb, "ldb_url"));
			goto fail;
		}
	}

	talloc_free(data->changed_dns);
	data->changed_dns = NULL;
	talloc_free(tmp_ctx);

	return ldb_next_prepare_commit(module);

fail:
	dbwrap_transaction_cancel(data->secrets_tdb);
	talloc_free(data->changed_dns);
	data->changed_dns = NULL;
	talloc_free(tmp_ctx);
	return LDB_ERR_OPERATIONS_ERROR;
}

/* start a transaction */
static int secrets_tdb_sync_start_transaction(struct ldb_module *module)
{
	struct secrets_tdb_sync_private *data = talloc_get_type(ldb_module_get_private(module), struct secrets_tdb_sync_private);

	if (dbwrap_transaction_start(data->secrets_tdb) != 0) {
		return ldb_module_operr(module);
	}

	return ldb_next_start_trans(module);
}

/* end a transaction */
static int secrets_tdb_sync_end_transaction(struct ldb_module *module)
{
	struct secrets_tdb_sync_private *data = talloc_get_type(ldb_module_get_private(module), struct secrets_tdb_sync_private);

	if (dbwrap_transaction_commit(data->secrets_tdb) != 0) {
		return ldb_module_operr(module);
	}

	return ldb_next_end_trans(module);
}

/* abandon a transaction */
static int secrets_tdb_sync_del_transaction(struct ldb_module *module)
{
	struct secrets_tdb_sync_private *data = talloc_get_type(ldb_module_get_private(module), struct secrets_tdb_sync_private);

	talloc_free(data->changed_dns);
	data->changed_dns = NULL;
	if (dbwrap_transaction_cancel(data->secrets_tdb) != 0) {
		return ldb_module_operr(module);
	}

	return ldb_next_del_trans(module);
}

static int secrets_tdb_sync_init(struct ldb_module *module)
{
	struct ldb_context *ldb;
	struct secrets_tdb_sync_private *data;
	char *private_dir, *p;
	const char *secrets_ldb;

	ldb = ldb_module_get_ctx(module);

	data = talloc(module, struct secrets_tdb_sync_private);
	if (data == NULL) {
		return ldb_oom(ldb);
	}

	data->changed_dns = NULL;

	ldb_module_set_private(module, data);

	secrets_ldb = (const char *)ldb_get_opaque(ldb, "ldb_url");
	if (strncmp("tdb://", secrets_ldb, 6) == 0) {
		secrets_ldb += 6;
	}
	if (!secrets_ldb) {
		return ldb_operr(ldb);
	}
	private_dir = talloc_strdup(data, secrets_ldb);
	p = strrchr(private_dir, '/');
	if (p) {
		*p = '\0';
		secrets_init_path(private_dir);
	} else {
		secrets_init_path(".");
	}

	TALLOC_FREE(private_dir);

	data->secrets_tdb = secrets_db_ctx();

	return ldb_next_init(module);
}

static const struct ldb_module_ops ldb_secrets_tdb_sync_module_ops = {
	.name		   = "secrets_tdb_sync",
	.init_context	   = secrets_tdb_sync_init,
	.add               = secrets_tdb_sync_add,
	.modify            = secrets_tdb_sync_modify,
	.rename            = secrets_tdb_sync_rename,
	.del               = secrets_tdb_sync_delete,
	.start_transaction = secrets_tdb_sync_start_transaction,
	.prepare_commit    = secrets_tdb_sync_prepare_commit,
	.end_transaction   = secrets_tdb_sync_end_transaction,
	.del_transaction   = secrets_tdb_sync_del_transaction,
};

int ldb_secrets_tdb_sync_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_secrets_tdb_sync_module_ops);
}

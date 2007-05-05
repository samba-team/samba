/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007

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
 *  Component: ldb update_keytabs module
 *
 *  Description: Update keytabs whenever their matching secret record changes
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/ldb_includes.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "system/kerberos.h"

struct dn_list {
	struct cli_credentials *creds;
	struct dn_list *prev, *next;
};

struct update_kt_private {
	struct dn_list *changed_dns;
};

static int add_modified(struct ldb_module *module, struct ldb_dn *dn, BOOL delete) {
	struct update_kt_private *data = talloc_get_type(module->private_data, struct update_kt_private);
	struct dn_list *item;
	char *filter;
	struct ldb_result *res;
	const char *attrs[] = { NULL };
	int ret;
	NTSTATUS status;

	filter = talloc_asprintf(data, "(&(dn=%s)(&(objectClass=kerberosSecret)(privateKeytab=*)))",
				 ldb_dn_get_linearized(dn));
	if (!filter) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_search(module->ldb, dn, LDB_SCOPE_BASE,
			 filter, attrs, &res);
	if (ret != LDB_SUCCESS) {
		talloc_free(filter);
		return ret;
	}

	if (res->count != 1) {
		/* if it's not a kerberosSecret then we don't have anything to update */
		talloc_free(res);
		talloc_free(filter);
		return LDB_SUCCESS;
	}
	talloc_free(res);

	item = talloc(data->changed_dns? (void *)data->changed_dns: (void *)data, struct dn_list);
	if (!item) {
		talloc_free(filter);
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	item->creds = cli_credentials_init(item);
	if (!item->creds) {
		DEBUG(1, ("cli_credentials_init failed!"));
		talloc_free(filter);
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	cli_credentials_set_conf(item->creds);
	status = cli_credentials_set_secrets(item->creds, module->ldb, NULL, filter);
	talloc_free(filter);
	if (NT_STATUS_IS_OK(status)) {
		if (delete) {
			/* Ensure we don't helpfully keep an old keytab entry */
			cli_credentials_set_kvno(item->creds, cli_credentials_get_kvno(item->creds)+2);	
			/* Wipe passwords */
			cli_credentials_set_nt_hash(item->creds, NULL, 
						    CRED_SPECIFIED);
		}
		DLIST_ADD_END(data->changed_dns, item, struct dn_list *);
	}
	return LDB_SUCCESS;
}

/* add */
static int update_kt_add(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return add_modified(module, req->op.add.message->dn, False);
}

/* modify */
static int update_kt_modify(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return add_modified(module, req->op.mod.message->dn, False);
}

/* delete */
static int update_kt_delete(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	/* Before we delete it, record the details */
	ret = add_modified(module, req->op.del.dn, True);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_next_request(module, req);
}

/* rename */
static int update_kt_rename(struct ldb_module *module, struct ldb_request *req)
{
	int ret;
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return add_modified(module, req->op.rename.newdn, False);
}

/* end a transaction */
static int update_kt_end_trans(struct ldb_module *module)
{
	struct update_kt_private *data = talloc_get_type(module->private_data, struct update_kt_private);
	
	struct dn_list *p;
	for (p=data->changed_dns; p; p = p->next) {
		int kret;
		kret = cli_credentials_update_keytab(p->creds);
		if (kret != 0) {
			talloc_free(data->changed_dns);
			data->changed_dns = NULL;
			ldb_asprintf_errstring(module->ldb, "Failed to update keytab: %s", error_message(kret));
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	talloc_free(data->changed_dns);
	data->changed_dns = NULL;
	return ldb_next_end_trans(module);
}

/* end a transaction */
static int update_kt_del_trans(struct ldb_module *module)
{
	struct update_kt_private *data = talloc_get_type(module->private_data, struct update_kt_private);
	
	talloc_free(data->changed_dns);
	data->changed_dns = NULL;

	return ldb_next_end_trans(module);
}

static int update_kt_init(struct ldb_module *module)
{
	struct update_kt_private *data;

	data = talloc(module, struct update_kt_private);
	if (data == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	module->private_data = data;
	data->changed_dns = NULL;

	return ldb_next_init(module);
}

static const struct ldb_module_ops update_kt_ops = {
	.name		   = "update_keytab",
	.init_context	   = update_kt_init,
	.add               = update_kt_add,
	.modify            = update_kt_modify,
	.rename            = update_kt_rename,
	.del               = update_kt_delete,
	.end_transaction   = update_kt_end_trans,
	.del_transaction   = update_kt_del_trans,
};

int ldb_update_kt_init(void)
{
	return ldb_register_module(&update_kt_ops);
}

/* 
   Unix SMB/CIFS implementation.
   
   LDB based services configuration
   
   Copyright (C) Simo Sorce	2006
   
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

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "auth/auth.h"
#include "db_wrap.h"
#include "param/share.h"

static NTSTATUS sldb_init(TALLOC_CTX *mem_ctx, const struct share_ops *ops, struct share_context **ctx)
{
	struct ldb_context *sdb;

	*ctx = talloc(mem_ctx, struct share_context);
	if (!*ctx) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	sdb = ldb_wrap_connect( *ctx,
				private_path(*ctx, "share.ldb"),
				system_session(*ctx),
				NULL, 0, NULL);

	if (!sdb) {
		talloc_free(*ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	(*ctx)->ops = ops;
	(*ctx)->priv_data = (void *)sdb;

	return NT_STATUS_OK;
}

static const char *sldb_string_option(struct share_config *scfg, const char *opt_name, const char *defval)
{
	struct ldb_message *msg;
	struct ldb_message_element *el;

	if (scfg == NULL) return defval;

	msg = talloc_get_type(scfg->opaque, struct ldb_message);

	if (strchr(opt_name, ':')) {
		char *name, *p;

		name = talloc_strdup(scfg, opt_name);
		if (!name) {
			return NULL;
		}
		p = strchr(name, ':');
		*p = '-';

		el = ldb_msg_find_element(msg, name);
	} else {
		el = ldb_msg_find_element(msg, opt_name);
	}

	if (el == NULL) {
		return defval;
	}

	return (const char *)(el->values[0].data);
}

static int sldb_int_option(struct share_config *scfg, const char *opt_name, int defval)
{
	const char *val;
	int ret;

       	val = sldb_string_option(scfg, opt_name, NULL);
	if (val == NULL) return defval;

	errno = 0;
	ret = (int)strtol(val, NULL, 10);
	if (errno) return -1;

	return ret;
}

static BOOL sldb_bool_option(struct share_config *scfg, const char *opt_name, BOOL defval)
{
	const char *val;

       	val = sldb_string_option(scfg, opt_name, NULL);
	if (val == NULL) return defval;

	if (strcasecmp(val, "true") == 0) return True;

	return False;
}

static const char **sldb_string_list_option(TALLOC_CTX *mem_ctx, struct share_config *scfg, const char *opt_name)
{
	struct ldb_message *msg;
	struct ldb_message_element *el;
	const char **list;
	int i;

	if (scfg == NULL) return NULL;

	msg = talloc_get_type(scfg->opaque, struct ldb_message);

	if (strchr(opt_name, ':')) {
		char *name, *p;

		name = talloc_strdup(scfg, opt_name);
		if (!name) {
			return NULL;
		}
		p = strchr(name, ':');
		*p = '-';

		el = ldb_msg_find_element(msg, name);
	} else {
		el = ldb_msg_find_element(msg, opt_name);
	}

	if (el == NULL) {
		return NULL;
	}

	list = talloc_array(mem_ctx, const char *, el->num_values + 1);
	if (!list) return NULL;

	for (i = 0; i < el->num_values; i++) {
		list[i] = (const char *)(el->values[i].data);
	}
	list[i] = NULL;

	return list;
}

static NTSTATUS sldb_list_all(TALLOC_CTX *mem_ctx,
				 struct share_context *ctx,
				 int *count,
				 const char ***names)
{
	int ret, i, j;
	const char **n;
	struct ldb_context *ldb;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ldb = talloc_get_type(ctx->priv_data, struct ldb_context);

	ret = ldb_search(ldb, ldb_dn_explode(tmp_ctx, "CN=SHARES"), LDB_SCOPE_SUBTREE, "(name=*)", NULL, &res);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}
	talloc_steal(tmp_ctx, res);

	n = talloc_array(mem_ctx, const char *, res->count);
	if (!n) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0, j = 0; i < res->count; i++) {
		n[j] = talloc_strdup(n, ldb_msg_find_attr_as_string(res->msgs[i], "name", NULL));
		if (!n[j]) {
			DEBUG(0,("WARNING: Malformed share object in share database\n!"));
			continue;
		}
		j++;
	}

	*names = n;
	*count = j;
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS sldb_get_config(TALLOC_CTX *mem_ctx,
			 struct share_context *ctx,
			 const char *name,
			 struct share_config **scfg)
{
	int ret;
	struct share_config *s;
	struct ldb_context *ldb;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx;
	char *filter;

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ldb = talloc_get_type(ctx->priv_data, struct ldb_context);

	filter = talloc_asprintf(tmp_ctx,"(name=%s)", name);
	if (!filter) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_search(ldb, ldb_dn_explode(tmp_ctx, "CN=SHARES"), LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	talloc_steal(tmp_ctx, res);

	s = talloc(tmp_ctx, struct share_config);
	if (!s) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	s->name = talloc_strdup(s, ldb_msg_find_attr_as_string(res->msgs[0], "name", NULL));
	if (!s->name) {
		DEBUG(0,("ERROR: Invalid share object!\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	s->opaque = talloc_steal(s, res->msgs[0]);
	if (!s->opaque) {
		DEBUG(0,("ERROR: Invalid share object!\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	s->ctx = ctx;

	*scfg = talloc_steal(mem_ctx, s);

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

NTSTATUS share_ldb_init(void *mem_ctx)
{
	struct share_ops ops;

	ops.name = "ldb";
	ops.init = sldb_init;
	ops.string_option = sldb_string_option;
	ops.int_option = sldb_int_option;
	ops.bool_option = sldb_bool_option;
	ops.string_list_option = sldb_string_list_option;
	ops.list_all = sldb_list_all;
	ops.get_config = sldb_get_config;

	return share_register(&ops);
}


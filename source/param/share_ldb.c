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

#define SHARE_ADD_STRING(type, data) do { \
	err = ldb_msg_add_string(msg, type, data); \
	if (err != LDB_SUCCESS) { \
		DEBUG(2,("ERROR: unable to add share %s to ldb msg\n", type)); \
		ret = NT_STATUS_UNSUCCESSFUL; \
		goto done; \
	} } while(0)

NTSTATUS sldb_create(struct share_context *ctx, struct share_info *info)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS ret;
	char *conns;
	int err;

	if (!info->name || !info->type || !info->path) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ldb = talloc_get_type(ctx->priv_data, struct ldb_context);

	msg = ldb_msg_new(tmp_ctx);
	if (!msg) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* TODO: escape info->name */
	msg->dn = ldb_dn_string_compose(tmp_ctx, ldb_dn_new(tmp_ctx), "CN=%s,CN=SHARES", info->name);
	if (!msg->dn) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	SHARE_ADD_STRING("cn", info->name);
	SHARE_ADD_STRING("objectClass", "top");
	SHARE_ADD_STRING("objectClass", "share");

	SHARE_ADD_STRING(SHARE_NAME, info->name);
	SHARE_ADD_STRING(SHARE_TYPE, info->type);
	SHARE_ADD_STRING(SHARE_PATH, info->path);
	if (strcmp(info->type, "DISK") == 0) {
		SHARE_ADD_STRING(SHARE_NTVFS_HANDLER, "default");
	}
	if (info->comment) {
		SHARE_ADD_STRING(SHARE_COMMENT, info->comment);
	}

	if (info->password) {
		SHARE_ADD_STRING(SHARE_PASSWORD, info->password);
	}

	/* TODO: Security Descriptor */

	SHARE_ADD_STRING(SHARE_AVAILABLE, "True");
	SHARE_ADD_STRING(SHARE_BROWSEABLE, "True");
	SHARE_ADD_STRING(SHARE_READONLY, "False");
	conns = talloc_asprintf(tmp_ctx, "%d", info->max_users);
	SHARE_ADD_STRING(SHARE_MAX_CONNECTIONS, conns);

	err = ldb_add(ldb, msg);
	if (err != LDB_SUCCESS) {
		DEBUG(2,("ERROR: unable to add share %s to share.ldb\n"
			 "       err=%d [%s]\n", info->name, err, ldb_errstring(ldb)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return ret;
}

NTSTATUS sldb_remove(struct share_context *ctx, const char *name)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS ret;
	int err;

	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ldb = talloc_get_type(ctx->priv_data, struct ldb_context);

	dn = ldb_dn_string_compose(tmp_ctx, ldb_dn_new(tmp_ctx), "CN=%s,CN=SHARES", name);
	if (!dn) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	err = ldb_delete(ldb, dn);
	if (err != LDB_SUCCESS) {
		DEBUG(2,("ERROR: unable to remove share %s from share.ldb\n"
			 "       err=%d [%s]\n", name, err, ldb_errstring(ldb)));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return ret;
}

NTSTATUS share_ldb_init(void)
{
	static struct share_ops ops = {
		.name = "ldb",
		.init = sldb_init,
		.string_option = sldb_string_option,
		.int_option = sldb_int_option,
		.bool_option = sldb_bool_option,
		.string_list_option = sldb_string_list_option,
		.list_all = sldb_list_all,
		.get_config = sldb_get_config,
		.create = sldb_create,
		.remove = sldb_remove
	};

	return share_register(&ops);
}


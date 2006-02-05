/* 
   Unix SMB/CIFS implementation.

   rootDSE ldb module

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Simo Sorce 2005
   
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
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "auth/gensec/gensec.h"
#include "system/time.h"

struct private_data {
	int num_controls;
	char **controls;
};

/*
  return 1 if a specific attribute has been requested
*/
static int do_attribute(const char * const *attrs, const char *name)
{
	return attrs == NULL ||
		ldb_attr_in_list(attrs, name) ||
		ldb_attr_in_list(attrs, "*");
}

/*
  add dynamically generated attributes to rootDSE result
*/
static int rootdse_add_dynamic(struct ldb_module *module, struct ldb_request *req)
{
	struct private_data *priv = talloc_get_type(module->private_data, struct private_data);
	struct ldb_search *s = &req->op.search;
	struct ldb_message *msg;
	struct cli_credentials *server_creds;

	/* this is gross, and will be removed when I change ldb_result not
	   to be so pointer crazy :-) */
	if (s->res->msgs == NULL) {
		return LDB_SUCCESS;
	}

	msg = s->res->msgs[0];

	msg->dn = ldb_dn_explode(msg, "");

	if (do_attribute(s->attrs, "currentTime")) {
		if (ldb_msg_add_string(msg, "currentTime", 
				       ldb_timestring(msg, time(NULL))) != 0) {
			goto failed;
		}
	}

	if (do_attribute(s->attrs, "supportedControl")) {
 		int i;
		for (i = 0; i < priv->num_controls; i++) {
			if (ldb_msg_add_string(msg, "supportedControl",
						priv->controls[i]) != 0) {
				goto failed;
 			}
 		}
 	}

	server_creds = talloc_get_type(ldb_get_opaque(module->ldb, "server_credentials"), 
				       struct cli_credentials);
	if (server_creds && do_attribute(s->attrs, "supportedSASLMechanisms")) {
		struct gensec_security_ops **backends = gensec_security_all();
		enum credentials_use_kerberos use_kerberos
			= cli_credentials_get_kerberos_state(server_creds);
		struct gensec_security_ops **ops
			= gensec_use_kerberos_mechs(req, backends, use_kerberos);
		int i;
		for (i = 0; ops && ops[i]; i++) {
			if (ops[i]->sasl_name) {
				const char *sasl_name = talloc_strdup(msg, ops[i]->sasl_name);
				if (!sasl_name) {
					goto failed;
				}
				if (ldb_msg_add_string(msg, "supportedSASLMechanisms",
						       sasl_name) != 0) {
					goto failed;
				}
			}
		}
	}
	
	/* TODO: lots more dynamic attributes should be added here */

	return 0;

failed:
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  handle search requests
*/
static int rootdse_search_bytree(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_search *s = &req->op.search;
	int ret;
	TALLOC_CTX *tmp_ctx;

	/* see if its for the rootDSE */
	if (s->scope != LDB_SCOPE_BASE ||
	    (s->base && s->base->comp_num != 0)) {
		return ldb_next_request(module, req);
	}

	tmp_ctx = talloc_new(module);

	/* in our db we store the rootDSE with a DN of cn=rootDSE */
	s->base = ldb_dn_explode(tmp_ctx, "cn=rootDSE");
	s->tree = ldb_parse_tree(tmp_ctx, "dn=*");
	if (s->base == NULL || s->tree == NULL) {
		ldb_oom(module->ldb);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* grab the static contents of the record */
	ret = ldb_next_request(module, req);

	req->op.search.res = s->res;

	if (ret == LDB_SUCCESS) {
		ret = rootdse_add_dynamic(module, req);
	}

	talloc_free(tmp_ctx);

	return ret;
}

static int rootdse_register_control(struct ldb_module *module, struct ldb_request *req)
{
	struct private_data *priv = talloc_get_type(module->private_data, struct private_data);
	char **list;

	list = talloc_realloc(priv, priv->controls, char *, priv->num_controls + 1);
	if (!list) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	list[priv->num_controls] = talloc_strdup(list, req->op.reg.oid);
	if (!list[priv->num_controls]) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	priv->num_controls += 1;
	priv->controls = list;

	return LDB_SUCCESS;
}
 

static int rootdse_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {
	case LDB_REQ_SEARCH:
		return rootdse_search_bytree(module, req);
	case LDB_REQ_REGISTER:
		return rootdse_register_control(module, req);
	default:
		break;
	}
	return ldb_next_request(module, req);
}

static const struct ldb_module_ops rootdse_ops = {
	.name		= "rootdse",
	.request	= rootdse_request
};

struct ldb_module *rootdse_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct private_data);
	if (data == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	data->num_controls = 0;
	data->controls = NULL;
	ctx->private_data = data;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &rootdse_ops;

	return ctx;
}


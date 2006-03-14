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
static int rootdse_add_dynamic(struct ldb_module *module, struct ldb_message *msg, const char * const *attrs)
{
	struct private_data *priv = talloc_get_type(module->private_data, struct private_data);
	struct cli_credentials *server_creds;

	msg->dn = ldb_dn_explode(msg, "");

	if (do_attribute(attrs, "currentTime")) {
		if (ldb_msg_add_steal_string(msg, "currentTime", 
					     ldb_timestring(msg, time(NULL))) != 0) {
			goto failed;
		}
	}

	if (do_attribute(attrs, "supportedControl")) {
 		int i;
		for (i = 0; i < priv->num_controls; i++) {
			char *control = talloc_strdup(msg, priv->controls[i]);
			if (!control) {
				goto failed;
			}
			if (ldb_msg_add_steal_string(msg, "supportedControl",
						     control) != 0) {
				goto failed;
 			}
 		}
 	}

	server_creds = talloc_get_type(ldb_get_opaque(module->ldb, "server_credentials"), 
				       struct cli_credentials);
	if (server_creds && do_attribute(attrs, "supportedSASLMechanisms")) {
		struct gensec_security_ops **backends = gensec_security_all();
		enum credentials_use_kerberos use_kerberos
			= cli_credentials_get_kerberos_state(server_creds);
		struct gensec_security_ops **ops
			= gensec_use_kerberos_mechs(msg, backends, use_kerberos);
		int i;
		for (i = 0; ops && ops[i]; i++) {
			if (ops[i]->sasl_name) {
				char *sasl_name = talloc_strdup(msg, ops[i]->sasl_name);
				if (!sasl_name) {
					goto failed;
				}
				if (ldb_msg_add_steal_string(msg, "supportedSASLMechanisms",
							     sasl_name) != 0) {
					goto failed;
				}
			}
		}
	}

	if (do_attribute(attrs, "highestCommittedUSN")) {
		if (module->ldb->sequence_number != NULL && 
		    ldb_msg_add_fmt(msg, "highestCommittedUSN", 
				    "%llu", module->ldb->sequence_number(module->ldb)) != 0) {
			goto failed;
		}
	}
	
	/* TODO: lots more dynamic attributes should be added here */

	return LDB_SUCCESS;

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

	if ((ret == LDB_SUCCESS) && (s->res->msgs != NULL)) {
		ret = rootdse_add_dynamic(module, s->res->msgs[0], s->attrs);
	}

	talloc_free(tmp_ctx);

	return ret;
}

struct rootdse_async_context {
	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_async_result *);
	int timeout;

	const char * const * attrs;
};

static int rootdse_async_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct rootdse_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}

	ac = talloc_get_type(context, struct rootdse_async_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		/* for each record returned post-process to add any dynamic
		   attributes that have been asked for */
		if (rootdse_add_dynamic(ac->module, ares->message, ac->attrs) != LDB_SUCCESS) {
			goto error;
		}
	}

	return ac->up_callback(ldb, ac->up_context, ares);

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int rootdse_search_async(struct ldb_module *module, struct ldb_request *req)
{
	struct rootdse_async_context *ac;
	struct ldb_request *down_req;
	int ret;

	/* see if its for the rootDSE */
	if (req->op.search.scope != LDB_SCOPE_BASE ||
	    (req->op.search.base && req->op.search.base->comp_num != 0)) {
		return ldb_next_request(module, req);
	}

	ac = talloc(req, struct rootdse_async_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->up_context = req->async.context;
	ac->up_callback = req->async.callback;
	ac->timeout = req->async.timeout;
	ac->attrs = req->op.search.attrs;

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	/* in our db we store the rootDSE with a DN of cn=rootDSE */
	down_req->op.search.base = ldb_dn_explode(down_req, "cn=rootDSE");
	down_req->op.search.scope = LDB_SCOPE_BASE;
	down_req->op.search.tree = ldb_parse_tree(down_req, "dn=*");
	if (down_req->op.search.base == NULL || down_req->op.search.tree == NULL) {
		ldb_oom(module->ldb);
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	down_req->op.search.attrs = req->op.search.attrs;
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = ac;
	down_req->async.callback = rootdse_async_callback;
	down_req->async.timeout = req->async.timeout;

	/* perform the search */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

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

	case LDB_ASYNC_SEARCH:
		return rootdse_search_async(module, req);
		
	case LDB_REQ_REGISTER:
		return rootdse_register_control(module, req);

	default:
		break;
	}
	return ldb_next_request(module, req);
}

static int rootdse_init(struct ldb_module *module)
{
	struct private_data *data;

	data = talloc(module, struct private_data);
	if (data == NULL) {
		return -1;
	}

	data->num_controls = 0;
	data->controls = NULL;
	module->private_data = data;

	return ldb_next_init(module);
}

static const struct ldb_module_ops rootdse_ops = {
	.name			= "rootdse",
	.init_context           = rootdse_init,
	.request		= rootdse_request
};

int rootdse_module_init(void)
{
	return ldb_register_module(&rootdse_ops);
}


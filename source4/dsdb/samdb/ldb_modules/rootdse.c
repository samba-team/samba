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
#include "system/time.h"

struct private_data {
	int num_controls;
	char **controls;
	int num_partitions;
	struct ldb_dn **partitions;
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
	char **server_sasl;

	msg->dn = ldb_dn_new(msg, module->ldb, NULL);

	/* don't return the distinduishedName, cn and name attributes */
	ldb_msg_remove_attr(msg, "distinguishedName");
	ldb_msg_remove_attr(msg, "cn");
	ldb_msg_remove_attr(msg, "name");

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

	if (do_attribute(attrs, "namingContexts")) {
		int i;
		for (i = 0; i < priv->num_partitions; i++) {
			struct ldb_dn *dn = priv->partitions[i];
			if (ldb_msg_add_steal_string(msg, "namingContexts",
						     ldb_dn_alloc_linearized(msg, dn)) != 0) {
				goto failed;
 			}
 		}
	}

	server_sasl = talloc_get_type(ldb_get_opaque(module->ldb, "supportedSASLMechanims"), 
				       char *);
	if (server_sasl && do_attribute(attrs, "supportedSASLMechanisms")) {
		int i;
		for (i = 0; server_sasl && server_sasl[i]; i++) {
			char *sasl_name = talloc_strdup(msg, server_sasl[i]);
			if (!sasl_name) {
				goto failed;
			}
			if (ldb_msg_add_steal_string(msg, "supportedSASLMechanisms",
						     sasl_name) != 0) {
				goto failed;
			}
		}
	}

	if (do_attribute(attrs, "highestCommittedUSN")) {
		uint64_t seq_num;
		int ret = ldb_sequence_number(module->ldb, LDB_SEQ_HIGHEST_SEQ, &seq_num);
		if (ret == LDB_SUCCESS) {
			if (ldb_msg_add_fmt(msg, "highestCommittedUSN", 
					    "%llu", (unsigned long long)seq_num) != 0) {
				goto failed;
			}
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

struct rootdse_context {
	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_reply *);

	const char * const * attrs;
};

static int rootdse_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct rootdse_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct rootdse_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		/*
		 * if the client explicit asks for the 'netlogon' attribute
		 * the reply_entry needs to be skipped
		 */
		if (ac->attrs && ldb_attr_in_list(ac->attrs, "netlogon")) {
			talloc_free(ares);
			return LDB_SUCCESS;
		}

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

static int rootdse_search(struct ldb_module *module, struct ldb_request *req)
{
	struct rootdse_context *ac;
	struct ldb_request *down_req;
	int ret;

	/* see if its for the rootDSE */
	if (req->op.search.scope != LDB_SCOPE_BASE ||
	    ( ! ldb_dn_is_null(req->op.search.base))) {
		return ldb_next_request(module, req);
	}

	ac = talloc(req, struct rootdse_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->up_context = req->context;
	ac->up_callback = req->callback;
	ac->attrs = req->op.search.attrs;

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	/* in our db we store the rootDSE with a DN of cn=rootDSE */
	down_req->op.search.base = ldb_dn_new(down_req, module->ldb, "cn=rootDSE");
	down_req->op.search.scope = LDB_SCOPE_BASE;
	down_req->op.search.tree = ldb_parse_tree(down_req, NULL);
	if (down_req->op.search.base == NULL || down_req->op.search.tree == NULL) {
		ldb_oom(module->ldb);
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	down_req->op.search.attrs = req->op.search.attrs;
	down_req->controls = req->controls;

	down_req->context = ac;
	down_req->callback = rootdse_callback;
	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

	/* perform the search */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
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

	list[priv->num_controls] = talloc_strdup(list, req->op.reg_control.oid);
	if (!list[priv->num_controls]) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	priv->num_controls += 1;
	priv->controls = list;

	return LDB_SUCCESS;
}
 
static int rootdse_register_partition(struct ldb_module *module, struct ldb_request *req)
{
	struct private_data *priv = talloc_get_type(module->private_data, struct private_data);
	struct ldb_dn **list;

	list = talloc_realloc(priv, priv->partitions, struct ldb_dn *, priv->num_partitions + 1);
	if (!list) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	list[priv->num_partitions] = ldb_dn_copy(list, req->op.reg_partition.dn);
	if (!list[priv->num_partitions]) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	priv->num_partitions += 1;
	priv->partitions = list;

	return LDB_SUCCESS;
}
 

static int rootdse_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_REGISTER_CONTROL:
		return rootdse_register_control(module, req);
	case LDB_REQ_REGISTER_PARTITION:
		return rootdse_register_partition(module, req);

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
	data->num_partitions = 0;
	data->partitions = NULL;
	module->private_data = data;

	return ldb_next_init(module);
}

static const struct ldb_module_ops rootdse_ops = {
	.name			= "rootdse",
	.init_context           = rootdse_init,
	.search                 = rootdse_search,
	.request		= rootdse_request
};

int rootdse_module_init(void)
{
	return ldb_register_module(&rootdse_ops);
}


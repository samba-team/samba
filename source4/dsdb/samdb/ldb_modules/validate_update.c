/*
   ldb database library

   Copyright (C) Stefan Metzmacher <metze@samba.org> 2009

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

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"

static int validate_update_message(struct ldb_context *ldb,
				   struct dsdb_schema *schema,
				   const struct ldb_message *msg)
{
	int i;

	for (i=0; i < msg->num_elements; i++) {
		WERROR werr;

		werr = dsdb_attribute_validate_ldb(ldb, schema,
						   &msg->elements[i]);
		if (!W_ERROR_IS_OK(werr)) {
			int j;

			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "TODO: object[%s] add/modify attribute[%d|%s] num_values[%d] - %s\n",
				  ldb_dn_get_linearized(msg->dn),
				  i, msg->elements[i].name,
				  msg->elements[i].num_values,
				  win_errstr(werr));

			for (j=0; j < msg->elements[i].num_values; j++) {
				ldb_debug(ldb, LDB_DEBUG_ERROR,
					  "TODO: value[%lu] len[%lu]\n", (long unsigned int)j,
					  (long unsigned int)msg->elements[i].values[j].length);
				dump_data(0,
					  msg->elements[i].values[j].data,
					  msg->elements[i].values[j].length);
			}

			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
	}

	return LDB_SUCCESS;
}

static int validate_update_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	int ret;

	ldb = ldb_module_get_ctx(module);
	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		return ldb_next_request(module, req);
	}

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ret = validate_update_message(ldb, schema,
				      req->op.add.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, req);
}

static int validate_update_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	int ret;

	ldb = ldb_module_get_ctx(module);
	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		return ldb_next_request(module, req);
	}

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	ret = validate_update_message(ldb, schema,
				      req->op.mod.message);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_validate_update_module_ops = {
	.name		= "validate_update",
	.add		= validate_update_add,
	.modify		= validate_update_modify,
};


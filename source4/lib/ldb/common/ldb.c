/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb core API
 *
 *  Description: core API routines interfacing to ldb backends
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/includes.h"

/* 
   initialise a ldb context
   The mem_ctx is optional
*/
struct ldb_context *ldb_init(void *mem_ctx)
{
	struct ldb_context *ldb = talloc_zero(mem_ctx, struct ldb_context);
	int ret;

	ret = ldb_setup_wellknown_attributes(ldb);
	if (ret != 0) {
		talloc_free(ldb);
		return NULL;
	}

	ldb_set_utf8_default(ldb);

	return ldb;
}

static struct ldb_backend {
	const char *name;
	ldb_connect_fn connect_fn;
	struct ldb_backend *prev, *next;
} *ldb_backends = NULL;
/*
 register a new ldb backend
*/
int ldb_register_backend(const char *url_prefix, ldb_connect_fn connectfn)
{
	struct ldb_backend *backend = talloc(talloc_autofree_context(), struct ldb_backend);

	/* Maybe check for duplicity here later on? */

	backend->name = talloc_strdup(backend, url_prefix);
	backend->connect_fn = connectfn;
	DLIST_ADD(ldb_backends, backend);

	return LDB_SUCCESS;
}

static ldb_connect_fn ldb_find_backend(const char *url)
{
	struct ldb_backend *backend;

	for (backend = ldb_backends; backend; backend = backend->next) {
		if (strncmp(backend->name, url, strlen(backend->name)) == 0) {
			return backend->connect_fn;
		}
	}

	return NULL;
}

/* 
 connect to a database. The URL can either be one of the following forms
   ldb://path
   ldapi://path

   flags is made up of LDB_FLG_*

   the options are passed uninterpreted to the backend, and are
   backend specific
*/
int ldb_connect(struct ldb_context *ldb, const char *url, unsigned int flags, const char *options[])
{
	int ret;
	char *backend;
	ldb_connect_fn fn;

	if (strchr(url, ':') != NULL) {
		backend = talloc_strndup(ldb, url, strchr(url, ':')-url-1);
	} else {
		/* Default to tdb */
		backend = talloc_strdup(ldb, "tdb");
	}

	fn = ldb_find_backend(backend);

	if (fn == NULL) {
		if (ldb_try_load_dso(ldb, backend) == 0) {
			fn = ldb_find_backend(backend);
		}
	}

	talloc_free(backend);

	if (fn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Unable to find backend for '%s'\n", url);
		return LDB_ERR_OTHER;
	}

	ret = fn(ldb, url, flags, options);

	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to connect to '%s'\n", url);
		return ret;
	}

	if (ldb_load_modules(ldb, options) != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Unable to load modules for '%s'\n", url);
		return LDB_ERR_OTHER;
	}

	return LDB_SUCCESS;
}

void ldb_set_errstring(struct ldb_context *ldb, char *err_string)
{
	if (ldb->err_string) {
		talloc_free(ldb->err_string);
	}
	ldb->err_string = talloc_steal(ldb, err_string);
}

void ldb_reset_err_string(struct ldb_context *ldb)
{
	if (ldb->err_string) {
		talloc_free(ldb->err_string);
		ldb->err_string = NULL;
	}
}

#define FIRST_OP(ldb, op) do { \
	module = ldb->modules; \
	while (module && module->ops->op == NULL) module = module->next; \
	if (module == NULL) return LDB_ERR_OPERATIONS_ERROR; \
} while (0)

/*
  start a transaction
*/
int ldb_transaction_start(struct ldb_context *ldb)
{
	struct ldb_module *module;
	int status;
	FIRST_OP(ldb, start_transaction);
	
	ldb->transaction_active++;

	ldb_reset_err_string(ldb);

	status = module->ops->start_transaction(module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_set_errstring(ldb, 
					  talloc_asprintf(ldb, "ldb transaction start error %d", status));
		}
	}
	return status;
}

/*
  commit a transaction
*/
int ldb_transaction_commit(struct ldb_context *ldb)
{
	struct ldb_module *module;
	int status;
	FIRST_OP(ldb, end_transaction);

	if (ldb->transaction_active > 0) {
		ldb->transaction_active--;
	} else {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_reset_err_string(ldb);

	status = module->ops->end_transaction(module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_set_errstring(ldb, 
					  talloc_asprintf(ldb, "ldb transaction commit error %d", status));
		}
	}
	return status;
}

/*
  cancel a transaction
*/
int ldb_transaction_cancel(struct ldb_context *ldb)
{
	struct ldb_module *module;
	int status;
	FIRST_OP(ldb, del_transaction);

	if (ldb->transaction_active > 0) {
		ldb->transaction_active--;
	} else {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	status = module->ops->del_transaction(module);
	if (status != LDB_SUCCESS) {
		if (ldb->err_string == NULL) {
			/* no error string was setup by the backend */
			ldb_set_errstring(ldb, 
					  talloc_asprintf(ldb, "ldb transaction cancel error %d", status));
		}
	}
	return status;
}

int ldb_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	return handle->module->ops->async_wait(handle, type);
}

/*
  check for an error return from an op 
  if an op fails, but has not setup an error string, then setup one now
*/
static int ldb_op_finish(struct ldb_context *ldb, int status)
{
	if (status == LDB_SUCCESS) {
		return ldb_transaction_commit(ldb);
	}
	if (ldb->err_string == NULL) {
		/* no error string was setup by the backend */
		ldb_set_errstring(ldb, 
				  talloc_asprintf(ldb, "ldb error %d", status));
	}
	ldb_transaction_cancel(ldb);
	return status;
}

/*
  start an ldb request
  autostarts a transacion if none active and the operation is not a search
  NOTE: the request must be a talloc context.
  returns LDB_ERR_* on errors.
*/
int ldb_request(struct ldb_context *ldb, struct ldb_request *req)
{
	int status, started_transaction=0;

	ldb_reset_err_string(ldb);

	if (req->operation == LDB_REQ_SEARCH) {
		req->op.search.res = NULL;
	}

	/* start a transaction if needed */
	if ((!ldb->transaction_active) &&
	    (req->operation == LDB_REQ_ADD ||
	     req->operation == LDB_REQ_MODIFY ||
	     req->operation == LDB_REQ_DELETE ||
	     req->operation == LDB_REQ_RENAME)) {
		status = ldb_transaction_start(ldb);
		if (status != LDB_SUCCESS) {
			talloc_free(req);
			return status;
		}
		started_transaction = 1;
	}

	/* call the first module in the chain */
	status = ldb->modules->ops->request(ldb->modules, req);

	if (started_transaction) {
		return ldb_op_finish(ldb, status);
	}

	return status;
}

/*
  search the database given a LDAP-like search expression

  return the number of records found, or -1 on error

  Use talloc_free to free the ldb_message returned in 'res'

*/
int ldb_search(struct ldb_context *ldb, 
	       const struct ldb_dn *base,
	       enum ldb_scope scope,
	       const char *expression,
	       const char * const *attrs, 
	       struct ldb_result **res)
{
	struct ldb_request *req;
	int ret;

	(*res) = NULL;

	req = talloc(ldb, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_SEARCH;
	req->op.search.base = base;
	req->op.search.scope = scope;

	req->op.search.tree = ldb_parse_tree(req, expression);
	if (req->op.search.tree == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Unable to parse search expression"));
		talloc_free(req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->op.search.attrs = attrs;
	req->controls = NULL;

	ret = ldb_request(ldb, req);

	(*res) = talloc_steal(ldb, req->op.search.res);

	talloc_free(req);
	return ret;
}

/*
  add a record to the database. Will fail if a record with the given class and key
  already exists
*/
int ldb_add(struct ldb_context *ldb, 
	    const struct ldb_message *message)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_msg_sanity_check(message);
	if (ret != LDB_SUCCESS) return ret;

	req = talloc(ldb, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_ADD;
	req->op.add.message = message;
	req->controls = NULL;

	ret = ldb_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  modify the specified attributes of a record
*/
int ldb_modify(struct ldb_context *ldb, 
	       const struct ldb_message *message)
{
	struct ldb_request *req;
	int ret;

	ret = ldb_msg_sanity_check(message);
	if (ret != LDB_SUCCESS) return ret;

	req = talloc(ldb, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_MODIFY;
	req->op.add.message = message;
	req->controls = NULL;

	ret = ldb_request(ldb, req);

	talloc_free(req);
	return ret;
}


/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, const struct ldb_dn *dn)
{
	struct ldb_request *req;
	int ret;

	req = talloc(ldb, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_DELETE;
	req->op.del.dn = dn;
	req->controls = NULL;

	ret = ldb_request(ldb, req);

	talloc_free(req);
	return ret;
}

/*
  rename a record in the database
*/
int ldb_rename(struct ldb_context *ldb, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct ldb_request *req;
	int ret;

	req = talloc(ldb, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(ldb, talloc_strdup(ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_RENAME;
	req->op.rename.olddn = olddn;
	req->op.rename.newdn = newdn;
	req->controls = NULL;

	ret = ldb_request(ldb, req);

	talloc_free(req);
	return ret;
}



/*
  return extended error information 
*/
const char *ldb_errstring(struct ldb_context *ldb)
{
	if (ldb->err_string) {
		return ldb->err_string;
	}

	return NULL;
}


/*
  set backend specific opaque parameters
*/
int ldb_set_opaque(struct ldb_context *ldb, const char *name, void *value)
{
	struct ldb_opaque *o;

	/* allow updating an existing value */
	for (o=ldb->opaque;o;o=o->next) {
		if (strcmp(o->name, name) == 0) {
			o->value = value;
			return LDB_SUCCESS;
		}
	}

	o = talloc(ldb, struct ldb_opaque);
	if (o == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OTHER;
	}
	o->next = ldb->opaque;
	o->name = name;
	o->value = value;
	ldb->opaque = o;
	return LDB_SUCCESS;
}

/*
  get a previously set opaque value
*/
void *ldb_get_opaque(struct ldb_context *ldb, const char *name)
{
	struct ldb_opaque *o;
	for (o=ldb->opaque;o;o=o->next) {
		if (strcmp(o->name, name) == 0) {
			return o->value;
		}
	}
	return NULL;
}

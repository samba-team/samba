/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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

#include "ldb.h"
#include "ldb_module.h"

/*
  search for attrs on one DN, in the modules below
 */
int dsdb_module_search_dn(struct ldb_module *module,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_result **_res,
			  struct ldb_dn *basedn,
			  const char * const *attrs)
{
	int ret;
	struct ldb_request *req;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;

	tmp_ctx = talloc_new(mem_ctx);

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb_module_get_ctx(module), tmp_ctx,
				   basedn,
				   LDB_SCOPE_BASE,
				   NULL,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	if (res->count != 1) {
		/* we may be reading a DB that does not have the 'check base on search' option... */
		ret = LDB_ERR_NO_SUCH_OBJECT;
	} else {
		*_res = talloc_steal(mem_ctx, res);
	}
	talloc_free(tmp_ctx);
	return ret;
}

/*
  search for attrs in the modules below
 */
int dsdb_module_search(struct ldb_module *module,
		       TALLOC_CTX *mem_ctx,
		       struct ldb_result **_res,
		       struct ldb_dn *basedn, enum ldb_scope scope, 
		       const char * const *attrs,
		       const char *expression)
{
	int ret;
	struct ldb_request *req;
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;

	tmp_ctx = talloc_new(mem_ctx);

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (!res) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&req, ldb_module_get_ctx(module), tmp_ctx,
				   basedn,
				   scope,
				   expression,
				   attrs,
				   NULL,
				   res,
				   ldb_search_default_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = ldb_next_request(module, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	talloc_free(req);
	if (ret == LDB_SUCCESS) {
		*_res = talloc_steal(mem_ctx, res);
	}
	talloc_free(tmp_ctx);
	return ret;
}


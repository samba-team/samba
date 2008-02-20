/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2007

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
 *  Component: ldb ranged results module
 *
 *  Description: munge AD-style 'ranged results' requests into
 *  requests for all values in an attribute, then return the range to
 *  the client.
 *
 *  Author: Andrew Bartlett
 */

#include "ldb_includes.h"

struct rr_context {
	struct ldb_request *orig_req;
	struct ldb_request *down_req;
};

static int rr_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	struct rr_context *rr_context = talloc_get_type(context, struct rr_context);
	struct ldb_request *orig_req = rr_context->orig_req;
	int i, j;
	
	if (ares->type != LDB_REPLY_ENTRY) {
		return rr_context->orig_req->callback(ldb, rr_context->orig_req->context, ares);
	}

	/* Find those that are range requests from the attribute list */
	for (i = 0; orig_req->op.search.attrs[i]; i++) {
		char *p, *new_attr;
		const char *end_str;
		unsigned int start, end, orig_num_values;
		struct ldb_message_element *el;
		struct ldb_val *orig_values;
		p = strchr(orig_req->op.search.attrs[i], ';');
		if (!p) {
			continue;
		}
		if (strncasecmp(p, ";range=", strlen(";range=")) != 0) {
			continue;
		}
		if (sscanf(p, ";range=%u-%u", &start, &end) == 2) {
		} else if (sscanf(p, ";range=%u-*", &start) == 1) {
			end = (unsigned int)-1;
		} else {
			continue;
		}
		new_attr = talloc_strndup(orig_req, 
					  orig_req->op.search.attrs[i],
					  (unsigned int)(p-orig_req->op.search.attrs[i]));

		if (!new_attr) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		el = ldb_msg_find_element(ares->message, new_attr);
		talloc_free(new_attr);
		if (!el) {
			continue;
		}
		if (start > end) {
			ldb_asprintf_errstring(ldb, "range request error: start must not be greater than end");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (end >= (el->num_values - 1)) {
			/* Need to leave the requested attribute in
			 * there (so add an empty one to match) */
			end_str = "*";
			end = el->num_values - 1;
		} else {
			end_str = talloc_asprintf(el, "%u", end);
			if (!end_str) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		/* If start is greater then where we noe find the end to be */
		if (start > end) {
			el->num_values = 0;
			el->values = NULL;
		} else {
			orig_values = el->values;
			orig_num_values = el->num_values;
			
			if ((start + end < start) || (start + end < end)) {
				ldb_asprintf_errstring(ldb, "range request error: start or end would overflow!");
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
			
			el->num_values = 0;
			
			el->values = talloc_array(el, struct ldb_val, (end - start) + 1);
			if (!el->values) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			for (j=start; j <= end; j++) {
				el->values[el->num_values] = orig_values[j];
				el->num_values++;
			}
		}
		el->name = talloc_asprintf(el, "%s;range=%u-%s", el->name, start, end_str);
		if (!el->name) {
			ldb_oom(ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	return rr_context->orig_req->callback(ldb, rr_context->orig_req->context, ares);

}

/* search */
static int rr_search(struct ldb_module *module, struct ldb_request *req)
{
	int i;
	unsigned int start, end;
	const char **new_attrs = NULL;
	struct rr_context *context;
	bool found_rr = false;

	/* Strip the range request from the attribute */
	for (i = 0; req->op.search.attrs && req->op.search.attrs[i]; i++) {
		char *p;
		new_attrs = talloc_realloc(req, new_attrs, const char *, i+2);
		new_attrs[i] = req->op.search.attrs[i];
		new_attrs[i+1] = NULL;
		p = strchr(req->op.search.attrs[i], ';');
		if (!p) {
			continue;
		}
		if (strncasecmp(p, ";range=", strlen(";range=")) != 0) {
			continue;
		}
		if (sscanf(p, ";range=%u-%u", &start, &end) == 2) {
		} else if (sscanf(p, ";range=%u-*", &start) == 1) {
			end = (unsigned int)-1;
		} else {
			ldb_asprintf_errstring(module->ldb, "range request error: range requst malformed");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		if (start > end) {
			ldb_asprintf_errstring(module->ldb, "range request error: start must not be greater than end");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		found_rr = true;
		new_attrs[i] = talloc_strndup(new_attrs, 
					      req->op.search.attrs[i],
					      (unsigned int)(p-req->op.search.attrs[i]));

		if (!new_attrs[i]) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (found_rr) {
		int ret;
		context = talloc(req, struct rr_context);
		context->orig_req = req;
		context->down_req = talloc(context, struct ldb_request);
		*context->down_req = *req;
		
		context->down_req->op.search.attrs = new_attrs;
		
		context->down_req->callback = rr_search_callback;
		context->down_req->context = context;

		ret = ldb_next_request(module, context->down_req);
		
		/* We don't need to implement our own 'wait' function, so pass the handle along */
		if (ret == LDB_SUCCESS) {
			req->handle = context->down_req->handle;
		}
		return ret;
	}

	/* No change, just run the original request as if we were never here */
	return ldb_next_request(module, req);
}

const struct ldb_module_ops ldb_ranged_results_module_ops = {
	.name		   = "ranged_results",
	.search            = rr_search,
};

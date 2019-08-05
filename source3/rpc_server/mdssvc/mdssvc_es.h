/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines / HTTP/ES/JSON backend

   Copyright (C) Ralph Boehme			2019

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

#ifndef _MDSSVC_ES_H_
#define _MDSSVC_ES_H_

#include <jansson.h>

/*
 * Some global state
 */
struct mdssvc_es_ctx {
	struct mdssvc_ctx *mdssvc_ctx;
	struct cli_credentials *creds;
	json_t *mappings;
};

/*
 * Per mdssvc RPC bind state
 */
struct mds_es_ctx {
	/*
	 * Pointer to higher level mds_ctx
	 */
	struct mds_ctx *mds_ctx;

	/*
	 * Pointer to our global context
	 */
	struct mdssvc_es_ctx *mdssvc_es_ctx;

	/*
	 * The HTTP connection handle to the ES server
	 */
	struct http_conn *http_conn;

	/*
	 * List of pending searches
	 */
	struct sl_es_search *searches;
};

/* Per search request */
struct sl_es_search {
	/*
	 * List pointers
	 */
	struct sl_es_search *prev, *next;

	/*
	 * Search is being executed. Only the list head can be pending.
	 */
	bool pending;

	/*
	 * Shorthand to our tevent context
	 */
	struct tevent_context *ev;

	/*
	 * Pointer to the RPC connection ctx the request is using
	 */
	struct mds_es_ctx *mds_es_ctx;

	/*
	 * The upper mdssvc.c level query context
	 */
	struct sl_query *slq;

	/*
	 * Maximum number of results we process and total number of
	 * results of a query.
	 */
	size_t total;
	size_t max;

	/*
	 * For paging results
	 */
	size_t from;
	size_t size;

	/*
	 * The translated Es query
	 */
	char *es_query;
};

extern struct mdssvc_backend mdsscv_backend_es;

#endif /* _MDSSVC_ES_H_ */

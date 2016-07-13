/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme			2012-2014

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

#ifndef _MDSSVC_H
#define _MDSSVC_H

#include "dalloc.h"
#include "marshalling.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/mdssvc.h"

/*
 * glib uses TRUE and FALSE which was redefined by "includes.h" to be
 * unusable, undefine so glib can establish its own working
 * replacement.
 */
#undef TRUE
#undef FALSE
/* allow building with --picky-developer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <gio/gio.h>
#include <tracker-sparql.h>
#pragma GCC diagnostic pop

#define MAX_SL_FRAGMENT_SIZE 0xFFFFF
#define MAX_SL_RESULTS 100
#define MAX_SL_RUNTIME 30
#define MDS_TRACKER_ASYNC_TIMEOUT_MS 250

/******************************************************************************
 * Some helper stuff dealing with queries
 ******************************************************************************/

/* query state */
typedef enum {
	SLQ_STATE_NEW,       /* Query received from client         */
	SLQ_STATE_RUNNING,   /* Query dispatched to Tracker        */
	SLQ_STATE_RESULTS,   /* Async Tracker query read           */
	SLQ_STATE_FULL,	     /* the max amount of result has beed queued */
	SLQ_STATE_DONE,      /* Got all results from Tracker       */
	SLQ_STATE_END,       /* Query results returned to client   */
	SLQ_STATE_ERROR	     /* an error happended somewhere       */
} slq_state_t;

/* query structure */
struct sl_query {
	struct sl_query *prev, *next;	 /* list pointers */
	struct mds_ctx  *mds_ctx;        /* context handle */
	slq_state_t      state;          /* query state */
	struct timeval   start_time;	 /* Query start time */
	struct timeval   last_used;	 /* Time of last result fetch */
	struct timeval   expire_time;	 /* Query expiration time */
	struct tevent_timer *te;	 /* query timeout */
	int              snum;           /* share snum  */
	uint64_t         ctx1;           /* client context 1 */
	uint64_t         ctx2;           /* client context 2 */
	sl_array_t      *reqinfo;        /* array with requested metadata */
	const char      *query_string;   /* the Spotlight query string */
	const char      *sparql_query;   /* the SPARQL query string */
	uint64_t        *cnids;          /* restrict query to these CNIDs */
	size_t           cnids_num;      /* Size of slq_cnids array */
	const char      *path_scope;	 /* path to directory to search */
	GCancellable    *gcancellable;
	TrackerSparqlCursor *tracker_cursor; /* Tracker SPARQL query result cursor */
	struct sl_rslts *query_results;  /* query results */
	TALLOC_CTX      *entries_ctx;    /* talloc parent of the search results */
};

struct sl_rslts {
	int                num_results;
	sl_cnids_t        *cnids;
	sl_array_t        *fm_array;
};

struct sl_inode_path_map {
	struct mds_ctx    *mds_ctx;
	uint64_t           ino;
	char              *path;
};

struct mds_ctx {
	struct dom_sid sid;
	uid_t uid;
	const char *spath;
	GCancellable *gcancellable;
	TrackerSparqlConnection *tracker_con;
	GMainContext *gcontext;
	GMainLoop *gmainloop;
	struct sl_query *query_list;     /* list of active queries */
	struct db_context *ino_path_map; /* dbwrap rbt for storing inode->path mappings */
};

/******************************************************************************
 * Function declarations
 ******************************************************************************/

/*
 * mdssvc.c
 */
extern bool mds_init(struct messaging_context *msg_ctx);
extern bool mds_shutdown(void);
extern struct mds_ctx *mds_init_ctx(TALLOC_CTX *mem_ctx,
				    const struct auth_session_info *session_info,
				    const char *path);
extern int mds_ctx_destructor_cb(struct mds_ctx *mds_ctx);
extern bool mds_dispatch(struct mds_ctx *query_ctx,
			 struct mdssvc_blob *request_blob,
			 struct mdssvc_blob *response_blob);
extern char *mds_dalloc_dump(DALLOC_CTX *dd, int nestinglevel);

#endif /* _MDSSVC_H */

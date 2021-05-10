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

#define MAX_SL_FRAGMENT_SIZE 0xFFFFF
#define MAX_SL_RESULTS 100
#define MAX_SL_RUNTIME 30
#define MDS_TRACKER_ASYNC_TIMEOUT_MS 250

#define SLQ_DEBUG(lvl, _slq, state) do { if (CHECK_DEBUGLVL(lvl)) {	\
	const struct sl_query *__slq = _slq;				\
	struct timeval_buf start_buf;					\
	const char *start;						\
	struct timeval_buf last_used_buf;				\
	const char *last_used;						\
	struct timeval_buf expire_buf;					\
	const char *expire;						\
	start = timeval_str_buf(&__slq->start_time, false,		\
				true, &start_buf);			\
	last_used = timeval_str_buf(&__slq->last_used, false,		\
				    true, &last_used_buf);		\
	expire = timeval_str_buf(&__slq->expire_time, false,		\
				 true, &expire_buf);			\
	DEBUG(lvl,("%s slq[0x%jx,0x%jx], start: %s, last_used: %s, "	\
		   "expires: %s, query: '%s'\n", state,			\
		   (uintmax_t)__slq->ctx1, (uintmax_t)__slq->ctx2,	\
		   start, last_used, expire, __slq->query_string));	\
}} while(0)

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
	void            *backend_private; /* search backend private data */
	slq_state_t      state;          /* query state */
	struct timeval   start_time;	 /* Query start time */
	struct timeval   last_used;	 /* Time of last result fetch */
	struct timeval   expire_time;	 /* Query expiration time */
	struct tevent_timer *te;	 /* query timeout */
	uint64_t         ctx1;           /* client context 1 */
	uint64_t         ctx2;           /* client context 2 */
	sl_array_t      *reqinfo;        /* array with requested metadata */
	char            *query_string;   /* the Spotlight query string */
	uint64_t        *cnids;          /* restrict query to these CNIDs */
	size_t           cnids_num;      /* Size of slq_cnids array */
	const char      *path_scope;	 /* path to directory to search */
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

/* Per process state */
struct mdssvc_ctx {
	struct tevent_context *ev_ctx;
	void *backend_private;
};

/* Per tree connect state */
struct mds_ctx {
	struct mdssvc_backend *backend;
	struct mdssvc_ctx *mdssvc_ctx;
	void *backend_private;
	struct auth_session_info *pipe_session_info;
	struct dom_sid sid;
	uid_t uid;
	smb_iconv_t ic_nfc_to_nfd;
	smb_iconv_t ic_nfd_to_nfc;
	int snum;
	const char *sharename;
	const char *spath;
	struct connection_struct *conn;
	struct sl_query *query_list;     /* list of active queries */
	struct db_context *ino_path_map; /* dbwrap rbt for storing inode->path mappings */
};

struct mdssvc_backend {
	bool (*init)(struct mdssvc_ctx *mdssvc_ctx);
	bool (*connect)(struct mds_ctx *mds_ctx);
	bool (*search_map)(struct sl_query *slq);
	bool (*search_start)(struct sl_query *slq);
	bool (*search_cont)(struct sl_query *slq);
	bool (*shutdown)(struct mdssvc_ctx *mdssvc_ctx);
};

/******************************************************************************
 * Function declarations
 ******************************************************************************/

/*
 * mdssvc.c
 */
extern bool mds_init(struct messaging_context *msg_ctx);
extern bool mds_shutdown(void);
struct mds_ctx *mds_init_ctx(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     struct messaging_context *msg_ctx,
			     struct auth_session_info *session_info,
			     int snum,
			     const char *sharename,
			     const char *path);
extern bool mds_dispatch(struct mds_ctx *query_ctx,
			 struct mdssvc_blob *request_blob,
			 struct mdssvc_blob *response_blob);
bool mds_add_result(struct sl_query *slq, const char *path);

#endif /* _MDSSVC_H */

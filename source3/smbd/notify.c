/*
   Unix SMB/CIFS implementation.
   change notify handling
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Jeremy Allison 1994-1998
   Copyright (C) Volker Lendecke 2007

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
#include "smbd/globals.h"

struct notify_change_request {
	struct notify_change_request *prev, *next;
	struct files_struct *fsp;	/* backpointer for cancel by mid */
	struct smb_request *req;
	uint32 filter;
	uint32 max_param;
	struct notify_mid_map *mid_map;
	void *backend_data;
};

static void notify_fsp(files_struct *fsp, uint32 action, const char *name);

/*
 * For NTCancel, we need to find the notify_change_request indexed by
 * mid. Separate list here.
 */

struct notify_mid_map {
	struct notify_mid_map *prev, *next;
	struct notify_change_request *req;
	uint16 mid;
};

static bool notify_change_record_identical(struct notify_change *c1,
					struct notify_change *c2)
{
	/* Note this is deliberately case sensitive. */
	if (c1->action == c2->action &&
			strcmp(c1->name, c2->name) == 0) {
		return True;
	}
	return False;
}

static bool notify_marshall_changes(int num_changes,
				uint32 max_offset,
				struct notify_change *changes,
				prs_struct *ps)
{
	int i;
	UNISTR uni_name;

	uni_name.buffer = NULL;

	for (i=0; i<num_changes; i++) {
		struct notify_change *c;
		size_t namelen;
		uint32 u32_tmp;	/* Temp arg to prs_uint32 to avoid
				 * signed/unsigned issues */

		/* Coalesce any identical records. */
		while (i+1 < num_changes &&
			notify_change_record_identical(&changes[i],
						&changes[i+1])) {
			i++;
		}

		c = &changes[i];

		if (!convert_string_allocate(NULL, CH_UNIX, CH_UTF16LE,
			c->name, strlen(c->name)+1, &uni_name.buffer,
			&namelen, True) || (uni_name.buffer == NULL)) {
			goto fail;
		}

		namelen -= 2;	/* Dump NULL termination */

		/*
		 * Offset to next entry, only if there is one
		 */

		u32_tmp = (i == num_changes-1) ? 0 : namelen + 12;
		if (!prs_uint32("offset", ps, 1, &u32_tmp)) goto fail;

		u32_tmp = c->action;
		if (!prs_uint32("action", ps, 1, &u32_tmp)) goto fail;

		u32_tmp = namelen;
		if (!prs_uint32("namelen", ps, 1, &u32_tmp)) goto fail;

		if (!prs_unistr("name", ps, 1, &uni_name)) goto fail;

		/*
		 * Not NULL terminated, decrease by the 2 UCS2 \0 chars
		 */
		prs_set_offset(ps, prs_offset(ps)-2);

		SAFE_FREE(uni_name.buffer);

		if (prs_offset(ps) > max_offset) {
			/* Too much data for client. */
			DEBUG(10, ("Client only wanted %d bytes, trying to "
				   "marshall %d bytes\n", (int)max_offset,
				   (int)prs_offset(ps)));
			return False;
		}
	}

	return True;

 fail:
	SAFE_FREE(uni_name.buffer);
	return False;
}

/****************************************************************************
 Setup the common parts of the return packet and send it.
*****************************************************************************/

static void change_notify_reply_packet(connection_struct *conn,
				       struct smb_request *req,
				       NTSTATUS error_code)
{
	reply_outbuf(req, 18, 0);

	if (!NT_STATUS_IS_OK(error_code)) {
		error_packet_set((char *)req->outbuf, 0, 0, error_code,
				 __LINE__,__FILE__);
	}

	show_msg((char *)req->outbuf);
	if (!srv_send_smb(smbd_server_fd(), (char *)req->outbuf,
			  req->encrypted, &req->pcd)) {
		exit_server_cleanly("change_notify_reply_packet: srv_send_smb "
				    "failed.");
	}
	TALLOC_FREE(req->outbuf);
}

void change_notify_reply(connection_struct *conn,
			 struct smb_request *req, uint32 max_param,
			 struct notify_change_buf *notify_buf)
{
	prs_struct ps;

	if (notify_buf->num_changes == -1) {
		change_notify_reply_packet(conn, req, NT_STATUS_OK);
		notify_buf->num_changes = 0;
		return;
	}

	prs_init_empty(&ps, NULL, MARSHALL);

	if (!notify_marshall_changes(notify_buf->num_changes, max_param,
					notify_buf->changes, &ps)) {
		/*
		 * We exceed what the client is willing to accept. Send
		 * nothing.
		 */
		change_notify_reply_packet(conn, req, NT_STATUS_OK);
		goto done;
	}

	send_nt_replies(conn, req, NT_STATUS_OK, prs_data_p(&ps),
			prs_offset(&ps), NULL, 0);

 done:
	prs_mem_free(&ps);

	TALLOC_FREE(notify_buf->changes);
	notify_buf->num_changes = 0;
}

static void notify_callback(void *private_data, const struct notify_event *e)
{
	files_struct *fsp = (files_struct *)private_data;
	DEBUG(10, ("notify_callback called for %s\n", fsp->fsp_name));
	notify_fsp(fsp, e->action, e->path);
}

NTSTATUS change_notify_create(struct files_struct *fsp, uint32 filter,
			      bool recursive)
{
	char *fullpath;
	struct notify_entry e;
	NTSTATUS status;

	SMB_ASSERT(fsp->notify == NULL);

	if (!(fsp->notify = TALLOC_ZERO_P(NULL, struct notify_change_buf))) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (asprintf(&fullpath, "%s/%s", fsp->conn->connectpath,
		     fsp->fsp_name) == -1) {
		DEBUG(0, ("asprintf failed\n"));
		TALLOC_FREE(fsp->notify);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(e);
	e.path = fullpath;
	e.dir_fd = fsp->fh->fd;
	e.dir_id = fsp->file_id;
	e.filter = filter;
	e.subdir_filter = 0;
	if (recursive) {
		e.subdir_filter = filter;
	}

	status = notify_add(fsp->conn->notify_ctx, &e, notify_callback, fsp);
	SAFE_FREE(fullpath);

	return status;
}

NTSTATUS change_notify_add_request(struct smb_request *req,
				uint32 max_param,
				uint32 filter, bool recursive,
				struct files_struct *fsp)
{
	struct notify_change_request *request = NULL;
	struct notify_mid_map *map = NULL;

	DEBUG(10, ("change_notify_add_request: Adding request for %s: "
		   "max_param = %d\n", fsp->fsp_name, (int)max_param));

	if (!(request = talloc(NULL, struct notify_change_request))
	    || !(map = talloc(request, struct notify_mid_map))) {
		TALLOC_FREE(request);
		return NT_STATUS_NO_MEMORY;
	}

	request->mid_map = map;
	map->req = request;

	request->req = talloc_move(request, &req);
	request->max_param = max_param;
	request->filter = filter;
	request->fsp = fsp;
	request->backend_data = NULL;

	DLIST_ADD_END(fsp->notify->requests, request,
		      struct notify_change_request *);

	map->mid = request->req->mid;
	DLIST_ADD(notify_changes_by_mid, map);

	/* Push the MID of this packet on the signing queue. */
	srv_defer_sign_response(request->req->mid);

	return NT_STATUS_OK;
}

static void change_notify_remove_request(struct notify_change_request *remove_req)
{
	files_struct *fsp;
	struct notify_change_request *req;

	/*
	 * Paranoia checks, the fsp referenced must must have the request in
	 * its list of pending requests
	 */

	fsp = remove_req->fsp;
	SMB_ASSERT(fsp->notify != NULL);

	for (req = fsp->notify->requests; req; req = req->next) {
		if (req == remove_req) {
			break;
		}
	}

	if (req == NULL) {
		smb_panic("notify_req not found in fsp's requests");
	}

	DLIST_REMOVE(fsp->notify->requests, req);
	DLIST_REMOVE(notify_changes_by_mid, req->mid_map);
	TALLOC_FREE(req);
}

/****************************************************************************
 Delete entries by mid from the change notify pending queue. Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_mid(uint16 mid)
{
	struct notify_mid_map *map;

	for (map = notify_changes_by_mid; map; map = map->next) {
		if (map->mid == mid) {
			break;
		}
	}

	if (map == NULL) {
		return;
	}

	change_notify_reply_packet(map->req->fsp->conn, map->req->req,
				   NT_STATUS_CANCELLED);
	change_notify_remove_request(map->req);
}

/****************************************************************************
 Delete entries by fnum from the change notify pending queue.
*****************************************************************************/

void remove_pending_change_notify_requests_by_fid(files_struct *fsp,
						  NTSTATUS status)
{
	if (fsp->notify == NULL) {
		return;
	}

	while (fsp->notify->requests != NULL) {
		change_notify_reply_packet(
			fsp->conn, fsp->notify->requests->req, status);
		change_notify_remove_request(fsp->notify->requests);
	}
}

void notify_fname(connection_struct *conn, uint32 action, uint32 filter,
		  const char *path)
{
	char *fullpath;

	if (path[0] == '.' && path[1] == '/') {
		path += 2;
	}
	if (asprintf(&fullpath, "%s/%s", conn->connectpath, path) == -1) {
		DEBUG(0, ("asprintf failed\n"));
		return;
	}

	notify_trigger(conn->notify_ctx, action, filter, fullpath);
	SAFE_FREE(fullpath);
}

static void notify_fsp(files_struct *fsp, uint32 action, const char *name)
{
	struct notify_change *change, *changes;
	char *tmp;

	if (fsp->notify == NULL) {
		/*
		 * Nobody is waiting, don't queue
		 */
		return;
	}

	/*
	 * Someone has triggered a notify previously, queue the change for
	 * later.
	 */

	if ((fsp->notify->num_changes > 1000) || (name == NULL)) {
		/*
		 * The real number depends on the client buf, just provide a
		 * guard against a DoS here.  If name == NULL the CN backend is
		 * alerting us to a problem.  Possibly dropped events.  Clear
		 * queued changes and send the catch-all response to the client
		 * if a request is pending.
		 */
		TALLOC_FREE(fsp->notify->changes);
		fsp->notify->num_changes = -1;
		if (fsp->notify->requests != NULL) {
			change_notify_reply(fsp->conn,
					    fsp->notify->requests->req,
					    fsp->notify->requests->max_param,
					    fsp->notify);
			change_notify_remove_request(fsp->notify->requests);
		}
		return;
	}

	/* If we've exceeded the server side queue or received a NULL name
	 * from the underlying CN implementation, don't queue up any more
	 * requests until we can send a catch-all response to the client */
	if (fsp->notify->num_changes == -1) {
		return;
	}

	if (!(changes = TALLOC_REALLOC_ARRAY(
		      fsp->notify, fsp->notify->changes,
		      struct notify_change, fsp->notify->num_changes+1))) {
		DEBUG(0, ("talloc_realloc failed\n"));
		return;
	}

	fsp->notify->changes = changes;

	change = &(fsp->notify->changes[fsp->notify->num_changes]);

	if (!(tmp = talloc_strdup(changes, name))) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return;
	}

	string_replace(tmp, '/', '\\');
	change->name = tmp;	

	change->action = action;
	fsp->notify->num_changes += 1;

	if (fsp->notify->requests == NULL) {
		/*
		 * Nobody is waiting, so don't send anything. The ot
		 */
		return;
	}

	if (action == NOTIFY_ACTION_OLD_NAME) {
		/*
		 * We have to send the two rename events in one reply. So hold
		 * the first part back.
		 */
		return;
	}

	/*
	 * Someone is waiting for the change, trigger the reply immediately.
	 *
	 * TODO: do we have to walk the lists of requests pending?
	 */

	change_notify_reply(fsp->conn,
			    fsp->notify->requests->req,
			    fsp->notify->requests->max_param,
			    fsp->notify);

	change_notify_remove_request(fsp->notify->requests);
}

char *notify_filter_string(TALLOC_CTX *mem_ctx, uint32 filter)
{
	char *result = NULL;

	result = talloc_strdup(mem_ctx, "");

	if (filter & FILE_NOTIFY_CHANGE_FILE_NAME)
		result = talloc_asprintf_append(result, "FILE_NAME|");
	if (filter & FILE_NOTIFY_CHANGE_DIR_NAME)
		result = talloc_asprintf_append(result, "DIR_NAME|");
	if (filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
		result = talloc_asprintf_append(result, "ATTRIBUTES|");
	if (filter & FILE_NOTIFY_CHANGE_SIZE)
		result = talloc_asprintf_append(result, "SIZE|");
	if (filter & FILE_NOTIFY_CHANGE_LAST_WRITE)
		result = talloc_asprintf_append(result, "LAST_WRITE|");
	if (filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)
		result = talloc_asprintf_append(result, "LAST_ACCESS|");
	if (filter & FILE_NOTIFY_CHANGE_CREATION)
		result = talloc_asprintf_append(result, "CREATION|");
	if (filter & FILE_NOTIFY_CHANGE_EA)
		result = talloc_asprintf_append(result, "EA|");
	if (filter & FILE_NOTIFY_CHANGE_SECURITY)
		result = talloc_asprintf_append(result, "SECURITY|");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_NAME)
		result = talloc_asprintf_append(result, "STREAM_NAME|");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_SIZE)
		result = talloc_asprintf_append(result, "STREAM_SIZE|");
	if (filter & FILE_NOTIFY_CHANGE_STREAM_WRITE)
		result = talloc_asprintf_append(result, "STREAM_WRITE|");

	if (result == NULL) return NULL;
	if (*result == '\0') return result;

	result[strlen(result)-1] = '\0';
	return result;
}

struct sys_notify_context *sys_notify_context_create(connection_struct *conn,
						     TALLOC_CTX *mem_ctx, 
						     struct event_context *ev)
{
	struct sys_notify_context *ctx;

	if (!(ctx = TALLOC_P(mem_ctx, struct sys_notify_context))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ctx->ev = ev;
	ctx->conn = conn;
	ctx->private_data = NULL;
	return ctx;
}

NTSTATUS sys_notify_watch(struct sys_notify_context *ctx,
			  struct notify_entry *e,
			  void (*callback)(struct sys_notify_context *ctx, 
					   void *private_data,
					   struct notify_event *ev),
			  void *private_data, void *handle)
{
	return SMB_VFS_NOTIFY_WATCH(ctx->conn, ctx, e, callback, private_data,
				    handle);
}


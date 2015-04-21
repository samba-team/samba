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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../librpc/gen_ndr/ndr_notify.h"
#include "librpc/gen_ndr/ndr_file_id.h"

struct notify_change_event {
	struct timespec when;
	uint32_t action;
	const char *name;
};

struct notify_change_buf {
	/*
	 * If no requests are pending, changes are queued here. Simple array,
	 * we only append.
	 */

	/*
	 * num_changes == -1 means that we have got a catch-all change, when
	 * asked we just return NT_STATUS_OK without specific changes.
	 */
	int num_changes;
	struct notify_change_event *changes;

	/*
	 * If no changes are around requests are queued here. Using a linked
	 * list, because we have to append at the end and delete from the top.
	 */
	struct notify_change_request *requests;
};

struct notify_change_request {
	struct notify_change_request *prev, *next;
	struct files_struct *fsp;	/* backpointer for cancel by mid */
	struct smb_request *req;
	uint32 filter;
	uint32 max_param;
	void (*reply_fn)(struct smb_request *req,
			 NTSTATUS error_code,
			 uint8_t *buf, size_t len);
	struct notify_mid_map *mid_map;
	void *backend_data;
};

static void notify_fsp(files_struct *fsp, struct timespec when,
		       uint32 action, const char *name);

bool change_notify_fsp_has_changes(struct files_struct *fsp)
{
	if (fsp == NULL) {
		return false;
	}

	if (fsp->notify == NULL) {
		return false;
	}

	if (fsp->notify->num_changes == 0) {
		return false;
	}

	return true;
}

/*
 * For NTCancel, we need to find the notify_change_request indexed by
 * mid. Separate list here.
 */

struct notify_mid_map {
	struct notify_mid_map *prev, *next;
	struct notify_change_request *req;
	uint64_t mid;
};

static bool notify_change_record_identical(struct notify_change_event *c1,
					   struct notify_change_event *c2)
{
	/* Note this is deliberately case sensitive. */
	if (c1->action == c2->action &&
			strcmp(c1->name, c2->name) == 0) {
		return True;
	}
	return False;
}

static int compare_notify_change_events(const void *p1, const void *p2)
{
	const struct notify_change_event *e1 = p1;
	const struct notify_change_event *e2 = p2;

	return timespec_compare(&e1->when, &e2->when);
}

static bool notify_marshall_changes(int num_changes,
				uint32 max_offset,
				struct notify_change_event *changes,
				DATA_BLOB *final_blob)
{
	int i;

	if (num_changes == -1) {
		return false;
	}

	/*
	 * Sort the notifies by timestamp when the event happened to avoid
	 * coalescing and thus dropping events.
	 */

	qsort(changes, num_changes,
	      sizeof(*changes), compare_notify_change_events);

	for (i=0; i<num_changes; i++) {
		enum ndr_err_code ndr_err;
		struct notify_change_event *c;
		struct FILE_NOTIFY_INFORMATION m;
		DATA_BLOB blob;

		/* Coalesce any identical records. */
		while (i+1 < num_changes &&
			notify_change_record_identical(&changes[i],
						&changes[i+1])) {
			i++;
		}

		c = &changes[i];

		m.FileName1 = c->name;
		m.FileNameLength = strlen_m(c->name)*2;
		m.Action = c->action;
		m.NextEntryOffset = (i == num_changes-1) ? 0 : ndr_size_FILE_NOTIFY_INFORMATION(&m, 0);

		/*
		 * Offset to next entry, only if there is one
		 */

		ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &m,
			(ndr_push_flags_fn_t)ndr_push_FILE_NOTIFY_INFORMATION);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return false;
		}

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(FILE_NOTIFY_INFORMATION, &m);
		}

		if (!data_blob_append(talloc_tos(), final_blob,
				      blob.data, blob.length)) {
			data_blob_free(&blob);
			return false;
		}

		data_blob_free(&blob);

		if (final_blob->length > max_offset) {
			/* Too much data for client. */
			DEBUG(10, ("Client only wanted %d bytes, trying to "
				   "marshall %d bytes\n", (int)max_offset,
				   (int)final_blob->length));
			return False;
		}
	}

	return True;
}

/****************************************************************************
 Setup the common parts of the return packet and send it.
*****************************************************************************/

void change_notify_reply(struct smb_request *req,
			 NTSTATUS error_code,
			 uint32_t max_param,
			 struct notify_change_buf *notify_buf,
			 void (*reply_fn)(struct smb_request *req,
					  NTSTATUS error_code,
					  uint8_t *buf, size_t len))
{
	DATA_BLOB blob = data_blob_null;

	if (!NT_STATUS_IS_OK(error_code)) {
		reply_fn(req, error_code, NULL, 0);
		return;
	}

	if (max_param == 0 || notify_buf == NULL) {
		reply_fn(req, NT_STATUS_OK, NULL, 0);
		return;
	}

	if (!notify_marshall_changes(notify_buf->num_changes, max_param,
					notify_buf->changes, &blob)) {
		/*
		 * We exceed what the client is willing to accept. Send
		 * nothing.
		 */
		data_blob_free(&blob);
	}

	reply_fn(req, NT_STATUS_OK, blob.data, blob.length);

	data_blob_free(&blob);

	TALLOC_FREE(notify_buf->changes);
	notify_buf->num_changes = 0;
}

static void notify_callback(void *private_data, struct timespec when,
			    const struct notify_event *e)
{
	files_struct *fsp = (files_struct *)private_data;
	DEBUG(10, ("notify_callback called for %s\n", fsp_str_dbg(fsp)));
	notify_fsp(fsp, when, e->action, e->path);
}

static void sys_notify_callback(struct sys_notify_context *ctx,
				void *private_data,
				struct notify_event *e)
{
	files_struct *fsp = (files_struct *)private_data;
	DEBUG(10, ("sys_notify_callback called for %s\n", fsp_str_dbg(fsp)));
	notify_fsp(fsp, timespec_current(), e->action, e->path);
}

NTSTATUS change_notify_create(struct files_struct *fsp, uint32 filter,
			      bool recursive)
{
	char *fullpath;
	size_t len;
	uint32_t subdir_filter;
	NTSTATUS status = NT_STATUS_NOT_IMPLEMENTED;

	if (fsp->notify != NULL) {
		DEBUG(1, ("change_notify_create: fsp->notify != NULL, "
			  "fname = %s\n", fsp->fsp_name->base_name));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!(fsp->notify = talloc_zero(NULL, struct notify_change_buf))) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Do notify operations on the base_name. */
	fullpath = talloc_asprintf(
		talloc_tos(), "%s/%s", fsp->conn->connectpath,
		fsp->fsp_name->base_name);
	if (fullpath == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		TALLOC_FREE(fsp->notify);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Avoid /. at the end of the path name. notify can't deal with it.
	 */
	len = strlen(fullpath);
	if (len > 1 && fullpath[len-1] == '.' && fullpath[len-2] == '/') {
		fullpath[len-2] = '\0';
	}

	subdir_filter = recursive ? filter : 0;

	if (fsp->conn->sconn->sys_notify_ctx != NULL) {
		void *sys_notify_handle = NULL;

		status = SMB_VFS_NOTIFY_WATCH(
			fsp->conn, fsp->conn->sconn->sys_notify_ctx,
			fullpath, &filter, &subdir_filter,
			sys_notify_callback, fsp, &sys_notify_handle);

		if (NT_STATUS_IS_OK(status)) {
			talloc_steal(fsp->notify, sys_notify_handle);
		}
	}

	if ((filter != 0) || (subdir_filter != 0)) {
		status = notify_add(fsp->conn->sconn->notify_ctx,
				    fullpath, filter, subdir_filter,
				    notify_callback, fsp);
	}
	TALLOC_FREE(fullpath);
	return status;
}

NTSTATUS change_notify_add_request(struct smb_request *req,
				uint32 max_param,
				uint32 filter, bool recursive,
				struct files_struct *fsp,
				void (*reply_fn)(struct smb_request *req,
					NTSTATUS error_code,
					uint8_t *buf, size_t len))
{
	struct notify_change_request *request = NULL;
	struct notify_mid_map *map = NULL;
	struct smbd_server_connection *sconn = req->sconn;

	DEBUG(10, ("change_notify_add_request: Adding request for %s: "
		   "max_param = %d\n", fsp_str_dbg(fsp), (int)max_param));

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
	request->reply_fn = reply_fn;
	request->backend_data = NULL;

	DLIST_ADD_END(fsp->notify->requests, request,
		      struct notify_change_request *);

	map->mid = request->req->mid;
	DLIST_ADD(sconn->smb1.notify_mid_maps, map);

	return NT_STATUS_OK;
}

static void change_notify_remove_request(struct smbd_server_connection *sconn,
					 struct notify_change_request *remove_req)
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
	DLIST_REMOVE(sconn->smb1.notify_mid_maps, req->mid_map);
	TALLOC_FREE(req);
}

static void smbd_notify_cancel_by_map(struct notify_mid_map *map)
{
	struct smb_request *smbreq = map->req->req;
	struct smbd_server_connection *sconn = smbreq->sconn;
	struct smbd_smb2_request *smb2req = smbreq->smb2req;
	NTSTATUS notify_status = NT_STATUS_CANCELLED;

	if (smb2req != NULL) {
		if (smb2req->session == NULL) {
			notify_status = STATUS_NOTIFY_CLEANUP;
		} else if (!NT_STATUS_IS_OK(smb2req->session->status)) {
			notify_status = STATUS_NOTIFY_CLEANUP;
		}
		if (smb2req->tcon == NULL) {
			notify_status = STATUS_NOTIFY_CLEANUP;
		} else if (!NT_STATUS_IS_OK(smb2req->tcon->status)) {
			notify_status = STATUS_NOTIFY_CLEANUP;
		}
	}

	change_notify_reply(smbreq, notify_status,
			    0, NULL, map->req->reply_fn);
	change_notify_remove_request(sconn, map->req);
}

/****************************************************************************
 Delete entries by mid from the change notify pending queue. Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid)
{
	struct notify_mid_map *map;

	for (map = sconn->smb1.notify_mid_maps; map; map = map->next) {
		if (map->mid == mid) {
			break;
		}
	}

	if (map == NULL) {
		return;
	}

	smbd_notify_cancel_by_map(map);
}

void smbd_notify_cancel_by_smbreq(const struct smb_request *smbreq)
{
	struct smbd_server_connection *sconn = smbreq->sconn;
	struct notify_mid_map *map;

	for (map = sconn->smb1.notify_mid_maps; map; map = map->next) {
		if (map->req->req == smbreq) {
			break;
		}
	}

	if (map == NULL) {
		return;
	}

	smbd_notify_cancel_by_map(map);
}

static struct files_struct *smbd_notify_cancel_deleted_fn(
	struct files_struct *fsp, void *private_data)
{
	struct file_id *fid = talloc_get_type_abort(
		private_data, struct file_id);

	if (file_id_equal(&fsp->file_id, fid)) {
		remove_pending_change_notify_requests_by_fid(
			fsp, NT_STATUS_DELETE_PENDING);
	}
	return NULL;
}

void smbd_notify_cancel_deleted(struct messaging_context *msg,
				void *private_data, uint32_t msg_type,
				struct server_id server_id, DATA_BLOB *data)
{
	struct smbd_server_connection *sconn = talloc_get_type_abort(
		private_data, struct smbd_server_connection);
	struct file_id *fid;
	enum ndr_err_code ndr_err;

	fid = talloc(talloc_tos(), struct file_id);
	if (fid == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		data, fid, fid, (ndr_pull_flags_fn_t)ndr_pull_file_id);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_file_id failed: %s\n", __func__,
			   ndr_errstr(ndr_err)));
		goto done;
	}

	files_forall(sconn, smbd_notify_cancel_deleted_fn, fid);

done:
	TALLOC_FREE(fid);
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
		change_notify_reply(fsp->notify->requests->req,
				    status, 0, NULL,
				    fsp->notify->requests->reply_fn);
		change_notify_remove_request(fsp->conn->sconn,
					     fsp->notify->requests);
	}
}

void notify_fname(connection_struct *conn, uint32 action, uint32 filter,
		  const char *path)
{
	struct notify_context *notify_ctx = conn->sconn->notify_ctx;
	char *fullpath, *to_free;
	char tmpbuf[PATH_MAX];
	ssize_t len;

	if (path[0] == '.' && path[1] == '/') {
		path += 2;
	}
	len = full_path_tos(conn->connectpath, path, tmpbuf, sizeof(tmpbuf),
			    &fullpath, &to_free);
	if (len == -1) {
		DEBUG(0, ("full_path_tos failed\n"));
		return;
	}
	notify_trigger(notify_ctx, action, filter, fullpath);
	TALLOC_FREE(to_free);
}

static void notify_fsp(files_struct *fsp, struct timespec when,
		       uint32 action, const char *name)
{
	struct notify_change_event *change, *changes;
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
			change_notify_reply(fsp->notify->requests->req,
					    NT_STATUS_OK,
					    fsp->notify->requests->max_param,
					    fsp->notify,
					    fsp->notify->requests->reply_fn);
			change_notify_remove_request(fsp->conn->sconn,
						     fsp->notify->requests);
		}
		return;
	}

	/* If we've exceeded the server side queue or received a NULL name
	 * from the underlying CN implementation, don't queue up any more
	 * requests until we can send a catch-all response to the client */
	if (fsp->notify->num_changes == -1) {
		return;
	}

	if (!(changes = talloc_realloc(
		      fsp->notify, fsp->notify->changes,
		      struct notify_change_event,
		      fsp->notify->num_changes+1))) {
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

	change->when = when;
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

	change_notify_reply(fsp->notify->requests->req,
			    NT_STATUS_OK,
			    fsp->notify->requests->max_param,
			    fsp->notify,
			    fsp->notify->requests->reply_fn);

	change_notify_remove_request(fsp->conn->sconn, fsp->notify->requests);
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

struct sys_notify_context *sys_notify_context_create(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev)
{
	struct sys_notify_context *ctx;

	if (!(ctx = talloc(mem_ctx, struct sys_notify_context))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ctx->ev = ev;
	ctx->private_data = NULL;
	return ctx;
}

/*
   Unix SMB/CIFS implementation.
   change notify handling
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Jeremy Allison 1994-1998
   Copyright (C) Volker Lendecke 2007

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

static struct cnotify_fns *cnotify;
static struct notify_mid_map *notify_changes_by_mid;

/*
 * For NTCancel, we need to find the notify_change_request indexed by
 * mid. Separate list here.
 */

struct notify_mid_map {
	struct notify_mid_map *prev, *next;
	struct notify_change_request *req;
	uint16 mid;
};

static BOOL notify_marshall_changes(int num_changes,
				    struct notify_change *changes,
				    prs_struct *ps)
{
	int i;
	UNISTR uni_name;

	for (i=0; i<num_changes; i++) {
		struct notify_change *c = &changes[i];
		size_t namelen;
		uint32 u32_tmp;	/* Temp arg to prs_uint32 to avoid
				 * signed/unsigned issues */

		namelen = convert_string_allocate(
			NULL, CH_UNIX, CH_UTF16LE, c->name, strlen(c->name)+1,
			&uni_name.buffer, True);
		if ((namelen == -1) || (uni_name.buffer == NULL)) {
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
	}

	return True;

 fail:
	SAFE_FREE(uni_name.buffer);
	return False;
}

/****************************************************************************
 Setup the common parts of the return packet and send it.
*****************************************************************************/

static void change_notify_reply_packet(const char *request_buf,
				       NTSTATUS error_code)
{
	char outbuf[smb_size+38];

	memset(outbuf, '\0', sizeof(outbuf));
	construct_reply_common(request_buf, outbuf);

	ERROR_NT(error_code);

	/*
	 * Seems NT needs a transact command with an error code
	 * in it. This is a longer packet than a simple error.
	 */
	set_message(outbuf,18,0,False);

	show_msg(outbuf);
	if (!send_smb(smbd_server_fd(),outbuf))
		exit_server_cleanly("change_notify_reply_packet: send_smb "
				    "failed.");
}

void change_notify_reply(const char *request_buf, uint32 max_param_count,
			 int num_changes, struct notify_change *changes)
{
	char *outbuf = NULL;
	prs_struct ps;
	size_t buflen = smb_size+38+max_param_count;

	if (num_changes == -1) {
		change_notify_reply_packet(request_buf, NT_STATUS_OK);
		return;
	}

	if (!prs_init(&ps, 0, NULL, False)
	    || !notify_marshall_changes(num_changes, changes, &ps)) {
		change_notify_reply_packet(request_buf, NT_STATUS_NO_MEMORY);
		goto done;
	}

	if (prs_offset(&ps) > max_param_count) {
		/*
		 * We exceed what the client is willing to accept. Send
		 * nothing.
		 */
		change_notify_reply_packet(request_buf, NT_STATUS_OK);
		goto done;
	}

	if (!(outbuf = SMB_MALLOC_ARRAY(char, buflen))) {
		change_notify_reply_packet(request_buf, NT_STATUS_NO_MEMORY);
		goto done;
	}

	construct_reply_common(request_buf, outbuf);

	if (send_nt_replies(outbuf, buflen, NT_STATUS_OK, prs_data_p(&ps),
			    prs_offset(&ps), NULL, 0) == -1) {
		exit_server("change_notify_reply_packet: send_smb failed.");
	}

 done:
	SAFE_FREE(outbuf);
	prs_mem_free(&ps);
}

NTSTATUS change_notify_add_request(const char *inbuf, uint32 max_param_count,
				   uint32 filter, struct files_struct *fsp)
{
	struct notify_change_request *request = NULL;
	struct notify_mid_map *map = NULL;

	if (!(request = SMB_MALLOC_P(struct notify_change_request))
	    || !(map = SMB_MALLOC_P(struct notify_mid_map))) {
		SAFE_FREE(request);
		return NT_STATUS_NO_MEMORY;
	}

	request->mid_map = map;
	map->req = request;

	memcpy(request->request_buf, inbuf, sizeof(request->request_buf));
	request->max_param_count = max_param_count;
	request->filter = filter;
	request->fsp = fsp;

	request->backend_data = cnotify->notify_add(NULL, smbd_event_context(),
						    fsp, &request->filter);
	
	DLIST_ADD_END(fsp->notify->requests, request,
		      struct notify_change_request *);

	map->mid = SVAL(inbuf, smb_mid);
	DLIST_ADD(notify_changes_by_mid, map);

	/* Push the MID of this packet on the signing queue. */
	srv_defer_sign_response(SVAL(inbuf,smb_mid));

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
		smb_panic("notify_req not found in fsp's requests\n");
	}

	DLIST_REMOVE(fsp->notify->requests, req);
	DLIST_REMOVE(notify_changes_by_mid, req->mid_map);
	SAFE_FREE(req->mid_map);
	TALLOC_FREE(req->backend_data);
	SAFE_FREE(req);
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

	change_notify_reply_packet(map->req->request_buf, NT_STATUS_CANCELLED);
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
			fsp->notify->requests->request_buf, status);
		change_notify_remove_request(fsp->notify->requests);
	}
}

/* notify message definition

Offset  Data			length.
0	SMB_DEV_T dev		8
8	SMB_INO_T inode		8
16	uint32 filter           4
20	uint32 action		4
24..	name
*/

#define MSG_NOTIFY_MESSAGE_SIZE 25 /* Includes at least the '\0' terminator */

struct notify_message {
	SMB_DEV_T dev;
	SMB_INO_T inode;
	uint32 filter;
	uint32 action;
	char *name;
};

static DATA_BLOB notify_message_to_buf(const struct notify_message *msg)
{
	DATA_BLOB result;
	size_t len;

	len = strlen(msg->name);

	result = data_blob(NULL, MSG_NOTIFY_MESSAGE_SIZE + len);
	if (!result.data) {
		return result;
	}

	SDEV_T_VAL(result.data, 0, msg->dev);
	SINO_T_VAL(result.data, 8, msg->inode);
	SIVAL(result.data, 16, msg->filter);
	SIVAL(result.data, 20, msg->action);
	memcpy(result.data+24, msg->name, len+1);

	return result;
}

static BOOL buf_to_notify_message(void *buf, size_t len,
				  struct notify_message *msg)
{
	if (len < MSG_NOTIFY_MESSAGE_SIZE) {
		DEBUG(0, ("Got invalid notify message of len %d\n",
			  (int)len));
		return False;
	}

	msg->dev     = DEV_T_VAL(buf, 0);
	msg->inode   = INO_T_VAL(buf, 8);
	msg->filter  = IVAL(buf, 16);
	msg->action  = IVAL(buf, 20);
	msg->name    = ((char *)buf)+24;
	return True;
}

void notify_action(connection_struct *conn, const char *parent,
		   const char *name, uint32 filter, uint32_t action)
{
	struct share_mode_lock *lck;
	SMB_STRUCT_STAT sbuf;
	int i;
	struct notify_message msg;
	DATA_BLOB blob;

	struct process_id *pids;
	int num_pids;

	DEBUG(10, ("notify_action: parent=%s, name=%s, action=%u\n",
		   parent, name, (unsigned)action));

	if (SMB_VFS_STAT(conn, parent, &sbuf) != 0) {
		/*
		 * Not 100% critical, ignore failure
		 */
		return;
	}

	if (!(lck = get_share_mode_lock(NULL, sbuf.st_dev, sbuf.st_ino,
					NULL, NULL))) {
		return;
	}

	msg.dev = sbuf.st_dev;
	msg.inode = sbuf.st_ino;
	msg.filter = filter;
	msg.action = action;
	msg.name = CONST_DISCARD(char *, name);

	blob = notify_message_to_buf(&msg);
	if (blob.data == NULL) {
		DEBUG(0, ("notify_message_to_buf failed\n"));
		return;
	}

	pids = NULL;
	num_pids = 0;

	become_root_uid_only();

	for (i=0; i<lck->num_share_modes; i++) {
		struct share_mode_entry *e = &lck->share_modes[i];
		int j;
		struct process_id *tmp;

		for (j=0; j<num_pids; j++) {
			if (procid_equal(&e->pid, &pids[j])) {
				break;
			}
		}

		if (j < num_pids) {
			/*
			 * Already sent to that process, skip it
			 */
			continue;
		}

		message_send_pid(lck->share_modes[i].pid, MSG_SMB_NOTIFY,
				 blob.data, blob.length, True);

		if (!(tmp = TALLOC_REALLOC_ARRAY(lck, pids, struct process_id,
						 num_pids+1))) {
			DEBUG(0, ("realloc failed\n"));
			break;
		}
		pids = tmp;
		pids[num_pids] = e->pid;
		num_pids += 1;
	}

	unbecome_root_uid_only();

	data_blob_free(&blob);
	TALLOC_FREE(lck);
}

void notify_fname(connection_struct *conn, uint32 action, uint32 filter,
		  const char *path)
{
	char *parent;
	const char *name;

	if (!parent_dirname_talloc(tmp_talloc_ctx(), path, &parent, &name)) {
		return;
	}

	notify_action(conn, parent, name, filter, action);
	TALLOC_FREE(parent);
}

void notify_fsp(files_struct *fsp, uint32 action, char *name)
{
	struct notify_change *change, *changes;

	if (fsp->notify == NULL) {
		/*
		 * Nobody is waiting, don't queue
		 */
		return;
	}

	if (fsp->notify->requests != NULL) {
		/*
		 * Someone is waiting for the change, trigger the reply
		 * immediately.
		 *
		 * TODO: do we have to walk the lists of requests pending?
		 */

		struct notify_change_request *req = fsp->notify->requests;
		struct notify_change onechange;

		if (name == NULL) {
			/*
			 * Catch-all change, possibly from notify_hash.c
			 */
			change_notify_reply(req->request_buf,
					    req->max_param_count,
					    -1, NULL);
			return;
		}

		onechange.action = action;
		onechange.name = name;

		change_notify_reply(req->request_buf, req->max_param_count,
				    1, &onechange);
		change_notify_remove_request(req);
		return;
	}

	/*
	 * Someone has triggered a notify previously, queue the change for
	 * later. TODO: Limit the number of changes queued, test how filters
	 * apply here. Do we have to store them?
	 */

	if ((fsp->notify->num_changes > 30) || (name == NULL)) {
		/*
		 * W2k3 seems to store at most 30 changes.
		 */
		TALLOC_FREE(fsp->notify->changes);
		fsp->notify->num_changes = -1;
		return;
	}

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

	if (!(change->name = talloc_strdup(changes, name))) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return;
	}
	change->action = action;
	fsp->notify->num_changes += 1;

	return;
}

static void notify_message_callback(int msgtype, struct process_id pid,
				    void *buf, size_t len,
				    void *private_data)
{
	struct notify_message msg;
	files_struct *fsp;

	if (!buf_to_notify_message(buf, len, &msg)) {
		return;
	}

	DEBUG(10, ("Received notify_message for 0x%x/%.0f: %d\n",
		   (unsigned)msg.dev, (double)msg.inode, msg.action));

	for(fsp = fsp_find_di_first(msg.dev, msg.inode); fsp;
	    fsp = fsp_find_di_next(fsp)) {
		if ((fsp->notify != NULL) 
		    && (fsp->notify->requests != NULL)
		    && (fsp->notify->requests->filter & msg.filter)) {
			notify_fsp(fsp, msg.action, msg.name);
		}
	}
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

/****************************************************************************
 Initialise the change notify subsystem.
****************************************************************************/

BOOL init_change_notify(void)
{
	cnotify = NULL;

#if HAVE_KERNEL_CHANGE_NOTIFY
	if (cnotify == NULL && lp_kernel_change_notify())
		cnotify = kernel_notify_init(smbd_event_context());
#endif
#if HAVE_FAM_CHANGE_NOTIFY
	if (cnotify == NULL && lp_fam_change_notify())
		cnotify = fam_notify_init(smbd_event_context());
#endif
	if (!cnotify) cnotify = hash_notify_init();
	
	if (!cnotify) {
		DEBUG(0,("Failed to init change notify system\n"));
		return False;
	}

	message_register(MSG_SMB_NOTIFY, notify_message_callback, NULL);

	return True;
}

struct sys_notify_context *sys_notify_context_create(struct share_params *scfg,
						     TALLOC_CTX *mem_ctx, 
						     struct event_context *ev)
{
	struct sys_notify_context *ctx;

	if (!(ctx = TALLOC_P(mem_ctx, struct sys_notify_context))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ctx->ev = ev;
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
#ifdef HAVE_INOTIFY
	return inotify_watch(ctx, e, callback, private_data, handle);
#else
	return NT_STATUS_OK;
#endif
}


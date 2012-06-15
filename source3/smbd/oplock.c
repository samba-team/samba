/* 
   Unix SMB/CIFS implementation.
   oplock processing
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998 - 2001
   Copyright (C) Volker Lendecke 2005

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

#define DBGC_CLASS DBGC_LOCKING
#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "messages.h"
#include "../librpc/gen_ndr/open_files.h"

/*
 * helper function used by the kernel oplock backends to post the break message
 */
void break_kernel_oplock(struct messaging_context *msg_ctx, files_struct *fsp)
{
	uint8_t msg[MSG_SMB_KERNEL_BREAK_SIZE];

	/* Put the kernel break info into the message. */
	push_file_id_24((char *)msg, &fsp->file_id);
	SIVAL(msg,24,fsp->fh->gen_id);

	/* Don't need to be root here as we're only ever
	   sending to ourselves. */

	messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
			   MSG_SMB_KERNEL_BREAK,
			   msg, MSG_SMB_KERNEL_BREAK_SIZE);
}

/****************************************************************************
 Attempt to set an oplock on a file. Succeeds if kernel oplocks are
 disabled (just sets flags) and no byte-range locks in the file. Returns True
 if oplock set.
****************************************************************************/

NTSTATUS set_file_oplock(files_struct *fsp, int oplock_type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	bool use_kernel = lp_kernel_oplocks(SNUM(fsp->conn)) && koplocks;

	if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		if (use_kernel &&
		    !(koplocks->flags & KOPLOCKS_LEVEL2_SUPPORTED)) {
			DEBUG(10, ("Refusing level2 oplock, kernel oplocks "
				   "don't support them\n"));
			return NT_STATUS_NOT_SUPPORTED;
		}
	}

	if ((fsp->oplock_type != NO_OPLOCK) &&
	    (fsp->oplock_type != FAKE_LEVEL_II_OPLOCK) &&
	    use_kernel &&
	    !koplocks->ops->set_oplock(koplocks, fsp, oplock_type))
	{
		return map_nt_error_from_unix(errno);
	}

	fsp->oplock_type = oplock_type;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	if (oplock_type == LEVEL_II_OPLOCK) {
		sconn->oplocks.level_II_open++;
	} else if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		sconn->oplocks.exclusive_open++;
	}

	DEBUG(5,("set_file_oplock: granted oplock on file %s, %s/%lu, "
		    "tv_sec = %x, tv_usec = %x\n",
		 fsp_str_dbg(fsp), file_id_string_tos(&fsp->file_id),
		 fsp->fh->gen_id, (int)fsp->open_time.tv_sec,
		 (int)fsp->open_time.tv_usec ));

	return NT_STATUS_OK;
}

/****************************************************************************
 Attempt to release an oplock on a file. Decrements oplock count.
****************************************************************************/

void release_file_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	if ((fsp->oplock_type != NO_OPLOCK) &&
	    (fsp->oplock_type != FAKE_LEVEL_II_OPLOCK) &&
	    koplocks) {
		koplocks->ops->release_oplock(koplocks, fsp, NO_OPLOCK);
	}

	if (fsp->oplock_type == LEVEL_II_OPLOCK) {
		sconn->oplocks.level_II_open--;
	} else if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		sconn->oplocks.exclusive_open--;
	}

	SMB_ASSERT(sconn->oplocks.exclusive_open>=0);
	SMB_ASSERT(sconn->oplocks.level_II_open>=0);

	if (EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		/* This doesn't matter for close. */
		fsp->oplock_type = FAKE_LEVEL_II_OPLOCK;
	} else {
		fsp->oplock_type = NO_OPLOCK;
	}
	fsp->sent_oplock_break = NO_BREAK_SENT;

	flush_write_cache(fsp, OPLOCK_RELEASE_FLUSH);
	delete_write_cache(fsp);

	TALLOC_FREE(fsp->oplock_timeout);
}

/****************************************************************************
 Attempt to downgrade an oplock on a file. Doesn't decrement oplock count.
****************************************************************************/

static void downgrade_file_oplock(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	if (!EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		DEBUG(0, ("trying to downgrade an already-downgraded oplock!\n"));
		return;
	}

	if (koplocks) {
		koplocks->ops->release_oplock(koplocks, fsp, LEVEL_II_OPLOCK);
	}
	fsp->oplock_type = LEVEL_II_OPLOCK;
	sconn->oplocks.exclusive_open--;
	sconn->oplocks.level_II_open++;
	fsp->sent_oplock_break = NO_BREAK_SENT;
}

/****************************************************************************
 Remove a file oplock. Copes with level II and exclusive.
 Locks then unlocks the share mode lock. Client can decide to go directly
 to none even if a "break-to-level II" was sent.
****************************************************************************/

bool remove_oplock(files_struct *fsp)
{
	bool ret;
	struct share_mode_lock *lck;

	/* Remove the oplock flag from the sharemode. */
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		DEBUG(0,("remove_oplock: failed to lock share entry for "
			 "file %s\n", fsp_str_dbg(fsp)));
		return False;
	}
	ret = remove_share_oplock(lck, fsp);
	if (!ret) {
		DEBUG(0,("remove_oplock: failed to remove share oplock for "
			 "file %s, %s, %s\n",
			 fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			 file_id_string_tos(&fsp->file_id)));
	}
	release_file_oplock(fsp);
	TALLOC_FREE(lck);
	return ret;
}

/*
 * Deal with a reply when a break-to-level II was sent.
 */
bool downgrade_oplock(files_struct *fsp)
{
	bool ret;
	struct share_mode_lock *lck;

	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck == NULL) {
		DEBUG(0,("downgrade_oplock: failed to lock share entry for "
			 "file %s\n", fsp_str_dbg(fsp)));
		return False;
	}
	ret = downgrade_share_oplock(lck, fsp);
	if (!ret) {
		DEBUG(0,("downgrade_oplock: failed to downgrade share oplock "
			 "for file %s, %s, file_id %s\n",
			 fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			 file_id_string_tos(&fsp->file_id)));
	}

	downgrade_file_oplock(fsp);
	TALLOC_FREE(lck);
	return ret;
}

/*
 * Some kernel oplock implementations handle the notification themselves.
 */
bool should_notify_deferred_opens(struct smbd_server_connection *sconn)
{
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	return !(koplocks &&
		(koplocks->flags & KOPLOCKS_DEFERRED_OPEN_NOTIFICATION));
}

/****************************************************************************
 Set up an oplock break message.
****************************************************************************/

static char *new_break_message_smb1(TALLOC_CTX *mem_ctx,
				   files_struct *fsp, int cmd)
{
	char *result = talloc_array(mem_ctx, char, smb_size + 8*2 + 0);

	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	memset(result,'\0',smb_size);
	srv_set_message(result,8,0,true);
	SCVAL(result,smb_com,SMBlockingX);
	SSVAL(result,smb_tid,fsp->conn->cnum);
	SSVAL(result,smb_pid,0xFFFF);
	SSVAL(result,smb_uid,0);
	SSVAL(result,smb_mid,0xFFFF);
	SCVAL(result,smb_vwv0,0xFF);
	SSVAL(result,smb_vwv2,fsp->fnum);
	SCVAL(result,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
	SCVAL(result,smb_vwv3+1,cmd);
	return result;
}

/****************************************************************************
 Function to do the waiting before sending a local break.
****************************************************************************/

static void wait_before_sending_break(void)
{
	long wait_time = (long)lp_oplock_break_wait_time();

	if (wait_time) {
		smb_msleep(wait_time);
	}
}

/****************************************************************************
 Ensure that we have a valid oplock.
****************************************************************************/

static files_struct *initial_break_processing(
	struct smbd_server_connection *sconn, struct file_id id,
	unsigned long file_id)
{
	files_struct *fsp = NULL;

	if( DEBUGLVL( 3 ) ) {
		dbgtext( "initial_break_processing: called for %s/%u\n",
			 file_id_string_tos(&id), (int)file_id);
		dbgtext( "Current oplocks_open (exclusive = %d, levelII = %d)\n",
			sconn->oplocks.exclusive_open,
			sconn->oplocks.level_II_open);
	}

	/*
	 * We need to search the file open table for the
	 * entry containing this dev and inode, and ensure
	 * we have an oplock on it.
	 */

	fsp = file_find_dif(sconn, id, file_id);

	if(fsp == NULL) {
		/* The file could have been closed in the meantime - return success. */
		if( DEBUGLVL( 3 ) ) {
			dbgtext( "initial_break_processing: cannot find open file with " );
			dbgtext( "file_id %s gen_id = %lu", file_id_string_tos(&id), file_id);
			dbgtext( "allowing break to succeed.\n" );
		}
		return NULL;
	}

	/* Ensure we have an oplock on the file */

	/*
	 * There is a potential race condition in that an oplock could
	 * have been broken due to another udp request, and yet there are
	 * still oplock break messages being sent in the udp message
	 * queue for this file. So return true if we don't have an oplock,
	 * as we may have just freed it.
	 */

	if(fsp->oplock_type == NO_OPLOCK) {
		if( DEBUGLVL( 3 ) ) {
			dbgtext( "initial_break_processing: file %s ",
				 fsp_str_dbg(fsp));
			dbgtext( "(file_id = %s gen_id = %lu) has no oplock.\n",
				 file_id_string_tos(&id), fsp->fh->gen_id );
			dbgtext( "Allowing break to succeed regardless.\n" );
		}
		return NULL;
	}

	return fsp;
}

static void oplock_timeout_handler(struct event_context *ctx,
				   struct timed_event *te,
				   struct timeval now,
				   void *private_data)
{
	files_struct *fsp = (files_struct *)private_data;

	/* Remove the timed event handler. */
	TALLOC_FREE(fsp->oplock_timeout);
	DEBUG(0, ("Oplock break failed for file %s -- replying anyway\n",
		  fsp_str_dbg(fsp)));
	remove_oplock(fsp);
	reply_to_oplock_break_requests(fsp);
}

/*******************************************************************
 Add a timeout handler waiting for the client reply.
*******************************************************************/

static void add_oplock_timeout_handler(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	/*
	 * If kernel oplocks already notifies smbds when an oplock break times
	 * out, just return.
	 */
	if (koplocks &&
	    (koplocks->flags & KOPLOCKS_TIMEOUT_NOTIFICATION)) {
		return;
	}

	if (fsp->oplock_timeout != NULL) {
		DEBUG(0, ("Logic problem -- have an oplock event hanging "
			  "around\n"));
	}

	fsp->oplock_timeout =
		tevent_add_timer(fsp->conn->sconn->ev_ctx, fsp,
				 timeval_current_ofs(OPLOCK_BREAK_TIMEOUT, 0),
				 oplock_timeout_handler, fsp);

	if (fsp->oplock_timeout == NULL) {
		DEBUG(0, ("Could not add oplock timeout handler\n"));
	}
}

static void send_break_message_smb1(files_struct *fsp, int level)
{
	char *break_msg = new_break_message_smb1(talloc_tos(),
					fsp,
					level);
	if (break_msg == NULL) {
		exit_server("Could not talloc break_msg\n");
	}

	show_msg(break_msg);
	if (!srv_send_smb(fsp->conn->sconn,
			break_msg, false, 0,
			IS_CONN_ENCRYPTED(fsp->conn),
			NULL)) {
		exit_server_cleanly("send_break_message_smb1: "
			"srv_send_smb failed.");
	}

	TALLOC_FREE(break_msg);
}

void break_level2_to_none_async(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;

	if (fsp->oplock_type == NO_OPLOCK) {
		/* We already got a "break to none" message and we've handled
		 * it.  just ignore. */
		DEBUG(3, ("process_oplock_async_level2_break_message: already "
			  "broken to none, ignoring.\n"));
		return;
	}

	if (fsp->oplock_type == FAKE_LEVEL_II_OPLOCK) {
		/* Don't tell the client, just downgrade. */
		DEBUG(3, ("process_oplock_async_level2_break_message: "
			  "downgrading fake level 2 oplock.\n"));
		remove_oplock(fsp);
		return;
	}

	/* Ensure we're really at level2 state. */
	SMB_ASSERT(fsp->oplock_type == LEVEL_II_OPLOCK);

	DEBUG(10,("process_oplock_async_level2_break_message: sending break "
		  "to none message for %s, file %s\n", fsp_fnum_dbg(fsp),
		  fsp_str_dbg(fsp)));

	/* Now send a break to none message to our client. */
	if (sconn->using_smb2) {
		send_break_message_smb2(fsp, OPLOCKLEVEL_NONE);
	} else {
		send_break_message_smb1(fsp, OPLOCKLEVEL_NONE);
	}

	/* Async level2 request, don't send a reply, just remove the oplock. */
	remove_oplock(fsp);
}

/*******************************************************************
 This handles the case of a write triggering a break to none
 message on a level2 oplock.
 When we get this message we may be in any of three states :
 NO_OPLOCK, LEVEL_II, FAKE_LEVEL2. We only send a message to
 the client for LEVEL2.
*******************************************************************/

static void process_oplock_async_level2_break_message(struct messaging_context *msg_ctx,
						      void *private_data,
						      uint32_t msg_type,
						      struct server_id src,
						      DATA_BLOB *data)
{
	struct share_mode_entry msg;
	files_struct *fsp;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_SHARE_MODE_ENTRY_SIZE) {
		DEBUG(0, ("Got invalid msg len %d\n", (int)data->length));
		return;
	}

	/* De-linearize incoming message. */
	message_to_share_mode_entry(&msg, (char *)data->data);

	DEBUG(10, ("Got oplock async level 2 break message from pid %s: "
		   "%s/%llu\n", server_id_str(talloc_tos(), &src),
		   file_id_string_tos(&msg.id),
		   (unsigned long long)msg.share_file_id));

	fsp = initial_break_processing(sconn, msg.id, msg.share_file_id);

	if (fsp == NULL) {
		/* We hit a race here. Break messages are sent, and before we
		 * get to process this message, we have closed the file. 
		 * No need to reply as this is an async message. */
		DEBUG(3, ("process_oplock_async_level2_break_message: Did not find fsp, ignoring\n"));
		return;
	}

	break_level2_to_none_async(fsp);
}

/*******************************************************************
 This handles the generic oplock break message from another smbd.
*******************************************************************/

static void process_oplock_break_message(struct messaging_context *msg_ctx,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id src,
					 DATA_BLOB *data)
{
	struct share_mode_entry msg;
	files_struct *fsp;
	bool break_to_level2 = False;
	bool use_kernel;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);
	struct server_id self = messaging_server_id(sconn->msg_ctx);
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_SHARE_MODE_ENTRY_SIZE) {
		DEBUG(0, ("Got invalid msg len %d\n", (int)data->length));
		return;
	}

	/* De-linearize incoming message. */
	message_to_share_mode_entry(&msg, (char *)data->data);

	DEBUG(10, ("Got oplock break message from pid %s: %s/%llu\n",
		   server_id_str(talloc_tos(), &src),
		   file_id_string_tos(&msg.id),
		   (unsigned long long)msg.share_file_id));

	fsp = initial_break_processing(sconn, msg.id, msg.share_file_id);

	if (fsp == NULL) {
		/* We hit a race here. Break messages are sent, and before we
		 * get to process this message, we have closed the file. Reply
		 * with 'ok, oplock broken' */
		DEBUG(3, ("Did not find fsp\n"));

		/* We just send the same message back. */
		messaging_send_buf(msg_ctx, src, MSG_SMB_BREAK_RESPONSE,
				   (uint8 *)data->data,
				   MSG_SMB_SHARE_MODE_ENTRY_SIZE);
		return;
	}

	if (fsp->sent_oplock_break != NO_BREAK_SENT) {
		/* Remember we have to inform the requesting PID when the
		 * client replies */
		msg.pid = src;
		ADD_TO_ARRAY(NULL, struct share_mode_entry, msg,
			     &fsp->pending_break_messages,
			     &fsp->num_pending_break_messages);
		return;
	}

	if (EXCLUSIVE_OPLOCK_TYPE(msg.op_type) &&
	    !EXCLUSIVE_OPLOCK_TYPE(fsp->oplock_type)) {
		DEBUG(3, ("Already downgraded oplock on %s: %s\n",
			  file_id_string_tos(&fsp->file_id),
			  fsp_str_dbg(fsp)));
		/* We just send the same message back. */
		messaging_send_buf(msg_ctx, src, MSG_SMB_BREAK_RESPONSE,
				   (uint8 *)data->data,
				   MSG_SMB_SHARE_MODE_ENTRY_SIZE);
		return;
	}

	use_kernel = lp_kernel_oplocks(SNUM(fsp->conn)) && koplocks;

	if ((global_client_caps & CAP_LEVEL_II_OPLOCKS) &&
	    !(msg.op_type & FORCE_OPLOCK_BREAK_TO_NONE) &&
	    !(use_kernel && !(koplocks->flags & KOPLOCKS_LEVEL2_SUPPORTED)) &&
	    lp_level2_oplocks(SNUM(fsp->conn))) {
		break_to_level2 = True;
	}

	/* Need to wait before sending a break
	   message if we sent ourselves this message. */
	if (serverid_equal(&self, &src)) {
		wait_before_sending_break();
	}

	if (sconn->using_smb2) {
		send_break_message_smb2(fsp, break_to_level2 ?
			OPLOCKLEVEL_II : OPLOCKLEVEL_NONE);
	} else {
		send_break_message_smb1(fsp, break_to_level2 ?
			OPLOCKLEVEL_II : OPLOCKLEVEL_NONE);
	}

	fsp->sent_oplock_break = break_to_level2 ? LEVEL_II_BREAK_SENT:BREAK_TO_NONE_SENT;

	msg.pid = src;
	ADD_TO_ARRAY(NULL, struct share_mode_entry, msg,
		     &fsp->pending_break_messages,
		     &fsp->num_pending_break_messages);

	add_oplock_timeout_handler(fsp);
}

/*******************************************************************
 This handles the kernel oplock break message.
*******************************************************************/

static void process_kernel_oplock_break(struct messaging_context *msg_ctx,
					void *private_data,
					uint32_t msg_type,
					struct server_id src,
					DATA_BLOB *data)
{
	struct file_id id;
	unsigned long file_id;
	files_struct *fsp;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_KERNEL_BREAK_SIZE) {
		DEBUG(0, ("Got invalid msg len %d\n", (int)data->length));
		return;
	}

	/* Pull the data from the message. */
	pull_file_id_24((char *)data->data, &id);
	file_id = (unsigned long)IVAL(data->data, 24);

	DEBUG(10, ("Got kernel oplock break message from pid %s: %s/%u\n",
		   server_id_str(talloc_tos(), &src), file_id_string_tos(&id),
		   (unsigned int)file_id));

	fsp = initial_break_processing(sconn, id, file_id);

	if (fsp == NULL) {
		DEBUG(3, ("Got a kernel oplock break message for a file "
			  "I don't know about\n"));
		return;
	}

	if (fsp->sent_oplock_break != NO_BREAK_SENT) {
		/* This is ok, kernel oplocks come in completely async */
		DEBUG(3, ("Got a kernel oplock request while waiting for a "
			  "break reply\n"));
		return;
	}

	if (sconn->using_smb2) {
		send_break_message_smb2(fsp, OPLOCKLEVEL_NONE);
	} else {
		send_break_message_smb1(fsp, OPLOCKLEVEL_NONE);
	}

	fsp->sent_oplock_break = BREAK_TO_NONE_SENT;

	add_oplock_timeout_handler(fsp);
}

void reply_to_oplock_break_requests(files_struct *fsp)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;
	int i;

	/*
	 * If kernel oplocks already notifies smbds when oplocks are
	 * broken/removed, just return.
	 */
	if (koplocks &&
	    (koplocks->flags & KOPLOCKS_OPLOCK_BROKEN_NOTIFICATION)) {
		return;
	}

	for (i=0; i<fsp->num_pending_break_messages; i++) {
		struct share_mode_entry *e = &fsp->pending_break_messages[i];
		char msg[MSG_SMB_SHARE_MODE_ENTRY_SIZE];

		share_mode_entry_to_message(msg, e);

		messaging_send_buf(fsp->conn->sconn->msg_ctx, e->pid,
				   MSG_SMB_BREAK_RESPONSE,
				   (uint8 *)msg,
				   MSG_SMB_SHARE_MODE_ENTRY_SIZE);
	}

	SAFE_FREE(fsp->pending_break_messages);
	fsp->num_pending_break_messages = 0;
	TALLOC_FREE(fsp->oplock_timeout);
	return;
}

static void process_oplock_break_response(struct messaging_context *msg_ctx,
					  void *private_data,
					  uint32_t msg_type,
					  struct server_id src,
					  DATA_BLOB *data)
{
	struct share_mode_entry msg;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_SHARE_MODE_ENTRY_SIZE) {
		DEBUG(0, ("Got invalid msg len %u\n",
			  (unsigned int)data->length));
		return;
	}

	/* De-linearize incoming message. */
	message_to_share_mode_entry(&msg, (char *)data->data);

	DEBUG(10, ("Got oplock break response from pid %s: %s/%llu mid %llu\n",
		   server_id_str(talloc_tos(), &src),
		   file_id_string_tos(&msg.id),
		   (unsigned long long)msg.share_file_id,
		   (unsigned long long)msg.op_mid));

	schedule_deferred_open_message_smb(sconn, msg.op_mid);
}

static void process_open_retry_message(struct messaging_context *msg_ctx,
				       void *private_data,
				       uint32_t msg_type,
				       struct server_id src,
				       DATA_BLOB *data)
{
	struct share_mode_entry msg;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL) {
		DEBUG(0, ("Got NULL buffer\n"));
		return;
	}

	if (data->length != MSG_SMB_SHARE_MODE_ENTRY_SIZE) {
		DEBUG(0, ("Got invalid msg len %d\n", (int)data->length));
		return;
	}

	/* De-linearize incoming message. */
	message_to_share_mode_entry(&msg, (char *)data->data);

	DEBUG(10, ("Got open retry msg from pid %s: %s mid %llu\n",
		   server_id_str(talloc_tos(), &src), file_id_string_tos(&msg.id),
		   (unsigned long long)msg.op_mid));

	schedule_deferred_open_message_smb(sconn, msg.op_mid);
}

struct break_to_none_state {
	struct smbd_server_connection *sconn;
	struct file_id id;
};
static void do_break_to_none(struct tevent_req *req);

/****************************************************************************
 This function is called on any file modification or lock request. If a file
 is level 2 oplocked then it must tell all other level 2 holders to break to
 none.
****************************************************************************/

static void contend_level2_oplocks_begin_default(files_struct *fsp,
					      enum level2_contention_type type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct tevent_req *req;
	struct break_to_none_state *state;

	/*
	 * If this file is level II oplocked then we need
	 * to grab the shared memory lock and inform all
	 * other files with a level II lock that they need
	 * to flush their read caches. We keep the lock over
	 * the shared memory area whilst doing this.
	 */

	if (!LEVEL_II_OPLOCK_TYPE(fsp->oplock_type))
		return;

	/*
	 * When we get here we might have a brlock entry locked. Also
	 * locking the share mode entry would violate the locking
	 * order. Breaking level2 oplocks to none is asynchronous
	 * anyway, so we postpone this into an immediate timed event.
	 */

	state = talloc(sconn, struct break_to_none_state);
	if (state == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return;
	}
	state->sconn = sconn;
	state->id = fsp->file_id;

	req = tevent_wakeup_send(state, sconn->ev_ctx, timeval_set(0, 0));
	if (req == NULL) {
		DEBUG(1, ("tevent_wakeup_send failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(req, do_break_to_none, state);
	return;
}

static void do_break_to_none(struct tevent_req *req)
{
	struct break_to_none_state *state = tevent_req_callback_data(
		req, struct break_to_none_state);
	struct server_id self = messaging_server_id(state->sconn->msg_ctx);
	bool ret;
	int i;
	struct share_mode_lock *lck;

	ret = tevent_wakeup_recv(req);
	TALLOC_FREE(req);
	if (!ret) {
		DEBUG(1, ("tevent_wakeup_recv failed\n"));
		goto done;
	}
	lck = get_existing_share_mode_lock(talloc_tos(), state->id);
	if (lck == NULL) {
		DEBUG(1, ("release_level_2_oplocks_on_change: failed to lock "
			  "share mode entry for file %s.\n",
			  file_id_string_tos(&state->id)));
		goto done;
	}

	DEBUG(10,("release_level_2_oplocks_on_change: num_share_modes = %d\n", 
		  lck->data->num_share_modes ));

	for(i = 0; i < lck->data->num_share_modes; i++) {
		struct share_mode_entry *share_entry = &lck->data->share_modes[i];
		char msg[MSG_SMB_SHARE_MODE_ENTRY_SIZE];

		if (!is_valid_share_mode_entry(share_entry)) {
			continue;
		}

		/*
		 * As there could have been multiple writes waiting at the
		 * lock_share_entry gate we may not be the first to
		 * enter. Hence the state of the op_types in the share mode
		 * entries may be partly NO_OPLOCK and partly LEVEL_II or FAKE_LEVEL_II
		 * oplock. It will do no harm to re-send break messages to
		 * those smbd's that are still waiting their turn to remove
		 * their LEVEL_II state, and also no harm to ignore existing
		 * NO_OPLOCK states. JRA.
		 */

		DEBUG(10,("release_level_2_oplocks_on_change: "
			  "share_entry[%i]->op_type == %d\n",
			  i, share_entry->op_type ));

		if (share_entry->op_type == NO_OPLOCK) {
			continue;
		}

		/* Paranoia .... */
		if (EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type)) {
			DEBUG(0,("release_level_2_oplocks_on_change: PANIC. "
				 "share mode entry %d is an exlusive "
				 "oplock !\n", i ));
			TALLOC_FREE(lck);
			abort();
		}

		share_mode_entry_to_message(msg, share_entry);

		/*
		 * Deal with a race condition when breaking level2
 		 * oplocks. Don't send all the messages and release
 		 * the lock, this allows someone else to come in and
 		 * get a level2 lock before any of the messages are
 		 * processed, and thus miss getting a break message.
 		 * Ensure at least one entry (the one we're breaking)
 		 * is processed immediately under the lock and becomes
 		 * set as NO_OPLOCK to stop any waiter getting a level2.
 		 * Bugid #5980.
 		 */

		if (serverid_equal(&self, &share_entry->pid)) {
			struct files_struct *cur_fsp =
				initial_break_processing(state->sconn,
					share_entry->id,
					share_entry->share_file_id);
			wait_before_sending_break();
			if (cur_fsp != NULL) {
				break_level2_to_none_async(cur_fsp);
			} else {
				DEBUG(3, ("release_level_2_oplocks_on_change: "
				"Did not find fsp, ignoring\n"));
			}
		} else {
			messaging_send_buf(state->sconn->msg_ctx,
					share_entry->pid,
					MSG_SMB_ASYNC_LEVEL2_BREAK,
					(uint8 *)msg,
					MSG_SMB_SHARE_MODE_ENTRY_SIZE);
		}
	}

	/* We let the message receivers handle removing the oplock state
	   in the share mode lock db. */

	TALLOC_FREE(lck);
done:
	TALLOC_FREE(state);
	return;
}

void smbd_contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	if (koplocks && koplocks->ops->contend_level2_oplocks_begin) {
		koplocks->ops->contend_level2_oplocks_begin(fsp, type);
		return;
	}

	contend_level2_oplocks_begin_default(fsp, type);
}

void smbd_contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	/* Only kernel oplocks implement this so far */
	if (koplocks && koplocks->ops->contend_level2_oplocks_end) {
		koplocks->ops->contend_level2_oplocks_end(fsp, type);
	}
}

/****************************************************************************
 Linearize a share mode entry struct to an internal oplock break message.
****************************************************************************/

void share_mode_entry_to_message(char *msg, const struct share_mode_entry *e)
{
	SIVAL(msg,OP_BREAK_MSG_PID_OFFSET,(uint32)e->pid.pid);
	SBVAL(msg,OP_BREAK_MSG_MID_OFFSET,e->op_mid);
	SSVAL(msg,OP_BREAK_MSG_OP_TYPE_OFFSET,e->op_type);
	SIVAL(msg,OP_BREAK_MSG_ACCESS_MASK_OFFSET,e->access_mask);
	SIVAL(msg,OP_BREAK_MSG_SHARE_ACCESS_OFFSET,e->share_access);
	SIVAL(msg,OP_BREAK_MSG_PRIV_OFFSET,e->private_options);
	SIVAL(msg,OP_BREAK_MSG_TIME_SEC_OFFSET,(uint32_t)e->time.tv_sec);
	SIVAL(msg,OP_BREAK_MSG_TIME_USEC_OFFSET,(uint32_t)e->time.tv_usec);
	push_file_id_24(msg+OP_BREAK_MSG_DEV_OFFSET, &e->id);
	SIVAL(msg,OP_BREAK_MSG_FILE_ID_OFFSET,e->share_file_id);
	SIVAL(msg,OP_BREAK_MSG_UID_OFFSET,e->uid);
	SSVAL(msg,OP_BREAK_MSG_FLAGS_OFFSET,e->flags);
	SIVAL(msg,OP_BREAK_MSG_NAME_HASH_OFFSET,e->name_hash);
	SIVAL(msg,OP_BREAK_MSG_VNN_OFFSET,e->pid.vnn);
}

/****************************************************************************
 De-linearize an internal oplock break message to a share mode entry struct.
****************************************************************************/

void message_to_share_mode_entry(struct share_mode_entry *e, char *msg)
{
	e->pid.pid = (pid_t)IVAL(msg,OP_BREAK_MSG_PID_OFFSET);
	e->op_mid = BVAL(msg,OP_BREAK_MSG_MID_OFFSET);
	e->op_type = SVAL(msg,OP_BREAK_MSG_OP_TYPE_OFFSET);
	e->access_mask = IVAL(msg,OP_BREAK_MSG_ACCESS_MASK_OFFSET);
	e->share_access = IVAL(msg,OP_BREAK_MSG_SHARE_ACCESS_OFFSET);
	e->private_options = IVAL(msg,OP_BREAK_MSG_PRIV_OFFSET);
	e->time.tv_sec = (time_t)IVAL(msg,OP_BREAK_MSG_TIME_SEC_OFFSET);
	e->time.tv_usec = (int)IVAL(msg,OP_BREAK_MSG_TIME_USEC_OFFSET);
	pull_file_id_24(msg+OP_BREAK_MSG_DEV_OFFSET, &e->id);
	e->share_file_id = (unsigned long)IVAL(msg,OP_BREAK_MSG_FILE_ID_OFFSET);
	e->uid = (uint32)IVAL(msg,OP_BREAK_MSG_UID_OFFSET);
	e->flags = (uint16)SVAL(msg,OP_BREAK_MSG_FLAGS_OFFSET);
	e->name_hash = IVAL(msg,OP_BREAK_MSG_NAME_HASH_OFFSET);
	e->pid.vnn = IVAL(msg,OP_BREAK_MSG_VNN_OFFSET);
}

/****************************************************************************
 Setup oplocks for this process.
****************************************************************************/

bool init_oplocks(struct smbd_server_connection *sconn)
{
	DEBUG(3,("init_oplocks: initializing messages.\n"));

	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_BREAK_REQUEST,
			   process_oplock_break_message);
	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_ASYNC_LEVEL2_BREAK,
			   process_oplock_async_level2_break_message);
	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_BREAK_RESPONSE,
			   process_oplock_break_response);
	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_KERNEL_BREAK,
			   process_kernel_oplock_break);
	messaging_register(sconn->msg_ctx, sconn, MSG_SMB_OPEN_RETRY,
			   process_open_retry_message);

	return true;
}

void init_kernel_oplocks(struct smbd_server_connection *sconn)
{
	struct kernel_oplocks *koplocks = sconn->oplocks.kernel_ops;

	/* only initialize once */
	if (koplocks == NULL) {
#if HAVE_KERNEL_OPLOCKS_IRIX
		koplocks = irix_init_kernel_oplocks(sconn);
#elif HAVE_KERNEL_OPLOCKS_LINUX
		koplocks = linux_init_kernel_oplocks(sconn);
#endif
		sconn->oplocks.kernel_ops = koplocks;
	}
}

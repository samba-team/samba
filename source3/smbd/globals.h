/*
   Unix SMB/Netbios implementation.
   smbd globals
   Copyright (C) Stefan Metzmacher 2009

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

#if defined(WITH_AIO)
struct aio_extra;
extern struct aio_extra *aio_list_head;
extern struct tevent_signal *aio_signal_event;
extern int aio_pending_size;
extern int outstanding_aio_calls;
#endif

/* dlink list we store pending lock records on. */
extern struct blocking_lock_record *blocking_lock_queue;

/* dlink list we move cancelled lock records onto. */
extern struct blocking_lock_record *blocking_lock_cancelled_queue;

/* The event that makes us process our blocking lock queue */
extern struct timed_event *brl_timeout;

extern bool blocking_lock_unlock_state;
extern bool blocking_lock_cancel_state;

#ifdef USE_DMAPI
struct smbd_dmapi_context;
extern struct smbd_dmapi_context *dmapi_ctx;
#endif

extern connection_struct *Connections;
/* number of open connections */
extern struct bitmap *bmap;
extern int num_open;

extern bool dfree_broken;

extern struct bitmap *dptr_bmap;
//struct dptr_struct;
extern struct dptr_struct *dirptrs;
extern int dirhandles_open;

/* how many write cache buffers have been allocated */
extern unsigned int allocated_write_caches;

extern int real_max_open_files;
extern struct bitmap *file_bmap;
extern files_struct *Files;
extern int files_used;
/* A singleton cache to speed up searching by dev/inode. */
struct fsp_singleton_cache {
	files_struct *fsp;
	struct file_id id;
};
extern struct fsp_singleton_cache fsp_fi_cache;
extern unsigned long file_gen_counter;
extern int first_file;

extern const struct mangle_fns *mangle_fns;

extern unsigned char *chartest;
extern TDB_CONTEXT *tdb_mangled_cache;

/* these tables are used to provide fast tests for characters */
extern unsigned char char_flags[256];
/*
  this determines how many characters are used from the original filename
  in the 8.3 mangled name. A larger value leads to a weaker hash and more collisions.
  The largest possible value is 6.
*/
extern unsigned mangle_prefix;
extern unsigned char base_reverse[256];

extern char *last_from;
extern char *last_to;

struct msg_state;
extern struct msg_state *smbd_msg_state;

extern bool global_encrypted_passwords_negotiated;
extern bool global_spnego_negotiated;
extern struct auth_context *negprot_global_auth_context;
extern bool done_negprot;

extern bool logged_ioctl_message;

/* users from session setup */
extern char *session_userlist;
/* workgroup from session setup. */
extern char *session_workgroup;
/* this holds info on user ids that are already validated for this VC */
extern user_struct *validated_users;
extern uint16_t next_vuid;
extern int num_validated_vuids;
#ifdef HAVE_NETGROUP
extern char *my_yp_domain;
#endif

extern bool already_got_session;

/*
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
extern int max_send;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
extern int max_recv;
extern uint16 last_session_tag;
extern int trans_num;
extern char *orig_inbuf;

extern pid_t mypid;
extern time_t last_smb_conf_reload_time;
extern time_t last_printer_reload_time;
/****************************************************************************
 structure to hold a linked list of queued messages.
 for processing.
****************************************************************************/
struct pending_message_list;
extern struct pending_message_list *deferred_open_queue;
extern uint32_t common_flags2;

struct smb_srv_trans_enc_ctx;
extern struct smb_srv_trans_enc_ctx *partial_srv_trans_enc_ctx;
extern struct smb_srv_trans_enc_ctx *srv_trans_enc_ctx;

struct sec_ctx {
	UNIX_USER_TOKEN ut;
	NT_USER_TOKEN *token;
};
/* A stack of security contexts.  We include the current context as being
   the first one, so there is room for another MAX_SEC_CTX_DEPTH more. */
extern struct sec_ctx sec_ctx_stack[MAX_SEC_CTX_DEPTH + 1];
extern int sec_ctx_stack_ndx;
extern bool become_uid_done;
extern bool become_gid_done;

extern connection_struct *last_conn;
extern uint16_t last_flags;

extern struct db_context *session_db_ctx_ptr;

extern uint32_t global_client_caps;
extern bool done_sesssetup;
/****************************************************************************
 List to store partial SPNEGO auth fragments.
****************************************************************************/
struct pending_auth_data;
extern struct pending_auth_data *pd_list;

extern uint16_t fnf_handle;

struct conn_ctx {
	connection_struct *conn;
	uint16 vuid;
};
/* A stack of current_user connection contexts. */
extern struct conn_ctx conn_ctx_stack[MAX_SEC_CTX_DEPTH];
extern int conn_ctx_stack_ndx;

struct vfs_init_function_entry;
extern struct vfs_init_function_entry *backends;
extern char *sparse_buf;
extern char *LastDir;

/* Current number of oplocks we have outstanding. */
extern int32_t exclusive_oplocks_open;
extern int32_t level_II_oplocks_open;
extern bool global_client_failed_oplock_break;
extern struct kernel_oplocks *koplocks;

extern struct notify_mid_map *notify_changes_by_mid;

extern int am_parent;
extern int server_fd;
extern struct event_context *smbd_event_ctx;
extern struct messaging_context *smbd_msg_ctx;
extern struct memcache *smbd_memcache_ctx;
extern bool exit_firsttime;
struct child_pid;
extern struct child_pid *children;
extern int num_children;

struct smbd_server_connection {
	struct fd_event *fde;
	uint64_t num_requests;
};
extern struct smbd_server_connection *smbd_server_conn;

void smbd_init_globals(void);

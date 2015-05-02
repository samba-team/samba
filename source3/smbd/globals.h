/*
   Unix SMB/Netbios implementation.
   smbd globals
   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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

#include "system/select.h"
#include "librpc/gen_ndr/smbXsrv.h"

extern int aio_pending_size;
extern int outstanding_aio_calls;

#ifdef USE_DMAPI
struct smbd_dmapi_context;
extern struct smbd_dmapi_context *dmapi_ctx;
#endif

extern bool dfree_broken;

/* how many write cache buffers have been allocated */
extern unsigned int allocated_write_caches;

/* A singleton cache to speed up searching by dev/inode. */
struct fsp_singleton_cache {
	files_struct *fsp;
	struct file_id id;
};

extern const struct mangle_fns *mangle_fns;

extern unsigned char *chartest;
struct tdb_context;
extern struct tdb_context *tdb_mangled_cache;

/*
  this determines how many characters are used from the original filename
  in the 8.3 mangled name. A larger value leads to a weaker hash and more collisions.
  The largest possible value is 6.
*/
extern unsigned mangle_prefix;

struct msg_state;

extern bool logged_ioctl_message;

extern int trans_num;

extern time_t last_smb_conf_reload_time;
extern time_t last_printer_reload_time;
extern pid_t background_lpq_updater_pid;

/****************************************************************************
 structure to hold a linked list of queued messages.
 for processing.
****************************************************************************/
extern uint32_t common_flags2;

extern struct smb_trans_enc_state *partial_srv_trans_enc_ctx;
extern struct smb_trans_enc_state *srv_trans_enc_ctx;

struct sec_ctx {
	struct security_unix_token ut;
	struct security_token *token;
};
/* A stack of security contexts.  We include the current context as being
   the first one, so there is room for another MAX_SEC_CTX_DEPTH more. */
extern struct sec_ctx sec_ctx_stack[MAX_SEC_CTX_DEPTH + 1];
extern int sec_ctx_stack_ndx;
extern bool become_uid_done;
extern bool become_gid_done;

extern connection_struct *last_conn;
extern uint16_t last_flags;

extern uint32_t global_client_caps;

extern uint16_t fnf_handle;

struct conn_ctx {
	connection_struct *conn;
	uint64_t vuid;
};
/* A stack of current_user connection contexts. */
extern struct conn_ctx conn_ctx_stack[MAX_SEC_CTX_DEPTH];
extern int conn_ctx_stack_ndx;

struct vfs_init_function_entry;
extern struct vfs_init_function_entry *backends;
extern char *sparse_buf;
extern char *LastDir;

struct smbd_parent_context;
extern struct smbd_parent_context *am_parent;
extern struct memcache *smbd_memcache_ctx;
extern bool exit_firsttime;

struct tstream_context;
struct smbd_smb2_request;

DATA_BLOB negprot_spnego(TALLOC_CTX *ctx, struct smbXsrv_connection *xconn);

void smbd_lock_socket(struct smbXsrv_connection *xconn);
void smbd_unlock_socket(struct smbXsrv_connection *xconn);

NTSTATUS smbd_do_locking(struct smb_request *req,
			 files_struct *fsp,
			 uint8_t type,
			 int32_t timeout,
			 uint16_t num_locks,
			 struct smbd_lock_element *locks,
			 bool *async);
NTSTATUS smbd_do_unlocking(struct smb_request *req,
			   files_struct *fsp,
			   uint16_t num_ulocks,
			   struct smbd_lock_element *ulocks);

NTSTATUS smbd_do_qfilepathinfo(connection_struct *conn,
			       TALLOC_CTX *mem_ctx,
			       uint16_t info_level,
			       files_struct *fsp,
			       struct smb_filename *smb_fname,
			       bool delete_pending,
			       struct timespec write_time_ts,
			       struct ea_list *ea_list,
			       int lock_data_count,
			       char *lock_data,
			       uint16_t flags2,
			       unsigned int max_data_bytes,
			       size_t *fixed_portion,
			       char **ppdata,
			       unsigned int *pdata_size);

NTSTATUS smbd_do_setfilepathinfo(connection_struct *conn,
				struct smb_request *req,
				TALLOC_CTX *mem_ctx,
				uint16_t info_level,
				files_struct *fsp,
				struct smb_filename *smb_fname,
				char **ppdata, int total_data,
				int *ret_data_size);

NTSTATUS smbd_do_qfsinfo(struct smbXsrv_connection *xconn,
			 connection_struct *conn,
			 TALLOC_CTX *mem_ctx,
			 uint16_t info_level,
			 uint16_t flags2,
			 unsigned int max_data_bytes,
			 size_t *fixed_portion,
			 struct smb_filename *smb_fname,
			 char **ppdata,
			 int *ret_data_len);

bool smbd_dirptr_get_entry(TALLOC_CTX *ctx,
			   struct dptr_struct *dirptr,
			   const char *mask,
			   uint32_t dirtype,
			   bool dont_descend,
			   bool ask_sharemode,
			   bool (*match_fn)(TALLOC_CTX *ctx,
					    void *private_data,
					    const char *dname,
					    const char *mask,
					    char **_fname),
			   bool (*mode_fn)(TALLOC_CTX *ctx,
					   void *private_data,
					   struct smb_filename *smb_fname,
					   uint32_t *_mode),
			   void *private_data,
			   char **_fname,
			   struct smb_filename **_smb_fname,
			   uint32_t *_mode,
			   long *_prev_offset);

NTSTATUS smbd_dirptr_lanman2_entry(TALLOC_CTX *ctx,
			       connection_struct *conn,
			       struct dptr_struct *dirptr,
			       uint16 flags2,
			       const char *path_mask,
			       uint32 dirtype,
			       int info_level,
			       int requires_resume_key,
			       bool dont_descend,
			       bool ask_sharemode,
			       uint8_t align,
			       bool do_pad,
			       char **ppdata,
			       char *base_data,
			       char *end_data,
			       int space_remaining,
			       bool *got_exact_match,
			       int *_last_entry_off,
			       struct ea_list *name_list);

NTSTATUS smbd_calculate_access_mask(connection_struct *conn,
				    const struct smb_filename *smb_fname,
				    bool use_privs,
				    uint32_t access_mask,
				    uint32_t *access_mask_out);

void smbd_notify_cancel_by_smbreq(const struct smb_request *smbreq);

void smbd_server_connection_terminate_ex(struct smbXsrv_connection *xconn,
					 const char *reason,
					 const char *location);
#define smbd_server_connection_terminate(xconn, reason) \
	smbd_server_connection_terminate_ex(xconn, reason, __location__)

const char *smb2_opcode_name(uint16_t opcode);
bool smbd_is_smb2_header(const uint8_t *inbuf, size_t size);

NTSTATUS smbd_add_connection(struct smbXsrv_client *client, int sock_fd,
			     struct smbXsrv_connection **_xconn);

void reply_smb2002(struct smb_request *req, uint16_t choice);
void reply_smb20ff(struct smb_request *req, uint16_t choice);
void smbd_smb2_first_negprot(struct smbXsrv_connection *xconn,
			     const uint8_t *inpdu, size_t size);

DATA_BLOB smbd_smb2_generate_outbody(struct smbd_smb2_request *req, size_t size);

NTSTATUS smbd_smb2_request_error_ex(struct smbd_smb2_request *req,
				    NTSTATUS status,
				    DATA_BLOB *info,
				    const char *location);
#define smbd_smb2_request_error(req, status) \
	smbd_smb2_request_error_ex(req, status, NULL, __location__)
NTSTATUS smbd_smb2_request_done_ex(struct smbd_smb2_request *req,
				   NTSTATUS status,
				   DATA_BLOB body, DATA_BLOB *dyn,
				   const char *location);
#define smbd_smb2_request_done(req, body, dyn) \
	smbd_smb2_request_done_ex(req, NT_STATUS_OK, body, dyn, __location__)

NTSTATUS smbd_smb2_send_oplock_break(struct smbXsrv_connection *xconn,
				     struct smbXsrv_session *session,
				     struct smbXsrv_tcon *tcon,
				     struct smbXsrv_open *op,
				     uint8_t oplock_level);
NTSTATUS smbd_smb2_send_lease_break(struct smbXsrv_connection *xconn,
				    uint16_t new_epoch,
				    uint32_t lease_flags,
				    struct smb2_lease_key *lease_key,
				    uint32_t current_lease_state,
				    uint32_t new_lease_state);

NTSTATUS smbd_smb2_request_pending_queue(struct smbd_smb2_request *req,
					 struct tevent_req *subreq,
					 uint32_t defer_time);

struct smb_request *smbd_smb2_fake_smb_request(struct smbd_smb2_request *req);
size_t smbd_smb2_unread_bytes(struct smbd_smb2_request *req);
void remove_smb2_chained_fsp(files_struct *fsp);

NTSTATUS smbd_smb2_request_verify_creditcharge(struct smbd_smb2_request *req,
					       uint32_t data_length);

NTSTATUS smbd_smb2_request_verify_sizes(struct smbd_smb2_request *req,
					size_t expected_body_size);

enum protocol_types smbd_smb2_protocol_dialect_match(const uint8_t *indyn,
		                                     const int dialect_count,
						     uint16_t *dialect);
NTSTATUS smbd_smb2_request_process_negprot(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_sesssetup(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_tcon(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_tdis(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_create(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_close(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_flush(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_read(struct smbd_smb2_request *req);
NTSTATUS smb2_read_complete(struct tevent_req *req, ssize_t nread, int err);
NTSTATUS smbd_smb2_request_process_write(struct smbd_smb2_request *req);
NTSTATUS smb2_write_complete(struct tevent_req *req, ssize_t nwritten, int err);
NTSTATUS smb2_write_complete_nosync(struct tevent_req *req, ssize_t nwritten,
				    int err);
NTSTATUS smbd_smb2_request_process_lock(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_ioctl(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_keepalive(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_find(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_notify(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_getinfo(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_setinfo(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_process_break(struct smbd_smb2_request *req);
NTSTATUS smbd_smb2_request_dispatch(struct smbd_smb2_request *req);
void smbd_smb2_request_dispatch_immediate(struct tevent_context *ctx,
				struct tevent_immediate *im,
				void *private_data);

struct deferred_open_record;

/* SMB1 -> SMB2 glue. */
void send_break_message_smb2(files_struct *fsp,
			     uint32_t break_from,
			     uint32_t break_to);
struct blocking_lock_record *get_pending_smb2req_blr(struct smbd_smb2_request *smb2req);
bool push_blocking_lock_request_smb2( struct byte_range_lock *br_lck,
				struct smb_request *req,
				files_struct *fsp,
				int lock_timeout,
				int lock_num,
				uint64_t smblctx,
				enum brl_type lock_type,
				enum brl_flavour lock_flav,
				uint64_t offset,
				uint64_t count,
				uint64_t blocking_smblctx);
void process_blocking_lock_queue_smb2(
	struct smbd_server_connection *sconn, struct timeval tv_curr);
void cancel_pending_lock_requests_by_fid_smb2(files_struct *fsp,
			struct byte_range_lock *br_lck,
			enum file_close_type close_type);
/* From smbd/smb2_create.c */
int map_smb2_oplock_levels_to_samba(uint8_t in_oplock_level);
bool get_deferred_open_message_state_smb2(struct smbd_smb2_request *smb2req,
			struct timeval *p_request_time,
			struct deferred_open_record **open_rec);
bool open_was_deferred_smb2(
	struct smbXsrv_connection *xconn, uint64_t mid);
void remove_deferred_open_message_smb2(
	struct smbXsrv_connection *xconn, uint64_t mid);
bool schedule_deferred_open_message_smb2(
	struct smbXsrv_connection *xconn, uint64_t mid);
bool push_deferred_open_message_smb2(struct smbd_smb2_request *smb2req,
                                struct timeval request_time,
                                struct timeval timeout,
				struct file_id id,
				struct deferred_open_record *open_rec);

struct smbXsrv_client;

struct smbXsrv_connection {
	struct smbXsrv_connection *prev, *next;

	struct smbXsrv_client *client;


	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;
	const char *remote_hostname;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;

	enum protocol_types protocol;

	struct {
		NTSTATUS status;
		int sock;
		struct tevent_fd *fde;

		struct {
			bool got_session;
		} nbt;
	} transport;

	struct {
		struct {
			/*
			 * fd for the fcntl lock and process shared
			 * robust mutex to coordinate access to the
			 * client socket. When the system supports
			 * process shared robust mutexes, those are
			 * used. If not, then the fcntl lock will be
			 * used.
			 */
			int socket_lock_fd;
#ifdef HAVE_ROBUST_MUTEXES
			pthread_mutex_t *socket_mutex;
#endif

			/*
			 * fd for the trusted pipe from
			 * echo handler child
			 */
			int trusted_fd;

			/*
			 * fde for the trusted_fd
			 */
			struct tevent_fd *trusted_fde;

			/*
			 * Reference count for the fcntl lock to
			 * allow recursive locks.
			 */
			int ref_count;
		} echo_handler;

		struct {
			bool encrypted_passwords;
			bool spnego;
			struct auth4_context *auth_context;
			bool done;
			/*
			 * Size of the data we can receive. Set by us.
			 * Can be modified by the max xmit parameter.
			 */
			int max_recv;
		} negprot;

		struct {
			bool done_sesssetup;
			/*
			 * Size of data we can send to client. Set
			 *  by the client for all protocols above CORE.
			 *  Set by us for CORE protocol.
			 */
			int max_send;
		} sessions;
		struct smb_signing_state *signing_state;

		struct {
			uint16_t client_major;
			uint16_t client_minor;
			uint32_t client_cap_low;
			uint32_t client_cap_high;
		} unix_info;

		struct msg_state *msg_state;
	} smb1;
	struct {
		struct smbd_smb2_request_read_state {
			struct smbd_smb2_request *req;
			struct {
				uint8_t nbt[NBT_HDR_SIZE];
				bool done;
			} hdr;
			struct iovec vector;
			bool doing_receivefile;
			size_t min_recv_size;
			size_t pktfull;
			size_t pktlen;
			uint8_t *pktbuf;
		} request_read_state;
		struct smbd_smb2_send_queue *send_queue;
		size_t send_queue_len;

		struct {
			/*
			 * seq_low is the lowest sequence number
			 * we will accept.
			 */
			uint64_t seq_low;
			/*
			 * seq_range is the range of credits we have
			 * granted from the sequence windows starting
			 * at seq_low.
			 *
			 * This gets incremented when new credits are
			 * granted and gets decremented when the
			 * lowest sequence number is consumed
			 * (when seq_low gets incremented).
			 */
			uint16_t seq_range;
			/*
			 * The number of credits we have currently granted
			 * to the client.
			 *
			 * This gets incremented when new credits are
			 * granted and gets decremented when any credit
			 * is comsumed.
			 *
			 * Note: the decrementing is different compared
			 *       to seq_range.
			 */
			uint16_t granted;
			/*
			 * The maximum number of credits we will ever
			 * grant to the client.
			 *
			 * Typically we will only grant 1/16th of
			 * max_credits.
			 *
			 * This is the "server max credits" parameter.
			 */
			uint16_t max;
			/*
			 * a bitmap of size max_credits
			 */
			struct bitmap *bitmap;
			bool multicredit;
		} credits;

		bool allow_2ff;
		struct {
			uint32_t capabilities;
			struct GUID guid;
			uint16_t security_mode;
			uint16_t num_dialects;
			uint16_t *dialects;
		} client;
		struct {
			uint32_t capabilities;
			struct GUID guid;
			uint16_t security_mode;
			uint16_t dialect;
			uint32_t max_trans;
			uint32_t max_read;
			uint32_t max_write;
		} server;

		struct smbd_smb2_request *requests;
	} smb2;
};

const char *smbXsrv_connection_dbg(const struct smbXsrv_connection *xconn);

NTSTATUS smbXsrv_version_global_init(const struct server_id *server_id);
uint32_t smbXsrv_version_global_current(void);

NTSTATUS smbXsrv_connection_init_tables(struct smbXsrv_connection *conn,
					enum protocol_types protocol);

NTSTATUS smbXsrv_session_global_init(void);
NTSTATUS smbXsrv_session_create(struct smbXsrv_connection *conn,
				NTTIME now,
				struct smbXsrv_session **_session);
NTSTATUS smbXsrv_session_update(struct smbXsrv_session *session);
struct smbXsrv_channel_global0;
NTSTATUS smbXsrv_session_find_channel(const struct smbXsrv_session *session,
				      const struct smbXsrv_connection *conn,
				      struct smbXsrv_channel_global0 **_c);
struct tevent_req *smb2srv_session_shutdown_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXsrv_session *session,
					struct smbd_smb2_request *current_req);
NTSTATUS smb2srv_session_shutdown_recv(struct tevent_req *req);
NTSTATUS smbXsrv_session_logoff(struct smbXsrv_session *session);
NTSTATUS smbXsrv_session_logoff_all(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_session_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_session_lookup(struct smbXsrv_connection *conn,
				uint16_t vuid, NTTIME now,
				struct smbXsrv_session **session);
NTSTATUS smb2srv_session_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb2srv_session_lookup(struct smbXsrv_connection *conn,
				uint64_t session_id, NTTIME now,
				struct smbXsrv_session **session);
struct smbXsrv_session_global0;
NTSTATUS smbXsrv_session_global_traverse(
			int (*fn)(struct smbXsrv_session_global0 *, void *),
			void *private_data);
struct tevent_req *smb2srv_session_close_previous_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXsrv_connection *conn,
					struct auth_session_info *session_info,
					uint64_t previous_session_id,
					uint64_t current_session_id);
NTSTATUS smb2srv_session_close_previous_recv(struct tevent_req *req);

NTSTATUS smbXsrv_tcon_global_init(void);
NTSTATUS smbXsrv_tcon_update(struct smbXsrv_tcon *tcon);
NTSTATUS smbXsrv_tcon_disconnect(struct smbXsrv_tcon *tcon, uint64_t vuid);
NTSTATUS smb1srv_tcon_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_tcon_create(struct smbXsrv_connection *conn,
			     NTTIME now,
			     struct smbXsrv_tcon **_tcon);
NTSTATUS smb1srv_tcon_lookup(struct smbXsrv_connection *conn,
			     uint16_t tree_id, NTTIME now,
			     struct smbXsrv_tcon **tcon);
NTSTATUS smb1srv_tcon_disconnect_all(struct smbXsrv_connection *conn);
NTSTATUS smb2srv_tcon_table_init(struct smbXsrv_session *session);
NTSTATUS smb2srv_tcon_create(struct smbXsrv_session *session,
			     NTTIME now,
			     struct smbXsrv_tcon **_tcon);
NTSTATUS smb2srv_tcon_lookup(struct smbXsrv_session *session,
			     uint32_t tree_id, NTTIME now,
			     struct smbXsrv_tcon **tcon);
NTSTATUS smb2srv_tcon_disconnect_all(struct smbXsrv_session *session);
struct smbXsrv_tcon_global0;
NTSTATUS smbXsrv_tcon_global_traverse(
			int (*fn)(struct smbXsrv_tcon_global0 *, void *),
			void *private_data);

NTSTATUS smbXsrv_open_global_init(void);
NTSTATUS smbXsrv_open_create(struct smbXsrv_connection *conn,
			     struct auth_session_info *session_info,
			     NTTIME now,
			     struct smbXsrv_open **_open);
uint32_t smbXsrv_open_hash(struct smbXsrv_open *_open);
NTSTATUS smbXsrv_open_update(struct smbXsrv_open *_open);
NTSTATUS smbXsrv_open_close(struct smbXsrv_open *op, NTTIME now);
NTSTATUS smb1srv_open_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb1srv_open_lookup(struct smbXsrv_connection *conn,
			     uint16_t fnum, NTTIME now,
			     struct smbXsrv_open **_open);
NTSTATUS smb2srv_open_table_init(struct smbXsrv_connection *conn);
NTSTATUS smb2srv_open_lookup(struct smbXsrv_connection *conn,
			     uint64_t persistent_id,
			     uint64_t volatile_id,
			     NTTIME now,
			     struct smbXsrv_open **_open);
NTSTATUS smb2srv_open_recreate(struct smbXsrv_connection *conn,
			       struct auth_session_info *session_info,
			       uint64_t persistent_id,
			       const struct GUID *create_guid,
			       NTTIME now,
			       struct smbXsrv_open **_open);
struct smbXsrv_open_global0;
NTSTATUS smbXsrv_open_global_traverse(
	int (*fn)(struct smbXsrv_open_global0 *, void *),
	void *private_data);

NTSTATUS smbXsrv_open_cleanup(uint64_t persistent_id);

struct smbd_smb2_send_queue {
	struct smbd_smb2_send_queue *prev, *next;

	DATA_BLOB *sendfile_header;
	NTSTATUS *sendfile_status;
	struct iovec *vector;
	int count;

	TALLOC_CTX *mem_ctx;
};

struct smbd_smb2_request {
	struct smbd_smb2_request *prev, *next;

	struct smbd_server_connection *sconn;
	struct smbXsrv_connection *xconn;

	struct smbd_smb2_send_queue queue_entry;

	/* the session the request operates on, maybe NULL */
	struct smbXsrv_session *session;
	uint64_t last_session_id;

	/* the tcon the request operates on, maybe NULL */
	struct smbXsrv_tcon *tcon;
	uint32_t last_tid;

	int current_idx;
	bool do_signing;
	bool do_encryption;
	struct tevent_timer *async_te;
	bool compound_related;

	/*
	 * the encryption key for the whole
	 * compound chain
	 */
	DATA_BLOB first_key;
	/*
	 * the signing key for the last
	 * request/response of a compound chain
	 */
	DATA_BLOB last_key;

	struct timeval request_time;

	/* fake smb1 request. */
	struct smb_request *smb1req;
	struct files_struct *compat_chain_fsp;

	/*
	 * The sub request for async backend calls.
	 * This is used for SMB2 Cancel.
	 */
	struct tevent_req *subreq;

#define SMBD_SMB2_TF_IOV_OFS 0
#define SMBD_SMB2_HDR_IOV_OFS 1
#define SMBD_SMB2_BODY_IOV_OFS 2
#define SMBD_SMB2_DYN_IOV_OFS 3

#define SMBD_SMB2_NUM_IOV_PER_REQ 4

#define SMBD_SMB2_IOV_IDX_OFS(req,dir,idx,ofs) \
	(&req->dir.vector[(idx)+(ofs)])

#define SMBD_SMB2_IDX_TF_IOV(req,dir,idx) \
	SMBD_SMB2_IOV_IDX_OFS(req,dir,idx,SMBD_SMB2_TF_IOV_OFS)
#define SMBD_SMB2_IDX_HDR_IOV(req,dir,idx) \
	SMBD_SMB2_IOV_IDX_OFS(req,dir,idx,SMBD_SMB2_HDR_IOV_OFS)
#define SMBD_SMB2_IDX_BODY_IOV(req,dir,idx) \
	SMBD_SMB2_IOV_IDX_OFS(req,dir,idx,SMBD_SMB2_BODY_IOV_OFS)
#define SMBD_SMB2_IDX_DYN_IOV(req,dir,idx) \
	SMBD_SMB2_IOV_IDX_OFS(req,dir,idx,SMBD_SMB2_DYN_IOV_OFS)

#define SMBD_SMB2_IN_TF_IOV(req)    SMBD_SMB2_IDX_TF_IOV(req,in,req->current_idx)
#define SMBD_SMB2_IN_TF_PTR(req)    (uint8_t *)(SMBD_SMB2_IN_TF_IOV(req)->iov_base)
#define SMBD_SMB2_IN_HDR_IOV(req)    SMBD_SMB2_IDX_HDR_IOV(req,in,req->current_idx)
#define SMBD_SMB2_IN_HDR_PTR(req)    (uint8_t *)(SMBD_SMB2_IN_HDR_IOV(req)->iov_base)
#define SMBD_SMB2_IN_BODY_IOV(req)   SMBD_SMB2_IDX_BODY_IOV(req,in,req->current_idx)
#define SMBD_SMB2_IN_BODY_PTR(req)   (uint8_t *)(SMBD_SMB2_IN_BODY_IOV(req)->iov_base)
#define SMBD_SMB2_IN_BODY_LEN(req)   (SMBD_SMB2_IN_BODY_IOV(req)->iov_len)
#define SMBD_SMB2_IN_DYN_IOV(req)    SMBD_SMB2_IDX_DYN_IOV(req,in,req->current_idx)
#define SMBD_SMB2_IN_DYN_PTR(req)    (uint8_t *)(SMBD_SMB2_IN_DYN_IOV(req)->iov_base)
#define SMBD_SMB2_IN_DYN_LEN(req)    (SMBD_SMB2_IN_DYN_IOV(req)->iov_len)

#define SMBD_SMB2_OUT_TF_IOV(req)   SMBD_SMB2_IDX_TF_IOV(req,out,req->current_idx)
#define SMBD_SMB2_OUT_TF_PTR(req)   (uint8_t *)(SMBD_SMB2_OUT_TF_IOV(req)->iov_base)
#define SMBD_SMB2_OUT_HDR_IOV(req)   SMBD_SMB2_IDX_HDR_IOV(req,out,req->current_idx)
#define SMBD_SMB2_OUT_HDR_PTR(req)   (uint8_t *)(SMBD_SMB2_OUT_HDR_IOV(req)->iov_base)
#define SMBD_SMB2_OUT_BODY_IOV(req)  SMBD_SMB2_IDX_BODY_IOV(req,out,req->current_idx)
#define SMBD_SMB2_OUT_BODY_PTR(req)  (uint8_t *)(SMBD_SMB2_OUT_BODY_IOV(req)->iov_base)
#define SMBD_SMB2_OUT_BODY_LEN(req)  (SMBD_SMB2_OUT_BODY_IOV(req)->iov_len)
#define SMBD_SMB2_OUT_DYN_IOV(req)   SMBD_SMB2_IDX_DYN_IOV(req,out,req->current_idx)
#define SMBD_SMB2_OUT_DYN_PTR(req)   (uint8_t *)(SMBD_SMB2_OUT_DYN_IOV(req)->iov_base)
#define SMBD_SMB2_OUT_DYN_LEN(req)   (SMBD_SMB2_OUT_DYN_IOV(req)->iov_len)

#define SMBD_SMB2_SHORT_RECEIVEFILE_WRITE_LEN (SMB2_HDR_BODY + 0x30)

	struct {
		/*
		 * vector[0] TRANSPORT HEADER (empty)
		 * .
		 * vector[1] SMB2_TRANSFORM (optional)
		 * vector[2] SMB2
		 * vector[3] fixed body
		 * vector[4] dynamic body
		 * .
		 * .
		 * .
		 * vector[5] SMB2_TRANSFORM (optional)
		 * vector[6] SMB2
		 * vector[7] fixed body
		 * vector[8] dynamic body
		 * .
		 * .
		 * .
		 */
		struct iovec *vector;
		int vector_count;
		struct iovec _vector[1 + SMBD_SMB2_NUM_IOV_PER_REQ];
	} in;
	struct {
		/* the NBT header is not allocated */
		uint8_t nbt_hdr[4];
		/*
		 * vector[0] TRANSPORT HEADER
		 * .
		 * vector[1] SMB2_TRANSFORM (optional)
		 * vector[2] SMB2
		 * vector[3] fixed body
		 * vector[4] dynamic body
		 * .
		 * .
		 * .
		 * vector[5] SMB2_TRANSFORM (empty)
		 * vector[6] SMB2
		 * vector[7] fixed body
		 * vector[8] dynamic body
		 * .
		 * .
		 * .
		 */
		struct iovec *vector;
		int vector_count;
		struct iovec _vector[1 + SMBD_SMB2_NUM_IOV_PER_REQ];
#define OUTVEC_ALLOC_SIZE (SMB2_HDR_BODY + 9)
		uint8_t _hdr[OUTVEC_ALLOC_SIZE];
		uint8_t _body[0x58];
	} out;
};

struct smbd_server_connection;
struct user_struct;

struct pending_message_list;
struct pending_auth_data;

struct user_struct {
	struct user_struct *next, *prev;
	uint64_t vuid; /* Tag for this entry. */

	char *session_keystr; /* used by utmp and pam session code.
				 TDB key string */
	int homes_snum;

	struct auth_session_info *session_info;

	struct smbXsrv_session *session;
};

struct smbd_server_connection {
	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;
	const char *remote_hostname;
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct sys_notify_context *sys_notify_ctx;
	struct notify_context *notify_ctx;
	bool using_smb2;
	int trans_num;

	size_t num_users;
	struct user_struct *users;

	size_t num_connections;
	struct connection_struct *connections;

	size_t num_files;
	struct files_struct *files;

	int real_max_open_files;
	struct fsp_singleton_cache fsp_fi_cache;

	struct pending_message_list *deferred_open_queue;


	/* open directory handles. */
	struct {
		struct bitmap *dptr_bmap;
		struct dptr_struct *dirptrs;
		int dirhandles_open;
	} searches;

	uint64_t num_requests;

	/* Current number of oplocks we have outstanding. */
	struct {
		int32_t exclusive_open;
		int32_t level_II_open;
		struct kernel_oplocks *kernel_ops;
	} oplocks;

	struct {
		struct notify_mid_map *notify_mid_maps;

		struct {
			/* dlink list we store pending lock records on. */
			struct blocking_lock_record *blocking_lock_queue;
			/* dlink list we move cancelled lock records onto. */
			struct blocking_lock_record *blocking_lock_cancelled_queue;

			/* The event that makes us process our blocking lock queue */
			struct tevent_timer *brl_timeout;

			bool blocking_lock_unlock_state;
			bool blocking_lock_cancel_state;
		} locks;
	} smb1;
	struct {
		struct {
			/* The event that makes us process our blocking lock queue */
			struct tevent_timer *brl_timeout;
			bool blocking_lock_unlock_state;
		} locks;
	} smb2;

	/*
	 * Link into libasys for asynchronous operations
	 */
	struct asys_context *asys_ctx;
	struct tevent_fd *asys_fde;

	struct smbXsrv_client *client;
};

extern struct smbXsrv_client *global_smbXsrv_client;

void smbd_init_globals(void);

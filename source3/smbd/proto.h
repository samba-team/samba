/*
 *  Unix SMB/CIFS implementation.
 *  Main SMB server routines
 *
 *  Copyright (C) Andrew Tridgell			1992-2002,2006
 *  Copyright (C) Jeremy Allison			1992-2010
 *  Copyright (C) Volker Lendecke			1993-2009
 *  Copyright (C) John H Terpstra			1995-1998
 *  Copyright (C) Luke Kenneth Casson Leighton		1996-1998
 *  Copyright (C) Paul Ashton				1997-1998
 *  Copyright (C) Tim Potter				1999-2000
 *  Copyright (C) T.D.Lee@durham.ac.uk			1999
 *  Copyright (C) Ying Chen				2000
 *  Copyright (C) Shirish Kalele			2000
 *  Copyright (C) Andrew Bartlett			2001-2003
 *  Copyright (C) Alexander Bokovoy			2002,2005
 *  Copyright (C) Simo Sorce				2001-2002,2009
 *  Copyright (C) Andreas Gruenbacher			2002
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>	2002
 *  Copyright (C) Martin Pool				2002
 *  Copyright (C) Luke Howard				2003
 *  Copyright (C) Stefan (metze) Metzmacher		2003,2009
 *  Copyright (C) Steve French				2005
 *  Copyright (C) Gerald (Jerry) Carter			2006
 *  Copyright (C) James Peach				2006-2007
 *  Copyright (C) Jelmer Vernooij			2002-2003
 *  Copyright (C) Michael Adam				2007
 *  Copyright (C) Rishi Srivatsavai			2007
 *  Copyright (C) Tim Prouty				2009
 *  Copyright (C) Gregor Beck				2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SMBD_PROTO_H_
#define _SMBD_PROTO_H_

struct smbXsrv_client;
struct smbXsrv_connection;
struct dcesrv_context;

/* The following definitions come from smbd/smb2_signing.c */

bool srv_init_signing(struct smbXsrv_connection *conn);

/* The following definitions come from smbd/aio.c  */

struct aio_extra;
bool aio_write_through_requested(struct aio_extra *aio_ex);
NTSTATUS schedule_smb2_aio_read(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				TALLOC_CTX *ctx,
				DATA_BLOB *preadbuf,
				off_t startpos,
				size_t smb_maxcnt);
NTSTATUS schedule_aio_smb2_write(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				uint64_t in_offset,
				DATA_BLOB in_data,
				bool write_through);
bool cancel_smb2_aio(struct smb_request *smbreq);
struct aio_req_fsp_link;
struct aio_req_fsp_link *aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req);
struct aio_extra *create_aio_extra(TALLOC_CTX *mem_ctx,
				   files_struct *fsp,
				   size_t buflen);
struct tevent_req *pwrite_fsync_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct files_struct *fsp,
				     const void *data,
				     size_t n, off_t offset,
				     bool write_through);
ssize_t pwrite_fsync_recv(struct tevent_req *req, int *perr);

/* The following definitions come from smbd/blocking.c  */

struct smbd_do_locks_state {
	uint16_t num_locks;
	struct smbd_lock_element *locks;
	NTSTATUS status;
	uint16_t blocker_idx;
	struct server_id blocking_pid;
	uint64_t blocking_smblctx;
};

NTSTATUS smbd_do_locks_try(struct byte_range_lock *br_lck,
			   struct smbd_do_locks_state *state);

struct tevent_req *smbd_smb1_do_locks_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smb_request **smbreq, /* talloc_move()d into our state */
	struct files_struct *fsp,
	uint32_t lock_timeout,
	bool large_offset,
	uint16_t num_locks,
	struct smbd_lock_element *locks);
NTSTATUS smbd_smb1_do_locks_recv(struct tevent_req *req);
bool smbd_smb1_do_locks_extract_smbreq(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct smb_request **psmbreq);
void smbd_smb1_brl_finish_by_req(struct tevent_req *req, NTSTATUS status);
bool smbd_smb1_brl_finish_by_lock(
	struct files_struct *fsp,
	bool large_offset,
	struct smbd_lock_element lock,
	NTSTATUS finish_status);
bool smbd_smb1_brl_finish_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid);

/* The following definitions come from smbd/close.c  */

void set_close_write_time(struct files_struct *fsp, struct timespec ts);
NTSTATUS close_file_smb(struct smb_request *req,
			struct files_struct *fsp,
			enum file_close_type close_type);
NTSTATUS close_file_free(struct smb_request *req,
			 struct files_struct **_fsp,
			 enum file_close_type close_type);
void msg_close_file(struct messaging_context *msg_ctx,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);
NTSTATUS delete_all_streams(struct files_struct *fsp,
			    struct files_struct *dirfsp,
			    struct smb_filename *fsp_atname);
NTSTATUS recursive_rmdir_fsp(struct files_struct *fsp);
bool has_other_nonposix_opens(struct share_mode_lock *lck,
			      struct files_struct *fsp);
bool has_nonposix_opens(struct share_mode_lock *lck);

/* The following definitions come from smbd/conn.c  */

int conn_num_open(struct smbd_server_connection *sconn);
bool conn_snum_used(struct smbd_server_connection *sconn, int snum);
enum protocol_types conn_protocol(struct smbd_server_connection *sconn);
bool conn_using_smb2(struct smbd_server_connection *sconn);
connection_struct *conn_new(struct smbd_server_connection *sconn);
bool conn_idle_all(struct smbd_server_connection *sconn, time_t t);
void conn_clear_vuid_caches(struct smbd_server_connection *sconn, uint64_t vuid);
void conn_free(connection_struct *conn);
void conn_setup_case_options(connection_struct *conn);
void conn_force_tdis(
	struct smbd_server_connection *sconn,
	bool (*check_fn)(struct connection_struct *conn,
			 void *private_data),
	void *private_data);
void msg_force_tdis(struct messaging_context *msg,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);
void msg_force_tdis_denied(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data);

/* The following definitions come from smbd/connection.c  */

int count_current_connections(const char *sharename, bool verify);
bool connections_snum_used(struct smbd_server_connection *unused, int snum);

/* The following definitions come from smbd/dfree.c  */

uint64_t get_dfree_info(connection_struct *conn, struct smb_filename *fname,
			uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
void flush_dfree_cache(void);

/* The following definitions come from smbd/dmapi.c  */

const void *dmapi_get_current_session(void);
bool dmapi_have_session(void);
bool dmapi_new_session(void);
bool dmapi_destroy_session(void);
uint32_t dmapi_file_flags(const char * const path);

/* The following definitions come from smbd/dnsregister.c  */

bool smbd_setup_mdns_registration(struct tevent_context *ev,
				  TALLOC_CTX *mem_ctx,
				  uint16_t port);

/* The following definitions come from smbd/dosmode.c  */

mode_t apply_conf_file_mask(struct connection_struct *conn, mode_t mode);
mode_t apply_conf_dir_mask(struct connection_struct *conn, mode_t mode);

mode_t unix_mode(connection_struct *conn, int dosmode,
		 const struct smb_filename *smb_fname,
		 struct files_struct *parent_dirfsp);
uint32_t dos_mode_msdfs(connection_struct *conn,
			const char *name,
			const struct stat_ex *st);
uint32_t fdos_mode(struct files_struct *fsp);
struct tevent_req *dos_mode_at_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    files_struct *dir_fsp,
				    struct smb_filename *smb_fname);
NTSTATUS dos_mode_at_recv(struct tevent_req *req, uint32_t *dosmode);
int file_set_dosmode(connection_struct *conn,
		     struct smb_filename *smb_fname,
		     uint32_t dosmode,
		     struct smb_filename *parent_dir,
		     bool newfile);
NTSTATUS file_set_sparse(connection_struct *conn,
			 struct files_struct *fsp,
			 bool sparse);
int file_ntimes(connection_struct *conn,
		files_struct *fsp,
		struct smb_file_time *ft);
void set_sticky_write_time_fsp(struct files_struct *fsp,
			       struct timespec mtime);

NTSTATUS fget_ea_dos_attribute(struct files_struct *fsp,
			      uint32_t *pattr);
NTSTATUS set_ea_dos_attribute(connection_struct *conn,
			      struct smb_filename *smb_fname,
			      uint32_t dosmode);

NTSTATUS set_create_timespec_ea(struct files_struct *fsp,
				struct timespec create_time);

struct timespec get_create_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname);

NTSTATUS parse_dos_attribute_blob(struct smb_filename *smb_fname,
				  DATA_BLOB blob,
				  uint32_t *pattr);

/* The following definitions come from smbd/error.c  */

bool use_nt_status(void);
void error_packet_set(char *outbuf, uint8_t eclass, uint32_t ecode, NTSTATUS ntstatus, int line, const char *file);
size_t error_packet(char *outbuf,
		    uint8_t eclass,
		    uint32_t ecode,
		    NTSTATUS ntstatus,
		    int line,
		    const char *file);
void reply_nt_error(struct smb_request *req, NTSTATUS ntstatus,
		    int line, const char *file);
void reply_force_dos_error(struct smb_request *req, uint8_t eclass, uint32_t ecode,
		    int line, const char *file);
void reply_both_error(struct smb_request *req, uint8_t eclass, uint32_t ecode,
		      NTSTATUS status, int line, const char *file);
void reply_openerror(struct smb_request *req, NTSTATUS status);

/* The following definitions come from smbd/file_access.c  */

bool can_delete_file_in_directory(connection_struct *conn,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname);
bool can_write_to_fsp(struct files_struct *fsp);
bool directory_has_default_acl_fsp(struct files_struct *fsp);
NTSTATUS can_set_delete_on_close(files_struct *fsp, uint32_t dosmode);

/* The following definitions come from smbd/fileio.c  */

ssize_t read_file(files_struct *fsp,char *data,off_t pos,size_t n);
void trigger_write_time_update_immediate(struct files_struct *fsp,
					 bool update_mtime,
					 bool update_ctime);
struct file_modified_state;
void prepare_file_modified(files_struct *fsp,
			   struct file_modified_state *state);
void mark_file_modified(files_struct *fsp,
			bool modified,
			struct file_modified_state *state);
ssize_t write_file(struct smb_request *req,
			files_struct *fsp,
			const char *data,
			off_t pos,
			size_t n);
NTSTATUS sync_file(connection_struct *conn, files_struct *fsp, bool write_through);

/* The following definitions come from smbd/filename.c  */

uint32_t ucf_flags_from_smb_request(struct smb_request *req);
uint32_t filename_create_ucf_flags(struct smb_request *req,
				   uint32_t create_disposition,
				   uint32_t create_options);
NTSTATUS canonicalize_snapshot_path(struct smb_filename *smb_fname,
				    uint32_t ucf_flags,
				    NTTIME twrp);
NTSTATUS get_real_filename_full_scan_at(struct files_struct *dirfsp,
					const char *name,
					bool mangled,
					TALLOC_CTX *mem_ctx,
					char **found_name);
char *get_original_lcomp(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *filename_in,
			uint32_t ucf_flags);
NTSTATUS get_real_filename_at(struct files_struct *dirfsp,
			      const char *name,
			      TALLOC_CTX *mem_ctx,
			      char **found_name);

/* The following definitions come from smbd/files.c  */

NTSTATUS fsp_new(struct connection_struct *conn, TALLOC_CTX *mem_ctx,
		 files_struct **result);
void fsp_set_gen_id(files_struct *fsp);
NTSTATUS file_new(struct smb_request *req, connection_struct *conn,
		  files_struct **result);
NTSTATUS fsp_bind_smb(struct files_struct *fsp, struct smb_request *req);
void file_close_conn(connection_struct *conn, enum file_close_type close_type);
bool file_init_global(void);
bool file_init(struct smbd_server_connection *sconn);
void file_close_user(struct smbd_server_connection *sconn, uint64_t vuid);
struct files_struct *files_forall(
	struct smbd_server_connection *sconn,
	struct files_struct *(*fn)(struct files_struct *fsp,
				   void *private_data),
	void *private_data);
files_struct *file_find_fd(struct smbd_server_connection *sconn, int fd);
files_struct *file_find_dif(struct smbd_server_connection *sconn,
			    struct file_id id, unsigned long gen_id);
files_struct *file_find_di_first(struct smbd_server_connection *sconn,
				 struct file_id id,
				 bool need_fsa);
files_struct *file_find_di_next(files_struct *start_fsp,
				 bool need_fsa);
struct files_struct *file_find_one_fsp_from_lease_key(
	struct smbd_server_connection *sconn,
	const struct smb2_lease_key *lease_key);
bool file_find_subpath(files_struct *dir_fsp);
void fsp_unbind_smb(struct smb_request *req, files_struct *fsp);
void file_free(struct smb_request *req, files_struct *fsp);
files_struct *file_fsp(struct smb_request *req, uint16_t fid);
struct files_struct *file_fsp_get(struct smbd_smb2_request *smb2req,
				  uint64_t persistent_id,
				  uint64_t volatile_id);
struct files_struct *file_fsp_smb2(struct smbd_smb2_request *smb2req,
				   uint64_t persistent_id,
				   uint64_t volatile_id);
NTSTATUS file_name_hash(connection_struct *conn,
			const char *name, uint32_t *p_name_hash);
NTSTATUS fsp_set_smb_fname(struct files_struct *fsp,
			   const struct smb_filename *smb_fname_in);
size_t fsp_fullbasepath(struct files_struct *fsp, char *buf, size_t buflen);
void fsp_set_base_fsp(struct files_struct *fsp, struct files_struct *base_fsp);
bool fsp_is_alternate_stream(const struct files_struct *fsp);
struct files_struct *metadata_fsp(struct files_struct *fsp);
bool fsp_search_ask_sharemode(struct files_struct *fsp);
bool fsp_getinfo_ask_sharemode(struct files_struct *fsp);

NTSTATUS create_internal_fsp(connection_struct *conn,
			     const struct smb_filename *smb_fname,
			     struct files_struct **_fsp);
NTSTATUS create_internal_dirfsp(connection_struct *conn,
				const struct smb_filename *smb_dname,
				struct files_struct **_fsp);

NTSTATUS open_internal_dirfsp(connection_struct *conn,
			      const struct smb_filename *smb_dname,
			      int open_flags,
			      struct files_struct **_fsp);

NTSTATUS open_rootdir_pathref_fsp(connection_struct *conn,
				  struct files_struct **_fsp);
NTSTATUS openat_pathref_fsp(const struct files_struct *dirfsp,
			    struct smb_filename *smb_fname);
NTSTATUS open_stream_pathref_fsp(
	struct files_struct **_base_fsp,
	struct smb_filename *smb_fname);

struct reparse_data_buffer;

NTSTATUS openat_pathref_fsp_nosymlink(
	TALLOC_CTX *mem_ctx,
	struct connection_struct *conn,
	struct files_struct *dirfsp,
	const char *path_in,
	NTTIME twrp,
	bool posix,
	struct smb_filename **_smb_fname,
	struct reparse_data_buffer **_symlink_err);
NTSTATUS openat_pathref_fsp_lcomp(struct files_struct *dirfsp,
				  struct smb_filename *smb_fname_rel,
				  uint32_t ucf_flags);
NTSTATUS readlink_talloc(
	TALLOC_CTX *mem_ctx,
	struct files_struct *dirfsp,
	struct smb_filename *smb_relname,
	char **_substitute);

NTSTATUS read_symlink_reparse(TALLOC_CTX *mem_ctx,
			      struct files_struct *dirfsp,
			      struct smb_filename *smb_relname,
			      struct reparse_data_buffer **_reparse);

void smb_fname_fsp_unlink(struct smb_filename *smb_fname);

NTSTATUS move_smb_fname_fsp_link(struct smb_filename *smb_fname_dst,
				 struct smb_filename *smb_fname_src);

NTSTATUS reference_smb_fname_fsp_link(struct smb_filename *smb_fname_dst,
				      const struct smb_filename *smb_fname_src);

NTSTATUS synthetic_pathref(TALLOC_CTX *mem_ctx,
			   const struct files_struct *dirfsp,
			   const char *base_name,
			   const char *stream_name,
			   const SMB_STRUCT_STAT *psbuf,
			   NTTIME twrp,
			   uint32_t flags,
			   struct smb_filename **_smb_fname);

NTSTATUS parent_pathref(TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			struct smb_filename **_parent,
			struct smb_filename **_atname);

void fsp_apply_private_ntcreatex_flags(struct files_struct *fsp,
				       uint32_t flags);

/* The following definitions come from smbd/smb2_ipc.c  */

NTSTATUS nt_status_np_pipe(NTSTATUS status);

/* The following definitions come from smbd/mangle.c  */

void mangle_reset_cache(void);
void mangle_change_to_posix(void);
bool mangle_is_mangled(const char *s, const struct share_params *p);
bool mangle_is_8_3(const char *fname, bool check_case,
		   const struct share_params *p);
bool mangle_is_8_3_wildcards(const char *fname, bool check_case,
			     const struct share_params *p);
bool mangle_must_mangle(const char *fname,
		   const struct share_params *p);
bool mangle_lookup_name_from_8_3(TALLOC_CTX *ctx,
			const char *in,
			char **out, /* talloced on the given context. */
			const struct share_params *p);
bool name_to_8_3(const char *in,
		char out[13],
		bool cache83,
		const struct share_params *p);

/* The following definitions come from smbd/mangle_hash.c  */

const struct mangle_fns *mangle_hash_init(void);

/* The following definitions come from smbd/mangle_hash2.c  */

const struct mangle_fns *mangle_hash2_init(void);
const struct mangle_fns *posix_mangle_init(void);

/* The following definitions come from smbd/msdfs.c  */

bool parse_msdfs_symlink(TALLOC_CTX *ctx,
			bool shuffle_referrals,
			const char *target,
			struct referral **preflist,
			size_t *refcount);
bool is_msdfs_link(struct files_struct *dirfsp,
		   struct smb_filename *smb_fname);
struct junction_map;
NTSTATUS get_referred_path(TALLOC_CTX *ctx,
			   struct auth_session_info *session_info,
			   const char *dfs_path,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   struct junction_map *jucn,
			   size_t *consumedcntp,
			   bool *self_referralp);
int setup_dfs_referral(connection_struct *orig_conn,
			const char *dfs_path,
			int max_referral_level,
			char **ppdata, NTSTATUS *pstatus);
bool create_junction(TALLOC_CTX *ctx,
		const char *dfs_path,
		struct junction_map *jucn);
struct referral;
char *msdfs_link_string(TALLOC_CTX *ctx,
		const struct referral *reflist,
		size_t referral_count);
bool create_msdfs_link(const struct junction_map *jucn,
		       struct auth_session_info *session_info);
bool remove_msdfs_link(const struct junction_map *jucn,
		       struct auth_session_info *session_info);

struct junction_map *enum_msdfs_links(TALLOC_CTX *ctx,
				      struct auth_session_info *session_info,
				      size_t *p_num_jn);
struct connection_struct;
struct smb_filename;

NTSTATUS create_conn_struct_cwd(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct messaging_context *msg,
				const struct auth_session_info *session_info,
				int snum,
				const char *path,
				struct connection_struct **c);
struct conn_struct_tos {
	struct connection_struct *conn;
	struct smb_filename *oldcwd_fname;
};
NTSTATUS create_conn_struct_tos(struct messaging_context *msg,
				int snum,
				const char *path,
				const struct auth_session_info *session_info,
				struct conn_struct_tos **_c);
NTSTATUS create_conn_struct_tos_cwd(struct messaging_context *msg,
				    int snum,
				    const char *path,
				    const struct auth_session_info *session_info,
				    struct conn_struct_tos **_c);

/* The following definitions come from smbd/notify.c  */

bool change_notify_fsp_has_changes(struct files_struct *fsp);
void change_notify_reply(struct smb_request *req,
			 NTSTATUS error_code,
			 uint32_t max_param,
			 struct notify_change_buf *notify_buf,
			 void (*reply_fn)(struct smb_request *req,
					  NTSTATUS error_code,
					  uint8_t *buf, size_t len));
void notify_callback(struct smbd_server_connection *sconn,
		     void *private_data, struct timespec when,
		     const struct notify_event *e);
NTSTATUS change_notify_create(struct files_struct *fsp,
			      uint32_t max_buffer_size,
			      uint32_t filter,
			      bool recursive);
NTSTATUS change_notify_add_request(struct smb_request *req,
				uint32_t max_param,
				uint32_t filter, bool recursive,
				struct files_struct *fsp,
				void (*reply_fn)(struct smb_request *req,
					NTSTATUS error_code,
					uint8_t *buf, size_t len));
void smbd_notify_cancel_deleted(struct messaging_context *msg,
				void *private_data, uint32_t msg_type,
				struct server_id server_id, DATA_BLOB *data);
void smbd_notifyd_restarted(struct messaging_context *msg,
			    void *private_data, uint32_t msg_type,
			    struct server_id server_id, DATA_BLOB *data);
bool remove_pending_change_notify_requests_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid);
void remove_pending_change_notify_requests_by_fid(files_struct *fsp,
						  NTSTATUS status);
void notify_fname(struct connection_struct *conn,
		  uint32_t action,
		  uint32_t filter,
		  const struct smb_filename *smb_fname,
		  const struct smb2_lease *lease);
char *notify_filter_string(TALLOC_CTX *mem_ctx, uint32_t filter);
struct sys_notify_context *sys_notify_context_create(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev);

/* The following definitions come from smbd/notify_inotify.c  */

int inotify_watch(TALLOC_CTX *mem_ctx,
		  struct sys_notify_context *ctx,
		  const char *path,
		  uint32_t *filter,
		  uint32_t *subdir_filter,
		  void (*callback)(struct sys_notify_context *ctx,
				   void *private_data,
				   struct notify_event *ev,
				   uint32_t filter),
		  void *private_data,
		  void *handle_p);

int fam_watch(TALLOC_CTX *mem_ctx,
	      struct sys_notify_context *ctx,
	      const char *path,
	      uint32_t *filter,
	      uint32_t *subdir_filter,
	      void (*callback)(struct sys_notify_context *ctx,
			       void *private_data,
			       struct notify_event *ev,
			       uint32_t filter),
	      void *private_data,
	      void *handle_p);


/* The following definitions come from smbd/notify_internal.c  */

struct notify_context *notify_init(
	TALLOC_CTX *mem_ctx, struct messaging_context *msg,
	struct smbd_server_connection *sconn,
	void (*callback)(struct smbd_server_connection *sconn,
			 void *, struct timespec,
			 const struct notify_event *));
NTSTATUS notify_add(struct notify_context *ctx,
		    const char *path, uint32_t filter, uint32_t subdir_filter,
		    void *private_data);
NTSTATUS notify_remove(struct notify_context *ctx, void *private_data,
		       char *path);
void notify_trigger(struct notify_context *notify,
		    uint32_t action, uint32_t filter,
		    const char *dir, const char *path);

/* The following definitions come from smbd/ntquotas.c  */

NTSTATUS vfs_get_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype,
			 struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_set_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_get_user_ntquota_list(files_struct *fsp, SMB_NTQUOTA_LIST **qt_list);
void *init_quota_handle(TALLOC_CTX *mem_ctx);

/* The following definitions come from smbd/smb2_nttrans.c  */

NTSTATUS set_sd(files_struct *fsp, struct security_descriptor *psd,
                       uint32_t security_info_sent);
NTSTATUS set_sd_blob(files_struct *fsp, uint8_t *data, uint32_t sd_len,
                       uint32_t security_info_sent);
NTSTATUS copy_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct files_struct *src_dirfsp,
			struct smb_filename *smb_fname_src,
			struct files_struct *dst_dirfsp,
			struct smb_filename *smb_fname_dst,
			uint32_t attrs);
NTSTATUS smbd_do_query_security_desc(connection_struct *conn,
					TALLOC_CTX *mem_ctx,
					files_struct *fsp,
					uint32_t security_info_wanted,
					uint32_t max_data_count,
					uint8_t **ppmarshalled_sd,
					size_t *psd_size);
#ifdef HAVE_SYS_QUOTAS

struct smb2_query_quota_info;

NTSTATUS smbd_do_query_getinfo_quota(TALLOC_CTX *mem_ctx,
				     files_struct *fsp,
				     bool restart_scan,
				     bool return_single,
				     uint32_t sid_list_length,
				     DATA_BLOB *sidbuffer,
				     uint32_t max_data_count,
				     uint8_t **p_data,
				     uint32_t *p_data_size);
#endif

/* The following definitions come from smbd/open.c  */

NTSTATUS smbd_check_access_rights_fsp(struct files_struct *dirfsp,
				      struct files_struct *fsp,
				      bool use_privs,
				      uint32_t access_mask);
NTSTATUS check_parent_access_fsp(struct files_struct *fsp,
				uint32_t access_mask);
bool smbd_is_tmpname(const char *n, int *_unlink_flags);
NTSTATUS fd_openat(const struct files_struct *dirfsp,
		   struct smb_filename *smb_fname,
		   files_struct *fsp,
		   const struct vfs_open_how *how);
NTSTATUS fd_close(files_struct *fsp);
NTSTATUS reopen_from_fsp(struct files_struct *dirfsp,
			 struct smb_filename *smb_fname,
			 struct files_struct *fsp,
			 const struct vfs_open_how *how,
			 bool *p_file_created);
bool is_oplock_stat_open(uint32_t access_mask);
bool is_lease_stat_open(uint32_t access_mask);
NTSTATUS send_break_message(struct messaging_context *msg_ctx,
			    const struct file_id *id,
			    const struct share_mode_entry *exclusive,
			    uint16_t break_to);
struct deferred_open_record;
bool is_deferred_open_async(const struct deferred_open_record *rec);
bool defer_smb1_sharing_violation(struct smb_request *req);
NTSTATUS create_directory(connection_struct *conn,
			  struct smb_request *req,
			  struct files_struct *dirfsp,
			  struct smb_filename *smb_dname);
void msg_file_was_renamed(struct messaging_context *msg,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id server_id,
			  DATA_BLOB *data);
struct fsp_lease *find_fsp_lease(struct files_struct *new_fsp,
				 const struct smb2_lease_key *key,
				 uint32_t current_state,
				 uint16_t lease_version,
				 uint16_t lease_epoch);
NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     struct files_struct *dirfsp,
			     struct smb_filename * smb_fname,
			     uint32_t access_mask,
			     uint32_t share_access,
			     uint32_t create_disposition,
			     uint32_t create_options,
			     uint32_t file_attributes,
			     uint32_t oplock_request,
			     const struct smb2_lease *lease,
			     uint64_t allocation_size,
			     uint32_t private_flags,
			     struct security_descriptor *sd,
			     struct ea_list *ea_list,
			     files_struct **result,
			     int *pinfo,
			     const struct smb2_create_blobs *in_context_blobs,
			     struct smb2_create_blobs *out_context_blobs);

/* The following definitions come from smbd/oplock.c  */

uint32_t get_lease_type(struct share_mode_entry *e, struct file_id id);

void break_kernel_oplock(struct messaging_context *msg_ctx, files_struct *fsp);
NTSTATUS set_file_oplock(files_struct *fsp);
void release_file_oplock(files_struct *fsp);
bool remove_oplock(files_struct *fsp);
bool downgrade_oplock(files_struct *fsp);
bool fsp_lease_update(struct files_struct *fsp);
const struct smb2_lease *fsp_get_smb2_lease(const struct files_struct *fsp);
NTSTATUS downgrade_lease(struct smbXsrv_client *client,
			uint32_t num_file_ids,
			const struct file_id *ids,
			const struct smb2_lease_key *key,
			uint32_t lease_state);
void contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type);
void contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type);
void smbd_contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type);
void smbd_contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type);
void contend_dirleases(struct connection_struct *conn,
		       const struct smb_filename *smb_fname,
		       const struct smb2_lease *lease);
bool init_oplocks(struct smbd_server_connection *sconn);
void init_kernel_oplocks(struct smbd_server_connection *sconn);

/* The following definitions come from smbd/oplock_linux.c  */

int linux_set_lease_sighandler(int fd);
int linux_setlease(int fd, int leasetype);
struct kernel_oplocks *linux_init_kernel_oplocks(struct smbd_server_connection *sconn);

/* The following definitions come from smbd/password.c  */

void invalidate_vuid(struct smbd_server_connection *sconn, uint64_t vuid);
int register_homes_share(const char *username);

/* The following definitions come from smbd/pipes.c  */

NTSTATUS open_np_file(struct smb_request *smb_req, const char *name,
		      struct files_struct **pfsp);

/* The following definitions come from smbd/posix_acls.c  */

mode_t unix_perms_to_acl_perms(mode_t mode, int r_mask, int w_mask, int x_mask);
int map_acl_perms_to_permset(mode_t mode, SMB_ACL_PERMSET_T *p_permset);
uint32_t map_canon_ace_perms(int snum,
                                enum security_ace_type *pacl_type,
                                mode_t perms,
                                bool directory_ace);
bool current_user_in_group(connection_struct *conn, gid_t gid);
SMB_ACL_T free_empty_sys_acl(connection_struct *conn, SMB_ACL_T the_acl);
NTSTATUS posix_fget_nt_acl(struct files_struct *fsp, uint32_t security_info,
			   TALLOC_CTX *mem_ctx,
			   struct security_descriptor **ppdesc);
NTSTATUS chown_if_needed(files_struct *fsp, uint32_t security_info_sent,
			 const struct security_descriptor *psd,
			 bool *did_chown);
NTSTATUS set_nt_acl(files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd);
int get_acl_group_bits(connection_struct *conn,
		       struct files_struct *fsp,
		       mode_t *mode);
int inherit_access_posix_acl(connection_struct *conn,
			     struct files_struct *inherit_from_dirfsp,
			     const struct smb_filename *smb_fname,
			     mode_t mode);
NTSTATUS set_unix_posix_default_acl(connection_struct *conn,
				files_struct *fsp,
				uint16_t num_def_acls, const char *pdata);
NTSTATUS set_unix_posix_acl(connection_struct *conn, files_struct *fsp,
				uint16_t num_acls,
				const char *pdata);
int posix_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob);
int posix_sys_acl_blob_get_fd(vfs_handle_struct *handle,
			      files_struct *fsp,
			      TALLOC_CTX *mem_ctx,
			      char **blob_description,
			      DATA_BLOB *blob);

enum default_acl_style {DEFAULT_ACL_POSIX, DEFAULT_ACL_WINDOWS, DEFAULT_ACL_EVERYONE};

const struct enum_list *get_default_acl_style_list(void);

NTSTATUS make_default_filesystem_acl(
	TALLOC_CTX *ctx,
	enum default_acl_style acl_style,
	const char *name,
	const SMB_STRUCT_STAT *psbuf,
	struct security_descriptor **ppdesc);

/* The following definitions come from smbd/smb2_process.c  */

#if !defined(WITH_SMB1SERVER)
bool smb1_srv_send(struct smbXsrv_connection *xconn,
		   char *buffer,
		   bool do_signing,
		   uint32_t seqnum,
		   bool do_encrypt);
#endif
size_t srv_smb1_set_message(char *buf,
		       size_t num_words,
		       size_t num_bytes,
		       bool zero);
NTSTATUS read_packet_remainder(int fd, char *buffer,
			       unsigned int timeout, ssize_t len);
NTSTATUS receive_smb_talloc(TALLOC_CTX *mem_ctx,
			    struct smbXsrv_connection *xconn,
			    int sock,
			    char **buffer, unsigned int timeout,
			    size_t *p_unread, bool *p_encrypted,
			    size_t *p_len,
			    uint32_t *seqnum,
			    bool trusted_channel);
void remove_deferred_open_message_smb(struct smbXsrv_connection *xconn,
				      uint64_t mid);
bool schedule_deferred_open_message_smb(struct smbXsrv_connection *xconn,
					uint64_t mid);
bool open_was_deferred(struct smbXsrv_connection *xconn, uint64_t mid);
bool get_deferred_open_message_state(struct smb_request *smbreq,
				struct timeval *p_request_time,
				struct deferred_open_record **open_rec);
bool push_deferred_open_message_smb(struct smb_request *req,
				    struct timeval timeout,
				    struct file_id id,
				    struct deferred_open_record *open_rec);
bool create_smb1_outbuf(TALLOC_CTX *mem_ctx, struct smb_request *req,
                   const uint8_t *inbuf, char **outbuf,
                   uint8_t num_words, uint32_t num_bytes);
void construct_smb1_reply_common_req(struct smb_request *req, char *outbuf);
void reply_smb1_outbuf(struct smb_request *req, uint8_t num_words, uint32_t num_bytes);
void process_smb(struct smbXsrv_connection *xconn,
		 uint8_t *inbuf,
		 size_t nread,
		 size_t unread_bytes,
		 uint32_t seqnum,
		 bool encrypted);
void smbd_process(struct tevent_context *ev_ctx,
		  struct messaging_context *msg_ctx,
		  int sock_fd,
		  bool interactive,
		  enum smb_transport_type transport_type);
bool valid_smb1_header(const uint8_t *inbuf);
bool init_smb1_request(struct smb_request *req,
		      struct smbd_server_connection *sconn,
		      struct smbXsrv_connection *xconn,
		      const uint8_t *inbuf,
		      size_t unread_bytes, bool encrypted,
		      uint32_t seqnum);

/* The following definitions come from smbd/quotas.c  */

bool disk_quotas(connection_struct *conn, struct smb_filename *fname,
		 uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);

/* The following definitions come from smbd/smb2_reply.c  */

NTSTATUS check_path_syntax(char *path, bool posix);
NTSTATUS smb1_strip_dfs_path(TALLOC_CTX *mem_ctx,
			     uint32_t *ucf_flags,
			     char **in_path);
NTSTATUS smb2_strip_dfs_path(const char *in_path, const char **out_path);
size_t srvstr_get_path(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err);
size_t srvstr_get_path_posix(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err);
size_t srvstr_get_path_req(TALLOC_CTX *mem_ctx, struct smb_request *req,
			   char **pp_dest, const char *src, int flags,
			   NTSTATUS *err);
size_t srvstr_pull_req_talloc(TALLOC_CTX *ctx, struct smb_request *req,
			      char **dest, const uint8_t *src, int flags);
bool check_fsp_open(connection_struct *conn, struct smb_request *req,
		    files_struct *fsp);
bool check_fsp(connection_struct *conn, struct smb_request *req,
	       files_struct *fsp);
bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp);
void reply_special(struct smbXsrv_connection *xconn, char *inbuf, size_t inbuf_size);
NTSTATUS unlink_internals(connection_struct *conn,
			struct smb_request *req,
			uint32_t dirtype,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname);
ssize_t fake_sendfile(struct smbXsrv_connection *xconn, files_struct *fsp,
		      off_t startpos, size_t nread);
ssize_t sendfile_short_send(struct smbXsrv_connection *xconn,
			    files_struct *fsp,
			    ssize_t nread,
			    size_t headersize,
			    size_t smb_maxcnt);
NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			struct share_mode_lock **lck,
			struct smb_filename *smb_fname_dst_in,
			const char *dst_original_lcomp,
			uint32_t attrs,
			bool replace_if_exists);
NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct files_struct *src_dirfsp,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			const char *dst_original_lcomp,
			uint32_t attrs,
			bool replace_if_exists,
			uint32_t access_mask);
NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			uint32_t new_create_disposition);
uint64_t get_lock_offset(const uint8_t *data, int data_offset,
			 bool large_file_format);

/* The following definitions come from smbd/seal.c  */

bool is_encrypted_packet(const uint8_t *inbuf);
void srv_free_enc_buffer(struct smbXsrv_connection *xconn, char *buf);
NTSTATUS srv_decrypt_buffer(struct smbXsrv_connection *xconn, char *buf);
NTSTATUS srv_encrypt_buffer(struct smbXsrv_connection *xconn, char *buf,
			    char **buf_out);
NTSTATUS srv_request_encryption_setup(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size);
NTSTATUS srv_encryption_start(connection_struct *conn);
void server_encryption_shutdown(struct smbXsrv_connection *xconn);

/* The following definitions come from smbd/sec_ctx.c  */

bool unix_token_equal(const struct security_unix_token *t1, const struct security_unix_token *t2);
bool push_sec_ctx(void);
void set_sec_ctx(uid_t uid, gid_t gid, int ngroups, gid_t *groups, const struct security_token *token);
void set_root_sec_ctx(void);
bool pop_sec_ctx(void);
void init_sec_ctx(void);
const struct security_token *sec_ctx_active_token(void);

/* The following definitions come from smbd/server.c  */

struct memcache *smbd_memcache(void);
bool snum_is_shared_printer(int snum);
void delete_and_reload_printers(void);
bool reload_services(struct smbd_server_connection *sconn,
		     bool (*snumused) (struct smbd_server_connection *, int),
		     bool test);

/* The following definitions come from smbd/server_exit.c  */

void smbd_exit_server(const char *reason) _NORETURN_;
void smbd_exit_server_cleanly(const char *const reason) _NORETURN_;

/* The following definitions come from smbd/smb2_service.c  */

bool set_conn_connectpath(connection_struct *conn, const char *connectpath);
bool canonicalize_connect_path(connection_struct *conn);
NTSTATUS set_conn_force_user_group(connection_struct *conn, int snum);
bool chdir_current_service(connection_struct *conn);
void load_registry_shares(void);
int add_home_service(const char *service, const char *username, const char *homedir);
int find_service(TALLOC_CTX *ctx, const char *service, char **p_service_out);
connection_struct *make_connection_smb2(struct smbd_smb2_request *req,
					struct smbXsrv_tcon *tcon,
					int snum,
					const char *pdev,
					NTSTATUS *pstatus);
NTSTATUS make_connection_snum(struct smbXsrv_connection *xconn,
			      connection_struct *conn,
			      int snum,
			      struct smbXsrv_session *session,
			      const char *pdev);
void close_cnum(connection_struct *conn,
		uint64_t vuid,
		enum file_close_type close_type);

/* The following definitions come from smbd/session.c  */
struct sessionid;
struct smbXsrv_session;
bool session_init(void);
bool session_claim(struct smbXsrv_session *session);
void session_yield(struct smbXsrv_session *session);
int list_sessions(TALLOC_CTX *mem_ctx, struct sessionid **session_list);
int find_sessions(TALLOC_CTX *mem_ctx, const char *username,
		  const char *machine, struct sessionid **session_list);

/* The following definitions come from smbd/share_access.c  */

bool token_contains_name_in_list(const char *username,
				 const char *domain,
				 const char *sharename,
				 const struct security_token *token,
				 const char **list,
				 bool *match);
bool user_ok_token(const char *username, const char *domain,
		   const struct security_token *token, int snum);
bool is_share_read_only_for_token(const char *username,
				  const char *domain,
				  const struct security_token *token,
				  connection_struct *conn,
				  bool *_read_only);

/* The following definitions come from smbd/srvstr.c  */

NTSTATUS srvstr_push_fn(const char *base_ptr, uint16_t smb_flags2, void *dest,
		      const char *src, int dest_len, int flags, size_t *ret_len);

/* The following definitions come from smbd/statvfs.c  */

int sys_statvfs(const char *path, struct vfs_statvfs_struct *statbuf);

/* The following definitions come from smbd/trans2.c  */

char *store_file_unix_basic(connection_struct *conn,
			    char *pdata,
			    files_struct *fsp,
			    const SMB_STRUCT_STAT *psbuf);
char *store_file_unix_basic_info2(connection_struct *conn,
				  char *pdata,
				  files_struct *fsp,
				  const SMB_STRUCT_STAT *psbuf);
NTSTATUS smb_check_file_disposition_info(struct files_struct *fsp,
					 const char *data,
					 int total_data,
					 bool *_delete_on_close);
NTSTATUS smb_set_file_disposition_info(connection_struct *conn,
				       const char *pdata,
				       int total_data,
				       files_struct *fsp,
				       struct smb_filename *smb_fname);
bool refuse_symlink_fsp(const struct files_struct *fsp);
NTSTATUS check_any_access_fsp(struct files_struct *fsp,
			      uint32_t access_requested);
uint64_t smb_roundup(connection_struct *conn, uint64_t val);
bool samba_private_attr_name(const char *unix_ea_name);
int get_ea_value_fsp(TALLOC_CTX *mem_ctx,
		     files_struct *fsp,
		     const char *ea_name,
		     struct ea_struct *pea);
NTSTATUS get_ea_names_from_fsp(TALLOC_CTX *mem_ctx,
			files_struct *fsp,
			char ***pnames,
			size_t *pnum_names);
NTSTATUS set_ea(connection_struct *conn, files_struct *fsp,
		struct ea_list *ea_list);
unsigned char *create_volume_objectid(connection_struct *conn, unsigned char objid[16]);
NTSTATUS hardlink_internals(TALLOC_CTX *ctx,
		connection_struct *conn,
		struct smb_request *req,
		bool overwrite_if_exists,
		const struct smb_filename *smb_fname_old,
		struct smb_filename *smb_fname_new);
NTSTATUS smb_set_file_time(connection_struct *conn,
			   files_struct *fsp,
			   struct smb_filename *smb_fname,
			   struct smb_file_time *ft,
			   bool setting_write_time);
NTSTATUS smb_set_file_size(connection_struct *conn,
			   struct smb_request *req,
			   files_struct *fsp,
			   struct smb_filename *smb_fname,
			   const SMB_STRUCT_STAT *psbuf,
			   off_t size,
			   bool fail_after_createfile);

bool map_info2_flags_to_sbuf(const SMB_STRUCT_STAT *psbuf,
			     const uint32_t smb_fflags,
			     const uint32_t smb_fmask,
			     int *stat_fflags);

NTSTATUS unix_perms_from_wire(connection_struct *conn,
			      const SMB_STRUCT_STAT *psbuf,
			      uint32_t perms,
			      mode_t *ret_perms);
struct ea_list *read_ea_list(TALLOC_CTX *ctx, const char *pdata,
			     size_t data_size);
unsigned int estimate_ea_size(files_struct *fsp);
NTSTATUS smb_set_fsquota(connection_struct *conn,
			 struct smb_request *req,
			 files_struct *fsp,
			 const DATA_BLOB *qdata);

NTSTATUS smb2_parse_file_rename_information(TALLOC_CTX *ctx,
					    struct connection_struct *conn,
					    struct smb_request *req,
					    const char *pdata,
					    int total_data,
					    files_struct *fsp,
					    struct smb_filename *smb_fname_src,
					    bool *overwrite,
					    struct files_struct **_dst_dirfsp,
					    struct smb_filename **_smb_fname_dst,
					    char **_dst_original_lcomp);

/* The following definitions come from smbd/uid.c  */

bool change_to_guest(void);
NTSTATUS check_user_share_access(connection_struct *conn,
				const struct auth_session_info *session_info,
				uint32_t *p_share_access,
				bool *p_readonly_share);
bool change_to_user_and_service(connection_struct *conn, uint64_t vuid);
bool change_to_user_and_service_by_fsp(struct files_struct *fsp);
bool smbd_change_to_root_user(void);
bool smbd_become_authenticated_pipe_user(struct auth_session_info *session_info);
bool smbd_unbecome_authenticated_pipe_user(void);
void become_root(void);
void unbecome_root(void);
void smbd_become_root(void);
void smbd_unbecome_root(void);
bool become_user_without_service(connection_struct *conn, uint64_t vuid);
bool become_user_without_service_by_fsp(struct files_struct *fsp);
bool become_user_without_service_by_session(connection_struct *conn,
			    const struct auth_session_info *session_info);
bool unbecome_user_without_service(void);
uid_t get_current_uid(connection_struct *conn);
gid_t get_current_gid(connection_struct *conn);
const struct security_unix_token *get_current_utok(connection_struct *conn);
const struct security_token *get_current_nttok(connection_struct *conn);

/* The following definitions come from smbd/utmp.c  */

void sys_utmp_claim(const char *username, const char *hostname,
		    const char *id_str, int id_num);
void sys_utmp_yield(const char *username, const char *hostname,
		    const char *id_str, int id_num);

/* The following definitions come from smbd/vfs.c  */

bool vfs_init_custom(connection_struct *conn, const char *vfs_object);
bool smbd_vfs_init(connection_struct *conn);
bool vfs_valid_pread_range(off_t offset, size_t length);
bool vfs_valid_pwrite_range(const struct files_struct *fsp,
			    off_t offset,
			    size_t length);
bool vfs_valid_allocation_range(off_t offset, size_t length);
ssize_t vfs_pwrite_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N,
			off_t offset);
int vfs_allocate_file_space(files_struct *fsp, uint64_t len);
int vfs_set_filelen(files_struct *fsp, off_t len);
int vfs_slow_fallocate(files_struct *fsp, off_t offset, off_t len);
int vfs_fill_sparse(files_struct *fsp, off_t len);
int vfs_set_blocking(files_struct *fsp, bool set);
off_t vfs_transfer_file(files_struct *in, files_struct *out, off_t n);
const char *vfs_readdirname(connection_struct *conn,
			    struct files_struct *dirfsp,
			    DIR *d,
			    char **talloced);
int vfs_ChDir(connection_struct *conn,
			const struct smb_filename *smb_fname);
struct smb_filename *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn);
int vfs_stat(struct connection_struct *conn,
	     struct smb_filename *smb_fname);
int vfs_stat_smb_basename(struct connection_struct *conn,
			const struct smb_filename *smb_fname_in,
			SMB_STRUCT_STAT *psbuf);
NTSTATUS vfs_stat_fsp(files_struct *fsp);
NTSTATUS vfs_fstreaminfo(struct files_struct *fsp,
			TALLOC_CTX *mem_ctx,
			unsigned int *num_streams,
			struct stream_struct **streams);
void init_smb_file_time(struct smb_file_time *ft);
int vfs_fake_fd(void);
int vfs_fake_fd_close(int fd);
uint32_t vfs_get_fs_capabilities(struct connection_struct *conn,
				 enum timestamp_set_resolution *ts_res);

/* The following definitions come from smbd/avahi_register.c */

void *avahi_start_register(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   uint16_t port);

/* The following definitions come from smbd/smb2_create.c */

NTSTATUS vfs_default_durable_cookie(struct files_struct *fsp,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *cookie_blob);
NTSTATUS vfs_default_durable_disconnect(struct files_struct *fsp,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *new_cookie);
NTSTATUS vfs_default_durable_reconnect(struct connection_struct *conn,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       files_struct **result,
				       DATA_BLOB *new_cookie);

struct smb3_file_posix_information;
NTSTATUS smb3_file_posix_information_init(
	connection_struct *conn,
	const struct smb_filename *smb_fname,
	uint32_t dos_attributes,
	struct smb3_file_posix_information *dst);

struct tevent_req *delay_for_handle_lease_break_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct timeval timeout,
	struct files_struct *fsp,
	bool recursive,
	struct share_mode_lock **lck);

NTSTATUS delay_for_handle_lease_break_recv(struct tevent_req *req,
					   TALLOC_CTX *mem_ctx,
					   struct share_mode_lock **lck);

#endif /* _SMBD_PROTO_H_ */

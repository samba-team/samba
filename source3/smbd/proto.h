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

/* The following definitions come from smbd/signing.c  */

struct smbXsrv_client;
struct smbXsrv_connection;
struct dcesrv_context;

bool srv_check_sign_mac(struct smbXsrv_connection *conn,
			const char *inbuf, uint32_t *seqnum, bool trusted_channel);
NTSTATUS srv_calculate_sign_mac(struct smbXsrv_connection *conn,
				char *outbuf, uint32_t seqnum);
void srv_cancel_sign_response(struct smbXsrv_connection *conn);
bool srv_init_signing(struct smbXsrv_connection *conn);
void srv_set_signing_negotiated(struct smbXsrv_connection *conn,
			        bool allowed, bool mandatory);
bool srv_is_signing_active(struct smbXsrv_connection *conn);
bool srv_is_signing_negotiated(struct smbXsrv_connection *conn);
void srv_set_signing(struct smbXsrv_connection *conn,
		     const DATA_BLOB user_session_key,
		     const DATA_BLOB response);

/* The following definitions come from smbd/aio.c  */

struct aio_extra;
bool aio_write_through_requested(struct aio_extra *aio_ex);
NTSTATUS schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, off_t startpos,
			     size_t smb_maxcnt);
NTSTATUS schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, const char *data,
			      off_t startpos,
			      size_t numtowrite);
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
bool aio_add_req_to_fsp(files_struct *fsp, struct tevent_req *req);

/* The following definitions come from smbd/blocking.c  */

NTSTATUS smbd_do_locks_try(
	struct files_struct *fsp,
	enum brl_flavour lock_flav,
	uint16_t num_locks,
	struct smbd_lock_element *locks,
	uint16_t *blocker_idx,
	struct server_id *blocking_pid,
	uint64_t *blocking_smblctx);
struct tevent_req *smbd_smb1_do_locks_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smb_request **smbreq, /* talloc_move()d into our state */
	struct files_struct *fsp,
	uint32_t lock_timeout,
	bool large_offset,
	enum brl_flavour lock_flav,
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
	enum brl_flavour lock_flav,
	struct smbd_lock_element lock,
	NTSTATUS finish_status);
bool smbd_smb1_brl_finish_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid);

/* The following definitions come from smbd/close.c  */

void set_close_write_time(struct files_struct *fsp, struct timespec ts);
NTSTATUS close_file(struct smb_request *req, files_struct *fsp,
		    enum file_close_type close_type);
void msg_close_file(struct messaging_context *msg_ctx,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);
NTSTATUS delete_all_streams(connection_struct *conn,
			const struct smb_filename *smb_fname);
bool recursive_rmdir(TALLOC_CTX *ctx,
		     connection_struct *conn,
		     struct smb_filename *smb_dname);
bool has_other_nonposix_opens(struct share_mode_lock *lck,
			      struct files_struct *fsp);

/* The following definitions come from smbd/conn.c  */

int conn_num_open(struct smbd_server_connection *sconn);
bool conn_snum_used(struct smbd_server_connection *sconn, int snum);
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

/* The following definitions come from smbd/dir.c  */

bool init_dptrs(struct smbd_server_connection *sconn);
const char *dptr_path(struct smbd_server_connection *sconn, int key);
const char *dptr_wcard(struct smbd_server_connection *sconn, int key);
uint16_t dptr_attr(struct smbd_server_connection *sconn, int key);
void dptr_closecnum(connection_struct *conn);
NTSTATUS dptr_create(connection_struct *conn,
		struct smb_request *req,
		files_struct *fsp,
		bool old_handle,
		bool expect_close,
		uint16_t spid,
		const char *wcard,
		bool wcard_has_wild,
		uint32_t attr,
		struct dptr_struct **dptr_ret);
void dptr_CloseDir(files_struct *fsp);
void dptr_SeekDir(struct dptr_struct *dptr, long offset);
long dptr_TellDir(struct dptr_struct *dptr);
bool dptr_has_wild(struct dptr_struct *dptr);
int dptr_dnum(struct dptr_struct *dptr);
bool dptr_get_priv(struct dptr_struct *dptr);
void dptr_set_priv(struct dptr_struct *dptr);
bool dptr_SearchDir(struct dptr_struct *dptr, const char *name, long *poffset, SMB_STRUCT_STAT *pst);
bool dptr_fill(struct smbd_server_connection *sconn,
	       char *buf1,unsigned int key);
files_struct *dptr_fetch_fsp(struct smbd_server_connection *sconn,
			       char *buf,int *num);
files_struct *dptr_fetch_lanman2_fsp(struct smbd_server_connection *sconn,
				       int dptr_num);
bool get_dir_entry(TALLOC_CTX *ctx,
		struct dptr_struct *dirptr,
		const char *mask,
		uint32_t dirtype,
		char **pp_fname_out,
		off_t *size,
		uint32_t *mode,
		struct timespec *date,
		bool check_descend,
		bool ask_sharemode);
struct smb_Dir;
bool is_visible_file(connection_struct *conn,
		struct smb_Dir *dir_hnd,
		const char *name,
		SMB_STRUCT_STAT *pst,
		bool use_veto);
struct smb_Dir *OpenDir(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr);
const char *ReadDirName(struct smb_Dir *dir_hnd, long *poffset,
			SMB_STRUCT_STAT *sbuf, char **talloced);
void RewindDir(struct smb_Dir *dir_hnd, long *poffset);
void SeekDir(struct smb_Dir *dirp, long offset);
long TellDir(struct smb_Dir *dirp);
bool SearchDir(struct smb_Dir *dirp, const char *name, long *poffset);
NTSTATUS can_delete_directory(struct connection_struct *conn,
				const char *dirname);
bool have_file_open_below(connection_struct *conn,
			const struct smb_filename *name);

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

mode_t unix_mode(connection_struct *conn, int dosmode,
		 const struct smb_filename *smb_fname,
		 struct smb_filename *smb_fname_parent);
uint32_t dos_mode_msdfs(connection_struct *conn,
		      const struct smb_filename *smb_fname);
uint32_t dos_mode(connection_struct *conn, struct smb_filename *smb_fname);
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
int file_ntimes(connection_struct *conn, const struct smb_filename *smb_fname,
		struct smb_file_time *ft);
bool set_sticky_write_time_path(struct file_id fileid, struct timespec mtime);
bool set_sticky_write_time_fsp(struct files_struct *fsp,
			       struct timespec mtime);

NTSTATUS get_ea_dos_attribute(connection_struct *conn,
			      struct smb_filename *smb_fname,
			      uint32_t *pattr);
NTSTATUS set_ea_dos_attribute(connection_struct *conn,
			      const struct smb_filename *smb_fname,
			      uint32_t dosmode);

NTSTATUS set_create_timespec_ea(connection_struct *conn,
				const struct smb_filename *smb_fname,
				struct timespec create_time);

struct timespec get_create_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname);

struct timespec get_change_timespec(connection_struct *conn,
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
bool can_write_to_file(connection_struct *conn,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname);
bool directory_has_default_acl(connection_struct *conn,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname);
NTSTATUS can_set_delete_on_close(files_struct *fsp, uint32_t dosmode);

/* The following definitions come from smbd/fileio.c  */

ssize_t read_file(files_struct *fsp,char *data,off_t pos,size_t n);
void fsp_flush_write_time_update(struct files_struct *fsp);
void trigger_write_time_update(struct files_struct *fsp);
void trigger_write_time_update_immediate(struct files_struct *fsp);
void mark_file_modified(files_struct *fsp);
ssize_t write_file(struct smb_request *req,
			files_struct *fsp,
			const char *data,
			off_t pos,
			size_t n);
NTSTATUS sync_file(connection_struct *conn, files_struct *fsp, bool write_through);

/* The following definitions come from smbd/filename.c  */

uint32_t ucf_flags_from_smb_request(struct smb_request *req);
uint32_t filename_create_ucf_flags(struct smb_request *req, uint32_t create_disposition);
NTSTATUS unix_convert(TALLOC_CTX *ctx,
		      connection_struct *conn,
		      const char *orig_path,
		      NTTIME twrp,
		      struct smb_filename **smb_fname,
		      uint32_t ucf_flags);
NTSTATUS check_name(connection_struct *conn,
			const struct smb_filename *smb_fname);
NTSTATUS canonicalize_snapshot_path(struct smb_filename *smb_fname,
				    uint32_t ucf_flags,
				    NTTIME twrp);
int get_real_filename(connection_struct *conn,
		      struct smb_filename *path,
		      const char *name,
		      TALLOC_CTX *mem_ctx,
		      char **found_name);
int get_real_filename_full_scan(connection_struct *conn,
				const char *path,
				const char *name,
				bool mangled,
				TALLOC_CTX *mem_ctx,
				char **found_name);
char *get_original_lcomp(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *filename_in,
			uint32_t ucf_flags);
NTSTATUS filename_convert(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			const char *name_in,
			uint32_t ucf_flags,
			NTTIME twrp,
			bool *ppath_contains_wcard,
			struct smb_filename **pp_smb_fname);
NTSTATUS filename_convert_with_privilege(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			struct smb_request *smbreq,
			const char *name_in,
			uint32_t ucf_flags,
			bool *ppath_contains_wcard,
			struct smb_filename **pp_smb_fname);

/* The following definitions come from smbd/files.c  */

NTSTATUS fsp_new(struct connection_struct *conn, TALLOC_CTX *mem_ctx,
		 files_struct **result);
void fsp_set_gen_id(files_struct *fsp);
NTSTATUS file_new(struct smb_request *req, connection_struct *conn,
		  files_struct **result);
void file_close_conn(connection_struct *conn);
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
				 struct file_id id);
files_struct *file_find_di_next(files_struct *start_fsp);
struct files_struct *file_find_one_fsp_from_lease_key(
	struct smbd_server_connection *sconn,
	const struct smb2_lease_key *lease_key);
bool file_find_subpath(files_struct *dir_fsp);
void fsp_free(files_struct *fsp);
void file_free(struct smb_request *req, files_struct *fsp);
files_struct *file_fsp(struct smb_request *req, uint16_t fid);
struct files_struct *file_fsp_get(struct smbd_smb2_request *smb2req,
				  uint64_t persistent_id,
				  uint64_t volatile_id);
struct files_struct *file_fsp_smb2(struct smbd_smb2_request *smb2req,
				   uint64_t persistent_id,
				   uint64_t volatile_id);
NTSTATUS dup_file_fsp(
	struct smb_request *req,
	files_struct *from,
	uint32_t access_mask,
	uint32_t create_options,
	files_struct *to);
NTSTATUS file_name_hash(connection_struct *conn,
			const char *name, uint32_t *p_name_hash);
NTSTATUS fsp_set_smb_fname(struct files_struct *fsp,
			   const struct smb_filename *smb_fname_in);
size_t fsp_fullbasepath(struct files_struct *fsp, char *buf, size_t buflen);

NTSTATUS create_internal_dirfsp(connection_struct *conn,
				const struct smb_filename *smb_dname,
				struct files_struct **_fsp);

NTSTATUS open_internal_dirfsp(connection_struct *conn,
			      const struct smb_filename *smb_dname,
			      int open_flags,
			      struct files_struct **_fsp);

/* The following definitions come from smbd/ipc.c  */

NTSTATUS nt_status_np_pipe(NTSTATUS status);
void send_trans_reply(connection_struct *conn,
		      struct smb_request *req,
		      char *rparam, int rparam_len,
		      char *rdata, int rdata_len,
		      bool buffer_too_large);
void reply_trans(struct smb_request *req);
void reply_transs(struct smb_request *req);

/* The following definitions come from smbd/lanman.c  */

void api_reply(connection_struct *conn, uint64_t vuid,
	       struct smb_request *req,
	       char *data, char *params,
	       int tdscnt, int tpscnt,
	       int mdrcnt, int mprcnt);

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

/* The following definitions come from smbd/message.c  */

void reply_sends(struct smb_request *req);
void reply_sendstrt(struct smb_request *req);
void reply_sendtxt(struct smb_request *req);
void reply_sendend(struct smb_request *req);

/* The following definitions come from smbd/msdfs.c  */

bool parse_msdfs_symlink(TALLOC_CTX *ctx,
			bool shuffle_referrals,
			const char *target,
			struct referral **preflist,
			size_t *refcount);
bool is_msdfs_link(connection_struct *conn,
		struct smb_filename *smb_fname);
struct junction_map;
NTSTATUS get_referred_path(TALLOC_CTX *ctx,
			   struct auth_session_info *session_info,
			   const char *dfs_path,
			   const struct tsocket_address *remote_address,
			   const struct tsocket_address *local_address,
			   bool allow_broken_path,
			   struct junction_map *jucn,
			   int *consumedcntp,
			   bool *self_referralp);
int setup_dfs_referral(connection_struct *orig_conn,
			const char *dfs_path,
			int max_referral_level,
			char **ppdata, NTSTATUS *pstatus);
bool create_junction(TALLOC_CTX *ctx,
		const char *dfs_path,
		bool allow_broken_path,
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
NTSTATUS resolve_dfspath_wcard(TALLOC_CTX *ctx,
				connection_struct *conn,
				const char *name_in,
				uint32_t ucf_flags,
				bool allow_broken_path,
				char **pp_name_out,
				bool *ppath_contains_wcard);
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

/* The following definitions come from smbd/negprot.c  */

void reply_negprot(struct smb_request *req);

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
void notify_fname(connection_struct *conn, uint32_t action, uint32_t filter,
		  const char *path);
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

struct notify_instance;
NTSTATUS notify_walk(struct notify_context *notify,
		     bool (*fn)(const char *path, struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data);

/* The following definitions come from smbd/ntquotas.c  */

NTSTATUS vfs_get_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype,
			 struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_set_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_get_user_ntquota_list(files_struct *fsp, SMB_NTQUOTA_LIST **qt_list);
void *init_quota_handle(TALLOC_CTX *mem_ctx);

/* The following definitions come from smbd/nttrans.c  */

void reply_ntcreate_and_X(struct smb_request *req);
NTSTATUS set_sd(files_struct *fsp, struct security_descriptor *psd,
                       uint32_t security_info_sent);
NTSTATUS set_sd_blob(files_struct *fsp, uint8_t *data, uint32_t sd_len,
                       uint32_t security_info_sent);
struct ea_list *read_nttrans_ea_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size);
void reply_ntcancel(struct smb_request *req);
void reply_ntrename(struct smb_request *req);
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
void reply_nttrans(struct smb_request *req);
void reply_nttranss(struct smb_request *req);

/* The following definitions come from smbd/open.c  */

NTSTATUS smbd_check_access_rights(struct connection_struct *conn,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				bool use_privs,
				uint32_t access_mask);
NTSTATUS check_parent_access(struct connection_struct *conn,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				uint32_t access_mask);
NTSTATUS fd_open(files_struct *fsp,
		 int flags, mode_t mode);
NTSTATUS fd_openat(files_struct *fsp,
		   int flags,
		   mode_t mode);
NTSTATUS fd_close(files_struct *fsp);
void change_file_owner_to_parent(connection_struct *conn,
				 struct smb_filename *inherit_from_dir,
				 files_struct *fsp);
bool is_oplock_stat_open(uint32_t access_mask);
bool is_lease_stat_open(uint32_t access_mask);
NTSTATUS send_break_message(struct messaging_context *msg_ctx,
			    const struct file_id *id,
			    const struct share_mode_entry *exclusive,
			    uint16_t break_to);
struct deferred_open_record;
bool is_deferred_open_async(const struct deferred_open_record *rec);
bool defer_smb1_sharing_violation(struct smb_request *req);
NTSTATUS create_directory(connection_struct *conn, struct smb_request *req,
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
			     struct files_struct **dirfsp,
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
bool remove_oplock(files_struct *fsp);
bool downgrade_oplock(files_struct *fsp);
bool fsp_lease_update(struct files_struct *fsp);
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
void share_mode_entry_to_message(char *msg, const struct file_id *id,
				 const struct share_mode_entry *e);
void message_to_share_mode_entry(struct file_id *id,
				 struct share_mode_entry *e,
				 const char *msg);
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
void reply_open_pipe_and_X(connection_struct *conn, struct smb_request *req);
void reply_pipe_write(struct smb_request *req);
void reply_pipe_write_and_X(struct smb_request *req);
void reply_pipe_read_and_X(struct smb_request *req);

/* The following definitions come from smbd/posix_acls.c  */

mode_t unix_perms_to_acl_perms(mode_t mode, int r_mask, int w_mask, int x_mask);
int map_acl_perms_to_permset(mode_t mode, SMB_ACL_PERMSET_T *p_permset);
uint32_t map_canon_ace_perms(int snum,
                                enum security_ace_type *pacl_type,
                                mode_t perms,
                                bool directory_ace);
NTSTATUS unpack_nt_owners(connection_struct *conn, uid_t *puser, gid_t *pgrp, uint32_t security_info_sent, const struct security_descriptor *psd);
bool current_user_in_group(connection_struct *conn, gid_t gid);
SMB_ACL_T free_empty_sys_acl(connection_struct *conn, SMB_ACL_T the_acl);
NTSTATUS posix_fget_nt_acl(struct files_struct *fsp, uint32_t security_info,
			   TALLOC_CTX *mem_ctx,
			   struct security_descriptor **ppdesc);
NTSTATUS posix_get_nt_acl(struct connection_struct *conn,
			const struct smb_filename *smb_fname_in,
			uint32_t security_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppdesc);
NTSTATUS try_chown(files_struct *fsp, uid_t uid, gid_t gid);
NTSTATUS set_nt_acl(files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd);
int get_acl_group_bits( connection_struct *conn,
			const struct smb_filename *smb_fname,
			mode_t *mode);
int inherit_access_posix_acl(connection_struct *conn,
			struct smb_filename *inherit_from_dir,
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

/* The following definitions come from smbd/process.c  */

bool srv_send_smb(struct smbXsrv_connection *xconn, char *buffer,
		  bool no_signing, uint32_t seqnum,
		  bool do_encrypt,
		  struct smb_perfcount_data *pcd);
size_t srv_set_message(char *buf,
		       size_t num_words,
		       size_t num_bytes,
		       bool zero);
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
NTSTATUS allow_new_trans(struct trans_state *list, uint64_t mid);
void reply_outbuf(struct smb_request *req, uint8_t num_words, uint32_t num_bytes);
void smb_request_done(struct smb_request *req);
const char *smb_fn_name(int type);
void add_to_common_flags2(uint32_t v);
void remove_from_common_flags2(uint32_t v);
void construct_reply_common_req(struct smb_request *req, char *outbuf);
bool smb1_is_chain(const uint8_t *buf);
bool smb1_walk_chain(const uint8_t *buf,
		     bool (*fn)(uint8_t cmd,
				uint8_t wct, const uint16_t *vwv,
				uint16_t num_bytes, const uint8_t *bytes,
				void *private_data),
		     void *private_data);
unsigned smb1_chain_length(const uint8_t *buf);
bool smb1_parse_chain(TALLOC_CTX *mem_ctx, const uint8_t *buf,
		      struct smbXsrv_connection *xconn,
		      bool encrypted, uint32_t seqnum,
		      struct smb_request ***reqs, unsigned *num_reqs);
bool req_is_in_chain(const struct smb_request *req);
void smbd_process(struct tevent_context *ev_ctx,
		  struct messaging_context *msg_ctx,
		  struct dcesrv_context *dce_ctx,
		  int sock_fd,
		  bool interactive);
bool fork_echo_handler(struct smbXsrv_connection *xconn);

/* The following definitions come from smbd/quotas.c  */

bool disk_quotas(connection_struct *conn, struct smb_filename *fname,
		 uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);

/* The following definitions come from smbd/reply.c  */

NTSTATUS check_path_syntax(char *path);
NTSTATUS check_path_syntax_wcard(char *path, bool *p_contains_wcard);
NTSTATUS check_path_syntax_posix(char *path);
size_t srvstr_get_path_wcard(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard);
size_t srvstr_get_path_wcard_posix(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16_t smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard);
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
size_t srvstr_get_path_req_wcard(TALLOC_CTX *mem_ctx, struct smb_request *req,
				 char **pp_dest, const char *src, int flags,
				 NTSTATUS *err, bool *contains_wcard);
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
void reply_tcon(struct smb_request *req);
void reply_tcon_and_X(struct smb_request *req);
void reply_unknown_new(struct smb_request *req, uint8_t type);
void reply_ioctl(struct smb_request *req);
void reply_checkpath(struct smb_request *req);
void reply_getatr(struct smb_request *req);
void reply_setatr(struct smb_request *req);
void reply_dskattr(struct smb_request *req);
void reply_search(struct smb_request *req);
void reply_fclose(struct smb_request *req);
void reply_open(struct smb_request *req);
void reply_open_and_X(struct smb_request *req);
void reply_ulogoffX(struct smb_request *req);
void reply_mknew(struct smb_request *req);
void reply_ctemp(struct smb_request *req);
NTSTATUS unlink_internals(connection_struct *conn, struct smb_request *req,
			  uint32_t dirtype, struct smb_filename *smb_fname,
			  bool has_wild);
void reply_unlink(struct smb_request *req);
ssize_t fake_sendfile(struct smbXsrv_connection *xconn, files_struct *fsp,
		      off_t startpos, size_t nread);
ssize_t sendfile_short_send(struct smbXsrv_connection *xconn,
			    files_struct *fsp,
			    ssize_t nread,
			    size_t headersize,
			    size_t smb_maxcnt);
void reply_readbraw(struct smb_request *req);
void reply_lockread(struct smb_request *req);
size_t setup_readX_header(char *outbuf, size_t smb_maxcnt);
void reply_read(struct smb_request *req);
void reply_read_and_X(struct smb_request *req);
void error_to_writebrawerr(struct smb_request *req);
void reply_writebraw(struct smb_request *req);
void reply_writeunlock(struct smb_request *req);
void reply_write(struct smb_request *req);
bool is_valid_writeX_buffer(struct smbXsrv_connection *xconn,
			    const uint8_t *inbuf);
void reply_write_and_X(struct smb_request *req);
void reply_lseek(struct smb_request *req);
void reply_flush(struct smb_request *req);
void reply_exit(struct smb_request *req);
void reply_close(struct smb_request *req);
void reply_writeclose(struct smb_request *req);
void reply_lock(struct smb_request *req);
void reply_unlock(struct smb_request *req);
void reply_tdis(struct smb_request *req);
void reply_echo(struct smb_request *req);
void reply_printopen(struct smb_request *req);
void reply_printclose(struct smb_request *req);
void reply_printqueue(struct smb_request *req);
void reply_printwrite(struct smb_request *req);
void reply_mkdir(struct smb_request *req);
void reply_rmdir(struct smb_request *req);
NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			const struct smb_filename *smb_fname_dst_in,
			const char *dst_original_lcomp,
			uint32_t attrs,
			bool replace_if_exists);
NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			const char *dst_original_lcomp,
			uint32_t attrs,
			bool replace_if_exists,
			bool src_has_wild,
			bool dest_has_wild,
			uint32_t access_mask);
void reply_mv(struct smb_request *req);
NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			int ofun,
			int count,
			bool target_is_directory);
void reply_copy(struct smb_request *req);
uint64_t get_lock_pid(const uint8_t *data, int data_offset,
		    bool large_file_format);
uint64_t get_lock_count(const uint8_t *data, int data_offset,
			bool large_file_format);
uint64_t get_lock_offset(const uint8_t *data, int data_offset,
			 bool large_file_format);
void reply_lockingX(struct smb_request *req);
void reply_readbmpx(struct smb_request *req);
void reply_readbs(struct smb_request *req);
void reply_setattrE(struct smb_request *req);
void reply_writebmpx(struct smb_request *req);
void reply_writebs(struct smb_request *req);
void reply_getattrE(struct smb_request *req);

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

/* The following definitions come from smbd/service.c  */

bool set_conn_connectpath(connection_struct *conn, const char *connectpath);
bool canonicalize_connect_path(connection_struct *conn);
NTSTATUS set_conn_force_user_group(connection_struct *conn, int snum);
void set_current_case_sensitive(connection_struct *conn, uint16_t flags);
bool chdir_current_service(connection_struct *conn);
void load_registry_shares(void);
int add_home_service(const char *service, const char *username, const char *homedir);
int find_service(TALLOC_CTX *ctx, const char *service, char **p_service_out);
connection_struct *make_connection_smb2(struct smbd_smb2_request *req,
					struct smbXsrv_tcon *tcon,
					int snum,
					const char *pdev,
					NTSTATUS *pstatus);
connection_struct *make_connection(struct smb_request *req,
				   NTTIME now,
				   const char *service_in,
				   const char *pdev, uint64_t vuid,
				   NTSTATUS *status);
void close_cnum(connection_struct *conn, uint64_t vuid);

/* The following definitions come from smbd/session.c  */
struct sessionid;
struct smbXsrv_session;
bool session_init(void);
bool session_claim(struct smbXsrv_session *session);
void session_yield(struct smbXsrv_session *session);
int list_sessions(TALLOC_CTX *mem_ctx, struct sessionid **session_list);
int find_sessions(TALLOC_CTX *mem_ctx, const char *username,
		  const char *machine, struct sessionid **session_list);

/* The following definitions come from smbd/sesssetup.c  */

void reply_sesssetup_and_X(struct smb_request *req);

/* The following definitions come from smbd/share_access.c  */

bool token_contains_name_in_list(const char *username,
				 const char *domain,
				 const char *sharename,
				 const struct security_token *token,
				 const char **list);
bool user_ok_token(const char *username, const char *domain,
		   const struct security_token *token, int snum);
bool is_share_read_only_for_token(const char *username,
				  const char *domain,
				  const struct security_token *token,
				  connection_struct *conn);

/* The following definitions come from smbd/srvstr.c  */

NTSTATUS srvstr_push_fn(const char *base_ptr, uint16_t smb_flags2, void *dest,
		      const char *src, int dest_len, int flags, size_t *ret_len);
ssize_t message_push_string(uint8_t **outbuf, const char *str, int flags);

/* The following definitions come from smbd/statcache.c  */

void stat_cache_add( const char *full_orig_name,
		const char *translated_path,
		NTTIME twrp,
		bool case_sensitive);
bool stat_cache_lookup(connection_struct *conn,
			bool posix_paths,
			char **pp_name,
			char **pp_dirpath,
			char **pp_start,
			NTTIME twrp,
			SMB_STRUCT_STAT *pst);
void smbd_send_stat_cache_delete_message(struct messaging_context *msg_ctx,
				    const char *name);
void send_stat_cache_delete_message(struct messaging_context *msg_ctx,
				    const char *name);
void stat_cache_delete(const char *name);
struct TDB_DATA;
unsigned int fast_string_hash(struct TDB_DATA *key);
bool reset_stat_cache( void );

/* The following definitions come from smbd/statvfs.c  */

int sys_statvfs(const char *path, vfs_statvfs_struct *statbuf);

/* The following definitions come from smbd/trans2.c  */

NTSTATUS check_access_fsp(const struct files_struct *fsp,
			  uint32_t access_mask);
uint64_t smb_roundup(connection_struct *conn, uint64_t val);
bool samba_private_attr_name(const char *unix_ea_name);
NTSTATUS get_ea_value(TALLOC_CTX *mem_ctx, connection_struct *conn,
			files_struct *fsp,
			const struct smb_filename *smb_fname,
			const char *ea_name,
			struct ea_struct *pea);
NTSTATUS get_ea_names_from_file(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			files_struct *fsp,
			const struct smb_filename *smb_fname,
			char ***pnames,
			size_t *pnum_names);
NTSTATUS set_ea(connection_struct *conn, files_struct *fsp,
		const struct smb_filename *smb_fname, struct ea_list *ea_list);
struct ea_list *read_ea_list_entry(TALLOC_CTX *ctx, const char *pdata, size_t data_size, size_t *pbytes_used);
void send_trans2_replies(connection_struct *conn,
			struct smb_request *req,
			NTSTATUS status,
			 const char *params,
			 int paramsize,
			 const char *pdata,
			 int datasize,
			 int max_data_bytes);
unsigned char *create_volume_objectid(connection_struct *conn, unsigned char objid[16]);
NTSTATUS hardlink_internals(TALLOC_CTX *ctx,
		connection_struct *conn,
		struct smb_request *req,
		bool overwrite_if_exists,
		const struct smb_filename *smb_fname_old,
		struct smb_filename *smb_fname_new);
NTSTATUS smb_set_file_time(connection_struct *conn,
			   files_struct *fsp,
			   const struct smb_filename *smb_fname,
			   struct smb_file_time *ft,
			   bool setting_write_time);
void reply_findclose(struct smb_request *req);
void reply_findnclose(struct smb_request *req);
void reply_trans2(struct smb_request *req);
void reply_transs2(struct smb_request *req);

enum perm_type {
	PERM_NEW_FILE,
	PERM_NEW_DIR,
	PERM_EXISTING_FILE,
	PERM_EXISTING_DIR
};

NTSTATUS unix_perms_from_wire(connection_struct *conn,
			      const SMB_STRUCT_STAT *psbuf,
			      uint32_t perms,
			      enum perm_type ptype,
			      mode_t *ret_perms);

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
uint64_t get_current_vuid(connection_struct *conn);

/* The following definitions come from smbd/utmp.c  */

void sys_utmp_claim(const char *username, const char *hostname,
		    const char *id_str, int id_num);
void sys_utmp_yield(const char *username, const char *hostname,
		    const char *id_str, int id_num);

/* The following definitions come from smbd/vfs.c  */

bool vfs_init_custom(connection_struct *conn, const char *vfs_object);
bool smbd_vfs_init(connection_struct *conn);
NTSTATUS vfs_file_exist(connection_struct *conn, struct smb_filename *smb_fname);
bool vfs_valid_pread_range(off_t offset, size_t length);
bool vfs_valid_pwrite_range(off_t offset, size_t length);
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
const char *vfs_readdirname(connection_struct *conn, void *p,
			    SMB_STRUCT_STAT *sbuf, char **talloced);
int vfs_ChDir(connection_struct *conn,
			const struct smb_filename *smb_fname);
struct smb_filename *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn);
NTSTATUS check_reduced_name(connection_struct *conn,
			const struct smb_filename *cwd_fname,
			const struct smb_filename *smb_fname);
NTSTATUS check_reduced_name_with_privilege(connection_struct *conn,
			const struct smb_filename *smb_fname,
			struct smb_request *smbreq);
int vfs_stat_smb_basename(struct connection_struct *conn,
			const struct smb_filename *smb_fname_in,
			SMB_STRUCT_STAT *psbuf);
NTSTATUS vfs_stat_fsp(files_struct *fsp);
NTSTATUS vfs_streaminfo(connection_struct *conn,
			struct files_struct *fsp,
			const struct smb_filename *smb_fname,
			TALLOC_CTX *mem_ctx,
			unsigned int *num_streams,
			struct stream_struct **streams);
void init_smb_file_time(struct smb_file_time *ft);
int vfs_fake_fd(void);
int vfs_fake_fd_close(int fd);

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

#endif /* _SMBD_PROTO_H_ */

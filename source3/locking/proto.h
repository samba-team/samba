/*
 *  Unix SMB/CIFS implementation.
 *  Locking functions
 *
 *  Copyright (C) Andrew Tridgell	1992-2000
 *  Copyright (C) Jeremy Allison	1992-2006
 *  Copyright (C) Volker Lendecke	2005
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

#ifndef _LOCKING_PROTO_H_
#define _LOCKING_PROTO_H_

#include <tdb.h>

/* The following definitions come from locking/brlock.c  */

void brl_init(bool read_only);
void brl_shutdown(void);

unsigned int brl_num_locks(const struct byte_range_lock *brl);
struct files_struct *brl_fsp(struct byte_range_lock *brl);
TALLOC_CTX *brl_req_mem_ctx(const struct byte_range_lock *brl);
const struct GUID *brl_req_guid(const struct byte_range_lock *brl);

bool byte_range_valid(uint64_t ofs, uint64_t len);
bool byte_range_overlap(uint64_t ofs1,
			uint64_t len1,
			uint64_t ofs2,
			uint64_t len2);

NTSTATUS brl_lock_windows_default(struct byte_range_lock *br_lck,
				  struct lock_struct *plock);

NTSTATUS brl_lock(
	struct byte_range_lock *br_lck,
	uint64_t smblctx,
	struct server_id pid,
	br_off start,
	br_off size,
	enum brl_type lock_type,
	enum brl_flavour lock_flav,
	struct server_id *blocker_pid,
	uint64_t *psmblctx);
bool brl_unlock(struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav);
bool brl_unlock_windows_default(struct byte_range_lock *br_lck,
				const struct lock_struct *plock);
bool brl_locktest(struct byte_range_lock *br_lck,
		  const struct lock_struct *rw_probe);
NTSTATUS brl_lockquery(struct byte_range_lock *br_lck,
		uint64_t *psmblctx,
		struct server_id pid,
		br_off *pstart,
		br_off *psize,
		enum brl_type *plock_type,
		enum brl_flavour lock_flav);
bool brl_mark_disconnected(struct files_struct *fsp);
bool brl_reconnect_disconnected(struct files_struct *fsp);
void brl_close_fnum(struct byte_range_lock *br_lck);
int brl_forall(void (*fn)(struct file_id id, struct server_id pid,
			  enum brl_type lock_type,
			  enum brl_flavour lock_flav,
			  br_off start, br_off size,
			  void *private_data),
	       void *private_data);
struct byte_range_lock *brl_get_locks_for_locking(TALLOC_CTX *mem_ctx,
						  files_struct *fsp,
						  TALLOC_CTX *req_mem_ctx,
						  const struct GUID *req_guid);
struct byte_range_lock *brl_get_locks(TALLOC_CTX *mem_ctx,
					files_struct *fsp);
struct byte_range_lock *brl_get_locks_readonly(files_struct *fsp);
bool brl_cleanup_disconnected(struct file_id fid, uint64_t open_persistent_id);

/* The following definitions come from locking/locking.c  */

const char *lock_type_name(enum brl_type lock_type);
const char *lock_flav_name(enum brl_flavour lock_flav);
void init_strict_lock_struct(files_struct *fsp,
				uint64_t smblctx,
				br_off start,
				br_off size,
				enum brl_type lock_type,
				struct lock_struct *plock);
bool strict_lock_check_default(files_struct *fsp,
			       struct lock_struct *plock);
NTSTATUS query_lock(files_struct *fsp,
			uint64_t *psmblctx,
			uint64_t *pcount,
			uint64_t *poffset,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
NTSTATUS do_lock(files_struct *fsp,
		 TALLOC_CTX *req_mem_ctx,
		 const struct GUID *req_guid,
		 uint64_t smblctx,
		 uint64_t count,
		 uint64_t offset,
		 enum brl_type lock_type,
		 enum brl_flavour lock_flav,
		 struct server_id *pblocker_pid,
		 uint64_t *psmblctx);
NTSTATUS do_unlock(files_struct *fsp,
		   uint64_t smblctx,
		   uint64_t count,
		   uint64_t offset,
		   enum brl_flavour lock_flav);
void locking_close_file(files_struct *fsp,
			enum file_close_type close_type);
bool locking_init(void);
bool locking_init_readonly(void);
bool locking_end(void);
char *share_mode_str(TALLOC_CTX *ctx, int num,
		     const struct file_id *id,
		     const struct share_mode_entry *e);
struct share_mode_lock *get_existing_share_mode_lock(TALLOC_CTX *mem_ctx,
						     struct file_id id);
struct share_mode_lock *get_share_mode_lock(
	TALLOC_CTX *mem_ctx,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	const struct timespec *old_write_time);

bool file_has_read_lease(struct files_struct *fsp);

struct db_record;
NTSTATUS share_mode_do_locked(
	struct file_id id,
	void (*fn)(const uint8_t *buf,
		   size_t buflen,
		   bool *modified_dependent,
		   void *private_data),
	void *private_data);
NTSTATUS share_mode_wakeup_waiters(struct file_id id);
bool share_mode_have_entries(struct share_mode_lock *lck);

struct tevent_req *share_mode_watch_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id id,
	struct server_id blocker);
NTSTATUS share_mode_watch_recv(
	struct tevent_req *req, bool *blockerdead, struct server_id *blocker);

struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  struct file_id id);
struct tevent_req *fetch_share_mode_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct file_id id,
					 bool *queued);
NTSTATUS fetch_share_mode_recv(struct tevent_req *req,
			       TALLOC_CTX *mem_ctx,
			       struct share_mode_lock **_lck);
bool rename_share_filename(struct messaging_context *msg_ctx,
			struct share_mode_lock *lck,
			struct file_id id,
			const char *servicepath,
			uint32_t orig_name_hash,
			uint32_t new_name_hash,
			const struct smb_filename *smb_fname);
void get_file_infos(struct file_id id,
		    uint32_t name_hash,
		    bool *delete_on_close,
		    struct timespec *write_time);
bool is_valid_share_mode_entry(const struct share_mode_entry *e);
bool share_entry_stale_pid(struct share_mode_entry *e);
bool set_share_mode(struct share_mode_lock *lck,
		    struct files_struct *fsp,
		    uid_t uid,
		    uint64_t mid,
		    uint16_t op_type,
		    uint32_t share_access,
		    uint32_t access_mask);
bool reset_share_mode_entry(
	struct share_mode_lock *lck,
	struct server_id old_pid,
	uint64_t old_share_file_id,
	struct server_id new_pid,
	uint64_t new_mid,
	uint64_t new_share_file_id);
NTSTATUS remove_lease_if_stale(struct share_mode_lock *lck,
			       const struct GUID *client_guid,
			       const struct smb2_lease_key *lease_key);
bool del_share_mode(struct share_mode_lock *lck, files_struct *fsp);
bool mark_share_mode_disconnected(struct share_mode_lock *lck,
				  struct files_struct *fsp);
bool remove_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
bool downgrade_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
bool get_delete_on_close_token(struct share_mode_lock *lck,
				uint32_t name_hash,
				const struct security_token **pp_nt_tok,
				const struct security_unix_token **pp_tok);
void reset_delete_on_close_lck(files_struct *fsp,
			       struct share_mode_lock *lck);
void set_delete_on_close_lck(files_struct *fsp,
			struct share_mode_lock *lck,
			const struct security_token *nt_tok,
			const struct security_unix_token *tok);
bool set_delete_on_close(files_struct *fsp, bool delete_on_close,
			const struct security_token *nt_tok,
			const struct security_unix_token *tok);
bool is_delete_on_close_set(struct share_mode_lock *lck, uint32_t name_hash);
bool set_sticky_write_time(struct file_id fileid, struct timespec write_time);
bool set_write_time(struct file_id fileid, struct timespec write_time);
struct timespec get_share_mode_write_time(struct share_mode_lock *lck);
bool file_has_open_streams(files_struct *fsp);
int share_mode_forall(int (*fn)(struct file_id fid,
				const struct share_mode_data *data,
				void *private_data),
		      void *private_data);
int share_entry_forall(int (*fn)(struct file_id fid,
				 const struct share_mode_data *data,
				 const struct share_mode_entry *entry,
				 void *private_data),
		      void *private_data);
bool share_mode_cleanup_disconnected(struct file_id id,
				     uint64_t open_persistent_id);
bool share_mode_forall_leases(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   void *private_data),
	void *private_data);

bool share_mode_forall_entries(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data),
	void *private_data);

NTSTATUS share_mode_count_entries(struct file_id fid, size_t *num_share_modes);

/* The following definitions come from locking/posix.c  */

bool is_posix_locked(files_struct *fsp,
			uint64_t *pu_offset,
			uint64_t *pu_count,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
bool posix_locking_init(bool read_only);
bool posix_locking_end(void);
int fd_close_posix(const struct files_struct *fsp);
bool set_posix_lock_windows_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			const struct lock_struct *plocks,
			int num_locks,
			int *errno_ret);
bool release_posix_lock_windows_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				enum brl_type deleted_lock_type,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);
bool set_posix_lock_posix_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			int *errno_ret);
bool release_posix_lock_posix_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);

/* The following definitions come from locking/leases_util.c */
uint32_t map_oplock_to_lease_type(uint16_t op_type);
uint32_t fsp_lease_type(struct files_struct *fsp);
bool fsp_lease_type_is_exclusive(struct files_struct *fsp);
const struct GUID *fsp_client_guid(const files_struct *fsp);

#endif /* _LOCKING_PROTO_H_ */

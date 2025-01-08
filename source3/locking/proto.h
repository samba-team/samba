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
void brl_req_set(struct byte_range_lock *br_lck,
		 TALLOC_CTX *req_mem_ctx,
		 const struct GUID *req_guid);
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
struct share_mode_lock;
typedef void (*share_mode_do_locked_brl_fn_t)(
	struct share_mode_lock *lck,
	struct byte_range_lock *br_lck, /* br_lck can be NULL */
	void *private_data);
NTSTATUS share_mode_do_locked_brl(files_struct *fsp,
		 share_mode_do_locked_brl_fn_t fn,
		 void *private_data);
struct byte_range_lock *brl_get_locks(TALLOC_CTX *mem_ctx,
					files_struct *fsp);
struct byte_range_lock *brl_get_locks_readonly(files_struct *fsp);
bool brl_cleanup_disconnected(struct file_id fid, uint64_t open_persistent_id);
void brl_set_modified(struct byte_range_lock *br_lck, bool modified);

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
NTSTATUS do_lock(struct byte_range_lock *br_lck,
		 TALLOC_CTX *req_mem_ctx,
		 const struct GUID *req_guid,
		 uint64_t smblctx,
		 uint64_t count,
		 uint64_t offset,
		 enum brl_type lock_type,
		 enum brl_flavour lock_flav,
		 struct server_id *pblocker_pid,
		 uint64_t *psmblctx);
NTSTATUS do_unlock(struct byte_range_lock *br_lck,
		   uint64_t smblctx,
		   uint64_t count,
		   uint64_t offset,
		   enum brl_flavour lock_flav);
void locking_close_file(files_struct *fsp,
			enum file_close_type close_type);
char *share_mode_str(TALLOC_CTX *ctx, int num,
		     const struct file_id *id,
		     const struct share_mode_entry *e);

bool rename_share_filename(struct messaging_context *msg_ctx,
			struct share_mode_lock *lck,
			struct file_id id,
			const char *servicepath,
			uint32_t orig_name_hash,
			uint32_t new_name_hash,
			const struct smb_filename *smb_fname);
void get_file_infos(struct file_id id,
		    uint32_t name_hash,
		    bool *delete_on_close);
bool is_valid_share_mode_entry(const struct share_mode_entry *e);
bool share_entry_stale_pid(struct share_mode_entry *e);
NTSTATUS remove_lease_if_stale(struct share_mode_lock *lck,
			       const struct GUID *client_guid,
			       const struct smb2_lease_key *lease_key);
bool get_delete_on_close_token(struct share_mode_lock *lck,
				uint32_t name_hash,
				const struct security_token **pp_nt_tok,
				const struct security_unix_token **pp_tok,
				struct smb2_lease_key *parent_lease_key);
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
bool file_has_open_streams(files_struct *fsp);
bool share_mode_forall_leases(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   void *private_data),
	void *private_data);

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
const struct GUID *fsp_client_guid(const files_struct *fsp);

#endif /* _LOCKING_PROTO_H_ */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LOCKING_SHARE_MODE_LOCK_H__
#define __LOCKING_SHARE_MODE_LOCK_H__

#include "replace.h"
#include <tevent.h>
#include "librpc/gen_ndr/file_id.h"
#include "lib/util/time.h"
#include "libcli/util/ntstatus.h"

struct share_mode_data;
struct share_mode_lock;
struct share_mode_entry;
struct smb_filename;
struct files_struct;
struct smb2_lease_key;

bool locking_init(void);
bool locking_init_readonly(void);
bool locking_end(void);

struct file_id share_mode_lock_file_id(const struct share_mode_lock *lck);

struct share_mode_lock *get_existing_share_mode_lock(TALLOC_CTX *mem_ctx,
						     struct file_id id);

bool del_share_mode_open_id(struct share_mode_lock *lck,
			    struct server_id open_pid,
			    uint64_t open_file_id);
bool del_share_mode(struct share_mode_lock *lck,
		    struct files_struct *fsp);
bool downgrade_share_oplock(struct share_mode_lock *lck,
			    struct files_struct *fsp);
bool remove_share_oplock(struct share_mode_lock *lck,
			 struct files_struct *fsp);
bool file_has_read_lease(struct files_struct *fsp);

bool set_share_mode(
	struct share_mode_lock *lck,
	struct files_struct *fsp,
	uid_t uid,
	uint64_t mid,
	uint16_t op_type,
	const struct smb2_lease_key *lease_key,
	uint32_t share_access,
	uint32_t access_mask);
bool reset_share_mode_entry(
	struct share_mode_lock *lck,
	struct server_id old_pid,
	uint64_t old_share_file_id,
	struct server_id new_pid,
	uint64_t new_mid,
	uint64_t new_share_file_id);

bool mark_share_mode_disconnected(
	struct share_mode_lock *lck, struct files_struct *fsp);

struct share_mode_lock *fetch_share_mode_unlocked(
	TALLOC_CTX *mem_ctx,
	struct file_id id);

struct tevent_req *fetch_share_mode_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id id,
	bool *queued);
NTSTATUS fetch_share_mode_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct share_mode_lock **_lck);

int share_entry_forall_read(int (*ro_fn)(struct file_id fid,
					 const struct share_mode_data *data,
					 const struct share_mode_entry *entry,
					 void *private_data),
			    void *private_data);
int share_entry_forall(int (*fn)(struct file_id fid,
				 struct share_mode_data *data,
				 struct share_mode_entry *entry,
				 void *private_data),
		       void *private_data);

NTSTATUS share_mode_count_entries(struct file_id fid, size_t *num_share_modes);
int share_mode_forall(
	int (*fn)(struct file_id fid,
		  struct share_mode_data *data,
		  void *private_data),
	void *private_data);
int share_mode_forall_read(int (*fn)(struct file_id fid,
				     const struct share_mode_data *data,
				     void *private_data),
			   void *private_data);
bool share_mode_forall_entries(
	struct share_mode_lock *lck,
	bool (*fn)(struct share_mode_entry *e,
		   bool *modified,
		   void *private_data),
	void *private_data);

const char *share_mode_servicepath(struct share_mode_lock *lck);
char *share_mode_filename(TALLOC_CTX *mem_ctx, struct share_mode_lock *lck);
char *share_mode_data_dump(
	TALLOC_CTX *mem_ctx, struct share_mode_lock *lck);

void share_mode_flags_get(
	struct share_mode_lock *lck,
	uint32_t *access_mask,
	uint32_t *share_mode,
	uint32_t *lease_type);
void share_mode_flags_set(
	struct share_mode_lock *lck,
	uint32_t access_mask,
	uint32_t share_mode,
	uint32_t lease_type,
	bool *modified);

struct tevent_req *share_mode_watch_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct file_id *id,
	struct server_id blocker);
NTSTATUS share_mode_watch_recv(
	struct tevent_req *req, bool *blockerdead, struct server_id *blocker);
NTSTATUS share_mode_wakeup_waiters(struct file_id id);

typedef void (*share_mode_do_locked_vfs_fn_t)(
		struct share_mode_lock *lck,
		void *private_data);
NTSTATUS _share_mode_do_locked_vfs_denied(
	struct file_id id,
	share_mode_do_locked_vfs_fn_t fn,
	void *private_data,
	const char *location);
#define share_mode_do_locked_vfs_denied(__id, __fn, __private_data) \
	_share_mode_do_locked_vfs_denied(__id, __fn, __private_data, __location__)
NTSTATUS _share_mode_do_locked_vfs_allowed(
	struct file_id id,
	share_mode_do_locked_vfs_fn_t fn,
	void *private_data,
	const char *location);
#define share_mode_do_locked_vfs_allowed(__id, __fn, __private_data) \
	_share_mode_do_locked_vfs_allowed(__id, __fn, __private_data, __location__)

struct share_mode_entry_prepare_state {
	struct file_id __fid;
	struct share_mode_lock *__lck_ptr;
	union {
#define __SHARE_MODE_LOCK_SPACE 32
		uint8_t __u8_space[__SHARE_MODE_LOCK_SPACE];
#ifdef SHARE_MODE_ENTRY_PREPARE_STATE_LCK_SPACE
		struct share_mode_lock __lck_space;
#endif
	};
};

typedef void (*share_mode_entry_prepare_lock_fn_t)(
		struct share_mode_lock *lck,
		bool *keep_locked,
		void *private_data);
NTSTATUS _share_mode_entry_prepare_lock(
	struct share_mode_entry_prepare_state *prepare_state,
	struct file_id id,
	const char *servicepath,
	const struct smb_filename *smb_fname,
	share_mode_entry_prepare_lock_fn_t fn,
	void *private_data,
	const char *location);
#define share_mode_entry_prepare_lock_add(__prepare_state, __id, \
		__servicepath, __smb_fname, \
		__fn, __private_data) \
	_share_mode_entry_prepare_lock(__prepare_state, __id, \
		__servicepath, __smb_fname, \
		__fn, __private_data, __location__);
#define share_mode_entry_prepare_lock_del(__prepare_state, __id, \
		__fn, __private_data) \
	_share_mode_entry_prepare_lock(__prepare_state, __id, \
		NULL, NULL, \
		__fn, __private_data, __location__);

typedef void (*share_mode_entry_prepare_unlock_fn_t)(
		struct share_mode_lock *lck,
		void *private_data);
NTSTATUS _share_mode_entry_prepare_unlock(
	struct share_mode_entry_prepare_state *prepare_state,
	share_mode_entry_prepare_unlock_fn_t fn,
	void *private_data,
	const char *location);
#define share_mode_entry_prepare_unlock(__prepare_state, \
		__fn, __private_data) \
	_share_mode_entry_prepare_unlock(__prepare_state, \
		__fn, __private_data, __location__);

#endif

uint16_t fsp_get_share_entry_flags(const struct files_struct *fsp);
void fsp_apply_share_entry_flags(struct files_struct *fsp, uint16_t flags);

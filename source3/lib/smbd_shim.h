/*
   Unix SMB/CIFS implementation.
   Runtime plugin adapter for various "smbd"-functions.

   Copyright (C) Gerald (Jerry) Carter          2004.
   Copyright (C) Andrew Bartlett                2011.

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

/* 
   shim functions are used required to allow library code to have
   references to smbd specific code. The smbd daemon sets up the set
   of function calls that it wants used by calling
   set_smbd_shim(). Other executables don't make this call, and get
   default (dummy) versions of these functions.
*/

struct smbd_shim
{
	void (*cancel_pending_lock_requests_by_fid)(files_struct *fsp,
						    struct byte_range_lock *br_lck,
						    enum file_close_type close_type);
	void (*send_stat_cache_delete_message)(struct messaging_context *msg_ctx,
					       const char *name);

	bool (*change_to_root_user)(void);

	void (*contend_level2_oplocks_begin)(files_struct *fsp,
					     enum level2_contention_type type);
	
	void (*contend_level2_oplocks_end)(files_struct *fsp,
					   enum level2_contention_type type);

	void (*become_root)(void);

	void (*unbecome_root)(void);

	void (*exit_server)(const char *const explanation) _NORETURN_;

	void (*exit_server_cleanly)(const char *const explanation) _NORETURN_;
};

void set_smbd_shim(const struct smbd_shim *shim_functions);



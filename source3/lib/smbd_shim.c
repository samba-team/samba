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

/* Shim functions required due to the horrible dependency mess
   in Samba. */

#include "includes.h"
#include "smbd_shim.h"

static struct smbd_shim shim;

void set_smbd_shim(const struct smbd_shim *shim_functions)
{
	shim = *shim_functions;
}

void cancel_pending_lock_requests_by_fid(files_struct *fsp,
			struct byte_range_lock *br_lck,
			enum file_close_type close_type)
{
	if (shim.cancel_pending_lock_requests_by_fid) {

		shim.cancel_pending_lock_requests_by_fid(fsp, br_lck, close_type);
	}
}

void send_stat_cache_delete_message(struct messaging_context *msg_ctx,
				    const char *name)
{
	if (shim.send_stat_cache_delete_message) {
		shim.send_stat_cache_delete_message(msg_ctx, name);
	}
}

bool change_to_root_user(void)
{
	if (shim.change_to_root_user) {
		return shim.change_to_root_user();
	}
	return false;
}

bool become_authenticated_pipe_user(struct auth_session_info *session_info)
{
	if (shim.become_authenticated_pipe_user) {
		return shim.become_authenticated_pipe_user(session_info);
	}

	return false;
}

bool unbecome_authenticated_pipe_user(void)
{
	if (shim.unbecome_authenticated_pipe_user) {
		return shim.unbecome_authenticated_pipe_user();
	}

	return false;
}

/**
 * The following two functions need to be called from inside the low-level BRL
 * code for oplocks correctness in smbd.  Since other utility binaries also
 * link in some of the brl code directly, these dummy functions are necessary
 * to avoid needing to link in the oplocks code and its dependencies to all of
 * the utility binaries.
 */
void contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type)
{
	if (shim.contend_level2_oplocks_begin) {
		shim.contend_level2_oplocks_begin(fsp, type);
	}
	return;
}

void contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type)
{
	if (shim.contend_level2_oplocks_end) {
		shim.contend_level2_oplocks_end(fsp, type);
	}
	return;
}

void become_root(void)
{
	if (shim.become_root) {
		shim.become_root();
	}
        return;
}

void unbecome_root(void)
{
	if (shim.unbecome_root) {
		shim.unbecome_root();
	}
	return;
}

void exit_server(const char *reason)
{
	if (shim.exit_server) {
		shim.exit_server(reason);
	}
	exit(1);
}

void exit_server_cleanly(const char *const reason)
{
	if (shim.exit_server_cleanly) {
		shim.exit_server_cleanly(reason);
	}
	exit(0);
}

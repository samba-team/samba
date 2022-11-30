/*
   Unix SMB/CIFS implementation.
   string substitution functions
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Gerald Carter   2006

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

#ifndef SUBSTITUTE_H
#define SUBSTITUTE_H

void set_remote_proto(const char *proto);
bool set_local_machine_name(const char *local_name, bool perm);
const char *get_local_machine_name(void);
bool set_remote_machine_name(const char *remote_name, bool perm);
const char *get_remote_machine_name(void);
void sub_set_socket_ids(const char *peeraddr, const char *peername,
			const char *sockaddr);
void set_current_user_info(const char *smb_name,
			   const char *unix_name,
			   const char *domain);
const char *get_current_username(void);
void standard_sub_basic(const char *smb_name,
			const char *domain_name,
			char *str,
			size_t len);
char *talloc_sub_basic(TALLOC_CTX *mem_ctx,
			const char *smb_name,
			const char *domain_name,
			const char *str);
char *talloc_sub_specified(TALLOC_CTX *mem_ctx,
			const char *input_string,
			const char *username,
			const char *grpname,
			const char *domain,
			uid_t uid,
			gid_t gid);
char *talloc_sub_advanced(TALLOC_CTX *ctx,
			const char *servicename,
			const char *user,
			const char *connectpath,
			gid_t gid,
			const char *str);
char *talloc_sub_full(TALLOC_CTX *ctx,
			const char *servicename,
			const char *user,
			const char *connectpath,
			gid_t gid,
			const char *smb_name,
			const char *domain_name,
			const char *str);
#endif

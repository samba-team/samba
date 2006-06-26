/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Rafal Szczesniak <mimir@samba.org> 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


struct libnet_CreateUser {
	struct {
		const char *user_name;
		const char *domain_name;
	} in;
	struct {
		const char *error_string;
	} out;
};


struct libnet_DeleteUser {
	struct {
		const char *user_name;
		const char *domain_name;
	} in;
	struct {
		const char *error_string;
	} out;
};


struct libnet_ModifyUser {
	struct {
		const char *user_name;
		const char *domain_name;

		const char *account_name;
		const char *full_name;
		const char *description;
		const char *comment;
		const char *logon_script;
		const char *profile_path;
		struct timeval *acct_expiry;
		struct timeval *allow_password_change;
		struct timeval *force_password_change;
		uint32_t acct_flags;
	} in;
	struct {
		const char *error_string;
	} out;
};

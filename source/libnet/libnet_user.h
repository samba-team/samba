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
		const char *home_directory;
		const char *home_drive;
		const char *comment;
		const char *logon_script;
		const char *profile_path;
		struct timeval *acct_expiry;
		struct timeval *allow_password_change;
		struct timeval *force_password_change;
		struct timeval *last_password_change;
		uint32_t acct_flags;
	} in;
	struct {
		const char *error_string;
	} out;
};


#define SET_FIELD_LSA_STRING(new, current, mod, field, flag) \
	if (new.field != NULL && \
	    !strequal_w(current->field.string, new.field)) { \
		\
		mod->field = talloc_strdup(mem_ctx, new.field);	\
		if (mod->field == NULL) return NT_STATUS_NO_MEMORY; \
		\
		mod->fields |= flag; \
	}

#define SET_FIELD_NTTIME(new, current, mod, field, flag) \
	if (new.field != 0) { \
		NTTIME newval = timeval_to_nttime(new.field); \
		if (newval != current->field) {	\
			mod->field = talloc_memdup(mem_ctx, new.field, sizeof(*new.field)); \
			if (mod->field == NULL) return NT_STATUS_NO_MEMORY; \
			mod->fields |= flag; \
		} \
	}


struct libnet_UserInfo {
	struct {
		const char *user_name;
		const char *domain_name;
	} in;
	struct {
		const char *account_name;
		const char *full_name;
		const char *description;
		const char *home_directory;
		const char *home_drive;
		const char *comment;
		const char *logon_script;
		const char *profile_path;
		struct timeval *acct_expiry;
		struct timeval *allow_password_change;
		struct timeval *force_password_change;
		struct timeval *last_logon;
		struct timeval *last_logoff;
		struct timeval *last_password_change;
		uint32_t acct_flags;
		
		const char *error_string;
	} out;
};


struct libnet_UserList {
	struct {
		const char *domain_name;
		int page_size;
		uint restore_index;
	} in;
	struct {
		int count;
		uint restore_index;

		struct userlist {
			const char *sid;
			const char *username;
		} *users;

		const char *error_string;
	} out;
};

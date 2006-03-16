/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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

/*
  composite function io definitions
*/

#include "librpc/gen_ndr/samr.h"

/*
 * Monitor structure and message types definitions. Composite function monitoring
 * allows client application to be notified on function progress. This enables
 * eg. gui client to display progress bars, status messages, etc.
 */


#define  rpc_create_user        (0x00000001)        /* userman.h */
#define  rpc_open_user          (0x00000002)        /* userinfo.h */
#define  rpc_query_user         (0x00000003)        /* userinfo.h */
#define  rpc_close_user         (0x00000004)        /* userinfo.h */
#define  rpc_lookup_name        (0x00000005)        /* userman.h */
#define  rpc_delete_user        (0x00000006)        /* userman.h */
#define  rpc_set_user           (0x00000007)        /* userman.h */

struct monitor_msg {
	uint32_t   type;
	void       *data;
	size_t     data_size;
};

struct libnet_rpc_userinfo {
	struct {
		struct policy_handle domain_handle;
		const char *sid;
		uint16_t level;
	} in;
	struct {
		union samr_UserInfo info;
	} out;
};


struct libnet_rpc_useradd {
	struct {
		struct policy_handle domain_handle;
		const char *username;
	} in;
	struct {
		struct policy_handle user_handle;
	} out;
};


struct libnet_rpc_userdel {
	struct {
		struct policy_handle domain_handle;
		const char *username;
	} in;
	struct {
		struct policy_handle user_handle;
	} out;
};


#define USERMOD_FIELD_ACCOUNT_NAME    ( 0x00000001 )
#define USERMOD_FIELD_FULL_NAME       ( 0x00000002 )
#define USERMOD_FIELD_DESCRIPTION     ( 0x00000010 )
#define USERMOD_FIELD_COMMENT         ( 0x00000020 )
#define USERMOD_FIELD_LOGON_SCRIPT    ( 0x00000100 )
#define USERMOD_FIELD_PROFILE_PATH    ( 0x00000200 )
#define USERMOD_FIELD_ACCT_EXPIRY     ( 0x00004000 )
#define USERMOD_FIELD_ALLOW_PASS_CHG  ( 0x00008000 )
#define USERMOD_FIELD_FORCE_PASS_CHG  ( 0x00010000 )
#define USERMOD_FIELD_ACCT_FLAGS      ( 0x00100000 )

struct libnet_rpc_usermod {
	struct {
		struct policy_handle domain_handle;
		const char *username;

		struct usermod_change {
			uint32_t fields;    /* bitmask field */

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
		} change;
	} in;
};


struct libnet_rpc_domain_open {
	struct {
		const char *domain_name;
		uint32_t access_mask;
	} in;
	struct {
		struct policy_handle domain_handle;
	} out;
};

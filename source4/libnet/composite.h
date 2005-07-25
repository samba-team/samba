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

#include "librpc/gen_ndr/ndr_samr.h"


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
#define USERMOD_FIELD_LOGON_SCRIPT    ( 0x00000100 )
#define USERMOD_FIELD_PROFILE_PATH    ( 0x00000200 )

struct libnet_rpc_usermod {
	struct {
		struct policy_handle domain_handle;
		const char *username;

		struct usermod_change {
			uint32_t fields;    /* bitmask field */

			const char *account_name;
			const char *full_name;
			const char *description;
			const char *logon_script;
			const char *profile_path;
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

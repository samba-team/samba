/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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

struct libnet_context {
	TALLOC_CTX *mem_ctx;
};

/* struct for doing a remote password change */

enum libnet_ChangePassword_level {
	LIBNET_CHANGE_PASSWORD_GENERIC,
	LIBNET_CHANGE_PASSWORD_RPC,
	LIBNET_CHANGE_PASSWORD_ADS,
	LIBNET_CHANGE_PASSWORD_RAP
};

union libnet_ChangePassword {
	struct {
		enum libnet_ChangePassword_level level;

		struct _libnet_ChangePassword_in {
			const char *account_name;
			const char *domain_name;
			const char *oldpassword;
			const char *newpassword;
		} in;

		struct _libnet_ChangePassword_out {
			const char *error_string;
		} out;
	} generic;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_ChangePassword_in in;
		struct _libnet_ChangePassword_out out;
	} rpc;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_ChangePassword_in in;
		struct _libnet_ChangePassword_out out;
	} ads;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_ChangePassword_in in;
		struct _libnet_ChangePassword_out out;
	} rap;
};

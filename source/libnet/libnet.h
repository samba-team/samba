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

	/* here we need:
	 * a client env context
	 * a user env context
	 */
	struct {
		const char *account_name;
		const char *domain_name;
		const char *password;
	} user;
};

/* struct and enum for finding a domain controller */
enum libnet_find_pdc_level {
	LIBNET_FIND_PDC_GENERIC
};

union libnet_find_pdc {
	/* find to a domains PDC */
	struct {
		enum libnet_find_pdc_level level;

		struct {
			const char *domain_name;
		} in;

		struct	{
			const char *pdc_name;
		} out;
	} generic;
};

/* struct and enum for connecting to a dcerpc inferface */
enum libnet_rpc_connect_level {
	LIBNET_RPC_CONNECT_PDC
};

union libnet_rpc_connect {
	/* connect to a domains PDC */
	struct {
		enum libnet_rpc_connect_level level;

		struct {
			const char *domain_name;
			const char *dcerpc_iface_name;
			const char *dcerpc_iface_uuid;
			uint32 dcerpc_iface_version;
		} in;

		struct	{
			struct dcerpc_pipe *dcerpc_pipe;
		} out;
	} pdc;
};


/* struct and enum for doing a remote password change */
enum libnet_ChangePassword_level {
	LIBNET_CHANGE_PASSWORD_GENERIC,
	LIBNET_CHANGE_PASSWORD_RPC,
	LIBNET_CHANGE_PASSWORD_KRB5,
	LIBNET_CHANGE_PASSWORD_LDAP,
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
	} krb5;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_ChangePassword_in in;
		struct _libnet_ChangePassword_out out;
	} ldap;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_ChangePassword_in in;
		struct _libnet_ChangePassword_out out;
	} rap;
};

/* struct and enum for doing a remote password set */
enum libnet_SetPassword_level {
	LIBNET_SET_PASSWORD_GENERIC,
	LIBNET_SET_PASSWORD_RPC,
	LIBNET_SET_PASSWORD_KRB5,
	LIBNET_SET_PASSWORD_LDAP,
	LIBNET_SET_PASSWORD_RAP
};

union libnet_SetPassword {
	struct {
		enum libnet_SetPassword_level level;

		struct _libnet_SetPassword_in {
			const char *account_name;
			const char *domain_name;
			const char *newpassword;
		} in;

		struct _libnet_SetPassword_out {
			const char *error_string;
		} out;
	} generic;

	struct {
		enum libnet_SetPassword_level level;
		struct _libnet_SetPassword_in in;
		struct _libnet_SetPassword_out out;
	} rpc;

	struct {
		enum libnet_SetPassword_level level;
		struct _libnet_SetPassword_in in;
		struct _libnet_SetPassword_out out;
	} krb5;

	struct {
		enum libnet_SetPassword_level level;
		struct _libnet_SetPassword_in in;
		struct _libnet_SetPassword_out out;
	} ldap;

	struct {
		enum libnet_ChangePassword_level level;
		struct _libnet_SetPassword_in in;
		struct _libnet_SetPassword_out out;
	} rap;
};

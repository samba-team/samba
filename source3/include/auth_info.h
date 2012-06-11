/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (c) 2012      Andreas Schneider <asn@samba.org>
 *
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _AUTH_INFO_H
#define _AUTH_INFO_H

struct user_auth_info {
	char *username;
	char *domain;
	char *password;
	bool got_pass;
	bool use_kerberos;
	int signing_state;
	bool smb_encrypt;
	bool use_machine_account;
	bool fallback_after_kerberos;
	bool use_ccache;
	bool use_pw_nt_hash;
};

struct user_auth_info *user_auth_info_init(TALLOC_CTX *mem_ctx);
const char *get_cmdline_auth_info_username(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_username(struct user_auth_info *auth_info,
				    const char *username);
const char *get_cmdline_auth_info_domain(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_domain(struct user_auth_info *auth_info,
				  const char *domain);
void set_cmdline_auth_info_password(struct user_auth_info *auth_info,
				    const char *password);
const char *get_cmdline_auth_info_password(const struct user_auth_info *auth_info);
bool set_cmdline_auth_info_signing_state(struct user_auth_info *auth_info,
					 const char *arg);
int get_cmdline_auth_info_signing_state(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_use_ccache(struct user_auth_info *auth_info,
				      bool b);
bool get_cmdline_auth_info_use_ccache(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_use_pw_nt_hash(struct user_auth_info *auth_info,
					  bool b);
bool get_cmdline_auth_info_use_pw_nt_hash(
	const struct user_auth_info *auth_info);
void set_cmdline_auth_info_use_kerberos(struct user_auth_info *auth_info,
					bool b);
bool get_cmdline_auth_info_use_kerberos(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_fallback_after_kerberos(struct user_auth_info *auth_info,
					bool b);
bool get_cmdline_auth_info_fallback_after_kerberos(const struct user_auth_info *auth_info);
void set_cmdline_auth_info_use_krb5_ticket(struct user_auth_info *auth_info);
void set_cmdline_auth_info_smb_encrypt(struct user_auth_info *auth_info);
void set_cmdline_auth_info_use_machine_account(struct user_auth_info *auth_info);
bool get_cmdline_auth_info_got_pass(const struct user_auth_info *auth_info);
bool get_cmdline_auth_info_smb_encrypt(const struct user_auth_info *auth_info);
bool get_cmdline_auth_info_use_machine_account(const struct user_auth_info *auth_info);
bool set_cmdline_auth_info_machine_account_creds(struct user_auth_info *auth_info);
void set_cmdline_auth_info_getpass(struct user_auth_info *auth_info);

#endif /* _AUTH_INFO_H */

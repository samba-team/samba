/*
   MIT-Samba4 library

   Copyright (c) 2010, Simo Sorce <idra@samba.org>

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

#ifndef _MIT_SAMBA_H
#define _MIT_SAMBA_H

struct mit_samba_context {
	struct auth_session_info *session_info;

	/* for compat with hdb plugin common code */
	krb5_context context;
	struct samba_kdc_db_context *db_ctx;
};

int mit_samba_context_init(struct mit_samba_context **_ctx);

void mit_samba_context_free(struct mit_samba_context *ctx);

int mit_samba_generate_salt(krb5_data *salt);

int mit_samba_generate_random_password(krb5_data *pwd);

int mit_samba_get_principal(struct mit_samba_context *ctx,
				   krb5_const_principal principal,
				   unsigned int kflags,
				   krb5_db_entry **_kentry);

int mit_samba_get_firstkey(struct mit_samba_context *ctx,
			   krb5_db_entry **_kentry);

int mit_samba_get_nextkey(struct mit_samba_context *ctx,
			  krb5_db_entry **_kentry);

int mit_samba_get_pac(struct mit_samba_context *smb_ctx,
		      krb5_context context,
		      krb5_db_entry *client,
		      krb5_keyblock *client_key,
		      krb5_pac *pac);

krb5_error_code mit_samba_reget_pac(struct mit_samba_context *ctx,
				    krb5_context context,
				    int flags,
				    krb5_const_principal client_principal,
				    krb5_db_entry *client,
				    krb5_db_entry *server,
				    krb5_db_entry *krbtgt,
				    krb5_keyblock *krbtgt_keyblock,
				    krb5_pac *pac);

int mit_samba_check_client_access(struct mit_samba_context *ctx,
				  krb5_db_entry *client,
				  const char *client_name,
				  krb5_db_entry *server,
				  const char *server_name,
				  const char *netbios_name,
				  bool password_change,
				  DATA_BLOB *e_data);

int mit_samba_check_s4u2proxy(struct mit_samba_context *ctx,
			      krb5_db_entry *kentry,
			      const char *target_name,
			      bool is_nt_enterprise_name);

int mit_samba_kpasswd_change_password(struct mit_samba_context *ctx,
				      char *pwd,
				      krb5_db_entry *db_entry);

void mit_samba_zero_bad_password_count(krb5_db_entry *db_entry);

void mit_samba_update_bad_password_count(krb5_db_entry *db_entry);

#endif /* _MIT_SAMBA_H */

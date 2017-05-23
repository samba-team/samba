/*
 * Unix SMB/CIFS implementation. 
 * secrets.tdb file format info
 * Copyright (C) Andrew Tridgell              2000
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.  
 */

#ifndef _SECRETS_H
#define _SECRETS_H

/* the first one is for the hashed password (NT4 style) the latter
   for plaintext (ADS)
*/
#define SECRETS_MACHINE_ACCT_PASS "SECRETS/$MACHINE.ACC"
#define SECRETS_MACHINE_PASSWORD "SECRETS/MACHINE_PASSWORD"
#define SECRETS_MACHINE_PASSWORD_PREV "SECRETS/MACHINE_PASSWORD.PREV"
#define SECRETS_MACHINE_LAST_CHANGE_TIME "SECRETS/MACHINE_LAST_CHANGE_TIME"
#define SECRETS_MACHINE_SEC_CHANNEL_TYPE "SECRETS/MACHINE_SEC_CHANNEL_TYPE"
#define SECRETS_MACHINE_TRUST_ACCOUNT_NAME "SECRETS/SECRETS_MACHINE_TRUST_ACCOUNT_NAME"
#define SECRETS_MACHINE_DOMAIN_INFO "SECRETS/MACHINE_DOMAIN_INFO"
/* this one is for storing trusted domain account password */
#define SECRETS_DOMTRUST_ACCT_PASS "SECRETS/$DOMTRUST.ACC"

/* Store the principal name used for Kerberos DES key salt under this key name. */
#define SECRETS_SALTING_PRINCIPAL "SECRETS/SALTING_PRINCIPAL"

/* The domain sid and our sid are stored here even though they aren't
   really secret. */
#define SECRETS_DOMAIN_SID    "SECRETS/SID"
#define SECRETS_SAM_SID       "SAM/SID"
#define SECRETS_PROTECT_IDS   "SECRETS/PROTECT/IDS"

/* The domain GUID and server GUID (NOT the same) are also not secret */
#define SECRETS_DOMAIN_GUID   "SECRETS/DOMGUID"
#define SECRETS_SERVER_GUID   "SECRETS/GUID"

#define SECRETS_LDAP_BIND_PW "SECRETS/LDAP_BIND_PW"

#define SECRETS_LOCAL_SCHANNEL_KEY "SECRETS/LOCAL_SCHANNEL_KEY"

/* Authenticated user info is stored in secrets.tdb under these keys */

#define SECRETS_AUTH_USER      "SECRETS/AUTH_USER"
#define SECRETS_AUTH_DOMAIN      "SECRETS/AUTH_DOMAIN"
#define SECRETS_AUTH_PASSWORD  "SECRETS/AUTH_PASSWORD"

/* structure for storing machine account password
   (ie. when samba server is member of a domain */
struct machine_acct_pass {
	uint8_t hash[16];
	time_t mod_time;
};

/*
 * Format of an OpenAFS keyfile
 */

#define SECRETS_AFS_MAXKEYS 8

struct afs_key {
	uint32_t kvno;
	char key[8];
};

struct afs_keyfile {
	uint32_t nkeys;
	struct afs_key entry[SECRETS_AFS_MAXKEYS];
};

#define SECRETS_AFS_KEYFILE "SECRETS/AFS_KEYFILE"

/* The following definitions come from passdb/secrets.c  */

bool secrets_init_path(const char *private_dir);
bool secrets_init(void);
struct db_context *secrets_db_ctx(void);
void secrets_shutdown(void);
void *secrets_fetch(const char *key, size_t *size);
bool secrets_store(const char *key, const void *data, size_t size);
bool secrets_delete_entry(const char *key);
bool secrets_delete(const char *key);

/* The following definitions come from passdb/machine_account_secrets.c */
bool secrets_mark_domain_protected(const char *domain);
bool secrets_clear_domain_protection(const char *domain);
bool secrets_store_domain_sid(const char *domain, const struct dom_sid  *sid);
bool secrets_fetch_domain_sid(const char *domain, struct dom_sid  *sid);
bool secrets_store_domain_guid(const char *domain, const struct GUID *guid);
bool secrets_fetch_domain_guid(const char *domain, struct GUID *guid);
enum netr_SchannelType get_default_sec_channel(void);
bool secrets_fetch_trust_account_password_legacy(const char *domain,
						 uint8_t ret_pwd[16],
						 time_t *pass_last_set_time,
						 enum netr_SchannelType *channel);
bool secrets_fetch_trust_account_password(const char *domain, uint8_t ret_pwd[16],
					  time_t *pass_last_set_time,
					  enum netr_SchannelType *channel);
bool secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
                                           struct dom_sid  *sid, time_t *pass_last_set_time);
bool secrets_store_trusted_domain_password(const char* domain, const char* pwd,
                                           const struct dom_sid  *sid);
struct libnet_JoinCtx;
NTSTATUS secrets_store_JoinCtx(const struct libnet_JoinCtx *r);
struct secrets_domain_info1;
struct secrets_domain_info1_change;
void secrets_debug_domain_info(int lvl, const struct secrets_domain_info1 *info,
			       const char *name);
char *secrets_domain_info_string(TALLOC_CTX *mem_ctx, const struct secrets_domain_info1 *info1,
				 const char *name, bool include_secrets);
NTSTATUS secrets_fetch_or_upgrade_domain_info(const char *domain,
					TALLOC_CTX *mem_ctx,
					struct secrets_domain_info1 **pinfo);
NTSTATUS secrets_prepare_password_change(const char *domain, const char *dcname,
					 const char *cleartext_unix,
					 TALLOC_CTX *mem_ctx,
					 struct secrets_domain_info1 **pinfo,
					 struct secrets_domain_info1_change **pprev);
NTSTATUS secrets_failed_password_change(const char *change_server,
					NTSTATUS local_status,
					NTSTATUS remote_status,
					const struct secrets_domain_info1 *info);
NTSTATUS secrets_defer_password_change(const char *change_server,
				       NTSTATUS local_status,
				       NTSTATUS remote_status,
				       const struct secrets_domain_info1 *info);
NTSTATUS secrets_finish_password_change(const char *change_server,
					NTTIME change_time,
					const struct secrets_domain_info1 *info);
bool secrets_delete_machine_password_ex(const char *domain, const char *realm);
bool secrets_delete_domain_sid(const char *domain);
char *secrets_fetch_prev_machine_password(const char *domain);
time_t secrets_fetch_pass_last_set_time(const char *domain);
char *secrets_fetch_machine_password(const char *domain,
				     time_t *pass_last_set_time,
				     enum netr_SchannelType *channel);
bool trusted_domain_password_delete(const char *domain);
bool secrets_store_ldap_pw(const char* dn, char* pw);
bool fetch_ldap_pw(char **dn, char** pw);
bool secrets_store_afs_keyfile(const char *cell, const struct afs_keyfile *keyfile);
bool secrets_fetch_afs_key(const char *cell, struct afs_key *result);
void secrets_fetch_ipc_userpass(char **username, char **domain, char **password);
bool secrets_store_generic(const char *owner, const char *key, const char *secret);
char *secrets_fetch_generic(const char *owner, const char *key);

bool secrets_store_machine_pw_sync(const char *pass, const char *oldpass, const char *domain,
				   const char *realm,
				   const char *salting_principal, uint32_t supported_enc_types,
				   const struct dom_sid *domain_sid, uint32_t last_change_time,
				   uint32_t secure_channel,
				   bool delete_join);

char* kerberos_standard_des_salt( void );
bool kerberos_secrets_store_des_salt( const char* salt );
char *kerberos_secrets_fetch_salt_princ(void);

/* The following definitions come from passdb/secrets_lsa.c  */
NTSTATUS lsa_secret_get(TALLOC_CTX *mem_ctx,
			const char *secret_name,
			DATA_BLOB *secret_current,
			NTTIME *secret_current_lastchange,
			DATA_BLOB *secret_old,
			NTTIME *secret_old_lastchange,
			struct security_descriptor **sd);
NTSTATUS lsa_secret_set(const char *secret_name,
			DATA_BLOB *secret_current,
			DATA_BLOB *secret_old,
			struct security_descriptor *sd);
NTSTATUS lsa_secret_delete(const char *secret_name);

#endif /* _SECRETS_H */

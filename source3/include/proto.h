/*
 * Unix SMB/CIFS implementation.
 * collected prototypes header
 *
 * frozen from "make proto" in May 2008
 *
 * Copyright (C) Michael Adam 2008
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

#ifndef _PROTO_H_
#define _PROTO_H_


/* The following definitions come from auth/auth.c  */

NTSTATUS smb_register_auth(int version, const char *name, auth_init_function init);
bool load_auth_module(struct auth_context *auth_context, 
		      const char *module, auth_methods **ret) ;
NTSTATUS make_auth_context_subsystem(struct auth_context **auth_context) ;
NTSTATUS make_auth_context_fixed(struct auth_context **auth_context, uchar chal[8]) ;

/* The following definitions come from auth/auth_builtin.c  */

NTSTATUS auth_builtin_init(void);

/* The following definitions come from auth/auth_compat.c  */

NTSTATUS check_plaintext_password(const char *smb_name,
				  DATA_BLOB plaintext_password,
				  struct auth_serversupplied_info **server_info);
bool password_ok(struct auth_context *actx, bool global_encrypted,
		 const char *session_workgroup,
		 const char *smb_name, DATA_BLOB password_blob);

/* The following definitions come from auth/auth_domain.c  */

void attempt_machine_password_change(void);
NTSTATUS auth_domain_init(void);

NTSTATUS auth_netlogond_init(void);

/* The following definitions come from auth/auth_ntlmssp.c  */

NTSTATUS auth_ntlmssp_steal_server_info(TALLOC_CTX *mem_ctx,
				struct auth_ntlmssp_state *auth_ntlmssp_state,
				struct auth_serversupplied_info **server_info);
void auth_ntlmssp_want_sign(struct auth_ntlmssp_state *auth_ntlmssp_state);
void auth_ntlmssp_want_seal(struct auth_ntlmssp_state *auth_ntlmssp_state);
NTSTATUS auth_ntlmssp_start(struct auth_ntlmssp_state **auth_ntlmssp_state);


/* The following definitions come from auth/auth_sam.c  */

NTSTATUS check_sam_security(const DATA_BLOB *challenge,
			    TALLOC_CTX *mem_ctx,
			    const struct auth_usersupplied_info *user_info,
			    struct auth_serversupplied_info **server_info);
NTSTATUS auth_sam_init(void);

/* The following definitions come from auth/auth_server.c  */

NTSTATUS auth_server_init(void);

/* The following definitions come from auth/auth_unix.c  */

NTSTATUS auth_unix_init(void);

/* The following definitions come from auth/auth_util.c  */

NTSTATUS make_user_info_map(struct auth_usersupplied_info **user_info,
			    const char *smb_name, 
			    const char *client_domain, 
			    const char *workstation_name,
 			    DATA_BLOB *lm_pwd, DATA_BLOB *nt_pwd,
 			    DATA_BLOB *lm_interactive_pwd, DATA_BLOB *nt_interactive_pwd,
			    DATA_BLOB *plaintext, 
			    bool encrypted);
bool make_user_info_netlogon_network(struct auth_usersupplied_info **user_info,
				     const char *smb_name, 
				     const char *client_domain, 
				     const char *workstation_name,
				     uint32 logon_parameters,
				     const uchar *lm_network_pwd,
				     int lm_pwd_len,
				     const uchar *nt_network_pwd,
				     int nt_pwd_len);
bool make_user_info_netlogon_interactive(struct auth_usersupplied_info **user_info,
					 const char *smb_name, 
					 const char *client_domain, 
					 const char *workstation_name,
					 uint32 logon_parameters,
					 const uchar chal[8], 
					 const uchar lm_interactive_pwd[16], 
					 const uchar nt_interactive_pwd[16], 
					 const uchar *dc_sess_key);
bool make_user_info_for_reply(struct auth_usersupplied_info **user_info,
			      const char *smb_name, 
			      const char *client_domain,
			      const uint8 chal[8],
			      DATA_BLOB plaintext_password);
NTSTATUS make_user_info_for_reply_enc(struct auth_usersupplied_info **user_info,
                                      const char *smb_name,
                                      const char *client_domain, 
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp);
bool make_user_info_guest(struct auth_usersupplied_info **user_info) ;
NTSTATUS make_server_info_sam(struct auth_serversupplied_info **server_info,
			      struct samu *sampass);
NTSTATUS create_local_token(struct auth_serversupplied_info *server_info);
NTSTATUS create_token_from_username(TALLOC_CTX *mem_ctx, const char *username,
				    bool is_guest,
				    uid_t *uid, gid_t *gid,
				    char **found_username,
				    struct nt_user_token **token);
bool user_in_group_sid(const char *username, const struct dom_sid *group_sid);
bool user_in_group(const char *username, const char *groupname);
NTSTATUS make_server_info_pw(struct auth_serversupplied_info **server_info,
                             char *unix_username,
			     struct passwd *pwd);
NTSTATUS make_serverinfo_from_username(TALLOC_CTX *mem_ctx,
				       const char *username,
				       bool is_guest,
				       struct auth_serversupplied_info **presult);
struct auth_serversupplied_info *copy_serverinfo(TALLOC_CTX *mem_ctx,
						 const struct auth_serversupplied_info *src);
bool init_guest_info(void);
bool init_system_info(void);
bool server_info_set_session_key(struct auth_serversupplied_info *info,
				 DATA_BLOB session_key);
NTSTATUS make_server_info_guest(TALLOC_CTX *mem_ctx,
				struct auth_serversupplied_info **server_info);
NTSTATUS make_server_info_system(TALLOC_CTX *mem_ctx,
				 struct auth_serversupplied_info **server_info);
bool copy_current_user(struct current_user *dst, struct current_user *src);
struct passwd *smb_getpwnam( TALLOC_CTX *mem_ctx, char *domuser,
			     fstring save_username, bool create );
NTSTATUS make_server_info_info3(TALLOC_CTX *mem_ctx, 
				const char *sent_nt_username,
				const char *domain,
				struct auth_serversupplied_info **server_info,
				struct netr_SamInfo3 *info3);
NTSTATUS make_server_info_wbcAuthUserInfo(TALLOC_CTX *mem_ctx,
					  const char *sent_nt_username,
					  const char *domain,
					  const struct wbcAuthUserInfo *info,
					  struct auth_serversupplied_info **server_info);
void free_user_info(struct auth_usersupplied_info **user_info);
bool make_auth_methods(struct auth_context *auth_context, auth_methods **auth_method) ;
bool is_trusted_domain(const char* dom_name);

/* The following definitions come from auth/user_info.c  */

NTSTATUS make_user_info(struct auth_usersupplied_info **user_info,
			const char *smb_name,
			const char *internal_username,
			const char *client_domain,
			const char *domain,
			const char *workstation_name,
			const DATA_BLOB *lm_pwd,
			const DATA_BLOB *nt_pwd,
			const DATA_BLOB *lm_interactive_pwd,
			const DATA_BLOB *nt_interactive_pwd,
			const DATA_BLOB *plaintext,
			bool encrypted);
void free_user_info(struct auth_usersupplied_info **user_info);

/* The following definitions come from auth/auth_winbind.c  */

NTSTATUS auth_winbind_init(void);

/* The following definitions come from auth/server_info.c  */

struct auth_serversupplied_info *make_server_info(TALLOC_CTX *mem_ctx);
NTSTATUS serverinfo_to_SamInfo2(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo2 *sam2);
NTSTATUS serverinfo_to_SamInfo3(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo3 *sam3);
NTSTATUS serverinfo_to_SamInfo6(struct auth_serversupplied_info *server_info,
				uint8_t *pipe_session_key,
				size_t pipe_session_key_len,
				struct netr_SamInfo6 *sam6);
NTSTATUS samu_to_SamInfo3(TALLOC_CTX *mem_ctx,
			  struct samu *samu,
			  const char *login_server,
			  struct netr_SamInfo3 **_info3,
			  struct extra_auth_info *extra);
struct netr_SamInfo3 *copy_netr_SamInfo3(TALLOC_CTX *mem_ctx,
					 struct netr_SamInfo3 *orig);
struct netr_SamInfo3 *wbcAuthUserInfo_to_netr_SamInfo3(TALLOC_CTX *mem_ctx,
					const struct wbcAuthUserInfo *info);

/* The following definitions come from auth/auth_wbc.c  */

NTSTATUS auth_wbc_init(void);

/* The following definitions come from auth/pampass.c  */

bool smb_pam_claim_session(char *user, char *tty, char *rhost);
bool smb_pam_close_session(char *user, char *tty, char *rhost);
NTSTATUS smb_pam_accountcheck(const char * user);
NTSTATUS smb_pam_passcheck(const char * user, const char * password);
bool smb_pam_passchange(const char * user, const char * oldpassword, const char * newpassword);
NTSTATUS smb_pam_accountcheck(const char * user);
bool smb_pam_claim_session(char *user, char *tty, char *rhost);
bool smb_pam_close_session(char *in_user, char *tty, char *rhost);

/* The following definitions come from auth/pass_check.c  */

void dfs_unlogin(void);
NTSTATUS pass_check(const struct passwd *pass, const char *user, const char *password, 
		    int pwlen, bool (*fn) (const char *, const char *), bool run_cracker);

/* The following definitions come from auth/token_util.c  */

bool nt_token_check_sid ( const struct dom_sid *sid, const NT_USER_TOKEN *token );
bool nt_token_check_domain_rid( NT_USER_TOKEN *token, uint32 rid );
NT_USER_TOKEN *get_root_nt_token( void );
NTSTATUS add_aliases(const struct dom_sid *domain_sid,
		     struct nt_user_token *token);
NTSTATUS create_builtin_users(const struct dom_sid *sid);
NTSTATUS create_builtin_administrators(const struct dom_sid *sid);
struct nt_user_token *create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const struct dom_sid *user_sid,
					    bool is_guest,
					    int num_groupsids,
					    const struct dom_sid *groupsids);
NTSTATUS create_local_nt_token_from_info3(TALLOC_CTX *mem_ctx,
					  bool is_guest,
					  struct netr_SamInfo3 *info3,
					  struct extra_auth_info *extra,
					  struct nt_user_token **ntok);
void debug_nt_user_token(int dbg_class, int dbg_lev, NT_USER_TOKEN *token);
void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid,
			   int n_groups, gid_t *groups);

/* The following definitions come from groupdb/mapping.c  */

NTSTATUS add_initial_entry(gid_t gid, const char *sid, enum lsa_SidType sid_name_use, const char *nt_name, const char *comment);
bool get_domain_group_from_sid(struct dom_sid sid, GROUP_MAP *map);
int smb_create_group(const char *unix_group, gid_t *new_gid);
int smb_delete_group(const char *unix_group);
int smb_set_primary_group(const char *unix_group, const char* unix_user);
int smb_add_user_group(const char *unix_group, const char *unix_user);
int smb_delete_user_group(const char *unix_group, const char *unix_user);
NTSTATUS pdb_default_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 struct dom_sid sid);
NTSTATUS pdb_default_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_default_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_default_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_default_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_default_delete_group_mapping_entry(struct pdb_methods *methods,
						   struct dom_sid sid);
NTSTATUS pdb_default_enum_group_mapping(struct pdb_methods *methods,
					   const struct dom_sid *sid, enum lsa_SidType sid_name_use,
					   GROUP_MAP **pp_rmap, size_t *p_num_entries,
					   bool unix_only);
NTSTATUS pdb_default_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid);
NTSTATUS pdb_default_delete_alias(struct pdb_methods *methods,
				  const struct dom_sid *sid);
NTSTATUS pdb_default_get_aliasinfo(struct pdb_methods *methods,
				   const struct dom_sid *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_set_aliasinfo(struct pdb_methods *methods,
				   const struct dom_sid *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_add_aliasmem(struct pdb_methods *methods,
				  const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_default_del_aliasmem(struct pdb_methods *methods,
				  const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_default_enum_aliasmem(struct pdb_methods *methods,
				   const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
				   struct dom_sid **pp_members,
				   size_t *p_num_members);
NTSTATUS pdb_default_alias_memberships(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const struct dom_sid *domain_sid,
				       const struct dom_sid *members,
				       size_t num_members,
				       uint32 **pp_alias_rids,
				       size_t *p_num_alias_rids);
NTSTATUS pdb_nop_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 struct dom_sid sid);
NTSTATUS pdb_nop_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_nop_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_nop_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_nop_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_nop_delete_group_mapping_entry(struct pdb_methods *methods,
						   struct dom_sid sid);
NTSTATUS pdb_nop_enum_group_mapping(struct pdb_methods *methods,
					   enum lsa_SidType sid_name_use,
					   GROUP_MAP **rmap, size_t *num_entries,
					   bool unix_only);
bool pdb_get_dom_grp_info(const struct dom_sid *sid, struct acct_info *info);
bool pdb_set_dom_grp_info(const struct dom_sid *sid, const struct acct_info *info);
NTSTATUS pdb_create_builtin_alias(uint32 rid);

/* The following definitions come from groupdb/mapping_ldb.c  */

const struct mapping_backend *groupdb_ldb_init(void);

/* The following definitions come from groupdb/mapping_tdb.c  */

const struct mapping_backend *groupdb_tdb_init(void);

/* The following definitions come from intl/lang_tdb.c  */

bool lang_tdb_init(const char *lang);
const char *lang_msg(const char *msgid);
void lang_msg_free(const char *msgstr);
char *lang_tdb_current(void);

/* The following definitions come from lib/access.c  */

bool client_match(const char *tok, const void *item);
bool list_match(const char **list,const void *item,
		bool (*match_fn)(const char *, const void *));
bool allow_access(const char **deny_list,
		const char **allow_list,
		const char *cname,
		const char *caddr);
bool check_access(int sock, const char **allow_list, const char **deny_list);

/* The following definitions come from passdb/account_pol.c  */

void account_policy_names_list(const char ***names, int *num_names);
const char *decode_account_policy_name(enum pdb_policy_type type);
const char *get_account_policy_attr(enum pdb_policy_type type);
const char *account_policy_get_desc(enum pdb_policy_type type);
enum pdb_policy_type account_policy_name_to_typenum(const char *name);
bool account_policy_get_default(enum pdb_policy_type type, uint32_t *val);
bool init_account_policy(void);
bool account_policy_get(enum pdb_policy_type type, uint32_t *value);
bool account_policy_set(enum pdb_policy_type type, uint32_t value);
bool cache_account_policy_set(enum pdb_policy_type type, uint32_t value);
bool cache_account_policy_get(enum pdb_policy_type type, uint32_t *value);
struct db_context *get_account_pol_db( void );

/* The following definitions come from lib/adt_tree.c  */


/* The following definitions come from lib/afs.c  */

char *afs_createtoken_str(const char *username, const char *cell);
bool afs_login(connection_struct *conn);
bool afs_login(connection_struct *conn);
char *afs_createtoken_str(const char *username, const char *cell);

/* The following definitions come from lib/afs_settoken.c  */

int afs_syscall( int subcall,
	  char * path,
	  int cmd,
	  char * cmarg,
	  int follow);
bool afs_settoken_str(const char *token_string);
bool afs_settoken_str(const char *token_string);

/* The following definitions come from lib/audit.c  */

const char *audit_category_str(uint32 category);
const char *audit_param_str(uint32 category);
const char *audit_description_str(uint32 category);
bool get_audit_category_from_param(const char *param, uint32 *audit_category);
const char *audit_policy_str(TALLOC_CTX *mem_ctx, uint32 policy);

/* The following definitions come from lib/bitmap.c  */

struct bitmap *bitmap_talloc(TALLOC_CTX *mem_ctx, int n);
int bitmap_copy(struct bitmap * const dst, const struct bitmap * const src);
bool bitmap_set(struct bitmap *bm, unsigned i);
bool bitmap_clear(struct bitmap *bm, unsigned i);
bool bitmap_query(struct bitmap *bm, unsigned i);
int bitmap_find(struct bitmap *bm, unsigned ofs);

/* The following definitions come from lib/charcnv.c  */

NTSTATUS smb_register_charset(struct charset_functions *funcs);
char lp_failed_convert_char(void);
void lazy_initialize_conv(void);
void gfree_charcnv(void);
void init_iconv(void);
size_t convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen, bool allow_bad_conv);
size_t unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen);
char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *s);
char *strupper_talloc(TALLOC_CTX *ctx, const char *s);
size_t unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen);
char *talloc_strdup_lower(TALLOC_CTX *ctx, const char *s);
char *strlower_talloc(TALLOC_CTX *ctx, const char *s);
size_t ucs2_align(const void *base_ptr, const void *p, int flags);
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags);
size_t push_ascii_fstring(void *dest, const char *src);
size_t push_ascii_nstring(void *dest, const char *src);
size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t pull_ascii_fstring(char *dest, const void *src);
size_t pull_ascii_nstring(char *dest, size_t dest_len, const void *src);
size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags);
size_t push_utf8_fstring(void *dest, const char *src);
bool push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size);
size_t pull_ucs2(const void *base_ptr, char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t pull_ucs2_base_talloc(TALLOC_CTX *ctx,
			const void *base_ptr,
			char **ppdest,
			const void *src,
			size_t src_len,
			int flags);
size_t pull_ucs2_fstring(char *dest, const void *src);
bool push_ucs2_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src,
		      size_t *converted_size);
bool pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size);
bool pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src,
		      size_t *converted_size);
bool pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		       size_t *converted_size);
size_t push_string_check_fn(const char *function, unsigned int line,
			    void *dest, const char *src,
			    size_t dest_len, int flags);
size_t push_string_base(const char *function, unsigned int line,
			const char *base, uint16 flags2, 
			void *dest, const char *src,
			size_t dest_len, int flags);
size_t pull_string_fn(const char *function,
			unsigned int line,
			const void *base_ptr,
			uint16 smb_flags2,
			char *dest,
			const void *src,
			size_t dest_len,
			size_t src_len,
			int flags);
size_t pull_string_talloc_fn(const char *function,
			unsigned int line,
			TALLOC_CTX *ctx,
			const void *base_ptr,
			uint16 smb_flags2,
			char **ppdest,
			const void *src,
			size_t src_len,
			int flags);
size_t align_string(const void *base_ptr, const char *p, int flags);
codepoint_t next_codepoint(const char *str, size_t *size);

/* The following definitions come from lib/clobber.c  */

void clobber_region(const char *fn, unsigned int line, char *dest, size_t len);

/* The following definitions come from lib/conn_tdb.c  */

struct db_record *connections_fetch_entry(TALLOC_CTX *mem_ctx,
					  connection_struct *conn,
					  const char *name);
int connections_traverse(int (*fn)(struct db_record *rec,
				   void *private_data),
			 void *private_data);
int connections_forall(int (*fn)(struct db_record *rec,
				 const struct connections_key *key,
				 const struct connections_data *data,
				 void *private_data),
		       void *private_data);
int connections_forall_read(int (*fn)(const struct connections_key *key,
				      const struct connections_data *data,
				      void *private_data),
			    void *private_data);
bool connections_init(bool rw);

/* The following definitions come from lib/dbwrap_util.c  */

int32_t dbwrap_fetch_int32(struct db_context *db, const char *keystr);
int dbwrap_store_int32(struct db_context *db, const char *keystr, int32_t v);
bool dbwrap_fetch_uint32(struct db_context *db, const char *keystr,
			 uint32_t *val);
int dbwrap_store_uint32(struct db_context *db, const char *keystr, uint32_t v);
NTSTATUS dbwrap_change_uint32_atomic(struct db_context *db, const char *keystr,
				     uint32_t *oldval, uint32_t change_val);
NTSTATUS dbwrap_trans_change_uint32_atomic(struct db_context *db,
					   const char *keystr,
					   uint32_t *oldval,
					   uint32_t change_val);
NTSTATUS dbwrap_change_int32_atomic(struct db_context *db, const char *keystr,
				    int32_t *oldval, int32_t change_val);
NTSTATUS dbwrap_trans_change_int32_atomic(struct db_context *db,
					  const char *keystr,
					  int32_t *oldval,
					  int32_t change_val);
NTSTATUS dbwrap_trans_store(struct db_context *db, TDB_DATA key, TDB_DATA dbuf,
			    int flag);
NTSTATUS dbwrap_trans_delete(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_trans_store_int32(struct db_context *db, const char *keystr,
				  int32_t v);
NTSTATUS dbwrap_trans_store_uint32(struct db_context *db, const char *keystr,
				   uint32_t v);
NTSTATUS dbwrap_trans_store_bystring(struct db_context *db, const char *key,
				     TDB_DATA data, int flags);
NTSTATUS dbwrap_trans_delete_bystring(struct db_context *db, const char *key);
NTSTATUS dbwrap_trans_do(struct db_context *db,
			 NTSTATUS (*action)(struct db_context *, void *),
			 void *private_data);
NTSTATUS dbwrap_delete_bystring_upper(struct db_context *db, const char *key);
NTSTATUS dbwrap_store_bystring_upper(struct db_context *db, const char *key,
				     TDB_DATA data, int flags);
TDB_DATA dbwrap_fetch_bystring_upper(struct db_context *db, TALLOC_CTX *mem_ctx,
				     const char *key);

/* The following definitions come from lib/debug.c  */

void gfree_debugsyms(void);
const char *debug_classname_from_index(int ndx);
int debug_add_class(const char *classname);
int debug_lookup_classname(const char *classname);
bool debug_parse_levels(const char *params_str);
void debug_message(struct messaging_context *msg_ctx, void *private_data, uint32_t msg_type, struct server_id src, DATA_BLOB *data);
void debug_init(void);
void debug_register_msgs(struct messaging_context *msg_ctx);
void setup_logging(const char *pname, bool interactive);
void setup_logging_stdout( void );
void debug_set_logfile(const char *name);
bool reopen_logs( void );
void force_check_log_size( void );
bool need_to_check_log_size( void );
void check_log_size( void );
void dbgflush( void );
bool dbghdrclass(int level, int cls, const char *location, const char *func);
bool dbghdr(int level, const char *location, const char *func);

/* The following definitions come from lib/display_sec.c  */

char *get_sec_mask_str(TALLOC_CTX *ctx, uint32 type);
void display_sec_access(uint32_t *info);
void display_sec_ace_flags(uint8_t flags);
void display_sec_ace(struct security_ace *ace);
void display_sec_acl(struct security_acl *sec_acl);
void display_acl_type(uint16 type);
void display_sec_desc(struct security_descriptor *sec);

/* The following definitions come from lib/dmallocmsg.c  */

void register_dmalloc_msgs(struct messaging_context *msg_ctx);

/* The following definitions come from lib/dprintf.c  */

void display_set_stderr(void);

/* The following definitions come from lib/errmap_unix.c  */

NTSTATUS map_nt_error_from_unix(int unix_error);
int map_errno_from_nt_status(NTSTATUS status);

/* The following definitions come from lib/fault.c  */
void fault_setup(void (*fn)(void *));
void dump_core_setup(const char *progname);

/* The following definitions come from lib/file_id.c  */

struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf);
bool file_id_equal(const struct file_id *id1, const struct file_id *id2);
const char *file_id_string_tos(const struct file_id *id);
void push_file_id_16(char *buf, const struct file_id *id);
void push_file_id_24(char *buf, const struct file_id *id);
void pull_file_id_24(char *buf, struct file_id *id);

/* The following definitions come from lib/gencache.c  */

bool gencache_set(const char *keystr, const char *value, time_t timeout);
bool gencache_del(const char *keystr);
bool gencache_get(const char *keystr, char **valstr, time_t *timeout);
bool gencache_get_data_blob(const char *keystr, DATA_BLOB *blob,
			    time_t *timeout, bool *was_expired);
bool gencache_stabilize(void);
bool gencache_set_data_blob(const char *keystr, const DATA_BLOB *blob, time_t timeout);
void gencache_iterate(void (*fn)(const char* key, const char *value, time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern);

/* The following definitions come from lib/interface.c  */

bool ismyaddr(const struct sockaddr *ip);
bool ismyip_v4(struct in_addr ip);
bool is_local_net(const struct sockaddr *from);
void setup_linklocal_scope_id(struct sockaddr *pss);
bool is_local_net_v4(struct in_addr from);
int iface_count(void);
int iface_count_v4_nl(void);
const struct in_addr *first_ipv4_iface(void);
struct interface *get_interface(int n);
const struct sockaddr_storage *iface_n_sockaddr_storage(int n);
const struct in_addr *iface_n_ip_v4(int n);
const struct in_addr *iface_n_bcast_v4(int n);
const struct sockaddr_storage *iface_n_bcast(int n);
const struct sockaddr_storage *iface_ip(const struct sockaddr *ip);
bool iface_local(const struct sockaddr *ip);
void load_interfaces(void);
void gfree_interfaces(void);
bool interfaces_changed(void);

/* The following definitions come from lib/ldap_debug_handler.c  */

void init_ldap_debugging(void);

/* The following definitions come from lib/ldap_escape.c  */

char *escape_ldap_string(TALLOC_CTX *mem_ctx, const char *s);
char *escape_rdn_val_string_alloc(const char *s);

/* The following definitions come from lib/module.c  */

NTSTATUS smb_load_module(const char *module_name);
int smb_load_modules(const char **modules);
NTSTATUS smb_probe_module(const char *subsystem, const char *module);
NTSTATUS smb_load_module(const char *module_name);
int smb_load_modules(const char **modules);
NTSTATUS smb_probe_module(const char *subsystem, const char *module);
void init_modules(void);

/* The following definitions come from lib/ms_fnmatch.c  */

int ms_fnmatch(const char *pattern, const char *string, bool translate_pattern,
	       bool is_case_sensitive);
int gen_fnmatch(const char *pattern, const char *string);

/* The following definitions come from lib/pam_errors.c  */

NTSTATUS pam_to_nt_status(int pam_error);
int nt_status_to_pam(NTSTATUS nt_status);
NTSTATUS pam_to_nt_status(int pam_error);
int nt_status_to_pam(NTSTATUS nt_status);

/* The following definitions come from lib/pidfile.c  */

pid_t pidfile_pid(const char *name);
void pidfile_create(const char *program_name);
void pidfile_unlink(void);

/* The following definitions come from lib/popt_common.c  */

void popt_common_set_auth_info(struct user_auth_info *auth_info);

/* The following definitions come from lib/privileges.c  */

bool get_privileges_for_sids(SE_PRIV *privileges, struct dom_sid *slist, int scount);
NTSTATUS privilege_enumerate_accounts(struct dom_sid **sids, int *num_sids);
NTSTATUS privilege_enum_sids(const SE_PRIV *mask, TALLOC_CTX *mem_ctx,
			     struct dom_sid **sids, int *num_sids);
bool grant_privilege(const struct dom_sid *sid, const SE_PRIV *priv_mask);
bool grant_privilege_by_name(struct dom_sid *sid, const char *name);
bool revoke_privilege(const struct dom_sid *sid, const SE_PRIV *priv_mask);
bool revoke_all_privileges( struct dom_sid *sid );
bool revoke_privilege_by_name(struct dom_sid *sid, const char *name);
NTSTATUS privilege_create_account(const struct dom_sid *sid );
NTSTATUS privilege_delete_account(const struct dom_sid *sid);
NTSTATUS privilege_set_init(PRIVILEGE_SET *priv_set);
NTSTATUS privilege_set_init_by_ctx(TALLOC_CTX *mem_ctx, PRIVILEGE_SET *priv_set);
void privilege_set_free(PRIVILEGE_SET *priv_set);
NTSTATUS dup_luid_attr(TALLOC_CTX *mem_ctx, struct lsa_LUIDAttribute **new_la, struct lsa_LUIDAttribute *old_la, int count);
bool is_privileged_sid( const struct dom_sid *sid );
bool grant_all_privileges( const struct dom_sid *sid );

/* The following definitions come from lib/privileges_basic.c  */

bool se_priv_copy( SE_PRIV *dst, const SE_PRIV *src );
bool se_priv_put_all_privileges(SE_PRIV *mask);
void se_priv_add( SE_PRIV *mask, const SE_PRIV *addpriv );
void se_priv_remove( SE_PRIV *mask, const SE_PRIV *removepriv );
bool se_priv_equal( const SE_PRIV *mask1, const SE_PRIV *mask2 );
bool se_priv_from_name( const char *name, SE_PRIV *mask );
void dump_se_priv( int dbg_cl, int dbg_lvl, const SE_PRIV *mask );
bool is_privilege_assigned(const SE_PRIV *privileges,
			   const SE_PRIV *check);
const char* get_privilege_dispname( const char *name );
bool user_has_privileges(const NT_USER_TOKEN *token, const SE_PRIV *privilege);
bool user_has_any_privilege(NT_USER_TOKEN *token, const SE_PRIV *privilege);
int count_all_privileges( void );
struct lsa_LUIDAttribute get_privilege_luid( SE_PRIV *mask );
const char *luid_to_privilege_name(const struct lsa_LUID *set);
bool se_priv_to_privilege_set( PRIVILEGE_SET *set, SE_PRIV *mask );
bool privilege_set_to_se_priv( SE_PRIV *mask, struct lsa_PrivilegeSet *privset );

/* The following definitions come from lib/readline.c  */

void smb_readline_done(void);
char *smb_readline(const char *prompt, void (*callback)(void),
		   char **(completion_fn)(const char *text, int start, int end));
const char *smb_readline_get_line_buffer(void);
void smb_readline_ca_char(char c);
int cmd_history(void);

/* The following definitions come from lib/recvfile.c  */

ssize_t sys_recvfile(int fromfd,
			int tofd,
			SMB_OFF_T offset,
			size_t count);
ssize_t sys_recvfile(int fromfd,
			int tofd,
			SMB_OFF_T offset,
			size_t count);
ssize_t drain_socket(int sockfd, size_t count);

/* The following definitions come from lib/secdesc.c  */

uint32_t get_sec_info(const struct security_descriptor *sd);
struct security_descriptor *sec_desc_merge(TALLOC_CTX *ctx, struct security_descriptor *new_sdb, struct security_descriptor *old_sdb);
struct sec_desc_buf *sec_desc_merge_buf(TALLOC_CTX *ctx, struct sec_desc_buf *new_sdb, struct sec_desc_buf *old_sdb);
struct security_descriptor *make_sec_desc(TALLOC_CTX *ctx,
			enum security_descriptor_revision revision,
			uint16 type,
			const struct dom_sid *owner_sid, const struct dom_sid *grp_sid,
			struct security_acl *sacl, struct security_acl *dacl, size_t *sd_size);
struct security_descriptor *dup_sec_desc(TALLOC_CTX *ctx, const struct security_descriptor *src);
NTSTATUS marshall_sec_desc(TALLOC_CTX *mem_ctx,
			   struct security_descriptor *secdesc,
			   uint8 **data, size_t *len);
NTSTATUS marshall_sec_desc_buf(TALLOC_CTX *mem_ctx,
			       struct sec_desc_buf *secdesc_buf,
			       uint8_t **data, size_t *len);
NTSTATUS unmarshall_sec_desc(TALLOC_CTX *mem_ctx, uint8 *data, size_t len,
			     struct security_descriptor **psecdesc);
NTSTATUS unmarshall_sec_desc_buf(TALLOC_CTX *mem_ctx, uint8_t *data, size_t len,
				 struct sec_desc_buf **psecdesc_buf);
struct security_descriptor *make_standard_sec_desc(TALLOC_CTX *ctx, const struct dom_sid *owner_sid, const struct dom_sid *grp_sid,
				 struct security_acl *dacl, size_t *sd_size);
struct sec_desc_buf *make_sec_desc_buf(TALLOC_CTX *ctx, size_t len, struct security_descriptor *sec_desc);
struct sec_desc_buf *dup_sec_desc_buf(TALLOC_CTX *ctx, struct sec_desc_buf *src);
NTSTATUS sec_desc_add_sid(TALLOC_CTX *ctx, struct security_descriptor **psd, struct dom_sid *sid, uint32 mask, size_t *sd_size);
NTSTATUS sec_desc_mod_sid(struct security_descriptor *sd, struct dom_sid *sid, uint32 mask);
NTSTATUS sec_desc_del_sid(TALLOC_CTX *ctx, struct security_descriptor **psd, struct dom_sid *sid, size_t *sd_size);
bool sd_has_inheritable_components(const struct security_descriptor *parent_ctr, bool container);
NTSTATUS se_create_child_secdesc(TALLOC_CTX *ctx,
                                        struct security_descriptor **ppsd,
					size_t *psize,
                                        const struct security_descriptor *parent_ctr,
                                        const struct dom_sid *owner_sid,
                                        const struct dom_sid *group_sid,
                                        bool container);
NTSTATUS se_create_child_secdesc_buf(TALLOC_CTX *ctx,
					struct sec_desc_buf **ppsdb,
					const struct security_descriptor *parent_ctr,
					bool container);

/* The following definitions come from lib/select.c  */

void sys_select_signal(char c);
int sys_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval);
int sys_select_intr(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval);

/* The following definitions come from lib/sendfile.c  */

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);

/* The following definitions come from lib/server_mutex.c  */

struct named_mutex *grab_named_mutex(TALLOC_CTX *mem_ctx, const char *name,
				     int timeout);

/* The following definitions come from lib/sharesec.c  */

bool share_info_db_init(void);
struct security_descriptor *get_share_security_default( TALLOC_CTX *ctx, size_t *psize, uint32 def_access);
struct security_descriptor *get_share_security( TALLOC_CTX *ctx, const char *servicename,
			      size_t *psize);
bool set_share_security(const char *share_name, struct security_descriptor *psd);
bool delete_share_security(const char *servicename);
bool share_access_check(const NT_USER_TOKEN *token, const char *sharename,
			uint32 desired_access);
bool parse_usershare_acl(TALLOC_CTX *ctx, const char *acl_str, struct security_descriptor **ppsd);

/* The following definitions come from lib/smbldap.c  */

int smb_ldap_start_tls(LDAP *ldap_struct, int version);
int smb_ldap_setup_full_conn(LDAP **ldap_struct, const char *uri);
int smbldap_search(struct smbldap_state *ldap_state, 
		   const char *base, int scope, const char *filter, 
		   const char *attrs[], int attrsonly, 
		   LDAPMessage **res);
int smbldap_search_paged(struct smbldap_state *ldap_state, 
			 const char *base, int scope, const char *filter, 
			 const char **attrs, int attrsonly, int pagesize,
			 LDAPMessage **res, void **cookie);
int smbldap_modify(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[]);
int smbldap_add(struct smbldap_state *ldap_state, const char *dn, LDAPMod *attrs[]);
int smbldap_delete(struct smbldap_state *ldap_state, const char *dn);
int smbldap_extended_operation(struct smbldap_state *ldap_state, 
			       LDAP_CONST char *reqoid, struct berval *reqdata, 
			       LDAPControl **serverctrls, LDAPControl **clientctrls, 
			       char **retoidp, struct berval **retdatap);
int smbldap_search_suffix (struct smbldap_state *ldap_state,
			   const char *filter, const char **search_attr,
			   LDAPMessage ** result);
void smbldap_free_struct(struct smbldap_state **ldap_state) ;
NTSTATUS smbldap_init(TALLOC_CTX *mem_ctx, struct event_context *event_ctx,
		      const char *location,
		      struct smbldap_state **smbldap_state);
bool smbldap_has_control(LDAP *ld, const char *control);
bool smbldap_has_extension(LDAP *ld, const char *extension);
bool smbldap_has_naming_context(LDAP *ld, const char *naming_context);
bool smbldap_set_creds(struct smbldap_state *ldap_state, bool anon, const char *dn, const char *secret);

/* The following definitions come from lib/smbldap_util.c  */

NTSTATUS smbldap_search_domain_info(struct smbldap_state *ldap_state,
                                    LDAPMessage ** result, const char *domain_name,
                                    bool try_add);

/* The following definitions come from lib/smbrun.c  */

int smbrun_no_sanitize(const char *cmd, int *outfd);
int smbrun(const char *cmd, int *outfd);
int smbrunsecret(const char *cmd, const char *secret);

/* The following definitions come from lib/sock_exec.c  */

int sock_exec(const char *prog);

/* The following definitions come from lib/substitute.c  */

void free_local_machine_name(void);
bool set_local_machine_name(const char *local_name, bool perm);
const char *get_local_machine_name(void);
bool set_remote_machine_name(const char *remote_name, bool perm);
const char *get_remote_machine_name(void);
void sub_set_smb_name(const char *name);
void set_current_user_info(const char *smb_name, const char *unix_name,
			   const char *domain);
const char *get_current_username(void);
void standard_sub_basic(const char *smb_name, const char *domain_name,
			char *str, size_t len);
char *talloc_sub_basic(TALLOC_CTX *mem_ctx, const char *smb_name,
		       const char *domain_name, const char *str);
char *talloc_sub_specified(TALLOC_CTX *mem_ctx,
			const char *input_string,
			const char *username,
			const char *domain,
			uid_t uid,
			gid_t gid);
char *talloc_sub_advanced(TALLOC_CTX *mem_ctx,
			  const char *servicename, const char *user,
			  const char *connectpath, gid_t gid,
			  const char *smb_name, const char *domain_name,
			  const char *str);
void standard_sub_advanced(const char *servicename, const char *user,
			   const char *connectpath, gid_t gid,
			   const char *smb_name, const char *domain_name,
			   char *str, size_t len);
char *standard_sub_conn(TALLOC_CTX *ctx, connection_struct *conn, const char *str);

/* The following definitions come from lib/sysacls.c  */

int sys_acl_get_entry(SMB_ACL_T acl_d, int entry_id, SMB_ACL_ENTRY_T *entry_p);
int sys_acl_get_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *type_p);
int sys_acl_get_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p);
void *sys_acl_get_qualifier(SMB_ACL_ENTRY_T entry_d);
int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset_d);
int sys_acl_add_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm);
int sys_acl_get_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm);
char *sys_acl_to_text(SMB_ACL_T acl_d, ssize_t *len_p);
SMB_ACL_T sys_acl_init(int count);
int sys_acl_create_entry(SMB_ACL_T *acl_p, SMB_ACL_ENTRY_T *entry_p);
int sys_acl_set_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T tag_type);
int sys_acl_set_qualifier(SMB_ACL_ENTRY_T entry_d, void *qual_p);
int sys_acl_set_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T permset_d);
int sys_acl_free_text(char *text);
int sys_acl_free_acl(SMB_ACL_T acl_d) ;
int sys_acl_free_qualifier(void *qual, SMB_ACL_TAG_T tagtype);
int sys_acl_valid(SMB_ACL_T acl_d);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle, 
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
SMB_ACL_T sys_acl_get_file(vfs_handle_struct *handle,
			   const char *path_p, SMB_ACL_TYPE_T type);
SMB_ACL_T sys_acl_get_fd(vfs_handle_struct *handle, files_struct *fsp);
int sys_acl_set_file(vfs_handle_struct *handle,
		     const char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d);
int sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
		   SMB_ACL_T acl_d);
int sys_acl_delete_def_file(vfs_handle_struct *handle,
			    const char *path);
int no_acl_syscall_error(int err);

/* The following definitions come from lib/sysquotas.c  */

int sys_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/sysquotas_*.c  */

int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/system.c  */

void *sys_memalign( size_t align, size_t size );
int sys_usleep(long usecs);
ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t sys_pread(int fd, void *buf, size_t count, SMB_OFF_T off);
ssize_t sys_pwrite(int fd, const void *buf, size_t count, SMB_OFF_T off);
ssize_t sys_send(int s, const void *msg, size_t len, int flags);
ssize_t sys_sendto(int s,  const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
ssize_t sys_recv(int fd, void *buf, size_t count, int flags);
ssize_t sys_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int sys_fcntl_ptr(int fd, int cmd, void *arg);
int sys_fcntl_long(int fd, int cmd, long arg);
void update_stat_ex_mtime(struct stat_ex *dst, struct timespec write_ts);
void update_stat_ex_create_time(struct stat_ex *dst, struct timespec create_time);
int sys_stat(const char *fname, SMB_STRUCT_STAT *sbuf,
	     bool fake_dir_create_times);
int sys_fstat(int fd, SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_ftruncate(int fd, SMB_OFF_T offset);
int sys_posix_fallocate(int fd, SMB_OFF_T offset, SMB_OFF_T len);
SMB_OFF_T sys_lseek(int fd, SMB_OFF_T offset, int whence);
int sys_fseek(FILE *fp, SMB_OFF_T offset, int whence);
SMB_OFF_T sys_ftell(FILE *fp);
int sys_creat(const char *path, mode_t mode);
int sys_open(const char *path, int oflag, mode_t mode);
FILE *sys_fopen(const char *path, const char *type);
void kernel_flock(int fd, uint32 share_mode, uint32 access_mask);
SMB_STRUCT_DIR *sys_opendir(const char *name);
SMB_STRUCT_DIRENT *sys_readdir(SMB_STRUCT_DIR *dirp);
void sys_seekdir(SMB_STRUCT_DIR *dirp, long offset);
long sys_telldir(SMB_STRUCT_DIR *dirp);
void sys_rewinddir(SMB_STRUCT_DIR *dirp);
int sys_closedir(SMB_STRUCT_DIR *dirp);
int sys_mknod(const char *path, mode_t mode, SMB_DEV_T dev);
int sys_waitpid(pid_t pid,int *status,int options);
char *sys_getwd(char *s);
void set_effective_capability(enum smbd_capability capability);
void drop_effective_capability(enum smbd_capability capability);
long sys_random(void);
void sys_srandom(unsigned int seed);
int groups_max(void);
int sys_getgroups(int setlen, gid_t *gidset);
int sys_setgroups(gid_t UNUSED(primary_gid), int setlen, gid_t *gidset);
void sys_setpwent(void);
struct passwd *sys_getpwent(void);
void sys_endpwent(void);
struct passwd *sys_getpwnam(const char *name);
struct passwd *sys_getpwuid(uid_t uid);
struct group *sys_getgrnam(const char *name);
struct group *sys_getgrgid(gid_t gid);
int sys_popen(const char *command);
int sys_pclose(int fd);
ssize_t sys_getxattr (const char *path, const char *name, void *value, size_t size);
ssize_t sys_lgetxattr (const char *path, const char *name, void *value, size_t size);
ssize_t sys_fgetxattr (int filedes, const char *name, void *value, size_t size);
ssize_t sys_listxattr (const char *path, char *list, size_t size);
ssize_t sys_llistxattr (const char *path, char *list, size_t size);
ssize_t sys_flistxattr (int filedes, char *list, size_t size);
int sys_removexattr (const char *path, const char *name);
int sys_lremovexattr (const char *path, const char *name);
int sys_fremovexattr (int filedes, const char *name);
int sys_setxattr (const char *path, const char *name, const void *value, size_t size, int flags);
int sys_lsetxattr (const char *path, const char *name, const void *value, size_t size, int flags);
int sys_fsetxattr (int filedes, const char *name, const void *value, size_t size, int flags);
uint32 unix_dev_major(SMB_DEV_T dev);
uint32 unix_dev_minor(SMB_DEV_T dev);
int sys_aio_read(SMB_STRUCT_AIOCB *aiocb);
int sys_aio_write(SMB_STRUCT_AIOCB *aiocb);
ssize_t sys_aio_return(SMB_STRUCT_AIOCB *aiocb);
int sys_aio_cancel(int fd, SMB_STRUCT_AIOCB *aiocb);
int sys_aio_error(const SMB_STRUCT_AIOCB *aiocb);
int sys_aio_fsync(int op, SMB_STRUCT_AIOCB *aiocb);
int sys_aio_suspend(const SMB_STRUCT_AIOCB * const cblist[], int n, const struct timespec *timeout);
int sys_aio_read(SMB_STRUCT_AIOCB *aiocb);
int sys_aio_write(SMB_STRUCT_AIOCB *aiocb);
ssize_t sys_aio_return(SMB_STRUCT_AIOCB *aiocb);
int sys_aio_cancel(int fd, SMB_STRUCT_AIOCB *aiocb);
int sys_aio_error(const SMB_STRUCT_AIOCB *aiocb);
int sys_aio_fsync(int op, SMB_STRUCT_AIOCB *aiocb);
int sys_aio_suspend(const SMB_STRUCT_AIOCB * const cblist[], int n, const struct timespec *timeout);
int sys_getpeereid( int s, uid_t *uid);
int sys_getnameinfo(const struct sockaddr *psa,
			socklen_t salen,
			char *host,
			size_t hostlen,
			char *service,
			size_t servlen,
			int flags);
int sys_connect(int fd, const struct sockaddr * addr);

/* The following definitions come from lib/system_smbd.c  */

bool getgroups_unix_user(TALLOC_CTX *mem_ctx, const char *user,
			 gid_t primary_gid,
			 gid_t **ret_groups, size_t *p_ngroups);

/* The following definitions come from lib/tallocmsg.c  */

void register_msg_pool_usage(struct messaging_context *msg_ctx);

/* The following definitions come from lib/time.c  */

void push_dos_date(uint8_t *buf, int offset, time_t unixdate, int zone_offset);
void push_dos_date2(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
void push_dos_date3(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
time_t pull_dos_date(const uint8_t *date_ptr, int zone_offset);
time_t pull_dos_date2(const uint8_t *date_ptr, int zone_offset);
time_t pull_dos_date3(const uint8_t *date_ptr, int zone_offset);
uint32_t convert_time_t_to_uint32_t(time_t t);
time_t convert_uint32_t_to_time_t(uint32_t u);
bool nt_time_is_zero(const NTTIME *nt);
time_t generalized_to_unix_time(const char *str);
int get_server_zone_offset(void);
int set_server_zone_offset(time_t t);
char *timeval_string(TALLOC_CTX *ctx, const struct timeval *tp, bool hires);
char *current_timestring(TALLOC_CTX *ctx, bool hires);
void srv_put_dos_date(char *buf,int offset,time_t unixdate);
void srv_put_dos_date2(char *buf,int offset, time_t unixdate);
void srv_put_dos_date3(char *buf,int offset,time_t unixdate);
void round_timespec(enum timestamp_set_resolution res, struct timespec *ts);
void put_long_date_timespec(enum timestamp_set_resolution res, char *p, struct timespec ts);
void put_long_date(char *p, time_t t);
void dos_filetime_timespec(struct timespec *tsp);
time_t make_unix_date2(const void *date_ptr, int zone_offset);
time_t make_unix_date3(const void *date_ptr, int zone_offset);
time_t srv_make_unix_date(const void *date_ptr);
time_t srv_make_unix_date2(const void *date_ptr);
time_t srv_make_unix_date3(const void *date_ptr);
time_t convert_timespec_to_time_t(struct timespec ts);
struct timespec convert_time_t_to_timespec(time_t t);
struct timespec convert_timeval_to_timespec(const struct timeval tv);
struct timeval convert_timespec_to_timeval(const struct timespec ts);
struct timespec timespec_current(void);
struct timespec timespec_min(const struct timespec *ts1,
			   const struct timespec *ts2);
int timespec_compare(const struct timespec *ts1, const struct timespec *ts2);
void round_timespec_to_sec(struct timespec *ts);
void round_timespec_to_usec(struct timespec *ts);
struct timespec interpret_long_date(const char *p);
void cli_put_dos_date(struct cli_state *cli, char *buf, int offset, time_t unixdate);
void cli_put_dos_date2(struct cli_state *cli, char *buf, int offset, time_t unixdate);
void cli_put_dos_date3(struct cli_state *cli, char *buf, int offset, time_t unixdate);
time_t cli_make_unix_date(struct cli_state *cli, const void *date_ptr);
time_t cli_make_unix_date2(struct cli_state *cli, const void *date_ptr);
time_t cli_make_unix_date3(struct cli_state *cli, const void *date_ptr);
void TimeInit(void);
void get_process_uptime(struct timeval *ret_time);
void get_startup_time(struct timeval *ret_time);
time_t nt_time_to_unix_abs(const NTTIME *nt);
time_t uint64s_nt_time_to_unix_abs(const uint64_t *src);
void unix_timespec_to_nt_time(NTTIME *nt, struct timespec ts);
void unix_to_nt_time_abs(NTTIME *nt, time_t t);
const char *time_to_asc(const time_t t);
const char *display_time(NTTIME nttime);
bool nt_time_is_set(const NTTIME *nt);

/* The following definitions come from lib/username.c  */

char *get_user_home_dir(TALLOC_CTX *mem_ctx, const char *user);
struct passwd *Get_Pwnam_alloc(TALLOC_CTX *mem_ctx, const char *user);

/* The following definitions come from lib/util_names.c  */
void gfree_netbios_names(void);
bool set_global_myname(const char *myname);
const char *global_myname(void);
bool set_global_myworkgroup(const char *myworkgroup);
const char *lp_workgroup(void);
const char *get_global_sam_name(void);

/* The following definitions come from lib/util.c  */

enum protocol_types get_Protocol(void);
void set_Protocol(enum protocol_types  p);
bool all_zero(const uint8_t *ptr, size_t size);
bool set_global_scope(const char *scope);
const char *global_scope(void);
void gfree_names(void);
void gfree_all( void );
const char *my_netbios_names(int i);
bool set_netbios_aliases(const char **str_array);
bool init_names(void);
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
struct user_auth_info *get_cmdline_auth_info_copy(TALLOC_CTX *mem_ctx,
						 const struct user_auth_info *info);
bool set_cmdline_auth_info_machine_account_creds(struct user_auth_info *auth_info);
void set_cmdline_auth_info_getpass(struct user_auth_info *auth_info);
bool file_exist_stat(const char *fname,SMB_STRUCT_STAT *sbuf,
		     bool fake_dir_create_times);
bool socket_exist(const char *fname);
uint64_t get_file_size_stat(const SMB_STRUCT_STAT *sbuf);
SMB_OFF_T get_file_size(char *file_name);
char *attrib_string(uint16 mode);
void show_msg(char *buf);
void smb_set_enclen(char *buf,int len,uint16 enc_ctx_num);
void smb_setlen(char *buf,int len);
int set_message_bcc(char *buf,int num_bytes);
ssize_t message_push_blob(uint8 **outbuf, DATA_BLOB blob);
char *unix_clean_name(TALLOC_CTX *ctx, const char *s);
char *clean_name(TALLOC_CTX *ctx, const char *s);
ssize_t write_data_at_offset(int fd, const char *buffer, size_t N, SMB_OFF_T pos);
int set_blocking(int fd, bool set);
void smb_msleep(unsigned int t);
NTSTATUS reinit_after_fork(struct messaging_context *msg_ctx,
			   struct event_context *ev_ctx,
			   struct server_id id,
			   bool parent_longlived);
void *malloc_(size_t size);
void *memalign_array(size_t el_size, size_t align, unsigned int count);
void *calloc_array(size_t size, size_t nmemb);
void *Realloc(void *p, size_t size, bool free_old_on_error);
void add_to_large_array(TALLOC_CTX *mem_ctx, size_t element_size,
			void *element, void *_array, uint32 *num_elements,
			ssize_t *array_size);
char *get_myname(TALLOC_CTX *ctx);
char *get_mydnsdomname(TALLOC_CTX *ctx);
int interpret_protocol(const char *str,int def);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
bool process_exists(const struct server_id pid);
const char *uidtoname(uid_t uid);
char *gidtoname(gid_t gid);
uid_t nametouid(const char *name);
gid_t nametogid(const char *name);
void smb_panic(const char *const why);
void log_stack_trace(void);
const char *readdirname(SMB_STRUCT_DIR *p);
bool is_in_path(const char *name, name_compare_entry *namelist, bool case_sensitive);
void set_namearray(name_compare_entry **ppname_array, const char *namelist);
void free_namearray(name_compare_entry *name_array);
bool fcntl_lock(int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type);
bool fcntl_getlock(int fd, SMB_OFF_T *poffset, SMB_OFF_T *pcount, int *ptype, pid_t *ppid);
bool is_myname(const char *s);
bool is_myworkgroup(const char *s);
void ra_lanman_string( const char *native_lanman );
const char *get_remote_arch_str(void);
void set_remote_arch(enum remote_arch_types type);
enum remote_arch_types get_remote_arch(void);
const char *tab_depth(int level, int depth);
int str_checksum(const char *s);
void zero_free(void *p, size_t size);
int set_maxfiles(int requested_max);
int smb_mkstemp(char *name_template);
void *smb_xmalloc_array(size_t size, unsigned int count);
char *myhostname(void);
char *lock_path(const char *name);
char *pid_path(const char *name);
char *lib_path(const char *name);
char *modules_path(const char *name);
char *data_path(const char *name);
char *state_path(const char *name);
char *cache_path(const char *name);
const char *shlib_ext(void);
bool parent_dirname(TALLOC_CTX *mem_ctx, const char *dir, char **parent,
		    const char **name);
bool ms_has_wild(const char *s);
bool ms_has_wild_w(const smb_ucs2_t *s);
bool mask_match(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_search(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive);
bool unix_wild_match(const char *pattern, const char *string);
bool name_to_fqdn(fstring fqdn, const char *name);
void *talloc_append_blob(TALLOC_CTX *mem_ctx, void *buf, DATA_BLOB blob);
uint32 map_share_mode_to_deny_mode(uint32 share_access, uint32 private_options);
pid_t procid_to_pid(const struct server_id *proc);
void set_my_vnn(uint32 vnn);
uint32 get_my_vnn(void);
void set_my_unique_id(uint64_t unique_id);
struct server_id pid_to_procid(pid_t pid);
struct server_id procid_self(void);
bool procid_equal(const struct server_id *p1, const struct server_id *p2);
bool cluster_id_equal(const struct server_id *id1,
		      const struct server_id *id2);
bool procid_is_me(const struct server_id *pid);
struct server_id interpret_pid(const char *pid_string);
char *procid_str(TALLOC_CTX *mem_ctx, const struct server_id *pid);
char *procid_str_static(const struct server_id *pid);
bool procid_valid(const struct server_id *pid);
bool procid_is_local(const struct server_id *pid);
int this_is_smp(void);
bool trans_oob(uint32_t bufsize, uint32_t offset, uint32_t length);
bool is_offset_safe(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_str_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
int get_safe_SVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
int get_safe_IVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
void split_domain_user(TALLOC_CTX *mem_ctx,
		       const char *full_name,
		       char **domain,
		       char **user);
void *_talloc_zero_zeronull(const void *ctx, size_t size, const char *name);
void *_talloc_memdup_zeronull(const void *t, const void *p, size_t size, const char *name);
void *_talloc_array_zeronull(const void *ctx, size_t el_size, unsigned count, const char *name);
void *_talloc_zero_array_zeronull(const void *ctx, size_t el_size, unsigned count, const char *name);
void *talloc_zeronull(const void *context, size_t size, const char *name);
bool is_valid_policy_hnd(const struct policy_handle *hnd);
bool policy_hnd_equal(const struct policy_handle *hnd1,
		      const struct policy_handle *hnd2);
const char *strip_hostname(const char *s);
bool tevent_req_poll_ntstatus(struct tevent_req *req,
			      struct tevent_context *ev,
			      NTSTATUS *status);

/* The following definitions come from lib/util_file.c  */

char **file_lines_pload(const char *syscmd, int *numlines);
void file_lines_free(char **lines);

/* The following definitions come from lib/util_nscd.c  */

void smb_nscd_flush_user_cache(void);
void smb_nscd_flush_group_cache(void);

/* The following definitions come from lib/util_nttoken.c  */

NT_USER_TOKEN *dup_nt_token(TALLOC_CTX *mem_ctx, const NT_USER_TOKEN *ptoken);
NTSTATUS merge_nt_token(TALLOC_CTX *mem_ctx,
			const struct nt_user_token *token_1,
			const struct nt_user_token *token_2,
			struct nt_user_token **token_out);
bool token_sid_in_ace(const NT_USER_TOKEN *token, const struct security_ace *ace);

/* The following definitions come from lib/util_pw.c  */

struct passwd *tcopy_passwd(TALLOC_CTX *mem_ctx, const struct passwd *from) ;
void flush_pwnam_cache(void);
struct passwd *getpwnam_alloc(TALLOC_CTX *mem_ctx, const char *name);
struct passwd *getpwuid_alloc(TALLOC_CTX *mem_ctx, uid_t uid) ;

/* The following definitions come from ..libcli/registry/util_reg.c  */

const char *str_regtype(int type);
int regtype_by_string(const char *str);
bool push_reg_sz(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, const char *s);
bool push_reg_multi_sz(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, const char **a);
bool pull_reg_sz(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, const char **s);
bool pull_reg_multi_sz(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, const char ***a);

/* The following definitions come from lib/util_seaccess.c  */

void se_map_generic(uint32 *access_mask, const struct generic_mapping *mapping);
void security_acl_map_generic(struct security_acl *sa, const struct generic_mapping *mapping);
void se_map_standard(uint32 *access_mask, const struct standard_mapping *mapping);
NTSTATUS se_access_check(const struct security_descriptor *sd, const NT_USER_TOKEN *token,
		     uint32 acc_desired, uint32 *acc_granted);

/* The following definitions come from lib/util_sec.c  */

void sec_init(void);
uid_t sec_initial_uid(void);
gid_t sec_initial_gid(void);
bool non_root_mode(void);
void gain_root_privilege(void);
void gain_root_group_privilege(void);
void set_effective_uid(uid_t uid);
void set_effective_gid(gid_t gid);
void save_re_uid(void);
void restore_re_uid_fromroot(void);
void restore_re_uid(void);
void save_re_gid(void);
void restore_re_gid(void);
int set_re_uid(void);
void become_user_permanently(uid_t uid, gid_t gid);
bool is_setuid_root(void) ;

/* The following definitions come from lib/util_sid.c  */

const char *sid_type_lookup(uint32 sid_type) ;
NT_USER_TOKEN *get_system_token(void) ;
char *sid_to_fstring(fstring sidstr_out, const struct dom_sid *sid);
char *sid_string_talloc(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
char *sid_string_dbg(const struct dom_sid *sid);
char *sid_string_tos(const struct dom_sid *sid);
bool string_to_sid(struct dom_sid *sidout, const char *sidstr);
bool sid_append_rid(struct dom_sid *sid, uint32 rid);
bool sid_compose(struct dom_sid *dst, const struct dom_sid *domain_sid, uint32 rid);
bool sid_split_rid(struct dom_sid *sid, uint32 *rid);
bool sid_peek_rid(const struct dom_sid *sid, uint32 *rid);
bool sid_peek_check_rid(const struct dom_sid *exp_dom_sid, const struct dom_sid *sid, uint32 *rid);
void sid_copy(struct dom_sid *dst, const struct dom_sid *src);
bool sid_linearize(char *outbuf, size_t len, const struct dom_sid *sid);
bool sid_parse(const char *inbuf, size_t len, struct dom_sid *sid);
int sid_compare(const struct dom_sid *sid1, const struct dom_sid *sid2);
int sid_compare_domain(const struct dom_sid *sid1, const struct dom_sid *sid2);
bool sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2);
bool non_mappable_sid(struct dom_sid *sid);
char *sid_binstring(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
char *sid_binstring_hex(const struct dom_sid *sid);
struct dom_sid *sid_dup_talloc(TALLOC_CTX *ctx, const struct dom_sid *src);
NTSTATUS add_sid_to_array(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			  struct dom_sid **sids, size_t *num);
NTSTATUS add_sid_to_array_unique(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
				 struct dom_sid **sids, size_t *num_sids);
void del_sid_from_array(const struct dom_sid *sid, struct dom_sid **sids, size_t *num);
bool add_rid_to_array_unique(TALLOC_CTX *mem_ctx,
				    uint32 rid, uint32 **pp_rids, size_t *p_num);
bool is_null_sid(const struct dom_sid *sid);
bool is_sid_in_token(const NT_USER_TOKEN *token, const struct dom_sid *sid);
NTSTATUS sid_array_from_info3(TALLOC_CTX *mem_ctx,
			      const struct netr_SamInfo3 *info3,
			      struct dom_sid **user_sids,
			      size_t *num_user_sids,
			      bool include_user_group_rid,
			      bool skip_ressource_groups);

/* The following definitions come from lib/util_sock.c  */

bool is_broadcast_addr(const struct sockaddr *pss);
bool is_loopback_ip_v4(struct in_addr ip);
bool is_loopback_addr(const struct sockaddr *pss);
bool is_zero_addr(const struct sockaddr *pss);
void zero_ip_v4(struct in_addr *ip);
void in_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
		struct in_addr ip);
bool same_net(const struct sockaddr *ip1,
		const struct sockaddr *ip2,
		const struct sockaddr *mask);
bool sockaddr_equal(const struct sockaddr *ip1,
		const struct sockaddr *ip2);
bool is_address_any(const struct sockaddr *psa);
uint16_t get_sockaddr_port(const struct sockaddr_storage *pss);
char *print_sockaddr(char *dest,
			size_t destlen,
			const struct sockaddr_storage *psa);
char *print_canonical_sockaddr(TALLOC_CTX *ctx,
			const struct sockaddr_storage *pss);
const char *client_name(int fd);
int get_socket_port(int fd);
const char *client_addr(int fd, char *addr, size_t addrlen);
const char *client_socket_addr(int fd, char *addr, size_t addr_len);
int client_socket_port(int fd);
void set_smb_read_error(enum smb_read_errors *pre,
			enum smb_read_errors newerr);
void cond_set_smb_read_error(enum smb_read_errors *pre,
			enum smb_read_errors newerr);
bool is_a_socket(int fd);
void set_socket_options(int fd, const char *options);
ssize_t read_udp_v4_socket(int fd,
			char *buf,
			size_t len,
			struct sockaddr_storage *psa);
NTSTATUS read_fd_with_timeout(int fd, char *buf,
				  size_t mincnt, size_t maxcnt,
				  unsigned int time_out,
				  size_t *size_ret);
NTSTATUS read_data(int fd, char *buffer, size_t N);
ssize_t write_data(int fd, const char *buffer, size_t N);
ssize_t write_data_iov(int fd, const struct iovec *orig_iov, int iovcnt);
bool send_keepalive(int client);
NTSTATUS read_smb_length_return_keepalive(int fd, char *inbuf,
					  unsigned int timeout,
					  size_t *len);
NTSTATUS read_smb_length(int fd, char *inbuf, unsigned int timeout,
			 size_t *len);
NTSTATUS receive_smb_raw(int fd,
			char *buffer,
			size_t buflen,
			unsigned int timeout,
			size_t maxlen,
			size_t *p_len);
int open_socket_in(int type,
		uint16_t port,
		int dlevel,
		const struct sockaddr_storage *psock,
		bool rebind);
NTSTATUS open_socket_out(const struct sockaddr_storage *pss, uint16_t port,
			 int timeout, int *pfd);
struct tevent_req *open_socket_out_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					const struct sockaddr_storage *pss,
					uint16_t port,
					int timeout);
NTSTATUS open_socket_out_recv(struct tevent_req *req, int *pfd);
struct tevent_req *open_socket_out_defer_send(TALLOC_CTX *mem_ctx,
					      struct event_context *ev,
					      struct timeval wait_time,
					      const struct sockaddr_storage *pss,
					      uint16_t port,
					      int timeout);
NTSTATUS open_socket_out_defer_recv(struct tevent_req *req, int *pfd);
bool open_any_socket_out(struct sockaddr_storage *addrs, int num_addrs,
			 int timeout, int *fd_index, int *fd);
int open_udp_socket(const char *host, int port);
const char *get_peer_name(int fd, bool force_lookup);
const char *get_peer_addr(int fd, char *addr, size_t addr_len);
int create_pipe_sock(const char *socket_dir,
		     const char *socket_name,
		     mode_t dir_perms);
const char *get_mydnsfullname(void);
bool is_myname_or_ipaddr(const char *s);
struct tevent_req *getaddrinfo_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct fncall_context *ctx,
				    const char *node,
				    const char *service,
				    const struct addrinfo *hints);
int getaddrinfo_recv(struct tevent_req *req, struct addrinfo **res);
struct tevent_req *tstream_read_packet_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tstream_context *stream,
					    size_t initial,
					    ssize_t (*more)(uint8_t *buf,
							    size_t buflen,
							    void *private_data),
					    void *private_data);
ssize_t tstream_read_packet_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 uint8_t **pbuf, int *perrno);

/* The following definitions come from lib/util_str.c  */

bool next_token(const char **ptr, char *buff, const char *sep, size_t bufsize);
bool next_token_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep);
bool next_token_no_ltrim_talloc(TALLOC_CTX *ctx,
			const char **ptr,
			char **pp_buff,
			const char *sep);
int StrCaseCmp(const char *s, const char *t);
int StrnCaseCmp(const char *s, const char *t, size_t len);
bool strnequal(const char *s1,const char *s2,size_t n);
bool strcsequal(const char *s1,const char *s2);
void strnorm(char *s, int case_default);
bool strisnormal(const char *s, int case_default);
char *push_skip_string(char *buf);
char *skip_string(const char *base, size_t len, char *buf);
size_t str_charnum(const char *s);
size_t str_ascii_charnum(const char *s);
bool trim_char(char *s,char cfront,char cback);
bool strhasupper(const char *s);
bool strhaslower(const char *s);
char *safe_strcpy_fn(const char *fn,
		int line,
		char *dest,
		const char *src,
		size_t maxlength);
char *safe_strcat_fn(const char *fn,
		int line,
		char *dest,
		const char *src,
		size_t maxlength);
char *alpha_strcpy_fn(const char *fn,
		int line,
		char *dest,
		const char *src,
		const char *other_safe_chars,
		size_t maxlength);
char *StrnCpy_fn(const char *fn, int line,char *dest,const char *src,size_t n);
bool in_list(const char *s, const char *list, bool casesensitive);
void string_free(char **s);
bool string_set(char **dest,const char *src);
void string_sub2(char *s,const char *pattern, const char *insert, size_t len,
		 bool remove_unsafe_characters, bool replace_once,
		 bool allow_trailing_dollar);
void string_sub_once(char *s, const char *pattern,
		const char *insert, size_t len);
void string_sub(char *s,const char *pattern, const char *insert, size_t len);
void fstring_sub(char *s,const char *pattern,const char *insert);
char *realloc_string_sub2(char *string,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool allow_trailing_dollar);
char *realloc_string_sub(char *string,
			const char *pattern,
			const char *insert);
char *talloc_string_sub2(TALLOC_CTX *mem_ctx, const char *src,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool replace_once,
			bool allow_trailing_dollar);
char *talloc_string_sub(TALLOC_CTX *mem_ctx,
			const char *src,
			const char *pattern,
			const char *insert);
void all_string_sub(char *s,const char *pattern,const char *insert, size_t len);
char *talloc_all_string_sub(TALLOC_CTX *ctx,
				const char *src,
				const char *pattern,
				const char *insert);
char *octal_string(int i);
char *string_truncate(char *s, unsigned int length);
char *strchr_m(const char *src, char c);
char *strrchr_m(const char *s, char c);
char *strnrchr_m(const char *s, char c, unsigned int n);
char *strstr_m(const char *src, const char *findstr);
void strlower_m(char *s);
void strupper_m(char *s);
size_t strlen_m(const char *s);
size_t strlen_m_term(const char *s);
size_t strlen_m_term_null(const char *s);
char *binary_string_rfc2254(TALLOC_CTX *mem_ctx, const uint8_t *buf, int len);
char *binary_string(char *buf, int len);
int fstr_sprintf(fstring s, const char *fmt, ...);
bool str_list_sub_basic( char **list, const char *smb_name,
			 const char *domain_name );
bool str_list_substitute(char **list, const char *pattern, const char *insert);
bool str_list_check(const char **list, const char *s);
bool str_list_check_ci(const char **list, const char *s);

char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count);
int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list);
void ipstr_list_free(char* ipstr_list);
void rfc1738_unescape(char *buf);
DATA_BLOB base64_decode_data_blob(const char *s);
void base64_decode_inplace(char *s);
char *base64_encode_data_blob(TALLOC_CTX *mem_ctx, DATA_BLOB data);
uint64_t STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr);
SMB_OFF_T conv_str_size(const char * str);
void string_append(char **left, const char *right);
bool add_string_to_array(TALLOC_CTX *mem_ctx,
			 const char *str, const char ***strings,
			 int *num);
void sprintf_append(TALLOC_CTX *mem_ctx, char **string, ssize_t *len,
		    size_t *bufsize, const char *fmt, ...);
int asprintf_strupper_m(char **strp, const char *fmt, ...);
char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...);
char *talloc_asprintf_strlower_m(TALLOC_CTX *t, const char *fmt, ...);
char *sstring_sub(const char *src, char front, char back);
bool validate_net_name( const char *name,
		const char *invalid_chars,
		int max_len);
char *escape_shell_string(const char *src);
char **str_list_make_v3(TALLOC_CTX *mem_ctx, const char *string, const char *sep);
char *sanitize_username(TALLOC_CTX *mem_ctx, const char *username);

/* The following definitions come from lib/util_unistr.c  */

void gfree_case_tables(void);
void load_case_tables(void);
void init_valid_table(void);
size_t dos_PutUniCode(char *dst,const char *src, size_t len, bool null_terminate);
char *skip_unibuf(char *src, size_t len);
int rpcstr_push(void *dest, const char *src, size_t dest_len, int flags);
int rpcstr_push_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src);
smb_ucs2_t toupper_w(smb_ucs2_t val);
smb_ucs2_t tolower_w( smb_ucs2_t val );
bool islower_w(smb_ucs2_t c);
bool isupper_w(smb_ucs2_t c);
bool isvalid83_w(smb_ucs2_t c);
size_t strlen_w(const smb_ucs2_t *src);
size_t strnlen_w(const smb_ucs2_t *src, size_t max);
smb_ucs2_t *strchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
smb_ucs2_t *strchr_wa(const smb_ucs2_t *s, char c);
smb_ucs2_t *strrchr_w(const smb_ucs2_t *s, smb_ucs2_t c);
smb_ucs2_t *strnrchr_w(const smb_ucs2_t *s, smb_ucs2_t c, unsigned int n);
smb_ucs2_t *strstr_w(const smb_ucs2_t *s, const smb_ucs2_t *ins);
bool strlower_w(smb_ucs2_t *s);
bool strupper_w(smb_ucs2_t *s);
void strnorm_w(smb_ucs2_t *s, int case_default);
int strcmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b);
int strncmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);
int strcasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b);
int strncasecmp_w(const smb_ucs2_t *a, const smb_ucs2_t *b, size_t len);
bool strequal_w(const smb_ucs2_t *s1, const smb_ucs2_t *s2);
bool strnequal_w(const smb_ucs2_t *s1,const smb_ucs2_t *s2,size_t n);
smb_ucs2_t *strdup_w(const smb_ucs2_t *src);
smb_ucs2_t *strndup_w(const smb_ucs2_t *src, size_t len);
smb_ucs2_t *strncpy_w(smb_ucs2_t *dest, const smb_ucs2_t *src, const size_t max);
smb_ucs2_t *strncat_w(smb_ucs2_t *dest, const smb_ucs2_t *src, const size_t max);
smb_ucs2_t *strcat_w(smb_ucs2_t *dest, const smb_ucs2_t *src);
void string_replace_w(smb_ucs2_t *s, smb_ucs2_t oldc, smb_ucs2_t newc);
bool trim_string_w(smb_ucs2_t *s, const smb_ucs2_t *front,
				  const smb_ucs2_t *back);
int strcmp_wa(const smb_ucs2_t *a, const char *b);
int strncmp_wa(const smb_ucs2_t *a, const char *b, size_t len);
smb_ucs2_t *strpbrk_wa(const smb_ucs2_t *s, const char *p);
smb_ucs2_t *strstr_wa(const smb_ucs2_t *s, const char *ins);
int toupper_ascii(int c);
int tolower_ascii(int c);
int isupper_ascii(int c);
int islower_ascii(int c);

/* The following definitions come from lib/util_uuid.c  */

void smb_uuid_pack(const struct GUID uu, UUID_FLAT *ptr);
void smb_uuid_unpack(const UUID_FLAT in, struct GUID *uu);
char *guid_binstring(TALLOC_CTX *mem_ctx, const struct GUID *guid);

/* The following definitions come from lib/version.c  */

const char *samba_version_string(void);

/* The following definitions come from lib/winbind_util.c  */

bool winbind_lookup_name(const char *dom_name, const char *name, struct dom_sid *sid,
                         enum lsa_SidType *name_type);
bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			const char **domain, const char **name,
                        enum lsa_SidType *name_type);
bool winbind_ping(void);
bool winbind_sid_to_uid(uid_t *puid, const struct dom_sid *sid);
bool winbind_uid_to_sid(struct dom_sid *sid, uid_t uid);
bool winbind_sid_to_gid(gid_t *pgid, const struct dom_sid *sid);
bool winbind_gid_to_sid(struct dom_sid *sid, gid_t gid);
struct passwd * winbind_getpwnam(const char * sname);
struct passwd * winbind_getpwsid(const struct dom_sid *sid);
wbcErr wb_is_trusted_domain(const char *domain);
bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const struct dom_sid *domain_sid,
			 int num_rids, uint32 *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types);
bool winbind_allocate_uid(uid_t *uid);
bool winbind_allocate_gid(gid_t *gid);
bool winbind_get_groups(TALLOC_CTX *mem_ctx,
			const char *account,
			uint32_t *num_groups,
			gid_t ** _groups);
bool winbind_get_sid_aliases(TALLOC_CTX *mem_ctx,
			     const struct dom_sid *dom_sid,
		             const struct dom_sid *members,
			     size_t num_members,
			     uint32_t **pp_alias_rids,
			     size_t *p_num_alias_rids);


/* The following definitions come from lib/wins_srv.c  */

bool wins_srv_is_dead(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_alive(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_died(struct in_addr wins_ip, struct in_addr src_ip);
unsigned wins_srv_count(void);
char **wins_srv_tags(void);
void wins_srv_tags_free(char **list);
struct in_addr wins_srv_ip_tag(const char *tag, struct in_addr src_ip);
unsigned wins_srv_count_tag(const char *tag);

/* The following definitions come from libads/ads_struct.c  */

char *ads_build_path(const char *realm, const char *sep, const char *field, int reverse);
char *ads_build_dn(const char *realm);
char *ads_build_domain(const char *dn);
ADS_STRUCT *ads_init(const char *realm, 
		     const char *workgroup,
		     const char *ldap_server);
bool ads_set_sasl_wrap_flags(ADS_STRUCT *ads, int flags);
void ads_destroy(ADS_STRUCT **ads);

const char *ads_get_ldap_server_name(ADS_STRUCT *ads);

/* The following definitions come from libads/authdata.c  */

NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     struct PAC_LOGON_INFO **logon_info);

/* The following definitions come from libads/disp_sec.c  */

void ads_disp_sd(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, struct security_descriptor *sd);

/* The following definitions come from libads/kerberos.c  */

int kerberos_kinit_password_ext(const char *principal,
				const char *password,
				int time_offset,
				time_t *expire_time,
				time_t *renew_till_time,
				const char *cache_name,
				bool request_pac,
				bool add_netbios_addr,
				time_t renewable_time,
				NTSTATUS *ntstatus);
int ads_kinit_password(ADS_STRUCT *ads);
int ads_kdestroy(const char *cc_name);
char* kerberos_standard_des_salt( void );
bool kerberos_secrets_store_des_salt( const char* salt );
char* kerberos_secrets_fetch_des_salt( void );
char *kerberos_get_default_realm_from_ccache( void );
char *kerberos_get_realm_from_hostname(const char *hostname);

bool kerberos_secrets_store_salting_principal(const char *service,
					      int enctype,
					      const char *principal);
int kerberos_kinit_password(const char *principal,
			    const char *password,
			    int time_offset,
			    const char *cache_name);
bool create_local_private_krb5_conf_for_domain(const char *realm,
						const char *domain,
						const char *sitename,
						struct sockaddr_storage *pss,
						const char *kdc_name);

/* The following definitions come from libads/kerberos_keytab.c  */

int ads_keytab_add_entry(ADS_STRUCT *ads, const char *srvPrinc);
int ads_keytab_flush(ADS_STRUCT *ads);
int ads_keytab_create_default(ADS_STRUCT *ads);
int ads_keytab_list(const char *keytab_name);

/* The following definitions come from libads/kerberos_verify.c  */

NTSTATUS ads_verify_ticket(TALLOC_CTX *mem_ctx,
			   const char *realm,
			   time_t time_offset,
			   const DATA_BLOB *ticket,
			   char **principal,
			   struct PAC_LOGON_INFO **logon_info,
			   DATA_BLOB *ap_rep,
			   DATA_BLOB *session_key,
			   bool use_replay_cache);

/* The following definitions come from libads/krb5_errs.c  */


/* The following definitions come from libads/krb5_setpw.c  */

ADS_STATUS ads_krb5_set_password(const char *kdc_host, const char *princ, 
				 const char *newpw, int time_offset);
ADS_STATUS kerberos_set_password(const char *kpasswd_server, 
				 const char *auth_principal, const char *auth_password,
				 const char *target_principal, const char *new_password,
				 int time_offset);
ADS_STATUS ads_set_machine_password(ADS_STRUCT *ads,
				    const char *machine_account,
				    const char *password);

/* The following definitions come from libads/ldap.c  */

bool ads_sitename_match(ADS_STRUCT *ads);
bool ads_closest_dc(ADS_STRUCT *ads);
ADS_STATUS ads_connect(ADS_STRUCT *ads);
ADS_STATUS ads_connect_user_creds(ADS_STRUCT *ads);
ADS_STATUS ads_connect_gc(ADS_STRUCT *ads);
void ads_disconnect(ADS_STRUCT *ads);
ADS_STATUS ads_do_search_all_fn(ADS_STRUCT *ads, const char *bind_path,
				int scope, const char *expr, const char **attrs,
				bool (*fn)(ADS_STRUCT *, char *, void **, void *), 
				void *data_area);
char *ads_parent_dn(const char *dn);
ADS_MODLIST ads_init_mods(TALLOC_CTX *ctx);
ADS_STATUS ads_mod_str(TALLOC_CTX *ctx, ADS_MODLIST *mods, 
		       const char *name, const char *val);
ADS_STATUS ads_mod_strlist(TALLOC_CTX *ctx, ADS_MODLIST *mods,
			   const char *name, const char **vals);
ADS_STATUS ads_gen_mod(ADS_STRUCT *ads, const char *mod_dn, ADS_MODLIST mods);
ADS_STATUS ads_gen_add(ADS_STRUCT *ads, const char *new_dn, ADS_MODLIST mods);
ADS_STATUS ads_del_dn(ADS_STRUCT *ads, char *del_dn);
char *ads_ou_string(ADS_STRUCT *ads, const char *org_unit);
char *ads_default_ou_string(ADS_STRUCT *ads, const char *wknguid);
ADS_STATUS ads_add_strlist(TALLOC_CTX *ctx, ADS_MODLIST *mods,
				const char *name, const char **vals);
uint32 ads_get_kvno(ADS_STRUCT *ads, const char *account_name);
uint32_t ads_get_machine_kvno(ADS_STRUCT *ads, const char *machine_name);
ADS_STATUS ads_clear_service_principal_names(ADS_STRUCT *ads, const char *machine_name);
ADS_STATUS ads_add_service_principal_name(ADS_STRUCT *ads, const char *machine_name, 
                                          const char *my_fqdn, const char *spn);
ADS_STATUS ads_create_machine_acct(ADS_STRUCT *ads, const char *machine_name, 
                                   const char *org_unit);
ADS_STATUS ads_move_machine_acct(ADS_STRUCT *ads, const char *machine_name, 
                                 const char *org_unit, bool *moved);
int ads_count_replies(ADS_STRUCT *ads, void *res);
ADS_STATUS ads_USN(ADS_STRUCT *ads, uint32 *usn);
ADS_STATUS ads_current_time(ADS_STRUCT *ads);
ADS_STATUS ads_domain_func_level(ADS_STRUCT *ads, uint32 *val);
ADS_STATUS ads_domain_sid(ADS_STRUCT *ads, struct dom_sid *sid);
ADS_STATUS ads_site_dn(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, const char **site_name);
ADS_STATUS ads_site_dn_for_machine(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, const char *computer_name, const char **site_dn);
ADS_STATUS ads_upn_suffixes(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, char ***suffixes, size_t *num_suffixes);
ADS_STATUS ads_get_joinable_ous(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				char ***ous,
				size_t *num_ous);
ADS_STATUS ads_get_sid_from_extended_dn(TALLOC_CTX *mem_ctx,
					const char *extended_dn,
					enum ads_extended_dn_flags flags,
					struct dom_sid *sid);
char* ads_get_dnshostname( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name );
char* ads_get_upn( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name );
char* ads_get_samaccountname( ADS_STRUCT *ads, TALLOC_CTX *ctx, const char *machine_name );
ADS_STATUS ads_join_realm(ADS_STRUCT *ads, const char *machine_name,
			uint32 account_type, const char *org_unit);
ADS_STATUS ads_leave_realm(ADS_STRUCT *ads, const char *hostname);
ADS_STATUS ads_find_samaccount(ADS_STRUCT *ads,
			       TALLOC_CTX *mem_ctx,
			       const char *samaccountname,
			       uint32 *uac_ret,
			       const char **dn_ret);
ADS_STATUS ads_config_path(ADS_STRUCT *ads, 
			   TALLOC_CTX *mem_ctx, 
			   char **config_path);
const char *ads_get_extended_right_name_by_guid(ADS_STRUCT *ads, 
						const char *config_path, 
						TALLOC_CTX *mem_ctx, 
						const struct GUID *rights_guid);
ADS_STATUS ads_check_ou_dn(TALLOC_CTX *mem_ctx,
			   ADS_STRUCT *ads,
			   const char **account_ou);

/* The following definitions come from libads/ldap_printer.c  */

ADS_STATUS ads_mod_printer_entry(ADS_STRUCT *ads, char *prt_dn,
				 TALLOC_CTX *ctx, const ADS_MODLIST *mods);
ADS_STATUS ads_add_printer_entry(ADS_STRUCT *ads, char *prt_dn,
					TALLOC_CTX *ctx, ADS_MODLIST *mods);
WERROR get_remote_printer_publishing_data(struct rpc_pipe_client *cli, 
					  TALLOC_CTX *mem_ctx,
					  ADS_MODLIST *mods,
					  const char *printer);
bool get_local_printer_publishing_data(TALLOC_CTX *mem_ctx,
				       ADS_MODLIST *mods,
				       NT_PRINTER_DATA *data);

/* The following definitions come from libads/ldap_user.c  */

ADS_STATUS ads_add_user_acct(ADS_STRUCT *ads, const char *user, 
			     const char *container, const char *fullname);
ADS_STATUS ads_add_group_acct(ADS_STRUCT *ads, const char *group, 
			      const char *container, const char *comment);

/* The following definitions come from libads/ldap_utils.c  */

ADS_STATUS ads_ranged_search(ADS_STRUCT *ads, 
			     TALLOC_CTX *mem_ctx,
			     int scope,
			     const char *base,
			     const char *filter,
			     void *args,
			     const char *range_attr,
			     char ***strings,
			     size_t *num_strings);
ADS_STATUS ads_ranged_search_internal(ADS_STRUCT *ads, 
				      TALLOC_CTX *mem_ctx,
				      int scope,
				      const char *base,
				      const char *filter,
				      const char **attrs,
				      void *args,
				      const char *range_attr,
				      char ***strings,
				      size_t *num_strings,
				      uint32 *first_usn,
				      int *num_retries,
				      bool *more_values);

/* The following definitions come from libads/ndr.c  */

void ndr_print_ads_auth_flags(struct ndr_print *ndr, const char *name, uint32_t r);
void ndr_print_ads_struct(struct ndr_print *ndr, const char *name, const struct ads_struct *r);

/* The following definitions come from libads/sasl.c  */

ADS_STATUS ads_sasl_bind(ADS_STRUCT *ads);

/* The following definitions come from libads/sasl_wrapping.c  */

ADS_STATUS ads_setup_sasl_wrapping(ADS_STRUCT *ads,
				   const struct ads_saslwrap_ops *ops,
				   void *private_data);
ADS_STATUS ads_setup_sasl_wrapping(ADS_STRUCT *ads,
				   const struct ads_saslwrap_ops *ops,
				   void *private_data);

/* The following definitions come from libads/util.c  */

ADS_STATUS ads_change_trust_account_password(ADS_STRUCT *ads, char *host_principal);
ADS_STATUS ads_guess_service_principal(ADS_STRUCT *ads,
				       char **returned_principal);

/* The following definitions come from librpc/ndr/util.c  */

enum ndr_err_code ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r);
enum ndr_err_code ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r);
void ndr_print_server_id(struct ndr_print *ndr, const char *name, const struct server_id *r);
enum ndr_err_code ndr_push_file_id(struct ndr_push *ndr, int ndr_flags, const struct file_id *r);
enum ndr_err_code ndr_pull_file_id(struct ndr_pull *ndr, int ndr_flags, struct file_id *r);
void ndr_print_file_id(struct ndr_print *ndr, const char *name, const struct file_id *r);
_PUBLIC_ void ndr_print_bool(struct ndr_print *ndr, const char *name, const bool b);
_PUBLIC_ void ndr_print_sockaddr_storage(struct ndr_print *ndr, const char *name, const struct sockaddr_storage *ss);
const char *ndr_errstr(enum ndr_err_code err);
extern const struct ndr_syntax_id null_ndr_syntax_id;

/* The following definitions come from libsmb/cliconnect.c  */

ADS_STATUS cli_session_setup_spnego(struct cli_state *cli, const char *user, 
			      const char *pass, const char *user_domain,
				    const char * dest_realm);

NTSTATUS cli_session_setup(struct cli_state *cli,
			   const char *user,
			   const char *pass, int passlen,
			   const char *ntpass, int ntpasslen,
			   const char *workgroup);
struct tevent_req *cli_session_setup_guest_create(TALLOC_CTX *mem_ctx,
						  struct event_context *ev,
						  struct cli_state *cli,
						  struct tevent_req **psmbreq);
struct tevent_req *cli_session_setup_guest_send(TALLOC_CTX *mem_ctx,
						struct event_context *ev,
						struct cli_state *cli);
NTSTATUS cli_session_setup_guest_recv(struct tevent_req *req);
struct tevent_req *cli_ulogoff_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli);
NTSTATUS cli_ulogoff_recv(struct tevent_req *req);
NTSTATUS cli_ulogoff(struct cli_state *cli);
struct tevent_req *cli_tcon_andx_create(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *share, const char *dev,
					const char *pass, int passlen,
					struct tevent_req **psmbreq);
struct tevent_req *cli_tcon_andx_send(TALLOC_CTX *mem_ctx,
				      struct event_context *ev,
				      struct cli_state *cli,
				      const char *share, const char *dev,
				      const char *pass, int passlen);
NTSTATUS cli_tcon_andx_recv(struct tevent_req *req);
NTSTATUS cli_tcon_andx(struct cli_state *cli, const char *share,
		       const char *dev, const char *pass, int passlen);
struct tevent_req *cli_tdis_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct cli_state *cli);
NTSTATUS cli_tdis_recv(struct tevent_req *req);
NTSTATUS cli_tdis(struct cli_state *cli);
void cli_negprot_sendsync(struct cli_state *cli);
NTSTATUS cli_negprot(struct cli_state *cli);
struct tevent_req *cli_negprot_send(TALLOC_CTX *mem_ctx,
				    struct event_context *ev,
				    struct cli_state *cli);
NTSTATUS cli_negprot_recv(struct tevent_req *req);
bool cli_session_request(struct cli_state *cli,
			 struct nmb_name *calling, struct nmb_name *called);
NTSTATUS cli_connect(struct cli_state *cli,
		const char *host,
		struct sockaddr_storage *dest_ss);
NTSTATUS cli_start_connection(struct cli_state **output_cli, 
			      const char *my_name, 
			      const char *dest_host, 
			      struct sockaddr_storage *dest_ss, int port,
			      int signing_state, int flags,
			      bool *retry) ;
NTSTATUS cli_full_connection(struct cli_state **output_cli, 
			     const char *my_name, 
			     const char *dest_host, 
			     struct sockaddr_storage *dest_ss, int port,
			     const char *service, const char *service_type,
			     const char *user, const char *domain, 
			     const char *password, int flags,
			     int signing_state,
			     bool *retry) ;
bool attempt_netbios_session_request(struct cli_state **ppcli, const char *srchost, const char *desthost,
                                     struct sockaddr_storage *pdest_ss);
NTSTATUS cli_raw_tcon(struct cli_state *cli, 
		      const char *service, const char *pass, const char *dev,
		      uint16 *max_xmit, uint16 *tid);
struct cli_state *get_ipc_connect(char *server,
				struct sockaddr_storage *server_ss,
				const struct user_auth_info *user_info);
struct cli_state *get_ipc_connect_master_ip(TALLOC_CTX *ctx,
				struct ip_service *mb_ip,
				const struct user_auth_info *user_info,
				char **pp_workgroup_out);
struct cli_state *get_ipc_connect_master_ip_bcast(TALLOC_CTX *ctx,
					const struct user_auth_info *user_info,
					char **pp_workgroup_out);

/* The following definitions come from libsmb/clidfs.c  */

NTSTATUS cli_cm_force_encryption(struct cli_state *c,
			const char *username,
			const char *password,
			const char *domain,
			const char *sharename);
struct cli_state *cli_cm_open(TALLOC_CTX *ctx,
				struct cli_state *referring_cli,
				const char *server,
				const char *share,
				const struct user_auth_info *auth_info,
				bool show_hdr,
				bool force_encrypt,
				int max_protocol,
				int port,
				int name_type);
void cli_cm_display(const struct cli_state *c);
bool cli_dfs_get_referral(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			struct client_dfs_referral **refs,
			size_t *num_refs,
			size_t *consumed);
bool cli_resolve_path(TALLOC_CTX *ctx,
			const char *mountpt,
			const struct user_auth_info *dfs_auth_info,
			struct cli_state *rootcli,
			const char *path,
			struct cli_state **targetcli,
			char **pp_targetpath);

bool cli_check_msdfs_proxy(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *sharename,
			char **pp_newserver,
			char **pp_newshare,
			bool force_encrypt,
			const char *username,
			const char *password,
			const char *domain);

/* The following definitions come from libsmb/clientgen.c  */

int cli_set_message(char *buf,int num_words,int num_bytes,bool zero);
unsigned int cli_set_timeout(struct cli_state *cli, unsigned int timeout);
void cli_set_port(struct cli_state *cli, int port);
bool cli_state_seqnum_persistent(struct cli_state *cli,
				 uint16_t mid);
bool cli_state_seqnum_remove(struct cli_state *cli,
			     uint16_t mid);
bool cli_receive_smb(struct cli_state *cli);
ssize_t cli_receive_smb_data(struct cli_state *cli, char *buffer, size_t len);
bool cli_receive_smb_readX_header(struct cli_state *cli);
bool cli_send_smb(struct cli_state *cli);
bool cli_send_smb_direct_writeX(struct cli_state *cli,
				const char *p,
				size_t extradata);
void cli_setup_packet_buf(struct cli_state *cli, char *buf);
void cli_setup_packet(struct cli_state *cli);
void cli_setup_bcc(struct cli_state *cli, void *p);
NTSTATUS cli_set_domain(struct cli_state *cli, const char *domain);
NTSTATUS cli_set_username(struct cli_state *cli, const char *username);
NTSTATUS cli_set_password(struct cli_state *cli, const char *password);
NTSTATUS cli_init_creds(struct cli_state *cli, const char *username, const char *domain, const char *password);
struct cli_state *cli_initialise(void);
struct cli_state *cli_initialise_ex(int signing_state);
void cli_nt_pipes_close(struct cli_state *cli);
void cli_shutdown(struct cli_state *cli);
void cli_sockopt(struct cli_state *cli, const char *options);
uint16 cli_setpid(struct cli_state *cli, uint16 pid);
bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive);
bool cli_send_keepalive(struct cli_state *cli);
struct tevent_req *cli_echo_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct cli_state *cli, uint16_t num_echos,
				 DATA_BLOB data);
NTSTATUS cli_echo_recv(struct tevent_req *req);
NTSTATUS cli_echo(struct cli_state *cli, uint16_t num_echos, DATA_BLOB data);
bool cli_ucs2(struct cli_state *cli);
bool is_andx_req(uint8_t cmd);
NTSTATUS cli_smb(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		 uint8_t smb_command, uint8_t additional_flags,
		 uint8_t wct, uint16_t *vwv,
		 uint32_t num_bytes, const uint8_t *bytes,
		 struct tevent_req **result_parent,
		 uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		 uint32_t *pnum_bytes, uint8_t **pbytes);

/* The following definitions come from libsmb/clierror.c  */

const char *cli_errstr(struct cli_state *cli);
NTSTATUS cli_nt_error(struct cli_state *cli);
void cli_dos_error(struct cli_state *cli, uint8 *eclass, uint32 *ecode);
int cli_errno(struct cli_state *cli);
bool cli_is_error(struct cli_state *cli);
bool cli_is_nt_error(struct cli_state *cli);
bool cli_is_dos_error(struct cli_state *cli);
NTSTATUS cli_get_nt_error(struct cli_state *cli);
void cli_set_nt_error(struct cli_state *cli, NTSTATUS status);
void cli_reset_error(struct cli_state *cli);
bool cli_state_is_connected(struct cli_state *cli);

/* The following definitions come from libsmb/clifile.c  */

struct tevent_req *cli_posix_symlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname);
NTSTATUS cli_posix_symlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_symlink(struct cli_state *cli,
			const char *oldname,
			const char *newname);
struct tevent_req *cli_posix_readlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					size_t len);
NTSTATUS cli_posix_readlink_recv(struct tevent_req *req, struct cli_state *cli,
				char *retpath, size_t len);
NTSTATUS cli_posix_readlink(struct cli_state *cli, const char *fname,
			char *linkpath, size_t len);
struct tevent_req *cli_posix_hardlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname);
NTSTATUS cli_posix_hardlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_hardlink(struct cli_state *cli,
			const char *oldname,
			const char *newname);
uint32_t unix_perms_to_wire(mode_t perms);
mode_t wire_perms_to_unix(uint32_t perms);
struct tevent_req *cli_posix_getfacl_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_getfacl_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				size_t *prb_size,
				char **retbuf);
NTSTATUS cli_posix_getfacl(struct cli_state *cli,
			const char *fname,
			TALLOC_CTX *mem_ctx,
			size_t *prb_size,
			char **retbuf);
struct tevent_req *cli_posix_stat_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_stat_recv(struct tevent_req *req,
				SMB_STRUCT_STAT *sbuf);
NTSTATUS cli_posix_stat(struct cli_state *cli,
			const char *fname,
			SMB_STRUCT_STAT *sbuf);
struct tevent_req *cli_posix_chmod_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					mode_t mode);
NTSTATUS cli_posix_chmod_recv(struct tevent_req *req);
NTSTATUS cli_posix_chmod(struct cli_state *cli, const char *fname, mode_t mode);
struct tevent_req *cli_posix_chown_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					uid_t uid,
					gid_t gid);
NTSTATUS cli_posix_chown_recv(struct tevent_req *req);
NTSTATUS cli_posix_chown(struct cli_state *cli,
			const char *fname,
			uid_t uid,
			gid_t gid);
struct tevent_req *cli_rename_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                const char *fname_src,
                                const char *fname_dst);
NTSTATUS cli_rename_recv(struct tevent_req *req);
NTSTATUS cli_rename(struct cli_state *cli, const char *fname_src, const char *fname_dst);
struct tevent_req *cli_ntrename_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                const char *fname_src,
                                const char *fname_dst);
NTSTATUS cli_ntrename_recv(struct tevent_req *req);
NTSTATUS cli_ntrename(struct cli_state *cli, const char *fname_src, const char *fname_dst);

struct tevent_req *cli_nt_hardlink_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                const char *fname_src,
                                const char *fname_dst);
NTSTATUS cli_nt_hardlink_recv(struct tevent_req *req);
NTSTATUS cli_nt_hardlink(struct cli_state *cli, const char *fname_src, const char *fname_dst);

struct tevent_req *cli_unlink_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                const char *fname,
                                uint16_t mayhave_attrs);
NTSTATUS cli_unlink_recv(struct tevent_req *req);
NTSTATUS cli_unlink(struct cli_state *cli, const char *fname, uint16_t mayhave_attrs);

struct tevent_req *cli_mkdir_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *dname);
NTSTATUS cli_mkdir_recv(struct tevent_req *req);
NTSTATUS cli_mkdir(struct cli_state *cli, const char *dname);
struct tevent_req *cli_rmdir_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *dname);
NTSTATUS cli_rmdir_recv(struct tevent_req *req);
NTSTATUS cli_rmdir(struct cli_state *cli, const char *dname);
struct tevent_req *cli_nt_delete_on_close_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					bool flag);
NTSTATUS cli_nt_delete_on_close_recv(struct tevent_req *req);
NTSTATUS cli_nt_delete_on_close(struct cli_state *cli, uint16_t fnum, bool flag);
struct tevent_req *cli_ntcreate_send(TALLOC_CTX *mem_ctx,
				     struct event_context *ev,
				     struct cli_state *cli,
				     const char *fname,
				     uint32_t CreatFlags,
				     uint32_t DesiredAccess,
				     uint32_t FileAttributes,
				     uint32_t ShareAccess,
				     uint32_t CreateDisposition,
				     uint32_t CreateOptions,
				     uint8_t SecurityFlags);
NTSTATUS cli_ntcreate_recv(struct tevent_req *req, uint16_t *pfnum);
NTSTATUS cli_ntcreate(struct cli_state *cli,
		      const char *fname,
		      uint32_t CreatFlags,
		      uint32_t DesiredAccess,
		      uint32_t FileAttributes,
		      uint32_t ShareAccess,
		      uint32_t CreateDisposition,
		      uint32_t CreateOptions,
		      uint8_t SecurityFlags,
		      uint16_t *pfid);
uint8_t *smb_bytes_push_str(uint8_t *buf, bool ucs2, const char *str,
			    size_t str_len, size_t *pconverted_size);
struct tevent_req *cli_open_create(TALLOC_CTX *mem_ctx,
				   struct event_context *ev,
				   struct cli_state *cli, const char *fname,
				   int flags, int share_mode,
				   struct tevent_req **psmbreq);
struct tevent_req *cli_open_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct cli_state *cli, const char *fname,
				 int flags, int share_mode);
NTSTATUS cli_open_recv(struct tevent_req *req, uint16_t *fnum);
NTSTATUS cli_open(struct cli_state *cli, const char *fname, int flags, int share_mode, uint16_t *pfnum);
struct tevent_req *cli_close_create(TALLOC_CTX *mem_ctx,
				    struct event_context *ev,
				    struct cli_state *cli, uint16_t fnum,
				    struct tevent_req **psubreq);
struct tevent_req *cli_close_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli, uint16_t fnum);
NTSTATUS cli_close_recv(struct tevent_req *req);
NTSTATUS cli_close(struct cli_state *cli, uint16_t fnum);
struct tevent_req *cli_ftruncate_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					uint64_t size);
NTSTATUS cli_ftruncate_recv(struct tevent_req *req);
NTSTATUS cli_ftruncate(struct cli_state *cli, uint16_t fnum, uint64_t size);
NTSTATUS cli_locktype(struct cli_state *cli, uint16_t fnum,
		      uint32_t offset, uint32_t len,
		      int timeout, unsigned char locktype);
bool cli_lock(struct cli_state *cli, uint16_t fnum,
	      uint32_t offset, uint32_t len, int timeout, enum brl_type lock_type);
struct tevent_req *cli_unlock_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                uint16_t fnum,
                                uint64_t offset,
                                uint64_t len);
NTSTATUS cli_unlock_recv(struct tevent_req *req);
NTSTATUS cli_unlock(struct cli_state *cli, uint16_t fnum, uint32_t offset, uint32_t len);
bool cli_lock64(struct cli_state *cli, uint16_t fnum,
		uint64_t offset, uint64_t len, int timeout, enum brl_type lock_type);
struct tevent_req *cli_unlock64_send(TALLOC_CTX *mem_ctx,
                                struct event_context *ev,
                                struct cli_state *cli,
                                uint16_t fnum,
                                uint64_t offset,
                                uint64_t len);
NTSTATUS cli_unlock64_recv(struct tevent_req *req);
NTSTATUS cli_unlock64(struct cli_state *cli, uint16_t fnum, uint64_t offset, uint64_t len);
struct tevent_req *cli_posix_lock_send(TALLOC_CTX *mem_ctx,
                                        struct event_context *ev,
                                        struct cli_state *cli,
                                        uint16_t fnum,
                                        uint64_t offset,
                                        uint64_t len,
                                        bool wait_lock,
                                        enum brl_type lock_type);
NTSTATUS cli_posix_lock_recv(struct tevent_req *req);
NTSTATUS cli_posix_lock(struct cli_state *cli, uint16_t fnum,
			uint64_t offset, uint64_t len,
			bool wait_lock, enum brl_type lock_type);
struct tevent_req *cli_posix_unlock_send(TALLOC_CTX *mem_ctx,
                                        struct event_context *ev,
                                        struct cli_state *cli,
                                        uint16_t fnum,
                                        uint64_t offset,
                                        uint64_t len);
NTSTATUS cli_posix_unlock_recv(struct tevent_req *req);
NTSTATUS cli_posix_unlock(struct cli_state *cli, uint16_t fnum, uint64_t offset, uint64_t len);
struct tevent_req *cli_getattrE_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
                                uint16_t fnum);
NTSTATUS cli_getattrE_recv(struct tevent_req *req,
                        uint16_t *attr,
                        SMB_OFF_T *size,
                        time_t *change_time,
                        time_t *access_time,
                        time_t *write_time);
NTSTATUS cli_getattrE(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time);
struct tevent_req *cli_setattrE_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				time_t change_time,
				time_t access_time,
				time_t write_time);
NTSTATUS cli_setattrE_recv(struct tevent_req *req);
NTSTATUS cli_setattrE(struct cli_state *cli,
			uint16_t fnum,
			time_t change_time,
			time_t access_time,
			time_t write_time);
struct tevent_req *cli_getatr_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname);
NTSTATUS cli_getatr_recv(struct tevent_req *req,
				uint16_t *attr,
				SMB_OFF_T *size,
				time_t *write_time);
NTSTATUS cli_getatr(struct cli_state *cli,
			const char *fname,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *write_time);
struct tevent_req *cli_setatr_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname,
				uint16_t attr,
				time_t mtime);
NTSTATUS cli_setatr_recv(struct tevent_req *req);
NTSTATUS cli_setatr(struct cli_state *cli,
                const char *fname,
                uint16_t attr,
                time_t mtime);
struct tevent_req *cli_chkpath_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *fname);
NTSTATUS cli_chkpath_recv(struct tevent_req *req);
NTSTATUS cli_chkpath(struct cli_state *cli, const char *path);
struct tevent_req *cli_dskattr_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli);
NTSTATUS cli_dskattr_recv(struct tevent_req *req, int *bsize, int *total,
			  int *avail);
NTSTATUS cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail);
struct tevent_req *cli_ctemp_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *path);
NTSTATUS cli_ctemp_recv(struct tevent_req *req,
			TALLOC_CTX *ctx,
			uint16_t *pfnum,
			char **outfile);
NTSTATUS cli_ctemp(struct cli_state *cli,
			TALLOC_CTX *ctx,
			const char *path,
			uint16_t *pfnum,
			char **out_path);
NTSTATUS cli_raw_ioctl(struct cli_state *cli, uint16_t fnum, uint32_t code, DATA_BLOB *blob);
bool cli_set_ea_path(struct cli_state *cli, const char *path, const char *ea_name, const char *ea_val, size_t ea_len);
bool cli_set_ea_fnum(struct cli_state *cli, uint16_t fnum, const char *ea_name, const char *ea_val, size_t ea_len);
struct tevent_req *cli_get_ea_list_path_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli,
					     const char *fname);
NTSTATUS cli_get_ea_list_path_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				   size_t *pnum_eas, struct ea_struct **peas);
NTSTATUS cli_get_ea_list_path(struct cli_state *cli, const char *path,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list);
bool cli_get_ea_list_fnum(struct cli_state *cli, uint16_t fnum,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list);
struct tevent_req *cli_posix_open_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					int flags,
					mode_t mode);
NTSTATUS cli_posix_open_recv(struct tevent_req *req, uint16_t *pfnum);
NTSTATUS cli_posix_open(struct cli_state *cli, const char *fname,
			int flags, mode_t mode, uint16_t *fnum);
struct tevent_req *cli_posix_mkdir_send(TALLOC_CTX *mem_ctx,
                                        struct event_context *ev,
                                        struct cli_state *cli,
                                        const char *fname,
                                        mode_t mode);
NTSTATUS cli_posix_mkdir_recv(struct tevent_req *req);
NTSTATUS cli_posix_mkdir(struct cli_state *cli, const char *fname, mode_t mode);

struct tevent_req *cli_posix_unlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_unlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_unlink(struct cli_state *cli, const char *fname);

struct tevent_req *cli_posix_rmdir_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_rmdir_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);
NTSTATUS cli_posix_rmdir(struct cli_state *cli, const char *fname);
struct tevent_req *cli_notify_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct cli_state *cli, uint16_t fnum,
				   uint32_t buffer_size,
				   uint32_t completion_filter, bool recursive);
NTSTATUS cli_notify_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 uint32_t *pnum_changes,
			 struct notify_change **pchanges);

/* The following definitions come from libsmb/clifsinfo.c  */

struct tevent_req *cli_unix_extensions_version_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct cli_state *cli);
NTSTATUS cli_unix_extensions_version_recv(struct tevent_req *req,
					  uint16_t *pmajor, uint16_t *pminor,
					  uint32_t *pcaplow,
					  uint32_t *pcaphigh);
NTSTATUS cli_unix_extensions_version(struct cli_state *cli, uint16 *pmajor,
				     uint16 *pminor, uint32 *pcaplow,
				     uint32 *pcaphigh);
struct tevent_req *cli_set_unix_extensions_capabilities_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	uint16_t major, uint16_t minor, uint32_t caplow, uint32_t caphigh);
NTSTATUS cli_set_unix_extensions_capabilities_recv(struct tevent_req *req);
NTSTATUS cli_set_unix_extensions_capabilities(struct cli_state *cli,
					      uint16 major, uint16 minor,
					      uint32 caplow, uint32 caphigh);
struct tevent_req *cli_get_fs_attr_info_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli);
NTSTATUS cli_get_fs_attr_info_recv(struct tevent_req *req, uint32_t *fs_attr);
NTSTATUS cli_get_fs_attr_info(struct cli_state *cli, uint32_t *fs_attr);
NTSTATUS cli_get_fs_volume_info(struct cli_state *cli, fstring volume_name,
				uint32 *pserial_number, time_t *pdate);
bool cli_get_fs_full_size_info(struct cli_state *cli,
                               uint64_t *total_allocation_units,
                               uint64_t *caller_allocation_units,
                               uint64_t *actual_allocation_units,
                               uint64_t *sectors_per_allocation_unit,
                               uint64_t *bytes_per_sector);
bool cli_get_posix_fs_info(struct cli_state *cli,
                           uint32 *optimal_transfer_size,
                           uint32 *block_size,
                           uint64_t *total_blocks,
                           uint64_t *blocks_available,
                           uint64_t *user_blocks_available,
                           uint64_t *total_file_nodes,
                           uint64_t *free_file_nodes,
                           uint64_t *fs_identifier);
NTSTATUS cli_raw_ntlm_smb_encryption_start(struct cli_state *cli, 
				const char *user,
				const char *pass,
				const char *domain);
NTSTATUS cli_gss_smb_encryption_start(struct cli_state *cli);
NTSTATUS cli_force_encryption(struct cli_state *c,
			const char *username,
			const char *password,
			const char *domain);

/* The following definitions come from libsmb/clikrb5.c  */

bool unwrap_edata_ntstatus(TALLOC_CTX *mem_ctx, 
			   DATA_BLOB *edata, 
			   DATA_BLOB *edata_out);
bool unwrap_pac(TALLOC_CTX *mem_ctx, DATA_BLOB *auth_data, DATA_BLOB *unwrapped_pac_data);

/* The following definitions come from libsmb/clilist.c  */

int cli_list_new(struct cli_state *cli,const char *Mask,uint16 attribute,
		 void (*fn)(const char *, struct file_info *, const char *,
			    void *), void *state);
int cli_list_old(struct cli_state *cli,const char *Mask,uint16 attribute,
		 void (*fn)(const char *, struct file_info *, const char *,
			    void *), void *state);
int cli_list(struct cli_state *cli,const char *Mask,uint16 attribute,
	     void (*fn)(const char *, struct file_info *, const char *,
			void *), void *state);

/* The following definitions come from libsmb/climessage.c  */

struct tevent_req *cli_message_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    const char *host, const char *username,
				    const char *message);
NTSTATUS cli_message_recv(struct tevent_req *req);
NTSTATUS cli_message(struct cli_state *cli, const char *host,
		     const char *username, const char *message);

/* The following definitions come from libsmb/clioplock.c  */

struct tevent_req *cli_oplock_ack_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli,
				       uint16_t fnum, uint8_t level);
NTSTATUS cli_oplock_ack_recv(struct tevent_req *req);
NTSTATUS cli_oplock_ack(struct cli_state *cli, uint16_t fnum, unsigned char level);
void cli_oplock_handler(struct cli_state *cli, 
			NTSTATUS (*handler)(struct cli_state *, uint16_t, unsigned char));

/* The following definitions come from libsmb/cliprint.c  */

int cli_print_queue(struct cli_state *cli,
		    void (*fn)(struct print_job_info *));
int cli_printjob_del(struct cli_state *cli, int job);
int cli_spl_open(struct cli_state *cli, const char *fname, int flags, int share_mode);
bool cli_spl_close(struct cli_state *cli, uint16_t fnum);

/* The following definitions come from libsmb/cliquota.c  */

NTSTATUS cli_get_quota_handle(struct cli_state *cli, uint16_t *quota_fnum);
void free_ntquota_list(SMB_NTQUOTA_LIST **qt_list);
bool cli_get_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_set_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_list_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_LIST **pqt_list);
bool cli_get_fs_quota_info(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_set_fs_quota_info(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
void dump_ntquota(SMB_NTQUOTA_STRUCT *qt, bool _verbose, bool _numeric, void (*_sidtostring)(fstring str, struct dom_sid *sid, bool _numeric));
void dump_ntquota_list(SMB_NTQUOTA_LIST **qtl, bool _verbose, bool _numeric, void (*_sidtostring)(fstring str, struct dom_sid *sid, bool _numeric));

/* The following definitions come from libsmb/clirap.c  */

bool cli_api(struct cli_state *cli,
	     char *param, int prcnt, int mprcnt,
	     char *data, int drcnt, int mdrcnt,
	     char **rparam, unsigned int *rprcnt,
	     char **rdata, unsigned int *rdrcnt);
bool cli_NetWkstaUserLogon(struct cli_state *cli,char *user, char *workstation);
int cli_RNetShareEnum(struct cli_state *cli, void (*fn)(const char *, uint32, const char *, void *), void *state);
bool cli_NetServerEnum(struct cli_state *cli, char *workgroup, uint32 stype,
		       void (*fn)(const char *, uint32, const char *, void *),
		       void *state);
bool cli_oem_change_password(struct cli_state *cli, const char *user, const char *new_password,
                             const char *old_password);
struct tevent_req *cli_qpathinfo1_send(TALLOC_CTX *mem_ctx,
				       struct event_context *ev,
				       struct cli_state *cli,
				       const char *fname);
NTSTATUS cli_qpathinfo1_recv(struct tevent_req *req,
			     time_t *change_time,
			     time_t *access_time,
			     time_t *write_time,
			     SMB_OFF_T *size,
			     uint16 *mode);
NTSTATUS cli_qpathinfo1(struct cli_state *cli,
			const char *fname,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time,
			SMB_OFF_T *size,
			uint16 *mode);
bool cli_setpathinfo(struct cli_state *cli, const char *fname,
                     time_t create_time,
                     time_t access_time,
                     time_t write_time,
                     time_t change_time,
                     uint16 mode);
struct tevent_req *cli_qpathinfo2_send(TALLOC_CTX *mem_ctx,
				       struct event_context *ev,
				       struct cli_state *cli,
				       const char *fname);
NTSTATUS cli_qpathinfo2_recv(struct tevent_req *req,
			     struct timespec *create_time,
			     struct timespec *access_time,
			     struct timespec *write_time,
			     struct timespec *change_time,
			     SMB_OFF_T *size, uint16 *mode,
			     SMB_INO_T *ino);
NTSTATUS cli_qpathinfo2(struct cli_state *cli, const char *fname,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			SMB_OFF_T *size, uint16 *mode,
			SMB_INO_T *ino);
struct tevent_req *cli_qpathinfo_streams_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct cli_state *cli,
					      const char *fname);
NTSTATUS cli_qpathinfo_streams_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    unsigned int *pnum_streams,
				    struct stream_struct **pstreams);
NTSTATUS cli_qpathinfo_streams(struct cli_state *cli, const char *fname,
			       TALLOC_CTX *mem_ctx,
			       unsigned int *pnum_streams,
			       struct stream_struct **pstreams);
bool cli_qfilename(struct cli_state *cli, uint16_t fnum, char *name, size_t namelen);
bool cli_qfileinfo(struct cli_state *cli, uint16_t fnum,
		   uint16 *mode, SMB_OFF_T *size,
		   struct timespec *create_time,
                   struct timespec *access_time,
                   struct timespec *write_time,
		   struct timespec *change_time,
                   SMB_INO_T *ino);
struct tevent_req *cli_qpathinfo_basic_send(TALLOC_CTX *mem_ctx,
					    struct event_context *ev,
					    struct cli_state *cli,
					    const char *fname);
NTSTATUS cli_qpathinfo_basic_recv(struct tevent_req *req,
				  SMB_STRUCT_STAT *sbuf, uint32 *attributes);
NTSTATUS cli_qpathinfo_basic(struct cli_state *cli, const char *name,
			     SMB_STRUCT_STAT *sbuf, uint32 *attributes);
bool cli_qfileinfo_test(struct cli_state *cli, uint16_t fnum, int level, char **poutdata, uint32 *poutlen);
NTSTATUS cli_qpathinfo_alt_name(struct cli_state *cli, const char *fname, fstring alt_name);
struct tevent_req *cli_qpathinfo_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli, const char *fname,
				      uint16_t level, uint32_t min_rdata,
				      uint32_t max_rdata);
NTSTATUS cli_qpathinfo_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    uint8_t **rdata, uint32_t *num_rdata);
NTSTATUS cli_qpathinfo(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		       const char *fname, uint16_t level, uint32_t min_rdata,
		       uint32_t max_rdata,
		       uint8_t **rdata, uint32_t *num_rdata);

/* The following definitions come from libsmb/clirap2.c  */
struct rap_group_info_1;
struct rap_user_info_1;
struct rap_share_info_2;

int cli_NetGroupDelete(struct cli_state *cli, const char *group_name);
int cli_NetGroupAdd(struct cli_state *cli, struct rap_group_info_1 *grinfo);
int cli_RNetGroupEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_RNetGroupEnum0(struct cli_state *cli,
		       void (*fn)(const char *, void *),
		       void *state);
int cli_NetGroupDelUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupAddUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupGetUsers(struct cli_state * cli, const char *group_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserGetGroups(struct cli_state * cli, const char *user_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserDelete(struct cli_state *cli, const char * user_name );
int cli_NetUserAdd(struct cli_state *cli, struct rap_user_info_1 * userinfo );
int cli_RNetUserEnum(struct cli_state *cli, void (*fn)(const char *, const char *, const char *, const char *, void *), void *state);
int cli_RNetUserEnum0(struct cli_state *cli,
		      void (*fn)(const char *, void *),
		      void *state);
int cli_NetFileClose(struct cli_state *cli, uint32 file_id );
int cli_NetFileGetInfo(struct cli_state *cli, uint32 file_id, void (*fn)(const char *, const char *, uint16, uint16, uint32));
int cli_NetFileEnum(struct cli_state *cli, const char * user,
		    const char * base_path,
		    void (*fn)(const char *, const char *, uint16, uint16,
			       uint32));
int cli_NetShareAdd(struct cli_state *cli, struct rap_share_info_2 * sinfo );
int cli_NetShareDelete(struct cli_state *cli, const char * share_name );
bool cli_get_pdc_name(struct cli_state *cli, const char *workgroup, char **pdc_name);
bool cli_get_server_domain(struct cli_state *cli);
bool cli_get_server_type(struct cli_state *cli, uint32 *pstype);
bool cli_get_server_name(TALLOC_CTX *mem_ctx, struct cli_state *cli,
			 char **servername);
bool cli_ns_check_server_type(struct cli_state *cli, char *workgroup, uint32 stype);
bool cli_NetWkstaUserLogoff(struct cli_state *cli, const char *user, const char *workstation);
int cli_NetPrintQEnum(struct cli_state *cli,
		void (*qfn)(const char*,uint16,uint16,uint16,const char*,const char*,const char*,const char*,const char*,uint16,uint16),
		void (*jfn)(uint16,const char*,const char*,const char*,const char*,uint16,uint16,const char*,unsigned int,unsigned int,const char*));
int cli_NetPrintQGetInfo(struct cli_state *cli, const char *printer,
	void (*qfn)(const char*,uint16,uint16,uint16,const char*,const char*,const char*,const char*,const char*,uint16,uint16),
	void (*jfn)(uint16,const char*,const char*,const char*,const char*,uint16,uint16,const char*,unsigned int,unsigned int,const char*));
int cli_RNetServiceEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_NetSessionEnum(struct cli_state *cli, void (*fn)(char *, char *, uint16, uint16, uint16, unsigned int, unsigned int, unsigned int, char *));
int cli_NetSessionGetInfo(struct cli_state *cli, const char *workstation,
		void (*fn)(const char *, const char *, uint16, uint16, uint16, unsigned int, unsigned int, unsigned int, const char *));
int cli_NetSessionDel(struct cli_state *cli, const char *workstation);
int cli_NetConnectionEnum(struct cli_state *cli, const char *qualifier,
			void (*fn)(uint16_t conid, uint16_t contype,
				uint16_t numopens, uint16_t numusers,
				uint32_t contime, const char *username,
				const char *netname));

/* The following definitions come from libsmb/clireadwrite.c  */

struct tevent_req *cli_read_andx_create(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli, uint16_t fnum,
					off_t offset, size_t size,
					struct tevent_req **psmbreq);
struct tevent_req *cli_read_andx_send(TALLOC_CTX *mem_ctx,
				      struct event_context *ev,
				      struct cli_state *cli, uint16_t fnum,
				      off_t offset, size_t size);
NTSTATUS cli_read_andx_recv(struct tevent_req *req, ssize_t *received,
			    uint8_t **rcvbuf);
struct tevent_req *cli_pull_send(TALLOC_CTX *mem_ctx,
				 struct event_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, off_t start_offset,
				 SMB_OFF_T size, size_t window_size,
				 NTSTATUS (*sink)(char *buf, size_t n,
						  void *priv),
				 void *priv);
NTSTATUS cli_pull_recv(struct tevent_req *req, SMB_OFF_T *received);
NTSTATUS cli_pull(struct cli_state *cli, uint16_t fnum,
		  off_t start_offset, SMB_OFF_T size, size_t window_size,
		  NTSTATUS (*sink)(char *buf, size_t n, void *priv),
		  void *priv, SMB_OFF_T *received);
ssize_t cli_read(struct cli_state *cli, uint16_t fnum, char *buf,
		 off_t offset, size_t size);
ssize_t cli_readraw(struct cli_state *cli, uint16_t fnum, char *buf, off_t offset, size_t size);
ssize_t cli_write(struct cli_state *cli,
    	         uint16_t fnum, uint16 write_mode,
		 const char *buf, off_t offset, size_t size);
ssize_t cli_smbwrite(struct cli_state *cli,
		     uint16_t fnum, char *buf, off_t offset, size_t size1);
struct tevent_req *cli_write_andx_create(TALLOC_CTX *mem_ctx,
					 struct event_context *ev,
					 struct cli_state *cli, uint16_t fnum,
					 uint16_t mode, const uint8_t *buf,
					 off_t offset, size_t size,
					 struct tevent_req **reqs_before,
					 int num_reqs_before,
					 struct tevent_req **psmbreq);
struct tevent_req *cli_write_andx_send(TALLOC_CTX *mem_ctx,
				       struct event_context *ev,
				       struct cli_state *cli, uint16_t fnum,
				       uint16_t mode, const uint8_t *buf,
				       off_t offset, size_t size);
NTSTATUS cli_write_andx_recv(struct tevent_req *req, size_t *pwritten);

struct tevent_req *cli_push_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, uint16_t mode,
				 off_t start_offset, size_t window_size,
				 size_t (*source)(uint8_t *buf, size_t n,
						  void *priv),
				 void *priv);
NTSTATUS cli_push_recv(struct tevent_req *req);
NTSTATUS cli_push(struct cli_state *cli, uint16_t fnum, uint16_t mode,
		  off_t start_offset, size_t window_size,
		  size_t (*source)(uint8_t *buf, size_t n, void *priv),
		  void *priv);

/* The following definitions come from libsmb/clisecdesc.c  */

struct security_descriptor *cli_query_secdesc(struct cli_state *cli, uint16_t fnum,
			    TALLOC_CTX *mem_ctx);
bool cli_set_secdesc(struct cli_state *cli, uint16_t fnum, struct security_descriptor *sd);

/* The following definitions come from libsmb/clispnego.c  */

DATA_BLOB spnego_gen_negTokenInit(TALLOC_CTX *ctx,
				  const char *OIDs[],
				  DATA_BLOB *psecblob,
				  const char *principal);
bool spnego_parse_negTokenInit(TALLOC_CTX *ctx,
			       DATA_BLOB blob,
			       char *OIDs[ASN1_MAX_OIDS],
			       char **principal,
			       DATA_BLOB *secblob);
DATA_BLOB spnego_gen_krb5_wrap(TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8 tok_id[2]);
bool spnego_parse_krb5_wrap(TALLOC_CTX *ctx, DATA_BLOB blob, DATA_BLOB *ticket, uint8 tok_id[2]);
int spnego_gen_krb5_negTokenInit(TALLOC_CTX *ctx,
			    const char *principal, int time_offset,
			    DATA_BLOB *targ,
			    DATA_BLOB *session_key_krb5, uint32 extra_ap_opts,
			    time_t *expire_time);
bool spnego_parse_challenge(TALLOC_CTX *ctx, const DATA_BLOB blob,
			    DATA_BLOB *chal1, DATA_BLOB *chal2);
DATA_BLOB spnego_gen_auth(TALLOC_CTX *ctx, DATA_BLOB blob);
bool spnego_parse_auth(TALLOC_CTX *ctx, DATA_BLOB blob, DATA_BLOB *auth);
DATA_BLOB spnego_gen_auth_response(TALLOC_CTX *ctx, DATA_BLOB *reply, NTSTATUS nt_status,
				   const char *mechOID);
bool spnego_parse_auth_response(TALLOC_CTX *ctx,
				DATA_BLOB blob, NTSTATUS nt_status,
				const char *mechOID,
				DATA_BLOB *auth);

/* The following definitions come from libsmb/clistr.c  */

size_t clistr_push_fn(const char *function,
			unsigned int line,
			struct cli_state *cli,
			void *dest,
			const char *src,
			int dest_len,
			int flags);
size_t clistr_pull_fn(const char *function,
			unsigned int line,
			const char *inbuf,
			char *dest,
			const void *src,
			int dest_len,
			int src_len,
			int flags);
size_t clistr_pull_talloc_fn(const char *function,
				unsigned int line,
				TALLOC_CTX *ctx,
				const char *inbuf,
				char **pp_dest,
				const void *src,
				int src_len,
				int flags);
size_t clistr_align_out(struct cli_state *cli, const void *p, int flags);
size_t clistr_align_in(struct cli_state *cli, const void *p, int flags);

/* The following definitions come from libsmb/clitrans.c  */

bool cli_send_trans(struct cli_state *cli, int trans,
		    const char *pipe_name,
		    int fid, int flags,
		    uint16 *setup, unsigned int lsetup, unsigned int msetup,
		    const char *param, unsigned int lparam, unsigned int mparam,
		    const char *data, unsigned int ldata, unsigned int mdata);
bool cli_receive_trans(struct cli_state *cli,int trans,
                              char **param, unsigned int *param_len,
                              char **data, unsigned int *data_len);
bool cli_send_nt_trans(struct cli_state *cli,
		       int function,
		       int flags,
		       uint16 *setup, unsigned int lsetup, unsigned int msetup,
		       char *param, unsigned int lparam, unsigned int mparam,
		       char *data, unsigned int ldata, unsigned int mdata);
bool cli_receive_nt_trans(struct cli_state *cli,
			  char **param, unsigned int *param_len,
			  char **data, unsigned int *data_len);
struct tevent_req *cli_trans_send(
	TALLOC_CTX *mem_ctx, struct event_context *ev,
	struct cli_state *cli, uint8_t cmd,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data);
NTSTATUS cli_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			uint16_t **setup, uint8_t min_setup,
			uint8_t *num_setup,
			uint8_t **param, uint32_t min_param,
			uint32_t *num_param,
			uint8_t **data, uint32_t min_data,
			uint32_t *num_data);
NTSTATUS cli_trans(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		   uint8_t trans_cmd,
		   const char *pipe_name, uint16_t fid, uint16_t function,
		   int flags,
		   uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
		   uint8_t *param, uint32_t num_param, uint32_t max_param,
		   uint8_t *data, uint32_t num_data, uint32_t max_data,
		   uint16_t **rsetup, uint8_t min_rsetup, uint8_t *num_rsetup,
		   uint8_t **rparam, uint32_t min_rparam, uint32_t *num_rparam,
		   uint8_t **rdata, uint32_t min_rdata, uint32_t *num_rdata);

/* The following definitions come from libsmb/conncache.c  */

NTSTATUS check_negative_conn_cache_timeout( const char *domain, const char *server, unsigned int failed_cache_timeout );
NTSTATUS check_negative_conn_cache( const char *domain, const char *server);
void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) ;
void flush_negative_conn_cache_for_domain(const char *domain);

/* The following definitions come from ../librpc/rpc/dcerpc_error.c  */

const char *dcerpc_errstr(TALLOC_CTX *mem_ctx, uint32_t fault_code);
NTSTATUS dcerpc_fault_to_nt_status(uint32_t fault_code);

/* The following definitions come from ../librpc/rpc/dcerpc_util.c  */

void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v);
uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob);
void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v);
uint8_t dcerpc_get_endian_flag(DATA_BLOB *blob);
NTSTATUS dcerpc_pull_auth_trailer(struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *pkt_trailer,
				  struct dcerpc_auth *auth,
				  uint32_t *auth_length,
				  bool auth_data_only);

/* The following definitions come from libsmb/dsgetdcname.c  */

void debug_dsdcinfo_flags(int lvl, uint32_t flags);
NTSTATUS dsgetdcname(TALLOC_CTX *mem_ctx,
		     struct messaging_context *msg_ctx,
		     const char *domain_name,
		     const struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info);

/* The following definitions come from libsmb/errormap.c  */

NTSTATUS dos_to_ntstatus(uint8 eclass, uint32 ecode);
void ntstatus_to_dos(NTSTATUS ntstatus, uint8 *eclass, uint32 *ecode);
NTSTATUS werror_to_ntstatus(WERROR error);
WERROR ntstatus_to_werror(NTSTATUS error);
NTSTATUS map_nt_error_from_wbcErr(wbcErr wbc_err);
NTSTATUS map_nt_error_from_gss(uint32 gss_maj, uint32 minor);

/* The following definitions come from libsmb/namecache.c  */

bool namecache_enable(void);
bool namecache_store(const char *name,
			int name_type,
			int num_names,
			struct ip_service *ip_list);
bool namecache_fetch(const char *name,
			int name_type,
			struct ip_service **ip_list,
			int *num_names);
bool namecache_delete(const char *name, int name_type);
void namecache_flush(void);
bool namecache_status_store(const char *keyname, int keyname_type,
		int name_type, const struct sockaddr_storage *keyip,
		const char *srvname);
bool namecache_status_fetch(const char *keyname,
				int keyname_type,
				int name_type,
				const struct sockaddr_storage *keyip,
				char *srvname_out);

/* The following definitions come from libsmb/namequery.c  */

bool saf_store( const char *domain, const char *servername );
bool saf_join_store( const char *domain, const char *servername );
bool saf_delete( const char *domain );
char *saf_fetch( const char *domain );
NODE_STATUS_STRUCT *node_status_query(int fd,
					struct nmb_name *name,
					const struct sockaddr_storage *to_ss,
					int *num_names,
					struct node_status_extra *extra);
bool name_status_find(const char *q_name,
			int q_type,
			int type,
			const struct sockaddr_storage *to_ss,
			fstring name);
int ip_service_compare(struct ip_service *ss1, struct ip_service *ss2);
struct sockaddr_storage *name_query(int fd,
			const char *name,
			int name_type,
			bool bcast,
			bool recurse,
			const struct sockaddr_storage *to_ss,
			int *count,
			int *flags,
			bool *timed_out);
NTSTATUS name_resolve_bcast(const char *name,
			int name_type,
			struct ip_service **return_iplist,
			int *return_count);
NTSTATUS resolve_wins(const char *name,
		int name_type,
		struct ip_service **return_iplist,
		int *return_count);
NTSTATUS internal_resolve_name(const char *name,
			        int name_type,
				const char *sitename,
				struct ip_service **return_iplist,
				int *return_count,
				const char *resolve_order);
bool resolve_name(const char *name,
		struct sockaddr_storage *return_ss,
		int name_type,
		bool prefer_ipv4);
NTSTATUS resolve_name_list(TALLOC_CTX *ctx,
		const char *name,
		int name_type,
		struct sockaddr_storage **return_ss_arr,
		unsigned int *p_num_entries);
bool find_master_ip(const char *group, struct sockaddr_storage *master_ss);
bool get_pdc_ip(const char *domain, struct sockaddr_storage *pss);
NTSTATUS get_sorted_dc_list( const char *domain,
			const char *sitename,
			struct ip_service **ip_list,
			int *count,
			bool ads_only );
NTSTATUS get_kdc_list( const char *realm,
			const char *sitename,
			struct ip_service **ip_list,
			int *count);

/* The following definitions come from libsmb/namequery_dc.c  */

bool get_dc_name(const char *domain,
		const char *realm,
		fstring srv_name,
		struct sockaddr_storage *ss_out);

/* The following definitions come from libsmb/nmblib.c  */

void debug_nmb_packet(struct packet_struct *p);
void put_name(char *dest, const char *name, int pad, unsigned int name_type);
char *nmb_namestr(const struct nmb_name *n);
struct packet_struct *copy_packet(struct packet_struct *packet);
void free_packet(struct packet_struct *packet);
struct packet_struct *parse_packet(char *buf,int length,
				   enum packet_type packet_type,
				   struct in_addr ip,
				   int port);
struct packet_struct *read_packet(int fd,enum packet_type packet_type);
void make_nmb_name( struct nmb_name *n, const char *name, int type);
bool nmb_name_equal(struct nmb_name *n1, struct nmb_name *n2);
int build_packet(char *buf, size_t buflen, struct packet_struct *p);
bool send_packet(struct packet_struct *p);
struct packet_struct *receive_packet(int fd,enum packet_type type,int t);
struct packet_struct *receive_nmb_packet(int fd, int t, int trn_id);
struct packet_struct *receive_dgram_packet(int fd, int t,
		const char *mailslot_name);
bool match_mailslot_name(struct packet_struct *p, const char *mailslot_name);
int matching_len_bits(unsigned char *p1, unsigned char *p2, size_t len);
void sort_query_replies(char *data, int n, struct in_addr ip);
char *name_mangle(TALLOC_CTX *mem_ctx, char *In, char name_type);
int name_extract(char *buf,int ofs, fstring name);
int name_len(char *s1);

/* The following definitions come from libsmb/nterr.c  */

const char *nt_errstr(NTSTATUS nt_code);
const char *get_friendly_nt_error_msg(NTSTATUS nt_code);
const char *get_nt_error_c_code(NTSTATUS nt_code);
NTSTATUS nt_status_string_to_code(const char *nt_status_str);
NTSTATUS nt_status_squash(NTSTATUS nt_status);

/* The following definitions come from libsmb/ntlmssp.c  */

NTSTATUS ntlmssp_set_username(struct ntlmssp_state *ntlmssp_state, const char *user) ;
NTSTATUS ntlmssp_set_hashes(struct ntlmssp_state *ntlmssp_state,
			    const uint8_t lm_hash[16],
			    const uint8_t nt_hash[16]) ;
NTSTATUS ntlmssp_set_password(struct ntlmssp_state *ntlmssp_state, const char *password) ;
NTSTATUS ntlmssp_set_domain(struct ntlmssp_state *ntlmssp_state, const char *domain) ;
void ntlmssp_want_feature_list(struct ntlmssp_state *ntlmssp_state, char *feature_list);
void ntlmssp_want_feature(struct ntlmssp_state *ntlmssp_state, uint32_t feature);
NTSTATUS ntlmssp_update(struct ntlmssp_state *ntlmssp_state,
			const DATA_BLOB in, DATA_BLOB *out) ;
DATA_BLOB ntlmssp_weaken_keys(struct ntlmssp_state *ntlmssp_state, TALLOC_CTX *mem_ctx);
NTSTATUS ntlmssp_server_start(TALLOC_CTX *mem_ctx,
			      bool is_standalone,
			      const char *netbios_name,
			      const char *netbios_domain,
			      const char *dns_name,
			      const char *dns_domain,
			      struct ntlmssp_state **ntlmssp_state);
NTSTATUS ntlmssp_client_start(TALLOC_CTX *mem_ctx,
			      const char *netbios_name,
			      const char *netbios_domain,
			      bool use_ntlmv2,
			      struct ntlmssp_state **_ntlmssp_state);

/* The following definitions come from libsmb/passchange.c  */

NTSTATUS remote_password_change(const char *remote_machine, const char *user_name, 
				const char *old_passwd, const char *new_passwd,
				char **err_str);

/* The following definitions come from libsmb/samlogon_cache.c  */

bool netsamlogon_cache_init(void);
bool netsamlogon_cache_shutdown(void);
void netsamlogon_clear_cached_user(struct netr_SamInfo3 *info3);
bool netsamlogon_cache_store(const char *username, struct netr_SamInfo3 *info3);
struct netr_SamInfo3 *netsamlogon_cache_get(TALLOC_CTX *mem_ctx, const struct dom_sid *user_sid);
bool netsamlogon_cache_have(const struct dom_sid *user_sid);

/* The following definitions come from libsmb/smb_seal.c  */

NTSTATUS get_enc_ctx_num(const uint8_t *buf, uint16 *p_enc_ctx_num);
bool common_encryption_on(struct smb_trans_enc_state *es);
NTSTATUS common_ntlm_decrypt_buffer(struct ntlmssp_state *ntlmssp_state, char *buf);
NTSTATUS common_ntlm_encrypt_buffer(struct ntlmssp_state *ntlmssp_state,
				uint16 enc_ctx_num,
				char *buf,
				char **ppbuf_out);
NTSTATUS common_encrypt_buffer(struct smb_trans_enc_state *es, char *buffer, char **buf_out);
NTSTATUS common_decrypt_buffer(struct smb_trans_enc_state *es, char *buf);
void common_free_encryption_state(struct smb_trans_enc_state **pp_es);
void common_free_enc_buffer(struct smb_trans_enc_state *es, char *buf);
bool cli_encryption_on(struct cli_state *cli);
void cli_free_encryption_context(struct cli_state *cli);
void cli_free_enc_buffer(struct cli_state *cli, char *buf);
NTSTATUS cli_decrypt_message(struct cli_state *cli);
NTSTATUS cli_encrypt_message(struct cli_state *cli, char *buf, char **buf_out);

/* The following definitions come from libsmb/clisigning.c  */

bool cli_simple_set_signing(struct cli_state *cli,
			    const DATA_BLOB user_session_key,
			    const DATA_BLOB response);
bool cli_temp_set_signing(struct cli_state *cli);
void cli_calculate_sign_mac(struct cli_state *cli, char *buf, uint32_t *seqnum);
bool cli_check_sign_mac(struct cli_state *cli, const char *buf, uint32_t seqnum);
bool client_is_signing_on(struct cli_state *cli);
bool client_is_signing_allowed(struct cli_state *cli);
bool client_is_signing_mandatory(struct cli_state *cli);
void cli_set_signing_negotiated(struct cli_state *cli);

/* The following definitions come from smbd/signing.c  */

struct smbd_server_connection;
bool srv_check_sign_mac(struct smbd_server_connection *conn,
			const char *inbuf, uint32_t *seqnum, bool trusted_channel);
void srv_calculate_sign_mac(struct smbd_server_connection *conn,
			    char *outbuf, uint32_t seqnum);
void srv_cancel_sign_response(struct smbd_server_connection *conn);
bool srv_init_signing(struct smbd_server_connection *conn);
void srv_set_signing_negotiated(struct smbd_server_connection *conn);
bool srv_is_signing_active(struct smbd_server_connection *conn);
bool srv_is_signing_negotiated(struct smbd_server_connection *conn);
void srv_set_signing(struct smbd_server_connection *conn,
		     const DATA_BLOB user_session_key,
		     const DATA_BLOB response);

/* The following definitions come from libsmb/smberr.c  */

const char *smb_dos_err_name(uint8 e_class, uint16 num);
const char *get_dos_error_msg(WERROR result);
const char *smb_dos_err_class(uint8 e_class);
char *smb_dos_errstr(char *inbuf);
WERROR map_werror_from_unix(int error);

/* The following definitions come from libsmb/trustdom_cache.c  */

bool trustdom_cache_enable(void);
bool trustdom_cache_shutdown(void);
bool trustdom_cache_store(char* name, char* alt_name, const struct dom_sid *sid,
                          time_t timeout);
bool trustdom_cache_fetch(const char* name, struct dom_sid* sid);
uint32 trustdom_cache_fetch_timestamp( void );
bool trustdom_cache_store_timestamp( uint32 t, time_t timeout );
void trustdom_cache_flush(void);
void update_trustdom_cache( void );

/* The following definitions come from libsmb/trusts_util.c  */

NTSTATUS trust_pw_change_and_store_it(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				      const char *domain,
				      const char *account_name,
				      unsigned char orig_trust_passwd_hash[16],
				      enum netr_SchannelType sec_channel_type);
NTSTATUS trust_pw_find_change_and_store_it(struct rpc_pipe_client *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) ;
bool enumerate_domain_trusts( TALLOC_CTX *mem_ctx, const char *domain,
                                     char ***domain_names, uint32 *num_domains,
				     struct dom_sid **sids );
NTSTATUS change_trust_account_password( const char *domain, const char *remote_machine);

/* The following definitions come from libsmb/unexpected.c  */

void unexpected_packet(struct packet_struct *p);
void clear_unexpected(time_t t);
struct packet_struct *receive_unexpected(enum packet_type packet_type, int id,
					 const char *mailslot_name);

/* The following definitions come from locking/brlock.c  */

bool brl_same_context(const struct lock_context *ctx1, 
			     const struct lock_context *ctx2);
NTSTATUS brl_lock_failed(files_struct *fsp, const struct lock_struct *lock, bool blocking_lock);
void brl_init(bool read_only);
void brl_shutdown(void);

NTSTATUS brl_lock_windows_default(struct byte_range_lock *br_lck,
		struct lock_struct *plock,
		bool blocking_lock);

NTSTATUS brl_lock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		bool blocking_lock,
		uint64_t *psmblctx,
		struct blocking_lock_record *blr);
bool brl_unlock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav);
bool brl_unlock_windows_default(struct messaging_context *msg_ctx,
			       struct byte_range_lock *br_lck,
			       const struct lock_struct *plock);
bool brl_locktest(struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav);
NTSTATUS brl_lockquery(struct byte_range_lock *br_lck,
		uint64_t *psmblctx,
		struct server_id pid,
		br_off *pstart,
		br_off *psize, 
		enum brl_type *plock_type,
		enum brl_flavour lock_flav);
bool brl_lock_cancel(struct byte_range_lock *br_lck,
		uint64_t smblctx,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav,
		struct blocking_lock_record *blr);
bool brl_lock_cancel_default(struct byte_range_lock *br_lck,
		struct lock_struct *plock);
void brl_close_fnum(struct messaging_context *msg_ctx,
		    struct byte_range_lock *br_lck);
int brl_forall(void (*fn)(struct file_id id, struct server_id pid,
			  enum brl_type lock_type,
			  enum brl_flavour lock_flav,
			  br_off start, br_off size,
			  void *private_data),
	       void *private_data);
struct byte_range_lock *brl_get_locks(TALLOC_CTX *mem_ctx,
					files_struct *fsp);
struct byte_range_lock *brl_get_locks_readonly(files_struct *fsp);
void brl_register_msgs(struct messaging_context *msg_ctx);

/* The following definitions come from locking/locking.c  */

const char *lock_type_name(enum brl_type lock_type);
const char *lock_flav_name(enum brl_flavour lock_flav);
void init_strict_lock_struct(files_struct *fsp,
				uint64_t smblctx,
				br_off start,
				br_off size,
				enum brl_type lock_type,
				struct lock_struct *plock);
bool strict_lock_default(files_struct *fsp,
				struct lock_struct *plock);
void strict_unlock_default(files_struct *fsp,
				struct lock_struct *plock);
NTSTATUS query_lock(files_struct *fsp,
			uint64_t *psmblctx,
			uint64_t *pcount,
			uint64_t *poffset,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
struct byte_range_lock *do_lock(struct messaging_context *msg_ctx,
			files_struct *fsp,
			uint64_t smblctx,
			uint64_t count,
			uint64_t offset,
			enum brl_type lock_type,
			enum brl_flavour lock_flav,
			bool blocking_lock,
			NTSTATUS *perr,
			uint64_t *psmblctx,
			struct blocking_lock_record *blr);
NTSTATUS do_unlock(struct messaging_context *msg_ctx,
			files_struct *fsp,
			uint64_t smblctx,
			uint64_t count,
			uint64_t offset,
			enum brl_flavour lock_flav);
NTSTATUS do_lock_cancel(files_struct *fsp,
			uint64 smblctx,
			uint64_t count,
			uint64_t offset,
			enum brl_flavour lock_flav,
			struct blocking_lock_record *blr);
void locking_close_file(struct messaging_context *msg_ctx,
			files_struct *fsp,
			enum file_close_type close_type);
bool locking_init(void);
bool locking_init_readonly(void);
bool locking_end(void);
char *share_mode_str(TALLOC_CTX *ctx, int num, const struct share_mode_entry *e);
struct share_mode_lock *get_share_mode_lock(TALLOC_CTX *mem_ctx,
					    const struct file_id id,
					    const char *servicepath,
					    const struct smb_filename *smb_fname,
					    const struct timespec *old_write_time);
struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  const struct file_id id);
bool rename_share_filename(struct messaging_context *msg_ctx,
			struct share_mode_lock *lck,
			const char *servicepath,
			const struct smb_filename *smb_fname);
void get_file_infos(struct file_id id,
		    bool *delete_on_close,
		    struct timespec *write_time);
bool is_valid_share_mode_entry(const struct share_mode_entry *e);
bool is_deferred_open_entry(const struct share_mode_entry *e);
bool is_unused_share_mode_entry(const struct share_mode_entry *e);
void set_share_mode(struct share_mode_lock *lck, files_struct *fsp,
		    uid_t uid, uint64_t mid, uint16 op_type);
void add_deferred_open(struct share_mode_lock *lck, uint64_t mid,
		       struct timeval request_time,
		       struct server_id pid, struct file_id id);
bool del_share_mode(struct share_mode_lock *lck, files_struct *fsp);
void del_deferred_open_entry(struct share_mode_lock *lck, uint64_t mid,
			     struct server_id pid);
bool remove_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
bool downgrade_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
NTSTATUS can_set_delete_on_close(files_struct *fsp, uint32 dosmode);
void set_delete_on_close_token(struct share_mode_lock *lck, const UNIX_USER_TOKEN *tok);
void set_delete_on_close_lck(struct share_mode_lock *lck, bool delete_on_close, const UNIX_USER_TOKEN *tok);
bool set_delete_on_close(files_struct *fsp, bool delete_on_close, const UNIX_USER_TOKEN *tok);
bool set_sticky_write_time(struct file_id fileid, struct timespec write_time);
bool set_write_time(struct file_id fileid, struct timespec write_time);
int share_mode_forall(void (*fn)(const struct share_mode_entry *, const char *,
				 const char *, void *),
		      void *private_data);

/* The following definitions come from locking/posix.c  */

bool is_posix_locked(files_struct *fsp,
			uint64_t *pu_offset,
			uint64_t *pu_count,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
bool posix_locking_init(bool read_only);
bool posix_locking_end(void);
void reduce_windows_lock_ref_count(files_struct *fsp, unsigned int dcount);
int fd_close_posix(struct files_struct *fsp);
bool set_posix_lock_windows_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			const struct lock_struct *plocks,
			int num_locks,
			int *errno_ret);
bool release_posix_lock_windows_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				enum brl_type deleted_lock_type,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);
bool set_posix_lock_posix_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			int *errno_ret);
bool release_posix_lock_posix_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);

/* The following definitions come from modules/vfs_default.c  */

ssize_t vfswrap_llistxattr(struct vfs_handle_struct *handle, const char *path, char *list, size_t size);
ssize_t vfswrap_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size);
NTSTATUS vfs_default_init(void);

/* The following definitions come from nmbd/asyncdns.c  */

int asyncdns_fd(void);
void kill_async_dns_child(void);
void start_async_dns(void);
void run_dns_queue(void);
bool queue_dns_query(struct packet_struct *p,struct nmb_name *question);
bool queue_dns_query(struct packet_struct *p,struct nmb_name *question);
void kill_async_dns_child(void);

/* The following definitions come from nmbd/nmbd.c  */

struct event_context *nmbd_event_context(void);
struct messaging_context *nmbd_messaging_context(void);

/* The following definitions come from nmbd/nmbd_become_dmb.c  */

void add_domain_names(time_t t);

/* The following definitions come from nmbd/nmbd_become_lmb.c  */

void insert_permanent_name_into_unicast( struct subnet_record *subrec, 
                                                struct nmb_name *nmbname, uint16 nb_type );
void unbecome_local_master_browser(struct subnet_record *subrec, struct work_record *work,
                                   bool force_new_election);
void become_local_master_browser(struct subnet_record *subrec, struct work_record *work);
void set_workgroup_local_master_browser_name( struct work_record *work, const char *newname);

/* The following definitions come from nmbd/nmbd_browserdb.c  */

void update_browser_death_time( struct browse_cache_record *browc );
struct browse_cache_record *create_browser_in_lmb_cache( const char *work_name, 
                                                         const char *browser_name, 
                                                         struct in_addr ip );
struct browse_cache_record *find_browser_in_lmb_cache( const char *browser_name );
void expire_lmb_browsers( time_t t );

/* The following definitions come from nmbd/nmbd_browsesync.c  */

void dmb_expire_and_sync_browser_lists(time_t t);
void announce_and_sync_with_domain_master_browser( struct subnet_record *subrec,
                                                   struct work_record *work);
void collect_all_workgroup_names_from_wins_server(time_t t);
void sync_all_dmbs(time_t t);

/* The following definitions come from nmbd/nmbd_elections.c  */

void check_master_browser_exists(time_t t);
void run_elections(time_t t);
void process_election(struct subnet_record *subrec, struct packet_struct *p, char *buf);
bool check_elections(void);
void nmbd_message_election(struct messaging_context *msg,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data);

/* The following definitions come from nmbd/nmbd_incomingdgrams.c  */

void tell_become_backup(void);
void process_host_announce(struct subnet_record *subrec, struct packet_struct *p, char *buf);
void process_workgroup_announce(struct subnet_record *subrec, struct packet_struct *p, char *buf);
void process_local_master_announce(struct subnet_record *subrec, struct packet_struct *p, char *buf);
void process_master_browser_announce(struct subnet_record *subrec, 
                                     struct packet_struct *p,char *buf);
void process_lm_host_announce(struct subnet_record *subrec, struct packet_struct *p, char *buf, int len);
void process_get_backup_list_request(struct subnet_record *subrec,
                                     struct packet_struct *p,char *buf);
void process_reset_browser(struct subnet_record *subrec,
                                  struct packet_struct *p,char *buf);
void process_announce_request(struct subnet_record *subrec, struct packet_struct *p, char *buf);
void process_lm_announce_request(struct subnet_record *subrec, struct packet_struct *p, char *buf, int len);

/* The following definitions come from nmbd/nmbd_incomingrequests.c  */

void process_name_release_request(struct subnet_record *subrec, 
                                  struct packet_struct *p);
void process_name_refresh_request(struct subnet_record *subrec,
                                  struct packet_struct *p);
void process_name_registration_request(struct subnet_record *subrec, 
                                       struct packet_struct *p);
void process_node_status_request(struct subnet_record *subrec, struct packet_struct *p);
void process_name_query_request(struct subnet_record *subrec, struct packet_struct *p);

/* The following definitions come from nmbd/nmbd_lmhosts.c  */

void load_lmhosts_file(const char *fname);
bool find_name_in_lmhosts(struct nmb_name *nmbname, struct name_record **namerecp);

/* The following definitions come from nmbd/nmbd_logonnames.c  */

void add_logon_names(void);

/* The following definitions come from nmbd/nmbd_mynames.c  */

void register_my_workgroup_one_subnet(struct subnet_record *subrec);
bool register_my_workgroup_and_names(void);
void release_wins_names(void);
void refresh_my_names(time_t t);

/* The following definitions come from nmbd/nmbd_namelistdb.c  */

void set_samba_nb_type(void);
void remove_name_from_namelist(struct subnet_record *subrec, 
				struct name_record *namerec );
struct name_record *find_name_on_subnet(struct subnet_record *subrec,
				const struct nmb_name *nmbname,
				bool self_only);
struct name_record *find_name_for_remote_broadcast_subnet(struct nmb_name *nmbname,
						bool self_only);
void update_name_ttl( struct name_record *namerec, int ttl );
bool add_name_to_subnet( struct subnet_record *subrec,
			const char *name,
			int type,
			uint16 nb_flags,
			int ttl,
			enum name_source source,
			int num_ips,
			struct in_addr *iplist);
void standard_success_register(struct subnet_record *subrec, 
                             struct userdata_struct *userdata,
                             struct nmb_name *nmbname, uint16 nb_flags, int ttl,
                             struct in_addr registered_ip);
void standard_fail_register( struct subnet_record   *subrec,
                             struct nmb_name        *nmbname );
bool find_ip_in_name_record( struct name_record *namerec, struct in_addr ip );
void add_ip_to_name_record( struct name_record *namerec, struct in_addr new_ip );
void remove_ip_from_name_record( struct name_record *namerec,
                                 struct in_addr      remove_ip );
void standard_success_release( struct subnet_record   *subrec,
                               struct userdata_struct *userdata,
                               struct nmb_name        *nmbname,
                               struct in_addr          released_ip );
void expire_names(time_t t);
void add_samba_names_to_subnet( struct subnet_record *subrec );
void dump_name_record( struct name_record *namerec, XFILE *fp);
void dump_all_namelists(void);

/* The following definitions come from nmbd/nmbd_namequery.c  */

bool query_name(struct subnet_record *subrec, const char *name, int type,
                   query_name_success_function success_fn,
                   query_name_fail_function fail_fn, 
                   struct userdata_struct *userdata);
bool query_name_from_wins_server(struct in_addr ip_to, 
                   const char *name, int type,
                   query_name_success_function success_fn,
                   query_name_fail_function fail_fn, 
                   struct userdata_struct *userdata);

/* The following definitions come from nmbd/nmbd_nameregister.c  */

void register_name(struct subnet_record *subrec,
                   const char *name, int type, uint16 nb_flags,
                   register_name_success_function success_fn,
                   register_name_fail_function fail_fn,
                   struct userdata_struct *userdata);
void wins_refresh_name(struct name_record *namerec);

/* The following definitions come from nmbd/nmbd_namerelease.c  */

void release_name(struct subnet_record *subrec, struct name_record *namerec,
		  release_name_success_function success_fn,
		  release_name_fail_function fail_fn,
		  struct userdata_struct *userdata);

/* The following definitions come from nmbd/nmbd_nodestatus.c  */

bool node_status(struct subnet_record *subrec, struct nmb_name *nmbname,
                 struct in_addr send_ip, node_status_success_function success_fn, 
                 node_status_fail_function fail_fn, struct userdata_struct *userdata);

/* The following definitions come from nmbd/nmbd_packets.c  */

uint16 get_nb_flags(char *buf);
void set_nb_flags(char *buf, uint16 nb_flags);
struct response_record *queue_register_name( struct subnet_record *subrec,
                          response_function resp_fn,
                          timeout_response_function timeout_fn,
                          register_name_success_function success_fn,
                          register_name_fail_function fail_fn,
                          struct userdata_struct *userdata,
                          struct nmb_name *nmbname,
                          uint16 nb_flags);
void queue_wins_refresh(struct nmb_name *nmbname,
			response_function resp_fn,
			timeout_response_function timeout_fn,
			uint16 nb_flags,
			struct in_addr refresh_ip,
			const char *tag);
struct response_record *queue_register_multihomed_name( struct subnet_record *subrec,
							response_function resp_fn,
							timeout_response_function timeout_fn,
							register_name_success_function success_fn,
							register_name_fail_function fail_fn,
							struct userdata_struct *userdata,
							struct nmb_name *nmbname,
							uint16 nb_flags,
							struct in_addr register_ip,
							struct in_addr wins_ip);
struct response_record *queue_release_name( struct subnet_record *subrec,
					    response_function resp_fn,
					    timeout_response_function timeout_fn,
					    release_name_success_function success_fn,
					    release_name_fail_function fail_fn,
					    struct userdata_struct *userdata,
					    struct nmb_name *nmbname,
					    uint16 nb_flags,
					    struct in_addr release_ip,
					    struct in_addr dest_ip);
struct response_record *queue_query_name( struct subnet_record *subrec,
                          response_function resp_fn,
                          timeout_response_function timeout_fn,
                          query_name_success_function success_fn,
                          query_name_fail_function fail_fn,
                          struct userdata_struct *userdata,
                          struct nmb_name *nmbname);
struct response_record *queue_query_name_from_wins_server( struct in_addr to_ip,
                          response_function resp_fn,
                          timeout_response_function timeout_fn,
                          query_name_success_function success_fn,
                          query_name_fail_function fail_fn,
                          struct userdata_struct *userdata,
                          struct nmb_name *nmbname);
struct response_record *queue_node_status( struct subnet_record *subrec,
                          response_function resp_fn,
                          timeout_response_function timeout_fn,
                          node_status_success_function success_fn,
                          node_status_fail_function fail_fn,
                          struct userdata_struct *userdata,
                          struct nmb_name *nmbname,
                          struct in_addr send_ip);
void reply_netbios_packet(struct packet_struct *orig_packet,
                          int rcode, enum netbios_reply_type_code rcv_code, int opcode,
                          int ttl, char *data,int len);
void queue_packet(struct packet_struct *packet);
void run_packet_queue(void);
void retransmit_or_expire_response_records(time_t t);
bool listen_for_packets(bool run_election);
bool send_mailslot(bool unique, const char *mailslot,char *buf, size_t len,
                   const char *srcname, int src_type,
                   const char *dstname, int dest_type,
                   struct in_addr dest_ip,struct in_addr src_ip,
		   int dest_port);

/* The following definitions come from nmbd/nmbd_processlogon.c  */

bool initialize_nmbd_proxy_logon(void);

void process_logon_packet(struct packet_struct *p, char *buf,int len, 
                          const char *mailslot);

/* The following definitions come from nmbd/nmbd_responserecordsdb.c  */

void remove_response_record(struct subnet_record *subrec,
				struct response_record *rrec);
struct response_record *make_response_record( struct subnet_record *subrec,
					      struct packet_struct *p,
					      response_function resp_fn,
					      timeout_response_function timeout_fn,
					      success_function success_fn,
					      fail_function fail_fn,
					      struct userdata_struct *userdata);
struct response_record *find_response_record(struct subnet_record **ppsubrec,
				uint16 id);
bool is_refresh_already_queued(struct subnet_record *subrec, struct name_record *namerec);

/* The following definitions come from nmbd/nmbd_sendannounce.c  */

void send_browser_reset(int reset_type, const char *to_name, int to_type, struct in_addr to_ip);
void broadcast_announce_request(struct subnet_record *subrec, struct work_record *work);
void announce_my_server_names(time_t t);
void announce_my_lm_server_names(time_t t);
void reset_announce_timer(void);
void announce_myself_to_domain_master_browser(time_t t);
void announce_my_servers_removed(void);
void announce_remote(time_t t);
void browse_sync_remote(time_t t);

/* The following definitions come from nmbd/nmbd_serverlistdb.c  */

void remove_all_servers(struct work_record *work);
struct server_record *find_server_in_workgroup(struct work_record *work, const char *name);
void remove_server_from_workgroup(struct work_record *work, struct server_record *servrec);
struct server_record *create_server_on_workgroup(struct work_record *work,
                                                 const char *name,int servertype, 
                                                 int ttl, const char *comment);
void update_server_ttl(struct server_record *servrec, int ttl);
void expire_servers(struct work_record *work, time_t t);
void write_browse_list_entry(XFILE *fp, const char *name, uint32 rec_type,
		const char *local_master_browser_name, const char *description);
void write_browse_list(time_t t, bool force_write);

/* The following definitions come from nmbd/nmbd_subnetdb.c  */

void close_subnet(struct subnet_record *subrec);
struct subnet_record *make_normal_subnet(const struct interface *iface);
bool create_subnets(void);
bool we_are_a_wins_client(void);
struct subnet_record *get_next_subnet_maybe_unicast(struct subnet_record *subrec);
struct subnet_record *get_next_subnet_maybe_unicast_or_wins_server(struct subnet_record *subrec);

/* The following definitions come from nmbd/nmbd_synclists.c  */

void sync_browse_lists(struct work_record *work,
		       char *name, int nm_type, 
		       struct in_addr ip, bool local, bool servers);
void sync_check_completion(void);

/* The following definitions come from nmbd/nmbd_winsproxy.c  */

void make_wins_proxy_name_query_request( struct subnet_record *subrec, 
                                         struct packet_struct *incoming_packet,
                                         struct nmb_name *question_name);

/* The following definitions come from nmbd/nmbd_winsserver.c  */

struct name_record *find_name_on_wins_subnet(const struct nmb_name *nmbname, bool self_only);
bool wins_store_changed_namerec(const struct name_record *namerec);
bool add_name_to_wins_subnet(const struct name_record *namerec);
bool remove_name_from_wins_namelist(struct name_record *namerec);
void dump_wins_subnet_namelist(XFILE *fp);
bool packet_is_for_wins_server(struct packet_struct *packet);
bool initialise_wins(void);
void wins_process_name_refresh_request( struct subnet_record *subrec,
                                        struct packet_struct *p );
void wins_process_name_registration_request(struct subnet_record *subrec,
                                            struct packet_struct *p);
void wins_process_multihomed_name_registration_request( struct subnet_record *subrec,
                                                        struct packet_struct *p);
void fetch_all_active_wins_1b_names(void);
void send_wins_name_query_response(int rcode, struct packet_struct *p, 
                                          struct name_record *namerec);
void wins_process_name_query_request(struct subnet_record *subrec, 
                                     struct packet_struct *p);
void wins_process_name_release_request(struct subnet_record *subrec,
                                       struct packet_struct *p);
void initiate_wins_processing(time_t t);
void wins_write_name_record(struct name_record *namerec, XFILE *fp);
void wins_write_database(time_t t, bool background);
void nmbd_wins_new_entry(struct messaging_context *msg,
                                       void *private_data,
                                       uint32_t msg_type,
                                       struct server_id server_id,
                                       DATA_BLOB *data);

/* The following definitions come from nmbd/nmbd_workgroupdb.c  */

struct work_record *find_workgroup_on_subnet(struct subnet_record *subrec, 
                                             const char *name);
struct work_record *create_workgroup_on_subnet(struct subnet_record *subrec,
                                               const char *name, int ttl);
void update_workgroup_ttl(struct work_record *work, int ttl);
void initiate_myworkgroup_startup(struct subnet_record *subrec, struct work_record *work);
void dump_workgroups(bool force_write);
void expire_workgroups_and_servers(time_t t);

/* The following definitions come from param/loadparm.c  */

char *lp_smb_ports(void);
char *lp_dos_charset(void);
char *lp_unix_charset(void);
char *lp_display_charset(void);
char *lp_logfile(void);
char *lp_configfile(void);
char *lp_smb_passwd_file(void);
char *lp_private_dir(void);
char *lp_serverstring(void);
int lp_printcap_cache_time(void);
char *lp_addport_cmd(void);
char *lp_enumports_cmd(void);
char *lp_addprinter_cmd(void);
char *lp_deleteprinter_cmd(void);
char *lp_os2_driver_map(void);
char *lp_lockdir(void);
char *lp_statedir(void);
char *lp_cachedir(void);
char *lp_piddir(void);
char *lp_mangling_method(void);
int lp_mangle_prefix(void);
char *lp_utmpdir(void);
char *lp_wtmpdir(void);
bool lp_utmp(void);
char *lp_rootdir(void);
char *lp_defaultservice(void);
char *lp_msg_command(void);
char *lp_get_quota_command(void);
char *lp_set_quota_command(void);
char *lp_auto_services(void);
char *lp_passwd_program(void);
char *lp_passwd_chat(void);
char *lp_passwordserver(void);
char *lp_name_resolve_order(void);
char *lp_realm(void);
const char *lp_afs_username_map(void);
int lp_afs_token_lifetime(void);
char *lp_log_nt_token_command(void);
char *lp_username_map(void);
const char *lp_logon_script(void);
const char *lp_logon_path(void);
const char *lp_logon_drive(void);
const char *lp_logon_home(void);
char *lp_remote_announce(void);
char *lp_remote_browse_sync(void);
bool lp_nmbd_bind_explicit_broadcast(void);
const char **lp_wins_server_list(void);
const char **lp_interfaces(void);
const char *lp_socket_address(void);
char *lp_nis_home_map_name(void);
const char **lp_netbios_aliases(void);
const char *lp_passdb_backend(void);
const char **lp_preload_modules(void);
char *lp_panic_action(void);
char *lp_adduser_script(void);
char *lp_renameuser_script(void);
char *lp_deluser_script(void);
const char *lp_guestaccount(void);
char *lp_addgroup_script(void);
char *lp_delgroup_script(void);
char *lp_addusertogroup_script(void);
char *lp_deluserfromgroup_script(void);
char *lp_setprimarygroup_script(void);
char *lp_addmachine_script(void);
char *lp_shutdown_script(void);
char *lp_abort_shutdown_script(void);
char *lp_username_map_script(void);
int lp_username_map_cache_time(void);
char *lp_check_password_script(void);
char *lp_wins_hook(void);
const char *lp_template_homedir(void);
const char *lp_template_shell(void);
const char *lp_winbind_separator(void);
int lp_acl_compatibility(void);
bool lp_winbind_enum_users(void);
bool lp_winbind_enum_groups(void);
bool lp_winbind_use_default_domain(void);
bool lp_winbind_trusted_domains_only(void);
bool lp_winbind_nested_groups(void);
int lp_winbind_expand_groups(void);
bool lp_winbind_refresh_tickets(void);
bool lp_winbind_offline_logon(void);
bool lp_winbind_normalize_names(void);
bool lp_winbind_rpc_only(void);
bool lp_create_krb5_conf(void);
const char *lp_idmap_backend(void);
char *lp_idmap_alloc_backend(void);
int lp_idmap_cache_time(void);
int lp_idmap_negative_cache_time(void);
int lp_keepalive(void);
bool lp_passdb_expand_explicit(void);
char *lp_ldap_suffix(void);
char *lp_ldap_admin_dn(void);
int lp_ldap_ssl(void);
bool lp_ldap_ssl_ads(void);
int lp_ldap_deref(void);
int lp_ldap_follow_referral(void);
int lp_ldap_passwd_sync(void);
bool lp_ldap_delete_dn(void);
int lp_ldap_replication_sleep(void);
int lp_ldap_timeout(void);
int lp_ldap_connection_timeout(void);
int lp_ldap_page_size(void);
int lp_ldap_debug_level(void);
int lp_ldap_debug_threshold(void);
char *lp_add_share_cmd(void);
char *lp_change_share_cmd(void);
char *lp_delete_share_cmd(void);
char *lp_usershare_path(void);
const char **lp_usershare_prefix_allow_list(void);
const char **lp_usershare_prefix_deny_list(void);
const char **lp_eventlog_list(void);
bool lp_registry_shares(void);
bool lp_usershare_allow_guests(void);
bool lp_usershare_owner_only(void);
bool lp_disable_netbios(void);
bool lp_reset_on_zero_vc(void);
bool lp_log_writeable_files_on_exit(void);
bool lp_ms_add_printer_wizard(void);
bool lp_dns_proxy(void);
bool lp_wins_support(void);
bool lp_we_are_a_wins_server(void);
bool lp_wins_proxy(void);
bool lp_local_master(void);
bool lp_domain_logons(void);
const char **lp_init_logon_delayed_hosts(void);
int lp_init_logon_delay(void);
bool lp_load_printers(void);
bool lp_readraw(void);
bool _lp_readraw(void);
bool lp_large_readwrite(void);
bool lp_writeraw(void);
bool _lp_writeraw(void);
bool lp_null_passwords(void);
bool lp_obey_pam_restrictions(void);
bool lp_encrypted_passwords(void);
bool lp_update_encrypted(void);
int lp_client_schannel(void);
int lp_server_schannel(void);
bool lp_syslog_only(void);
bool lp_timestamp_logs(void);
bool lp_debug_prefix_timestamp(void);
bool lp_debug_hires_timestamp(void);
bool lp_debug_pid(void);
bool lp_debug_uid(void);
bool lp_debug_class(void);
bool lp_enable_core_files(void);
bool lp_browse_list(void);
bool lp_nis_home_map(void);
bool lp_bind_interfaces_only(void);
bool lp_pam_password_change(void);
bool lp_unix_password_sync(void);
bool lp_passwd_chat_debug(void);
int lp_passwd_chat_timeout(void);
bool lp_nt_pipe_support(void);
bool lp_nt_status_support(void);
bool lp_stat_cache(void);
int lp_max_stat_cache_size(void);
bool lp_allow_trusted_domains(void);
bool lp_map_untrusted_to_domain(void);
int lp_restrict_anonymous(void);
bool lp_lanman_auth(void);
bool lp_ntlm_auth(void);
bool lp_client_plaintext_auth(void);
bool lp_client_lanman_auth(void);
bool lp_client_ntlmv2_auth(void);
bool lp_host_msdfs(void);
bool lp_kernel_oplocks(void);
bool lp_enhanced_browsing(void);
bool lp_use_mmap(void);
bool lp_unix_extensions(void);
bool lp_use_spnego(void);
bool lp_client_use_spnego(void);
bool lp_hostname_lookups(void);
bool lp_change_notify(const struct share_params *p );
bool lp_kernel_change_notify(const struct share_params *p );
char * lp_dedicated_keytab_file(void);
int lp_kerberos_method(void);
bool lp_defer_sharing_violations(void);
bool lp_enable_privileges(void);
bool lp_enable_asu_support(void);
int lp_os_level(void);
int lp_max_ttl(void);
int lp_max_wins_ttl(void);
int lp_min_wins_ttl(void);
int lp_max_log_size(void);
int lp_max_open_files(void);
int lp_open_files_db_hash_size(void);
int lp_maxxmit(void);
int lp_maxmux(void);
int lp_passwordlevel(void);
int lp_usernamelevel(void);
int lp_deadtime(void);
bool lp_getwd_cache(void);
int lp_maxprotocol(void);
int lp_minprotocol(void);
int lp_security(void);
const char **lp_auth_methods(void);
bool lp_paranoid_server_security(void);
int lp_maxdisksize(void);
int lp_lpqcachetime(void);
int lp_max_smbd_processes(void);
bool _lp_disable_spoolss(void);
int lp_syslog(void);
int lp_lm_announce(void);
int lp_lm_interval(void);
int lp_machine_password_timeout(void);
int lp_map_to_guest(void);
int lp_oplock_break_wait_time(void);
int lp_lock_spin_time(void);
int lp_usershare_max_shares(void);
const char *lp_socket_options(void);
int lp_config_backend(void);
int lp_smb2_max_read(void);
int lp_smb2_max_write(void);
int lp_smb2_max_trans(void);
char *lp_preexec(int );
char *lp_postexec(int );
char *lp_rootpreexec(int );
char *lp_rootpostexec(int );
char *lp_servicename(int );
const char *lp_const_servicename(int );
char *lp_pathname(int );
char *lp_dontdescend(int );
char *lp_username(int );
const char **lp_invalid_users(int );
const char **lp_valid_users(int );
const char **lp_admin_users(int );
const char **lp_svcctl_list(void);
char *lp_cups_options(int );
char *lp_cups_server(void);
int lp_cups_encrypt(void);
char *lp_iprint_server(void);
int lp_cups_connection_timeout(void);
const char *lp_ctdbd_socket(void);
const char **lp_cluster_addresses(void);
bool lp_clustering(void);
int lp_ctdb_timeout(void);
int lp_ctdb_locktime_warn_threshold(void);
char *lp_printcommand(int );
char *lp_lpqcommand(int );
char *lp_lprmcommand(int );
char *lp_lppausecommand(int );
char *lp_lpresumecommand(int );
char *lp_queuepausecommand(int );
char *lp_queueresumecommand(int );
const char *lp_printjob_username(int );
const char **lp_hostsallow(int );
const char **lp_hostsdeny(int );
char *lp_magicscript(int );
char *lp_magicoutput(int );
char *lp_comment(int );
char *lp_force_user(int );
char *lp_force_group(int );
const char **lp_readlist(int );
const char **lp_writelist(int );
const char **lp_printer_admin(int );
char *lp_fstype(int );
const char **lp_vfs_objects(int );
char *lp_msdfs_proxy(int );
char *lp_veto_files(int );
char *lp_hide_files(int );
char *lp_veto_oplocks(int );
bool lp_msdfs_root(int );
char *lp_aio_write_behind(int );
char *lp_dfree_command(int );
bool lp_autoloaded(int );
bool lp_preexec_close(int );
bool lp_rootpreexec_close(int );
int lp_casesensitive(int );
bool lp_preservecase(int );
bool lp_shortpreservecase(int );
bool lp_hide_dot_files(int );
bool lp_hide_special_files(int );
bool lp_hideunreadable(int );
bool lp_hideunwriteable_files(int );
bool lp_browseable(int );
bool lp_access_based_share_enum(int );
bool lp_readonly(int );
bool lp_no_set_dir(int );
bool lp_guest_ok(int );
bool lp_guest_only(int );
bool lp_administrative_share(int );
bool lp_print_ok(int );
bool lp_map_hidden(int );
bool lp_map_archive(int );
bool lp_store_dos_attributes(int );
bool lp_dmapi_support(int );
bool lp_locking(const struct share_params *p );
int lp_strict_locking(const struct share_params *p );
bool lp_posix_locking(const struct share_params *p );
bool lp_share_modes(int );
bool lp_oplocks(int );
bool lp_level2_oplocks(int );
bool lp_onlyuser(int );
bool lp_manglednames(const struct share_params *p );
bool lp_widelinks(int );
bool lp_symlinks(int );
bool lp_syncalways(int );
bool lp_strict_allocate(int );
bool lp_strict_sync(int );
bool lp_map_system(int );
bool lp_delete_readonly(int );
bool lp_fake_oplocks(int );
bool lp_recursive_veto_delete(int );
bool lp_dos_filemode(int );
bool lp_dos_filetimes(int );
bool lp_dos_filetime_resolution(int );
bool lp_fake_dir_create_times(int);
bool lp_async_smb_echo_handler(void);
bool lp_blocking_locks(int );
bool lp_inherit_perms(int );
bool lp_inherit_acls(int );
bool lp_inherit_owner(int );
bool lp_use_client_driver(int );
bool lp_default_devmode(int );
bool lp_force_printername(int );
bool lp_nt_acl_support(int );
bool lp_force_unknown_acl_user(int );
bool lp_ea_support(int );
bool _lp_use_sendfile(int );
bool lp_profile_acls(int );
bool lp_map_acl_inherit(int );
bool lp_afs_share(int );
bool lp_acl_check_permissions(int );
bool lp_acl_group_control(int );
bool lp_acl_map_full_control(int );
int lp_create_mask(int );
int lp_force_create_mode(int );
int lp_security_mask(int );
int lp_force_security_mode(int );
int lp_dir_mask(int );
int lp_force_dir_mode(int );
int lp_dir_security_mask(int );
int lp_force_dir_security_mode(int );
int lp_max_connections(int );
int lp_defaultcase(int );
int lp_minprintspace(int );
int lp_printing(int );
int lp_max_reported_jobs(int );
int lp_oplock_contention_limit(int );
int lp_csc_policy(int );
int lp_write_cache_size(int );
int lp_block_size(int );
int lp_dfree_cache_time(int );
int lp_allocation_roundup_size(int );
int lp_aio_read_size(int );
int lp_aio_write_size(int );
int lp_map_readonly(int );
int lp_directory_name_cache_size(int );
int lp_smb_encrypt(int );
char lp_magicchar(const struct share_params *p );
int lp_winbind_cache_time(void);
int lp_winbind_reconnect_delay(void);
const char **lp_winbind_nss_info(void);
int lp_algorithmic_rid_base(void);
int lp_name_cache_timeout(void);
int lp_client_signing(void);
int lp_server_signing(void);
int lp_client_ldap_sasl_wrapping(void);
char *lp_parm_talloc_string(int snum, const char *type, const char *option, const char *def);
const char *lp_parm_const_string(int snum, const char *type, const char *option, const char *def);
const char **lp_parm_string_list(int snum, const char *type, const char *option, const char **def);
int lp_parm_int(int snum, const char *type, const char *option, int def);
unsigned long lp_parm_ulong(int snum, const char *type, const char *option, unsigned long def);
bool lp_parm_bool(int snum, const char *type, const char *option, bool def);
int lp_parm_enum(int snum, const char *type, const char *option,
		 const struct enum_list *_enum, int def);
char *canonicalize_servicename(TALLOC_CTX *ctx, const char *src);
bool lp_add_home(const char *pszHomename, int iDefaultService,
		 const char *user, const char *pszHomedir);
int lp_add_service(const char *pszService, int iDefaultService);
bool lp_add_printer(const char *pszPrintername, int iDefaultService);
bool lp_parameter_is_valid(const char *pszParmName);
bool lp_parameter_is_global(const char *pszParmName);
bool lp_parameter_is_canonical(const char *parm_name);
bool lp_canonicalize_parameter(const char *parm_name, const char **canon_parm,
			       bool *inverse);
bool lp_canonicalize_parameter_with_value(const char *parm_name,
					  const char *val,
					  const char **canon_parm,
					  const char **canon_val);
void show_parameter_list(void);
bool lp_string_is_valid_boolean(const char *parm_value);
bool lp_invert_boolean(const char *str, const char **inverse_str);
bool lp_canonicalize_boolean(const char *str, const char**canon_str);
bool service_ok(int iService);
bool process_registry_service(const char *service_name);
bool process_registry_shares(void);
bool lp_config_backend_is_registry(void);
bool lp_config_backend_is_file(void);
bool lp_file_list_changed(void);
bool lp_idmap_uid(uid_t *low, uid_t *high);
bool lp_idmap_gid(gid_t *low, gid_t *high);
const char *lp_ldap_machine_suffix(void);
const char *lp_ldap_user_suffix(void);
const char *lp_ldap_group_suffix(void);
const char *lp_ldap_idmap_suffix(void);
void *lp_local_ptr_by_snum(int snum, void *ptr);
bool lp_do_parameter(int snum, const char *pszParmName, const char *pszParmValue);
void init_locals(void);
bool lp_is_default(int snum, struct parm_struct *parm);
bool dump_a_parameter(int snum, char *parm_name, FILE * f, bool isGlobal);
struct parm_struct *lp_get_parameter(const char *param_name);
struct parm_struct *lp_next_parameter(int snum, int *i, int allparameters);
bool lp_snum_ok(int iService);
void lp_add_one_printer(const char *name, const char *comment, void *pdata);
bool lp_loaded(void);
void lp_killunused(bool (*snumused) (int));
void lp_kill_all_services(void);
void lp_killservice(int iServiceIn);
const char* server_role_str(uint32 role);
enum usershare_err parse_usershare_file(TALLOC_CTX *ctx,
			SMB_STRUCT_STAT *psbuf,
			const char *servicename,
			int snum,
			char **lines,
			int numlines,
			char **pp_sharepath,
			char **pp_comment,
			char **pp_cp_share_name,
			struct security_descriptor **ppsd,
			bool *pallow_guest);
int load_usershare_service(const char *servicename);
int load_usershare_shares(void);
void gfree_loadparm(void);
void lp_set_in_client(bool b);
bool lp_is_in_client(void);
bool lp_load_ex(const char *pszFname,
		bool global_only,
		bool save_defaults,
		bool add_ipc,
		bool initialize_globals,
		bool allow_include_registry,
		bool allow_registry_shares);
bool lp_load(const char *pszFname,
	     bool global_only,
	     bool save_defaults,
	     bool add_ipc,
	     bool initialize_globals);
bool lp_load_initial_only(const char *pszFname);
bool lp_load_with_registry_shares(const char *pszFname,
				  bool global_only,
				  bool save_defaults,
				  bool add_ipc,
				  bool initialize_globals);
int lp_numservices(void);
void lp_dump(FILE *f, bool show_defaults, int maxtoprint);
void lp_dump_one(FILE * f, bool show_defaults, int snum);
int lp_servicenumber(const char *pszServiceName);
bool share_defined(const char *service_name);
struct share_params *get_share_params(TALLOC_CTX *mem_ctx,
				      const char *sharename);
struct share_iterator *share_list_all(TALLOC_CTX *mem_ctx);
struct share_params *next_share(struct share_iterator *list);
struct share_params *next_printer(struct share_iterator *list);
struct share_params *snum2params_static(int snum);
const char *volume_label(int snum);
bool lp_domain_master(void);
bool lp_domain_master_true_or_auto(void);
bool lp_preferred_master(void);
void lp_remove_service(int snum);
void lp_copy_service(int snum, const char *new_name);
int lp_default_server_announce(void);
int lp_major_announce_version(void);
int lp_minor_announce_version(void);
void lp_set_name_resolve_order(const char *new_order);
const char *lp_printername(int snum);
void lp_set_logfile(const char *name);
int lp_maxprintjobs(int snum);
const char *lp_printcapname(void);
bool lp_disable_spoolss( void );
void lp_set_spoolss_state( uint32 state );
uint32 lp_get_spoolss_state( void );
bool lp_use_sendfile(int snum, struct smb_signing_state *signing_state);
void set_use_sendfile(int snum, bool val);
void set_store_dos_attributes(int snum, bool val);
void lp_set_mangling_method(const char *new_method);
bool lp_posix_pathnames(void);
void lp_set_posix_pathnames(void);
enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp);
void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val);
int lp_min_receive_file_size(void);
char* lp_perfcount_module(void);
void lp_set_passdb_backend(const char *backend);
void widelinks_warning(int snum);

/* The following definitions come from param/loadparm_server_role.c  */

int lp_server_role(void);
void set_server_role(void);

/* The following definitions come from param/util.c  */

uint32 get_int_param( const char* param );
char* get_string_param( const char* param );

/* The following definitions come from passdb/login_cache.c  */

bool login_cache_init(void);
bool login_cache_shutdown(void);
bool login_cache_read(struct samu *sampass, struct login_cache *entry);
bool login_cache_write(const struct samu *sampass,
		       const struct login_cache *entry);
bool login_cache_delentry(const struct samu *sampass);

/* The following definitions come from passdb/lookup_sid.c  */

bool lookup_name(TALLOC_CTX *mem_ctx,
		 const char *full_name, int flags,
		 const char **ret_domain, const char **ret_name,
		 struct dom_sid *ret_sid, enum lsa_SidType *ret_type);
bool lookup_name_smbconf(TALLOC_CTX *mem_ctx,
		 const char *full_name, int flags,
		 const char **ret_domain, const char **ret_name,
		 struct dom_sid *ret_sid, enum lsa_SidType *ret_type);
NTSTATUS lookup_sids(TALLOC_CTX *mem_ctx, int num_sids,
		     const struct dom_sid **sids, int level,
		     struct lsa_dom_info **ret_domains,
		     struct lsa_name_info **ret_names);
bool lookup_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
		const char **ret_domain, const char **ret_name,
		enum lsa_SidType *ret_type);
void store_uid_sid_cache(const struct dom_sid *psid, uid_t uid);
void store_gid_sid_cache(const struct dom_sid *psid, gid_t gid);
void uid_to_sid(struct dom_sid *psid, uid_t uid);
void gid_to_sid(struct dom_sid *psid, gid_t gid);
bool sid_to_uid(const struct dom_sid *psid, uid_t *puid);
bool sid_to_gid(const struct dom_sid *psid, gid_t *pgid);
NTSTATUS get_primary_group_sid(TALLOC_CTX *mem_ctx,
				const char *username,
				struct passwd **_pwd,
				struct dom_sid **_group_sid);

/* The following definitions come from passdb/machine_sid.c  */

struct dom_sid  *get_global_sam_sid(void);
void reset_global_sam_sid(void) ;
bool sid_check_is_domain(const struct dom_sid  *sid);
bool sid_check_is_in_our_domain(const struct dom_sid  *sid);

/* The following definitions come from passdb/passdb.c  */

const char *my_sam_name(void);
struct samu *samu_new( TALLOC_CTX *ctx );
NTSTATUS samu_set_unix(struct samu *user, const struct passwd *pwd);
NTSTATUS samu_alloc_rid_unix(struct samu *user, const struct passwd *pwd);
char *pdb_encode_acct_ctrl(uint32_t acct_ctrl, size_t length);
uint32_t pdb_decode_acct_ctrl(const char *p);
void pdb_sethexpwd(char p[33], const unsigned char *pwd, uint32_t acct_ctrl);
bool pdb_gethexpwd(const char *p, unsigned char *pwd);
void pdb_sethexhours(char *p, const unsigned char *hours);
bool pdb_gethexhours(const char *p, unsigned char *hours);
int algorithmic_rid_base(void);
uid_t algorithmic_pdb_user_rid_to_uid(uint32_t user_rid);
uid_t max_algorithmic_uid(void);
uint32_t algorithmic_pdb_uid_to_user_rid(uid_t uid);
gid_t pdb_group_rid_to_gid(uint32_t group_rid);
gid_t max_algorithmic_gid(void);
uint32_t algorithmic_pdb_gid_to_group_rid(gid_t gid);
bool algorithmic_pdb_rid_is_user(uint32_t rid);
bool lookup_global_sam_name(const char *name, int flags, uint32_t *rid,
			    enum lsa_SidType *type);
NTSTATUS local_password_change(const char *user_name,
				int local_flags,
				const char *new_passwd, 
				char **pp_err_str,
				char **pp_msg_str);
bool init_samu_from_buffer(struct samu *sampass, uint32_t level,
			   uint8_t *buf, uint32_t buflen);
uint32_t init_buffer_from_samu (uint8_t **buf, struct samu *sampass, bool size_only);
bool pdb_copy_sam_account(struct samu *dst, struct samu *src );
bool pdb_update_bad_password_count(struct samu *sampass, bool *updated);
bool pdb_update_autolock_flag(struct samu *sampass, bool *updated);
bool pdb_increment_bad_password_count(struct samu *sampass);
bool is_dc_trusted_domain_situation(const char *domain_name);
bool get_trust_pw_clear(const char *domain, char **ret_pwd,
			const char **account_name,
			enum netr_SchannelType *channel);
bool get_trust_pw_hash(const char *domain, uint8_t ret_pwd[16],
		       const char **account_name,
		       enum netr_SchannelType *channel);

/* The following definitions come from passdb/pdb_compat.c  */

uint32_t pdb_get_user_rid (const struct samu *sampass);
uint32_t pdb_get_group_rid (struct samu *sampass);
bool pdb_set_user_sid_from_rid (struct samu *sampass, uint32_t rid, enum pdb_value_state flag);
bool pdb_set_group_sid_from_rid (struct samu *sampass, uint32_t grid, enum pdb_value_state flag);

/* The following definitions come from passdb/pdb_get_set.c  */

uint32_t pdb_get_acct_ctrl(const struct samu *sampass);
time_t pdb_get_logon_time(const struct samu *sampass);
time_t pdb_get_logoff_time(const struct samu *sampass);
time_t pdb_get_kickoff_time(const struct samu *sampass);
time_t pdb_get_bad_password_time(const struct samu *sampass);
time_t pdb_get_pass_last_set_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time_noncalc(const struct samu *sampass);
time_t pdb_get_pass_must_change_time(const struct samu *sampass);
bool pdb_get_pass_can_change(const struct samu *sampass);
uint16_t pdb_get_logon_divs(const struct samu *sampass);
uint32_t pdb_get_hours_len(const struct samu *sampass);
const uint8_t *pdb_get_hours(const struct samu *sampass);
const uint8_t *pdb_get_nt_passwd(const struct samu *sampass);
const uint8_t *pdb_get_lanman_passwd(const struct samu *sampass);
const uint8_t *pdb_get_pw_history(const struct samu *sampass, uint32_t *current_hist_len);
const char *pdb_get_plaintext_passwd(const struct samu *sampass);
const struct dom_sid *pdb_get_user_sid(const struct samu *sampass);
const struct dom_sid *pdb_get_group_sid(struct samu *sampass);
enum pdb_value_state pdb_get_init_flags(const struct samu *sampass, enum pdb_elements element);
const char *pdb_get_username(const struct samu *sampass);
const char *pdb_get_domain(const struct samu *sampass);
const char *pdb_get_nt_username(const struct samu *sampass);
const char *pdb_get_fullname(const struct samu *sampass);
const char *pdb_get_homedir(const struct samu *sampass);
const char *pdb_get_dir_drive(const struct samu *sampass);
const char *pdb_get_logon_script(const struct samu *sampass);
const char *pdb_get_profile_path(const struct samu *sampass);
const char *pdb_get_acct_desc(const struct samu *sampass);
const char *pdb_get_workstations(const struct samu *sampass);
const char *pdb_get_comment(const struct samu *sampass);
const char *pdb_get_munged_dial(const struct samu *sampass);
uint16_t pdb_get_bad_password_count(const struct samu *sampass);
uint16_t pdb_get_logon_count(const struct samu *sampass);
uint32_t pdb_get_unknown_6(const struct samu *sampass);
void *pdb_get_backend_private_data(const struct samu *sampass, const struct pdb_methods *my_methods);
bool pdb_set_acct_ctrl(struct samu *sampass, uint32_t acct_ctrl, enum pdb_value_state flag);
bool pdb_set_logon_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_logoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_kickoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_bad_password_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_can_change_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_must_change_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_last_set_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_hours_len(struct samu *sampass, uint32_t len, enum pdb_value_state flag);
bool pdb_set_logon_divs(struct samu *sampass, uint16_t hours, enum pdb_value_state flag);
bool pdb_set_init_flags(struct samu *sampass, enum pdb_elements element, enum pdb_value_state value_flag);
bool pdb_set_user_sid(struct samu *sampass, const struct dom_sid *u_sid, enum pdb_value_state flag);
bool pdb_set_user_sid_from_string(struct samu *sampass, fstring u_sid, enum pdb_value_state flag);
bool pdb_set_group_sid(struct samu *sampass, const struct dom_sid *g_sid, enum pdb_value_state flag);
bool pdb_set_username(struct samu *sampass, const char *username, enum pdb_value_state flag);
bool pdb_set_domain(struct samu *sampass, const char *domain, enum pdb_value_state flag);
bool pdb_set_nt_username(struct samu *sampass, const char *nt_username, enum pdb_value_state flag);
bool pdb_set_fullname(struct samu *sampass, const char *full_name, enum pdb_value_state flag);
bool pdb_set_logon_script(struct samu *sampass, const char *logon_script, enum pdb_value_state flag);
bool pdb_set_profile_path(struct samu *sampass, const char *profile_path, enum pdb_value_state flag);
bool pdb_set_dir_drive(struct samu *sampass, const char *dir_drive, enum pdb_value_state flag);
bool pdb_set_homedir(struct samu *sampass, const char *home_dir, enum pdb_value_state flag);
bool pdb_set_acct_desc(struct samu *sampass, const char *acct_desc, enum pdb_value_state flag);
bool pdb_set_workstations(struct samu *sampass, const char *workstations, enum pdb_value_state flag);
bool pdb_set_comment(struct samu *sampass, const char *comment, enum pdb_value_state flag);
bool pdb_set_munged_dial(struct samu *sampass, const char *munged_dial, enum pdb_value_state flag);
bool pdb_set_nt_passwd(struct samu *sampass, const uint8_t pwd[NT_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_lanman_passwd(struct samu *sampass, const uint8_t pwd[LM_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_pw_history(struct samu *sampass, const uint8_t *pwd, uint32_t historyLen, enum pdb_value_state flag);
bool pdb_set_plaintext_pw_only(struct samu *sampass, const char *password, enum pdb_value_state flag);
bool pdb_set_bad_password_count(struct samu *sampass, uint16_t bad_password_count, enum pdb_value_state flag);
bool pdb_set_logon_count(struct samu *sampass, uint16_t logon_count, enum pdb_value_state flag);
bool pdb_set_unknown_6(struct samu *sampass, uint32_t unkn, enum pdb_value_state flag);
bool pdb_set_hours(struct samu *sampass, const uint8_t *hours, enum pdb_value_state flag);
bool pdb_set_backend_private_data(struct samu *sampass, void *private_data, 
				   void (*free_fn)(void **), 
				   const struct pdb_methods *my_methods, 
				   enum pdb_value_state flag);
bool pdb_set_pass_can_change(struct samu *sampass, bool canchange);
bool pdb_set_plaintext_passwd(struct samu *sampass, const char *plaintext);
uint32_t pdb_build_fields_present(struct samu *sampass);

/* The following definitions come from passdb/pdb_interface.c  */

NTSTATUS smb_register_passdb(int version, const char *name, pdb_init_function init) ;
struct pdb_init_function_entry *pdb_find_backend_entry(const char *name);
struct event_context *pdb_get_event_context(void);
NTSTATUS make_pdb_method_name(struct pdb_methods **methods, const char *selected);
struct pdb_domain_info *pdb_get_domain_info(TALLOC_CTX *mem_ctx);
bool pdb_getsampwnam(struct samu *sam_acct, const char *username) ;
bool pdb_getsampwsid(struct samu *sam_acct, const struct dom_sid *sid) ;
NTSTATUS pdb_create_user(TALLOC_CTX *mem_ctx, const char *name, uint32_t flags,
			 uint32_t *rid);
NTSTATUS pdb_delete_user(TALLOC_CTX *mem_ctx, struct samu *sam_acct);
NTSTATUS pdb_add_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_update_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_delete_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_rename_sam_account(struct samu *oldname, const char *newname);
NTSTATUS pdb_update_login_attempts(struct samu *sam_acct, bool success);
bool pdb_getgrsid(GROUP_MAP *map, struct dom_sid sid);
bool pdb_getgrgid(GROUP_MAP *map, gid_t gid);
bool pdb_getgrnam(GROUP_MAP *map, const char *name);
NTSTATUS pdb_create_dom_group(TALLOC_CTX *mem_ctx, const char *name,
			      uint32_t *rid);
NTSTATUS pdb_delete_dom_group(TALLOC_CTX *mem_ctx, uint32_t rid);
NTSTATUS pdb_add_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_update_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_delete_group_mapping_entry(struct dom_sid sid);
bool pdb_enum_group_mapping(const struct dom_sid *sid, enum lsa_SidType sid_name_use, GROUP_MAP **pp_rmap,
			    size_t *p_num_entries, bool unix_only);
NTSTATUS pdb_enum_group_members(TALLOC_CTX *mem_ctx,
				const struct dom_sid *sid,
				uint32_t **pp_member_rids,
				size_t *p_num_members);
NTSTATUS pdb_enum_group_memberships(TALLOC_CTX *mem_ctx, struct samu *user,
				    struct dom_sid **pp_sids, gid_t **pp_gids,
				    size_t *p_num_groups);
NTSTATUS pdb_set_unix_primary_group(TALLOC_CTX *mem_ctx, struct samu *user);
NTSTATUS pdb_add_groupmem(TALLOC_CTX *mem_ctx, uint32_t group_rid,
			  uint32_t member_rid);
NTSTATUS pdb_del_groupmem(TALLOC_CTX *mem_ctx, uint32_t group_rid,
			  uint32_t member_rid);
NTSTATUS pdb_create_alias(const char *name, uint32_t *rid);
NTSTATUS pdb_delete_alias(const struct dom_sid *sid);
NTSTATUS pdb_get_aliasinfo(const struct dom_sid *sid, struct acct_info *info);
NTSTATUS pdb_set_aliasinfo(const struct dom_sid *sid, struct acct_info *info);
NTSTATUS pdb_add_aliasmem(const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_del_aliasmem(const struct dom_sid *alias, const struct dom_sid *member);
NTSTATUS pdb_enum_aliasmem(const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
			   struct dom_sid **pp_members, size_t *p_num_members);
NTSTATUS pdb_enum_alias_memberships(TALLOC_CTX *mem_ctx,
				    const struct dom_sid *domain_sid,
				    const struct dom_sid *members, size_t num_members,
				    uint32_t **pp_alias_rids,
				    size_t *p_num_alias_rids);
NTSTATUS pdb_lookup_rids(const struct dom_sid *domain_sid,
			 int num_rids,
			 uint32_t *rids,
			 const char **names,
			 enum lsa_SidType *attrs);
NTSTATUS pdb_lookup_names(const struct dom_sid *domain_sid,
			  int num_names,
			  const char **names,
			  uint32_t *rids,
			  enum lsa_SidType *attrs);
bool pdb_get_account_policy(enum pdb_policy_type type, uint32_t *value);
bool pdb_set_account_policy(enum pdb_policy_type type, uint32_t value);
bool pdb_get_seq_num(time_t *seq_num);
bool pdb_uid_to_sid(uid_t uid, struct dom_sid *sid);
bool pdb_gid_to_sid(gid_t gid, struct dom_sid *sid);
bool pdb_sid_to_id(const struct dom_sid *sid, union unid_t *id,
		   enum lsa_SidType *type);
uint32_t pdb_capabilities(void);
bool pdb_new_rid(uint32_t *rid);
bool initialize_password_db(bool reload, struct event_context *event_ctx);
struct pdb_search *pdb_search_init(TALLOC_CTX *mem_ctx,
				   enum pdb_search_type type);
struct pdb_search *pdb_search_users(TALLOC_CTX *mem_ctx, uint32_t acct_flags);
struct pdb_search *pdb_search_groups(TALLOC_CTX *mem_ctx);
struct pdb_search *pdb_search_aliases(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
uint32_t pdb_search_entries(struct pdb_search *search,
			  uint32_t start_idx, uint32_t max_entries,
			  struct samr_displayentry **result);
bool pdb_get_trusteddom_pw(const char *domain, char** pwd, struct dom_sid *sid,
			   time_t *pass_last_set_time);
bool pdb_set_trusteddom_pw(const char* domain, const char* pwd,
			   const struct dom_sid *sid);
bool pdb_del_trusteddom_pw(const char *domain);
NTSTATUS pdb_enum_trusteddoms(TALLOC_CTX *mem_ctx, uint32_t *num_domains,
			      struct trustdom_info ***domains);
NTSTATUS make_pdb_method( struct pdb_methods **methods ) ;

/* The following definitions come from passdb/pdb_ldap.c  */

const char** get_userattr_list( TALLOC_CTX *mem_ctx, int schema_ver );
int ldapsam_search_suffix_by_name(struct ldapsam_privates *ldap_state,
					  const char *user,
					  LDAPMessage ** result,
					  const char **attr);
NTSTATUS pdb_init_ldapsam_compat(struct pdb_methods **pdb_method, const char *location);
NTSTATUS pdb_init_ldapsam(struct pdb_methods **pdb_method, const char *location);
NTSTATUS pdb_ldap_init(void);

/* The following definitions come from passdb/pdb_nds.c  */

int pdb_nds_get_password(
	struct smbldap_state *ldap_state,
	char *object_dn,
	size_t *pwd_len,
	char *pwd );
int pdb_nds_set_password(
	struct smbldap_state *ldap_state,
	char *object_dn,
	const char *pwd );
NTSTATUS pdb_nds_init(void);

/* The following definitions come from passdb/pdb_smbpasswd.c  */

NTSTATUS pdb_smbpasswd_init(void) ;

/* The following definitions come from passdb/pdb_wbc_sam.c  */

NTSTATUS pdb_wbc_sam_init(void);

/* The following definitions come from passdb/pdb_tdb.c  */

bool init_sam_from_buffer_v2(struct samu *sampass, uint8_t *buf, uint32_t buflen);
NTSTATUS pdb_tdbsam_init(void);

/* The following definitions come from passdb/secrets.c  */

bool secrets_init(void);
struct db_context *secrets_db_ctx(void);
void secrets_shutdown(void);
void *secrets_fetch(const char *key, size_t *size);
bool secrets_store(const char *key, const void *data, size_t size);
bool secrets_delete(const char *key);
bool secrets_store_domain_sid(const char *domain, const struct dom_sid  *sid);
bool secrets_fetch_domain_sid(const char *domain, struct dom_sid  *sid);
bool secrets_store_domain_guid(const char *domain, struct GUID *guid);
bool secrets_fetch_domain_guid(const char *domain, struct GUID *guid);
void *secrets_get_trust_account_lock(TALLOC_CTX *mem_ctx, const char *domain);
enum netr_SchannelType get_default_sec_channel(void);
bool secrets_fetch_trust_account_password_legacy(const char *domain,
						 uint8 ret_pwd[16],
						 time_t *pass_last_set_time,
						 enum netr_SchannelType *channel);
bool secrets_fetch_trust_account_password(const char *domain, uint8 ret_pwd[16],
					  time_t *pass_last_set_time,
					  enum netr_SchannelType *channel);
bool secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
                                           struct dom_sid  *sid, time_t *pass_last_set_time);
bool secrets_store_trusted_domain_password(const char* domain, const char* pwd,
                                           const struct dom_sid  *sid);
bool secrets_delete_machine_password(const char *domain);
bool secrets_delete_machine_password_ex(const char *domain);
bool secrets_delete_domain_sid(const char *domain);
bool secrets_store_machine_password(const char *pass, const char *domain, enum netr_SchannelType sec_channel);
char *secrets_fetch_prev_machine_password(const char *domain);
char *secrets_fetch_machine_password(const char *domain,
				     time_t *pass_last_set_time,
				     enum netr_SchannelType *channel);
bool trusted_domain_password_delete(const char *domain);
bool secrets_store_ldap_pw(const char* dn, char* pw);
bool fetch_ldap_pw(char **dn, char** pw);
NTSTATUS secrets_trusted_domains(TALLOC_CTX *mem_ctx, uint32 *num_domains,
				 struct trustdom_info ***domains);
bool secrets_store_afs_keyfile(const char *cell, const struct afs_keyfile *keyfile);
bool secrets_fetch_afs_key(const char *cell, struct afs_key *result);
void secrets_fetch_ipc_userpass(char **username, char **domain, char **password);
bool secrets_store_generic(const char *owner, const char *key, const char *secret);
char *secrets_fetch_generic(const char *owner, const char *key);
bool secrets_delete_generic(const char *owner, const char *key);
bool secrets_store_local_schannel_key(uint8_t schannel_key[16]);
bool secrets_fetch_local_schannel_key(uint8_t schannel_key[16]);

/* The following definitions come from passdb/util_builtin.c  */

bool lookup_builtin_rid(TALLOC_CTX *mem_ctx, uint32 rid, const char **name);
bool lookup_builtin_name(const char *name, uint32 *rid);
const char *builtin_domain_name(void);
bool sid_check_is_builtin(const struct dom_sid *sid);
bool sid_check_is_in_builtin(const struct dom_sid *sid);

/* The following definitions come from passdb/util_unixsids.c  */

bool sid_check_is_unix_users(const struct dom_sid *sid);
bool sid_check_is_in_unix_users(const struct dom_sid *sid);
void uid_to_unix_users_sid(uid_t uid, struct dom_sid *sid);
void gid_to_unix_groups_sid(gid_t gid, struct dom_sid *sid);
const char *unix_users_domain_name(void);
bool lookup_unix_user_name(const char *name, struct dom_sid *sid);
bool sid_check_is_unix_groups(const struct dom_sid *sid);
bool sid_check_is_in_unix_groups(const struct dom_sid *sid);
const char *unix_groups_domain_name(void);
bool lookup_unix_group_name(const char *name, struct dom_sid *sid);

/* The following definitions come from passdb/util_wellknown.c  */

bool sid_check_is_wellknown_domain(const struct dom_sid *sid, const char **name);
bool sid_check_is_in_wellknown_domain(const struct dom_sid *sid);
bool lookup_wellknown_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			  const char **domain, const char **name);
bool lookup_wellknown_name(TALLOC_CTX *mem_ctx, const char *name,
			   struct dom_sid *sid, const char **domain);

/* The following definitions come from printing/load.c  */

void load_printers(void);

/* The following definitions come from printing/lpq_parse.c  */

bool parse_lpq_entry(enum printing_types printing_type,char *line,
		     print_queue_struct *buf,
		     print_status_struct *status,bool first);
uint32_t print_parse_jobid(const char *fname);

/* The following definitions come from printing/notify.c  */

int print_queue_snum(const char *qname);
void print_notify_send_messages(struct messaging_context *msg_ctx,
				unsigned int timeout);
void notify_printer_status_byname(const char *sharename, uint32 status);
void notify_printer_status(int snum, uint32 status);
void notify_job_status_byname(const char *sharename, uint32 jobid, uint32 status,
			      uint32 flags);
void notify_job_status(const char *sharename, uint32 jobid, uint32 status);
void notify_job_total_bytes(const char *sharename, uint32 jobid,
			    uint32 size);
void notify_job_total_pages(const char *sharename, uint32 jobid,
			    uint32 pages);
void notify_job_username(const char *sharename, uint32 jobid, char *name);
void notify_job_name(const char *sharename, uint32 jobid, char *name);
void notify_job_submitted(const char *sharename, uint32 jobid,
			  time_t submitted);
void notify_printer_driver(int snum, const char *driver_name);
void notify_printer_comment(int snum, const char *comment);
void notify_printer_sharename(int snum, const char *share_name);
void notify_printer_printername(int snum, const char *printername);
void notify_printer_port(int snum, const char *port_name);
void notify_printer_location(int snum, const char *location);
void notify_printer_byname( const char *printername, uint32 change, const char *value );

/* The following definitions come from printing/pcap.c  */

void pcap_cache_reload(void);
bool pcap_printername_ok(const char *printername);

/* The following definitions come from printing/printing.c  */

uint16 pjobid_to_rap(const char* sharename, uint32 jobid);
bool rap_to_pjobid(uint16 rap_jobid, fstring sharename, uint32 *pjobid);
void rap_jobid_delete(const char* sharename, uint32 jobid);
bool print_backend_init(struct messaging_context *msg_ctx);
void start_background_queue(void);
void printing_end(void);

/* The following definitions come from printing/printing_db.c  */

struct tdb_print_db *get_print_db_byname(const char *printername);
void release_print_db( struct tdb_print_db *pdb);
void close_all_print_db(void);
TDB_DATA get_printer_notify_pid_list(TDB_CONTEXT *tdb, const char *printer_name, bool cleanlist);

/* The following definitions come from profile/profile.c  */

void set_profile_level(int level, struct server_id src);
bool profile_setup(struct messaging_context *msg_ctx, bool rdonly);

/* The following definitions come from rpc_client/cli_pipe.c  */
bool smb_register_ndr_interface(const struct ndr_interface_table *interface);
const struct ndr_interface_table *get_iface_from_syntax(
	const struct ndr_syntax_id *syntax);
const char *get_pipe_name_from_syntax(TALLOC_CTX *mem_ctx,
                                     const struct ndr_syntax_id *syntax);
enum dcerpc_AuthType map_pipe_auth_type_to_rpc_auth_type(enum pipe_auth_type auth_type);

struct tevent_req *rpc_api_pipe_req_send(TALLOC_CTX *mem_ctx,
					 struct event_context *ev,
					 struct rpc_pipe_client *cli,
					 uint8_t op_num,
					 DATA_BLOB *req_data);
NTSTATUS rpc_api_pipe_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       DATA_BLOB *reply_pdu);
struct tevent_req *rpc_pipe_bind_send(TALLOC_CTX *mem_ctx,
				      struct event_context *ev,
				      struct rpc_pipe_client *cli,
				      struct pipe_auth_data *auth);
NTSTATUS rpc_pipe_bind_recv(struct tevent_req *req);
NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct pipe_auth_data *auth);
unsigned int rpccli_set_timeout(struct rpc_pipe_client *cli,
				unsigned int timeout);
bool rpccli_is_connected(struct rpc_pipe_client *rpc_cli);
bool rpccli_get_pwd_hash(struct rpc_pipe_client *cli, uint8_t nt_hash[16]);
NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct pipe_auth_data **presult);
NTSTATUS rpccli_schannel_bind_data(TALLOC_CTX *mem_ctx, const char *domain,
				   enum dcerpc_AuthLevel auth_level,
				   struct netlogon_creds_CredentialState *creds,
				   struct pipe_auth_data **presult);
NTSTATUS rpc_pipe_open_tcp(TALLOC_CTX *mem_ctx, const char *host,
			   const struct ndr_syntax_id *abstract_syntax,
			   struct rpc_pipe_client **presult);
NTSTATUS rpc_pipe_open_ncalrpc(TALLOC_CTX *mem_ctx, const char *socket_path,
			       const struct ndr_syntax_id *abstract_syntax,
			       struct rpc_pipe_client **presult);
struct pipes_struct *make_internal_rpc_pipe_p(TALLOC_CTX *mem_ctx,
					      const struct ndr_syntax_id *syntax,
					      const char *client_address,
					      struct auth_serversupplied_info *server_info);
NTSTATUS rpc_pipe_open_internal(TALLOC_CTX *mem_ctx, const struct ndr_syntax_id *abstract_syntax,
				struct auth_serversupplied_info *serversupplied_info,
				struct rpc_pipe_client **presult);
NTSTATUS rpc_connect_spoolss_pipe(connection_struct *conn,
				  struct rpc_pipe_client **spoolss_pipe);
NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
				  const struct ndr_syntax_id *interface,
				  struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_noauth_transport(struct cli_state *cli,
					    enum dcerpc_transport_t transport,
					    const struct ndr_syntax_id *interface,
					    struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_ntlmssp(struct cli_state *cli,
				   const struct ndr_syntax_id *interface,
				   enum dcerpc_transport_t transport,
				   enum dcerpc_AuthLevel auth_level,
				   const char *domain,
				   const char *username,
				   const char *password,
				   struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_spnego_ntlmssp(struct cli_state *cli,
					  const struct ndr_syntax_id *interface,
					  enum dcerpc_transport_t transport,
					  enum dcerpc_AuthLevel auth_level,
					  const char *domain,
					  const char *username,
					  const char *password,
					  struct rpc_pipe_client **presult);
NTSTATUS get_schannel_session_key(struct cli_state *cli,
				  const char *domain,
				  uint32 *pneg_flags,
				  struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_schannel_with_key(struct cli_state *cli,
					     const struct ndr_syntax_id *interface,
					     enum dcerpc_transport_t transport,
					     enum dcerpc_AuthLevel auth_level,
					     const char *domain,
					     struct netlogon_creds_CredentialState **pdc,
					     struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_ntlmssp_auth_schannel(struct cli_state *cli,
						 const struct ndr_syntax_id *interface,
						 enum dcerpc_transport_t transport,
						 enum dcerpc_AuthLevel auth_level,
						 const char *domain,
						 const char *username,
						 const char *password,
						 struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_schannel(struct cli_state *cli,
				    const struct ndr_syntax_id *interface,
				    enum dcerpc_transport_t transport,
				    enum dcerpc_AuthLevel auth_level,
				    const char *domain,
				    struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_krb5(struct cli_state *cli,
				const struct ndr_syntax_id *interface,
				enum dcerpc_AuthLevel auth_level,
				const char *service_princ,
				const char *username,
				const char *password,
				struct rpc_pipe_client **presult);
NTSTATUS cli_get_session_key(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *cli,
			     DATA_BLOB *session_key);
NTSTATUS rpc_pipe_open_local(TALLOC_CTX *mem_ctx,
			     struct rpc_cli_smbd_conn *conn,
			     const struct ndr_syntax_id *syntax,
			     struct rpc_pipe_client **presult);

/* The following definitions come from rpc_client/rpc_transport_np.c  */

struct tevent_req *rpc_transport_np_init_send(TALLOC_CTX *mem_ctx,
					      struct event_context *ev,
					      struct cli_state *cli,
					      const struct ndr_syntax_id *abstract_syntax);
NTSTATUS rpc_transport_np_init_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    struct rpc_cli_transport **presult);
NTSTATUS rpc_transport_np_init(TALLOC_CTX *mem_ctx, struct cli_state *cli,
			       const struct ndr_syntax_id *abstract_syntax,
			       struct rpc_cli_transport **presult);
struct cli_state *rpc_pipe_np_smb_conn(struct rpc_pipe_client *p);

/* The following definitions come from rpc_client/rpc_transport_smbd.c  */

struct tevent_req *rpc_cli_smbd_conn_init_send(TALLOC_CTX *mem_ctx,
					       struct event_context *ev,
					       void (*stdout_callback)(char *buf,
								       size_t len,
								       void *priv),
					       void *priv);
NTSTATUS rpc_cli_smbd_conn_init_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     struct rpc_cli_smbd_conn **pconn);
NTSTATUS rpc_cli_smbd_conn_init(TALLOC_CTX *mem_ctx,
				struct rpc_cli_smbd_conn **pconn,
				void (*stdout_callback)(char *buf,
							size_t len,
							void *priv),
				void *priv);

struct tevent_req *rpc_transport_smbd_init_send(TALLOC_CTX *mem_ctx,
						struct event_context *ev,
						struct rpc_cli_smbd_conn *conn,
						const struct ndr_syntax_id *abstract_syntax);
NTSTATUS rpc_transport_smbd_init_recv(struct tevent_req *req,
				      TALLOC_CTX *mem_ctx,
				      struct rpc_cli_transport **presult);
NTSTATUS rpc_transport_smbd_init(TALLOC_CTX *mem_ctx,
				 struct rpc_cli_smbd_conn *conn,
				 const struct ndr_syntax_id *abstract_syntax,
				 struct rpc_cli_transport **presult);
struct cli_state *rpc_pipe_smbd_smb_conn(struct rpc_pipe_client *p);

/* The following definitions come from rpc_client/rpc_transport_sock.c  */

NTSTATUS rpc_transport_sock_init(TALLOC_CTX *mem_ctx, int fd,
				 struct rpc_cli_transport **presult);

/* The following definitions come from rpc_client/init_lsa.c  */

void init_lsa_String(struct lsa_String *name, const char *s);
void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s);
void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s);
void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s);

/* The following definitions come from rpc_client/ndr.c  */

struct tevent_req *cli_do_rpc_ndr_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct rpc_pipe_client *cli,
				       const struct ndr_interface_table *table,
				       uint32_t opnum,
				       void *r);
NTSTATUS cli_do_rpc_ndr_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);
NTSTATUS cli_do_rpc_ndr(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			const struct ndr_interface_table *table,
			uint32 opnum, void *r);

/* The following definitions come from rpc_server/srv_eventlog_nt.c  */

/* The following definitions come from rpc_server/rpc_handles.c  */

size_t num_pipe_handles(struct pipes_struct *p);
bool init_pipe_handles(struct pipes_struct *p, const struct ndr_syntax_id *syntax);
bool create_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd, void *data_ptr);
bool find_policy_by_hnd(struct pipes_struct *p, const struct policy_handle *hnd,
			void **data_p);
bool close_policy_hnd(struct pipes_struct *p, struct policy_handle *hnd);
void close_policy_by_pipe(struct pipes_struct *p);
bool pipe_access_check(struct pipes_struct *p);

void *_policy_handle_create(struct pipes_struct *p, struct policy_handle *hnd,
			    uint32_t access_granted, size_t data_size,
			    const char *type, NTSTATUS *pstatus);
#define policy_handle_create(_p, _hnd, _access, _type, _pstatus) \
	(_type *)_policy_handle_create((_p), (_hnd), (_access), sizeof(_type), #_type, \
				       (_pstatus))

void *_policy_handle_find(struct pipes_struct *p,
			  const struct policy_handle *hnd,
			  uint32_t access_required, uint32_t *paccess_granted,
			  const char *name, const char *location,
			  NTSTATUS *pstatus);
#define policy_handle_find(_p, _hnd, _access_required, _access_granted, _type, _pstatus) \
	(_type *)_policy_handle_find((_p), (_hnd), (_access_required), \
				     (_access_granted), #_type, __location__, (_pstatus))


/* The following definitions come from rpc_server/srv_rpc_register.c  */

struct rpc_srv_callbacks {
	bool (*init)(void *private_data);
	bool (*shutdown)(void *private_data);
	void *private_data;
};

NTSTATUS rpc_srv_register(int version, const char *clnt,
			  const char *srv,
			  const struct ndr_interface_table *iface,
			  const struct api_struct *cmds, int size,
			  const struct rpc_srv_callbacks *rpc_srv_cb);

NTSTATUS rpc_srv_unregister(const struct ndr_interface_table *iface);

/* The following definitions come from rpc_server/srv_pipe.c  */

bool create_next_pdu(struct pipes_struct *p);
bool api_pipe_bind_auth3(struct pipes_struct *p, struct ncacn_packet *pkt);
bool setup_fault_pdu(struct pipes_struct *p, NTSTATUS status);
NTSTATUS rpc_pipe_register_commands(int version, const char *clnt,
				    const char *srv,
				    const struct ndr_syntax_id *interface,
				    const struct api_struct *cmds, int size);
bool is_known_pipename(const char *cli_filename, struct ndr_syntax_id *syntax);
bool api_pipe_bind_req(struct pipes_struct *p, struct ncacn_packet *pkt);
bool api_pipe_alter_context(struct pipes_struct *p, struct ncacn_packet *pkt);
void free_pipe_rpc_context( PIPE_RPC_FNS *list );
bool api_pipe_request(struct pipes_struct *p, struct ncacn_packet *pkt);

/* The following definitions come from rpc_server/srv_pipe_hnd.c  */

struct pipes_struct *get_first_internal_pipe(void);
struct pipes_struct *get_next_internal_pipe(struct pipes_struct *p);
bool check_open_pipes(void);

bool fsp_is_np(struct files_struct *fsp);
struct tsocket_address;
NTSTATUS np_open(TALLOC_CTX *mem_ctx, const char *name,
		 const struct tsocket_address *local_address,
		 const struct tsocket_address *remote_address,
		 struct auth_serversupplied_info *server_info,
		 struct fake_file_handle **phandle);
bool np_read_in_progress(struct fake_file_handle *handle);
struct tevent_req *np_write_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct fake_file_handle *handle,
				 const uint8_t *data, size_t len);
NTSTATUS np_write_recv(struct tevent_req *req, ssize_t *pnwritten);
struct tevent_req *np_read_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				struct fake_file_handle *handle,
				uint8_t *data, size_t len);
NTSTATUS np_read_recv(struct tevent_req *req, ssize_t *nread,
		      bool *is_data_outstanding);

/* The following definitions come from rpc_server/srv_spoolss_nt.c  */

void do_drv_upgrade_printer(struct messaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data);
void update_monitored_printq_cache( void );
void reset_all_printerdata(struct messaging_context *msg,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data);

/* The following definitions come from rpc_server/srv_srvsvc_nt.c  */

char *valid_share_pathname(TALLOC_CTX *ctx, const char *dos_pathname);

/* The following definitions come from rpc_server/srv_svcctl_nt.c  */

bool init_service_op_table( void );

/* The following definitions come from rpcclient/cmd_dfs.c  */


/* The following definitions come from rpcclient/cmd_dssetup.c  */


/* The following definitions come from rpcclient/cmd_echo.c  */


/* The following definitions come from rpcclient/cmd_lsarpc.c  */


/* The following definitions come from rpcclient/cmd_netlogon.c  */


/* The following definitions come from rpcclient/cmd_ntsvcs.c  */


/* The following definitions come from rpcclient/cmd_samr.c  */


/* The following definitions come from rpcclient/cmd_shutdown.c  */


/* The following definitions come from rpcclient/cmd_spoolss.c  */


/* The following definitions come from rpcclient/cmd_srvsvc.c  */


/* The following definitions come from rpcclient/cmd_test.c  */


/* The following definitions come from rpcclient/cmd_wkssvc.c  */


/* The following definitions come from rpcclient/rpcclient.c  */


/* The following definitions come from services/services_db.c  */

void svcctl_init_keys( void );
struct security_descriptor *svcctl_get_secdesc( TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
bool svcctl_set_secdesc( TALLOC_CTX *ctx, const char *name, struct security_descriptor *sec_desc, NT_USER_TOKEN *token );
const char *svcctl_lookup_dispname(TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
const char *svcctl_lookup_description(TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
struct regval_ctr *svcctl_fetch_regvalues( const char *name, NT_USER_TOKEN *token );

/* The following definitions come from services/svc_netlogon.c  */


/* The following definitions come from services/svc_rcinit.c  */


/* The following definitions come from services/svc_spoolss.c  */


/* The following definitions come from services/svc_winreg.c  */


/* The following definitions come from services/svc_wins.c  */


/* The following definitions come from smbd/aio.c  */

NTSTATUS schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt);
NTSTATUS schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, char *data,
			      SMB_OFF_T startpos,
			      size_t numtowrite);
NTSTATUS schedule_smb2_aio_read(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				char *inbuf,
				SMB_OFF_T startpos,
				size_t smb_maxcnt);
NTSTATUS schedule_aio_smb2_write(connection_struct *conn,
				struct smb_request *smbreq,
				files_struct *fsp,
				uint64_t in_offset,
				DATA_BLOB in_data,
				bool write_through);
int wait_for_aio_completion(files_struct *fsp);
void cancel_aio_by_fsp(files_struct *fsp);
void smbd_aio_complete_aio_ex(struct aio_extra *aio_ex);

/* The following definitions come from smbd/blocking.c  */

void brl_timeout_fn(struct event_context *event_ctx,
		struct timed_event *te,
		struct timeval now,
		void *private_data);
struct timeval timeval_brl_min(const struct timeval *tv1,
			const struct timeval *tv2);
void process_blocking_lock_queue(struct smbd_server_connection *sconn);
bool push_blocking_lock_request( struct byte_range_lock *br_lck,
		struct smb_request *req,
		files_struct *fsp,
		int lock_timeout,
		int lock_num,
		uint64_t smblctx,
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		uint64_t offset,
		uint64_t count,
		uint64_t blocking_smblctx);
void cancel_pending_lock_requests_by_fid(files_struct *fsp,
			struct byte_range_lock *br_lck,
			enum file_close_type close_type);
void remove_pending_lock_requests_by_mid_smb1(
	struct smbd_server_connection *sconn, uint64_t mid);
bool blocking_lock_was_deferred_smb1(
	struct smbd_server_connection *sconn, uint64_t mid);
struct blocking_lock_record *blocking_lock_cancel_smb1(files_struct *fsp,
			uint64_t smblctx,
			uint64_t offset,
			uint64_t count,
			enum brl_flavour lock_flav,
			unsigned char locktype,
                        NTSTATUS err);

/* The following definitions come from smbd/close.c  */

void set_close_write_time(struct files_struct *fsp, struct timespec ts);
NTSTATUS close_file(struct smb_request *req, files_struct *fsp,
		    enum file_close_type close_type);
void msg_close_file(struct messaging_context *msg_ctx,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);
NTSTATUS delete_all_streams(connection_struct *conn, const char *fname);

/* The following definitions come from smbd/conn.c  */

void conn_init(struct smbd_server_connection *sconn);
int conn_num_open(struct smbd_server_connection *sconn);
bool conn_snum_used(int snum);
connection_struct *conn_find(struct smbd_server_connection *sconn,
			     unsigned cnum);
connection_struct *conn_new(struct smbd_server_connection *sconn);
bool conn_close_all(struct smbd_server_connection *sconn);
bool conn_idle_all(struct smbd_server_connection *sconn, time_t t);
void conn_clear_vuid_caches(struct smbd_server_connection *sconn, uint16 vuid);
void conn_free(connection_struct *conn);
void msg_force_tdis(struct messaging_context *msg,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);

/* The following definitions come from smbd/connection.c  */

bool yield_connection(connection_struct *conn, const char *name);
int count_current_connections( const char *sharename, bool clear  );
bool claim_connection(connection_struct *conn, const char *name);

/* The following definitions come from smbd/dfree.c  */

uint64_t sys_disk_free(connection_struct *conn, const char *path, bool small_query, 
                              uint64_t *bsize,uint64_t *dfree,uint64_t *dsize);
uint64_t get_dfree_info(connection_struct *conn,
			const char *path,
			bool small_query,
			uint64_t *bsize,
			uint64_t *dfree,
			uint64_t *dsize);

/* The following definitions come from smbd/dir.c  */

bool make_dir_struct(TALLOC_CTX *ctx,
			char *buf,
			const char *mask,
			const char *fname,
			SMB_OFF_T size,
			uint32 mode,
			time_t date,
			bool uc);
bool init_dptrs(struct smbd_server_connection *sconn);
char *dptr_path(struct smbd_server_connection *sconn, int key);
char *dptr_wcard(struct smbd_server_connection *sconn, int key);
uint16 dptr_attr(struct smbd_server_connection *sconn, int key);
void dptr_close(struct smbd_server_connection *sconn, int *key);
void dptr_closecnum(connection_struct *conn);
void dptr_idlecnum(connection_struct *conn);
void dptr_closepath(struct smbd_server_connection *sconn,
		    char *path,uint16 spid);
NTSTATUS dptr_create(connection_struct *conn, const char *path, bool old_handle, bool expect_close,uint16 spid,
		const char *wcard, bool wcard_has_wild, uint32 attr, struct dptr_struct **dptr_ret);
int dptr_CloseDir(struct dptr_struct *dptr);
void dptr_SeekDir(struct dptr_struct *dptr, long offset);
long dptr_TellDir(struct dptr_struct *dptr);
bool dptr_has_wild(struct dptr_struct *dptr);
int dptr_dnum(struct dptr_struct *dptr);
char *dptr_ReadDirName(TALLOC_CTX *ctx,
			struct dptr_struct *dptr,
			long *poffset,
			SMB_STRUCT_STAT *pst);
bool dptr_SearchDir(struct dptr_struct *dptr, const char *name, long *poffset, SMB_STRUCT_STAT *pst);
void dptr_DirCacheAdd(struct dptr_struct *dptr, const char *name, long offset);
void dptr_init_search_op(struct dptr_struct *dptr);
bool dptr_fill(struct smbd_server_connection *sconn,
	       char *buf1,unsigned int key);
struct dptr_struct *dptr_fetch(struct smbd_server_connection *sconn,
			       char *buf,int *num);
struct dptr_struct *dptr_fetch_lanman2(struct smbd_server_connection *sconn,
				       int dptr_num);
bool dir_check_ftype(connection_struct *conn, uint32 mode, uint32 dirtype);
bool get_dir_entry(TALLOC_CTX *ctx,
		struct dptr_struct *dirptr,
		const char *mask,
		uint32 dirtype,
		char **pp_fname_out,
		SMB_OFF_T *size,
		uint32 *mode,
		struct timespec *date,
		bool check_descend,
		bool ask_sharemode);
bool is_visible_file(connection_struct *conn, const char *dir_path, const char *name, SMB_STRUCT_STAT *pst, bool use_veto);
struct smb_Dir *OpenDir(TALLOC_CTX *mem_ctx, connection_struct *conn,
			const char *name, const char *mask, uint32 attr);
const char *ReadDirName(struct smb_Dir *dirp, long *poffset,
			SMB_STRUCT_STAT *sbuf, char **talloced);
void RewindDir(struct smb_Dir *dirp, long *poffset);
void SeekDir(struct smb_Dir *dirp, long offset);
long TellDir(struct smb_Dir *dirp);
void DirCacheAdd(struct smb_Dir *dirp, const char *name, long offset);
bool SearchDir(struct smb_Dir *dirp, const char *name, long *poffset);
NTSTATUS can_delete_directory(struct connection_struct *conn,
				const char *dirname);

/* The following definitions come from smbd/dmapi.c  */

const void *dmapi_get_current_session(void);
bool dmapi_have_session(void);
bool dmapi_new_session(void);
bool dmapi_destroy_session(void);
uint32 dmapi_file_flags(const char * const path);

/* The following definitions come from smbd/dnsregister.c  */

bool smbd_setup_mdns_registration(struct tevent_context *ev,
				  TALLOC_CTX *mem_ctx,
				  uint16_t port);

/* The following definitions come from smbd/dosmode.c  */

mode_t unix_mode(connection_struct *conn, int dosmode,
		 const struct smb_filename *smb_fname,
		 const char *inherit_from_dir);
uint32 dos_mode_msdfs(connection_struct *conn,
		      const struct smb_filename *smb_fname);
int dos_attributes_to_stat_dos_flags(uint32_t dosmode);
uint32 dos_mode(connection_struct *conn, struct smb_filename *smb_fname);
int file_set_dosmode(connection_struct *conn, struct smb_filename *smb_fname,
		     uint32 dosmode, const char *parent_dir, bool newfile);
int file_ntimes(connection_struct *conn, const struct smb_filename *smb_fname,
		struct smb_file_time *ft);
bool set_sticky_write_time_path(struct file_id fileid, struct timespec mtime);
bool set_sticky_write_time_fsp(struct files_struct *fsp,
			       struct timespec mtime);

NTSTATUS set_create_timespec_ea(connection_struct *conn,
				const struct smb_filename *smb_fname,
				struct timespec create_time);

struct timespec get_create_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname);

struct timespec get_change_timespec(connection_struct *conn,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname);

/* The following definitions come from smbd/error.c  */

bool use_nt_status(void);
void error_packet_set(char *outbuf, uint8 eclass, uint32 ecode, NTSTATUS ntstatus, int line, const char *file);
int error_packet(char *outbuf, uint8 eclass, uint32 ecode, NTSTATUS ntstatus, int line, const char *file);
void reply_nt_error(struct smb_request *req, NTSTATUS ntstatus,
		    int line, const char *file);
void reply_force_dos_error(struct smb_request *req, uint8 eclass, uint32 ecode,
		    int line, const char *file);
void reply_both_error(struct smb_request *req, uint8 eclass, uint32 ecode,
		      NTSTATUS status, int line, const char *file);
void reply_openerror(struct smb_request *req, NTSTATUS status);

/* The following definitions come from smbd/fake_file.c  */

enum FAKE_FILE_TYPE is_fake_file_path(const char *path);
enum FAKE_FILE_TYPE is_fake_file(const struct smb_filename *smb_fname);
NTSTATUS open_fake_file(struct smb_request *req, connection_struct *conn,
				uint16_t current_vuid,
				enum FAKE_FILE_TYPE fake_file_type,
				const struct smb_filename *smb_fname,
				uint32 access_mask,
				files_struct **result);
NTSTATUS close_fake_file(struct smb_request *req, files_struct *fsp);

/* The following definitions come from smbd/file_access.c  */

bool can_access_file_acl(struct connection_struct *conn,
			 const struct smb_filename *smb_fname,
			 uint32_t access_mask);
bool can_delete_file_in_directory(connection_struct *conn,
				  struct smb_filename *smb_fname);
bool can_access_file_data(connection_struct *conn,
			  const struct smb_filename *smb_fname,
			  uint32 access_mask);
bool can_write_to_file(connection_struct *conn,
		       const struct smb_filename *smb_fname);
bool directory_has_default_acl(connection_struct *conn, const char *fname);

/* The following definitions come from smbd/fileio.c  */

ssize_t read_file(files_struct *fsp,char *data,SMB_OFF_T pos,size_t n);
void update_write_time_handler(struct event_context *ctx,
                                      struct timed_event *te,
                                      struct timeval now,
                                      void *private_data);
void trigger_write_time_update(struct files_struct *fsp);
void trigger_write_time_update_immediate(struct files_struct *fsp);
ssize_t write_file(struct smb_request *req,
			files_struct *fsp,
			const char *data,
			SMB_OFF_T pos,
			size_t n);
void delete_write_cache(files_struct *fsp);
void set_filelen_write_cache(files_struct *fsp, SMB_OFF_T file_size);
ssize_t flush_write_cache(files_struct *fsp, enum flush_reason_enum reason);
NTSTATUS sync_file(connection_struct *conn, files_struct *fsp, bool write_through);
int fsp_stat(files_struct *fsp);

/* The following definitions come from smbd/filename.c  */

NTSTATUS unix_convert(TALLOC_CTX *ctx,
		      connection_struct *conn,
		      const char *orig_path,
		      struct smb_filename **smb_fname,
		      uint32_t ucf_flags);
NTSTATUS check_name(connection_struct *conn, const char *name);
int get_real_filename(connection_struct *conn, const char *path,
		      const char *name, TALLOC_CTX *mem_ctx,
		      char **found_name);
NTSTATUS filename_convert(TALLOC_CTX *mem_ctx,
			connection_struct *conn,
			bool dfs_path,
			const char *name_in,
			uint32_t ucf_flags,
			bool *ppath_contains_wcard,
			struct smb_filename **pp_smb_fname);

/* The following definitions come from smbd/filename_utils.c */

NTSTATUS get_full_smb_filename(TALLOC_CTX *ctx, const struct smb_filename *smb_fname,
			      char **full_name);
NTSTATUS create_synthetic_smb_fname(TALLOC_CTX *ctx, const char *base_name,
				    const char *stream_name,
				    const SMB_STRUCT_STAT *psbuf,
				    struct smb_filename **smb_fname_out);
NTSTATUS create_synthetic_smb_fname_split(TALLOC_CTX *ctx,
					  const char *fname,
					  const SMB_STRUCT_STAT *psbuf,
					  struct smb_filename **smb_fname_out);
const char *smb_fname_str_dbg(const struct smb_filename *smb_fname);
const char *fsp_str_dbg(const struct files_struct *fsp);
NTSTATUS copy_smb_filename(TALLOC_CTX *ctx,
			   const struct smb_filename *smb_fname_in,
			   struct smb_filename **smb_fname_out);
bool is_ntfs_stream_smb_fname(const struct smb_filename *smb_fname);
bool is_ntfs_default_stream_smb_fname(const struct smb_filename *smb_fname);

/* The following definitions come from smbd/files.c  */

NTSTATUS file_new(struct smb_request *req, connection_struct *conn,
		  files_struct **result);
void file_close_conn(connection_struct *conn);
void file_close_pid(uint16 smbpid, int vuid);
void file_init(void);
void file_close_user(int vuid);
void file_dump_open_table(void);
struct files_struct *files_forall(
	struct files_struct *(*fn)(struct files_struct *fsp,
				   void *private_data),
	void *private_data);
files_struct *file_find_fd(int fd);
files_struct *file_find_dif(struct file_id id, unsigned long gen_id);
files_struct *file_find_fsp(files_struct *orig_fsp);
files_struct *file_find_di_first(struct file_id id);
files_struct *file_find_di_next(files_struct *start_fsp);
files_struct *file_find_print(void);
bool file_find_subpath(files_struct *dir_fsp);
void file_sync_all(connection_struct *conn);
void file_free(struct smb_request *req, files_struct *fsp);
files_struct *file_fnum(uint16 fnum);
files_struct *file_fsp(struct smb_request *req, uint16 fid);
NTSTATUS dup_file_fsp(struct smb_request *req, files_struct *from,
		      uint32 access_mask, uint32 share_access,
		      uint32 create_options, files_struct *to);
NTSTATUS fsp_set_smb_fname(struct files_struct *fsp,
			   const struct smb_filename *smb_fname_in);

/* The following definitions come from smbd/ipc.c  */

void send_trans_reply(connection_struct *conn,
		      struct smb_request *req,
		      char *rparam, int rparam_len,
		      char *rdata, int rdata_len,
		      bool buffer_too_large);
void reply_trans(struct smb_request *req);
void reply_transs(struct smb_request *req);

/* The following definitions come from smbd/lanman.c  */

time_t spoolss_Time_to_time_t(const struct spoolss_Time *r);
void api_reply(connection_struct *conn, uint16 vuid,
	       struct smb_request *req,
	       char *data, char *params,
	       int tdscnt, int tpscnt,
	       int mdrcnt, int mprcnt);

/* The following definitions come from smbd/mangle.c  */

void mangle_reset_cache(void);
void mangle_change_to_posix(void);
bool mangle_is_mangled(const char *s, const struct share_params *p);
bool mangle_is_8_3(const char *fname, bool check_case,
		   const struct share_params *p);
bool mangle_is_8_3_wildcards(const char *fname, bool check_case,
			     const struct share_params *p);
bool mangle_must_mangle(const char *fname,
		   const struct share_params *p);
bool mangle_lookup_name_from_8_3(TALLOC_CTX *ctx,
			const char *in,
			char **out, /* talloced on the given context. */
			const struct share_params *p);
bool name_to_8_3(const char *in,
		char out[13],
		bool cache83,
		const struct share_params *p);

/* The following definitions come from smbd/mangle_hash.c  */

const struct mangle_fns *mangle_hash_init(void);

/* The following definitions come from smbd/mangle_hash2.c  */

const struct mangle_fns *mangle_hash2_init(void);
const struct mangle_fns *posix_mangle_init(void);

/* The following definitions come from smbd/map_username.c  */

bool map_username(fstring user);

/* The following definitions come from smbd/message.c  */

void reply_sends(struct smb_request *req);
void reply_sendstrt(struct smb_request *req);
void reply_sendtxt(struct smb_request *req);
void reply_sendend(struct smb_request *req);

/* The following definitions come from smbd/msdfs.c  */

bool is_msdfs_link(connection_struct *conn,
		const char *path,
		SMB_STRUCT_STAT *sbufp);
NTSTATUS get_referred_path(TALLOC_CTX *ctx,
			const char *dfs_path,
			struct junction_map *jucn,
			int *consumedcntp,
			bool *self_referralp);
int setup_dfs_referral(connection_struct *orig_conn,
			const char *dfs_path,
			int max_referral_level,
			char **ppdata, NTSTATUS *pstatus);
bool create_junction(TALLOC_CTX *ctx,
		const char *dfs_path,
		struct junction_map *jucn);
bool create_msdfs_link(const struct junction_map *jucn);
bool remove_msdfs_link(const struct junction_map *jucn);
struct junction_map *enum_msdfs_links(TALLOC_CTX *ctx, size_t *p_num_jn);
NTSTATUS resolve_dfspath(TALLOC_CTX *ctx,
			connection_struct *conn,
			bool dfs_pathnames,
			const char *name_in,
			char **pp_name_out);
NTSTATUS resolve_dfspath_wcard(TALLOC_CTX *ctx,
				connection_struct *conn,
				bool dfs_pathnames,
				const char *name_in,
				bool allow_wcards,
				char **pp_name_out,
				bool *ppath_contains_wcard);
NTSTATUS create_conn_struct(TALLOC_CTX *ctx,
				connection_struct **pconn,
				int snum,
				const char *path,
				struct auth_serversupplied_info *server_info,
				char **poldcwd);

/* The following definitions come from smbd/negprot.c  */

void reply_negprot(struct smb_request *req);

/* The following definitions come from smbd/notify.c  */

void change_notify_reply(struct smb_request *req,
			 NTSTATUS error_code,
			 uint32_t max_param,
			 struct notify_change_buf *notify_buf,
			 void (*reply_fn)(struct smb_request *req,
					  NTSTATUS error_code,
					  uint8_t *buf, size_t len));
NTSTATUS change_notify_create(struct files_struct *fsp, uint32 filter,
			      bool recursive);
NTSTATUS change_notify_add_request(struct smb_request *req,
				uint32 max_param,
				uint32 filter, bool recursive,
				struct files_struct *fsp,
				void (*reply_fn)(struct smb_request *req,
					NTSTATUS error_code,
					uint8_t *buf, size_t len));
void remove_pending_change_notify_requests_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid);
void remove_pending_change_notify_requests_by_fid(files_struct *fsp,
						  NTSTATUS status);
void notify_fname(connection_struct *conn, uint32 action, uint32 filter,
		  const char *path);
char *notify_filter_string(TALLOC_CTX *mem_ctx, uint32 filter);
struct sys_notify_context *sys_notify_context_create(connection_struct *conn,
						     TALLOC_CTX *mem_ctx, 
						     struct event_context *ev);
NTSTATUS sys_notify_watch(struct sys_notify_context *ctx,
			  struct notify_entry *e,
			  void (*callback)(struct sys_notify_context *ctx, 
					   void *private_data,
					   struct notify_event *ev),
			  void *private_data, void *handle);

/* The following definitions come from smbd/notify_inotify.c  */

NTSTATUS inotify_watch(struct sys_notify_context *ctx,
		       struct notify_entry *e,
		       void (*callback)(struct sys_notify_context *ctx, 
					void *private_data,
					struct notify_event *ev),
		       void *private_data, 
		       void *handle_p);

/* The following definitions come from smbd/notify_internal.c  */

struct notify_context *notify_init(TALLOC_CTX *mem_ctx, struct server_id server, 
				   struct messaging_context *messaging_ctx,
				   struct event_context *ev,
				   connection_struct *conn);
bool notify_internal_parent_init(void);
NTSTATUS notify_add(struct notify_context *notify, struct notify_entry *e0,
		    void (*callback)(void *, const struct notify_event *), 
		    void *private_data);
NTSTATUS notify_remove(struct notify_context *notify, void *private_data);
NTSTATUS notify_remove_onelevel(struct notify_context *notify,
				const struct file_id *fid,
				void *private_data);
void notify_onelevel(struct notify_context *notify, uint32_t action,
		     uint32_t filter, struct file_id fid, const char *name);
void notify_trigger(struct notify_context *notify,
		    uint32_t action, uint32_t filter, const char *path);

/* The following definitions come from smbd/ntquotas.c  */

int vfs_get_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_set_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, struct dom_sid *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_get_user_ntquota_list(files_struct *fsp, SMB_NTQUOTA_LIST **qt_list);
void *init_quota_handle(TALLOC_CTX *mem_ctx);

/* The following definitions come from smbd/nttrans.c  */

void send_nt_replies(connection_struct *conn,
			struct smb_request *req, NTSTATUS nt_error,
		     char *params, int paramsize,
		     char *pdata, int datasize);
void reply_ntcreate_and_X(struct smb_request *req);
NTSTATUS set_sd(files_struct *fsp, uint8_t *data, uint32_t sd_len,
                       uint32_t security_info_sent);
struct ea_list *read_nttrans_ea_list(TALLOC_CTX *ctx, const char *pdata, size_t data_size);
void reply_ntcancel(struct smb_request *req);
void reply_ntrename(struct smb_request *req);
NTSTATUS smbd_do_query_security_desc(connection_struct *conn,
					TALLOC_CTX *mem_ctx,
					files_struct *fsp,
					uint32_t security_info_wanted,
					uint32_t max_data_count,
					uint8_t **ppmarshalled_sd,
					size_t *psd_size);
void reply_nttrans(struct smb_request *req);
void reply_nttranss(struct smb_request *req);

/* The following definitions come from smbd/open.c  */

NTSTATUS smb1_file_se_access_check(connection_struct *conn,
				const struct security_descriptor *sd,
				const NT_USER_TOKEN *token,
				uint32_t access_desired,
				uint32_t *access_granted);
NTSTATUS fd_close(files_struct *fsp);
void change_file_owner_to_parent(connection_struct *conn,
				 const char *inherit_from_dir,
				 files_struct *fsp);
NTSTATUS change_dir_owner_to_parent(connection_struct *conn,
				    const char *inherit_from_dir,
				    const char *fname,
				    SMB_STRUCT_STAT *psbuf);
bool is_executable(const char *fname);
bool is_stat_open(uint32 access_mask);
bool request_timed_out(struct timeval request_time,
		       struct timeval timeout);
bool open_match_attributes(connection_struct *conn,
			   uint32 old_dos_attr,
			   uint32 new_dos_attr,
			   mode_t existing_unx_mode,
			   mode_t new_unx_mode,
			   mode_t *returned_unx_mode);
NTSTATUS fcb_or_dos_open(struct smb_request *req,
			 connection_struct *conn,
			 files_struct *fsp_to_dup_into,
			 const struct smb_filename *smb_fname,
			 struct file_id id,
			 uint16 file_pid,
			 uint16 vuid,
			 uint32 access_mask,
			 uint32 share_access,
			 uint32 create_options);
bool map_open_params_to_ntcreate(const struct smb_filename *smb_fname,
				 int deny_mode, int open_func,
				 uint32 *paccess_mask,
				 uint32 *pshare_mode,
				 uint32 *pcreate_disposition,
				 uint32 *pcreate_options,
				 uint32_t *pprivate_flags);
void remove_deferred_open_entry(struct file_id id, uint64_t mid,
				struct server_id pid);
NTSTATUS open_file_fchmod(struct smb_request *req, connection_struct *conn,
			  struct smb_filename *smb_fname,
			  files_struct **result);
NTSTATUS close_file_fchmod(struct smb_request *req, files_struct *fsp);
NTSTATUS create_directory(connection_struct *conn, struct smb_request *req,
			  struct smb_filename *smb_dname);
void msg_file_was_renamed(struct messaging_context *msg,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id server_id,
			  DATA_BLOB *data);
NTSTATUS open_streams_for_delete(connection_struct *conn,
				 const char *fname);
NTSTATUS create_file_default(connection_struct *conn,
			     struct smb_request *req,
			     uint16_t root_dir_fid,
			     struct smb_filename * smb_fname,
			     uint32_t access_mask,
			     uint32_t share_access,
			     uint32_t create_disposition,
			     uint32_t create_options,
			     uint32_t file_attributes,
			     uint32_t oplock_request,
			     uint64_t allocation_size,
			     uint32_t private_flags,
			     struct security_descriptor *sd,
			     struct ea_list *ea_list,

			     files_struct **result,
			     int *pinfo);
NTSTATUS get_relative_fid_filename(connection_struct *conn,
				   struct smb_request *req,
				   uint16_t root_dir_fid,
				   struct smb_filename *smb_fname);

/* The following definitions come from smbd/oplock.c  */

int32 get_number_of_exclusive_open_oplocks(void);
void break_kernel_oplock(struct messaging_context *msg_ctx, files_struct *fsp);
bool set_file_oplock(files_struct *fsp, int oplock_type);
void release_file_oplock(files_struct *fsp);
bool remove_oplock(files_struct *fsp);
bool downgrade_oplock(files_struct *fsp);
bool should_notify_deferred_opens(void);
void break_level2_to_none_async(files_struct *fsp);
void reply_to_oplock_break_requests(files_struct *fsp);
void process_oplock_async_level2_break_message(struct messaging_context *msg_ctx,
						      void *private_data,
						      uint32_t msg_type,
						      struct server_id src,
						      DATA_BLOB *data);
void contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type);
void contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type);
void share_mode_entry_to_message(char *msg, const struct share_mode_entry *e);
void message_to_share_mode_entry(struct share_mode_entry *e, char *msg);
bool init_oplocks(struct messaging_context *msg_ctx);

/* The following definitions come from smbd/oplock_irix.c  */

struct kernel_oplocks *irix_init_kernel_oplocks(TALLOC_CTX *mem_ctx) ;

/* The following definitions come from smbd/oplock_linux.c  */

void linux_set_lease_capability(void);
int linux_set_lease_sighandler(int fd);
int linux_setlease(int fd, int leasetype);
struct kernel_oplocks *linux_init_kernel_oplocks(TALLOC_CTX *mem_ctx) ;

/* The following definitions come from smbd/oplock_onefs.c  */

struct kernel_oplocks *onefs_init_kernel_oplocks(TALLOC_CTX *mem_ctx);

/* The following definitions come from smbd/password.c  */

user_struct *get_valid_user_struct(struct smbd_server_connection *sconn,
				   uint16 vuid);
bool is_partial_auth_vuid(struct smbd_server_connection *sconn, uint16 vuid);
user_struct *get_partial_auth_user_struct(struct smbd_server_connection *sconn,
					  uint16 vuid);
void invalidate_vuid(struct smbd_server_connection *sconn, uint16 vuid);
void invalidate_all_vuids(struct smbd_server_connection *sconn);
int register_initial_vuid(struct smbd_server_connection *sconn);
int register_homes_share(const char *username);
int register_existing_vuid(struct smbd_server_connection *sconn,
			uint16 vuid,
			struct auth_serversupplied_info *server_info,
			DATA_BLOB response_blob,
			const char *smb_name);
void add_session_user(struct smbd_server_connection *sconn, const char *user);
void add_session_workgroup(struct smbd_server_connection *sconn,
			   const char *workgroup);
const char *get_session_workgroup(struct smbd_server_connection *sconn);
bool user_in_netgroup(const char *user, const char *ngname);
bool user_in_list(const char *user,const char **list);
bool authorise_login(struct smbd_server_connection *sconn,
		     int snum, fstring user, DATA_BLOB password,
		     bool *guest);

/* The following definitions come from smbd/pipes.c  */

NTSTATUS open_np_file(struct smb_request *smb_req, const char *name,
		      struct files_struct **pfsp);
void reply_open_pipe_and_X(connection_struct *conn, struct smb_request *req);
void reply_pipe_write(struct smb_request *req);
void reply_pipe_write_and_X(struct smb_request *req);
void reply_pipe_read_and_X(struct smb_request *req);
void reply_pipe_close(connection_struct *conn, struct smb_request *req);

/* The following definitions come from smbd/posix_acls.c  */

void create_file_sids(const SMB_STRUCT_STAT *psbuf, struct dom_sid *powner_sid, struct dom_sid *pgroup_sid);
bool nt4_compatible_acls(void);
uint32_t map_canon_ace_perms(int snum,
                                enum security_ace_type *pacl_type,
                                mode_t perms,
                                bool directory_ace);
NTSTATUS unpack_nt_owners(connection_struct *conn, uid_t *puser, gid_t *pgrp, uint32 security_info_sent, const struct security_descriptor *psd);
SMB_ACL_T free_empty_sys_acl(connection_struct *conn, SMB_ACL_T the_acl);
NTSTATUS posix_fget_nt_acl(struct files_struct *fsp, uint32_t security_info,
			   struct security_descriptor **ppdesc);
NTSTATUS posix_get_nt_acl(struct connection_struct *conn, const char *name,
			  uint32_t security_info, struct security_descriptor **ppdesc);
int try_chown(connection_struct *conn, struct smb_filename *smb_fname,
	      uid_t uid, gid_t gid);
NTSTATUS append_parent_acl(files_struct *fsp,
				const struct security_descriptor *pcsd,
				struct security_descriptor **pp_new_sd);
NTSTATUS set_nt_acl(files_struct *fsp, uint32 security_info_sent, const struct security_descriptor *psd);
int get_acl_group_bits( connection_struct *conn, const char *fname, mode_t *mode );
int chmod_acl(connection_struct *conn, const char *name, mode_t mode);
int inherit_access_posix_acl(connection_struct *conn, const char *inherit_from_dir,
		       const char *name, mode_t mode);
int fchmod_acl(files_struct *fsp, mode_t mode);
bool set_unix_posix_default_acl(connection_struct *conn, const char *fname,
				const SMB_STRUCT_STAT *psbuf,
				uint16 num_def_acls, const char *pdata);
bool set_unix_posix_acl(connection_struct *conn, files_struct *fsp, const char *fname, uint16 num_acls, const char *pdata);
struct security_descriptor *get_nt_acl_no_snum( TALLOC_CTX *ctx, const char *fname);

/* The following definitions come from smbd/process.c  */

void smbd_setup_sig_term_handler(void);
void smbd_setup_sig_hup_handler(void);
bool srv_send_smb(int fd, char *buffer,
		  bool no_signing, uint32_t seqnum,
		  bool do_encrypt,
		  struct smb_perfcount_data *pcd);
int srv_set_message(char *buf,
                        int num_words,
                        int num_bytes,
                        bool zero);
void remove_deferred_open_message_smb(uint64_t mid);
void schedule_deferred_open_message_smb(uint64_t mid);
bool open_was_deferred(uint64_t mid);
bool get_deferred_open_message_state(struct smb_request *smbreq,
				struct timeval *p_request_time,
				void **pp_state);
bool push_deferred_open_message_smb(struct smb_request *req,
				struct timeval request_time,
				struct timeval timeout,
				struct file_id id,
				char *private_data,
				size_t priv_len);
struct idle_event *event_add_idle(struct event_context *event_ctx,
				  TALLOC_CTX *mem_ctx,
				  struct timeval interval,
				  const char *name,
				  bool (*handler)(const struct timeval *now,
						  void *private_data),
				  void *private_data);
NTSTATUS allow_new_trans(struct trans_state *list, uint64_t mid);
void reply_outbuf(struct smb_request *req, uint8 num_words, uint32 num_bytes);
const char *smb_fn_name(int type);
void add_to_common_flags2(uint32 v);
void remove_from_common_flags2(uint32 v);
void construct_reply_common_req(struct smb_request *req, char *outbuf);
size_t req_wct_ofs(struct smb_request *req);
void chain_reply(struct smb_request *req);
bool req_is_in_chain(struct smb_request *req);
void check_reload(time_t t);
void smbd_process(void);

/* The following definitions come from smbd/quotas.c  */

bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas(const char *path,
		uint64_t *bsize,
		uint64_t *dfree,
		uint64_t *dsize);
bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas_vxfs(const char *name, char *path, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize);
bool disk_quotas(const char *path,uint64_t *bsize,uint64_t *dfree,uint64_t *dsize);
bool disk_quotas(const char *path,uint64_t *bsize,uint64_t *dfree,uint64_t *dsize);

/* The following definitions come from smbd/reply.c  */

NTSTATUS check_path_syntax(char *path);
NTSTATUS check_path_syntax_wcard(char *path, bool *p_contains_wcard);
NTSTATUS check_path_syntax_posix(char *path);
size_t srvstr_get_path_wcard(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16 smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err,
			bool *contains_wcard);
size_t srvstr_get_path(TALLOC_CTX *ctx,
			const char *inbuf,
			uint16 smb_flags2,
			char **pp_dest,
			const char *src,
			size_t src_len,
			int flags,
			NTSTATUS *err);
size_t srvstr_get_path_req_wcard(TALLOC_CTX *mem_ctx, struct smb_request *req,
				 char **pp_dest, const char *src, int flags,
				 NTSTATUS *err, bool *contains_wcard);
size_t srvstr_get_path_req(TALLOC_CTX *mem_ctx, struct smb_request *req,
			   char **pp_dest, const char *src, int flags,
			   NTSTATUS *err);
bool check_fsp_open(connection_struct *conn, struct smb_request *req,
		    files_struct *fsp);
bool check_fsp(connection_struct *conn, struct smb_request *req,
	       files_struct *fsp);
bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp);
void reply_special(struct smbd_server_connection *sconn, char *inbuf);
void reply_tcon(struct smb_request *req);
void reply_tcon_and_X(struct smb_request *req);
void reply_unknown_new(struct smb_request *req, uint8 type);
void reply_ioctl(struct smb_request *req);
void reply_checkpath(struct smb_request *req);
void reply_getatr(struct smb_request *req);
void reply_setatr(struct smb_request *req);
void reply_dskattr(struct smb_request *req);
void reply_search(struct smb_request *req);
void reply_fclose(struct smb_request *req);
void reply_open(struct smb_request *req);
void reply_open_and_X(struct smb_request *req);
void reply_ulogoffX(struct smb_request *req);
void reply_mknew(struct smb_request *req);
void reply_ctemp(struct smb_request *req);
NTSTATUS unlink_internals(connection_struct *conn, struct smb_request *req,
			  uint32 dirtype, struct smb_filename *smb_fname,
			  bool has_wild);
void reply_unlink(struct smb_request *req);
void reply_readbraw(struct smb_request *req);
void reply_lockread(struct smb_request *req);
void reply_read(struct smb_request *req);
void reply_read_and_X(struct smb_request *req);
void error_to_writebrawerr(struct smb_request *req);
void reply_writebraw(struct smb_request *req);
void reply_writeunlock(struct smb_request *req);
void reply_write(struct smb_request *req);
bool is_valid_writeX_buffer(struct smbd_server_connection *sconn,
			    const uint8_t *inbuf);
void reply_write_and_X(struct smb_request *req);
void reply_lseek(struct smb_request *req);
void reply_flush(struct smb_request *req);
void reply_exit(struct smb_request *req);
void reply_close(struct smb_request *req);
void reply_writeclose(struct smb_request *req);
void reply_lock(struct smb_request *req);
void reply_unlock(struct smb_request *req);
void reply_tdis(struct smb_request *req);
void reply_echo(struct smb_request *req);
void reply_printopen(struct smb_request *req);
void reply_printclose(struct smb_request *req);
void reply_printqueue(struct smb_request *req);
void reply_printwrite(struct smb_request *req);
void reply_mkdir(struct smb_request *req);
void reply_rmdir(struct smb_request *req);
NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			const struct smb_filename *smb_fname_dst_in,
			uint32 attrs,
			bool replace_if_exists);
NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			uint32 attrs,
			bool replace_if_exists,
			bool src_has_wild,
			bool dest_has_wild,
			uint32_t access_mask);
void reply_mv(struct smb_request *req);
NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			int ofun,
			int count,
			bool target_is_directory);
void reply_copy(struct smb_request *req);
uint64_t get_lock_pid(const uint8_t *data, int data_offset,
		    bool large_file_format);
uint64_t get_lock_count(const uint8_t *data, int data_offset,
			bool large_file_format);
uint64_t get_lock_offset(const uint8_t *data, int data_offset,
			 bool large_file_format, bool *err);
void reply_lockingX(struct smb_request *req);
void reply_readbmpx(struct smb_request *req);
void reply_readbs(struct smb_request *req);
void reply_setattrE(struct smb_request *req);
void reply_writebmpx(struct smb_request *req);
void reply_writebs(struct smb_request *req);
void reply_getattrE(struct smb_request *req);

/* The following definitions come from smbd/seal.c  */

uint16_t srv_enc_ctx(void);
bool is_encrypted_packet(const uint8_t *inbuf);
void srv_free_enc_buffer(char *buf);
NTSTATUS srv_decrypt_buffer(char *buf);
NTSTATUS srv_encrypt_buffer(char *buf, char **buf_out);
NTSTATUS srv_request_encryption_setup(connection_struct *conn,
					unsigned char **ppdata,
					size_t *p_data_size,
					unsigned char **pparam,
					size_t *p_param_size);
NTSTATUS srv_encryption_start(connection_struct *conn);
void server_encryption_shutdown(void);

/* The following definitions come from smbd/sec_ctx.c  */

bool unix_token_equal(const UNIX_USER_TOKEN *t1, const UNIX_USER_TOKEN *t2);
bool push_sec_ctx(void);
void set_sec_ctx(uid_t uid, gid_t gid, int ngroups, gid_t *groups, NT_USER_TOKEN *token);
void set_root_sec_ctx(void);
bool pop_sec_ctx(void);
void init_sec_ctx(void);

/* The following definitions come from lib/server_contexts.c  */
struct tevent_context *server_event_context(void);
void server_event_context_free(void);
struct messaging_context *server_messaging_context(void);
void server_messaging_context_free(void);

/* The following definitions come from smbd/server.c  */

int smbd_server_fd(void);
int get_client_fd(void);
struct event_context *smbd_event_context(void);
struct messaging_context *smbd_messaging_context(void);
struct memcache *smbd_memcache(void);
void reload_printers(void);
bool reload_services(bool test);
void exit_server(const char *const explanation);
void exit_server_cleanly(const char *const explanation);
void exit_server_fault(void);

/* The following definitions come from smbd/service.c  */

bool set_conn_connectpath(connection_struct *conn, const char *connectpath);
bool set_current_service(connection_struct *conn, uint16 flags, bool do_chdir);
void load_registry_shares(void);
int add_home_service(const char *service, const char *username, const char *homedir);
int find_service(fstring service);
connection_struct *make_connection_snum(struct smbd_server_connection *sconn,
					int snum, user_struct *vuser,
					DATA_BLOB password,
					const char *pdev,
					NTSTATUS *pstatus);
connection_struct *make_connection(struct smbd_server_connection *sconn,
				   const char *service_in, DATA_BLOB password,
				   const char *pdev, uint16 vuid,
				   NTSTATUS *status);
void close_cnum(connection_struct *conn, uint16 vuid);

/* The following definitions come from smbd/session.c  */

bool session_init(void);
bool session_claim(struct server_id pid, user_struct *vuser);
void session_yield(user_struct *vuser);
int list_sessions(TALLOC_CTX *mem_ctx, struct sessionid **session_list);

/* The following definitions come from lib/sessionid_tdb.c  */

bool sessionid_init(void);
struct db_record *sessionid_fetch_record(TALLOC_CTX *mem_ctx, const char *key);
int sessionid_traverse(int (*fn)(struct db_record *rec, const char *key,
				 struct sessionid *session,
				 void *private_data),
		       void *private_data);
int sessionid_traverse_read(int (*fn)(const char *key,
				      struct sessionid *session,
				      void *private_data),
			    void *private_data);

/* The following definitions come from smbd/sesssetup.c  */

NTSTATUS do_map_to_guest(NTSTATUS status,
		struct auth_serversupplied_info **server_info,
		const char *user, const char *domain);

NTSTATUS parse_spnego_mechanisms(TALLOC_CTX *ctx,
		DATA_BLOB blob_in,
		DATA_BLOB *pblob_out,
		char **kerb_mechOID);
void reply_sesssetup_and_X(struct smb_request *req);

/* The following definitions come from smbd/share_access.c  */

bool token_contains_name_in_list(const char *username,
				 const char *domain,
				 const char *sharename,
				 const struct nt_user_token *token,
				 const char **list);
bool user_ok_token(const char *username, const char *domain,
		   const struct nt_user_token *token, int snum);
bool is_share_read_only_for_token(const char *username,
				  const char *domain,
				  const struct nt_user_token *token,
				  connection_struct *conn);

/* The following definitions come from smbd/srvstr.c  */

size_t srvstr_push_fn(const char *function, unsigned int line,
		      const char *base_ptr, uint16 smb_flags2, void *dest,
		      const char *src, int dest_len, int flags);
ssize_t message_push_string(uint8 **outbuf, const char *str, int flags);

/* The following definitions come from smbd/statcache.c  */

void stat_cache_add( const char *full_orig_name,
		char *translated_path,
		bool case_sensitive);
bool stat_cache_lookup(connection_struct *conn,
			char **pp_name,
			char **pp_dirpath,
			char **pp_start,
			SMB_STRUCT_STAT *pst);
void send_stat_cache_delete_message(const char *name);
void stat_cache_delete(const char *name);
unsigned int fast_string_hash(TDB_DATA *key);
bool reset_stat_cache( void );

/* The following definitions come from smbd/statvfs.c  */

int sys_statvfs(const char *path, vfs_statvfs_struct *statbuf);

/* The following definitions come from smbd/trans2.c  */

uint64_t smb_roundup(connection_struct *conn, uint64_t val);
uint64_t get_FileIndex(connection_struct *conn, const SMB_STRUCT_STAT *psbuf);
NTSTATUS get_ea_value(TALLOC_CTX *mem_ctx, connection_struct *conn,
		      files_struct *fsp, const char *fname,
		      const char *ea_name, struct ea_struct *pea);
NTSTATUS get_ea_names_from_file(TALLOC_CTX *mem_ctx, connection_struct *conn,
				files_struct *fsp, const char *fname,
				char ***pnames, size_t *pnum_names);
NTSTATUS set_ea(connection_struct *conn, files_struct *fsp,
		const struct smb_filename *smb_fname, struct ea_list *ea_list);
struct ea_list *read_ea_list_entry(TALLOC_CTX *ctx, const char *pdata, size_t data_size, size_t *pbytes_used);
void send_trans2_replies(connection_struct *conn,
			struct smb_request *req,
			 const char *params,
			 int paramsize,
			 const char *pdata,
			 int datasize,
			 int max_data_bytes);
unsigned char *create_volume_objectid(connection_struct *conn, unsigned char objid[16]);
NTSTATUS hardlink_internals(TALLOC_CTX *ctx,
		connection_struct *conn,
		struct smb_request *req,
		bool overwrite_if_exists,
		const struct smb_filename *smb_fname_old,
		struct smb_filename *smb_fname_new);
NTSTATUS smb_set_file_time(connection_struct *conn,
			   files_struct *fsp,
			   const struct smb_filename *smb_fname,
			   struct smb_file_time *ft,
			   bool setting_write_time);
void reply_findclose(struct smb_request *req);
void reply_findnclose(struct smb_request *req);
void reply_trans2(struct smb_request *req);
void reply_transs2(struct smb_request *req);

/* The following definitions come from smbd/uid.c  */

bool change_to_guest(void);
void conn_clear_vuid_cache(connection_struct *conn, uint16_t vuid);
bool change_to_user(connection_struct *conn, uint16 vuid);
bool change_to_root_user(void);
bool become_authenticated_pipe_user(struct pipes_struct *p);
bool unbecome_authenticated_pipe_user(void);
void become_root(void);
void unbecome_root(void);
bool become_user(connection_struct *conn, uint16 vuid);
bool unbecome_user(void);
uid_t get_current_uid(connection_struct *conn);
gid_t get_current_gid(connection_struct *conn);
const UNIX_USER_TOKEN *get_current_utok(connection_struct *conn);
const NT_USER_TOKEN *get_current_nttok(connection_struct *conn);
uint16_t get_current_vuid(connection_struct *conn);

/* The following definitions come from smbd/utmp.c  */

void sys_utmp_claim(const char *username, const char *hostname,
			const char *ip_addr_str,
			const char *id_str, int id_num);
void sys_utmp_yield(const char *username, const char *hostname,
			const char *ip_addr_str,
			const char *id_str, int id_num);
void sys_utmp_yield(const char *username, const char *hostname,
			const char *ip_addr_str,
			const char *id_str, int id_num);
void sys_utmp_claim(const char *username, const char *hostname,
			const char *ip_addr_str,
			const char *id_str, int id_num);

/* The following definitions come from smbd/vfs.c  */

NTSTATUS smb_register_vfs(int version, const char *name,
			  const struct vfs_fn_pointers *fns);
bool vfs_init_custom(connection_struct *conn, const char *vfs_object);
void *vfs_add_fsp_extension_notype(vfs_handle_struct *handle,
				   files_struct *fsp, size_t ext_size,
				   void (*destroy_fn)(void *p_data));
void vfs_remove_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void *vfs_memctx_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void *vfs_fetch_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
bool smbd_vfs_init(connection_struct *conn);
NTSTATUS vfs_file_exist(connection_struct *conn, struct smb_filename *smb_fname);
ssize_t vfs_read_data(files_struct *fsp, char *buf, size_t byte_count);
ssize_t vfs_pread_data(files_struct *fsp, char *buf,
                size_t byte_count, SMB_OFF_T offset);
ssize_t vfs_write_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N);
ssize_t vfs_pwrite_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N,
			SMB_OFF_T offset);
int vfs_allocate_file_space(files_struct *fsp, uint64_t len);
int vfs_set_filelen(files_struct *fsp, SMB_OFF_T len);
int vfs_fill_sparse(files_struct *fsp, SMB_OFF_T len);
SMB_OFF_T vfs_transfer_file(files_struct *in, files_struct *out, SMB_OFF_T n);
const char *vfs_readdirname(connection_struct *conn, void *p,
			    SMB_STRUCT_STAT *sbuf, char **talloced);
int vfs_ChDir(connection_struct *conn, const char *path);
char *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn);
NTSTATUS check_reduced_name(connection_struct *conn, const char *fname);
int vfs_stat_smb_fname(struct connection_struct *conn, const char *fname,
		       SMB_STRUCT_STAT *psbuf);
int vfs_lstat_smb_fname(struct connection_struct *conn, const char *fname,
			SMB_STRUCT_STAT *psbuf);
NTSTATUS vfs_stat_fsp(files_struct *fsp);

/* The following definitions come from utils/passwd_util.c  */

char *stdin_new_passwd( void);
char *get_pass( const char *prompt, bool stdin_get);

/* The following definitions come from winbindd/idmap.c  */

bool idmap_is_offline(void);
bool idmap_is_online(void);
NTSTATUS smb_register_idmap(int version, const char *name,
			    struct idmap_methods *methods);
NTSTATUS smb_register_idmap_alloc(int version, const char *name,
				  struct idmap_alloc_methods *methods);
void idmap_close(void);
NTSTATUS idmap_init_cache(void);
NTSTATUS idmap_allocate_uid(struct unixid *id);
NTSTATUS idmap_allocate_gid(struct unixid *id);
NTSTATUS idmap_set_uid_hwm(struct unixid *id);
NTSTATUS idmap_set_gid_hwm(struct unixid *id);
NTSTATUS idmap_backends_unixid_to_sid(const char *domname,
				      struct id_map *id);
NTSTATUS idmap_backends_sid_to_unixid(const char *domname,
				      struct id_map *id);
NTSTATUS idmap_new_mapping(const struct dom_sid *psid, enum id_type type,
			   struct unixid *pxid);
NTSTATUS idmap_set_mapping(const struct id_map *map);
NTSTATUS idmap_remove_mapping(const struct id_map *map);

/* The following definitions come from winbindd/idmap_cache.c  */

bool idmap_cache_find_sid2uid(const struct dom_sid *sid, uid_t *puid,
			      bool *expired);
bool idmap_cache_find_uid2sid(uid_t uid, struct dom_sid *sid, bool *expired);
void idmap_cache_set_sid2uid(const struct dom_sid *sid, uid_t uid);
bool idmap_cache_find_sid2gid(const struct dom_sid *sid, gid_t *pgid,
			      bool *expired);
bool idmap_cache_find_gid2sid(gid_t gid, struct dom_sid *sid, bool *expired);
void idmap_cache_set_sid2gid(const struct dom_sid *sid, gid_t gid);


/* The following definitions come from winbindd/idmap_nss.c  */

NTSTATUS idmap_nss_init(void);

/* The following definitions come from winbindd/idmap_passdb.c  */

NTSTATUS idmap_passdb_init(void);

/* The following definitions come from winbindd/idmap_tdb.c  */

NTSTATUS idmap_alloc_tdb_init(void);
NTSTATUS idmap_tdb_init(void);

/* The following definitions come from winbindd/idmap_util.c  */

NTSTATUS idmap_uid_to_sid(const char *domname, struct dom_sid *sid, uid_t uid);
NTSTATUS idmap_gid_to_sid(const char *domname, struct dom_sid *sid, gid_t gid);
NTSTATUS idmap_sid_to_uid(const char *dom_name, struct dom_sid *sid, uid_t *uid);
NTSTATUS idmap_sid_to_gid(const char *domname, struct dom_sid *sid, gid_t *gid);

/* The following definitions come from winbindd/nss_info.c  */


/* The following definitions come from winbindd/nss_info_template.c  */

NTSTATUS nss_info_template_init( void );

/* The following definitions come from lib/avahi.c */

struct AvahiPoll *tevent_avahi_poll(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev);

/* The following definitions come from smbd/avahi_register.c */

void *avahi_start_register(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   uint16_t port);

/* Misc protos */

struct fncall_context *fncall_context_init(TALLOC_CTX *mem_ctx,
					   int max_threads);
struct tevent_req *fncall_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct fncall_context *ctx,
			       void (*fn)(void *private_data),
			       void *private_data);
int fncall_recv(struct tevent_req *req, int *perr);

/* The following definitions come from rpc_server/srv_samr_nt.c */
NTSTATUS access_check_object( struct security_descriptor *psd, NT_USER_TOKEN *token,
				SE_PRIV *rights, uint32 rights_mask,
				uint32 des_access, uint32 *acc_granted,
				const char *debug);
void map_max_allowed_access(const NT_USER_TOKEN *nt_token,
			    const struct unix_user_token *unix_token,
			    uint32_t *pacc_requested);

/* The following definitions come from ../libds/common/flag_mapping.c  */

uint32_t ds_acb2uf(uint32_t acb);
uint32_t ds_uf2acb(uint32_t uf);
uint32_t ds_uf2atype(uint32_t uf);
uint32_t ds_gtype2atype(uint32_t gtype);
enum lsa_SidType ds_atype_map(uint32_t atype);

#endif /*  _PROTO_H_  */

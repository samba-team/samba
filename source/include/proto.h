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

NTSTATUS check_plaintext_password(const char *smb_name, DATA_BLOB plaintext_password, auth_serversupplied_info **server_info);
bool password_ok(const char *smb_name, DATA_BLOB password_blob);

/* The following definitions come from auth/auth_domain.c  */

void attempt_machine_password_change(void);
NTSTATUS auth_domain_init(void);

/* The following definitions come from auth/auth_ntlmssp.c  */

NTSTATUS auth_ntlmssp_start(AUTH_NTLMSSP_STATE **auth_ntlmssp_state);
void auth_ntlmssp_end(AUTH_NTLMSSP_STATE **auth_ntlmssp_state);
NTSTATUS auth_ntlmssp_update(AUTH_NTLMSSP_STATE *auth_ntlmssp_state, 
			     const DATA_BLOB request, DATA_BLOB *reply) ;

/* The following definitions come from auth/auth_sam.c  */

NTSTATUS auth_sam_init(void);

/* The following definitions come from auth/auth_server.c  */

NTSTATUS auth_server_init(void);

/* The following definitions come from auth/auth_unix.c  */

NTSTATUS auth_unix_init(void);

/* The following definitions come from auth/auth_util.c  */

NTSTATUS make_user_info_map(auth_usersupplied_info **user_info, 
			    const char *smb_name, 
			    const char *client_domain, 
			    const char *wksta_name, 
 			    DATA_BLOB *lm_pwd, DATA_BLOB *nt_pwd,
 			    DATA_BLOB *lm_interactive_pwd, DATA_BLOB *nt_interactive_pwd,
			    DATA_BLOB *plaintext, 
			    bool encrypted);
bool make_user_info_netlogon_network(auth_usersupplied_info **user_info, 
				     const char *smb_name, 
				     const char *client_domain, 
				     const char *wksta_name, 
				     uint32 logon_parameters,
				     const uchar *lm_network_pwd,
				     int lm_pwd_len,
				     const uchar *nt_network_pwd,
				     int nt_pwd_len);
bool make_user_info_netlogon_interactive(auth_usersupplied_info **user_info, 
					 const char *smb_name, 
					 const char *client_domain, 
					 const char *wksta_name, 
					 uint32 logon_parameters,
					 const uchar chal[8], 
					 const uchar lm_interactive_pwd[16], 
					 const uchar nt_interactive_pwd[16], 
					 const uchar *dc_sess_key);
bool make_user_info_for_reply(auth_usersupplied_info **user_info, 
			      const char *smb_name, 
			      const char *client_domain,
			      const uint8 chal[8],
			      DATA_BLOB plaintext_password);
NTSTATUS make_user_info_for_reply_enc(auth_usersupplied_info **user_info, 
                                      const char *smb_name,
                                      const char *client_domain, 
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp);
bool make_user_info_guest(auth_usersupplied_info **user_info) ;
NTSTATUS make_server_info_sam(auth_serversupplied_info **server_info, 
			      struct samu *sampass);
NTSTATUS create_local_token(auth_serversupplied_info *server_info);
NTSTATUS create_token_from_username(TALLOC_CTX *mem_ctx, const char *username,
				    bool is_guest,
				    uid_t *uid, gid_t *gid,
				    char **found_username,
				    struct nt_user_token **token);
bool user_in_group_sid(const char *username, const DOM_SID *group_sid);
bool user_in_group(const char *username, const char *groupname);
NTSTATUS make_server_info_pw(auth_serversupplied_info **server_info, 
                             char *unix_username,
			     struct passwd *pwd);
NTSTATUS make_serverinfo_from_username(TALLOC_CTX *mem_ctx,
				       const char *username,
				       bool is_guest,
				       struct auth_serversupplied_info **presult);
struct auth_serversupplied_info *copy_serverinfo(TALLOC_CTX *mem_ctx,
						 const auth_serversupplied_info *src);
bool init_guest_info(void);
bool server_info_set_session_key(struct auth_serversupplied_info *info,
				 DATA_BLOB session_key);
NTSTATUS make_server_info_guest(TALLOC_CTX *mem_ctx,
				auth_serversupplied_info **server_info);
bool copy_current_user(struct current_user *dst, struct current_user *src);
struct passwd *smb_getpwnam( TALLOC_CTX *mem_ctx, char *domuser,
			     fstring save_username, bool create );
NTSTATUS make_server_info_info3(TALLOC_CTX *mem_ctx, 
				const char *sent_nt_username,
				const char *domain,
				auth_serversupplied_info **server_info, 
				struct netr_SamInfo3 *info3);
NTSTATUS make_server_info_wbcAuthUserInfo(TALLOC_CTX *mem_ctx,
					  const char *sent_nt_username,
					  const char *domain,
					  const struct wbcAuthUserInfo *info,
					  auth_serversupplied_info **server_info);
void free_user_info(auth_usersupplied_info **user_info);
bool make_auth_methods(struct auth_context *auth_context, auth_methods **auth_method) ;
bool is_trusted_domain(const char* dom_name);

/* The following definitions come from auth/auth_winbind.c  */

NTSTATUS auth_winbind_init(void);

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

bool nt_token_check_sid ( const DOM_SID *sid, const NT_USER_TOKEN *token );
bool nt_token_check_domain_rid( NT_USER_TOKEN *token, uint32 rid );
NT_USER_TOKEN *get_root_nt_token( void );
NTSTATUS add_aliases(const DOM_SID *domain_sid,
		     struct nt_user_token *token);
NTSTATUS create_builtin_users(const DOM_SID *sid);
NTSTATUS create_builtin_administrators(const DOM_SID *sid);
struct nt_user_token *create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const DOM_SID *user_sid,
					    bool is_guest,
					    int num_groupsids,
					    const DOM_SID *groupsids);
void debug_nt_user_token(int dbg_class, int dbg_lev, NT_USER_TOKEN *token);
void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid,
			   int n_groups, gid_t *groups);

/* The following definitions come from groupdb/mapping.c  */

NTSTATUS add_initial_entry(gid_t gid, const char *sid, enum lsa_SidType sid_name_use, const char *nt_name, const char *comment);
bool get_domain_group_from_sid(DOM_SID sid, GROUP_MAP *map);
int smb_create_group(const char *unix_group, gid_t *new_gid);
int smb_delete_group(const char *unix_group);
int smb_set_primary_group(const char *unix_group, const char* unix_user);
int smb_add_user_group(const char *unix_group, const char *unix_user);
int smb_delete_user_group(const char *unix_group, const char *unix_user);
NTSTATUS pdb_default_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid);
NTSTATUS pdb_default_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_default_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_default_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_default_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_default_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid);
NTSTATUS pdb_default_enum_group_mapping(struct pdb_methods *methods,
					   const DOM_SID *sid, enum lsa_SidType sid_name_use,
					   GROUP_MAP **pp_rmap, size_t *p_num_entries,
					   bool unix_only);
NTSTATUS pdb_default_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid);
NTSTATUS pdb_default_delete_alias(struct pdb_methods *methods,
				  const DOM_SID *sid);
NTSTATUS pdb_default_get_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_set_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info);
NTSTATUS pdb_default_add_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member);
NTSTATUS pdb_default_del_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member);
NTSTATUS pdb_default_enum_aliasmem(struct pdb_methods *methods,
				   const DOM_SID *alias, DOM_SID **pp_members,
				   size_t *p_num_members);
NTSTATUS pdb_default_alias_memberships(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const DOM_SID *domain_sid,
				       const DOM_SID *members,
				       size_t num_members,
				       uint32 **pp_alias_rids,
				       size_t *p_num_alias_rids);
NTSTATUS pdb_nop_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid);
NTSTATUS pdb_nop_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid);
NTSTATUS pdb_nop_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name);
NTSTATUS pdb_nop_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map);
NTSTATUS pdb_nop_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map);
NTSTATUS pdb_nop_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid);
NTSTATUS pdb_nop_enum_group_mapping(struct pdb_methods *methods,
					   enum lsa_SidType sid_name_use,
					   GROUP_MAP **rmap, size_t *num_entries,
					   bool unix_only);
bool pdb_get_dom_grp_info(const DOM_SID *sid, struct acct_info *info);
bool pdb_set_dom_grp_info(const DOM_SID *sid, const struct acct_info *info);
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

/* The following definitions come from lib/account_pol.c  */

void account_policy_names_list(const char ***names, int *num_names);
const char *decode_account_policy_name(int field);
const char *get_account_policy_attr(int field);
const char *account_policy_get_desc(int field);
int account_policy_name_to_fieldnum(const char *name);
bool account_policy_get_default(int account_policy, uint32 *val);
bool init_account_policy(void);
bool account_policy_get(int field, uint32 *value);
bool account_policy_set(int field, uint32 value);
bool cache_account_policy_set(int field, uint32 value);
bool cache_account_policy_get(int field, uint32 *value);
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

/* The following definitions come from lib/arc4.c  */

void smb_arc4_init(unsigned char arc4_state_out[258], const unsigned char *key, size_t keylen);
void smb_arc4_crypt(unsigned char arc4_state_inout[258], unsigned char *data, size_t len);

/* The following definitions come from lib/audit.c  */

const char *audit_category_str(uint32 category);
const char *audit_param_str(uint32 category);
const char *audit_description_str(uint32 category);
bool get_audit_category_from_param(const char *param, uint32 *audit_category);
const char *audit_policy_str(TALLOC_CTX *mem_ctx, uint32 policy);

/* The following definitions come from lib/bitmap.c  */

struct bitmap *bitmap_allocate(int n);
void bitmap_free(struct bitmap *bm);
struct bitmap *bitmap_talloc(TALLOC_CTX *mem_ctx, int n);
int bitmap_copy(struct bitmap * const dst, const struct bitmap * const src);
bool bitmap_set(struct bitmap *bm, unsigned i);
bool bitmap_clear(struct bitmap *bm, unsigned i);
bool bitmap_query(struct bitmap *bm, unsigned i);
int bitmap_find(struct bitmap *bm, unsigned ofs);

/* The following definitions come from lib/charcnv.c  */

char lp_failed_convert_char(void);
void lazy_initialize_conv(void);
void gfree_charcnv(void);
void init_iconv(void);
size_t convert_string(charset_t from, charset_t to,
		      void const *src, size_t srclen, 
		      void *dest, size_t destlen, bool allow_bad_conv);
bool convert_string_allocate(TALLOC_CTX *ctx, charset_t from, charset_t to,
			     void const *src, size_t srclen, void *dst,
			     size_t *converted_size, bool allow_bad_conv);
bool convert_string_talloc(TALLOC_CTX *ctx, charset_t from, charset_t to,
			   void const *src, size_t srclen, void *dst,
			   size_t *converted_size, bool allow_bad_conv);
size_t unix_strupper(const char *src, size_t srclen, char *dest, size_t destlen);
char *strdup_upper(const char *s);
char *talloc_strdup_upper(TALLOC_CTX *ctx, const char *s);
size_t unix_strlower(const char *src, size_t srclen, char *dest, size_t destlen);
char *strdup_lower(const char *s);
char *talloc_strdup_lower(TALLOC_CTX *ctx, const char *s);
size_t ucs2_align(const void *base_ptr, const void *p, int flags);
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags);
size_t push_ascii_fstring(void *dest, const char *src);
size_t push_ascii_nstring(void *dest, const char *src);
bool push_ascii_allocate(char **dest, const char *src, size_t *converted_size);
size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t pull_ascii_fstring(char *dest, const void *src);
size_t pull_ascii_nstring(char *dest, size_t dest_len, const void *src);
size_t push_ucs2(const void *base_ptr, void *dest, const char *src, size_t dest_len, int flags);
bool push_ucs2_allocate(smb_ucs2_t **dest, const char *src,
			size_t *converted_size);
size_t push_utf8_fstring(void *dest, const char *src);
bool push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size);
bool push_utf8_allocate(char **dest, const char *src, size_t *converted_size);
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
bool pull_ucs2_allocate(char **dest, const smb_ucs2_t *src,
			size_t *converted_size);
bool pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size);
bool pull_utf8_allocate(char **dest, const char *src, size_t *converted_size);
bool pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src,
		      size_t *converted_size);
bool pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		       size_t *converted_size);
size_t push_string_fn(const char *function, unsigned int line,
		      const void *base_ptr, uint16 flags2,
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

struct db_record *connections_fetch_record(TALLOC_CTX *mem_ctx,
					   TDB_DATA key);
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
bool connections_init(bool rw);

/* The following definitions come from lib/crc32.c  */

uint32 crc32_calc_buffer(const char *buf, size_t size);

/* The following definitions come from lib/data_blob.c  */

DATA_BLOB data_blob(const void *p, size_t length);
DATA_BLOB data_blob_talloc(TALLOC_CTX *mem_ctx, const void *p, size_t length);
void data_blob_free(DATA_BLOB *d);
void data_blob_clear(DATA_BLOB *d);
void data_blob_clear_free(DATA_BLOB *d);
DATA_BLOB data_blob_string_const(const char *str);
DATA_BLOB data_blob_const(const void *p, size_t length);
DATA_BLOB data_blob_talloc_zero(TALLOC_CTX *mem_ctx, size_t length);
_PUBLIC_ char *data_blob_hex_string(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob);

/* The following definitions come from lib/dbwrap_util.c  */

int32_t dbwrap_fetch_int32(struct db_context *db, const char *keystr);
int dbwrap_store_int32(struct db_context *db, const char *keystr, int32_t v);
bool dbwrap_fetch_uint32(struct db_context *db, const char *keystr,
			 uint32_t *val);
int dbwrap_store_uint32(struct db_context *db, const char *keystr, uint32_t v);
uint32_t dbwrap_change_uint32_atomic(struct db_context *db, const char *keystr,
				     uint32_t *oldval, uint32_t change_val);
int32 dbwrap_change_int32_atomic(struct db_context *db, const char *keystr,
				 int32 *oldval, int32 change_val);
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
void debug_set_logfile(const char *name);
bool reopen_logs( void );
void force_check_log_size( void );
bool need_to_check_log_size( void );
void check_log_size( void );
void dbgflush( void );
bool dbghdr(int level, int cls, const char *file, const char *func, int line);
TALLOC_CTX *debug_ctx(void);

/* The following definitions come from lib/display_sec.c  */

char *get_sec_mask_str(TALLOC_CTX *ctx, uint32 type);
void display_sec_access(uint32_t *info);
void display_sec_ace_flags(uint8_t flags);
void display_sec_ace(SEC_ACE *ace);
void display_sec_acl(SEC_ACL *sec_acl);
void display_acl_type(uint16 type);
void display_sec_desc(SEC_DESC *sec);

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

struct file_id file_id_create_dev(SMB_DEV_T dev, SMB_INO_T inode);
struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf);
bool file_id_equal(const struct file_id *id1, const struct file_id *id2);
const char *file_id_string_tos(const struct file_id *id);
void push_file_id_16(char *buf, const struct file_id *id);
void pull_file_id_16(char *buf, struct file_id *id);

/* The following definitions come from lib/fsusage.c  */

int sys_fsusage(const char *path, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);

/* The following definitions come from lib/gencache.c  */

bool gencache_init(void);
bool gencache_shutdown(void);
bool gencache_set(const char *keystr, const char *value, time_t timeout);
bool gencache_del(const char *keystr);
bool gencache_get(const char *keystr, char **valstr, time_t *timeout);
bool gencache_get_data_blob(const char *keystr, DATA_BLOB *blob, bool *expired);
bool gencache_set_data_blob(const char *keystr, const DATA_BLOB *blob, time_t timeout);
void gencache_iterate(void (*fn)(const char* key, const char *value, time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern);
int gencache_lock_entry( const char *key );
void gencache_unlock_entry( const char *key );

/* The following definitions come from lib/genrand.c  */

void set_rand_reseed_callback(void (*fn)(int *));
void set_need_random_reseed(void);
void generate_random_buffer( unsigned char *out, int len);
char *generate_random_str(size_t len);

/* The following definitions come from lib/hmacmd5.c  */

void hmac_md5_init_rfc2104(const unsigned char *key, int key_len, HMACMD5Context *ctx);
void hmac_md5_init_limK_to_64(const unsigned char* key, int key_len,
			HMACMD5Context *ctx);
void hmac_md5_update(const unsigned char *text, int text_len, HMACMD5Context *ctx);
void hmac_md5_final(unsigned char *digest, HMACMD5Context *ctx);
void hmac_md5( unsigned char key[16], const unsigned char *data, int data_len,
	       unsigned char *digest);

/* The following definitions come from lib/iconv.c  */

NTSTATUS smb_register_charset(struct charset_functions *funcs) ;
size_t smb_iconv(smb_iconv_t cd, 
		 const char **inbuf, size_t *inbytesleft,
		 char **outbuf, size_t *outbytesleft);
smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode);
int smb_iconv_close (smb_iconv_t cd);

/* The following definitions come from lib/interface.c  */

bool ismyaddr(const struct sockaddr_storage *ip);
bool ismyip_v4(struct in_addr ip);
bool is_local_net(const struct sockaddr_storage *from);
void setup_linklocal_scope_id(struct sockaddr_storage *pss);
bool is_local_net_v4(struct in_addr from);
int iface_count(void);
int iface_count_v4_nl(void);
const struct in_addr *first_ipv4_iface(void);
struct interface *get_interface(int n);
const struct sockaddr_storage *iface_n_sockaddr_storage(int n);
const struct in_addr *iface_n_ip_v4(int n);
const struct in_addr *iface_n_bcast_v4(int n);
const struct sockaddr_storage *iface_n_bcast(int n);
const struct sockaddr_storage *iface_ip(const struct sockaddr_storage *ip);
bool iface_local(const struct sockaddr_storage *ip);
void load_interfaces(void);
void gfree_interfaces(void);
bool interfaces_changed(void);

/* The following definitions come from lib/ldap_debug_handler.c  */

void init_ldap_debugging(void);

/* The following definitions come from lib/ldap_escape.c  */

char *escape_ldap_string_alloc(const char *s);
char *escape_rdn_val_string_alloc(const char *s);

/* The following definitions come from lib/md4.c  */

void mdfour(unsigned char *out, const unsigned char *in, int n);

/* The following definitions come from lib/md5.c  */

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *ctx);

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

/* The following definitions come from lib/popt_common.c  */


/* The following definitions come from lib/privileges.c  */

bool get_privileges_for_sids(SE_PRIV *privileges, DOM_SID *slist, int scount);
NTSTATUS privilege_enumerate_accounts(DOM_SID **sids, int *num_sids);
NTSTATUS privilege_enum_sids(const SE_PRIV *mask, TALLOC_CTX *mem_ctx,
			     DOM_SID **sids, int *num_sids);
bool grant_privilege(const DOM_SID *sid, const SE_PRIV *priv_mask);
bool grant_privilege_by_name(DOM_SID *sid, const char *name);
bool revoke_privilege(const DOM_SID *sid, const SE_PRIV *priv_mask);
bool revoke_all_privileges( DOM_SID *sid );
bool revoke_privilege_by_name(DOM_SID *sid, const char *name);
NTSTATUS privilege_create_account(const DOM_SID *sid );
NTSTATUS privilege_set_init(PRIVILEGE_SET *priv_set);
NTSTATUS privilege_set_init_by_ctx(TALLOC_CTX *mem_ctx, PRIVILEGE_SET *priv_set);
void privilege_set_free(PRIVILEGE_SET *priv_set);
NTSTATUS dup_luid_attr(TALLOC_CTX *mem_ctx, LUID_ATTR **new_la, LUID_ATTR *old_la, int count);
bool is_privileged_sid( const DOM_SID *sid );
bool grant_all_privileges( const DOM_SID *sid );

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
LUID_ATTR get_privilege_luid( SE_PRIV *mask );
const char *luid_to_privilege_name(const LUID *set);
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

/* The following definitions come from lib/secace.c  */

bool sec_ace_object(uint8 type);
void sec_ace_copy(SEC_ACE *ace_dest, SEC_ACE *ace_src);
void init_sec_ace(SEC_ACE *t, const DOM_SID *sid, enum security_ace_type type,
		  uint32 mask, uint8 flag);
NTSTATUS sec_ace_add_sid(TALLOC_CTX *ctx, SEC_ACE **pp_new, SEC_ACE *old, unsigned *num, DOM_SID *sid, uint32 mask);
NTSTATUS sec_ace_mod_sid(SEC_ACE *ace, size_t num, DOM_SID *sid, uint32 mask);
NTSTATUS sec_ace_del_sid(TALLOC_CTX *ctx, SEC_ACE **pp_new, SEC_ACE *old, uint32 *num, DOM_SID *sid);
bool sec_ace_equal(SEC_ACE *s1, SEC_ACE *s2);
int nt_ace_inherit_comp( SEC_ACE *a1, SEC_ACE *a2);
int nt_ace_canon_comp( SEC_ACE *a1, SEC_ACE *a2);
void dacl_sort_into_canonical_order(SEC_ACE *srclist, unsigned int num_aces);
bool token_sid_in_ace(const NT_USER_TOKEN *token, const SEC_ACE *ace);

/* The following definitions come from lib/secacl.c  */

SEC_ACL *make_sec_acl(TALLOC_CTX *ctx, enum security_acl_revision revision,
		      int num_aces, SEC_ACE *ace_list);
SEC_ACL *dup_sec_acl(TALLOC_CTX *ctx, SEC_ACL *src);
bool sec_acl_equal(SEC_ACL *s1, SEC_ACL *s2);

/* The following definitions come from lib/secdesc.c  */

bool sec_desc_equal(SEC_DESC *s1, SEC_DESC *s2);
SEC_DESC_BUF *sec_desc_merge(TALLOC_CTX *ctx, SEC_DESC_BUF *new_sdb, SEC_DESC_BUF *old_sdb);
SEC_DESC *make_sec_desc(TALLOC_CTX *ctx,
			enum security_descriptor_revision revision,
			uint16 type,
			const DOM_SID *owner_sid, const DOM_SID *grp_sid,
			SEC_ACL *sacl, SEC_ACL *dacl, size_t *sd_size);
SEC_DESC *dup_sec_desc(TALLOC_CTX *ctx, const SEC_DESC *src);
NTSTATUS marshall_sec_desc(TALLOC_CTX *mem_ctx,
			   struct security_descriptor *secdesc,
			   uint8 **data, size_t *len);
NTSTATUS unmarshall_sec_desc(TALLOC_CTX *mem_ctx, uint8 *data, size_t len,
			     struct security_descriptor **psecdesc);
SEC_DESC *make_standard_sec_desc(TALLOC_CTX *ctx, const DOM_SID *owner_sid, const DOM_SID *grp_sid,
				 SEC_ACL *dacl, size_t *sd_size);
SEC_DESC_BUF *make_sec_desc_buf(TALLOC_CTX *ctx, size_t len, SEC_DESC *sec_desc);
SEC_DESC_BUF *dup_sec_desc_buf(TALLOC_CTX *ctx, SEC_DESC_BUF *src);
NTSTATUS sec_desc_add_sid(TALLOC_CTX *ctx, SEC_DESC **psd, DOM_SID *sid, uint32 mask, size_t *sd_size);
NTSTATUS sec_desc_mod_sid(SEC_DESC *sd, DOM_SID *sid, uint32 mask);
NTSTATUS sec_desc_del_sid(TALLOC_CTX *ctx, SEC_DESC **psd, DOM_SID *sid, size_t *sd_size);
NTSTATUS se_create_child_secdesc(TALLOC_CTX *ctx,
                                        SEC_DESC **ppsd,
					size_t *psize,
                                        const SEC_DESC *parent_ctr,
                                        const DOM_SID *owner_sid,
                                        const DOM_SID *group_sid,
                                        bool container);
NTSTATUS se_create_child_secdesc_buf(TALLOC_CTX *ctx,
					SEC_DESC_BUF **ppsdb,
					const SEC_DESC *parent_ctr,
					bool container);

/* The following definitions come from lib/select.c  */

void sys_select_signal(char c);
int sys_select(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval);
int sys_select_intr(int maxfd, fd_set *readfds, fd_set *writefds, fd_set *errorfds, struct timeval *tval);

/* The following definitions come from lib/sendfile.c  */

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);

/* The following definitions come from lib/server_mutex.c  */

struct named_mutex *grab_named_mutex(TALLOC_CTX *mem_ctx, const char *name,
				     int timeout);

/* The following definitions come from lib/sharesec.c  */

SEC_DESC *get_share_security_default( TALLOC_CTX *ctx, size_t *psize, uint32 def_access);
SEC_DESC *get_share_security( TALLOC_CTX *ctx, const char *servicename,
			      size_t *psize);
bool set_share_security(const char *share_name, SEC_DESC *psd);
bool delete_share_security(const char *servicename);
bool share_access_check(const NT_USER_TOKEN *token, const char *sharename,
			uint32 desired_access);
bool parse_usershare_acl(TALLOC_CTX *ctx, const char *acl_str, SEC_DESC **ppsd);

/* The following definitions come from lib/signal.c  */

void BlockSignals(bool block,int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);
void CatchChild(void);
void CatchChildLeaveStatus(void);

/* The following definitions come from lib/smbldap.c  */

int smb_ldap_start_tls(LDAP *ldap_struct, int version);
int smb_ldap_setup_conn(LDAP **ldap_struct, const char *uri);
int smb_ldap_upgrade_conn(LDAP *ldap_struct, int *new_version) ;
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
char *smbldap_get_dn(LDAP *ld, LDAPMessage *entry);
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
			   const char *full_name, const char *domain);
const char *get_current_username(void);
void standard_sub_basic(const char *smb_name, const char *domain_name,
			char *str, size_t len);
char *talloc_sub_basic(TALLOC_CTX *mem_ctx, const char *smb_name,
		       const char *domain_name, const char *str);
char *alloc_sub_basic(const char *smb_name, const char *domain_name,
		      const char *str);
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

/* The following definitions come from lib/sysquotas_4A.c  */

int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/sysquotas_linux.c  */

int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/sysquotas_xfs.c  */

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
int sys_stat(const char *fname,SMB_STRUCT_STAT *sbuf);
int sys_fstat(int fd,SMB_STRUCT_STAT *sbuf);
int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf);
int sys_ftruncate(int fd, SMB_OFF_T offset);
SMB_OFF_T sys_lseek(int fd, SMB_OFF_T offset, int whence);
int sys_fseek(FILE *fp, SMB_OFF_T offset, int whence);
SMB_OFF_T sys_ftell(FILE *fp);
int sys_creat(const char *path, mode_t mode);
int sys_open(const char *path, int oflag, mode_t mode);
FILE *sys_fopen(const char *path, const char *type);
void kernel_flock(int fd, uint32 share_mode);
SMB_STRUCT_DIR *sys_opendir(const char *name);
SMB_STRUCT_DIRENT *sys_readdir(SMB_STRUCT_DIR *dirp);
void sys_seekdir(SMB_STRUCT_DIR *dirp, long offset);
long sys_telldir(SMB_STRUCT_DIR *dirp);
void sys_rewinddir(SMB_STRUCT_DIR *dirp);
int sys_closedir(SMB_STRUCT_DIR *dirp);
int sys_mknod(const char *path, mode_t mode, SMB_DEV_T dev);
char *sys_realpath(const char *path, char *resolved_path);
int sys_waitpid(pid_t pid,int *status,int options);
char *sys_getwd(char *s);
int sys_symlink(const char *oldpath, const char *newpath);
int sys_readlink(const char *path, char *buf, size_t bufsiz);
int sys_link(const char *oldpath, const char *newpath);
int sys_chown(const char *fname,uid_t uid,gid_t gid);
int sys_lchown(const char *fname,uid_t uid,gid_t gid);
int sys_chroot(const char *dname);
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
pid_t sys_fork(void);
pid_t sys_getpid(void);
int sys_popen(const char *command);
int sys_pclose(int fd);
void *sys_dlopen(const char *name, int flags);
void *sys_dlsym(void *handle, const char *symbol);
int sys_dlclose (void *handle);
const char *sys_dlerror(void);
int sys_dup2(int oldfd, int newfd) ;
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

time_t get_time_t_max(void);
void GetTimeOfDay(struct timeval *tval);
time_t nt_time_to_unix(NTTIME nt);
void unix_to_nt_time(NTTIME *nt, time_t t);
bool null_time(time_t t);
bool null_nttime(NTTIME t);
bool null_timespec(struct timespec ts);
void push_dos_date(uint8_t *buf, int offset, time_t unixdate, int zone_offset);
void push_dos_date2(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
void push_dos_date3(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
time_t pull_dos_date(const uint8_t *date_ptr, int zone_offset);
time_t pull_dos_date2(const uint8_t *date_ptr, int zone_offset);
time_t pull_dos_date3(const uint8_t *date_ptr, int zone_offset);
char *http_timestring(time_t t);
char *timestring(TALLOC_CTX *mem_ctx, time_t t);
const char *nt_time_string(TALLOC_CTX *mem_ctx, NTTIME nt);
NTTIME nttime_from_string(const char *s);
int64_t usec_time_diff(struct timeval *tv1, struct timeval *tv2);
struct timeval timeval_zero(void);
bool timeval_is_zero(const struct timeval *tv);
struct timeval timeval_current(void);
struct timeval timeval_set(uint32_t secs, uint32_t usecs);
struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs);
struct timeval timeval_sum(const struct timeval *tv1,
			   const struct timeval *tv2);
struct timeval timeval_current_ofs(uint32_t secs, uint32_t usecs);
int timeval_compare(const struct timeval *tv1, const struct timeval *tv2);
bool timeval_expired(const struct timeval *tv);
double timeval_elapsed2(const struct timeval *tv1, const struct timeval *tv2);
double timeval_elapsed(const struct timeval *tv);
struct timeval timeval_min(const struct timeval *tv1,
			   const struct timeval *tv2);
struct timeval timeval_max(const struct timeval *tv1,
			   const struct timeval *tv2);
struct timeval timeval_until(const struct timeval *tv1,
			     const struct timeval *tv2);
NTTIME timeval_to_nttime(const struct timeval *tv);
uint32 convert_time_t_to_uint32(time_t t);
time_t convert_uint32_to_time_t(uint32 u);
int get_time_zone(time_t t);
bool nt_time_is_zero(const NTTIME *nt);
time_t generalized_to_unix_time(const char *str);
int get_server_zone_offset(void);
int set_server_zone_offset(time_t t);
char *current_timestring(TALLOC_CTX *ctx, bool hires);
void srv_put_dos_date(char *buf,int offset,time_t unixdate);
void srv_put_dos_date2(char *buf,int offset, time_t unixdate);
void srv_put_dos_date3(char *buf,int offset,time_t unixdate);
void put_long_date_timespec(char *p, struct timespec ts);
void put_long_date(char *p, time_t t);
struct timespec get_create_timespec(const SMB_STRUCT_STAT *st,bool fake_dirs);
struct timespec get_atimespec(const SMB_STRUCT_STAT *pst);
void set_atimespec(SMB_STRUCT_STAT *pst, struct timespec ts);
struct timespec get_mtimespec(const SMB_STRUCT_STAT *pst);
void set_mtimespec(SMB_STRUCT_STAT *pst, struct timespec ts);
struct timespec get_ctimespec(const SMB_STRUCT_STAT *pst);
void set_ctimespec(SMB_STRUCT_STAT *pst, struct timespec ts);
void dos_filetime_timespec(struct timespec *tsp);
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
struct timespec interpret_long_date(const char *p);
void cli_put_dos_date(struct cli_state *cli, char *buf, int offset, time_t unixdate);
void cli_put_dos_date2(struct cli_state *cli, char *buf, int offset, time_t unixdate);
void cli_put_dos_date3(struct cli_state *cli, char *buf, int offset, time_t unixdate);
time_t cli_make_unix_date(struct cli_state *cli, const void *date_ptr);
time_t cli_make_unix_date2(struct cli_state *cli, const void *date_ptr);
time_t cli_make_unix_date3(struct cli_state *cli, const void *date_ptr);
struct timespec nt_time_to_unix_timespec(NTTIME *nt);
bool nt_time_equals(const NTTIME *nt1, const NTTIME *nt2);
void TimeInit(void);
void get_process_uptime(struct timeval *ret_time);
time_t nt_time_to_unix_abs(const NTTIME *nt);
time_t uint64s_nt_time_to_unix_abs(const uint64_t *src);
void unix_timespec_to_nt_time(NTTIME *nt, struct timespec ts);
void unix_to_nt_time_abs(NTTIME *nt, time_t t);
bool null_mtime(time_t mtime);
const char *time_to_asc(const time_t t);
const char *display_time(NTTIME nttime);
bool nt_time_is_set(const NTTIME *nt);

/* The following definitions come from lib/ufc.c  */

char *ufc_crypt(const char *key,const char *salt);

/* The following definitions come from lib/username.c  */

char *get_user_home_dir(TALLOC_CTX *mem_ctx, const char *user);
struct passwd *Get_Pwnam_alloc(TALLOC_CTX *mem_ctx, const char *user);

/* The following definitions come from lib/util.c  */

bool set_global_myname(const char *myname);
const char *global_myname(void);
bool set_global_myworkgroup(const char *myworkgroup);
const char *lp_workgroup(void);
bool set_global_scope(const char *scope);
const char *global_scope(void);
void gfree_names(void);
void gfree_all( void );
const char *my_netbios_names(int i);
bool set_netbios_aliases(const char **str_array);
bool init_names(void);
const char *get_cmdline_auth_info_username(void);
void set_cmdline_auth_info_username(const char *username);
const char *get_cmdline_auth_info_password(void);
void set_cmdline_auth_info_password(const char *password);
bool set_cmdline_auth_info_signing_state(const char *arg);
int get_cmdline_auth_info_signing_state(void);
void set_cmdline_auth_info_use_kerberos(bool b);
bool get_cmdline_auth_info_use_kerberos(void);
void set_cmdline_auth_info_use_krb5_ticket(void);
void set_cmdline_auth_info_smb_encrypt(void);
void set_cmdline_auth_info_use_machine_account(void);
bool get_cmdline_auth_info_got_pass(void);
bool get_cmdline_auth_info_smb_encrypt(void);
bool get_cmdline_auth_info_use_machine_account(void);
bool get_cmdline_auth_info_copy(struct user_auth_info *info);
bool set_cmdline_auth_info_machine_account_creds(void);
const char *tmpdir(void);
bool add_gid_to_array_unique(TALLOC_CTX *mem_ctx, gid_t gid,
			     gid_t **gids, size_t *num_gids);
const char *get_numlist(const char *p, uint32 **num, int *count);
bool file_exist(const char *fname,SMB_STRUCT_STAT *sbuf);
bool socket_exist(const char *fname);
time_t file_modtime(const char *fname);
bool directory_exist(char *dname,SMB_STRUCT_STAT *st);
SMB_OFF_T get_file_size(char *file_name);
char *attrib_string(uint16 mode);
void show_msg(char *buf);
void smb_set_enclen(char *buf,int len,uint16 enc_ctx_num);
void smb_setlen(char *buf,int len);
int set_message_bcc(char *buf,int num_bytes);
ssize_t message_push_blob(uint8 **outbuf, DATA_BLOB blob);
char *unix_clean_name(TALLOC_CTX *ctx, const char *s);
char *clean_name(TALLOC_CTX *ctx, const char *s);
void close_low_fds(bool stderr_too);
ssize_t write_data_at_offset(int fd, const char *buffer, size_t N, SMB_OFF_T pos);
int set_blocking(int fd, bool set);
void smb_msleep(unsigned int t);
void become_daemon(bool Fork, bool no_process_group);
bool reinit_after_fork(struct messaging_context *msg_ctx,
		       struct event_context *ev_ctx,
		       bool parent_longlived);
bool yesno(const char *p);
void *malloc_(size_t size);
void *malloc_array(size_t el_size, unsigned int count);
void *memalign_array(size_t el_size, size_t align, unsigned int count);
void *calloc_array(size_t size, size_t nmemb);
void *Realloc(void *p, size_t size, bool free_old_on_error);
void *realloc_array(void *p, size_t el_size, unsigned int count, bool free_old_on_error);
void add_to_large_array(TALLOC_CTX *mem_ctx, size_t element_size,
			void *element, void *_array, uint32 *num_elements,
			ssize_t *array_size);
void safe_free(void *p);
char *get_myname(TALLOC_CTX *ctx);
char *get_mydnsdomname(TALLOC_CTX *ctx);
int interpret_protocol(const char *str,int def);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
bool process_exists(const struct server_id pid);
bool process_exists_by_pid(pid_t pid);
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
void print_asc(int level, const unsigned char *buf,int len);
void dump_data(int level, const unsigned char *buf1,int len);
void dump_data_pw(const char *msg, const uchar * data, size_t len);
const char *tab_depth(int level, int depth);
int str_checksum(const char *s);
void zero_free(void *p, size_t size);
int set_maxfiles(int requested_max);
int smb_mkstemp(char *name_template);
void *smb_xmalloc_array(size_t size, unsigned int count);
void *smb_xmemdup(const void *p, size_t size);
char *smb_xstrdup(const char *s);
char *smb_xstrndup(const char *s, size_t n);
void *memdup(const void *p, size_t size);
char *myhostname(void);
char *lock_path(const char *name);
char *pid_path(const char *name);
char *lib_path(const char *name);
char *modules_path(const char *name);
char *data_path(const char *name);
char *state_path(const char *name);
const char *shlib_ext(void);
char *parent_dirname(const char *path);
bool parent_dirname_talloc(TALLOC_CTX *mem_ctx, const char *dir,
			   char **parent, const char **name);
bool ms_has_wild(const char *s);
bool ms_has_wild_w(const smb_ucs2_t *s);
bool mask_match(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_search(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive);
bool unix_wild_match(const char *pattern, const char *string);
bool name_to_fqdn(fstring fqdn, const char *name);
void *talloc_check_name_abort(const void *ptr, const char *name);
uint32 map_share_mode_to_deny_mode(uint32 share_access, uint32 private_options);
pid_t procid_to_pid(const struct server_id *proc);
void set_my_vnn(uint32 vnn);
uint32 get_my_vnn(void);
struct server_id pid_to_procid(pid_t pid);
struct server_id procid_self(void);
struct server_id server_id_self(void);
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
NTSTATUS split_ntfs_stream_name(TALLOC_CTX *mem_ctx, const char *fname,
				char **pbase, char **pstream);
bool is_valid_policy_hnd(const POLICY_HND *hnd);
bool policy_hnd_equal(const struct policy_handle *hnd1,
		      const struct policy_handle *hnd2);
const char *strip_hostname(const char *s);

/* The following definitions come from lib/util_file.c  */

char *fgets_slash(char *s2,int maxlen,XFILE *f);
char *fd_load(int fd, size_t *psize, size_t maxsize);
char *file_load(const char *fname, size_t *size, size_t maxsize);
bool unmap_file(void* start, size_t size);
void *map_file(char *fname, size_t size);
char **file_lines_load(const char *fname, int *numlines, size_t maxsize);
char **fd_lines_load(int fd, int *numlines, size_t maxsize);
char **file_lines_pload(const char *syscmd, int *numlines);
void file_lines_free(char **lines);
void file_lines_slashcont(char **lines);
bool file_save(const char *fname, void *packet, size_t length);

/* The following definitions come from lib/util_nscd.c  */

void smb_nscd_flush_user_cache(void);
void smb_nscd_flush_group_cache(void);

/* The following definitions come from lib/util_nttoken.c  */

NT_USER_TOKEN *dup_nt_token(TALLOC_CTX *mem_ctx, const NT_USER_TOKEN *ptoken);
NTSTATUS merge_nt_token(TALLOC_CTX *mem_ctx,
			const struct nt_user_token *token_1,
			const struct nt_user_token *token_2,
			struct nt_user_token **token_out);

/* The following definitions come from lib/util_pw.c  */

struct passwd *tcopy_passwd(TALLOC_CTX *mem_ctx, const struct passwd *from) ;
void flush_pwnam_cache(void);
struct passwd *getpwnam_alloc(TALLOC_CTX *mem_ctx, const char *name);
struct passwd *getpwuid_alloc(TALLOC_CTX *mem_ctx, uid_t uid) ;

/* The following definitions come from lib/util_reg.c  */

const char *reg_type_lookup(enum winreg_Type type);
WERROR reg_pull_multi_sz(TALLOC_CTX *mem_ctx, const void *buf, size_t len,
			 uint32 *num_values, char ***values);

/* The following definitions come from lib/util_reg_api.c  */

WERROR registry_pull_value(TALLOC_CTX *mem_ctx,
			   struct registry_value **pvalue,
			   enum winreg_Type type, uint8 *data,
			   uint32 size, uint32 length);
WERROR registry_push_value(TALLOC_CTX *mem_ctx,
			   const struct registry_value *value,
			   DATA_BLOB *presult);

/* The following definitions come from lib/util_seaccess.c  */

void se_map_generic(uint32 *access_mask, const struct generic_mapping *mapping);
void security_acl_map_generic(struct security_acl *sa, const struct generic_mapping *mapping);
void se_map_standard(uint32 *access_mask, struct standard_mapping *mapping);
NTSTATUS se_access_check(const SEC_DESC *sd, const NT_USER_TOKEN *token,
		     uint32 acc_desired, uint32 *acc_granted);
NTSTATUS samr_make_sam_obj_sd(TALLOC_CTX *ctx, SEC_DESC **psd, size_t *sd_size);

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
const char *get_global_sam_name(void) ;
char *sid_to_fstring(fstring sidstr_out, const DOM_SID *sid);
char *sid_string_talloc(TALLOC_CTX *mem_ctx, const DOM_SID *sid);
char *sid_string_dbg(const DOM_SID *sid);
char *sid_string_tos(const DOM_SID *sid);
bool string_to_sid(DOM_SID *sidout, const char *sidstr);
DOM_SID *string_sid_talloc(TALLOC_CTX *mem_ctx, const char *sidstr);
bool sid_append_rid(DOM_SID *sid, uint32 rid);
bool sid_compose(DOM_SID *dst, const DOM_SID *domain_sid, uint32 rid);
bool sid_split_rid(DOM_SID *sid, uint32 *rid);
bool sid_peek_rid(const DOM_SID *sid, uint32 *rid);
bool sid_peek_check_rid(const DOM_SID *exp_dom_sid, const DOM_SID *sid, uint32 *rid);
void sid_copy(DOM_SID *dst, const DOM_SID *src);
bool sid_linearize(char *outbuf, size_t len, const DOM_SID *sid);
bool sid_parse(const char *inbuf, size_t len, DOM_SID *sid);
int sid_compare(const DOM_SID *sid1, const DOM_SID *sid2);
int sid_compare_domain(const DOM_SID *sid1, const DOM_SID *sid2);
bool sid_equal(const DOM_SID *sid1, const DOM_SID *sid2);
bool non_mappable_sid(DOM_SID *sid);
char *sid_binstring(const DOM_SID *sid);
char *sid_binstring_hex(const DOM_SID *sid);
DOM_SID *sid_dup_talloc(TALLOC_CTX *ctx, const DOM_SID *src);
NTSTATUS add_sid_to_array(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			  DOM_SID **sids, size_t *num);
NTSTATUS add_sid_to_array_unique(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
				 DOM_SID **sids, size_t *num_sids);
void del_sid_from_array(const DOM_SID *sid, DOM_SID **sids, size_t *num);
bool add_rid_to_array_unique(TALLOC_CTX *mem_ctx,
				    uint32 rid, uint32 **pp_rids, size_t *p_num);
bool is_null_sid(const DOM_SID *sid);
bool is_sid_in_token(const NT_USER_TOKEN *token, const DOM_SID *sid);
NTSTATUS sid_array_from_info3(TALLOC_CTX *mem_ctx,
			      const struct netr_SamInfo3 *info3,
			      DOM_SID **user_sids,
			      size_t *num_user_sids,
			      bool include_user_group_rid,
			      bool skip_ressource_groups);

/* The following definitions come from lib/util_sock.c  */

bool is_ipaddress_v4(const char *str);
bool is_ipaddress(const char *str);
bool is_broadcast_addr(const struct sockaddr_storage *pss);
uint32 interpret_addr(const char *str);
struct in_addr *interpret_addr2(struct in_addr *ip, const char *str);
bool interpret_string_addr(struct sockaddr_storage *pss,
		const char *str,
		int flags);
bool is_loopback_ip_v4(struct in_addr ip);
bool is_loopback_addr(const struct sockaddr_storage *pss);
bool is_zero_ip_v4(struct in_addr ip);
bool is_zero_addr(const struct sockaddr_storage *pss);
void zero_ip_v4(struct in_addr *ip);
void zero_sockaddr(struct sockaddr_storage *pss);
bool same_net_v4(struct in_addr ip1,struct in_addr ip2,struct in_addr mask);
void in_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
		struct in_addr ip);
bool same_net(const struct sockaddr_storage *ip1,
		const struct sockaddr_storage *ip2,
		const struct sockaddr_storage *mask);
bool sockaddr_equal(const struct sockaddr_storage *ip1,
		const struct sockaddr_storage *ip2);
bool is_address_any(const struct sockaddr_storage *psa);
uint16_t get_sockaddr_port(const struct sockaddr_storage *pss);
char *print_sockaddr(char *dest,
			size_t destlen,
			const struct sockaddr_storage *psa);
char *print_canonical_sockaddr(TALLOC_CTX *ctx,
			const struct sockaddr_storage *pss);
void set_sockaddr_port(struct sockaddr_storage *psa, uint16 port);
const char *client_name(int fd);
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
NTSTATUS read_socket_with_timeout(int fd, char *buf,
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
int open_socket_out(int type,
		const struct sockaddr_storage *pss,
		uint16_t port,
		int timeout);
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
bool strequal(const char *s1, const char *s2);
bool strnequal(const char *s1,const char *s2,size_t n);
bool strcsequal(const char *s1,const char *s2);
int strwicmp(const char *psz1, const char *psz2);
void strnorm(char *s, int case_default);
bool strisnormal(const char *s, int case_default);
void string_replace( char *s, char oldc, char newc );
char *push_skip_string(char *buf);
char *skip_string(const char *base, size_t len, char *buf);
size_t str_charnum(const char *s);
size_t str_ascii_charnum(const char *s);
bool trim_char(char *s,char cfront,char cback);
bool trim_string(char *s,const char *front,const char *back);
bool strhasupper(const char *s);
bool strhaslower(const char *s);
size_t count_chars(const char *s,char c);
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
size_t strhex_to_str(char *buf, size_t buf_len, const char *strhex, size_t strhex_len);
DATA_BLOB strhex_to_data_blob(TALLOC_CTX *mem_ctx, const char *strhex);
char *hex_encode(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);
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
char *binary_string_rfc2254(char *buf, int len);
char *binary_string(char *buf, int len);
int fstr_sprintf(fstring s, const char *fmt, ...);
char **str_list_make(TALLOC_CTX *mem_ctx, const char *string, const char *sep);
bool str_list_copy(TALLOC_CTX *mem_ctx, char ***dest, const char **src);
bool str_list_compare(char **list1, char **list2);
int str_list_count( const char **list );
bool str_list_sub_basic( char **list, const char *smb_name,
			 const char *domain_name );
bool str_list_substitute(char **list, const char *pattern, const char *insert);
char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count);
int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list);
void ipstr_list_free(char* ipstr_list);
void rfc1738_unescape(char *buf);
DATA_BLOB base64_decode_data_blob(const char *s);
void base64_decode_inplace(char *s);
char *base64_encode_data_blob(TALLOC_CTX *mem_ctx, DATA_BLOB data);
SMB_BIG_UINT STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr);
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
size_t ascii_len_n(const char *src, size_t n);
size_t utf16_len(const void *buf);
size_t utf16_len_n(const void *src, size_t n);
char *escape_shell_string(const char *src);

/* The following definitions come from lib/util_unistr.c  */

void gfree_case_tables(void);
void load_case_tables(void);
void init_valid_table(void);
size_t dos_PutUniCode(char *dst,const char *src, size_t len, bool null_terminate);
char *skip_unibuf(char *src, size_t len);
int rpcstr_pull(char* dest, void *src, int dest_len, int src_len, int flags);
int rpcstr_pull_talloc(TALLOC_CTX *ctx,
			char **dest,
			void *src,
			int src_len,
			int flags);
int rpcstr_pull_unistr2_fstring(char *dest, UNISTR2 *src);
char *rpcstr_pull_unistr2_talloc(TALLOC_CTX *ctx, const UNISTR2 *src);
int rpcstr_push(void *dest, const char *src, size_t dest_len, int flags);
int rpcstr_push_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src);
void unistr2_to_ascii(char *dest, const UNISTR2 *str, size_t maxlen);
void unistr3_to_ascii(char *dest, const UNISTR3 *str, size_t maxlen);
char *unistr2_to_ascii_talloc(TALLOC_CTX *ctx, const UNISTR2 *str);
const char *unistr2_static(const UNISTR2 *str);
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
int unistrlen(uint16 *s);
int unistrcpy(uint16 *dst, uint16 *src);
UNISTR2* ucs2_to_unistr2(TALLOC_CTX *ctx, UNISTR2* dst, smb_ucs2_t* src);
int toupper_ascii(int c);
int tolower_ascii(int c);
int isupper_ascii(int c);
int islower_ascii(int c);

/* The following definitions come from lib/util_uuid.c  */

void smb_uuid_pack(const struct GUID uu, UUID_FLAT *ptr);
void smb_uuid_unpack(const UUID_FLAT in, struct GUID *uu);
void smb_uuid_generate_random(struct GUID *uu);
const char *smb_uuid_string(TALLOC_CTX *mem_ctx, const struct GUID uu);
bool smb_string_to_uuid(const char *in, struct GUID* uu);
char *guid_binstring(const struct GUID *guid);

/* The following definitions come from lib/version.c  */

const char *samba_version_string(void);

/* The following definitions come from lib/winbind_util.c  */

bool winbind_lookup_name(const char *dom_name, const char *name, DOM_SID *sid, 
                         enum lsa_SidType *name_type);
bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const DOM_SID *sid, 
			const char **domain, const char **name,
                        enum lsa_SidType *name_type);
bool winbind_ping(void);
bool winbind_sid_to_uid(uid_t *puid, const DOM_SID *sid);
bool winbind_uid_to_sid(DOM_SID *sid, uid_t uid);
bool winbind_sid_to_gid(gid_t *pgid, const DOM_SID *sid);
bool winbind_gid_to_sid(DOM_SID *sid, gid_t gid);
wbcErr wb_is_trusted_domain(const char *domain);
bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const DOM_SID *domain_sid,
			 int num_rids, uint32 *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types);
bool winbind_allocate_uid(uid_t *uid);
bool winbind_allocate_gid(gid_t *gid);
bool winbind_lookup_name(const char *dom_name, const char *name, DOM_SID *sid, 
                         enum lsa_SidType *name_type);
bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const DOM_SID *sid, 
			const char **domain, const char **name,
                        enum lsa_SidType *name_type);
bool winbind_ping(void);
bool winbind_sid_to_uid(uid_t *puid, const DOM_SID *sid);
bool winbind_uid_to_sid(DOM_SID *sid, uid_t uid);
bool winbind_sid_to_gid(gid_t *pgid, const DOM_SID *sid);
bool winbind_gid_to_sid(DOM_SID *sid, gid_t gid);
wbcErr wb_is_trusted_domain(const char *domain);
bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const DOM_SID *domain_sid,
			 int num_rids, uint32 *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types);
bool winbind_allocate_uid(uid_t *uid);
bool winbind_allocate_gid(gid_t *gid);

/* The following definitions come from lib/wins_srv.c  */

bool wins_srv_is_dead(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_alive(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_died(struct in_addr wins_ip, struct in_addr src_ip);
unsigned wins_srv_count(void);
char **wins_srv_tags(void);
void wins_srv_tags_free(char **list);
struct in_addr wins_srv_ip_tag(const char *tag, struct in_addr src_ip);
unsigned wins_srv_count_tag(const char *tag);

/* The following definitions come from lib/xfile.c  */

int x_setvbuf(XFILE *f, char *buf, int mode, size_t size);
XFILE *x_fopen(const char *fname, int flags, mode_t mode);
XFILE *x_fdup(const XFILE *f);
int x_fclose(XFILE *f);
size_t x_fwrite(const void *p, size_t size, size_t nmemb, XFILE *f);
int x_fileno(const XFILE *f);
int x_fflush(XFILE *f);
void x_setbuffer(XFILE *f, char *buf, size_t size);
void x_setbuf(XFILE *f, char *buf);
void x_setlinebuf(XFILE *f);
int x_feof(XFILE *f);
int x_ferror(XFILE *f);
int x_fgetc(XFILE *f);
size_t x_fread(void *p, size_t size, size_t nmemb, XFILE *f);
char *x_fgets(char *s, int size, XFILE *stream) ;
off_t x_tseek(XFILE *f, off_t offset, int whence);

/* The following definitions come from libads/ads_status.c  */

ADS_STATUS ads_build_error(enum ads_error_type etype, 
			   int rc, int minor_status);
ADS_STATUS ads_build_nt_error(enum ads_error_type etype, 
			   NTSTATUS nt_status);
NTSTATUS ads_ntstatus(ADS_STATUS status);
const char *ads_errstr(ADS_STATUS status);
NTSTATUS gss_err_to_ntstatus(uint32 maj, uint32 min);

/* The following definitions come from libads/ads_struct.c  */

char *ads_build_path(const char *realm, const char *sep, const char *field, int reverse);
char *ads_build_dn(const char *realm);
char *ads_build_domain(const char *dn);
ADS_STRUCT *ads_init(const char *realm, 
		     const char *workgroup,
		     const char *ldap_server);
void ads_destroy(ADS_STRUCT **ads);

/* The following definitions come from libads/ads_utils.c  */

uint32 ads_acb2uf(uint32 acb);
uint32 ads_uf2acb(uint32 uf);
uint32 ads_uf2atype(uint32 uf);
uint32 ads_gtype2atype(uint32 gtype);
enum lsa_SidType ads_atype_map(uint32 atype);

/* The following definitions come from libads/authdata.c  */

struct PAC_LOGON_INFO *get_logon_info_from_pac(struct PAC_DATA *pac_data);
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
			     struct PAC_DATA **pac_ret);
NTSTATUS kerberos_return_info3_from_pac(TALLOC_CTX *mem_ctx,
					const char *name,
					const char *pass,
					time_t time_offset,
					time_t *expire_time,
					time_t *renew_till_time,
					const char *cache_name,
					bool request_pac,
					bool add_netbios_addr,
					time_t renewable_time,
					struct netr_SamInfo3 **info3);

/* The following definitions come from libads/cldap.c  */
bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			const char *server,
			const char *realm,
			uint32_t nt_version,
			struct netlogon_samlogon_response **reply);
bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  const char *server,
			  const char *realm,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5);

/* The following definitions come from libads/disp_sec.c  */

void ads_disp_sd(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, SEC_DESC *sd);

/* The following definitions come from libads/dns.c  */

NTSTATUS ads_dns_lookup_ns(TALLOC_CTX *ctx,
				const char *dnsdomain,
				struct dns_rr_ns **nslist,
				int *numns);
bool sitename_store(const char *realm, const char *sitename);
char *sitename_fetch(const char *realm);
bool stored_sitename_changed(const char *realm, const char *sitename);
NTSTATUS ads_dns_query_dcs(TALLOC_CTX *ctx,
			   const char *realm,
			   const char *sitename,
			   struct dns_rr_srv **dclist,
			   int *numdcs );
NTSTATUS ads_dns_query_gcs(TALLOC_CTX *ctx,
			   const char *realm,
			   const char *sitename,
			   struct dns_rr_srv **dclist,
			   int *numdcs );
NTSTATUS ads_dns_query_kdcs(TALLOC_CTX *ctx,
			    const char *dns_forest_name,
			    const char *sitename,
			    struct dns_rr_srv **dclist,
			    int *numdcs );
NTSTATUS ads_dns_query_pdc(TALLOC_CTX *ctx,
			   const char *dns_domain_name,
			   struct dns_rr_srv **dclist,
			   int *numdcs );
NTSTATUS ads_dns_query_dcs_guid(TALLOC_CTX *ctx,
				const char *dns_forest_name,
				const struct GUID *domain_guid,
				struct dns_rr_srv **dclist,
				int *numdcs );

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
						struct sockaddr_storage *pss);

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
			   struct PAC_DATA **pac_data,
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
void ads_memfree(ADS_STRUCT *ads, void *mem);
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
ADS_STATUS ads_domain_sid(ADS_STRUCT *ads, DOM_SID *sid);
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
					DOM_SID *sid);
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

/* The following definitions come from libads/ldap_schema.c  */

ADS_STATUS ads_get_attrnames_by_oids(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
				     const char *schema_path,
				     const char **OIDs, size_t num_OIDs, 
				     char ***OIDs_out, char ***names, size_t *count);
const char *ads_get_attrname_by_guid(ADS_STRUCT *ads, 
				     const char *schema_path, 
				     TALLOC_CTX *mem_ctx, 
				     const struct GUID *schema_guid);
const char *ads_get_attrname_by_oid(ADS_STRUCT *ads, const char *schema_path, TALLOC_CTX *mem_ctx, const char * OID);
ADS_STATUS ads_schema_path(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, char **schema_path);
ADS_STATUS ads_check_posix_schema_mapping(TALLOC_CTX *mem_ctx,
					  ADS_STRUCT *ads,
					  enum wb_posix_mapping map_type,
					  struct posix_schema **s ) ;

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

/* The following definitions come from libcli/nbt/nbtname.c  */

_PUBLIC_ void ndr_print_nbt_string(struct ndr_print *ndr, const char *name, const char *s);
_PUBLIC_ enum ndr_err_code ndr_pull_nbt_string(struct ndr_pull *ndr, int ndr_flags, const char **s);
_PUBLIC_ enum ndr_err_code ndr_push_nbt_string(struct ndr_push *ndr, int ndr_flags, const char *s);
_PUBLIC_ enum ndr_err_code ndr_pull_nbt_name(struct ndr_pull *ndr, int ndr_flags, struct nbt_name *r);
_PUBLIC_ enum ndr_err_code ndr_push_nbt_name(struct ndr_push *ndr, int ndr_flags, const struct nbt_name *r);
_PUBLIC_ NTSTATUS nbt_name_dup(TALLOC_CTX *mem_ctx, struct nbt_name *name, struct nbt_name *newname);
_PUBLIC_ NTSTATUS nbt_name_to_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, struct nbt_name *name);
_PUBLIC_ NTSTATUS nbt_name_from_blob(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, struct nbt_name *name);
_PUBLIC_ void nbt_choose_called_name(TALLOC_CTX *mem_ctx,
			    struct nbt_name *n, const char *name, int type);
_PUBLIC_ char *nbt_name_string(TALLOC_CTX *mem_ctx, const struct nbt_name *name);
_PUBLIC_ enum ndr_err_code ndr_pull_wrepl_nbt_name(struct ndr_pull *ndr, int ndr_flags, const struct nbt_name **_r);
_PUBLIC_ enum ndr_err_code ndr_push_wrepl_nbt_name(struct ndr_push *ndr, int ndr_flags, const struct nbt_name *r);
_PUBLIC_ void ndr_print_wrepl_nbt_name(struct ndr_print *ndr, const char *name, const struct nbt_name *r);

/* The following definitions come from libgpo/gpext/gpext.c  */

struct gp_extension *get_gp_extension_list(void);
NTSTATUS unregister_gp_extension(const char *name);
NTSTATUS register_gp_extension(TALLOC_CTX *gpext_ctx,
			       int version,
			       const char *name,
			       const char *guid,
			       struct gp_extension_methods *methods);
NTSTATUS gp_ext_info_add_entry(TALLOC_CTX *mem_ctx,
			       const char *module,
			       const char *ext_guid,
			       struct gp_extension_reg_table *table,
			       struct gp_extension_reg_info *info);
NTSTATUS shutdown_gp_extensions(void);
NTSTATUS init_gp_extensions(TALLOC_CTX *mem_ctx);
NTSTATUS free_gp_extensions(void);
void debug_gpext_header(int lvl,
			const char *name,
			uint32_t flags,
			struct GROUP_POLICY_OBJECT *gpo,
			const char *extension_guid,
			const char *snapin_guid);
NTSTATUS process_gpo_list_with_extension(ADS_STRUCT *ads,
			   TALLOC_CTX *mem_ctx,
			   uint32_t flags,
			   const struct nt_user_token *token,
			   struct GROUP_POLICY_OBJECT *gpo_list,
			   const char *extension_guid,
			   const char *snapin_guid);
NTSTATUS gpext_process_extension(ADS_STRUCT *ads,
				 TALLOC_CTX *mem_ctx,
				 uint32_t flags,
				 const struct nt_user_token *token,
				 struct registry_key *root_key,
				 struct GROUP_POLICY_OBJECT *gpo,
				 const char *extension_guid,
				 const char *snapin_guid);

/* The following definitions come from libgpo/gpo_fetch.c  */

NTSTATUS gpo_explode_filesyspath(TALLOC_CTX *mem_ctx,
				 const char *file_sys_path,
				 char **server,
				 char **service,
				 char **nt_path,
				 char **unix_path);
NTSTATUS gpo_fetch_files(TALLOC_CTX *mem_ctx,
			 struct cli_state *cli,
			 struct GROUP_POLICY_OBJECT *gpo);
NTSTATUS gpo_get_sysvol_gpt_version(TALLOC_CTX *mem_ctx,
				    const char *unix_path,
				    uint32_t *sysvol_version,
				    char **display_name);

/* The following definitions come from libgpo/gpo_filesync.c  */

NTSTATUS gpo_copy_file(TALLOC_CTX *mem_ctx,
		       struct cli_state *cli,
		       const char *nt_path,
		       const char *unix_path);
NTSTATUS gpo_sync_directories(TALLOC_CTX *mem_ctx,
			      struct cli_state *cli,
			      const char *nt_path,
			      const char *local_path);

/* The following definitions come from libgpo/gpo_ini.c  */

NTSTATUS parse_gpt_ini(TALLOC_CTX *mem_ctx,
		       const char *filename,
		       uint32_t *version,
		       char **display_name);

/* The following definitions come from libgpo/gpo_ldap.c  */

bool ads_parse_gp_ext(TALLOC_CTX *mem_ctx,
		      const char *extension_raw,
		      struct GP_EXT **gp_ext);
ADS_STATUS ads_get_gpo_link(ADS_STRUCT *ads,
			    TALLOC_CTX *mem_ctx,
			    const char *link_dn,
			    struct GP_LINK *gp_link_struct);
ADS_STATUS ads_add_gpo_link(ADS_STRUCT *ads,
			    TALLOC_CTX *mem_ctx,
			    const char *link_dn,
			    const char *gpo_dn,
			    uint32_t gpo_opt);
ADS_STATUS ads_delete_gpo_link(ADS_STRUCT *ads,
			       TALLOC_CTX *mem_ctx,
			       const char *link_dn,
			       const char *gpo_dn);
ADS_STATUS ads_get_gpo(ADS_STRUCT *ads,
		       TALLOC_CTX *mem_ctx,
		       const char *gpo_dn,
		       const char *display_name,
		       const char *guid_name,
		       struct GROUP_POLICY_OBJECT *gpo);
ADS_STATUS ads_get_sid_token(ADS_STRUCT *ads,
			     TALLOC_CTX *mem_ctx,
			     const char *dn,
			     struct nt_user_token **token);
ADS_STATUS ads_get_gpo_list(ADS_STRUCT *ads,
			    TALLOC_CTX *mem_ctx,
			    const char *dn,
			    uint32_t flags,
			    const struct nt_user_token *token,
			    struct GROUP_POLICY_OBJECT **gpo_list);

/* The following definitions come from libgpo/gpo_reg.c  */

struct nt_user_token *registry_create_system_token(TALLOC_CTX *mem_ctx);
WERROR gp_init_reg_ctx(TALLOC_CTX *mem_ctx,
		       const char *initial_path,
		       uint32_t desired_access,
		       const struct nt_user_token *token,
		       struct gp_registry_context **reg_ctx);
void gp_free_reg_ctx(struct gp_registry_context *reg_ctx);
WERROR gp_store_reg_subkey(TALLOC_CTX *mem_ctx,
			   const char *subkeyname,
			   struct registry_key *curr_key,
			   struct registry_key **new_key);
WERROR gp_read_reg_subkey(TALLOC_CTX *mem_ctx,
			  struct gp_registry_context *reg_ctx,
			  const char *subkeyname,
			  struct registry_key **key);
WERROR gp_store_reg_val_sz(TALLOC_CTX *mem_ctx,
			   struct registry_key *key,
			   const char *val_name,
			   const char *val);
WERROR gp_read_reg_val_sz(TALLOC_CTX *mem_ctx,
			  struct registry_key *key,
			  const char *val_name,
			  const char **val);
WERROR gp_reg_state_store(TALLOC_CTX *mem_ctx,
			  uint32_t flags,
			  const char *dn,
			  const struct nt_user_token *token,
			  struct GROUP_POLICY_OBJECT *gpo_list);
WERROR gp_reg_state_read(TALLOC_CTX *mem_ctx,
			 uint32_t flags,
			 const DOM_SID *sid,
			 struct GROUP_POLICY_OBJECT **gpo_list);
WERROR gp_secure_key(TALLOC_CTX *mem_ctx,
		     uint32_t flags,
		     struct registry_key *key,
		     const DOM_SID *sid);
void dump_reg_val(int lvl, const char *direction,
		  const char *key, const char *subkey,
		  struct registry_value *val);
void dump_reg_entry(uint32_t flags,
		    const char *dir,
		    struct gp_registry_entry *entry);
void dump_reg_entries(uint32_t flags,
		      const char *dir,
		      struct gp_registry_entry *entries,
		      size_t num_entries);
bool add_gp_registry_entry_to_array(TALLOC_CTX *mem_ctx,
				    struct gp_registry_entry *entry,
				    struct gp_registry_entry **entries,
				    size_t *num);
WERROR reg_apply_registry_entry(TALLOC_CTX *mem_ctx,
				struct registry_key *root_key,
				struct gp_registry_context *reg_ctx,
				struct gp_registry_entry *entry,
				const struct nt_user_token *token,
				uint32_t flags);

/* The following definitions come from libgpo/gpo_sec.c  */

NTSTATUS gpo_apply_security_filtering(const struct GROUP_POLICY_OBJECT *gpo,
				      const struct nt_user_token *token);

/* The following definitions come from libgpo/gpo_util.c  */

const char *cse_gpo_guid_string_to_name(const char *guid);
const char *cse_gpo_name_to_guid_string(const char *name);
const char *cse_snapin_gpo_guid_string_to_name(const char *guid);
void dump_gp_ext(struct GP_EXT *gp_ext, int debuglevel);
void dump_gpo(ADS_STRUCT *ads,
	      TALLOC_CTX *mem_ctx,
	      struct GROUP_POLICY_OBJECT *gpo,
	      int debuglevel);
void dump_gpo_list(ADS_STRUCT *ads,
		   TALLOC_CTX *mem_ctx,
		   struct GROUP_POLICY_OBJECT *gpo_list,
		   int debuglevel);
void dump_gplink(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, struct GP_LINK *gp_link);
ADS_STATUS gpo_process_a_gpo(ADS_STRUCT *ads,
			     TALLOC_CTX *mem_ctx,
			     const struct nt_user_token *token,
			     struct registry_key *root_key,
			     struct GROUP_POLICY_OBJECT *gpo,
			     const char *extension_guid_filter,
			     uint32_t flags);
ADS_STATUS gpo_process_gpo_list(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				const struct nt_user_token *token,
				struct GROUP_POLICY_OBJECT *gpo_list,
				const char *extensions_guid_filter,
				uint32_t flags);
NTSTATUS check_refresh_gpo(ADS_STRUCT *ads,
			   TALLOC_CTX *mem_ctx,
			   uint32_t flags,
			   struct GROUP_POLICY_OBJECT *gpo,
			   struct cli_state **cli_out);
NTSTATUS check_refresh_gpo_list(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				uint32_t flags,
				struct GROUP_POLICY_OBJECT *gpo_list);
NTSTATUS gpo_get_unix_path(TALLOC_CTX *mem_ctx,
			   struct GROUP_POLICY_OBJECT *gpo,
			   char **unix_path);
char *gpo_flag_str(uint32_t flags);
NTSTATUS gp_find_file(TALLOC_CTX *mem_ctx,
		      uint32_t flags,
		      const char *filename,
		      const char *suffix,
		      const char **filename_out);
ADS_STATUS gp_get_machine_token(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				const char *dn,
				struct nt_user_token **token);

/* The following definitions come from librpc/gen_ndr/ndr_dfs.c  */

_PUBLIC_ void ndr_print_dfs_ManagerVersion(struct ndr_print *ndr, const char *name, enum dfs_ManagerVersion r);
_PUBLIC_ void ndr_print_dfs_Info0(struct ndr_print *ndr, const char *name, const struct dfs_Info0 *r);
_PUBLIC_ void ndr_print_dfs_Info1(struct ndr_print *ndr, const char *name, const struct dfs_Info1 *r);
_PUBLIC_ enum ndr_err_code ndr_push_dfs_VolumeState(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_dfs_VolumeState(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_dfs_VolumeState(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_dfs_Info2(struct ndr_print *ndr, const char *name, const struct dfs_Info2 *r);
_PUBLIC_ enum ndr_err_code ndr_push_dfs_StorageState(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_dfs_StorageState(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_dfs_StorageState(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_dfs_StorageInfo(struct ndr_print *ndr, const char *name, const struct dfs_StorageInfo *r);
_PUBLIC_ void ndr_print_dfs_Info3(struct ndr_print *ndr, const char *name, const struct dfs_Info3 *r);
_PUBLIC_ void ndr_print_dfs_Info4(struct ndr_print *ndr, const char *name, const struct dfs_Info4 *r);
_PUBLIC_ enum ndr_err_code ndr_push_dfs_PropertyFlags(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_dfs_PropertyFlags(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_dfs_PropertyFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_dfs_Info5(struct ndr_print *ndr, const char *name, const struct dfs_Info5 *r);
_PUBLIC_ void ndr_print_dfs_Target_PriorityClass(struct ndr_print *ndr, const char *name, enum dfs_Target_PriorityClass r);
_PUBLIC_ void ndr_print_dfs_Target_Priority(struct ndr_print *ndr, const char *name, const struct dfs_Target_Priority *r);
_PUBLIC_ void ndr_print_dfs_StorageInfo2(struct ndr_print *ndr, const char *name, const struct dfs_StorageInfo2 *r);
_PUBLIC_ void ndr_print_dfs_Info6(struct ndr_print *ndr, const char *name, const struct dfs_Info6 *r);
_PUBLIC_ void ndr_print_dfs_Info7(struct ndr_print *ndr, const char *name, const struct dfs_Info7 *r);
_PUBLIC_ void ndr_print_dfs_Info100(struct ndr_print *ndr, const char *name, const struct dfs_Info100 *r);
_PUBLIC_ void ndr_print_dfs_Info101(struct ndr_print *ndr, const char *name, const struct dfs_Info101 *r);
_PUBLIC_ void ndr_print_dfs_Info102(struct ndr_print *ndr, const char *name, const struct dfs_Info102 *r);
_PUBLIC_ void ndr_print_dfs_Info103(struct ndr_print *ndr, const char *name, const struct dfs_Info103 *r);
_PUBLIC_ void ndr_print_dfs_Info104(struct ndr_print *ndr, const char *name, const struct dfs_Info104 *r);
_PUBLIC_ void ndr_print_dfs_Info105(struct ndr_print *ndr, const char *name, const struct dfs_Info105 *r);
_PUBLIC_ void ndr_print_dfs_Info106(struct ndr_print *ndr, const char *name, const struct dfs_Info106 *r);
_PUBLIC_ void ndr_print_dfs_Info200(struct ndr_print *ndr, const char *name, const struct dfs_Info200 *r);
_PUBLIC_ void ndr_print_dfs_VolumeFlavor(struct ndr_print *ndr, const char *name, enum dfs_VolumeFlavor r);
_PUBLIC_ void ndr_print_dfs_Info300(struct ndr_print *ndr, const char *name, const struct dfs_Info300 *r);
_PUBLIC_ void ndr_print_dfs_Info(struct ndr_print *ndr, const char *name, const union dfs_Info *r);
_PUBLIC_ void ndr_print_dfs_EnumArray1(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray1 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray2(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray2 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray3(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray3 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray4(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray4 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray5(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray5 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray6(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray6 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray200(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray200 *r);
_PUBLIC_ void ndr_print_dfs_EnumArray300(struct ndr_print *ndr, const char *name, const struct dfs_EnumArray300 *r);
_PUBLIC_ void ndr_print_dfs_EnumInfo(struct ndr_print *ndr, const char *name, const union dfs_EnumInfo *r);
_PUBLIC_ void ndr_print_dfs_EnumStruct(struct ndr_print *ndr, const char *name, const struct dfs_EnumStruct *r);
_PUBLIC_ void ndr_print_dfs_UnknownStruct(struct ndr_print *ndr, const char *name, const struct dfs_UnknownStruct *r);
_PUBLIC_ enum ndr_err_code ndr_push_dfs_GetManagerVersion(struct ndr_push *ndr, int flags, const struct dfs_GetManagerVersion *r);
_PUBLIC_ enum ndr_err_code ndr_pull_dfs_GetManagerVersion(struct ndr_pull *ndr, int flags, struct dfs_GetManagerVersion *r);
_PUBLIC_ void ndr_print_dfs_GetManagerVersion(struct ndr_print *ndr, const char *name, int flags, const struct dfs_GetManagerVersion *r);
_PUBLIC_ void ndr_print_dfs_Add(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Add *r);
_PUBLIC_ void ndr_print_dfs_Remove(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Remove *r);
_PUBLIC_ void ndr_print_dfs_SetInfo(struct ndr_print *ndr, const char *name, int flags, const struct dfs_SetInfo *r);
_PUBLIC_ void ndr_print_dfs_GetInfo(struct ndr_print *ndr, const char *name, int flags, const struct dfs_GetInfo *r);
_PUBLIC_ void ndr_print_dfs_Enum(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Enum *r);
_PUBLIC_ void ndr_print_dfs_Rename(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Rename *r);
_PUBLIC_ void ndr_print_dfs_Move(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Move *r);
_PUBLIC_ void ndr_print_dfs_ManagerGetConfigInfo(struct ndr_print *ndr, const char *name, int flags, const struct dfs_ManagerGetConfigInfo *r);
_PUBLIC_ void ndr_print_dfs_ManagerSendSiteInfo(struct ndr_print *ndr, const char *name, int flags, const struct dfs_ManagerSendSiteInfo *r);
_PUBLIC_ void ndr_print_dfs_AddFtRoot(struct ndr_print *ndr, const char *name, int flags, const struct dfs_AddFtRoot *r);
_PUBLIC_ void ndr_print_dfs_RemoveFtRoot(struct ndr_print *ndr, const char *name, int flags, const struct dfs_RemoveFtRoot *r);
_PUBLIC_ void ndr_print_dfs_AddStdRoot(struct ndr_print *ndr, const char *name, int flags, const struct dfs_AddStdRoot *r);
_PUBLIC_ void ndr_print_dfs_RemoveStdRoot(struct ndr_print *ndr, const char *name, int flags, const struct dfs_RemoveStdRoot *r);
_PUBLIC_ void ndr_print_dfs_ManagerInitialize(struct ndr_print *ndr, const char *name, int flags, const struct dfs_ManagerInitialize *r);
_PUBLIC_ void ndr_print_dfs_AddStdRootForced(struct ndr_print *ndr, const char *name, int flags, const struct dfs_AddStdRootForced *r);
_PUBLIC_ void ndr_print_dfs_GetDcAddress(struct ndr_print *ndr, const char *name, int flags, const struct dfs_GetDcAddress *r);
_PUBLIC_ void ndr_print_dfs_SetDcAddress(struct ndr_print *ndr, const char *name, int flags, const struct dfs_SetDcAddress *r);
_PUBLIC_ void ndr_print_dfs_FlushFtTable(struct ndr_print *ndr, const char *name, int flags, const struct dfs_FlushFtTable *r);
_PUBLIC_ void ndr_print_dfs_Add2(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Add2 *r);
_PUBLIC_ void ndr_print_dfs_Remove2(struct ndr_print *ndr, const char *name, int flags, const struct dfs_Remove2 *r);
_PUBLIC_ enum ndr_err_code ndr_push_dfs_EnumEx(struct ndr_push *ndr, int flags, const struct dfs_EnumEx *r);
_PUBLIC_ enum ndr_err_code ndr_pull_dfs_EnumEx(struct ndr_pull *ndr, int flags, struct dfs_EnumEx *r);
_PUBLIC_ void ndr_print_dfs_EnumEx(struct ndr_print *ndr, const char *name, int flags, const struct dfs_EnumEx *r);
_PUBLIC_ void ndr_print_dfs_SetInfo2(struct ndr_print *ndr, const char *name, int flags, const struct dfs_SetInfo2 *r);

/* The following definitions come from librpc/gen_ndr/ndr_dssetup.c  */

_PUBLIC_ void ndr_print_dssetup_DsRole(struct ndr_print *ndr, const char *name, enum dssetup_DsRole r);
_PUBLIC_ void ndr_print_dssetup_DsRoleFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_dssetup_DsRolePrimaryDomInfoBasic(struct ndr_print *ndr, const char *name, const struct dssetup_DsRolePrimaryDomInfoBasic *r);
_PUBLIC_ void ndr_print_dssetup_DsUpgrade(struct ndr_print *ndr, const char *name, enum dssetup_DsUpgrade r);
_PUBLIC_ void ndr_print_dssetup_DsPrevious(struct ndr_print *ndr, const char *name, enum dssetup_DsPrevious r);
_PUBLIC_ void ndr_print_dssetup_DsRoleUpgradeStatus(struct ndr_print *ndr, const char *name, const struct dssetup_DsRoleUpgradeStatus *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleOp(struct ndr_print *ndr, const char *name, enum dssetup_DsRoleOp r);
_PUBLIC_ void ndr_print_dssetup_DsRoleOpStatus(struct ndr_print *ndr, const char *name, const struct dssetup_DsRoleOpStatus *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleInfoLevel(struct ndr_print *ndr, const char *name, enum dssetup_DsRoleInfoLevel r);
_PUBLIC_ void ndr_print_dssetup_DsRoleInfo(struct ndr_print *ndr, const char *name, const union dssetup_DsRoleInfo *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleGetPrimaryDomainInformation(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetPrimaryDomainInformation *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleDnsNameToFlatName(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDnsNameToFlatName *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleDcAsDc(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDcAsDc *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleDcAsReplica(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDcAsReplica *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleDemoteDc(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleDemoteDc *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleGetDcOperationProgress(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetDcOperationProgress *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleGetDcOperationResults(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleGetDcOperationResults *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleCancel(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleCancel *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleServerSaveStateForUpgrade(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleServerSaveStateForUpgrade *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleUpgradeDownlevelServer(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleUpgradeDownlevelServer *r);
_PUBLIC_ void ndr_print_dssetup_DsRoleAbortDownlevelServerUpgrade(struct ndr_print *ndr, const char *name, int flags, const struct dssetup_DsRoleAbortDownlevelServerUpgrade *r);

/* The following definitions come from librpc/gen_ndr/ndr_echo.c  */

_PUBLIC_ void ndr_print_echo_info1(struct ndr_print *ndr, const char *name, const struct echo_info1 *r);
_PUBLIC_ void ndr_print_echo_info2(struct ndr_print *ndr, const char *name, const struct echo_info2 *r);
_PUBLIC_ void ndr_print_echo_info3(struct ndr_print *ndr, const char *name, const struct echo_info3 *r);
_PUBLIC_ void ndr_print_STRUCT_echo_info4(struct ndr_print *ndr, const char *name, const struct echo_info4 *r);
_PUBLIC_ void ndr_print_echo_info5(struct ndr_print *ndr, const char *name, const struct echo_info5 *r);
_PUBLIC_ void ndr_print_echo_info6(struct ndr_print *ndr, const char *name, const struct echo_info6 *r);
_PUBLIC_ void ndr_print_echo_info7(struct ndr_print *ndr, const char *name, const struct echo_info7 *r);
_PUBLIC_ void ndr_print_echo_Info(struct ndr_print *ndr, const char *name, const union echo_Info *r);
_PUBLIC_ void ndr_print_echo_Enum1(struct ndr_print *ndr, const char *name, enum echo_Enum1 r);
_PUBLIC_ void ndr_print_echo_Enum1_32(struct ndr_print *ndr, const char *name, enum echo_Enum1_32 r);
_PUBLIC_ void ndr_print_echo_Enum2(struct ndr_print *ndr, const char *name, const struct echo_Enum2 *r);
_PUBLIC_ void ndr_print_echo_Enum3(struct ndr_print *ndr, const char *name, const union echo_Enum3 *r);
_PUBLIC_ void ndr_print_echo_Surrounding(struct ndr_print *ndr, const char *name, const struct echo_Surrounding *r);
_PUBLIC_ void ndr_print_echo_AddOne(struct ndr_print *ndr, const char *name, int flags, const struct echo_AddOne *r);
_PUBLIC_ void ndr_print_echo_EchoData(struct ndr_print *ndr, const char *name, int flags, const struct echo_EchoData *r);
_PUBLIC_ void ndr_print_echo_SinkData(struct ndr_print *ndr, const char *name, int flags, const struct echo_SinkData *r);
_PUBLIC_ void ndr_print_echo_SourceData(struct ndr_print *ndr, const char *name, int flags, const struct echo_SourceData *r);
_PUBLIC_ void ndr_print_echo_TestCall(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestCall *r);
_PUBLIC_ void ndr_print_echo_TestCall2(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestCall2 *r);
_PUBLIC_ void ndr_print_echo_TestSleep(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestSleep *r);
_PUBLIC_ void ndr_print_echo_TestEnum(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestEnum *r);
_PUBLIC_ void ndr_print_echo_TestSurrounding(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestSurrounding *r);
_PUBLIC_ void ndr_print_echo_TestDoublePointer(struct ndr_print *ndr, const char *name, int flags, const struct echo_TestDoublePointer *r);

/* The following definitions come from librpc/gen_ndr/ndr_eventlog.c  */

_PUBLIC_ void ndr_print_eventlog_OpenUnknown0(struct ndr_print *ndr, const char *name, const struct eventlog_OpenUnknown0 *r);
_PUBLIC_ enum ndr_err_code ndr_push_eventlog_Record(struct ndr_push *ndr, int ndr_flags, const struct eventlog_Record *r);
_PUBLIC_ enum ndr_err_code ndr_pull_eventlog_Record(struct ndr_pull *ndr, int ndr_flags, struct eventlog_Record *r);
_PUBLIC_ void ndr_print_eventlog_Record(struct ndr_print *ndr, const char *name, const struct eventlog_Record *r);
_PUBLIC_ void ndr_print_eventlog_ClearEventLogW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ClearEventLogW *r);
_PUBLIC_ void ndr_print_eventlog_BackupEventLogW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_BackupEventLogW *r);
_PUBLIC_ void ndr_print_eventlog_CloseEventLog(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_CloseEventLog *r);
_PUBLIC_ void ndr_print_eventlog_DeregisterEventSource(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_DeregisterEventSource *r);
_PUBLIC_ void ndr_print_eventlog_GetNumRecords(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_GetNumRecords *r);
_PUBLIC_ void ndr_print_eventlog_GetOldestRecord(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_GetOldestRecord *r);
_PUBLIC_ void ndr_print_eventlog_ChangeNotify(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ChangeNotify *r);
_PUBLIC_ void ndr_print_eventlog_OpenEventLogW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_OpenEventLogW *r);
_PUBLIC_ void ndr_print_eventlog_RegisterEventSourceW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_RegisterEventSourceW *r);
_PUBLIC_ void ndr_print_eventlog_OpenBackupEventLogW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_OpenBackupEventLogW *r);
_PUBLIC_ void ndr_print_eventlog_ReadEventLogW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ReadEventLogW *r);
_PUBLIC_ void ndr_print_eventlog_ReportEventW(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ReportEventW *r);
_PUBLIC_ void ndr_print_eventlog_ClearEventLogA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ClearEventLogA *r);
_PUBLIC_ void ndr_print_eventlog_BackupEventLogA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_BackupEventLogA *r);
_PUBLIC_ void ndr_print_eventlog_OpenEventLogA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_OpenEventLogA *r);
_PUBLIC_ void ndr_print_eventlog_RegisterEventSourceA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_RegisterEventSourceA *r);
_PUBLIC_ void ndr_print_eventlog_OpenBackupEventLogA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_OpenBackupEventLogA *r);
_PUBLIC_ void ndr_print_eventlog_ReadEventLogA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ReadEventLogA *r);
_PUBLIC_ void ndr_print_eventlog_ReportEventA(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_ReportEventA *r);
_PUBLIC_ void ndr_print_eventlog_RegisterClusterSvc(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_RegisterClusterSvc *r);
_PUBLIC_ void ndr_print_eventlog_DeregisterClusterSvc(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_DeregisterClusterSvc *r);
_PUBLIC_ void ndr_print_eventlog_WriteClusterEvents(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_WriteClusterEvents *r);
_PUBLIC_ void ndr_print_eventlog_GetLogIntormation(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_GetLogIntormation *r);
_PUBLIC_ void ndr_print_eventlog_FlushEventLog(struct ndr_print *ndr, const char *name, int flags, const struct eventlog_FlushEventLog *r);

/* The following definitions come from librpc/gen_ndr/ndr_initshutdown.c  */

_PUBLIC_ void ndr_print_initshutdown_String_sub(struct ndr_print *ndr, const char *name, const struct initshutdown_String_sub *r);
_PUBLIC_ enum ndr_err_code ndr_push_initshutdown_String(struct ndr_push *ndr, int ndr_flags, const struct initshutdown_String *r);
_PUBLIC_ enum ndr_err_code ndr_pull_initshutdown_String(struct ndr_pull *ndr, int ndr_flags, struct initshutdown_String *r);
_PUBLIC_ void ndr_print_initshutdown_String(struct ndr_print *ndr, const char *name, const struct initshutdown_String *r);
_PUBLIC_ void ndr_print_initshutdown_Init(struct ndr_print *ndr, const char *name, int flags, const struct initshutdown_Init *r);
_PUBLIC_ void ndr_print_initshutdown_Abort(struct ndr_print *ndr, const char *name, int flags, const struct initshutdown_Abort *r);
_PUBLIC_ void ndr_print_initshutdown_InitEx(struct ndr_print *ndr, const char *name, int flags, const struct initshutdown_InitEx *r);

/* The following definitions come from librpc/gen_ndr/ndr_krb5pac.c  */

_PUBLIC_ void ndr_print_PAC_LOGON_NAME(struct ndr_print *ndr, const char *name, const struct PAC_LOGON_NAME *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_SIGNATURE_DATA(struct ndr_push *ndr, int ndr_flags, const struct PAC_SIGNATURE_DATA *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_SIGNATURE_DATA(struct ndr_pull *ndr, int ndr_flags, struct PAC_SIGNATURE_DATA *r);
_PUBLIC_ void ndr_print_PAC_SIGNATURE_DATA(struct ndr_print *ndr, const char *name, const struct PAC_SIGNATURE_DATA *r);
_PUBLIC_ void ndr_print_PAC_LOGON_INFO(struct ndr_print *ndr, const char *name, const struct PAC_LOGON_INFO *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_LOGON_INFO_CTR(struct ndr_push *ndr, int ndr_flags, const struct PAC_LOGON_INFO_CTR *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_LOGON_INFO_CTR(struct ndr_pull *ndr, int ndr_flags, struct PAC_LOGON_INFO_CTR *r);
_PUBLIC_ void ndr_print_PAC_LOGON_INFO_CTR(struct ndr_print *ndr, const char *name, const struct PAC_LOGON_INFO_CTR *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_TYPE(struct ndr_push *ndr, int ndr_flags, enum PAC_TYPE r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_TYPE(struct ndr_pull *ndr, int ndr_flags, enum PAC_TYPE *r);
_PUBLIC_ void ndr_print_PAC_TYPE(struct ndr_print *ndr, const char *name, enum PAC_TYPE r);
_PUBLIC_ void ndr_print_DATA_BLOB_REM(struct ndr_print *ndr, const char *name, const struct DATA_BLOB_REM *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_INFO(struct ndr_push *ndr, int ndr_flags, const union PAC_INFO *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_INFO(struct ndr_pull *ndr, int ndr_flags, union PAC_INFO *r);
_PUBLIC_ void ndr_print_PAC_INFO(struct ndr_print *ndr, const char *name, const union PAC_INFO *r);
_PUBLIC_ size_t ndr_size_PAC_INFO(const union PAC_INFO *r, uint32_t level, int flags);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_DATA(struct ndr_push *ndr, int ndr_flags, const struct PAC_DATA *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_DATA(struct ndr_pull *ndr, int ndr_flags, struct PAC_DATA *r);
_PUBLIC_ void ndr_print_PAC_DATA(struct ndr_print *ndr, const char *name, const struct PAC_DATA *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_BUFFER_RAW(struct ndr_push *ndr, int ndr_flags, const struct PAC_BUFFER_RAW *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_BUFFER_RAW(struct ndr_pull *ndr, int ndr_flags, struct PAC_BUFFER_RAW *r);
_PUBLIC_ void ndr_print_PAC_BUFFER_RAW(struct ndr_print *ndr, const char *name, const struct PAC_BUFFER_RAW *r);
_PUBLIC_ enum ndr_err_code ndr_push_PAC_DATA_RAW(struct ndr_push *ndr, int ndr_flags, const struct PAC_DATA_RAW *r);
_PUBLIC_ enum ndr_err_code ndr_pull_PAC_DATA_RAW(struct ndr_pull *ndr, int ndr_flags, struct PAC_DATA_RAW *r);
_PUBLIC_ void ndr_print_PAC_DATA_RAW(struct ndr_print *ndr, const char *name, const struct PAC_DATA_RAW *r);
_PUBLIC_ enum ndr_err_code ndr_push_netsamlogoncache_entry(struct ndr_push *ndr, int ndr_flags, const struct netsamlogoncache_entry *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netsamlogoncache_entry(struct ndr_pull *ndr, int ndr_flags, struct netsamlogoncache_entry *r);
_PUBLIC_ void ndr_print_netsamlogoncache_entry(struct ndr_print *ndr, const char *name, const struct netsamlogoncache_entry *r);
_PUBLIC_ void ndr_print_decode_pac(struct ndr_print *ndr, const char *name, int flags, const struct decode_pac *r);
_PUBLIC_ void ndr_print_decode_pac_raw(struct ndr_print *ndr, const char *name, int flags, const struct decode_pac_raw *r);
_PUBLIC_ void ndr_print_decode_login_info(struct ndr_print *ndr, const char *name, int flags, const struct decode_login_info *r);

/* The following definitions come from librpc/gen_ndr/ndr_lsa.c  */

_PUBLIC_ enum ndr_err_code ndr_push_lsa_String(struct ndr_push *ndr, int ndr_flags, const struct lsa_String *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_String(struct ndr_pull *ndr, int ndr_flags, struct lsa_String *r);
_PUBLIC_ void ndr_print_lsa_String(struct ndr_print *ndr, const char *name, const struct lsa_String *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_StringLarge(struct ndr_push *ndr, int ndr_flags, const struct lsa_StringLarge *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_StringLarge(struct ndr_pull *ndr, int ndr_flags, struct lsa_StringLarge *r);
_PUBLIC_ void ndr_print_lsa_StringLarge(struct ndr_print *ndr, const char *name, const struct lsa_StringLarge *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_Strings(struct ndr_push *ndr, int ndr_flags, const struct lsa_Strings *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_Strings(struct ndr_pull *ndr, int ndr_flags, struct lsa_Strings *r);
_PUBLIC_ void ndr_print_lsa_Strings(struct ndr_print *ndr, const char *name, const struct lsa_Strings *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_AsciiString(struct ndr_push *ndr, int ndr_flags, const struct lsa_AsciiString *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_AsciiString(struct ndr_pull *ndr, int ndr_flags, struct lsa_AsciiString *r);
_PUBLIC_ void ndr_print_lsa_AsciiString(struct ndr_print *ndr, const char *name, const struct lsa_AsciiString *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_AsciiStringLarge(struct ndr_push *ndr, int ndr_flags, const struct lsa_AsciiStringLarge *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_AsciiStringLarge(struct ndr_pull *ndr, int ndr_flags, struct lsa_AsciiStringLarge *r);
_PUBLIC_ void ndr_print_lsa_AsciiStringLarge(struct ndr_print *ndr, const char *name, const struct lsa_AsciiStringLarge *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_BinaryString(struct ndr_push *ndr, int ndr_flags, const struct lsa_BinaryString *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_BinaryString(struct ndr_pull *ndr, int ndr_flags, struct lsa_BinaryString *r);
_PUBLIC_ void ndr_print_lsa_BinaryString(struct ndr_print *ndr, const char *name, const struct lsa_BinaryString *r);
_PUBLIC_ void ndr_print_lsa_LUID(struct ndr_print *ndr, const char *name, const struct lsa_LUID *r);
_PUBLIC_ void ndr_print_lsa_PrivEntry(struct ndr_print *ndr, const char *name, const struct lsa_PrivEntry *r);
_PUBLIC_ void ndr_print_lsa_PrivArray(struct ndr_print *ndr, const char *name, const struct lsa_PrivArray *r);
_PUBLIC_ void ndr_print_lsa_QosInfo(struct ndr_print *ndr, const char *name, const struct lsa_QosInfo *r);
_PUBLIC_ void ndr_print_lsa_ObjectAttribute(struct ndr_print *ndr, const char *name, const struct lsa_ObjectAttribute *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_PolicyAccessMask(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_PolicyAccessMask(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_lsa_PolicyAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_lsa_AuditLogInfo(struct ndr_print *ndr, const char *name, const struct lsa_AuditLogInfo *r);
_PUBLIC_ void ndr_print_lsa_PolicyAuditPolicy(struct ndr_print *ndr, const char *name, enum lsa_PolicyAuditPolicy r);
_PUBLIC_ void ndr_print_lsa_AuditEventsInfo(struct ndr_print *ndr, const char *name, const struct lsa_AuditEventsInfo *r);
_PUBLIC_ void ndr_print_lsa_DomainInfo(struct ndr_print *ndr, const char *name, const struct lsa_DomainInfo *r);
_PUBLIC_ void ndr_print_lsa_PDAccountInfo(struct ndr_print *ndr, const char *name, const struct lsa_PDAccountInfo *r);
_PUBLIC_ void ndr_print_lsa_ServerRole(struct ndr_print *ndr, const char *name, const struct lsa_ServerRole *r);
_PUBLIC_ void ndr_print_lsa_ReplicaSourceInfo(struct ndr_print *ndr, const char *name, const struct lsa_ReplicaSourceInfo *r);
_PUBLIC_ void ndr_print_lsa_DefaultQuotaInfo(struct ndr_print *ndr, const char *name, const struct lsa_DefaultQuotaInfo *r);
_PUBLIC_ void ndr_print_lsa_ModificationInfo(struct ndr_print *ndr, const char *name, const struct lsa_ModificationInfo *r);
_PUBLIC_ void ndr_print_lsa_AuditFullSetInfo(struct ndr_print *ndr, const char *name, const struct lsa_AuditFullSetInfo *r);
_PUBLIC_ void ndr_print_lsa_AuditFullQueryInfo(struct ndr_print *ndr, const char *name, const struct lsa_AuditFullQueryInfo *r);
_PUBLIC_ void ndr_print_lsa_DnsDomainInfo(struct ndr_print *ndr, const char *name, const struct lsa_DnsDomainInfo *r);
_PUBLIC_ void ndr_print_lsa_PolicyInfo(struct ndr_print *ndr, const char *name, enum lsa_PolicyInfo r);
_PUBLIC_ void ndr_print_lsa_PolicyInformation(struct ndr_print *ndr, const char *name, const union lsa_PolicyInformation *r);
_PUBLIC_ void ndr_print_lsa_SidPtr(struct ndr_print *ndr, const char *name, const struct lsa_SidPtr *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_SidArray(struct ndr_push *ndr, int ndr_flags, const struct lsa_SidArray *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_SidArray(struct ndr_pull *ndr, int ndr_flags, struct lsa_SidArray *r);
_PUBLIC_ void ndr_print_lsa_SidArray(struct ndr_print *ndr, const char *name, const struct lsa_SidArray *r);
_PUBLIC_ void ndr_print_lsa_DomainList(struct ndr_print *ndr, const char *name, const struct lsa_DomainList *r);
_PUBLIC_ void ndr_print_lsa_SidType(struct ndr_print *ndr, const char *name, enum lsa_SidType r);
_PUBLIC_ void ndr_print_lsa_TranslatedSid(struct ndr_print *ndr, const char *name, const struct lsa_TranslatedSid *r);
_PUBLIC_ void ndr_print_lsa_TransSidArray(struct ndr_print *ndr, const char *name, const struct lsa_TransSidArray *r);
_PUBLIC_ void ndr_print_lsa_RefDomainList(struct ndr_print *ndr, const char *name, const struct lsa_RefDomainList *r);
_PUBLIC_ void ndr_print_lsa_LookupNamesLevel(struct ndr_print *ndr, const char *name, enum lsa_LookupNamesLevel r);
_PUBLIC_ void ndr_print_lsa_TranslatedName(struct ndr_print *ndr, const char *name, const struct lsa_TranslatedName *r);
_PUBLIC_ void ndr_print_lsa_TransNameArray(struct ndr_print *ndr, const char *name, const struct lsa_TransNameArray *r);
_PUBLIC_ void ndr_print_lsa_LUIDAttribute(struct ndr_print *ndr, const char *name, const struct lsa_LUIDAttribute *r);
_PUBLIC_ void ndr_print_lsa_PrivilegeSet(struct ndr_print *ndr, const char *name, const struct lsa_PrivilegeSet *r);
_PUBLIC_ void ndr_print_lsa_DATA_BUF(struct ndr_print *ndr, const char *name, const struct lsa_DATA_BUF *r);
_PUBLIC_ void ndr_print_lsa_DATA_BUF2(struct ndr_print *ndr, const char *name, const struct lsa_DATA_BUF2 *r);
_PUBLIC_ void ndr_print_lsa_TrustDomInfoEnum(struct ndr_print *ndr, const char *name, enum lsa_TrustDomInfoEnum r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoName(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoName *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoPosixOffset(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoPosixOffset *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoPassword(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoPassword *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoBasic(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoBasic *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoInfoEx(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoInfoEx *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoBuffer(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoBuffer *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoAuthInfo(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoAuthInfo *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoFullInfo(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoFullInfo *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfo11(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfo11 *r);
_PUBLIC_ void ndr_print_lsa_TrustDomainInfoInfoAll(struct ndr_print *ndr, const char *name, const struct lsa_TrustDomainInfoInfoAll *r);
_PUBLIC_ void ndr_print_lsa_TrustedDomainInfo(struct ndr_print *ndr, const char *name, const union lsa_TrustedDomainInfo *r);
_PUBLIC_ void ndr_print_lsa_DATA_BUF_PTR(struct ndr_print *ndr, const char *name, const struct lsa_DATA_BUF_PTR *r);
_PUBLIC_ void ndr_print_lsa_RightSet(struct ndr_print *ndr, const char *name, const struct lsa_RightSet *r);
_PUBLIC_ void ndr_print_lsa_DomainListEx(struct ndr_print *ndr, const char *name, const struct lsa_DomainListEx *r);
_PUBLIC_ void ndr_print_lsa_DomainInfoKerberos(struct ndr_print *ndr, const char *name, const struct lsa_DomainInfoKerberos *r);
_PUBLIC_ void ndr_print_lsa_DomainInfoEfs(struct ndr_print *ndr, const char *name, const struct lsa_DomainInfoEfs *r);
_PUBLIC_ void ndr_print_lsa_DomainInformationPolicy(struct ndr_print *ndr, const char *name, const union lsa_DomainInformationPolicy *r);
_PUBLIC_ void ndr_print_lsa_TranslatedName2(struct ndr_print *ndr, const char *name, const struct lsa_TranslatedName2 *r);
_PUBLIC_ void ndr_print_lsa_TransNameArray2(struct ndr_print *ndr, const char *name, const struct lsa_TransNameArray2 *r);
_PUBLIC_ void ndr_print_lsa_TranslatedSid2(struct ndr_print *ndr, const char *name, const struct lsa_TranslatedSid2 *r);
_PUBLIC_ void ndr_print_lsa_TransSidArray2(struct ndr_print *ndr, const char *name, const struct lsa_TransSidArray2 *r);
_PUBLIC_ void ndr_print_lsa_TranslatedSid3(struct ndr_print *ndr, const char *name, const struct lsa_TranslatedSid3 *r);
_PUBLIC_ void ndr_print_lsa_TransSidArray3(struct ndr_print *ndr, const char *name, const struct lsa_TransSidArray3 *r);
_PUBLIC_ void ndr_print_lsa_ForestTrustBinaryData(struct ndr_print *ndr, const char *name, const struct lsa_ForestTrustBinaryData *r);
_PUBLIC_ void ndr_print_lsa_ForestTrustDomainInfo(struct ndr_print *ndr, const char *name, const struct lsa_ForestTrustDomainInfo *r);
_PUBLIC_ void ndr_print_lsa_ForestTrustData(struct ndr_print *ndr, const char *name, const union lsa_ForestTrustData *r);
_PUBLIC_ void ndr_print_lsa_ForestTrustRecordType(struct ndr_print *ndr, const char *name, enum lsa_ForestTrustRecordType r);
_PUBLIC_ void ndr_print_lsa_ForestTrustRecord(struct ndr_print *ndr, const char *name, const struct lsa_ForestTrustRecord *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_ForestTrustInformation(struct ndr_push *ndr, int ndr_flags, const struct lsa_ForestTrustInformation *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_ForestTrustInformation(struct ndr_pull *ndr, int ndr_flags, struct lsa_ForestTrustInformation *r);
_PUBLIC_ void ndr_print_lsa_ForestTrustInformation(struct ndr_print *ndr, const char *name, const struct lsa_ForestTrustInformation *r);
_PUBLIC_ void ndr_print_lsa_Close(struct ndr_print *ndr, const char *name, int flags, const struct lsa_Close *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_Delete(struct ndr_push *ndr, int flags, const struct lsa_Delete *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_Delete(struct ndr_pull *ndr, int flags, struct lsa_Delete *r);
_PUBLIC_ void ndr_print_lsa_Delete(struct ndr_print *ndr, const char *name, int flags, const struct lsa_Delete *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_EnumPrivs(struct ndr_push *ndr, int flags, const struct lsa_EnumPrivs *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_EnumPrivs(struct ndr_pull *ndr, int flags, struct lsa_EnumPrivs *r);
_PUBLIC_ void ndr_print_lsa_EnumPrivs(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumPrivs *r);
_PUBLIC_ void ndr_print_lsa_QuerySecurity(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QuerySecurity *r);
_PUBLIC_ void ndr_print_lsa_SetSecObj(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetSecObj *r);
_PUBLIC_ void ndr_print_lsa_ChangePassword(struct ndr_print *ndr, const char *name, int flags, const struct lsa_ChangePassword *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_OpenPolicy(struct ndr_push *ndr, int flags, const struct lsa_OpenPolicy *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_OpenPolicy(struct ndr_pull *ndr, int flags, struct lsa_OpenPolicy *r);
_PUBLIC_ void ndr_print_lsa_OpenPolicy(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenPolicy *r);
_PUBLIC_ void ndr_print_lsa_QueryInfoPolicy(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryInfoPolicy *r);
_PUBLIC_ void ndr_print_lsa_SetInfoPolicy(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetInfoPolicy *r);
_PUBLIC_ void ndr_print_lsa_ClearAuditLog(struct ndr_print *ndr, const char *name, int flags, const struct lsa_ClearAuditLog *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_CreateAccount(struct ndr_push *ndr, int flags, const struct lsa_CreateAccount *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_CreateAccount(struct ndr_pull *ndr, int flags, struct lsa_CreateAccount *r);
_PUBLIC_ void ndr_print_lsa_CreateAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CreateAccount *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_EnumAccounts(struct ndr_push *ndr, int flags, const struct lsa_EnumAccounts *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_EnumAccounts(struct ndr_pull *ndr, int flags, struct lsa_EnumAccounts *r);
_PUBLIC_ void ndr_print_lsa_EnumAccounts(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumAccounts *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_CreateTrustedDomain(struct ndr_push *ndr, int flags, const struct lsa_CreateTrustedDomain *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_CreateTrustedDomain(struct ndr_pull *ndr, int flags, struct lsa_CreateTrustedDomain *r);
_PUBLIC_ void ndr_print_lsa_CreateTrustedDomain(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CreateTrustedDomain *r);
_PUBLIC_ void ndr_print_lsa_EnumTrustDom(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumTrustDom *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupNames(struct ndr_push *ndr, int flags, const struct lsa_LookupNames *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupNames(struct ndr_pull *ndr, int flags, struct lsa_LookupNames *r);
_PUBLIC_ void ndr_print_lsa_LookupNames(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupNames *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupSids(struct ndr_push *ndr, int flags, const struct lsa_LookupSids *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupSids(struct ndr_pull *ndr, int flags, struct lsa_LookupSids *r);
_PUBLIC_ void ndr_print_lsa_LookupSids(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupSids *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_CreateSecret(struct ndr_push *ndr, int flags, const struct lsa_CreateSecret *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_CreateSecret(struct ndr_pull *ndr, int flags, struct lsa_CreateSecret *r);
_PUBLIC_ void ndr_print_lsa_CreateSecret(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CreateSecret *r);
_PUBLIC_ void ndr_print_lsa_OpenAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenAccount *r);
_PUBLIC_ void ndr_print_lsa_EnumPrivsAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumPrivsAccount *r);
_PUBLIC_ void ndr_print_lsa_AddPrivilegesToAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_AddPrivilegesToAccount *r);
_PUBLIC_ void ndr_print_lsa_RemovePrivilegesFromAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_RemovePrivilegesFromAccount *r);
_PUBLIC_ void ndr_print_lsa_GetQuotasForAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_GetQuotasForAccount *r);
_PUBLIC_ void ndr_print_lsa_SetQuotasForAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetQuotasForAccount *r);
_PUBLIC_ void ndr_print_lsa_GetSystemAccessAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_GetSystemAccessAccount *r);
_PUBLIC_ void ndr_print_lsa_SetSystemAccessAccount(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetSystemAccessAccount *r);
_PUBLIC_ void ndr_print_lsa_OpenTrustedDomain(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenTrustedDomain *r);
_PUBLIC_ void ndr_print_lsa_QueryTrustedDomainInfo(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryTrustedDomainInfo *r);
_PUBLIC_ void ndr_print_lsa_SetInformationTrustedDomain(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetInformationTrustedDomain *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_OpenSecret(struct ndr_push *ndr, int flags, const struct lsa_OpenSecret *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_OpenSecret(struct ndr_pull *ndr, int flags, struct lsa_OpenSecret *r);
_PUBLIC_ void ndr_print_lsa_OpenSecret(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenSecret *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_SetSecret(struct ndr_push *ndr, int flags, const struct lsa_SetSecret *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_SetSecret(struct ndr_pull *ndr, int flags, struct lsa_SetSecret *r);
_PUBLIC_ void ndr_print_lsa_SetSecret(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetSecret *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_QuerySecret(struct ndr_push *ndr, int flags, const struct lsa_QuerySecret *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_QuerySecret(struct ndr_pull *ndr, int flags, struct lsa_QuerySecret *r);
_PUBLIC_ void ndr_print_lsa_QuerySecret(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QuerySecret *r);
_PUBLIC_ void ndr_print_lsa_LookupPrivValue(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupPrivValue *r);
_PUBLIC_ void ndr_print_lsa_LookupPrivName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupPrivName *r);
_PUBLIC_ void ndr_print_lsa_LookupPrivDisplayName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupPrivDisplayName *r);
_PUBLIC_ void ndr_print_lsa_DeleteObject(struct ndr_print *ndr, const char *name, int flags, const struct lsa_DeleteObject *r);
_PUBLIC_ void ndr_print_lsa_EnumAccountsWithUserRight(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumAccountsWithUserRight *r);
_PUBLIC_ void ndr_print_lsa_EnumAccountRights(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumAccountRights *r);
_PUBLIC_ void ndr_print_lsa_AddAccountRights(struct ndr_print *ndr, const char *name, int flags, const struct lsa_AddAccountRights *r);
_PUBLIC_ void ndr_print_lsa_RemoveAccountRights(struct ndr_print *ndr, const char *name, int flags, const struct lsa_RemoveAccountRights *r);
_PUBLIC_ void ndr_print_lsa_QueryTrustedDomainInfoBySid(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryTrustedDomainInfoBySid *r);
_PUBLIC_ void ndr_print_lsa_SetTrustedDomainInfo(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetTrustedDomainInfo *r);
_PUBLIC_ void ndr_print_lsa_DeleteTrustedDomain(struct ndr_print *ndr, const char *name, int flags, const struct lsa_DeleteTrustedDomain *r);
_PUBLIC_ void ndr_print_lsa_StorePrivateData(struct ndr_print *ndr, const char *name, int flags, const struct lsa_StorePrivateData *r);
_PUBLIC_ void ndr_print_lsa_RetrievePrivateData(struct ndr_print *ndr, const char *name, int flags, const struct lsa_RetrievePrivateData *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_OpenPolicy2(struct ndr_push *ndr, int flags, const struct lsa_OpenPolicy2 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_OpenPolicy2(struct ndr_pull *ndr, int flags, struct lsa_OpenPolicy2 *r);
_PUBLIC_ void ndr_print_lsa_OpenPolicy2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenPolicy2 *r);
_PUBLIC_ void ndr_print_lsa_GetUserName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_GetUserName *r);
_PUBLIC_ void ndr_print_lsa_QueryInfoPolicy2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryInfoPolicy2 *r);
_PUBLIC_ void ndr_print_lsa_SetInfoPolicy2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetInfoPolicy2 *r);
_PUBLIC_ void ndr_print_lsa_QueryTrustedDomainInfoByName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryTrustedDomainInfoByName *r);
_PUBLIC_ void ndr_print_lsa_SetTrustedDomainInfoByName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetTrustedDomainInfoByName *r);
_PUBLIC_ void ndr_print_lsa_EnumTrustedDomainsEx(struct ndr_print *ndr, const char *name, int flags, const struct lsa_EnumTrustedDomainsEx *r);
_PUBLIC_ void ndr_print_lsa_CreateTrustedDomainEx(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CreateTrustedDomainEx *r);
_PUBLIC_ void ndr_print_lsa_CloseTrustedDomainEx(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CloseTrustedDomainEx *r);
_PUBLIC_ void ndr_print_lsa_QueryDomainInformationPolicy(struct ndr_print *ndr, const char *name, int flags, const struct lsa_QueryDomainInformationPolicy *r);
_PUBLIC_ void ndr_print_lsa_SetDomainInformationPolicy(struct ndr_print *ndr, const char *name, int flags, const struct lsa_SetDomainInformationPolicy *r);
_PUBLIC_ void ndr_print_lsa_OpenTrustedDomainByName(struct ndr_print *ndr, const char *name, int flags, const struct lsa_OpenTrustedDomainByName *r);
_PUBLIC_ void ndr_print_lsa_TestCall(struct ndr_print *ndr, const char *name, int flags, const struct lsa_TestCall *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupSids2(struct ndr_push *ndr, int flags, const struct lsa_LookupSids2 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupSids2(struct ndr_pull *ndr, int flags, struct lsa_LookupSids2 *r);
_PUBLIC_ void ndr_print_lsa_LookupSids2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupSids2 *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupNames2(struct ndr_push *ndr, int flags, const struct lsa_LookupNames2 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupNames2(struct ndr_pull *ndr, int flags, struct lsa_LookupNames2 *r);
_PUBLIC_ void ndr_print_lsa_LookupNames2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupNames2 *r);
_PUBLIC_ void ndr_print_lsa_CreateTrustedDomainEx2(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CreateTrustedDomainEx2 *r);
_PUBLIC_ void ndr_print_lsa_CREDRWRITE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRWRITE *r);
_PUBLIC_ void ndr_print_lsa_CREDRREAD(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRREAD *r);
_PUBLIC_ void ndr_print_lsa_CREDRENUMERATE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRENUMERATE *r);
_PUBLIC_ void ndr_print_lsa_CREDRWRITEDOMAINCREDENTIALS(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRWRITEDOMAINCREDENTIALS *r);
_PUBLIC_ void ndr_print_lsa_CREDRREADDOMAINCREDENTIALS(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRREADDOMAINCREDENTIALS *r);
_PUBLIC_ void ndr_print_lsa_CREDRDELETE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRDELETE *r);
_PUBLIC_ void ndr_print_lsa_CREDRGETTARGETINFO(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRGETTARGETINFO *r);
_PUBLIC_ void ndr_print_lsa_CREDRPROFILELOADED(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRPROFILELOADED *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupNames3(struct ndr_push *ndr, int flags, const struct lsa_LookupNames3 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupNames3(struct ndr_pull *ndr, int flags, struct lsa_LookupNames3 *r);
_PUBLIC_ void ndr_print_lsa_LookupNames3(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupNames3 *r);
_PUBLIC_ void ndr_print_lsa_CREDRGETSESSIONTYPES(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRGETSESSIONTYPES *r);
_PUBLIC_ void ndr_print_lsa_LSARREGISTERAUDITEVENT(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARREGISTERAUDITEVENT *r);
_PUBLIC_ void ndr_print_lsa_LSARGENAUDITEVENT(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARGENAUDITEVENT *r);
_PUBLIC_ void ndr_print_lsa_LSARUNREGISTERAUDITEVENT(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARUNREGISTERAUDITEVENT *r);
_PUBLIC_ void ndr_print_lsa_lsaRQueryForestTrustInformation(struct ndr_print *ndr, const char *name, int flags, const struct lsa_lsaRQueryForestTrustInformation *r);
_PUBLIC_ void ndr_print_lsa_LSARSETFORESTTRUSTINFORMATION(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARSETFORESTTRUSTINFORMATION *r);
_PUBLIC_ void ndr_print_lsa_CREDRRENAME(struct ndr_print *ndr, const char *name, int flags, const struct lsa_CREDRRENAME *r);
_PUBLIC_ enum ndr_err_code ndr_push_lsa_LookupSids3(struct ndr_push *ndr, int flags, const struct lsa_LookupSids3 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_lsa_LookupSids3(struct ndr_pull *ndr, int flags, struct lsa_LookupSids3 *r);
_PUBLIC_ void ndr_print_lsa_LookupSids3(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupSids3 *r);
_PUBLIC_ void ndr_print_lsa_LookupNames4(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LookupNames4 *r);
_PUBLIC_ void ndr_print_lsa_LSAROPENPOLICYSCE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSAROPENPOLICYSCE *r);
_PUBLIC_ void ndr_print_lsa_LSARADTREGISTERSECURITYEVENTSOURCE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARADTREGISTERSECURITYEVENTSOURCE *r);
_PUBLIC_ void ndr_print_lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE *r);
_PUBLIC_ void ndr_print_lsa_LSARADTREPORTSECURITYEVENT(struct ndr_print *ndr, const char *name, int flags, const struct lsa_LSARADTREPORTSECURITYEVENT *r);

/* The following definitions come from librpc/gen_ndr/ndr_misc.c  */

_PUBLIC_ enum ndr_err_code ndr_push_GUID(struct ndr_push *ndr, int ndr_flags, const struct GUID *r);
_PUBLIC_ enum ndr_err_code ndr_pull_GUID(struct ndr_pull *ndr, int ndr_flags, struct GUID *r);
_PUBLIC_ size_t ndr_size_GUID(const struct GUID *r, int flags);
_PUBLIC_ enum ndr_err_code ndr_push_ndr_syntax_id(struct ndr_push *ndr, int ndr_flags, const struct ndr_syntax_id *r);
_PUBLIC_ enum ndr_err_code ndr_pull_ndr_syntax_id(struct ndr_pull *ndr, int ndr_flags, struct ndr_syntax_id *r);
_PUBLIC_ void ndr_print_ndr_syntax_id(struct ndr_print *ndr, const char *name, const struct ndr_syntax_id *r);
_PUBLIC_ enum ndr_err_code ndr_push_policy_handle(struct ndr_push *ndr, int ndr_flags, const struct policy_handle *r);
_PUBLIC_ enum ndr_err_code ndr_pull_policy_handle(struct ndr_pull *ndr, int ndr_flags, struct policy_handle *r);
_PUBLIC_ void ndr_print_policy_handle(struct ndr_print *ndr, const char *name, const struct policy_handle *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_SchannelType(struct ndr_push *ndr, int ndr_flags, enum netr_SchannelType r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_SchannelType(struct ndr_pull *ndr, int ndr_flags, enum netr_SchannelType *r);
_PUBLIC_ void ndr_print_netr_SchannelType(struct ndr_print *ndr, const char *name, enum netr_SchannelType r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_SamDatabaseID(struct ndr_push *ndr, int ndr_flags, enum netr_SamDatabaseID r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_SamDatabaseID(struct ndr_pull *ndr, int ndr_flags, enum netr_SamDatabaseID *r);
_PUBLIC_ void ndr_print_netr_SamDatabaseID(struct ndr_print *ndr, const char *name, enum netr_SamDatabaseID r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_RejectReason(struct ndr_push *ndr, int ndr_flags, enum samr_RejectReason r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_RejectReason(struct ndr_pull *ndr, int ndr_flags, enum samr_RejectReason *r);
_PUBLIC_ void ndr_print_samr_RejectReason(struct ndr_print *ndr, const char *name, enum samr_RejectReason r);

/* The following definitions come from librpc/gen_ndr/ndr_netlogon.c  */

_PUBLIC_ void ndr_print_netr_UasInfo(struct ndr_print *ndr, const char *name, const struct netr_UasInfo *r);
_PUBLIC_ void ndr_print_netr_UasLogoffInfo(struct ndr_print *ndr, const char *name, const struct netr_UasLogoffInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_AcctLockStr(struct ndr_push *ndr, int ndr_flags, const struct netr_AcctLockStr *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_AcctLockStr(struct ndr_pull *ndr, int ndr_flags, struct netr_AcctLockStr *r);
_PUBLIC_ void ndr_print_netr_AcctLockStr(struct ndr_print *ndr, const char *name, const struct netr_AcctLockStr *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_LogonParameterControl(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_LogonParameterControl(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_netr_LogonParameterControl(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_IdentityInfo(struct ndr_print *ndr, const char *name, const struct netr_IdentityInfo *r);
_PUBLIC_ void ndr_print_netr_PasswordInfo(struct ndr_print *ndr, const char *name, const struct netr_PasswordInfo *r);
_PUBLIC_ void ndr_print_netr_ChallengeResponse(struct ndr_print *ndr, const char *name, const struct netr_ChallengeResponse *r);
_PUBLIC_ void ndr_print_netr_NetworkInfo(struct ndr_print *ndr, const char *name, const struct netr_NetworkInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_LogonInfo(struct ndr_push *ndr, int ndr_flags, const union netr_LogonInfo *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_LogonInfo(struct ndr_pull *ndr, int ndr_flags, union netr_LogonInfo *r);
_PUBLIC_ void ndr_print_netr_LogonInfo(struct ndr_print *ndr, const char *name, const union netr_LogonInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_UserSessionKey(struct ndr_push *ndr, int ndr_flags, const struct netr_UserSessionKey *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_UserSessionKey(struct ndr_pull *ndr, int ndr_flags, struct netr_UserSessionKey *r);
_PUBLIC_ void ndr_print_netr_UserSessionKey(struct ndr_print *ndr, const char *name, const struct netr_UserSessionKey *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_LMSessionKey(struct ndr_push *ndr, int ndr_flags, const struct netr_LMSessionKey *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_LMSessionKey(struct ndr_pull *ndr, int ndr_flags, struct netr_LMSessionKey *r);
_PUBLIC_ void ndr_print_netr_LMSessionKey(struct ndr_print *ndr, const char *name, const struct netr_LMSessionKey *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_UserFlags(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_UserFlags(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_netr_UserFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_SamBaseInfo(struct ndr_print *ndr, const char *name, const struct netr_SamBaseInfo *r);
_PUBLIC_ void ndr_print_netr_SamInfo2(struct ndr_print *ndr, const char *name, const struct netr_SamInfo2 *r);
_PUBLIC_ void ndr_print_netr_SidAttr(struct ndr_print *ndr, const char *name, const struct netr_SidAttr *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_SamInfo3(struct ndr_push *ndr, int ndr_flags, const struct netr_SamInfo3 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_SamInfo3(struct ndr_pull *ndr, int ndr_flags, struct netr_SamInfo3 *r);
_PUBLIC_ void ndr_print_netr_SamInfo3(struct ndr_print *ndr, const char *name, const struct netr_SamInfo3 *r);
_PUBLIC_ void ndr_print_netr_SamInfo6(struct ndr_print *ndr, const char *name, const struct netr_SamInfo6 *r);
_PUBLIC_ void ndr_print_netr_PacInfo(struct ndr_print *ndr, const char *name, const struct netr_PacInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_Validation(struct ndr_push *ndr, int ndr_flags, const union netr_Validation *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_Validation(struct ndr_pull *ndr, int ndr_flags, union netr_Validation *r);
_PUBLIC_ void ndr_print_netr_Validation(struct ndr_print *ndr, const char *name, const union netr_Validation *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_Credential(struct ndr_push *ndr, int ndr_flags, const struct netr_Credential *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_Credential(struct ndr_pull *ndr, int ndr_flags, struct netr_Credential *r);
_PUBLIC_ void ndr_print_netr_Credential(struct ndr_print *ndr, const char *name, const struct netr_Credential *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_Authenticator(struct ndr_push *ndr, int ndr_flags, const struct netr_Authenticator *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_Authenticator(struct ndr_pull *ndr, int ndr_flags, struct netr_Authenticator *r);
_PUBLIC_ void ndr_print_netr_Authenticator(struct ndr_print *ndr, const char *name, const struct netr_Authenticator *r);
_PUBLIC_ void ndr_print_netr_LogonLevel(struct ndr_print *ndr, const char *name, enum netr_LogonLevel r);
_PUBLIC_ void ndr_print_netr_DELTA_DELETE_USER(struct ndr_print *ndr, const char *name, const struct netr_DELTA_DELETE_USER *r);
_PUBLIC_ void ndr_print_netr_USER_KEY16(struct ndr_print *ndr, const char *name, const struct netr_USER_KEY16 *r);
_PUBLIC_ void ndr_print_netr_PasswordHistory(struct ndr_print *ndr, const char *name, const struct netr_PasswordHistory *r);
_PUBLIC_ void ndr_print_netr_USER_KEYS2(struct ndr_print *ndr, const char *name, const struct netr_USER_KEYS2 *r);
_PUBLIC_ void ndr_print_netr_USER_KEY_UNION(struct ndr_print *ndr, const char *name, const struct netr_USER_KEY_UNION *r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_USER_KEYS(struct ndr_push *ndr, int ndr_flags, const struct netr_USER_KEYS *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_USER_KEYS(struct ndr_pull *ndr, int ndr_flags, struct netr_USER_KEYS *r);
_PUBLIC_ void ndr_print_netr_USER_KEYS(struct ndr_print *ndr, const char *name, const struct netr_USER_KEYS *r);
_PUBLIC_ void ndr_print_netr_USER_PRIVATE_INFO(struct ndr_print *ndr, const char *name, const struct netr_USER_PRIVATE_INFO *r);
_PUBLIC_ void ndr_print_netr_DELTA_USER(struct ndr_print *ndr, const char *name, const struct netr_DELTA_USER *r);
_PUBLIC_ void ndr_print_netr_DELTA_DOMAIN(struct ndr_print *ndr, const char *name, const struct netr_DELTA_DOMAIN *r);
_PUBLIC_ void ndr_print_netr_DELTA_GROUP(struct ndr_print *ndr, const char *name, const struct netr_DELTA_GROUP *r);
_PUBLIC_ void ndr_print_netr_DELTA_RENAME(struct ndr_print *ndr, const char *name, const struct netr_DELTA_RENAME *r);
_PUBLIC_ void ndr_print_netr_DELTA_GROUP_MEMBER(struct ndr_print *ndr, const char *name, const struct netr_DELTA_GROUP_MEMBER *r);
_PUBLIC_ void ndr_print_netr_DELTA_ALIAS(struct ndr_print *ndr, const char *name, const struct netr_DELTA_ALIAS *r);
_PUBLIC_ void ndr_print_netr_DELTA_ALIAS_MEMBER(struct ndr_print *ndr, const char *name, const struct netr_DELTA_ALIAS_MEMBER *r);
_PUBLIC_ void ndr_print_netr_QUOTA_LIMITS(struct ndr_print *ndr, const char *name, const struct netr_QUOTA_LIMITS *r);
_PUBLIC_ void ndr_print_netr_DELTA_POLICY(struct ndr_print *ndr, const char *name, const struct netr_DELTA_POLICY *r);
_PUBLIC_ void ndr_print_netr_DELTA_TRUSTED_DOMAIN(struct ndr_print *ndr, const char *name, const struct netr_DELTA_TRUSTED_DOMAIN *r);
_PUBLIC_ void ndr_print_netr_DELTA_DELETE_TRUST(struct ndr_print *ndr, const char *name, const struct netr_DELTA_DELETE_TRUST *r);
_PUBLIC_ void ndr_print_netr_DELTA_ACCOUNT(struct ndr_print *ndr, const char *name, const struct netr_DELTA_ACCOUNT *r);
_PUBLIC_ void ndr_print_netr_DELTA_DELETE_ACCOUNT(struct ndr_print *ndr, const char *name, const struct netr_DELTA_DELETE_ACCOUNT *r);
_PUBLIC_ void ndr_print_netr_DELTA_DELETE_SECRET(struct ndr_print *ndr, const char *name, const struct netr_DELTA_DELETE_SECRET *r);
_PUBLIC_ void ndr_print_netr_CIPHER_VALUE(struct ndr_print *ndr, const char *name, const struct netr_CIPHER_VALUE *r);
_PUBLIC_ void ndr_print_netr_DELTA_SECRET(struct ndr_print *ndr, const char *name, const struct netr_DELTA_SECRET *r);
_PUBLIC_ void ndr_print_netr_DeltaEnum(struct ndr_print *ndr, const char *name, enum netr_DeltaEnum r);
_PUBLIC_ void ndr_print_netr_DELTA_UNION(struct ndr_print *ndr, const char *name, const union netr_DELTA_UNION *r);
_PUBLIC_ void ndr_print_netr_DELTA_ID_UNION(struct ndr_print *ndr, const char *name, const union netr_DELTA_ID_UNION *r);
_PUBLIC_ void ndr_print_netr_DELTA_ENUM(struct ndr_print *ndr, const char *name, const struct netr_DELTA_ENUM *r);
_PUBLIC_ void ndr_print_netr_DELTA_ENUM_ARRAY(struct ndr_print *ndr, const char *name, const struct netr_DELTA_ENUM_ARRAY *r);
_PUBLIC_ void ndr_print_netr_UAS_INFO_0(struct ndr_print *ndr, const char *name, const struct netr_UAS_INFO_0 *r);
_PUBLIC_ void ndr_print_netr_AccountBuffer(struct ndr_print *ndr, const char *name, const struct netr_AccountBuffer *r);
_PUBLIC_ void ndr_print_netr_InfoFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_NETLOGON_INFO_1(struct ndr_print *ndr, const char *name, const struct netr_NETLOGON_INFO_1 *r);
_PUBLIC_ void ndr_print_netr_NETLOGON_INFO_2(struct ndr_print *ndr, const char *name, const struct netr_NETLOGON_INFO_2 *r);
_PUBLIC_ void ndr_print_netr_NETLOGON_INFO_3(struct ndr_print *ndr, const char *name, const struct netr_NETLOGON_INFO_3 *r);
_PUBLIC_ void ndr_print_netr_CONTROL_QUERY_INFORMATION(struct ndr_print *ndr, const char *name, const union netr_CONTROL_QUERY_INFORMATION *r);
_PUBLIC_ void ndr_print_netr_LogonControlCode(struct ndr_print *ndr, const char *name, enum netr_LogonControlCode r);
_PUBLIC_ void ndr_print_netr_CONTROL_DATA_INFORMATION(struct ndr_print *ndr, const char *name, const union netr_CONTROL_DATA_INFORMATION *r);
_PUBLIC_ void ndr_print_netr_NegotiateFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_Blob(struct ndr_print *ndr, const char *name, const struct netr_Blob *r);
_PUBLIC_ void ndr_print_netr_DsRGetDCName_flags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_DsRGetDCNameInfo_AddressType(struct ndr_print *ndr, const char *name, enum netr_DsRGetDCNameInfo_AddressType r);
_PUBLIC_ void ndr_print_netr_DsR_DcFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_push_netr_DsRGetDCNameInfo(struct ndr_push *ndr, int ndr_flags, const struct netr_DsRGetDCNameInfo *r);
_PUBLIC_ enum ndr_err_code ndr_pull_netr_DsRGetDCNameInfo(struct ndr_pull *ndr, int ndr_flags, struct netr_DsRGetDCNameInfo *r);
_PUBLIC_ void ndr_print_netr_DsRGetDCNameInfo(struct ndr_print *ndr, const char *name, const struct netr_DsRGetDCNameInfo *r);
_PUBLIC_ void ndr_print_netr_BinaryString(struct ndr_print *ndr, const char *name, const struct netr_BinaryString *r);
_PUBLIC_ void ndr_print_netr_DomainQuery1(struct ndr_print *ndr, const char *name, const struct netr_DomainQuery1 *r);
_PUBLIC_ void ndr_print_netr_DomainQuery(struct ndr_print *ndr, const char *name, const union netr_DomainQuery *r);
_PUBLIC_ void ndr_print_netr_DomainTrustInfo(struct ndr_print *ndr, const char *name, const struct netr_DomainTrustInfo *r);
_PUBLIC_ void ndr_print_netr_DomainInfo1(struct ndr_print *ndr, const char *name, const struct netr_DomainInfo1 *r);
_PUBLIC_ void ndr_print_netr_DomainInfo(struct ndr_print *ndr, const char *name, const union netr_DomainInfo *r);
_PUBLIC_ void ndr_print_netr_CryptPassword(struct ndr_print *ndr, const char *name, const struct netr_CryptPassword *r);
_PUBLIC_ void ndr_print_netr_DsRAddressToSitenamesWCtr(struct ndr_print *ndr, const char *name, const struct netr_DsRAddressToSitenamesWCtr *r);
_PUBLIC_ void ndr_print_netr_DsRAddress(struct ndr_print *ndr, const char *name, const struct netr_DsRAddress *r);
_PUBLIC_ void ndr_print_netr_TrustFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_TrustType(struct ndr_print *ndr, const char *name, enum netr_TrustType r);
_PUBLIC_ void ndr_print_netr_TrustAttributes(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_netr_DomainTrust(struct ndr_print *ndr, const char *name, const struct netr_DomainTrust *r);
_PUBLIC_ void ndr_print_netr_DomainTrustList(struct ndr_print *ndr, const char *name, const struct netr_DomainTrustList *r);
_PUBLIC_ void ndr_print_netr_DsRAddressToSitenamesExWCtr(struct ndr_print *ndr, const char *name, const struct netr_DsRAddressToSitenamesExWCtr *r);
_PUBLIC_ void ndr_print_DcSitesCtr(struct ndr_print *ndr, const char *name, const struct DcSitesCtr *r);
_PUBLIC_ void ndr_print_netr_LogonUasLogon(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonUasLogon *r);
_PUBLIC_ void ndr_print_netr_LogonUasLogoff(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonUasLogoff *r);
_PUBLIC_ void ndr_print_netr_LogonSamLogon(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonSamLogon *r);
_PUBLIC_ void ndr_print_netr_LogonSamLogoff(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonSamLogoff *r);
_PUBLIC_ void ndr_print_netr_ServerReqChallenge(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerReqChallenge *r);
_PUBLIC_ void ndr_print_netr_ServerAuthenticate(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerAuthenticate *r);
_PUBLIC_ void ndr_print_netr_ServerPasswordSet(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerPasswordSet *r);
_PUBLIC_ void ndr_print_netr_DatabaseDeltas(struct ndr_print *ndr, const char *name, int flags, const struct netr_DatabaseDeltas *r);
_PUBLIC_ void ndr_print_netr_DatabaseSync(struct ndr_print *ndr, const char *name, int flags, const struct netr_DatabaseSync *r);
_PUBLIC_ void ndr_print_netr_AccountDeltas(struct ndr_print *ndr, const char *name, int flags, const struct netr_AccountDeltas *r);
_PUBLIC_ void ndr_print_netr_AccountSync(struct ndr_print *ndr, const char *name, int flags, const struct netr_AccountSync *r);
_PUBLIC_ void ndr_print_netr_GetDcName(struct ndr_print *ndr, const char *name, int flags, const struct netr_GetDcName *r);
_PUBLIC_ void ndr_print_netr_LogonControl(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonControl *r);
_PUBLIC_ void ndr_print_netr_GetAnyDCName(struct ndr_print *ndr, const char *name, int flags, const struct netr_GetAnyDCName *r);
_PUBLIC_ void ndr_print_netr_LogonControl2(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonControl2 *r);
_PUBLIC_ void ndr_print_netr_ServerAuthenticate2(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerAuthenticate2 *r);
_PUBLIC_ void ndr_print_netr_DatabaseSync2(struct ndr_print *ndr, const char *name, int flags, const struct netr_DatabaseSync2 *r);
_PUBLIC_ void ndr_print_netr_DatabaseRedo(struct ndr_print *ndr, const char *name, int flags, const struct netr_DatabaseRedo *r);
_PUBLIC_ void ndr_print_netr_LogonControl2Ex(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonControl2Ex *r);
_PUBLIC_ void ndr_print_netr_NetrEnumerateTrustedDomains(struct ndr_print *ndr, const char *name, int flags, const struct netr_NetrEnumerateTrustedDomains *r);
_PUBLIC_ void ndr_print_netr_DsRGetDCName(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRGetDCName *r);
_PUBLIC_ void ndr_print_netr_Capabilities(struct ndr_print *ndr, const char *name, const union netr_Capabilities *r);
_PUBLIC_ void ndr_print_netr_NETRLOGONSETSERVICEBITS(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRLOGONSETSERVICEBITS *r);
_PUBLIC_ void ndr_print_netr_LogonGetTrustRid(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonGetTrustRid *r);
_PUBLIC_ void ndr_print_netr_NETRLOGONCOMPUTESERVERDIGEST(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRLOGONCOMPUTESERVERDIGEST *r);
_PUBLIC_ void ndr_print_netr_NETRLOGONCOMPUTECLIENTDIGEST(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRLOGONCOMPUTECLIENTDIGEST *r);
_PUBLIC_ void ndr_print_netr_ServerAuthenticate3(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerAuthenticate3 *r);
_PUBLIC_ void ndr_print_netr_DsRGetDCNameEx(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRGetDCNameEx *r);
_PUBLIC_ void ndr_print_netr_DsRGetSiteName(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRGetSiteName *r);
_PUBLIC_ void ndr_print_netr_LogonGetDomainInfo(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonGetDomainInfo *r);
_PUBLIC_ void ndr_print_netr_ServerPasswordSet2(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerPasswordSet2 *r);
_PUBLIC_ void ndr_print_netr_ServerPasswordGet(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerPasswordGet *r);
_PUBLIC_ void ndr_print_netr_NETRLOGONSENDTOSAM(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRLOGONSENDTOSAM *r);
_PUBLIC_ void ndr_print_netr_DsRAddressToSitenamesW(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRAddressToSitenamesW *r);
_PUBLIC_ void ndr_print_netr_DsRGetDCNameEx2(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRGetDCNameEx2 *r);
_PUBLIC_ void ndr_print_netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN *r);
_PUBLIC_ void ndr_print_netr_NetrEnumerateTrustedDomainsEx(struct ndr_print *ndr, const char *name, int flags, const struct netr_NetrEnumerateTrustedDomainsEx *r);
_PUBLIC_ void ndr_print_netr_DsRAddressToSitenamesExW(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRAddressToSitenamesExW *r);
_PUBLIC_ void ndr_print_netr_DsrGetDcSiteCoverageW(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsrGetDcSiteCoverageW *r);
_PUBLIC_ void ndr_print_netr_LogonSamLogonEx(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonSamLogonEx *r);
_PUBLIC_ void ndr_print_netr_DsrEnumerateDomainTrusts(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsrEnumerateDomainTrusts *r);
_PUBLIC_ void ndr_print_netr_DsrDeregisterDNSHostRecords(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsrDeregisterDNSHostRecords *r);
_PUBLIC_ void ndr_print_netr_ServerTrustPasswordsGet(struct ndr_print *ndr, const char *name, int flags, const struct netr_ServerTrustPasswordsGet *r);
_PUBLIC_ void ndr_print_netr_DsRGetForestTrustInformation(struct ndr_print *ndr, const char *name, int flags, const struct netr_DsRGetForestTrustInformation *r);
_PUBLIC_ void ndr_print_netr_GetForestTrustInformation(struct ndr_print *ndr, const char *name, int flags, const struct netr_GetForestTrustInformation *r);
_PUBLIC_ void ndr_print_netr_LogonSamLogonWithFlags(struct ndr_print *ndr, const char *name, int flags, const struct netr_LogonSamLogonWithFlags *r);
_PUBLIC_ void ndr_print_netr_NETRSERVERGETTRUSTINFO(struct ndr_print *ndr, const char *name, int flags, const struct netr_NETRSERVERGETTRUSTINFO *r);

/* The following definitions come from librpc/gen_ndr/ndr_notify.c  */

_PUBLIC_ enum ndr_err_code ndr_push_notify_entry(struct ndr_push *ndr, int ndr_flags, const struct notify_entry *r);
_PUBLIC_ enum ndr_err_code ndr_pull_notify_entry(struct ndr_pull *ndr, int ndr_flags, struct notify_entry *r);
_PUBLIC_ void ndr_print_notify_entry(struct ndr_print *ndr, const char *name, const struct notify_entry *r);
_PUBLIC_ void ndr_print_notify_depth(struct ndr_print *ndr, const char *name, const struct notify_depth *r);
_PUBLIC_ enum ndr_err_code ndr_push_notify_array(struct ndr_push *ndr, int ndr_flags, const struct notify_array *r);
_PUBLIC_ enum ndr_err_code ndr_pull_notify_array(struct ndr_pull *ndr, int ndr_flags, struct notify_array *r);
_PUBLIC_ void ndr_print_notify_array(struct ndr_print *ndr, const char *name, const struct notify_array *r);
_PUBLIC_ enum ndr_err_code ndr_push_notify_event(struct ndr_push *ndr, int ndr_flags, const struct notify_event *r);
_PUBLIC_ enum ndr_err_code ndr_pull_notify_event(struct ndr_pull *ndr, int ndr_flags, struct notify_event *r);
_PUBLIC_ void ndr_print_notify_event(struct ndr_print *ndr, const char *name, const struct notify_event *r);

/* The following definitions come from librpc/gen_ndr/ndr_ntsvcs.c  */

_PUBLIC_ void ndr_print_PNP_HwProfInfo(struct ndr_print *ndr, const char *name, const struct PNP_HwProfInfo *r);
_PUBLIC_ void ndr_print_PNP_Disconnect(struct ndr_print *ndr, const char *name, int flags, const struct PNP_Disconnect *r);
_PUBLIC_ void ndr_print_PNP_Connect(struct ndr_print *ndr, const char *name, int flags, const struct PNP_Connect *r);
_PUBLIC_ void ndr_print_PNP_GetVersion(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetVersion *r);
_PUBLIC_ void ndr_print_PNP_GetGlobalState(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetGlobalState *r);
_PUBLIC_ void ndr_print_PNP_InitDetection(struct ndr_print *ndr, const char *name, int flags, const struct PNP_InitDetection *r);
_PUBLIC_ void ndr_print_PNP_ReportLogOn(struct ndr_print *ndr, const char *name, int flags, const struct PNP_ReportLogOn *r);
_PUBLIC_ void ndr_print_PNP_ValidateDeviceInstance(struct ndr_print *ndr, const char *name, int flags, const struct PNP_ValidateDeviceInstance *r);
_PUBLIC_ void ndr_print_PNP_GetRootDeviceInstance(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetRootDeviceInstance *r);
_PUBLIC_ void ndr_print_PNP_GetRelatedDeviceInstance(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetRelatedDeviceInstance *r);
_PUBLIC_ void ndr_print_PNP_EnumerateSubKeys(struct ndr_print *ndr, const char *name, int flags, const struct PNP_EnumerateSubKeys *r);
_PUBLIC_ void ndr_print_PNP_GetDeviceList(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetDeviceList *r);
_PUBLIC_ void ndr_print_PNP_GetDeviceListSize(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetDeviceListSize *r);
_PUBLIC_ void ndr_print_PNP_GetDepth(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetDepth *r);
_PUBLIC_ void ndr_print_PNP_GetDeviceRegProp(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetDeviceRegProp *r);
_PUBLIC_ void ndr_print_PNP_SetDeviceRegProp(struct ndr_print *ndr, const char *name, int flags, const struct PNP_SetDeviceRegProp *r);
_PUBLIC_ void ndr_print_PNP_GetClassInstance(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetClassInstance *r);
_PUBLIC_ void ndr_print_PNP_CreateKey(struct ndr_print *ndr, const char *name, int flags, const struct PNP_CreateKey *r);
_PUBLIC_ void ndr_print_PNP_DeleteRegistryKey(struct ndr_print *ndr, const char *name, int flags, const struct PNP_DeleteRegistryKey *r);
_PUBLIC_ void ndr_print_PNP_GetClassCount(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetClassCount *r);
_PUBLIC_ void ndr_print_PNP_GetClassName(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetClassName *r);
_PUBLIC_ void ndr_print_PNP_DeleteClassKey(struct ndr_print *ndr, const char *name, int flags, const struct PNP_DeleteClassKey *r);
_PUBLIC_ void ndr_print_PNP_GetInterfaceDeviceAlias(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetInterfaceDeviceAlias *r);
_PUBLIC_ void ndr_print_PNP_GetInterfaceDeviceList(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetInterfaceDeviceList *r);
_PUBLIC_ void ndr_print_PNP_GetInterfaceDeviceListSize(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetInterfaceDeviceListSize *r);
_PUBLIC_ void ndr_print_PNP_RegisterDeviceClassAssociation(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RegisterDeviceClassAssociation *r);
_PUBLIC_ void ndr_print_PNP_UnregisterDeviceClassAssociation(struct ndr_print *ndr, const char *name, int flags, const struct PNP_UnregisterDeviceClassAssociation *r);
_PUBLIC_ void ndr_print_PNP_GetClassRegProp(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetClassRegProp *r);
_PUBLIC_ void ndr_print_PNP_SetClassRegProp(struct ndr_print *ndr, const char *name, int flags, const struct PNP_SetClassRegProp *r);
_PUBLIC_ void ndr_print_PNP_CreateDevInst(struct ndr_print *ndr, const char *name, int flags, const struct PNP_CreateDevInst *r);
_PUBLIC_ void ndr_print_PNP_DeviceInstanceAction(struct ndr_print *ndr, const char *name, int flags, const struct PNP_DeviceInstanceAction *r);
_PUBLIC_ void ndr_print_PNP_GetDeviceStatus(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetDeviceStatus *r);
_PUBLIC_ void ndr_print_PNP_SetDeviceProblem(struct ndr_print *ndr, const char *name, int flags, const struct PNP_SetDeviceProblem *r);
_PUBLIC_ void ndr_print_PNP_DisableDevInst(struct ndr_print *ndr, const char *name, int flags, const struct PNP_DisableDevInst *r);
_PUBLIC_ void ndr_print_PNP_UninstallDevInst(struct ndr_print *ndr, const char *name, int flags, const struct PNP_UninstallDevInst *r);
_PUBLIC_ void ndr_print_PNP_AddID(struct ndr_print *ndr, const char *name, int flags, const struct PNP_AddID *r);
_PUBLIC_ void ndr_print_PNP_RegisterDriver(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RegisterDriver *r);
_PUBLIC_ void ndr_print_PNP_QueryRemove(struct ndr_print *ndr, const char *name, int flags, const struct PNP_QueryRemove *r);
_PUBLIC_ void ndr_print_PNP_RequestDeviceEject(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RequestDeviceEject *r);
_PUBLIC_ void ndr_print_PNP_IsDockStationPresent(struct ndr_print *ndr, const char *name, int flags, const struct PNP_IsDockStationPresent *r);
_PUBLIC_ void ndr_print_PNP_RequestEjectPC(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RequestEjectPC *r);
_PUBLIC_ void ndr_print_PNP_HwProfFlags(struct ndr_print *ndr, const char *name, int flags, const struct PNP_HwProfFlags *r);
_PUBLIC_ void ndr_print_PNP_GetHwProfInfo(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetHwProfInfo *r);
_PUBLIC_ void ndr_print_PNP_AddEmptyLogConf(struct ndr_print *ndr, const char *name, int flags, const struct PNP_AddEmptyLogConf *r);
_PUBLIC_ void ndr_print_PNP_FreeLogConf(struct ndr_print *ndr, const char *name, int flags, const struct PNP_FreeLogConf *r);
_PUBLIC_ void ndr_print_PNP_GetFirstLogConf(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetFirstLogConf *r);
_PUBLIC_ void ndr_print_PNP_GetNextLogConf(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetNextLogConf *r);
_PUBLIC_ void ndr_print_PNP_GetLogConfPriority(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetLogConfPriority *r);
_PUBLIC_ void ndr_print_PNP_AddResDes(struct ndr_print *ndr, const char *name, int flags, const struct PNP_AddResDes *r);
_PUBLIC_ void ndr_print_PNP_FreeResDes(struct ndr_print *ndr, const char *name, int flags, const struct PNP_FreeResDes *r);
_PUBLIC_ void ndr_print_PNP_GetNextResDes(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetNextResDes *r);
_PUBLIC_ void ndr_print_PNP_GetResDesData(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetResDesData *r);
_PUBLIC_ void ndr_print_PNP_GetResDesDataSize(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetResDesDataSize *r);
_PUBLIC_ void ndr_print_PNP_ModifyResDes(struct ndr_print *ndr, const char *name, int flags, const struct PNP_ModifyResDes *r);
_PUBLIC_ void ndr_print_PNP_DetectResourceLimit(struct ndr_print *ndr, const char *name, int flags, const struct PNP_DetectResourceLimit *r);
_PUBLIC_ void ndr_print_PNP_QueryResConfList(struct ndr_print *ndr, const char *name, int flags, const struct PNP_QueryResConfList *r);
_PUBLIC_ void ndr_print_PNP_SetHwProf(struct ndr_print *ndr, const char *name, int flags, const struct PNP_SetHwProf *r);
_PUBLIC_ void ndr_print_PNP_QueryArbitratorFreeData(struct ndr_print *ndr, const char *name, int flags, const struct PNP_QueryArbitratorFreeData *r);
_PUBLIC_ void ndr_print_PNP_QueryArbitratorFreeSize(struct ndr_print *ndr, const char *name, int flags, const struct PNP_QueryArbitratorFreeSize *r);
_PUBLIC_ void ndr_print_PNP_RunDetection(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RunDetection *r);
_PUBLIC_ void ndr_print_PNP_RegisterNotification(struct ndr_print *ndr, const char *name, int flags, const struct PNP_RegisterNotification *r);
_PUBLIC_ void ndr_print_PNP_UnregisterNotification(struct ndr_print *ndr, const char *name, int flags, const struct PNP_UnregisterNotification *r);
_PUBLIC_ void ndr_print_PNP_GetCustomDevProp(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetCustomDevProp *r);
_PUBLIC_ void ndr_print_PNP_GetVersionInternal(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetVersionInternal *r);
_PUBLIC_ void ndr_print_PNP_GetBlockedDriverInfo(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetBlockedDriverInfo *r);
_PUBLIC_ void ndr_print_PNP_GetServerSideDeviceInstallFlags(struct ndr_print *ndr, const char *name, int flags, const struct PNP_GetServerSideDeviceInstallFlags *r);

/* The following definitions come from librpc/gen_ndr/ndr_samr.c  */

_PUBLIC_ enum ndr_err_code ndr_push_samr_AcctFlags(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_AcctFlags(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_samr_AcctFlags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_ConnectAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_UserAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_DomainAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_GroupAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_AliasAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_SamEntry(struct ndr_print *ndr, const char *name, const struct samr_SamEntry *r);
_PUBLIC_ void ndr_print_samr_SamArray(struct ndr_print *ndr, const char *name, const struct samr_SamArray *r);
_PUBLIC_ void ndr_print_samr_Role(struct ndr_print *ndr, const char *name, enum samr_Role r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_PasswordProperties(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_PasswordProperties(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_samr_PasswordProperties(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_DomInfo1(struct ndr_print *ndr, const char *name, const struct samr_DomInfo1 *r);
_PUBLIC_ void ndr_print_samr_DomInfo2(struct ndr_print *ndr, const char *name, const struct samr_DomInfo2 *r);
_PUBLIC_ void ndr_print_samr_DomInfo3(struct ndr_print *ndr, const char *name, const struct samr_DomInfo3 *r);
_PUBLIC_ void ndr_print_samr_DomInfo4(struct ndr_print *ndr, const char *name, const struct samr_DomInfo4 *r);
_PUBLIC_ void ndr_print_samr_DomInfo5(struct ndr_print *ndr, const char *name, const struct samr_DomInfo5 *r);
_PUBLIC_ void ndr_print_samr_DomInfo6(struct ndr_print *ndr, const char *name, const struct samr_DomInfo6 *r);
_PUBLIC_ void ndr_print_samr_DomInfo7(struct ndr_print *ndr, const char *name, const struct samr_DomInfo7 *r);
_PUBLIC_ void ndr_print_samr_DomInfo8(struct ndr_print *ndr, const char *name, const struct samr_DomInfo8 *r);
_PUBLIC_ void ndr_print_samr_DomInfo9(struct ndr_print *ndr, const char *name, const struct samr_DomInfo9 *r);
_PUBLIC_ void ndr_print_samr_DomInfo11(struct ndr_print *ndr, const char *name, const struct samr_DomInfo11 *r);
_PUBLIC_ void ndr_print_samr_DomInfo12(struct ndr_print *ndr, const char *name, const struct samr_DomInfo12 *r);
_PUBLIC_ void ndr_print_samr_DomInfo13(struct ndr_print *ndr, const char *name, const struct samr_DomInfo13 *r);
_PUBLIC_ void ndr_print_samr_DomainInfo(struct ndr_print *ndr, const char *name, const union samr_DomainInfo *r);
_PUBLIC_ void ndr_print_samr_Ids(struct ndr_print *ndr, const char *name, const struct samr_Ids *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_GroupAttrs(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_GroupAttrs(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_samr_GroupAttrs(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_GroupInfoAll(struct ndr_print *ndr, const char *name, const struct samr_GroupInfoAll *r);
_PUBLIC_ void ndr_print_samr_GroupInfoAttributes(struct ndr_print *ndr, const char *name, const struct samr_GroupInfoAttributes *r);
_PUBLIC_ void ndr_print_samr_GroupInfoEnum(struct ndr_print *ndr, const char *name, enum samr_GroupInfoEnum r);
_PUBLIC_ void ndr_print_samr_GroupInfo(struct ndr_print *ndr, const char *name, const union samr_GroupInfo *r);
_PUBLIC_ void ndr_print_samr_RidTypeArray(struct ndr_print *ndr, const char *name, const struct samr_RidTypeArray *r);
_PUBLIC_ void ndr_print_samr_AliasInfoAll(struct ndr_print *ndr, const char *name, const struct samr_AliasInfoAll *r);
_PUBLIC_ void ndr_print_samr_AliasInfoEnum(struct ndr_print *ndr, const char *name, enum samr_AliasInfoEnum r);
_PUBLIC_ void ndr_print_samr_AliasInfo(struct ndr_print *ndr, const char *name, const union samr_AliasInfo *r);
_PUBLIC_ void ndr_print_samr_UserInfo1(struct ndr_print *ndr, const char *name, const struct samr_UserInfo1 *r);
_PUBLIC_ void ndr_print_samr_UserInfo2(struct ndr_print *ndr, const char *name, const struct samr_UserInfo2 *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_LogonHours(struct ndr_push *ndr, int ndr_flags, const struct samr_LogonHours *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_LogonHours(struct ndr_pull *ndr, int ndr_flags, struct samr_LogonHours *r);
_PUBLIC_ void ndr_print_samr_LogonHours(struct ndr_print *ndr, const char *name, const struct samr_LogonHours *r);
_PUBLIC_ void ndr_print_samr_UserInfo3(struct ndr_print *ndr, const char *name, const struct samr_UserInfo3 *r);
_PUBLIC_ void ndr_print_samr_UserInfo4(struct ndr_print *ndr, const char *name, const struct samr_UserInfo4 *r);
_PUBLIC_ void ndr_print_samr_UserInfo5(struct ndr_print *ndr, const char *name, const struct samr_UserInfo5 *r);
_PUBLIC_ void ndr_print_samr_UserInfo6(struct ndr_print *ndr, const char *name, const struct samr_UserInfo6 *r);
_PUBLIC_ void ndr_print_samr_UserInfo7(struct ndr_print *ndr, const char *name, const struct samr_UserInfo7 *r);
_PUBLIC_ void ndr_print_samr_UserInfo8(struct ndr_print *ndr, const char *name, const struct samr_UserInfo8 *r);
_PUBLIC_ void ndr_print_samr_UserInfo9(struct ndr_print *ndr, const char *name, const struct samr_UserInfo9 *r);
_PUBLIC_ void ndr_print_samr_UserInfo10(struct ndr_print *ndr, const char *name, const struct samr_UserInfo10 *r);
_PUBLIC_ void ndr_print_samr_UserInfo11(struct ndr_print *ndr, const char *name, const struct samr_UserInfo11 *r);
_PUBLIC_ void ndr_print_samr_UserInfo12(struct ndr_print *ndr, const char *name, const struct samr_UserInfo12 *r);
_PUBLIC_ void ndr_print_samr_UserInfo13(struct ndr_print *ndr, const char *name, const struct samr_UserInfo13 *r);
_PUBLIC_ void ndr_print_samr_UserInfo14(struct ndr_print *ndr, const char *name, const struct samr_UserInfo14 *r);
_PUBLIC_ void ndr_print_samr_UserInfo16(struct ndr_print *ndr, const char *name, const struct samr_UserInfo16 *r);
_PUBLIC_ void ndr_print_samr_UserInfo17(struct ndr_print *ndr, const char *name, const struct samr_UserInfo17 *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_Password(struct ndr_push *ndr, int ndr_flags, const struct samr_Password *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_Password(struct ndr_pull *ndr, int ndr_flags, struct samr_Password *r);
_PUBLIC_ void ndr_print_samr_Password(struct ndr_print *ndr, const char *name, const struct samr_Password *r);
_PUBLIC_ void ndr_print_samr_UserInfo18(struct ndr_print *ndr, const char *name, const struct samr_UserInfo18 *r);
_PUBLIC_ void ndr_print_samr_UserInfo20(struct ndr_print *ndr, const char *name, const struct samr_UserInfo20 *r);
_PUBLIC_ void ndr_print_samr_FieldsPresent(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_UserInfo21(struct ndr_print *ndr, const char *name, const struct samr_UserInfo21 *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_CryptPassword(struct ndr_push *ndr, int ndr_flags, const struct samr_CryptPassword *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_CryptPassword(struct ndr_pull *ndr, int ndr_flags, struct samr_CryptPassword *r);
_PUBLIC_ void ndr_print_samr_CryptPassword(struct ndr_print *ndr, const char *name, const struct samr_CryptPassword *r);
_PUBLIC_ void ndr_print_samr_UserInfo23(struct ndr_print *ndr, const char *name, const struct samr_UserInfo23 *r);
_PUBLIC_ void ndr_print_samr_UserInfo24(struct ndr_print *ndr, const char *name, const struct samr_UserInfo24 *r);
_PUBLIC_ void ndr_print_samr_CryptPasswordEx(struct ndr_print *ndr, const char *name, const struct samr_CryptPasswordEx *r);
_PUBLIC_ void ndr_print_samr_UserInfo25(struct ndr_print *ndr, const char *name, const struct samr_UserInfo25 *r);
_PUBLIC_ void ndr_print_samr_UserInfo26(struct ndr_print *ndr, const char *name, const struct samr_UserInfo26 *r);
_PUBLIC_ void ndr_print_samr_UserInfo(struct ndr_print *ndr, const char *name, const union samr_UserInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_RidWithAttribute(struct ndr_push *ndr, int ndr_flags, const struct samr_RidWithAttribute *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_RidWithAttribute(struct ndr_pull *ndr, int ndr_flags, struct samr_RidWithAttribute *r);
_PUBLIC_ void ndr_print_samr_RidWithAttribute(struct ndr_print *ndr, const char *name, const struct samr_RidWithAttribute *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_RidWithAttributeArray(struct ndr_push *ndr, int ndr_flags, const struct samr_RidWithAttributeArray *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_RidWithAttributeArray(struct ndr_pull *ndr, int ndr_flags, struct samr_RidWithAttributeArray *r);
_PUBLIC_ void ndr_print_samr_RidWithAttributeArray(struct ndr_print *ndr, const char *name, const struct samr_RidWithAttributeArray *r);
_PUBLIC_ void ndr_print_samr_DispEntryGeneral(struct ndr_print *ndr, const char *name, const struct samr_DispEntryGeneral *r);
_PUBLIC_ void ndr_print_samr_DispInfoGeneral(struct ndr_print *ndr, const char *name, const struct samr_DispInfoGeneral *r);
_PUBLIC_ void ndr_print_samr_DispEntryFull(struct ndr_print *ndr, const char *name, const struct samr_DispEntryFull *r);
_PUBLIC_ void ndr_print_samr_DispInfoFull(struct ndr_print *ndr, const char *name, const struct samr_DispInfoFull *r);
_PUBLIC_ void ndr_print_samr_DispEntryFullGroup(struct ndr_print *ndr, const char *name, const struct samr_DispEntryFullGroup *r);
_PUBLIC_ void ndr_print_samr_DispInfoFullGroups(struct ndr_print *ndr, const char *name, const struct samr_DispInfoFullGroups *r);
_PUBLIC_ void ndr_print_samr_DispEntryAscii(struct ndr_print *ndr, const char *name, const struct samr_DispEntryAscii *r);
_PUBLIC_ void ndr_print_samr_DispInfoAscii(struct ndr_print *ndr, const char *name, const struct samr_DispInfoAscii *r);
_PUBLIC_ void ndr_print_samr_DispInfo(struct ndr_print *ndr, const char *name, const union samr_DispInfo *r);
_PUBLIC_ void ndr_print_samr_PwInfo(struct ndr_print *ndr, const char *name, const struct samr_PwInfo *r);
_PUBLIC_ void ndr_print_samr_ConnectVersion(struct ndr_print *ndr, const char *name, enum samr_ConnectVersion r);
_PUBLIC_ void ndr_print_samr_ChangeReject(struct ndr_print *ndr, const char *name, const struct samr_ChangeReject *r);
_PUBLIC_ void ndr_print_samr_ConnectInfo1(struct ndr_print *ndr, const char *name, const struct samr_ConnectInfo1 *r);
_PUBLIC_ void ndr_print_samr_ConnectInfo(struct ndr_print *ndr, const char *name, const union samr_ConnectInfo *r);
_PUBLIC_ void ndr_print_samr_ValidateFieldsPresent(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordLevel(struct ndr_print *ndr, const char *name, enum samr_ValidatePasswordLevel r);
_PUBLIC_ void ndr_print_samr_ValidationStatus(struct ndr_print *ndr, const char *name, enum samr_ValidationStatus r);
_PUBLIC_ void ndr_print_samr_ValidationBlob(struct ndr_print *ndr, const char *name, const struct samr_ValidationBlob *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordInfo(struct ndr_print *ndr, const char *name, const struct samr_ValidatePasswordInfo *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordRepCtr(struct ndr_print *ndr, const char *name, const struct samr_ValidatePasswordRepCtr *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordRep(struct ndr_print *ndr, const char *name, const union samr_ValidatePasswordRep *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordReq3(struct ndr_print *ndr, const char *name, const struct samr_ValidatePasswordReq3 *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordReq2(struct ndr_print *ndr, const char *name, const struct samr_ValidatePasswordReq2 *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordReq1(struct ndr_print *ndr, const char *name, const struct samr_ValidatePasswordReq1 *r);
_PUBLIC_ void ndr_print_samr_ValidatePasswordReq(struct ndr_print *ndr, const char *name, const union samr_ValidatePasswordReq *r);
_PUBLIC_ void ndr_print_samr_Connect(struct ndr_print *ndr, const char *name, int flags, const struct samr_Connect *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_Close(struct ndr_push *ndr, int flags, const struct samr_Close *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_Close(struct ndr_pull *ndr, int flags, struct samr_Close *r);
_PUBLIC_ void ndr_print_samr_Close(struct ndr_print *ndr, const char *name, int flags, const struct samr_Close *r);
_PUBLIC_ void ndr_print_samr_SetSecurity(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetSecurity *r);
_PUBLIC_ void ndr_print_samr_QuerySecurity(struct ndr_print *ndr, const char *name, int flags, const struct samr_QuerySecurity *r);
_PUBLIC_ void ndr_print_samr_Shutdown(struct ndr_print *ndr, const char *name, int flags, const struct samr_Shutdown *r);
_PUBLIC_ void ndr_print_samr_LookupDomain(struct ndr_print *ndr, const char *name, int flags, const struct samr_LookupDomain *r);
_PUBLIC_ void ndr_print_samr_EnumDomains(struct ndr_print *ndr, const char *name, int flags, const struct samr_EnumDomains *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_OpenDomain(struct ndr_push *ndr, int flags, const struct samr_OpenDomain *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_OpenDomain(struct ndr_pull *ndr, int flags, struct samr_OpenDomain *r);
_PUBLIC_ void ndr_print_samr_OpenDomain(struct ndr_print *ndr, const char *name, int flags, const struct samr_OpenDomain *r);
_PUBLIC_ void ndr_print_samr_QueryDomainInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryDomainInfo *r);
_PUBLIC_ void ndr_print_samr_SetDomainInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetDomainInfo *r);
_PUBLIC_ void ndr_print_samr_CreateDomainGroup(struct ndr_print *ndr, const char *name, int flags, const struct samr_CreateDomainGroup *r);
_PUBLIC_ void ndr_print_samr_EnumDomainGroups(struct ndr_print *ndr, const char *name, int flags, const struct samr_EnumDomainGroups *r);
_PUBLIC_ void ndr_print_samr_CreateUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_CreateUser *r);
_PUBLIC_ void ndr_print_samr_EnumDomainUsers(struct ndr_print *ndr, const char *name, int flags, const struct samr_EnumDomainUsers *r);
_PUBLIC_ void ndr_print_samr_CreateDomAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_CreateDomAlias *r);
_PUBLIC_ void ndr_print_samr_EnumDomainAliases(struct ndr_print *ndr, const char *name, int flags, const struct samr_EnumDomainAliases *r);
_PUBLIC_ void ndr_print_samr_GetAliasMembership(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetAliasMembership *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_LookupNames(struct ndr_push *ndr, int flags, const struct samr_LookupNames *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_LookupNames(struct ndr_pull *ndr, int flags, struct samr_LookupNames *r);
_PUBLIC_ void ndr_print_samr_LookupNames(struct ndr_print *ndr, const char *name, int flags, const struct samr_LookupNames *r);
_PUBLIC_ void ndr_print_samr_LookupRids(struct ndr_print *ndr, const char *name, int flags, const struct samr_LookupRids *r);
_PUBLIC_ void ndr_print_samr_OpenGroup(struct ndr_print *ndr, const char *name, int flags, const struct samr_OpenGroup *r);
_PUBLIC_ void ndr_print_samr_QueryGroupInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryGroupInfo *r);
_PUBLIC_ void ndr_print_samr_SetGroupInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetGroupInfo *r);
_PUBLIC_ void ndr_print_samr_AddGroupMember(struct ndr_print *ndr, const char *name, int flags, const struct samr_AddGroupMember *r);
_PUBLIC_ void ndr_print_samr_DeleteDomainGroup(struct ndr_print *ndr, const char *name, int flags, const struct samr_DeleteDomainGroup *r);
_PUBLIC_ void ndr_print_samr_DeleteGroupMember(struct ndr_print *ndr, const char *name, int flags, const struct samr_DeleteGroupMember *r);
_PUBLIC_ void ndr_print_samr_QueryGroupMember(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryGroupMember *r);
_PUBLIC_ void ndr_print_samr_SetMemberAttributesOfGroup(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetMemberAttributesOfGroup *r);
_PUBLIC_ void ndr_print_samr_OpenAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_OpenAlias *r);
_PUBLIC_ void ndr_print_samr_QueryAliasInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryAliasInfo *r);
_PUBLIC_ void ndr_print_samr_SetAliasInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetAliasInfo *r);
_PUBLIC_ void ndr_print_samr_DeleteDomAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_DeleteDomAlias *r);
_PUBLIC_ void ndr_print_samr_AddAliasMember(struct ndr_print *ndr, const char *name, int flags, const struct samr_AddAliasMember *r);
_PUBLIC_ void ndr_print_samr_DeleteAliasMember(struct ndr_print *ndr, const char *name, int flags, const struct samr_DeleteAliasMember *r);
_PUBLIC_ void ndr_print_samr_GetMembersInAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetMembersInAlias *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_OpenUser(struct ndr_push *ndr, int flags, const struct samr_OpenUser *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_OpenUser(struct ndr_pull *ndr, int flags, struct samr_OpenUser *r);
_PUBLIC_ void ndr_print_samr_OpenUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_OpenUser *r);
_PUBLIC_ void ndr_print_samr_DeleteUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_DeleteUser *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_QueryUserInfo(struct ndr_push *ndr, int flags, const struct samr_QueryUserInfo *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_QueryUserInfo(struct ndr_pull *ndr, int flags, struct samr_QueryUserInfo *r);
_PUBLIC_ void ndr_print_samr_QueryUserInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryUserInfo *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_SetUserInfo(struct ndr_push *ndr, int flags, const struct samr_SetUserInfo *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_SetUserInfo(struct ndr_pull *ndr, int flags, struct samr_SetUserInfo *r);
_PUBLIC_ void ndr_print_samr_SetUserInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetUserInfo *r);
_PUBLIC_ void ndr_print_samr_ChangePasswordUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_ChangePasswordUser *r);
_PUBLIC_ void ndr_print_samr_GetGroupsForUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetGroupsForUser *r);
_PUBLIC_ void ndr_print_samr_QueryDisplayInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryDisplayInfo *r);
_PUBLIC_ void ndr_print_samr_GetDisplayEnumerationIndex(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetDisplayEnumerationIndex *r);
_PUBLIC_ void ndr_print_samr_TestPrivateFunctionsDomain(struct ndr_print *ndr, const char *name, int flags, const struct samr_TestPrivateFunctionsDomain *r);
_PUBLIC_ void ndr_print_samr_TestPrivateFunctionsUser(struct ndr_print *ndr, const char *name, int flags, const struct samr_TestPrivateFunctionsUser *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_GetUserPwInfo(struct ndr_push *ndr, int flags, const struct samr_GetUserPwInfo *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_GetUserPwInfo(struct ndr_pull *ndr, int flags, struct samr_GetUserPwInfo *r);
_PUBLIC_ void ndr_print_samr_GetUserPwInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetUserPwInfo *r);
_PUBLIC_ void ndr_print_samr_RemoveMemberFromForeignDomain(struct ndr_print *ndr, const char *name, int flags, const struct samr_RemoveMemberFromForeignDomain *r);
_PUBLIC_ void ndr_print_samr_QueryDomainInfo2(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryDomainInfo2 *r);
_PUBLIC_ void ndr_print_samr_QueryUserInfo2(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryUserInfo2 *r);
_PUBLIC_ void ndr_print_samr_QueryDisplayInfo2(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryDisplayInfo2 *r);
_PUBLIC_ void ndr_print_samr_GetDisplayEnumerationIndex2(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetDisplayEnumerationIndex2 *r);
_PUBLIC_ void ndr_print_samr_CreateUser2(struct ndr_print *ndr, const char *name, int flags, const struct samr_CreateUser2 *r);
_PUBLIC_ void ndr_print_samr_QueryDisplayInfo3(struct ndr_print *ndr, const char *name, int flags, const struct samr_QueryDisplayInfo3 *r);
_PUBLIC_ void ndr_print_samr_AddMultipleMembersToAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_AddMultipleMembersToAlias *r);
_PUBLIC_ void ndr_print_samr_RemoveMultipleMembersFromAlias(struct ndr_print *ndr, const char *name, int flags, const struct samr_RemoveMultipleMembersFromAlias *r);
_PUBLIC_ void ndr_print_samr_OemChangePasswordUser2(struct ndr_print *ndr, const char *name, int flags, const struct samr_OemChangePasswordUser2 *r);
_PUBLIC_ void ndr_print_samr_ChangePasswordUser2(struct ndr_print *ndr, const char *name, int flags, const struct samr_ChangePasswordUser2 *r);
_PUBLIC_ void ndr_print_samr_GetDomPwInfo(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetDomPwInfo *r);
_PUBLIC_ void ndr_print_samr_Connect2(struct ndr_print *ndr, const char *name, int flags, const struct samr_Connect2 *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_SetUserInfo2(struct ndr_push *ndr, int flags, const struct samr_SetUserInfo2 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_SetUserInfo2(struct ndr_pull *ndr, int flags, struct samr_SetUserInfo2 *r);
_PUBLIC_ void ndr_print_samr_SetUserInfo2(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetUserInfo2 *r);
_PUBLIC_ void ndr_print_samr_SetBootKeyInformation(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetBootKeyInformation *r);
_PUBLIC_ void ndr_print_samr_GetBootKeyInformation(struct ndr_print *ndr, const char *name, int flags, const struct samr_GetBootKeyInformation *r);
_PUBLIC_ void ndr_print_samr_Connect3(struct ndr_print *ndr, const char *name, int flags, const struct samr_Connect3 *r);
_PUBLIC_ void ndr_print_samr_Connect4(struct ndr_print *ndr, const char *name, int flags, const struct samr_Connect4 *r);
_PUBLIC_ void ndr_print_samr_ChangePasswordUser3(struct ndr_print *ndr, const char *name, int flags, const struct samr_ChangePasswordUser3 *r);
_PUBLIC_ enum ndr_err_code ndr_push_samr_Connect5(struct ndr_push *ndr, int flags, const struct samr_Connect5 *r);
_PUBLIC_ enum ndr_err_code ndr_pull_samr_Connect5(struct ndr_pull *ndr, int flags, struct samr_Connect5 *r);
_PUBLIC_ void ndr_print_samr_Connect5(struct ndr_print *ndr, const char *name, int flags, const struct samr_Connect5 *r);
_PUBLIC_ void ndr_print_samr_RidToSid(struct ndr_print *ndr, const char *name, int flags, const struct samr_RidToSid *r);
_PUBLIC_ void ndr_print_samr_SetDsrmPassword(struct ndr_print *ndr, const char *name, int flags, const struct samr_SetDsrmPassword *r);
_PUBLIC_ void ndr_print_samr_ValidatePassword(struct ndr_print *ndr, const char *name, int flags, const struct samr_ValidatePassword *r);

/* The following definitions come from librpc/gen_ndr/ndr_security.c  */

_PUBLIC_ void ndr_print_security_ace_flags(struct ndr_print *ndr, const char *name, uint8_t r);
_PUBLIC_ void ndr_print_security_ace_type(struct ndr_print *ndr, const char *name, enum security_ace_type r);
_PUBLIC_ void ndr_print_security_ace_object_flags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_security_ace_object_type(struct ndr_print *ndr, const char *name, const union security_ace_object_type *r);
_PUBLIC_ void ndr_print_security_ace_object_inherited_type(struct ndr_print *ndr, const char *name, const union security_ace_object_inherited_type *r);
_PUBLIC_ void ndr_print_security_ace_object(struct ndr_print *ndr, const char *name, const struct security_ace_object *r);
_PUBLIC_ void ndr_print_security_ace_object_ctr(struct ndr_print *ndr, const char *name, const union security_ace_object_ctr *r);
_PUBLIC_ enum ndr_err_code ndr_push_security_ace(struct ndr_push *ndr, int ndr_flags, const struct security_ace *r);
_PUBLIC_ enum ndr_err_code ndr_pull_security_ace(struct ndr_pull *ndr, int ndr_flags, struct security_ace *r);
_PUBLIC_ void ndr_print_security_ace(struct ndr_print *ndr, const char *name, const struct security_ace *r);
_PUBLIC_ void ndr_print_security_acl_revision(struct ndr_print *ndr, const char *name, enum security_acl_revision r);
_PUBLIC_ enum ndr_err_code ndr_push_security_acl(struct ndr_push *ndr, int ndr_flags, const struct security_acl *r);
_PUBLIC_ enum ndr_err_code ndr_pull_security_acl(struct ndr_pull *ndr, int ndr_flags, struct security_acl *r);
_PUBLIC_ void ndr_print_security_acl(struct ndr_print *ndr, const char *name, const struct security_acl *r);
_PUBLIC_ void ndr_print_security_descriptor_revision(struct ndr_print *ndr, const char *name, enum security_descriptor_revision r);
_PUBLIC_ void ndr_print_security_descriptor_type(struct ndr_print *ndr, const char *name, uint16_t r);
_PUBLIC_ enum ndr_err_code ndr_push_security_descriptor(struct ndr_push *ndr, int ndr_flags, const struct security_descriptor *r);
_PUBLIC_ enum ndr_err_code ndr_pull_security_descriptor(struct ndr_pull *ndr, int ndr_flags, struct security_descriptor *r);
_PUBLIC_ void ndr_print_security_descriptor(struct ndr_print *ndr, const char *name, const struct security_descriptor *r);
_PUBLIC_ enum ndr_err_code ndr_push_sec_desc_buf(struct ndr_push *ndr, int ndr_flags, const struct sec_desc_buf *r);
_PUBLIC_ enum ndr_err_code ndr_pull_sec_desc_buf(struct ndr_pull *ndr, int ndr_flags, struct sec_desc_buf *r);
_PUBLIC_ void ndr_print_sec_desc_buf(struct ndr_print *ndr, const char *name, const struct sec_desc_buf *r);
_PUBLIC_ enum ndr_err_code ndr_push_security_token(struct ndr_push *ndr, int ndr_flags, const struct security_token *r);
_PUBLIC_ enum ndr_err_code ndr_pull_security_token(struct ndr_pull *ndr, int ndr_flags, struct security_token *r);
_PUBLIC_ void ndr_print_security_token(struct ndr_print *ndr, const char *name, const struct security_token *r);
_PUBLIC_ enum ndr_err_code ndr_push_security_secinfo(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_security_secinfo(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_security_secinfo(struct ndr_print *ndr, const char *name, uint32_t r);

/* The following definitions come from librpc/gen_ndr/ndr_srvsvc.c  */

_PUBLIC_ void ndr_print_srvsvc_NetCharDevInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetCharDevInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetCharDevCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevQInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevQCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevQInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetCharDevQCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetCharDevQInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetCharDevQCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetConnInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetConnCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetConnInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetConnCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetConnCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnInfoCtr(struct ndr_print *ndr, const char *name, const struct srvsvc_NetConnInfoCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileInfo2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetFileInfo2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileCtr2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetFileCtr2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileInfo3(struct ndr_print *ndr, const char *name, const struct srvsvc_NetFileInfo3 *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileCtr3(struct ndr_print *ndr, const char *name, const struct srvsvc_NetFileCtr3 *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetFileInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetFileCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileInfoCtr(struct ndr_print *ndr, const char *name, const struct srvsvc_NetFileInfoCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfo2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfo2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessCtr2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfo10(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfo10 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr10(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessCtr10 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfo502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfo502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessCtr502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetSessCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessInfoCtr(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSessInfoCtr *r);
_PUBLIC_ void ndr_print_srvsvc_ShareType(struct ndr_print *ndr, const char *name, enum srvsvc_ShareType r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo501(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo501 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr501(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr501 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo1004(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo1004 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1004(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1004 *r);
_PUBLIC_ void ndr_print_NetShareInfo1005Flags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo1005(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo1005 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1005(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1005 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo1006(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo1006 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1006(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1006 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo1007(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfo1007 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1007(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1007 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr1501(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareCtr1501 *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetShareInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetShareCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareInfoCtr(struct ndr_print *ndr, const char *name, const struct srvsvc_NetShareInfoCtr *r);
_PUBLIC_ enum ndr_err_code ndr_push_srvsvc_PlatformId(struct ndr_push *ndr, int ndr_flags, enum srvsvc_PlatformId r);
_PUBLIC_ enum ndr_err_code ndr_pull_srvsvc_PlatformId(struct ndr_pull *ndr, int ndr_flags, enum srvsvc_PlatformId *r);
_PUBLIC_ void ndr_print_srvsvc_PlatformId(struct ndr_print *ndr, const char *name, enum srvsvc_PlatformId r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo100(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo100 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo101(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo101 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo102(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo102 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo402(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo402 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo403(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo403 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo503(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo503 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo599(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo599 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1005(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1005 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1010(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1010 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1016(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1016 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1017(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1017 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1018(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1018 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1107(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1107 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1501(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1501 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1502(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1502 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1503(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1503 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1506(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1506 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1509(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1509 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1510(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1510 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1511(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1511 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1512(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1512 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1513(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1513 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1514(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1514 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1515(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1515 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1516(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1516 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1518(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1518 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1520(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1520 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1521(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1521 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1522(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1522 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1523(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1523 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1524(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1524 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1525(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1525 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1528(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1528 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1529(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1529 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1530(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1530 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1533(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1533 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1534(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1534 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1535(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1535 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1536(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1536 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1537(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1537 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1538(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1538 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1539(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1539 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1540(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1540 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1541(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1541 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1542(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1542 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1543(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1543 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1544(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1544 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1545(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1545 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1546(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1546 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1547(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1547 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1548(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1548 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1549(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1549 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1550(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1550 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1552(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1552 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1553(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1553 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1554(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1554 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1555(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1555 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo1556(struct ndr_print *ndr, const char *name, const struct srvsvc_NetSrvInfo1556 *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetSrvInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetDiskInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetDiskInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetDiskInfo(struct ndr_print *ndr, const char *name, const struct srvsvc_NetDiskInfo *r);
_PUBLIC_ void ndr_print_srvsvc_Statistics(struct ndr_print *ndr, const char *name, const struct srvsvc_Statistics *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportInfo0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportInfo0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportCtr0(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportCtr0 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportInfo1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportInfo1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportCtr1(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportCtr1 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportInfo2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportInfo2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportCtr2(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportCtr2 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportInfo3(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportInfo3 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportCtr3(struct ndr_print *ndr, const char *name, const struct srvsvc_NetTransportCtr3 *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportCtr(struct ndr_print *ndr, const char *name, const union srvsvc_NetTransportCtr *r);
_PUBLIC_ void ndr_print_srvsvc_NetRemoteTODInfo(struct ndr_print *ndr, const char *name, const struct srvsvc_NetRemoteTODInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportInfo(struct ndr_print *ndr, const char *name, const union srvsvc_NetTransportInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevGetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevControl(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevControl *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevQEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevQGetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQSetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevQSetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQPurge(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevQPurge *r);
_PUBLIC_ void ndr_print_srvsvc_NetCharDevQPurgeSelf(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetCharDevQPurgeSelf *r);
_PUBLIC_ void ndr_print_srvsvc_NetConnEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetConnEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetFileEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetFileGetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetFileClose(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetFileClose *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSessEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetSessDel(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSessDel *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareAdd(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareAdd *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareEnumAll(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareEnumAll *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareGetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareSetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareSetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareDel(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareDel *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareDelSticky(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareDelSticky *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareCheck(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareCheck *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSrvGetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetSrvSetInfo(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSrvSetInfo *r);
_PUBLIC_ void ndr_print_srvsvc_NetDiskEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetDiskEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetServerStatisticsGet(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetServerStatisticsGet *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportAdd(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetTransportAdd *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetTransportEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetTransportDel(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetTransportDel *r);
_PUBLIC_ void ndr_print_srvsvc_NetRemoteTOD(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetRemoteTOD *r);
_PUBLIC_ void ndr_print_srvsvc_NetSetServiceBits(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSetServiceBits *r);
_PUBLIC_ void ndr_print_srvsvc_NetPathType(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetPathType *r);
_PUBLIC_ void ndr_print_srvsvc_NetPathCanonicalize(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetPathCanonicalize *r);
_PUBLIC_ void ndr_print_srvsvc_NetPathCompare(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetPathCompare *r);
_PUBLIC_ void ndr_print_srvsvc_NetNameValidate(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetNameValidate *r);
_PUBLIC_ void ndr_print_srvsvc_NETRPRNAMECANONICALIZE(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRPRNAMECANONICALIZE *r);
_PUBLIC_ void ndr_print_srvsvc_NetPRNameCompare(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetPRNameCompare *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareEnum(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareEnum *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareDelStart(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareDelStart *r);
_PUBLIC_ void ndr_print_srvsvc_NetShareDelCommit(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetShareDelCommit *r);
_PUBLIC_ void ndr_print_srvsvc_NetGetFileSecurity(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetGetFileSecurity *r);
_PUBLIC_ void ndr_print_srvsvc_NetSetFileSecurity(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetSetFileSecurity *r);
_PUBLIC_ void ndr_print_srvsvc_NetServerTransportAddEx(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetServerTransportAddEx *r);
_PUBLIC_ void ndr_print_srvsvc_NetServerSetServiceBitsEx(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NetServerSetServiceBitsEx *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSGETVERSION(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSGETVERSION *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSCREATELOCALPARTITION(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSCREATELOCALPARTITION *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSDELETELOCALPARTITION(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSDELETELOCALPARTITION *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSSETLOCALVOLUMESTATE(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSSETLOCALVOLUMESTATE *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSSETSERVERINFO(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSSETSERVERINFO *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSCREATEEXITPOINT(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSCREATEEXITPOINT *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSDELETEEXITPOINT(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSDELETEEXITPOINT *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSMODIFYPREFIX(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSMODIFYPREFIX *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSFIXLOCALVOLUME(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSFIXLOCALVOLUME *r);
_PUBLIC_ void ndr_print_srvsvc_NETRDFSMANAGERREPORTSITEINFO(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRDFSMANAGERREPORTSITEINFO *r);
_PUBLIC_ void ndr_print_srvsvc_NETRSERVERTRANSPORTDELEX(struct ndr_print *ndr, const char *name, int flags, const struct srvsvc_NETRSERVERTRANSPORTDELEX *r);

/* The following definitions come from librpc/gen_ndr/ndr_svcctl.c  */

_PUBLIC_ void ndr_print_SERVICE_LOCK_STATUS(struct ndr_print *ndr, const char *name, const struct SERVICE_LOCK_STATUS *r);
_PUBLIC_ void ndr_print_SERVICE_STATUS(struct ndr_print *ndr, const char *name, const struct SERVICE_STATUS *r);
_PUBLIC_ void ndr_print_ENUM_SERVICE_STATUS(struct ndr_print *ndr, const char *name, const struct ENUM_SERVICE_STATUS *r);
_PUBLIC_ enum ndr_err_code ndr_push_svcctl_ServerType(struct ndr_push *ndr, int ndr_flags, uint32_t r);
_PUBLIC_ enum ndr_err_code ndr_pull_svcctl_ServerType(struct ndr_pull *ndr, int ndr_flags, uint32_t *r);
_PUBLIC_ void ndr_print_svcctl_ServerType(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_svcctl_MgrAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_svcctl_ServiceAccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_svcctl_CloseServiceHandle(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_CloseServiceHandle *r);
_PUBLIC_ void ndr_print_svcctl_ControlService(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_ControlService *r);
_PUBLIC_ void ndr_print_svcctl_DeleteService(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_DeleteService *r);
_PUBLIC_ void ndr_print_svcctl_LockServiceDatabase(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_LockServiceDatabase *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceObjectSecurity(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceObjectSecurity *r);
_PUBLIC_ void ndr_print_svcctl_SetServiceObjectSecurity(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_SetServiceObjectSecurity *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceStatus(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceStatus *r);
_PUBLIC_ void ndr_print_svcctl_SetServiceStatus(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_SetServiceStatus *r);
_PUBLIC_ void ndr_print_svcctl_UnlockServiceDatabase(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_UnlockServiceDatabase *r);
_PUBLIC_ void ndr_print_svcctl_NotifyBootConfigStatus(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_NotifyBootConfigStatus *r);
_PUBLIC_ void ndr_print_svcctl_SCSetServiceBitsW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_SCSetServiceBitsW *r);
_PUBLIC_ void ndr_print_svcctl_ChangeServiceConfigW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_ChangeServiceConfigW *r);
_PUBLIC_ void ndr_print_svcctl_CreateServiceW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_CreateServiceW *r);
_PUBLIC_ void ndr_print_svcctl_EnumDependentServicesW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_EnumDependentServicesW *r);
_PUBLIC_ void ndr_print_svcctl_EnumServicesStatusW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_EnumServicesStatusW *r);
_PUBLIC_ void ndr_print_svcctl_OpenSCManagerW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_OpenSCManagerW *r);
_PUBLIC_ void ndr_print_svcctl_OpenServiceW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_OpenServiceW *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceConfigW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceConfigW *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceLockStatusW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceLockStatusW *r);
_PUBLIC_ void ndr_print_svcctl_StartServiceW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_StartServiceW *r);
_PUBLIC_ void ndr_print_svcctl_GetServiceDisplayNameW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_GetServiceDisplayNameW *r);
_PUBLIC_ void ndr_print_svcctl_GetServiceKeyNameW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_GetServiceKeyNameW *r);
_PUBLIC_ void ndr_print_svcctl_SCSetServiceBitsA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_SCSetServiceBitsA *r);
_PUBLIC_ void ndr_print_svcctl_ChangeServiceConfigA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_ChangeServiceConfigA *r);
_PUBLIC_ void ndr_print_svcctl_CreateServiceA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_CreateServiceA *r);
_PUBLIC_ void ndr_print_svcctl_EnumDependentServicesA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_EnumDependentServicesA *r);
_PUBLIC_ void ndr_print_svcctl_EnumServicesStatusA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_EnumServicesStatusA *r);
_PUBLIC_ void ndr_print_svcctl_OpenSCManagerA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_OpenSCManagerA *r);
_PUBLIC_ void ndr_print_svcctl_OpenServiceA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_OpenServiceA *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceConfigA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceConfigA *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceLockStatusA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceLockStatusA *r);
_PUBLIC_ void ndr_print_svcctl_StartServiceA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_StartServiceA *r);
_PUBLIC_ void ndr_print_svcctl_GetServiceDisplayNameA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_GetServiceDisplayNameA *r);
_PUBLIC_ void ndr_print_svcctl_GetServiceKeyNameA(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_GetServiceKeyNameA *r);
_PUBLIC_ void ndr_print_svcctl_GetCurrentGroupeStateW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_GetCurrentGroupeStateW *r);
_PUBLIC_ void ndr_print_svcctl_EnumServiceGroupW(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_EnumServiceGroupW *r);
_PUBLIC_ void ndr_print_svcctl_ChangeServiceConfig2A(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_ChangeServiceConfig2A *r);
_PUBLIC_ void ndr_print_svcctl_ChangeServiceConfig2W(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_ChangeServiceConfig2W *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceConfig2A(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceConfig2A *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceConfig2W(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceConfig2W *r);
_PUBLIC_ void ndr_print_svcctl_QueryServiceStatusEx(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_QueryServiceStatusEx *r);
_PUBLIC_ void ndr_print_EnumServicesStatusExA(struct ndr_print *ndr, const char *name, int flags, const struct EnumServicesStatusExA *r);
_PUBLIC_ void ndr_print_EnumServicesStatusExW(struct ndr_print *ndr, const char *name, int flags, const struct EnumServicesStatusExW *r);
_PUBLIC_ void ndr_print_svcctl_SCSendTSMessage(struct ndr_print *ndr, const char *name, int flags, const struct svcctl_SCSendTSMessage *r);

/* The following definitions come from librpc/gen_ndr/ndr_winreg.c  */

_PUBLIC_ void ndr_print_winreg_AccessMask(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_winreg_Type(struct ndr_print *ndr, const char *name, enum winreg_Type r);
_PUBLIC_ enum ndr_err_code ndr_push_winreg_String(struct ndr_push *ndr, int ndr_flags, const struct winreg_String *r);
_PUBLIC_ enum ndr_err_code ndr_pull_winreg_String(struct ndr_pull *ndr, int ndr_flags, struct winreg_String *r);
_PUBLIC_ void ndr_print_winreg_String(struct ndr_print *ndr, const char *name, const struct winreg_String *r);
_PUBLIC_ void ndr_print_KeySecurityData(struct ndr_print *ndr, const char *name, const struct KeySecurityData *r);
_PUBLIC_ void ndr_print_winreg_SecBuf(struct ndr_print *ndr, const char *name, const struct winreg_SecBuf *r);
_PUBLIC_ void ndr_print_winreg_CreateAction(struct ndr_print *ndr, const char *name, enum winreg_CreateAction r);
_PUBLIC_ void ndr_print_winreg_StringBuf(struct ndr_print *ndr, const char *name, const struct winreg_StringBuf *r);
_PUBLIC_ void ndr_print_winreg_ValNameBuf(struct ndr_print *ndr, const char *name, const struct winreg_ValNameBuf *r);
_PUBLIC_ void ndr_print_KeySecurityAttribute(struct ndr_print *ndr, const char *name, const struct KeySecurityAttribute *r);
_PUBLIC_ void ndr_print_QueryMultipleValue(struct ndr_print *ndr, const char *name, const struct QueryMultipleValue *r);
_PUBLIC_ void ndr_print_winreg_OpenHKCR(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKCR *r);
_PUBLIC_ void ndr_print_winreg_OpenHKCU(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKCU *r);
_PUBLIC_ void ndr_print_winreg_OpenHKLM(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKLM *r);
_PUBLIC_ void ndr_print_winreg_OpenHKPD(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKPD *r);
_PUBLIC_ void ndr_print_winreg_OpenHKU(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKU *r);
_PUBLIC_ void ndr_print_winreg_CloseKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_CloseKey *r);
_PUBLIC_ void ndr_print_winreg_CreateKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_CreateKey *r);
_PUBLIC_ void ndr_print_winreg_DeleteKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_DeleteKey *r);
_PUBLIC_ void ndr_print_winreg_DeleteValue(struct ndr_print *ndr, const char *name, int flags, const struct winreg_DeleteValue *r);
_PUBLIC_ void ndr_print_winreg_EnumKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_EnumKey *r);
_PUBLIC_ void ndr_print_winreg_EnumValue(struct ndr_print *ndr, const char *name, int flags, const struct winreg_EnumValue *r);
_PUBLIC_ void ndr_print_winreg_FlushKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_FlushKey *r);
_PUBLIC_ void ndr_print_winreg_GetKeySecurity(struct ndr_print *ndr, const char *name, int flags, const struct winreg_GetKeySecurity *r);
_PUBLIC_ void ndr_print_winreg_LoadKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_LoadKey *r);
_PUBLIC_ void ndr_print_winreg_NotifyChangeKeyValue(struct ndr_print *ndr, const char *name, int flags, const struct winreg_NotifyChangeKeyValue *r);
_PUBLIC_ void ndr_print_winreg_OpenKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenKey *r);
_PUBLIC_ void ndr_print_winreg_QueryInfoKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_QueryInfoKey *r);
_PUBLIC_ void ndr_print_winreg_QueryValue(struct ndr_print *ndr, const char *name, int flags, const struct winreg_QueryValue *r);
_PUBLIC_ void ndr_print_winreg_ReplaceKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_ReplaceKey *r);
_PUBLIC_ void ndr_print_winreg_RestoreKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_RestoreKey *r);
_PUBLIC_ void ndr_print_winreg_SaveKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_SaveKey *r);
_PUBLIC_ void ndr_print_winreg_SetKeySecurity(struct ndr_print *ndr, const char *name, int flags, const struct winreg_SetKeySecurity *r);
_PUBLIC_ void ndr_print_winreg_SetValue(struct ndr_print *ndr, const char *name, int flags, const struct winreg_SetValue *r);
_PUBLIC_ void ndr_print_winreg_UnLoadKey(struct ndr_print *ndr, const char *name, int flags, const struct winreg_UnLoadKey *r);
_PUBLIC_ void ndr_print_winreg_InitiateSystemShutdown(struct ndr_print *ndr, const char *name, int flags, const struct winreg_InitiateSystemShutdown *r);
_PUBLIC_ void ndr_print_winreg_AbortSystemShutdown(struct ndr_print *ndr, const char *name, int flags, const struct winreg_AbortSystemShutdown *r);
_PUBLIC_ void ndr_print_winreg_GetVersion(struct ndr_print *ndr, const char *name, int flags, const struct winreg_GetVersion *r);
_PUBLIC_ void ndr_print_winreg_OpenHKCC(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKCC *r);
_PUBLIC_ void ndr_print_winreg_OpenHKDD(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKDD *r);
_PUBLIC_ void ndr_print_winreg_QueryMultipleValues(struct ndr_print *ndr, const char *name, int flags, const struct winreg_QueryMultipleValues *r);
_PUBLIC_ void ndr_print_winreg_InitiateSystemShutdownEx(struct ndr_print *ndr, const char *name, int flags, const struct winreg_InitiateSystemShutdownEx *r);
_PUBLIC_ void ndr_print_winreg_SaveKeyEx(struct ndr_print *ndr, const char *name, int flags, const struct winreg_SaveKeyEx *r);
_PUBLIC_ void ndr_print_winreg_OpenHKPT(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKPT *r);
_PUBLIC_ void ndr_print_winreg_OpenHKPN(struct ndr_print *ndr, const char *name, int flags, const struct winreg_OpenHKPN *r);
_PUBLIC_ void ndr_print_winreg_QueryMultipleValues2(struct ndr_print *ndr, const char *name, int flags, const struct winreg_QueryMultipleValues2 *r);

/* The following definitions come from librpc/gen_ndr/ndr_wkssvc.c  */

_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo100(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo100 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo101(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo101 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo102(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo102 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo502(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo502 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1010(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1010 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1011(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1011 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1012(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1012 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1013(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1013 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1018(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1018 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1023(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1023 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1027(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1027 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1028(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1028 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1032(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1032 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1033(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1033 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1041(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1041 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1042(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1042 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1043(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1043 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1044(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1044 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1045(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1045 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1046(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1046 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1047(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1047 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1048(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1048 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1049(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1049 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1050(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1050 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1051(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1051 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1052(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1052 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1053(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1053 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1054(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1054 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1055(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1055 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1056(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1056 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1057(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1057 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1058(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1058 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1059(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1059 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1060(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1060 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1061(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1061 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo1062(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaInfo1062 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaInfo(struct ndr_print *ndr, const char *name, const union wkssvc_NetWkstaInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserInfo0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrWkstaUserInfo0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaEnumUsersCtr0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaEnumUsersCtr0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserInfo1(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrWkstaUserInfo1 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaEnumUsersCtr1(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaEnumUsersCtr1 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaEnumUsersCtr(struct ndr_print *ndr, const char *name, const union wkssvc_NetWkstaEnumUsersCtr *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaEnumUsersInfo(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaEnumUsersInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserInfo1101(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrWkstaUserInfo1101 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserInfo(struct ndr_print *ndr, const char *name, const union wkssvc_NetrWkstaUserInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaTransportInfo0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaTransportInfo0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaTransportCtr0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaTransportCtr0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaTransportCtr(struct ndr_print *ndr, const char *name, const union wkssvc_NetWkstaTransportCtr *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaTransportInfo(struct ndr_print *ndr, const char *name, const struct wkssvc_NetWkstaTransportInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseInfo3(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseInfo3 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseInfo2(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseInfo2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseInfo1(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseInfo1 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseInfo0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseInfo0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseGetInfoCtr(struct ndr_print *ndr, const char *name, const union wkssvc_NetrUseGetInfoCtr *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnumCtr2(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseEnumCtr2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnumCtr1(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseEnumCtr1 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnumCtr0(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseEnumCtr0 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnumCtr(struct ndr_print *ndr, const char *name, const union wkssvc_NetrUseEnumCtr *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnumInfo(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrUseEnumInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWorkstationStatistics(struct ndr_print *ndr, const char *name, const struct wkssvc_NetrWorkstationStatistics *r);
_PUBLIC_ void ndr_print_wkssvc_renameflags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_wkssvc_NetValidateNameType(struct ndr_print *ndr, const char *name, enum wkssvc_NetValidateNameType r);
_PUBLIC_ void ndr_print_wkssvc_NetJoinStatus(struct ndr_print *ndr, const char *name, enum wkssvc_NetJoinStatus r);
_PUBLIC_ void ndr_print_wkssvc_PasswordBuffer(struct ndr_print *ndr, const char *name, const struct wkssvc_PasswordBuffer *r);
_PUBLIC_ void ndr_print_wkssvc_joinflags(struct ndr_print *ndr, const char *name, uint32_t r);
_PUBLIC_ void ndr_print_wkssvc_ComputerNameType(struct ndr_print *ndr, const char *name, enum wkssvc_ComputerNameType r);
_PUBLIC_ void ndr_print_wkssvc_ComputerNamesCtr(struct ndr_print *ndr, const char *name, const struct wkssvc_ComputerNamesCtr *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetWkstaGetInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaSetInfo(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetWkstaSetInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaEnumUsers(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetWkstaEnumUsers *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrWkstaUserGetInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaUserSetInfo(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrWkstaUserSetInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetWkstaTransportEnum(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetWkstaTransportEnum *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaTransportAdd(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrWkstaTransportAdd *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWkstaTransportDel(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrWkstaTransportDel *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseAdd(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUseAdd *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseGetInfo(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUseGetInfo *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseDel(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUseDel *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUseEnum(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUseEnum *r);
_PUBLIC_ void ndr_print_wkssvc_NetrMessageBufferSend(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrMessageBufferSend *r);
_PUBLIC_ void ndr_print_wkssvc_NetrWorkstationStatisticsGet(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrWorkstationStatisticsGet *r);
_PUBLIC_ void ndr_print_wkssvc_NetrLogonDomainNameAdd(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrLogonDomainNameAdd *r);
_PUBLIC_ void ndr_print_wkssvc_NetrLogonDomainNameDel(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrLogonDomainNameDel *r);
_PUBLIC_ void ndr_print_wkssvc_NetrJoinDomain(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrJoinDomain *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUnjoinDomain(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUnjoinDomain *r);
_PUBLIC_ void ndr_print_wkssvc_NetrRenameMachineInDomain(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrRenameMachineInDomain *r);
_PUBLIC_ void ndr_print_wkssvc_NetrValidateName(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrValidateName *r);
_PUBLIC_ void ndr_print_wkssvc_NetrGetJoinInformation(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrGetJoinInformation *r);
_PUBLIC_ void ndr_print_wkssvc_NetrGetJoinableOus(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrGetJoinableOus *r);
_PUBLIC_ void ndr_print_wkssvc_NetrJoinDomain2(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrJoinDomain2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrUnjoinDomain2(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrUnjoinDomain2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrRenameMachineInDomain2(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrRenameMachineInDomain2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrValidateName2(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrValidateName2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrGetJoinableOus2(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrGetJoinableOus2 *r);
_PUBLIC_ void ndr_print_wkssvc_NetrAddAlternateComputerName(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrAddAlternateComputerName *r);
_PUBLIC_ void ndr_print_wkssvc_NetrRemoveAlternateComputerName(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrRemoveAlternateComputerName *r);
_PUBLIC_ void ndr_print_wkssvc_NetrSetPrimaryComputername(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrSetPrimaryComputername *r);
_PUBLIC_ void ndr_print_wkssvc_NetrEnumerateComputerNames(struct ndr_print *ndr, const char *name, int flags, const struct wkssvc_NetrEnumerateComputerNames *r);

/* The following definitions come from librpc/gen_ndr/ndr_xattr.c  */

_PUBLIC_ enum ndr_err_code ndr_push_tdb_xattr(struct ndr_push *ndr, int ndr_flags, const struct tdb_xattr *r);
_PUBLIC_ enum ndr_err_code ndr_pull_tdb_xattr(struct ndr_pull *ndr, int ndr_flags, struct tdb_xattr *r);
_PUBLIC_ void ndr_print_tdb_xattr(struct ndr_print *ndr, const char *name, const struct tdb_xattr *r);
_PUBLIC_ enum ndr_err_code ndr_push_tdb_xattrs(struct ndr_push *ndr, int ndr_flags, const struct tdb_xattrs *r);
_PUBLIC_ enum ndr_err_code ndr_pull_tdb_xattrs(struct ndr_pull *ndr, int ndr_flags, struct tdb_xattrs *r);
_PUBLIC_ void ndr_print_tdb_xattrs(struct ndr_print *ndr, const char *name, const struct tdb_xattrs *r);

/* The following definitions come from librpc/gen_ndr/srv_dfs.c  */

void netdfs_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_netdfs_init(void);

/* The following definitions come from librpc/gen_ndr/srv_dssetup.c  */

void dssetup_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_dssetup_init(void);

/* The following definitions come from librpc/gen_ndr/srv_echo.c  */

void rpcecho_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_rpcecho_init(void);

/* The following definitions come from librpc/gen_ndr/srv_eventlog.c  */

void eventlog_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_eventlog_init(void);

/* The following definitions come from librpc/gen_ndr/srv_initshutdown.c  */

void initshutdown_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_initshutdown_init(void);

/* The following definitions come from librpc/gen_ndr/srv_lsa.c  */

void lsarpc_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_lsarpc_init(void);

/* The following definitions come from librpc/gen_ndr/srv_netlogon.c  */

void netlogon_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_netlogon_init(void);

/* The following definitions come from librpc/gen_ndr/srv_ntsvcs.c  */

void ntsvcs_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_ntsvcs_init(void);

/* The following definitions come from librpc/gen_ndr/srv_samr.c  */

void samr_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_samr_init(void);

/* The following definitions come from librpc/gen_ndr/srv_srvsvc.c  */

void srvsvc_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_srvsvc_init(void);

/* The following definitions come from librpc/gen_ndr/srv_svcctl.c  */

void svcctl_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_svcctl_init(void);

/* The following definitions come from librpc/gen_ndr/srv_winreg.c  */

void winreg_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_winreg_init(void);

/* The following definitions come from librpc/gen_ndr/srv_wkssvc.c  */

void wkssvc_get_pipe_fns(struct api_struct **fns, int *n_fns);
NTSTATUS rpc_wkssvc_init(void);

/* The following definitions come from librpc/ndr/ndr.c  */

_PUBLIC_ size_t ndr_align_size(uint32_t offset, size_t n);
_PUBLIC_ struct ndr_pull *ndr_pull_init_blob(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx);
_PUBLIC_ enum ndr_err_code ndr_pull_advance(struct ndr_pull *ndr, uint32_t size);
_PUBLIC_ void ndr_pull_save(struct ndr_pull *ndr, struct ndr_pull_save *save);
_PUBLIC_ void ndr_pull_restore(struct ndr_pull *ndr, struct ndr_pull_save *save);
_PUBLIC_ struct ndr_push *ndr_push_init_ctx(TALLOC_CTX *mem_ctx);
_PUBLIC_ DATA_BLOB ndr_push_blob(struct ndr_push *ndr);
_PUBLIC_ enum ndr_err_code ndr_push_expand(struct ndr_push *ndr, uint32_t extra_size);
_PUBLIC_ void ndr_print_debug_helper(struct ndr_print *ndr, const char *format, ...) _PRINTF_ATTRIBUTE(2,3);
_PUBLIC_ void ndr_print_string_helper(struct ndr_print *ndr, const char *format, ...) _PRINTF_ATTRIBUTE(2,3);
_PUBLIC_ void ndr_print_debug(ndr_print_fn_t fn, const char *name, void *ptr);
_PUBLIC_ void ndr_print_union_debug(ndr_print_fn_t fn, const char *name, uint32_t level, void *ptr);
_PUBLIC_ void ndr_print_function_debug(ndr_print_function_t fn, const char *name, int flags, void *ptr);
_PUBLIC_ char *ndr_print_struct_string(TALLOC_CTX *mem_ctx, ndr_print_fn_t fn, const char *name, void *ptr);
_PUBLIC_ char *ndr_print_union_string(TALLOC_CTX *mem_ctx, ndr_print_fn_t fn, const char *name, uint32_t level, void *ptr);
_PUBLIC_ char *ndr_print_function_string(TALLOC_CTX *mem_ctx,
				ndr_print_function_t fn, const char *name, 
				int flags, void *ptr);
_PUBLIC_ void ndr_set_flags(uint32_t *pflags, uint32_t new_flags);
NTSTATUS ndr_map_error2ntstatus(enum ndr_err_code ndr_err);
const char *ndr_errstr(enum ndr_err_code err);
_PUBLIC_ enum ndr_err_code ndr_pull_error(struct ndr_pull *ndr,
				 enum ndr_err_code ndr_err,
				 const char *format, ...) _PRINTF_ATTRIBUTE(3,4);
_PUBLIC_ enum ndr_err_code ndr_push_error(struct ndr_push *ndr,
				 enum ndr_err_code ndr_err,
				 const char *format, ...)  _PRINTF_ATTRIBUTE(3,4);
_PUBLIC_ enum ndr_err_code ndr_pull_subcontext_start(struct ndr_pull *ndr,
				   struct ndr_pull **_subndr,
				   size_t header_size,
				   ssize_t size_is);
_PUBLIC_ enum ndr_err_code ndr_pull_subcontext_end(struct ndr_pull *ndr,
				 struct ndr_pull *subndr,
				 size_t header_size,
				 ssize_t size_is);
_PUBLIC_ enum ndr_err_code ndr_push_subcontext_start(struct ndr_push *ndr,
				   struct ndr_push **_subndr,
				   size_t header_size,
				   ssize_t size_is);
_PUBLIC_ enum ndr_err_code ndr_push_subcontext_end(struct ndr_push *ndr,
				 struct ndr_push *subndr,
				 size_t header_size,
				 ssize_t size_is);
_PUBLIC_ enum ndr_err_code ndr_token_store(TALLOC_CTX *mem_ctx,
			 struct ndr_token_list **list, 
			 const void *key, 
			 uint32_t value);
_PUBLIC_ enum ndr_err_code ndr_token_retrieve_cmp_fn(struct ndr_token_list **list, const void *key, uint32_t *v,
				   comparison_fn_t _cmp_fn, bool _remove_tok);
_PUBLIC_ enum ndr_err_code ndr_token_retrieve(struct ndr_token_list **list, const void *key, uint32_t *v);
_PUBLIC_ uint32_t ndr_token_peek(struct ndr_token_list **list, const void *key);
_PUBLIC_ enum ndr_err_code ndr_pull_array_size(struct ndr_pull *ndr, const void *p);
_PUBLIC_ uint32_t ndr_get_array_size(struct ndr_pull *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_check_array_size(struct ndr_pull *ndr, void *p, uint32_t size);
_PUBLIC_ enum ndr_err_code ndr_pull_array_length(struct ndr_pull *ndr, const void *p);
_PUBLIC_ uint32_t ndr_get_array_length(struct ndr_pull *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_check_array_length(struct ndr_pull *ndr, void *p, uint32_t length);
_PUBLIC_ enum ndr_err_code ndr_push_set_switch_value(struct ndr_push *ndr, const void *p, uint32_t val);
_PUBLIC_ enum ndr_err_code ndr_pull_set_switch_value(struct ndr_pull *ndr, const void *p, uint32_t val);
_PUBLIC_ enum ndr_err_code ndr_print_set_switch_value(struct ndr_print *ndr, const void *p, uint32_t val);
_PUBLIC_ uint32_t ndr_push_get_switch_value(struct ndr_push *ndr, const void *p);
_PUBLIC_ uint32_t ndr_pull_get_switch_value(struct ndr_pull *ndr, const void *p);
_PUBLIC_ uint32_t ndr_print_get_switch_value(struct ndr_print *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_pull_struct_blob(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			      ndr_pull_flags_fn_t fn);
_PUBLIC_ enum ndr_err_code ndr_pull_struct_blob_all(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
				  ndr_pull_flags_fn_t fn);
_PUBLIC_ enum ndr_err_code ndr_pull_union_blob(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			     uint32_t level, ndr_pull_flags_fn_t fn);
_PUBLIC_ enum ndr_err_code ndr_pull_union_blob_all(const DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			     uint32_t level, ndr_pull_flags_fn_t fn);
_PUBLIC_ enum ndr_err_code ndr_push_struct_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, const void *p,
			      ndr_push_flags_fn_t fn);
_PUBLIC_ enum ndr_err_code ndr_push_union_blob(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, void *p,
			     uint32_t level, ndr_push_flags_fn_t fn);
_PUBLIC_ size_t ndr_size_struct(const void *p, int flags, ndr_push_flags_fn_t push);
_PUBLIC_ size_t ndr_size_union(const void *p, int flags, uint32_t level, ndr_push_flags_fn_t push);
_PUBLIC_ uint32_t ndr_push_get_relative_base_offset(struct ndr_push *ndr);
_PUBLIC_ void ndr_push_restore_relative_base_offset(struct ndr_push *ndr, uint32_t offset);
_PUBLIC_ enum ndr_err_code ndr_push_setup_relative_base_offset1(struct ndr_push *ndr, const void *p, uint32_t offset);
_PUBLIC_ enum ndr_err_code ndr_push_setup_relative_base_offset2(struct ndr_push *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_push_relative_ptr1(struct ndr_push *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_push_relative_ptr2(struct ndr_push *ndr, const void *p);
_PUBLIC_ uint32_t ndr_pull_get_relative_base_offset(struct ndr_pull *ndr);
_PUBLIC_ void ndr_pull_restore_relative_base_offset(struct ndr_pull *ndr, uint32_t offset);
_PUBLIC_ enum ndr_err_code ndr_pull_setup_relative_base_offset1(struct ndr_pull *ndr, const void *p, uint32_t offset);
_PUBLIC_ enum ndr_err_code ndr_pull_setup_relative_base_offset2(struct ndr_pull *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_pull_relative_ptr1(struct ndr_pull *ndr, const void *p, uint32_t rel_offset);
_PUBLIC_ enum ndr_err_code ndr_pull_relative_ptr2(struct ndr_pull *ndr, const void *p);

/* The following definitions come from librpc/ndr/ndr_basic.c  */

_PUBLIC_ void ndr_check_padding(struct ndr_pull *ndr, size_t n);
_PUBLIC_ enum ndr_err_code ndr_pull_int8(struct ndr_pull *ndr, int ndr_flags, int8_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_int16(struct ndr_pull *ndr, int ndr_flags, int16_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_uint16(struct ndr_pull *ndr, int ndr_flags, uint16_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_int32(struct ndr_pull *ndr, int ndr_flags, int32_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_uint32(struct ndr_pull *ndr, int ndr_flags, uint32_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_generic_ptr(struct ndr_pull *ndr, uint32_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_ref_ptr(struct ndr_pull *ndr, uint32_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_udlong(struct ndr_pull *ndr, int ndr_flags, uint64_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_udlongr(struct ndr_pull *ndr, int ndr_flags, uint64_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_dlong(struct ndr_pull *ndr, int ndr_flags, int64_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_hyper(struct ndr_pull *ndr, int ndr_flags, uint64_t *v);
_PUBLIC_ enum ndr_err_code ndr_pull_pointer(struct ndr_pull *ndr, int ndr_flags, void* *v);
_PUBLIC_ enum ndr_err_code ndr_pull_NTSTATUS(struct ndr_pull *ndr, int ndr_flags, NTSTATUS *status);
_PUBLIC_ enum ndr_err_code ndr_push_NTSTATUS(struct ndr_push *ndr, int ndr_flags, NTSTATUS status);
_PUBLIC_ void ndr_print_NTSTATUS(struct ndr_print *ndr, const char *name, NTSTATUS r);
_PUBLIC_ enum ndr_err_code ndr_pull_WERROR(struct ndr_pull *ndr, int ndr_flags, WERROR *status);
_PUBLIC_ enum ndr_err_code ndr_push_WERROR(struct ndr_push *ndr, int ndr_flags, WERROR status);
_PUBLIC_ void ndr_print_WERROR(struct ndr_print *ndr, const char *name, WERROR r);
_PUBLIC_ enum ndr_err_code ndr_pull_bytes(struct ndr_pull *ndr, uint8_t *data, uint32_t n);
_PUBLIC_ enum ndr_err_code ndr_pull_array_uint8(struct ndr_pull *ndr, int ndr_flags, uint8_t *data, uint32_t n);
_PUBLIC_ enum ndr_err_code ndr_push_int8(struct ndr_push *ndr, int ndr_flags, int8_t v);
_PUBLIC_ enum ndr_err_code ndr_push_uint8(struct ndr_push *ndr, int ndr_flags, uint8_t v);
_PUBLIC_ enum ndr_err_code ndr_push_int16(struct ndr_push *ndr, int ndr_flags, int16_t v);
_PUBLIC_ enum ndr_err_code ndr_push_uint16(struct ndr_push *ndr, int ndr_flags, uint16_t v);
_PUBLIC_ enum ndr_err_code ndr_push_int32(struct ndr_push *ndr, int ndr_flags, int32_t v);
_PUBLIC_ enum ndr_err_code ndr_push_uint32(struct ndr_push *ndr, int ndr_flags, uint32_t v);
_PUBLIC_ enum ndr_err_code ndr_push_udlong(struct ndr_push *ndr, int ndr_flags, uint64_t v);
_PUBLIC_ enum ndr_err_code ndr_push_udlongr(struct ndr_push *ndr, int ndr_flags, uint64_t v);
_PUBLIC_ enum ndr_err_code ndr_push_dlong(struct ndr_push *ndr, int ndr_flags, int64_t v);
_PUBLIC_ enum ndr_err_code ndr_push_hyper(struct ndr_push *ndr, int ndr_flags, uint64_t v);
_PUBLIC_ enum ndr_err_code ndr_push_pointer(struct ndr_push *ndr, int ndr_flags, void* v);
_PUBLIC_ enum ndr_err_code ndr_push_align(struct ndr_push *ndr, size_t size);
_PUBLIC_ enum ndr_err_code ndr_pull_align(struct ndr_pull *ndr, size_t size);
_PUBLIC_ enum ndr_err_code ndr_push_bytes(struct ndr_push *ndr, const uint8_t *data, uint32_t n);
_PUBLIC_ enum ndr_err_code ndr_push_zero(struct ndr_push *ndr, uint32_t n);
_PUBLIC_ enum ndr_err_code ndr_push_array_uint8(struct ndr_push *ndr, int ndr_flags, const uint8_t *data, uint32_t n);
_PUBLIC_ void ndr_push_save(struct ndr_push *ndr, struct ndr_push_save *save);
_PUBLIC_ void ndr_push_restore(struct ndr_push *ndr, struct ndr_push_save *save);
_PUBLIC_ enum ndr_err_code ndr_push_unique_ptr(struct ndr_push *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_push_full_ptr(struct ndr_push *ndr, const void *p);
_PUBLIC_ enum ndr_err_code ndr_push_ref_ptr(struct ndr_push *ndr);
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME(struct ndr_push *ndr, int ndr_flags, NTTIME t);
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME(struct ndr_pull *ndr, int ndr_flags, NTTIME *t);
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME_1sec(struct ndr_push *ndr, int ndr_flags, NTTIME t);
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME_1sec(struct ndr_pull *ndr, int ndr_flags, NTTIME *t);
_PUBLIC_ enum ndr_err_code ndr_pull_NTTIME_hyper(struct ndr_pull *ndr, int ndr_flags, NTTIME *t);
_PUBLIC_ enum ndr_err_code ndr_push_NTTIME_hyper(struct ndr_push *ndr, int ndr_flags, NTTIME t);
_PUBLIC_ enum ndr_err_code ndr_push_time_t(struct ndr_push *ndr, int ndr_flags, time_t t);
_PUBLIC_ enum ndr_err_code ndr_pull_time_t(struct ndr_pull *ndr, int ndr_flags, time_t *t);
_PUBLIC_ enum ndr_err_code ndr_pull_ipv4address(struct ndr_pull *ndr, int ndr_flags, const char **address);
_PUBLIC_ enum ndr_err_code ndr_push_ipv4address(struct ndr_push *ndr, int ndr_flags, const char *address);
_PUBLIC_ void ndr_print_ipv4address(struct ndr_print *ndr, const char *name, 
			   const char *address);
_PUBLIC_ void ndr_print_struct(struct ndr_print *ndr, const char *name, const char *type);
_PUBLIC_ void ndr_print_enum(struct ndr_print *ndr, const char *name, const char *type, 
		    const char *val, uint32_t value);
_PUBLIC_ void ndr_print_bitmap_flag(struct ndr_print *ndr, size_t size, const char *flag_name, uint32_t flag, uint32_t value);
_PUBLIC_ void ndr_print_int8(struct ndr_print *ndr, const char *name, int8_t v);
_PUBLIC_ void ndr_print_uint8(struct ndr_print *ndr, const char *name, uint8_t v);
_PUBLIC_ void ndr_print_int16(struct ndr_print *ndr, const char *name, int16_t v);
_PUBLIC_ void ndr_print_uint16(struct ndr_print *ndr, const char *name, uint16_t v);
_PUBLIC_ void ndr_print_int32(struct ndr_print *ndr, const char *name, int32_t v);
_PUBLIC_ void ndr_print_uint32(struct ndr_print *ndr, const char *name, uint32_t v);
_PUBLIC_ void ndr_print_udlong(struct ndr_print *ndr, const char *name, uint64_t v);
_PUBLIC_ void ndr_print_udlongr(struct ndr_print *ndr, const char *name, uint64_t v);
_PUBLIC_ void ndr_print_dlong(struct ndr_print *ndr, const char *name, int64_t v);
_PUBLIC_ void ndr_print_hyper(struct ndr_print *ndr, const char *name, uint64_t v);
_PUBLIC_ void ndr_print_pointer(struct ndr_print *ndr, const char *name, void *v);
_PUBLIC_ void ndr_print_ptr(struct ndr_print *ndr, const char *name, const void *p);
_PUBLIC_ void ndr_print_NTTIME(struct ndr_print *ndr, const char *name, NTTIME t);
_PUBLIC_ void ndr_print_NTTIME_1sec(struct ndr_print *ndr, const char *name, NTTIME t);
_PUBLIC_ void ndr_print_NTTIME_hyper(struct ndr_print *ndr, const char *name, NTTIME t);
_PUBLIC_ void ndr_print_time_t(struct ndr_print *ndr, const char *name, time_t t);
_PUBLIC_ void ndr_print_union(struct ndr_print *ndr, const char *name, int level, const char *type);
_PUBLIC_ void ndr_print_bad_level(struct ndr_print *ndr, const char *name, uint16_t level);
_PUBLIC_ void ndr_print_array_uint8(struct ndr_print *ndr, const char *name, 
			   const uint8_t *data, uint32_t count);
_PUBLIC_ void ndr_print_DATA_BLOB(struct ndr_print *ndr, const char *name, DATA_BLOB r);
_PUBLIC_ enum ndr_err_code ndr_push_DATA_BLOB(struct ndr_push *ndr, int ndr_flags, DATA_BLOB blob);
_PUBLIC_ enum ndr_err_code ndr_pull_DATA_BLOB(struct ndr_pull *ndr, int ndr_flags, DATA_BLOB *blob);
_PUBLIC_ uint32_t ndr_size_DATA_BLOB(int ret, const DATA_BLOB *data, int flags);
_PUBLIC_ void ndr_print_bool(struct ndr_print *ndr, const char *name, const bool b);
_PUBLIC_ void ndr_print_sockaddr_storage(struct ndr_print *ndr, const char *name, const struct sockaddr_storage *ss);

/* The following definitions come from librpc/ndr/ndr_krb5pac.c  */

enum ndr_err_code ndr_push_PAC_BUFFER(struct ndr_push *ndr, int ndr_flags, const struct PAC_BUFFER *r);
enum ndr_err_code ndr_pull_PAC_BUFFER(struct ndr_pull *ndr, int ndr_flags, struct PAC_BUFFER *r);
void ndr_print_PAC_BUFFER(struct ndr_print *ndr, const char *name, const struct PAC_BUFFER *r);

/* The following definitions come from librpc/ndr/ndr_misc.c  */

bool all_zero(const uint8_t *ptr, size_t size);
void ndr_print_GUID(struct ndr_print *ndr, const char *name, const struct GUID *guid);
bool ndr_syntax_id_equal(const struct ndr_syntax_id *i1,
			 const struct ndr_syntax_id *i2);
enum ndr_err_code ndr_push_server_id(struct ndr_push *ndr, int ndr_flags, const struct server_id *r);
enum ndr_err_code ndr_pull_server_id(struct ndr_pull *ndr, int ndr_flags, struct server_id *r);
void ndr_print_server_id(struct ndr_print *ndr, const char *name, const struct server_id *r);

/* The following definitions come from librpc/ndr/ndr_sec_helper.c  */

size_t ndr_size_dom_sid(const struct dom_sid *sid, int flags);
size_t ndr_size_dom_sid28(const struct dom_sid *sid, int flags);
size_t ndr_size_dom_sid0(const struct dom_sid *sid, int flags);
size_t ndr_size_security_ace(const struct security_ace *ace, int flags);
size_t ndr_size_security_acl(const struct security_acl *theacl, int flags);
size_t ndr_size_security_descriptor(const struct security_descriptor *sd, int flags);
void ndr_print_dom_sid(struct ndr_print *ndr, const char *name, const struct dom_sid *sid);
void ndr_print_dom_sid2(struct ndr_print *ndr, const char *name, const struct dom_sid *sid);
void ndr_print_dom_sid28(struct ndr_print *ndr, const char *name, const struct dom_sid *sid);
void ndr_print_dom_sid0(struct ndr_print *ndr, const char *name, const struct dom_sid *sid);

/* The following definitions come from librpc/ndr/ndr_string.c  */

_PUBLIC_ enum ndr_err_code ndr_pull_string(struct ndr_pull *ndr, int ndr_flags, const char **s);
_PUBLIC_ enum ndr_err_code ndr_push_string(struct ndr_push *ndr, int ndr_flags, const char *s);
_PUBLIC_ size_t ndr_string_array_size(struct ndr_push *ndr, const char *s);
_PUBLIC_ void ndr_print_string(struct ndr_print *ndr, const char *name, const char *s);
_PUBLIC_ uint32_t ndr_size_string(int ret, const char * const* string, int flags) ;
_PUBLIC_ enum ndr_err_code ndr_pull_string_array(struct ndr_pull *ndr, int ndr_flags, const char ***_a);
_PUBLIC_ enum ndr_err_code ndr_push_string_array(struct ndr_push *ndr, int ndr_flags, const char **a);
_PUBLIC_ void ndr_print_string_array(struct ndr_print *ndr, const char *name, const char **a);
_PUBLIC_ uint32_t ndr_string_length(const void *_var, uint32_t element_size);
_PUBLIC_ enum ndr_err_code ndr_check_string_terminator(struct ndr_pull *ndr, uint32_t count, uint32_t element_size);
_PUBLIC_ enum ndr_err_code ndr_pull_charset(struct ndr_pull *ndr, int ndr_flags, const char **var, uint32_t length, uint8_t byte_mul, charset_t chset);
_PUBLIC_ enum ndr_err_code ndr_push_charset(struct ndr_push *ndr, int ndr_flags, const char *var, uint32_t length, uint8_t byte_mul, charset_t chset);
_PUBLIC_ uint32_t ndr_charset_length(const void *var, charset_t chset);

/* The following definitions come from librpc/ndr/sid.c  */

enum ndr_err_code ndr_push_dom_sid(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *r);
enum ndr_err_code ndr_pull_dom_sid(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *r);
char *dom_sid_string(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
enum ndr_err_code ndr_pull_dom_sid2(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid);
enum ndr_err_code ndr_push_dom_sid2(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *sid);
enum ndr_err_code ndr_pull_dom_sid28(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid);
enum ndr_err_code ndr_push_dom_sid28(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *sid);
enum ndr_err_code ndr_pull_dom_sid0(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid);
enum ndr_err_code ndr_push_dom_sid0(struct ndr_push *ndr, int ndr_flags, const struct dom_sid *sid);

/* The following definitions come from librpc/ndr/uuid.c  */

_PUBLIC_ NTSTATUS GUID_from_string(const char *s, struct GUID *guid);
_PUBLIC_ NTSTATUS NS_GUID_from_string(const char *s, struct GUID *guid);
struct GUID GUID_random(void);
_PUBLIC_ struct GUID GUID_zero(void);
_PUBLIC_ bool GUID_all_zero(const struct GUID *u);
_PUBLIC_ bool GUID_equal(const struct GUID *u1, const struct GUID *u2);
_PUBLIC_ int GUID_compare(const struct GUID *u1, const struct GUID *u2);
_PUBLIC_ char *GUID_string(TALLOC_CTX *mem_ctx, const struct GUID *guid);
_PUBLIC_ char *GUID_string2(TALLOC_CTX *mem_ctx, const struct GUID *guid);
_PUBLIC_ char *NS_GUID_string(TALLOC_CTX *mem_ctx, const struct GUID *guid);
_PUBLIC_ bool policy_handle_empty(struct policy_handle *h) ;

/* The following definitions come from librpc/rpc/binding.c  */

const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
_PUBLIC_ char *dcerpc_binding_string(TALLOC_CTX *mem_ctx, const struct dcerpc_binding *b);
_PUBLIC_ NTSTATUS dcerpc_parse_binding(TALLOC_CTX *mem_ctx, const char *s, struct dcerpc_binding **b_out);
_PUBLIC_ NTSTATUS dcerpc_floor_get_lhs_data(struct epm_floor *epm_floor, struct ndr_syntax_id *syntax);
const char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
enum dcerpc_transport_t dcerpc_transport_by_endpoint_protocol(int prot);
_PUBLIC_ enum dcerpc_transport_t dcerpc_transport_by_tower(struct epm_tower *tower);
_PUBLIC_ NTSTATUS dcerpc_binding_from_tower(TALLOC_CTX *mem_ctx, 
				   struct epm_tower *tower, 
				   struct dcerpc_binding **b_out);
_PUBLIC_ NTSTATUS dcerpc_binding_build_tower(TALLOC_CTX *mem_ctx, struct dcerpc_binding *binding, struct epm_tower *tower);

/* The following definitions come from librpc/rpc/dcerpc.c  */

struct rpc_request *dcerpc_ndr_request_send(struct dcerpc_pipe *p, const struct GUID *object, 
					    const struct ndr_interface_table *table, uint32_t opnum, 
					    TALLOC_CTX *mem_ctx, void *r);
NTSTATUS dcerpc_ndr_request_recv(struct rpc_request *req);
_PUBLIC_ NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx, struct dcerpc_pipe **pp, 
				      const char *binding_string, const struct ndr_interface_table *table, 
				      struct cli_credentials *credentials, struct event_context *ev, 
				      struct loadparm_context *lp_ctx);

/* The following definitions come from libsmb/asn1.c  */

void asn1_free(ASN1_DATA *data);
bool asn1_write(ASN1_DATA *data, const void *p, int len);
bool asn1_write_uint8(ASN1_DATA *data, uint8 v);
bool asn1_push_tag(ASN1_DATA *data, uint8 tag);
bool asn1_pop_tag(ASN1_DATA *data);
bool asn1_write_Integer(ASN1_DATA *data, int i);
bool asn1_write_OID(ASN1_DATA *data, const char *OID);
bool asn1_write_OctetString(ASN1_DATA *data, const void *p, size_t length);
bool asn1_write_GeneralString(ASN1_DATA *data, const char *s);
bool asn1_write_BOOLEAN(ASN1_DATA *data, bool v);
bool asn1_write_BOOLEAN2(ASN1_DATA *data, bool v);
bool asn1_check_BOOLEAN(ASN1_DATA *data, bool v);
bool asn1_load(ASN1_DATA *data, DATA_BLOB blob);
bool asn1_read(ASN1_DATA *data, void *p, int len);
bool asn1_read_uint8(ASN1_DATA *data, uint8 *v);
bool asn1_check_tag(ASN1_DATA *data, uint8 tag);
bool asn1_start_tag(ASN1_DATA *data, uint8 tag);
bool asn1_end_tag(ASN1_DATA *data);
int asn1_tag_remaining(ASN1_DATA *data);
bool asn1_read_OID(ASN1_DATA *data, char **OID);
bool asn1_check_OID(ASN1_DATA *data, const char *OID);
bool asn1_read_GeneralString(ASN1_DATA *data, char **s);
bool asn1_read_OctetString(ASN1_DATA *data, DATA_BLOB *blob);
bool asn1_read_Integer(ASN1_DATA *data, int *i);
bool asn1_check_enumerated(ASN1_DATA *data, int v);
bool asn1_write_enumerated(ASN1_DATA *data, uint8 v);
bool ber_write_OID_String(DATA_BLOB *blob, const char *OID);
bool ber_read_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB blob, const char **OID);

/* The following definitions come from libsmb/async_smb.c  */

NTSTATUS cli_pull_error(char *buf);
void cli_set_error(struct cli_state *cli, NTSTATUS status);
struct async_req *cli_request_new(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  uint8_t num_words, size_t num_bytes,
				  struct cli_request **preq);
struct cli_request *cli_request_get(struct async_req *req);
struct cli_tmp_event *cli_tmp_event_ctx(TALLOC_CTX *mem_ctx,
					struct cli_state *cli);
NTSTATUS cli_add_event_ctx(struct cli_state *cli,
			   struct event_context *event_ctx);

/* The following definitions come from libsmb/cliconnect.c  */

ADS_STATUS cli_session_setup_spnego(struct cli_state *cli, const char *user, 
			      const char *pass, const char *user_domain,
				    const char * dest_realm);

NTSTATUS cli_session_setup(struct cli_state *cli,
			   const char *user,
			   const char *pass, int passlen,
			   const char *ntpass, int ntpasslen,
			   const char *workgroup);
bool cli_ulogoff(struct cli_state *cli);
bool cli_send_tconX(struct cli_state *cli, 
		    const char *share, const char *dev, const char *pass, int passlen);
bool cli_tdis(struct cli_state *cli);
void cli_negprot_send(struct cli_state *cli);
bool cli_negprot(struct cli_state *cli);
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
const char *cli_cm_get_mntpoint(struct cli_state *c);
struct cli_state *cli_cm_open(TALLOC_CTX *ctx,
				struct cli_state *referring_cli,
				const char *server,
				const char *share,
				bool show_hdr,
				bool force_encrypt);
void cli_cm_shutdown(void);
void cli_cm_display(void);
void cli_cm_set_credentials(void);
void cli_cm_set_port(int port_number);
void cli_cm_set_dest_name_type(int type);
void cli_cm_set_signing_state(int state);
void cli_cm_set_username(const char *username);
void cli_cm_set_password(const char *newpass);
void cli_cm_set_use_kerberos(void);
void cli_cm_set_fallback_after_kerberos(void);
void cli_cm_set_dest_ss(struct sockaddr_storage *pss);
bool cli_dfs_get_referral(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			CLIENT_DFS_REFERRAL**refs,
			size_t *num_refs,
			uint16 *consumed);
bool cli_resolve_path(TALLOC_CTX *ctx,
			const char *mountpt,
			struct cli_state *rootcli,
			const char *path,
			struct cli_state **targetcli,
			char **pp_targetpath);

/* The following definitions come from libsmb/clidgram.c  */

bool cli_send_mailslot(struct messaging_context *msg_ctx,
		       bool unique, const char *mailslot,
		       uint16 priority,
		       char *buf, int len,
		       const char *srcname, int src_type,
		       const char *dstname, int dest_type,
		       const struct sockaddr_storage *dest_ss);
bool send_getdc_request(TALLOC_CTX *mem_ctx,
			struct messaging_context *msg_ctx,
			struct sockaddr_storage *dc_ss,
			const char *domain_name,
			const DOM_SID *sid,
			uint32_t nt_version);
bool receive_getdc_response(TALLOC_CTX *mem_ctx,
			    struct sockaddr_storage *dc_ss,
			    const char *domain_name,
			    uint32_t *nt_version,
			    const char **dc_name,
			    struct netlogon_samlogon_response **reply);

/* The following definitions come from libsmb/clientgen.c  */

int cli_set_message(char *buf,int num_words,int num_bytes,bool zero);
unsigned int cli_set_timeout(struct cli_state *cli, unsigned int timeout);
int cli_set_port(struct cli_state *cli, int port);
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
void cli_init_creds(struct cli_state *cli, const char *username, const char *domain, const char *password);
void cli_setup_signing_state(struct cli_state *cli, int signing_state);
struct cli_state *cli_initialise(void);
void cli_nt_pipes_close(struct cli_state *cli);
void cli_shutdown(struct cli_state *cli);
void cli_sockopt(struct cli_state *cli, const char *options);
uint16 cli_setpid(struct cli_state *cli, uint16 pid);
bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive);
bool cli_send_keepalive(struct cli_state *cli);
bool cli_echo(struct cli_state *cli, uint16 num_echos,
	      unsigned char *data, size_t length);

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

/* The following definitions come from libsmb/clifile.c  */

uint32 unix_perms_to_wire(mode_t perms);
mode_t wire_perms_to_unix(uint32 perms);
bool cli_unix_getfacl(struct cli_state *cli, const char *name, size_t *prb_size, char **retbuf);
bool cli_unix_stat(struct cli_state *cli, const char *name, SMB_STRUCT_STAT *sbuf);
bool cli_unix_symlink(struct cli_state *cli, const char *oldname, const char *newname);
bool cli_unix_hardlink(struct cli_state *cli, const char *oldname, const char *newname);
bool cli_unix_chmod(struct cli_state *cli, const char *fname, mode_t mode);
bool cli_unix_chown(struct cli_state *cli, const char *fname, uid_t uid, gid_t gid);
bool cli_rename(struct cli_state *cli, const char *fname_src, const char *fname_dst);
bool cli_ntrename(struct cli_state *cli, const char *fname_src, const char *fname_dst);
bool cli_nt_hardlink(struct cli_state *cli, const char *fname_src, const char *fname_dst);
bool cli_unlink_full(struct cli_state *cli, const char *fname, uint16 attrs);
bool cli_unlink(struct cli_state *cli, const char *fname);
bool cli_mkdir(struct cli_state *cli, const char *dname);
bool cli_rmdir(struct cli_state *cli, const char *dname);
int cli_nt_delete_on_close(struct cli_state *cli, int fnum, bool flag);
int cli_nt_create_full(struct cli_state *cli, const char *fname,
		 uint32 CreatFlags, uint32 DesiredAccess,
		 uint32 FileAttributes, uint32 ShareAccess,
		 uint32 CreateDisposition, uint32 CreateOptions,
		 uint8 SecuityFlags);
int cli_nt_create(struct cli_state *cli, const char *fname, uint32 DesiredAccess);
int cli_open(struct cli_state *cli, const char *fname, int flags, int share_mode);
bool cli_close(struct cli_state *cli, int fnum);
bool cli_ftruncate(struct cli_state *cli, int fnum, uint64_t size);
NTSTATUS cli_locktype(struct cli_state *cli, int fnum,
		      uint32 offset, uint32 len,
		      int timeout, unsigned char locktype);
bool cli_lock(struct cli_state *cli, int fnum,
	      uint32 offset, uint32 len, int timeout, enum brl_type lock_type);
bool cli_unlock(struct cli_state *cli, int fnum, uint32 offset, uint32 len);
bool cli_lock64(struct cli_state *cli, int fnum,
		SMB_BIG_UINT offset, SMB_BIG_UINT len, int timeout, enum brl_type lock_type);
bool cli_unlock64(struct cli_state *cli, int fnum, SMB_BIG_UINT offset, SMB_BIG_UINT len);
bool cli_posix_lock(struct cli_state *cli, int fnum,
			SMB_BIG_UINT offset, SMB_BIG_UINT len,
			bool wait_lock, enum brl_type lock_type);
bool cli_posix_unlock(struct cli_state *cli, int fnum, SMB_BIG_UINT offset, SMB_BIG_UINT len);
bool cli_posix_getlock(struct cli_state *cli, int fnum, SMB_BIG_UINT *poffset, SMB_BIG_UINT *plen);
bool cli_getattrE(struct cli_state *cli, int fd,
		  uint16 *attr, SMB_OFF_T *size,
		  time_t *change_time,
                  time_t *access_time,
                  time_t *write_time);
bool cli_getatr(struct cli_state *cli, const char *fname,
		uint16 *attr, SMB_OFF_T *size, time_t *write_time);
bool cli_setattrE(struct cli_state *cli, int fd,
		  time_t change_time,
                  time_t access_time,
                  time_t write_time);
bool cli_setatr(struct cli_state *cli, const char *fname, uint16 attr, time_t t);
bool cli_chkpath(struct cli_state *cli, const char *path);
bool cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail);
int cli_ctemp(struct cli_state *cli, const char *path, char **tmp_path);
NTSTATUS cli_raw_ioctl(struct cli_state *cli, int fnum, uint32 code, DATA_BLOB *blob);
bool cli_set_ea_path(struct cli_state *cli, const char *path, const char *ea_name, const char *ea_val, size_t ea_len);
bool cli_set_ea_fnum(struct cli_state *cli, int fnum, const char *ea_name, const char *ea_val, size_t ea_len);
bool cli_get_ea_list_path(struct cli_state *cli, const char *path,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list);
bool cli_get_ea_list_fnum(struct cli_state *cli, int fnum,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list);
int cli_posix_open(struct cli_state *cli, const char *fname, int flags, mode_t mode);
int cli_posix_mkdir(struct cli_state *cli, const char *fname, mode_t mode);
bool cli_posix_unlink(struct cli_state *cli, const char *fname);
int cli_posix_rmdir(struct cli_state *cli, const char *fname);

/* The following definitions come from libsmb/clifsinfo.c  */

bool cli_unix_extensions_version(struct cli_state *cli, uint16 *pmajor, uint16 *pminor,
                                        uint32 *pcaplow, uint32 *pcaphigh);
bool cli_set_unix_extensions_capabilities(struct cli_state *cli, uint16 major, uint16 minor,
                                        uint32 caplow, uint32 caphigh);
bool cli_get_fs_attr_info(struct cli_state *cli, uint32 *fs_attr);
bool cli_get_fs_volume_info_old(struct cli_state *cli, fstring volume_name, uint32 *pserial_number);
bool cli_get_fs_volume_info(struct cli_state *cli, fstring volume_name, uint32 *pserial_number, time_t *pdate);
bool cli_get_fs_full_size_info(struct cli_state *cli,
                               SMB_BIG_UINT *total_allocation_units,
                               SMB_BIG_UINT *caller_allocation_units,
                               SMB_BIG_UINT *actual_allocation_units,
                               SMB_BIG_UINT *sectors_per_allocation_unit,
                               SMB_BIG_UINT *bytes_per_sector);
bool cli_get_posix_fs_info(struct cli_state *cli,
                           uint32 *optimal_transfer_size,
                           uint32 *block_size,
                           SMB_BIG_UINT *total_blocks,
                           SMB_BIG_UINT *blocks_available,
                           SMB_BIG_UINT *user_blocks_available,
                           SMB_BIG_UINT *total_file_nodes,
                           SMB_BIG_UINT *free_file_nodes,
                           SMB_BIG_UINT *fs_identifier);
NTSTATUS cli_raw_ntlm_smb_encryption_start(struct cli_state *cli, 
				const char *user,
				const char *pass,
				const char *domain);
NTSTATUS cli_gss_smb_encryption_start(struct cli_state *cli);
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
int cli_krb5_get_ticket(const char *principal, time_t time_offset, 
			DATA_BLOB *ticket, DATA_BLOB *session_key_krb5, 
			uint32 extra_ap_opts, const char *ccname, 
			time_t *tgs_expire);

/* The following definitions come from libsmb/clilist.c  */

int cli_list_new(struct cli_state *cli,const char *Mask,uint16 attribute,
		 void (*fn)(const char *, file_info *, const char *, void *), void *state);
int cli_list_old(struct cli_state *cli,const char *Mask,uint16 attribute,
		 void (*fn)(const char *, file_info *, const char *, void *), void *state);
int cli_list(struct cli_state *cli,const char *Mask,uint16 attribute,
	     void (*fn)(const char *, file_info *, const char *, void *), void *state);

/* The following definitions come from libsmb/climessage.c  */

int cli_message_start_build(struct cli_state *cli, const char *host, const char *username);
bool cli_message_start(struct cli_state *cli, const char *host, const char *username,
			      int *grp);
int cli_message_text_build(struct cli_state *cli, const char *msg, int len, int grp);
bool cli_message_text(struct cli_state *cli, const char *msg, int len, int grp);
int cli_message_end_build(struct cli_state *cli, int grp);
bool cli_message_end(struct cli_state *cli, int grp);

/* The following definitions come from libsmb/clioplock.c  */

bool cli_oplock_ack(struct cli_state *cli, int fnum, unsigned char level);
void cli_oplock_handler(struct cli_state *cli, 
			bool (*handler)(struct cli_state *, int, unsigned char));

/* The following definitions come from libsmb/cliprint.c  */

int cli_print_queue(struct cli_state *cli,
		    void (*fn)(struct print_job_info *));
int cli_printjob_del(struct cli_state *cli, int job);
int cli_spl_open(struct cli_state *cli, const char *fname, int flags, int share_mode);
bool cli_spl_close(struct cli_state *cli, int fnum);

/* The following definitions come from libsmb/cliquota.c  */

bool cli_get_quota_handle(struct cli_state *cli, int *quota_fnum);
void free_ntquota_list(SMB_NTQUOTA_LIST **qt_list);
bool cli_get_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_set_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_list_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_LIST **pqt_list);
bool cli_get_fs_quota_info(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
bool cli_set_fs_quota_info(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_STRUCT *pqt);
void dump_ntquota(SMB_NTQUOTA_STRUCT *qt, bool _verbose, bool _numeric, void (*_sidtostring)(fstring str, DOM_SID *sid, bool _numeric));
void dump_ntquota_list(SMB_NTQUOTA_LIST **qtl, bool _verbose, bool _numeric, void (*_sidtostring)(fstring str, DOM_SID *sid, bool _numeric));

/* The following definitions come from libsmb/clirap.c  */

bool cli_api_pipe(struct cli_state *cli, const char *pipe_name,
                  uint16 *setup, uint32 setup_count, uint32 max_setup_count,
                  char *params, uint32 param_count, uint32 max_param_count,
                  char *data, uint32 data_count, uint32 max_data_count,
                  char **rparam, uint32 *rparam_count,
                  char **rdata, uint32 *rdata_count);
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
bool cli_qpathinfo(struct cli_state *cli,
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
bool cli_qpathinfo2(struct cli_state *cli, const char *fname,
		    struct timespec *create_time,
                    struct timespec *access_time,
                    struct timespec *write_time,
		    struct timespec *change_time,
                    SMB_OFF_T *size, uint16 *mode,
		    SMB_INO_T *ino);
bool cli_qpathinfo_streams(struct cli_state *cli, const char *fname,
			   TALLOC_CTX *mem_ctx,
			   unsigned int *pnum_streams,
			   struct stream_struct **pstreams);
bool cli_qfilename(struct cli_state *cli, int fnum, char *name, size_t namelen);
bool cli_qfileinfo(struct cli_state *cli, int fnum,
		   uint16 *mode, SMB_OFF_T *size,
		   struct timespec *create_time,
                   struct timespec *access_time,
                   struct timespec *write_time,
		   struct timespec *change_time,
                   SMB_INO_T *ino);
bool cli_qpathinfo_basic( struct cli_state *cli, const char *name,
                          SMB_STRUCT_STAT *sbuf, uint32 *attributes );
bool cli_qfileinfo_test(struct cli_state *cli, int fnum, int level, char **poutdata, uint32 *poutlen);
NTSTATUS cli_qpathinfo_alt_name(struct cli_state *cli, const char *fname, fstring alt_name);

/* The following definitions come from libsmb/clirap2.c  */

int cli_NetGroupDelete(struct cli_state *cli, const char *group_name);
int cli_NetGroupAdd(struct cli_state *cli, RAP_GROUP_INFO_1 *grinfo);
int cli_RNetGroupEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_RNetGroupEnum0(struct cli_state *cli,
		       void (*fn)(const char *, void *),
		       void *state);
int cli_NetGroupDelUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupAddUser(struct cli_state * cli, const char *group_name, const char *user_name);
int cli_NetGroupGetUsers(struct cli_state * cli, const char *group_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserGetGroups(struct cli_state * cli, const char *user_name, void (*fn)(const char *, void *), void *state );
int cli_NetUserDelete(struct cli_state *cli, const char * user_name );
int cli_NetUserAdd(struct cli_state *cli, RAP_USER_INFO_1 * userinfo );
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
int cli_NetShareAdd(struct cli_state *cli, RAP_SHARE_INFO_2 * sinfo );
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
		void (*jfn)(uint16,const char*,const char*,const char*,const char*,uint16,uint16,const char*,uint,uint,const char*));
int cli_NetPrintQGetInfo(struct cli_state *cli, const char *printer,
	void (*qfn)(const char*,uint16,uint16,uint16,const char*,const char*,const char*,const char*,const char*,uint16,uint16),
	void (*jfn)(uint16,const char*,const char*,const char*,const char*,uint16,uint16,const char*,uint,uint,const char*));
int cli_RNetServiceEnum(struct cli_state *cli, void (*fn)(const char *, const char *, void *), void *state);
int cli_NetSessionEnum(struct cli_state *cli, void (*fn)(char *, char *, uint16, uint16, uint16, uint, uint, uint, char *));
int cli_NetSessionGetInfo(struct cli_state *cli, const char *workstation,
		void (*fn)(const char *, const char *, uint16, uint16, uint16, uint, uint, uint, const char *));
int cli_NetSessionDel(struct cli_state *cli, const char *workstation);
int cli_NetConnectionEnum(struct cli_state *cli, const char *qualifier,
			void (*fn)(uint16_t conid, uint16_t contype,
				uint16_t numopens, uint16_t numusers,
				uint32_t contime, const char *username,
				const char *netname));

/* The following definitions come from libsmb/clireadwrite.c  */

struct async_req *cli_read_andx_send(TALLOC_CTX *mem_ctx,
				     struct cli_state *cli, int fnum,
				     off_t offset, size_t size);
NTSTATUS cli_read_andx_recv(struct async_req *req, ssize_t *received,
			    uint8_t **rcvbuf);
struct async_req *cli_pull_send(TALLOC_CTX *mem_ctx, struct cli_state *cli,
				uint16_t fnum, off_t start_offset,
				SMB_OFF_T size, size_t window_size,
				NTSTATUS (*sink)(char *buf, size_t n,
						 void *priv),
				void *priv);
NTSTATUS cli_pull_recv(struct async_req *req, SMB_OFF_T *received);
NTSTATUS cli_pull(struct cli_state *cli, uint16_t fnum,
		  off_t start_offset, SMB_OFF_T size, size_t window_size,
		  NTSTATUS (*sink)(char *buf, size_t n, void *priv),
		  void *priv, SMB_OFF_T *received);
ssize_t cli_read(struct cli_state *cli, int fnum, char *buf,
		 off_t offset, size_t size);
ssize_t cli_readraw(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size);
ssize_t cli_write(struct cli_state *cli,
    	         int fnum, uint16 write_mode,
		 const char *buf, off_t offset, size_t size);
ssize_t cli_smbwrite(struct cli_state *cli,
		     int fnum, char *buf, off_t offset, size_t size1);

/* The following definitions come from libsmb/clisecdesc.c  */

SEC_DESC *cli_query_secdesc(struct cli_state *cli, int fnum, 
			    TALLOC_CTX *mem_ctx);
bool cli_set_secdesc(struct cli_state *cli, int fnum, SEC_DESC *sd);

/* The following definitions come from libsmb/clispnego.c  */

DATA_BLOB spnego_gen_negTokenInit(char guid[16], 
				  const char *OIDs[], 
				  const char *principal);
DATA_BLOB gen_negTokenInit(const char *OID, DATA_BLOB blob);
bool spnego_parse_negTokenInit(DATA_BLOB blob,
			       char *OIDs[ASN1_MAX_OIDS], 
			       char **principal);
DATA_BLOB gen_negTokenTarg(const char *OIDs[], DATA_BLOB blob);
bool parse_negTokenTarg(DATA_BLOB blob, char *OIDs[ASN1_MAX_OIDS], DATA_BLOB *secblob);
DATA_BLOB spnego_gen_krb5_wrap(const DATA_BLOB ticket, const uint8 tok_id[2]);
bool spnego_parse_krb5_wrap(DATA_BLOB blob, DATA_BLOB *ticket, uint8 tok_id[2]);
int spnego_gen_negTokenTarg(const char *principal, int time_offset, 
			    DATA_BLOB *targ, 
			    DATA_BLOB *session_key_krb5, uint32 extra_ap_opts,
			    time_t *expire_time);
bool spnego_parse_challenge(const DATA_BLOB blob,
			    DATA_BLOB *chal1, DATA_BLOB *chal2);
DATA_BLOB spnego_gen_auth(DATA_BLOB blob);
bool spnego_parse_auth(DATA_BLOB blob, DATA_BLOB *auth);
DATA_BLOB spnego_gen_auth_response(DATA_BLOB *reply, NTSTATUS nt_status,
				   const char *mechOID);
bool spnego_parse_auth_response(DATA_BLOB blob, NTSTATUS nt_status,
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
			struct cli_state *cli,
			char *dest,
			const void *src,
			int dest_len,
			int src_len,
			int flags);
size_t clistr_pull_talloc_fn(const char *function,
				unsigned int line,
				TALLOC_CTX *ctx,
				struct cli_state *cli,
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

/* The following definitions come from libsmb/conncache.c  */

NTSTATUS check_negative_conn_cache_timeout( const char *domain, const char *server, unsigned int failed_cache_timeout );
NTSTATUS check_negative_conn_cache( const char *domain, const char *server);
void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) ;
void delete_negative_conn_cache(const char *domain, const char *server);
void flush_negative_conn_cache( void );
void flush_negative_conn_cache_for_domain(const char *domain);

/* The following definitions come from libsmb/credentials.c  */

char *credstr(const unsigned char *cred);
void creds_server_init(uint32 neg_flags,
			struct dcinfo *dc,
			struct netr_Credential *clnt_chal,
			struct netr_Credential *srv_chal,
			const unsigned char mach_pw[16],
			struct netr_Credential *init_chal_out);
bool netlogon_creds_server_check(const struct dcinfo *dc,
				 const struct netr_Credential *rcv_cli_chal_in);
bool netlogon_creds_server_step(struct dcinfo *dc,
				const struct netr_Authenticator *received_cred,
				struct netr_Authenticator *cred_out);
void creds_client_init(uint32 neg_flags,
			struct dcinfo *dc,
			struct netr_Credential *clnt_chal,
			struct netr_Credential *srv_chal,
			const unsigned char mach_pw[16],
			struct netr_Credential *init_chal_out);
bool netlogon_creds_client_check(const struct dcinfo *dc,
				 const struct netr_Credential *rcv_srv_chal_in);
void netlogon_creds_client_step(struct dcinfo *dc,
				struct netr_Authenticator *next_cred_out);

/* The following definitions come from libsmb/dcerpc_err.c  */

const char *dcerpc_errstr(uint32 fault_code);

/* The following definitions come from libsmb/doserr.c  */

const char *dos_errstr(WERROR werror);
const char *get_friendly_werror_msg(WERROR werror);
const char *win_errstr(WERROR werror);

/* The following definitions come from libsmb/dsgetdcname.c  */

void debug_dsdcinfo_flags(int lvl, uint32_t flags);
NTSTATUS dsgetdcname(TALLOC_CTX *mem_ctx,
		     struct messaging_context *msg_ctx,
		     const char *domain_name,
		     struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info);

/* The following definitions come from libsmb/errormap.c  */

NTSTATUS dos_to_ntstatus(uint8 eclass, uint32 ecode);
void ntstatus_to_dos(NTSTATUS ntstatus, uint8 *eclass, uint32 *ecode);
NTSTATUS werror_to_ntstatus(WERROR error);
WERROR ntstatus_to_werror(NTSTATUS error);
NTSTATUS map_nt_error_from_gss(uint32 gss_maj, uint32 minor);

/* The following definitions come from libsmb/namecache.c  */

bool namecache_enable(void);
bool namecache_shutdown(void);
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
XFILE *startlmhosts(const char *fname);
bool getlmhostsent(TALLOC_CTX *ctx, XFILE *fp, char **pp_name, int *name_type,
		struct sockaddr_storage *pss);
void endlmhosts(XFILE *fp);
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
		int name_type);
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
int name_mangle( char *In, char *Out, char name_type );
int name_extract(char *buf,int ofs, fstring name);
int name_len(char *s1);

/* The following definitions come from libsmb/nterr.c  */

const char *nt_errstr(NTSTATUS nt_code);
const char *get_friendly_nt_error_msg(NTSTATUS nt_code);
const char *get_nt_error_c_code(NTSTATUS nt_code);
NTSTATUS nt_status_string_to_code(char *nt_status_str);
NTSTATUS nt_status_squash(NTSTATUS nt_status);

/* The following definitions come from libsmb/ntlm_check.c  */

NTSTATUS ntlm_password_check(TALLOC_CTX *mem_ctx,
			     const DATA_BLOB *challenge,
			     const DATA_BLOB *lm_response,
			     const DATA_BLOB *nt_response,
			     const DATA_BLOB *lm_interactive_pwd,
			     const DATA_BLOB *nt_interactive_pwd,
			     const char *username, 
			     const char *client_username, 
			     const char *client_domain,
			     const uint8 *lm_pw, const uint8 *nt_pw, 
			     DATA_BLOB *user_sess_key, 
			     DATA_BLOB *lm_sess_key);

/* The following definitions come from libsmb/ntlmssp.c  */

void debug_ntlmssp_flags(uint32 neg_flags);
NTSTATUS ntlmssp_set_username(NTLMSSP_STATE *ntlmssp_state, const char *user) ;
NTSTATUS ntlmssp_set_hashes(NTLMSSP_STATE *ntlmssp_state,
		const unsigned char lm_hash[16],
		const unsigned char nt_hash[16]) ;
NTSTATUS ntlmssp_set_password(NTLMSSP_STATE *ntlmssp_state, const char *password) ;
NTSTATUS ntlmssp_set_domain(NTLMSSP_STATE *ntlmssp_state, const char *domain) ;
NTSTATUS ntlmssp_set_workstation(NTLMSSP_STATE *ntlmssp_state, const char *workstation) ;
NTSTATUS ntlmssp_store_response(NTLMSSP_STATE *ntlmssp_state,
				DATA_BLOB response) ;
void ntlmssp_want_feature_list(NTLMSSP_STATE *ntlmssp_state, char *feature_list);
void ntlmssp_want_feature(NTLMSSP_STATE *ntlmssp_state, uint32 feature);
NTSTATUS ntlmssp_update(NTLMSSP_STATE *ntlmssp_state, 
			const DATA_BLOB in, DATA_BLOB *out) ;
void ntlmssp_end(NTLMSSP_STATE **ntlmssp_state);
DATA_BLOB ntlmssp_weaken_keys(NTLMSSP_STATE *ntlmssp_state, TALLOC_CTX *mem_ctx);
NTSTATUS ntlmssp_server_start(NTLMSSP_STATE **ntlmssp_state);
NTSTATUS ntlmssp_client_start(NTLMSSP_STATE **ntlmssp_state);

/* The following definitions come from libsmb/ntlmssp_parse.c  */

bool msrpc_gen(DATA_BLOB *blob,
	       const char *format, ...);
bool msrpc_parse(const DATA_BLOB *blob,
		 const char *format, ...);

/* The following definitions come from libsmb/ntlmssp_sign.c  */

NTSTATUS ntlmssp_sign_packet(NTLMSSP_STATE *ntlmssp_state,
				    const uchar *data, size_t length, 
				    const uchar *whole_pdu, size_t pdu_length, 
				    DATA_BLOB *sig) ;
NTSTATUS ntlmssp_check_packet(NTLMSSP_STATE *ntlmssp_state,
				const uchar *data, size_t length, 
				const uchar *whole_pdu, size_t pdu_length, 
				const DATA_BLOB *sig) ;
NTSTATUS ntlmssp_seal_packet(NTLMSSP_STATE *ntlmssp_state,
			     uchar *data, size_t length,
			     uchar *whole_pdu, size_t pdu_length,
			     DATA_BLOB *sig);
NTSTATUS ntlmssp_unseal_packet(NTLMSSP_STATE *ntlmssp_state,
				uchar *data, size_t length,
				uchar *whole_pdu, size_t pdu_length,
				DATA_BLOB *sig);
NTSTATUS ntlmssp_sign_init(NTLMSSP_STATE *ntlmssp_state);

/* The following definitions come from libsmb/passchange.c  */

NTSTATUS remote_password_change(const char *remote_machine, const char *user_name, 
				const char *old_passwd, const char *new_passwd,
				char **err_str);

/* The following definitions come from libsmb/pwd_cache.c  */

void pwd_set_cleartext(struct pwd_info *pwd, const char *clr);
void pwd_get_cleartext(struct pwd_info *pwd, fstring clr);

/* The following definitions come from libsmb/samlogon_cache.c  */

bool netsamlogon_cache_init(void);
bool netsamlogon_cache_shutdown(void);
void netsamlogon_clear_cached_user(struct netr_SamInfo3 *info3);
bool netsamlogon_cache_store(const char *username, struct netr_SamInfo3 *info3);
struct netr_SamInfo3 *netsamlogon_cache_get(TALLOC_CTX *mem_ctx, const DOM_SID *user_sid);
bool netsamlogon_cache_have(const DOM_SID *user_sid);

/* The following definitions come from libsmb/smb_seal.c  */

NTSTATUS get_enc_ctx_num(const uint8_t *buf, uint16 *p_enc_ctx_num);
bool common_encryption_on(struct smb_trans_enc_state *es);
NTSTATUS common_ntlm_decrypt_buffer(NTLMSSP_STATE *ntlmssp_state, char *buf);
NTSTATUS common_ntlm_encrypt_buffer(NTLMSSP_STATE *ntlmssp_state,
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

/* The following definitions come from libsmb/smb_signing.c  */

bool cli_simple_set_signing(struct cli_state *cli,
			    const DATA_BLOB user_session_key,
			    const DATA_BLOB response);
bool cli_null_set_signing(struct cli_state *cli);
bool cli_temp_set_signing(struct cli_state *cli);
void cli_free_signing_context(struct cli_state *cli);
void cli_calculate_sign_mac(struct cli_state *cli, char *buf);
bool cli_check_sign_mac(struct cli_state *cli, char *buf);
bool client_set_trans_sign_state_on(struct cli_state *cli, uint16 mid);
bool client_set_trans_sign_state_off(struct cli_state *cli, uint16 mid);
bool client_is_signing_on(struct cli_state *cli);
bool srv_oplock_set_signing(bool onoff);
bool srv_check_sign_mac(const char *inbuf, bool must_be_ok);
void srv_calculate_sign_mac(char *outbuf);
void srv_defer_sign_response(uint16 mid);
void srv_cancel_sign_response(uint16 mid, bool cancel);
void srv_set_signing_negotiated(void);
bool srv_is_signing_active(void);
bool srv_is_signing_negotiated(void);
bool srv_signing_started(void);
void srv_set_signing(const DATA_BLOB user_session_key, const DATA_BLOB response);

/* The following definitions come from libsmb/smbdes.c  */

void des_crypt56(unsigned char *out, const unsigned char *in, const unsigned char *key, int forw);
void E_P16(const unsigned char *p14,unsigned char *p16);
void E_P24(const unsigned char *p21, const unsigned char *c8, unsigned char *p24);
void D_P16(const unsigned char *p14, const unsigned char *in, unsigned char *out);
void E_old_pw_hash( unsigned char *p14, const unsigned char *in, unsigned char *out);
void des_crypt128(unsigned char out[8], const unsigned char in[8], const unsigned char key[16]);
void des_crypt64(unsigned char out[8], const unsigned char in[8], const unsigned char key[8]);
void des_crypt112(unsigned char out[8], const unsigned char in[8], const unsigned char key[14], int forw);
void cred_hash3(unsigned char *out, const unsigned char *in, const unsigned char *key, int forw);
void des_crypt112_16(unsigned char out[16], unsigned char in[16], const unsigned char key[14], int forw);
void SamOEMhash( unsigned char *data, const unsigned char key[16], size_t len);
void SamOEMhashBlob( unsigned char *data, size_t len, DATA_BLOB *key);
void sam_pwd_hash(unsigned int rid, const uchar *in, uchar *out, int forw);

/* The following definitions come from libsmb/smbencrypt.c  */

void SMBencrypt_hash(const uchar lm_hash[16], const uchar *c8, uchar p24[24]);
bool SMBencrypt(const char *passwd, const uchar *c8, uchar p24[24]);
void E_md4hash(const char *passwd, uchar p16[16]);
void E_md5hash(const uchar salt[16], const uchar nthash[16], uchar hash_out[16]);
bool E_deshash(const char *passwd, uchar p16[16]);
void nt_lm_owf_gen(const char *pwd, uchar nt_p16[16], uchar p16[16]);
bool ntv2_owf_gen(const uchar owf[16],
		  const char *user_in, const char *domain_in,
		  bool upper_case_domain, /* Transform the domain into UPPER case */
		  uchar kr_buf[16]);
void SMBOWFencrypt(const uchar passwd[16], const uchar *c8, uchar p24[24]);
void NTLMSSPOWFencrypt(const uchar passwd[8], const uchar *ntlmchalresp, uchar p24[24]);
void SMBNTencrypt_hash(const uchar nt_hash[16], uchar *c8, uchar *p24);
void SMBNTencrypt(const char *passwd, uchar *c8, uchar *p24);
void SMBOWFencrypt_ntv2(const uchar kr[16],
			const DATA_BLOB *srv_chal,
			const DATA_BLOB *cli_chal,
			uchar resp_buf[16]);
void SMBsesskeygen_ntv2(const uchar kr[16],
			const uchar * nt_resp, uint8 sess_key[16]);
void SMBsesskeygen_ntv1(const uchar kr[16],
			const uchar * nt_resp, uint8 sess_key[16]);
void SMBsesskeygen_lm_sess_key(const uchar lm_hash[16],
			const uchar lm_resp[24], /* only uses 8 */ 
			uint8 sess_key[16]);
DATA_BLOB NTLMv2_generate_names_blob(const char *hostname, 
				     const char *domain);
bool SMBNTLMv2encrypt_hash(const char *user, const char *domain, const uchar nt_hash[16], 
		      const DATA_BLOB *server_chal, 
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response, 
		      DATA_BLOB *user_session_key) ;
bool SMBNTLMv2encrypt(const char *user, const char *domain, const char *password, 
		      const DATA_BLOB *server_chal, 
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response, 
		      DATA_BLOB *user_session_key) ;
bool encode_pw_buffer(uint8 buffer[516], const char *password, int string_flags);
bool decode_pw_buffer(TALLOC_CTX *ctx,
			uint8 in_buffer[516],
			char **pp_new_pwrd,
			uint32 *new_pw_len,
			int string_flags);
void encode_or_decode_arc4_passwd_buffer(unsigned char pw_buf[532], const DATA_BLOB *psession_key);
void sess_crypt_blob(DATA_BLOB *out, const DATA_BLOB *in, const DATA_BLOB *session_key, int forward);
char *decrypt_trustdom_secret(uint8_t nt_hash[16], DATA_BLOB *data_in);
void encode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					const char *pwd,
					DATA_BLOB *session_key,
					struct wkssvc_PasswordBuffer **pwd_buf);
WERROR decode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  struct wkssvc_PasswordBuffer *pwd_buf,
					  DATA_BLOB *session_key,
					  char **pwd);
DATA_BLOB decrypt_drsuapi_blob(TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *session_key,
			       bool rcrypt,
			       uint32_t rid,
			       const DATA_BLOB *buffer);

/* The following definitions come from libsmb/smberr.c  */

const char *smb_dos_err_name(uint8 e_class, uint16 num);
const char *get_dos_error_msg(WERROR result);
const char *smb_dos_err_class(uint8 e_class);
char *smb_dos_errstr(char *inbuf);
WERROR map_werror_from_unix(int error);

/* The following definitions come from libsmb/spnego.c  */

ssize_t read_spnego_data(DATA_BLOB data, SPNEGO_DATA *token);
ssize_t write_spnego_data(DATA_BLOB *blob, SPNEGO_DATA *spnego);
bool free_spnego_data(SPNEGO_DATA *spnego);

/* The following definitions come from libsmb/trustdom_cache.c  */

bool trustdom_cache_enable(void);
bool trustdom_cache_shutdown(void);
bool trustdom_cache_store(char* name, char* alt_name, const DOM_SID *sid,
                          time_t timeout);
bool trustdom_cache_fetch(const char* name, DOM_SID* sid);
uint32 trustdom_cache_fetch_timestamp( void );
bool trustdom_cache_store_timestamp( uint32 t, time_t timeout );
void trustdom_cache_flush(void);
void update_trustdom_cache( void );

/* The following definitions come from libsmb/trusts_util.c  */

NTSTATUS trust_pw_change_and_store_it(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				      const char *domain,
				      unsigned char orig_trust_passwd_hash[16],
				      uint32 sec_channel_type);
NTSTATUS trust_pw_find_change_and_store_it(struct rpc_pipe_client *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) ;
bool enumerate_domain_trusts( TALLOC_CTX *mem_ctx, const char *domain,
                                     char ***domain_names, uint32 *num_domains,
				     DOM_SID **sids );

/* The following definitions come from libsmb/unexpected.c  */

void unexpected_packet(struct packet_struct *p);
void clear_unexpected(time_t t);
struct packet_struct *receive_unexpected(enum packet_type packet_type, int id,
					 const char *mailslot_name);

/* The following definitions come from locking/brlock.c  */

bool brl_same_context(const struct lock_context *ctx1, 
			     const struct lock_context *ctx2);
void brl_init(bool read_only);
void brl_shutdown(void);
NTSTATUS brl_lock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
		uint32 smbpid,
		struct server_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		bool blocking_lock,
		uint32 *psmbpid);
bool brl_unlock(struct messaging_context *msg_ctx,
		struct byte_range_lock *br_lck,
		uint32 smbpid,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav);
bool brl_locktest(struct byte_range_lock *br_lck,
		uint32 smbpid,
		struct server_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav);
NTSTATUS brl_lockquery(struct byte_range_lock *br_lck,
		uint32 *psmbpid,
		struct server_id pid,
		br_off *pstart,
		br_off *psize, 
		enum brl_type *plock_type,
		enum brl_flavour lock_flav);
bool brl_lock_cancel(struct byte_range_lock *br_lck,
		uint32 smbpid,
		struct server_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav);
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
struct byte_range_lock *brl_get_locks_readonly(TALLOC_CTX *mem_ctx,
					files_struct *fsp);
void brl_register_msgs(struct messaging_context *msg_ctx);

/* The following definitions come from locking/locking.c  */

const char *lock_type_name(enum brl_type lock_type);
const char *lock_flav_name(enum brl_flavour lock_flav);
bool is_locked(files_struct *fsp,
		uint32 smbpid,
		SMB_BIG_UINT count,
		SMB_BIG_UINT offset, 
		enum brl_type lock_type);
NTSTATUS query_lock(files_struct *fsp,
			uint32 *psmbpid,
			SMB_BIG_UINT *pcount,
			SMB_BIG_UINT *poffset,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
struct byte_range_lock *do_lock(struct messaging_context *msg_ctx,
			files_struct *fsp,
			uint32 lock_pid,
			SMB_BIG_UINT count,
			SMB_BIG_UINT offset,
			enum brl_type lock_type,
			enum brl_flavour lock_flav,
			bool blocking_lock,
			NTSTATUS *perr,
			uint32 *plock_pid);
NTSTATUS do_unlock(struct messaging_context *msg_ctx,
			files_struct *fsp,
			uint32 lock_pid,
			SMB_BIG_UINT count,
			SMB_BIG_UINT offset,
			enum brl_flavour lock_flav);
NTSTATUS do_lock_cancel(files_struct *fsp,
			uint32 lock_pid,
			SMB_BIG_UINT count,
			SMB_BIG_UINT offset,
			enum brl_flavour lock_flav);
void locking_close_file(struct messaging_context *msg_ctx,
			files_struct *fsp);
bool locking_init(void);
bool locking_init_readonly(void);
bool locking_end(void);
char *share_mode_str(TALLOC_CTX *ctx, int num, const struct share_mode_entry *e);
struct share_mode_lock *get_share_mode_lock(TALLOC_CTX *mem_ctx,
					    const struct file_id id,
					    const char *servicepath,
					    const char *fname,
					    const struct timespec *old_write_time);
struct share_mode_lock *fetch_share_mode_unlocked(TALLOC_CTX *mem_ctx,
						  const struct file_id id,
						  const char *servicepath,
						  const char *fname);
bool rename_share_filename(struct messaging_context *msg_ctx,
			struct share_mode_lock *lck,
			const char *servicepath,
			const char *newname);
void get_file_infos(struct file_id id,
		    bool *delete_on_close,
		    struct timespec *write_time);
bool is_valid_share_mode_entry(const struct share_mode_entry *e);
bool is_deferred_open_entry(const struct share_mode_entry *e);
bool is_unused_share_mode_entry(const struct share_mode_entry *e);
void set_share_mode(struct share_mode_lock *lck, files_struct *fsp,
		    uid_t uid, uint16 mid, uint16 op_type);
void add_deferred_open(struct share_mode_lock *lck, uint16 mid,
		       struct timeval request_time,
		       struct file_id id);
bool del_share_mode(struct share_mode_lock *lck, files_struct *fsp);
void del_deferred_open_entry(struct share_mode_lock *lck, uint16 mid);
bool remove_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
bool downgrade_share_oplock(struct share_mode_lock *lck, files_struct *fsp);
NTSTATUS can_set_delete_on_close(files_struct *fsp, bool delete_on_close,
				 uint32 dosmode);
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
			SMB_BIG_UINT *pu_offset,
			SMB_BIG_UINT *pu_count,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav);
bool posix_locking_init(bool read_only);
bool posix_locking_end(void);
void reduce_windows_lock_ref_count(files_struct *fsp, unsigned int dcount);
int fd_close_posix(struct files_struct *fsp);
bool set_posix_lock_windows_flavour(files_struct *fsp,
			SMB_BIG_UINT u_offset,
			SMB_BIG_UINT u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			const struct lock_struct *plocks,
			int num_locks,
			int *errno_ret);
bool release_posix_lock_windows_flavour(files_struct *fsp,
				SMB_BIG_UINT u_offset,
				SMB_BIG_UINT u_count,
				enum brl_type deleted_lock_type,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);
bool set_posix_lock_posix_flavour(files_struct *fsp,
			SMB_BIG_UINT u_offset,
			SMB_BIG_UINT u_count,
			enum brl_type lock_type,
			int *errno_ret);
bool release_posix_lock_posix_flavour(files_struct *fsp,
				SMB_BIG_UINT u_offset,
				SMB_BIG_UINT u_count,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks);

/* The following definitions come from modules/vfs_default.c  */

int vfswrap_lstat(vfs_handle_struct *handle,  const char *path, SMB_STRUCT_STAT *sbuf);
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
const char **lp_idmap_domains(void);
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
bool lp_large_readwrite(void);
bool lp_writeraw(void);
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
bool lp_use_kerberos_keytab(void);
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
char *lp_iprint_server(void);
int lp_cups_connection_timeout(void);
const char *lp_ctdbd_socket(void);
const char **lp_cluster_addresses(void);
bool lp_clustering(void);
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
bool lp_fake_dir_create_times(int );
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
bool lp_config_backend_is_registry(void);
bool lp_config_backend_is_file(void);
bool lp_file_list_changed(void);
bool lp_idmap_uid(uid_t *low, uid_t *high);
bool lp_idmap_gid(gid_t *low, gid_t *high);
const char *lp_ldap_machine_suffix(void);
const char *lp_ldap_user_suffix(void);
const char *lp_ldap_group_suffix(void);
const char *lp_ldap_idmap_suffix(void);
void *lp_local_ptr(int snum, void *ptr);
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
			SEC_DESC **ppsd,
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
int lp_server_role(void);
bool lp_domain_master(void);
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
bool lp_use_sendfile(int snum);
void set_use_sendfile(int snum, bool val);
void set_store_dos_attributes(int snum, bool val);
void lp_set_mangling_method(const char *new_method);
bool lp_posix_pathnames(void);
void lp_set_posix_pathnames(void);
enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp);
void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val);
int lp_min_receive_file_size(void);

/* The following definitions come from param/params.c  */

bool pm_process( const char *FileName,
		bool (*sfunc)(const char *, void *),
		bool (*pfunc)(const char *, const char *, void *),
		void *userdata);

/* The following definitions come from param/util.c  */

uint32 get_int_param( const char* param );
char* get_string_param( const char* param );

/* The following definitions come from passdb/login_cache.c  */

bool login_cache_init(void);
bool login_cache_shutdown(void);
LOGIN_CACHE * login_cache_read(struct samu *sampass);
bool login_cache_write(const struct samu *sampass, LOGIN_CACHE entry);
bool login_cache_delentry(const struct samu *sampass);

/* The following definitions come from passdb/lookup_sid.c  */

bool lookup_name(TALLOC_CTX *mem_ctx,
		 const char *full_name, int flags,
		 const char **ret_domain, const char **ret_name,
		 DOM_SID *ret_sid, enum lsa_SidType *ret_type);
bool lookup_name_smbconf(TALLOC_CTX *mem_ctx,
		 const char *full_name, int flags,
		 const char **ret_domain, const char **ret_name,
		 DOM_SID *ret_sid, enum lsa_SidType *ret_type);
NTSTATUS lookup_sids(TALLOC_CTX *mem_ctx, int num_sids,
		     const DOM_SID **sids, int level,
		     struct lsa_dom_info **ret_domains,
		     struct lsa_name_info **ret_names);
bool lookup_sid(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
		const char **ret_domain, const char **ret_name,
		enum lsa_SidType *ret_type);
void store_uid_sid_cache(const DOM_SID *psid, uid_t uid);
void store_gid_sid_cache(const DOM_SID *psid, gid_t gid);
void uid_to_sid(DOM_SID *psid, uid_t uid);
void gid_to_sid(DOM_SID *psid, gid_t gid);
bool sid_to_uid(const DOM_SID *psid, uid_t *puid);
bool sid_to_gid(const DOM_SID *psid, gid_t *pgid);

/* The following definitions come from passdb/machine_sid.c  */

DOM_SID *get_global_sam_sid(void);
void reset_global_sam_sid(void) ;
bool sid_check_is_domain(const DOM_SID *sid);
bool sid_check_is_in_our_domain(const DOM_SID *sid);

/* The following definitions come from passdb/passdb.c  */

const char *my_sam_name(void);
struct samu *samu_new( TALLOC_CTX *ctx );
NTSTATUS samu_set_unix(struct samu *user, const struct passwd *pwd);
NTSTATUS samu_alloc_rid_unix(struct samu *user, const struct passwd *pwd);
char *pdb_encode_acct_ctrl(uint32 acct_ctrl, size_t length);
uint32 pdb_decode_acct_ctrl(const char *p);
void pdb_sethexpwd(char p[33], const unsigned char *pwd, uint32 acct_ctrl);
bool pdb_gethexpwd(const char *p, unsigned char *pwd);
void pdb_sethexhours(char *p, const unsigned char *hours);
bool pdb_gethexhours(const char *p, unsigned char *hours);
int algorithmic_rid_base(void);
uid_t algorithmic_pdb_user_rid_to_uid(uint32 user_rid);
uid_t max_algorithmic_uid(void);
uint32 algorithmic_pdb_uid_to_user_rid(uid_t uid);
gid_t pdb_group_rid_to_gid(uint32 group_rid);
gid_t max_algorithmic_gid(void);
uint32 algorithmic_pdb_gid_to_group_rid(gid_t gid);
bool algorithmic_pdb_rid_is_user(uint32 rid);
bool lookup_global_sam_name(const char *name, int flags, uint32_t *rid,
			    enum lsa_SidType *type);
NTSTATUS local_password_change(const char *user_name,
				int local_flags,
				const char *new_passwd, 
				char **pp_err_str,
				char **pp_msg_str);
bool init_samu_from_buffer(struct samu *sampass, uint32_t level,
			   uint8 *buf, uint32 buflen);
uint32 init_buffer_from_samu (uint8 **buf, struct samu *sampass, bool size_only);
bool pdb_copy_sam_account(struct samu *dst, struct samu *src );
bool pdb_update_bad_password_count(struct samu *sampass, bool *updated);
bool pdb_update_autolock_flag(struct samu *sampass, bool *updated);
bool pdb_increment_bad_password_count(struct samu *sampass);
bool is_dc_trusted_domain_situation(const char *domain_name);
bool get_trust_pw_clear(const char *domain, char **ret_pwd,
			const char **account_name, uint32 *channel);
bool get_trust_pw_hash(const char *domain, uint8 ret_pwd[16],
		       const char **account_name, uint32 *channel);
struct samr_LogonHours get_logon_hours_from_pdb(TALLOC_CTX *mem_ctx,
						struct samu *pw);

/* The following definitions come from passdb/pdb_compat.c  */

uint32 pdb_get_user_rid (const struct samu *sampass);
uint32 pdb_get_group_rid (struct samu *sampass);
bool pdb_set_user_sid_from_rid (struct samu *sampass, uint32 rid, enum pdb_value_state flag);
bool pdb_set_group_sid_from_rid (struct samu *sampass, uint32 grid, enum pdb_value_state flag);

/* The following definitions come from passdb/pdb_get_set.c  */

uint32 pdb_get_acct_ctrl(const struct samu *sampass);
time_t pdb_get_logon_time(const struct samu *sampass);
time_t pdb_get_logoff_time(const struct samu *sampass);
time_t pdb_get_kickoff_time(const struct samu *sampass);
time_t pdb_get_bad_password_time(const struct samu *sampass);
time_t pdb_get_pass_last_set_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time(const struct samu *sampass);
time_t pdb_get_pass_can_change_time_noncalc(const struct samu *sampass);
time_t pdb_get_pass_must_change_time(const struct samu *sampass);
bool pdb_get_pass_can_change(const struct samu *sampass);
uint16 pdb_get_logon_divs(const struct samu *sampass);
uint32 pdb_get_hours_len(const struct samu *sampass);
const uint8 *pdb_get_hours(const struct samu *sampass);
const uint8 *pdb_get_nt_passwd(const struct samu *sampass);
const uint8 *pdb_get_lanman_passwd(const struct samu *sampass);
const uint8 *pdb_get_pw_history(const struct samu *sampass, uint32 *current_hist_len);
const char *pdb_get_plaintext_passwd(const struct samu *sampass);
const DOM_SID *pdb_get_user_sid(const struct samu *sampass);
const DOM_SID *pdb_get_group_sid(struct samu *sampass);
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
uint16 pdb_get_bad_password_count(const struct samu *sampass);
uint16 pdb_get_logon_count(const struct samu *sampass);
uint32 pdb_get_unknown_6(const struct samu *sampass);
void *pdb_get_backend_private_data(const struct samu *sampass, const struct pdb_methods *my_methods);
bool pdb_set_acct_ctrl(struct samu *sampass, uint32 acct_ctrl, enum pdb_value_state flag);
bool pdb_set_logon_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_logoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_kickoff_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_bad_password_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_can_change_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_must_change_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_pass_last_set_time(struct samu *sampass, time_t mytime, enum pdb_value_state flag);
bool pdb_set_hours_len(struct samu *sampass, uint32 len, enum pdb_value_state flag);
bool pdb_set_logon_divs(struct samu *sampass, uint16 hours, enum pdb_value_state flag);
bool pdb_set_init_flags(struct samu *sampass, enum pdb_elements element, enum pdb_value_state value_flag);
bool pdb_set_user_sid(struct samu *sampass, const DOM_SID *u_sid, enum pdb_value_state flag);
bool pdb_set_user_sid_from_string(struct samu *sampass, fstring u_sid, enum pdb_value_state flag);
bool pdb_set_group_sid(struct samu *sampass, const DOM_SID *g_sid, enum pdb_value_state flag);
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
bool pdb_set_nt_passwd(struct samu *sampass, const uint8 pwd[NT_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_lanman_passwd(struct samu *sampass, const uint8 pwd[LM_HASH_LEN], enum pdb_value_state flag);
bool pdb_set_pw_history(struct samu *sampass, const uint8 *pwd, uint32 historyLen, enum pdb_value_state flag);
bool pdb_set_plaintext_pw_only(struct samu *sampass, const char *password, enum pdb_value_state flag);
bool pdb_set_bad_password_count(struct samu *sampass, uint16 bad_password_count, enum pdb_value_state flag);
bool pdb_set_logon_count(struct samu *sampass, uint16 logon_count, enum pdb_value_state flag);
bool pdb_set_unknown_6(struct samu *sampass, uint32 unkn, enum pdb_value_state flag);
bool pdb_set_hours(struct samu *sampass, const uint8 *hours, enum pdb_value_state flag);
bool pdb_set_backend_private_data(struct samu *sampass, void *private_data, 
				   void (*free_fn)(void **), 
				   const struct pdb_methods *my_methods, 
				   enum pdb_value_state flag);
bool pdb_set_pass_can_change(struct samu *sampass, bool canchange);
bool pdb_set_plaintext_passwd(struct samu *sampass, const char *plaintext);
uint32 pdb_build_fields_present(struct samu *sampass);

/* The following definitions come from passdb/pdb_interface.c  */

NTSTATUS smb_register_passdb(int version, const char *name, pdb_init_function init) ;
struct pdb_init_function_entry *pdb_find_backend_entry(const char *name);
struct event_context *pdb_get_event_context(void);
NTSTATUS make_pdb_method_name(struct pdb_methods **methods, const char *selected);
bool pdb_getsampwnam(struct samu *sam_acct, const char *username) ;
bool guest_user_info( struct samu *user );
bool pdb_getsampwsid(struct samu *sam_acct, const DOM_SID *sid) ;
NTSTATUS pdb_create_user(TALLOC_CTX *mem_ctx, const char *name, uint32 flags,
			 uint32 *rid);
NTSTATUS pdb_delete_user(TALLOC_CTX *mem_ctx, struct samu *sam_acct);
NTSTATUS pdb_add_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_update_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_delete_sam_account(struct samu *sam_acct) ;
NTSTATUS pdb_rename_sam_account(struct samu *oldname, const char *newname);
NTSTATUS pdb_update_login_attempts(struct samu *sam_acct, bool success);
bool pdb_getgrsid(GROUP_MAP *map, DOM_SID sid);
bool pdb_getgrgid(GROUP_MAP *map, gid_t gid);
bool pdb_getgrnam(GROUP_MAP *map, const char *name);
NTSTATUS pdb_create_dom_group(TALLOC_CTX *mem_ctx, const char *name,
			      uint32 *rid);
NTSTATUS pdb_delete_dom_group(TALLOC_CTX *mem_ctx, uint32 rid);
NTSTATUS pdb_add_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_update_group_mapping_entry(GROUP_MAP *map);
NTSTATUS pdb_delete_group_mapping_entry(DOM_SID sid);
bool pdb_enum_group_mapping(const DOM_SID *sid, enum lsa_SidType sid_name_use, GROUP_MAP **pp_rmap,
			    size_t *p_num_entries, bool unix_only);
NTSTATUS pdb_enum_group_members(TALLOC_CTX *mem_ctx,
				const DOM_SID *sid,
				uint32 **pp_member_rids,
				size_t *p_num_members);
NTSTATUS pdb_enum_group_memberships(TALLOC_CTX *mem_ctx, struct samu *user,
				    DOM_SID **pp_sids, gid_t **pp_gids,
				    size_t *p_num_groups);
NTSTATUS pdb_set_unix_primary_group(TALLOC_CTX *mem_ctx, struct samu *user);
NTSTATUS pdb_add_groupmem(TALLOC_CTX *mem_ctx, uint32 group_rid,
			  uint32 member_rid);
NTSTATUS pdb_del_groupmem(TALLOC_CTX *mem_ctx, uint32 group_rid,
			  uint32 member_rid);
NTSTATUS pdb_create_alias(const char *name, uint32 *rid);
NTSTATUS pdb_delete_alias(const DOM_SID *sid);
NTSTATUS pdb_get_aliasinfo(const DOM_SID *sid, struct acct_info *info);
NTSTATUS pdb_set_aliasinfo(const DOM_SID *sid, struct acct_info *info);
NTSTATUS pdb_add_aliasmem(const DOM_SID *alias, const DOM_SID *member);
NTSTATUS pdb_del_aliasmem(const DOM_SID *alias, const DOM_SID *member);
NTSTATUS pdb_enum_aliasmem(const DOM_SID *alias,
			   DOM_SID **pp_members, size_t *p_num_members);
NTSTATUS pdb_enum_alias_memberships(TALLOC_CTX *mem_ctx,
				    const DOM_SID *domain_sid,
				    const DOM_SID *members, size_t num_members,
				    uint32 **pp_alias_rids,
				    size_t *p_num_alias_rids);
NTSTATUS pdb_lookup_rids(const DOM_SID *domain_sid,
			 int num_rids,
			 uint32 *rids,
			 const char **names,
			 enum lsa_SidType *attrs);
NTSTATUS pdb_lookup_names(const DOM_SID *domain_sid,
			  int num_names,
			  const char **names,
			  uint32 *rids,
			  enum lsa_SidType *attrs);
bool pdb_get_account_policy(int policy_index, uint32 *value);
bool pdb_set_account_policy(int policy_index, uint32 value);
bool pdb_get_seq_num(time_t *seq_num);
bool pdb_uid_to_rid(uid_t uid, uint32 *rid);
bool pdb_uid_to_sid(uid_t uid, DOM_SID *sid);
bool pdb_gid_to_sid(gid_t gid, DOM_SID *sid);
bool pdb_sid_to_id(const DOM_SID *sid, union unid_t *id,
		   enum lsa_SidType *type);
bool pdb_rid_algorithm(void);
bool pdb_new_rid(uint32 *rid);
bool initialize_password_db(bool reload, struct event_context *event_ctx);
struct pdb_search *pdb_search_init(enum pdb_search_type type);
struct pdb_search *pdb_search_users(uint32 acct_flags);
struct pdb_search *pdb_search_groups(void);
struct pdb_search *pdb_search_aliases(const DOM_SID *sid);
uint32 pdb_search_entries(struct pdb_search *search,
			  uint32 start_idx, uint32 max_entries,
			  struct samr_displayentry **result);
void pdb_search_destroy(struct pdb_search *search);
bool pdb_get_trusteddom_pw(const char *domain, char** pwd, DOM_SID *sid, 
			   time_t *pass_last_set_time);
bool pdb_set_trusteddom_pw(const char* domain, const char* pwd,
			   const DOM_SID *sid);
bool pdb_del_trusteddom_pw(const char *domain);
NTSTATUS pdb_enum_trusteddoms(TALLOC_CTX *mem_ctx, uint32 *num_domains,
			      struct trustdom_info ***domains);
NTSTATUS make_pdb_method( struct pdb_methods **methods ) ;

/* The following definitions come from passdb/pdb_ldap.c  */

const char** get_userattr_list( TALLOC_CTX *mem_ctx, int schema_ver );
int ldapsam_search_suffix_by_name(struct ldapsam_privates *ldap_state,
					  const char *user,
					  LDAPMessage ** result,
					  const char **attr);
const char **talloc_attrs(TALLOC_CTX *mem_ctx, ...);
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

/* The following definitions come from passdb/pdb_tdb.c  */

bool init_sam_from_buffer_v2(struct samu *sampass, uint8 *buf, uint32 buflen);
NTSTATUS pdb_tdbsam_init(void);

/* The following definitions come from passdb/secrets.c  */

bool secrets_init(void);
struct db_context *secrets_db_ctx(void);
void secrets_shutdown(void);
void *secrets_fetch(const char *key, size_t *size);
bool secrets_store(const char *key, const void *data, size_t size);
bool secrets_delete(const char *key);
bool secrets_store_domain_sid(const char *domain, const DOM_SID *sid);
bool secrets_fetch_domain_sid(const char *domain, DOM_SID *sid);
bool secrets_store_domain_guid(const char *domain, struct GUID *guid);
bool secrets_fetch_domain_guid(const char *domain, struct GUID *guid);
void *secrets_get_trust_account_lock(TALLOC_CTX *mem_ctx, const char *domain);
uint32 get_default_sec_channel(void);
bool secrets_fetch_trust_account_password_legacy(const char *domain,
						 uint8 ret_pwd[16],
						 time_t *pass_last_set_time,
						 uint32 *channel);
bool secrets_fetch_trust_account_password(const char *domain, uint8 ret_pwd[16],
					  time_t *pass_last_set_time,
					  uint32 *channel);
bool secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
                                           DOM_SID *sid, time_t *pass_last_set_time);
bool secrets_store_trusted_domain_password(const char* domain, const char* pwd,
                                           const DOM_SID *sid);
bool secrets_delete_machine_password(const char *domain);
bool secrets_delete_machine_password_ex(const char *domain);
bool secrets_delete_domain_sid(const char *domain);
bool secrets_store_machine_password(const char *pass, const char *domain, uint32 sec_channel);
char *secrets_fetch_machine_password(const char *domain,
				     time_t *pass_last_set_time,
				     uint32 *channel);
bool trusted_domain_password_delete(const char *domain);
bool secrets_store_ldap_pw(const char* dn, char* pw);
bool fetch_ldap_pw(char **dn, char** pw);
NTSTATUS secrets_trusted_domains(TALLOC_CTX *mem_ctx, uint32 *num_domains,
				 struct trustdom_info ***domains);
bool secrets_store_afs_keyfile(const char *cell, const struct afs_keyfile *keyfile);
bool secrets_fetch_afs_key(const char *cell, struct afs_key *result);
void secrets_fetch_ipc_userpass(char **username, char **domain, char **password);
bool secrets_store_schannel_session_info(TALLOC_CTX *mem_ctx,
				const char *remote_machine,
				const struct dcinfo *pdc);
bool secrets_restore_schannel_session_info(TALLOC_CTX *mem_ctx,
				const char *remote_machine,
				struct dcinfo **ppdc);
bool secrets_store_generic(const char *owner, const char *key, const char *secret);
char *secrets_fetch_generic(const char *owner, const char *key);

/* The following definitions come from passdb/util_builtin.c  */

bool lookup_builtin_rid(TALLOC_CTX *mem_ctx, uint32 rid, const char **name);
bool lookup_builtin_name(const char *name, uint32 *rid);
const char *builtin_domain_name(void);
bool sid_check_is_builtin(const DOM_SID *sid);
bool sid_check_is_in_builtin(const DOM_SID *sid);

/* The following definitions come from passdb/util_unixsids.c  */

bool sid_check_is_unix_users(const DOM_SID *sid);
bool sid_check_is_in_unix_users(const DOM_SID *sid);
bool uid_to_unix_users_sid(uid_t uid, DOM_SID *sid);
bool gid_to_unix_groups_sid(gid_t gid, DOM_SID *sid);
const char *unix_users_domain_name(void);
bool lookup_unix_user_name(const char *name, DOM_SID *sid);
bool sid_check_is_unix_groups(const DOM_SID *sid);
bool sid_check_is_in_unix_groups(const DOM_SID *sid);
const char *unix_groups_domain_name(void);
bool lookup_unix_group_name(const char *name, DOM_SID *sid);

/* The following definitions come from passdb/util_wellknown.c  */

bool sid_check_is_wellknown_domain(const DOM_SID *sid, const char **name);
bool sid_check_is_in_wellknown_domain(const DOM_SID *sid);
bool lookup_wellknown_sid(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			  const char **domain, const char **name);
bool lookup_wellknown_name(TALLOC_CTX *mem_ctx, const char *name,
			   DOM_SID *sid, const char **domain);

/* The following definitions come from printing/load.c  */

void load_printers(void);

/* The following definitions come from printing/lpq_parse.c  */

bool parse_lpq_entry(enum printing_types printing_type,char *line,
		     print_queue_struct *buf,
		     print_status_struct *status,bool first);

/* The following definitions come from printing/notify.c  */

int print_queue_snum(const char *qname);
bool print_notify_messages_pending(void);
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
void notify_printer_driver(int snum, char *driver_name);
void notify_printer_comment(int snum, char *comment);
void notify_printer_sharename(int snum, char *share_name);
void notify_printer_printername(int snum, char *printername);
void notify_printer_port(int snum, char *port_name);
void notify_printer_location(int snum, char *location);
void notify_printer_byname( const char *printername, uint32 change, const char *value );
bool print_notify_pid_list(const char *printername, TALLOC_CTX *mem_ctx, size_t *p_num_pids, pid_t **pp_pid_list);

/* The following definitions come from printing/nt_printing.c  */

bool nt_printing_init(struct messaging_context *msg_ctx);
uint32 update_c_setprinter(bool initialize);
uint32 get_c_setprinter(void);
int get_builtin_ntforms(nt_forms_struct **list);
bool get_a_builtin_ntform(UNISTR2 *uni_formname,nt_forms_struct *form);
int get_ntforms(nt_forms_struct **list);
int write_ntforms(nt_forms_struct **list, int number);
bool add_a_form(nt_forms_struct **list, const FORM *form, int *count);
bool delete_a_form(nt_forms_struct **list, UNISTR2 *del_name, int *count, WERROR *ret);
void update_a_form(nt_forms_struct **list, const FORM *form, int count);
int get_ntdrivers(fstring **list, const char *architecture, uint32 version);
const char *get_short_archi(const char *long_archi);
WERROR clean_up_driver_struct(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract,
							  uint32 level, struct current_user *user);
WERROR move_driver_to_download_area(NT_PRINTER_DRIVER_INFO_LEVEL driver_abstract, uint32 level, 
				  struct current_user *user, WERROR *perr);
int pack_devicemode(NT_DEVICEMODE *nt_devmode, uint8 *buf, int buflen);
uint32 del_a_printer(const char *sharename);
NT_DEVICEMODE *construct_nt_devicemode(const fstring default_devicename);
NT_DEVICEMODE *dup_nt_devicemode(NT_DEVICEMODE *nt_devicemode);
void free_nt_devicemode(NT_DEVICEMODE **devmode_ptr);
int unpack_devicemode(NT_DEVICEMODE **nt_devmode, const uint8 *buf, int buflen);
int add_new_printer_key( NT_PRINTER_DATA *data, const char *name );
int delete_printer_key( NT_PRINTER_DATA *data, const char *name );
int lookup_printerkey( NT_PRINTER_DATA *data, const char *name );
int get_printer_subkeys( NT_PRINTER_DATA *data, const char* key, fstring **subkeys );
WERROR nt_printer_publish(Printer_entry *print_hnd, int snum, int action);
WERROR check_published_printers(void);
bool is_printer_published(Printer_entry *print_hnd, int snum, 
			  struct GUID *guid);
WERROR nt_printer_publish(Printer_entry *print_hnd, int snum, int action);
WERROR check_published_printers(void);
bool is_printer_published(Printer_entry *print_hnd, int snum, 
			  struct GUID *guid);
WERROR delete_all_printer_data( NT_PRINTER_INFO_LEVEL_2 *p2, const char *key );
WERROR delete_printer_data( NT_PRINTER_INFO_LEVEL_2 *p2, const char *key, const char *value );
WERROR add_printer_data( NT_PRINTER_INFO_LEVEL_2 *p2, const char *key, const char *value, 
                           uint32 type, uint8 *data, int real_len );
REGISTRY_VALUE* get_printer_data( NT_PRINTER_INFO_LEVEL_2 *p2, const char *key, const char *value );
WERROR mod_a_printer(NT_PRINTER_INFO_LEVEL *printer, uint32 level);
bool set_driver_init(NT_PRINTER_INFO_LEVEL *printer, uint32 level);
bool del_driver_init(char *drivername);
WERROR save_driver_init(NT_PRINTER_INFO_LEVEL *printer, uint32 level, uint8 *data, uint32 data_len);
WERROR get_a_printer( Printer_entry *print_hnd,
			NT_PRINTER_INFO_LEVEL **pp_printer,
			uint32 level,
			const char *sharename);
WERROR get_a_printer_search( Printer_entry *print_hnd,
			NT_PRINTER_INFO_LEVEL **pp_printer,
			uint32 level,
			const char *sharename);
uint32 free_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level);
uint32 add_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level);
WERROR get_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level,
                            fstring drivername, const char *architecture, uint32 version);
uint32 free_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level);
bool printer_driver_in_use ( NT_PRINTER_DRIVER_INFO_LEVEL_3 *info_3 );
bool printer_driver_files_in_use ( NT_PRINTER_DRIVER_INFO_LEVEL_3 *info );
WERROR delete_printer_driver( NT_PRINTER_DRIVER_INFO_LEVEL_3 *info_3, struct current_user *user,
                              uint32 version, bool delete_files );
WERROR nt_printing_setsec(const char *sharename, SEC_DESC_BUF *secdesc_ctr);
bool nt_printing_getsec(TALLOC_CTX *ctx, const char *sharename, SEC_DESC_BUF **secdesc_ctr);
void map_printer_permissions(SEC_DESC *sd);
void map_job_permissions(SEC_DESC *sd);
bool print_access_check(struct auth_serversupplied_info *server_info, int snum,
			int access_type);
bool print_time_access_check(const char *servicename);
char* get_server_name( Printer_entry *printer );

/* The following definitions come from printing/pcap.c  */

bool pcap_cache_add_specific(struct pcap_cache **ppcache, const char *name, const char *comment);
void pcap_cache_destroy_specific(struct pcap_cache **ppcache);
bool pcap_cache_add(const char *name, const char *comment);
bool pcap_cache_loaded(void);
void pcap_cache_replace(const struct pcap_cache *cache);
void pcap_cache_reload(void);
bool pcap_printername_ok(const char *printername);
void pcap_printer_fn_specific(const struct pcap_cache *, void (*fn)(const char *, const char *, void *), void *);
void pcap_printer_fn(void (*fn)(const char *, const char *, void *), void *);

/* The following definitions come from printing/print_aix.c  */

bool aix_cache_reload(void);

/* The following definitions come from printing/print_cups.c  */

bool cups_cache_reload(void);
bool cups_pull_comment_location(NT_PRINTER_INFO_LEVEL_2 *printer);

/* The following definitions come from printing/print_generic.c  */


/* The following definitions come from printing/print_iprint.c  */

bool iprint_cache_reload(void);

/* The following definitions come from printing/print_svid.c  */

bool sysv_cache_reload(void);

/* The following definitions come from printing/printfsp.c  */

NTSTATUS print_fsp_open(connection_struct *conn, const char *fname,
			uint16_t current_vuid, files_struct *fsp,
			SMB_STRUCT_STAT *psbuf);
void print_fsp_end(files_struct *fsp, enum file_close_type close_type);

/* The following definitions come from printing/printing.c  */

uint16 pjobid_to_rap(const char* sharename, uint32 jobid);
bool rap_to_pjobid(uint16 rap_jobid, fstring sharename, uint32 *pjobid);
bool print_backend_init(struct messaging_context *msg_ctx);
void printing_end(void);
int unpack_pjob( uint8 *buf, int buflen, struct printjob *pjob );
uint32 sysjob_to_jobid(int unix_jobid);
void pjob_delete(const char* sharename, uint32 jobid);
void start_background_queue(void);
bool print_notify_register_pid(int snum);
bool print_notify_deregister_pid(int snum);
bool print_job_exists(const char* sharename, uint32 jobid);
int print_job_fd(const char* sharename, uint32 jobid);
char *print_job_fname(const char* sharename, uint32 jobid);
NT_DEVICEMODE *print_job_devmode(const char* sharename, uint32 jobid);
bool print_job_set_place(const char *sharename, uint32 jobid, int place);
bool print_job_set_name(const char *sharename, uint32 jobid, char *name);
bool print_job_delete(struct auth_serversupplied_info *server_info, int snum,
		      uint32 jobid, WERROR *errcode);
bool print_job_pause(struct auth_serversupplied_info *server_info, int snum,
		     uint32 jobid, WERROR *errcode);
bool print_job_resume(struct auth_serversupplied_info *server_info, int snum,
		      uint32 jobid, WERROR *errcode);
ssize_t print_job_write(int snum, uint32 jobid, const char *buf, SMB_OFF_T pos, size_t size);
int print_queue_length(int snum, print_status_struct *pstatus);
uint32 print_job_start(struct auth_serversupplied_info *server_info, int snum,
		       char *jobname, NT_DEVICEMODE *nt_devmode );
void print_job_endpage(int snum, uint32 jobid);
bool print_job_end(int snum, uint32 jobid, enum file_close_type close_type);
int print_queue_status(int snum, 
		       print_queue_struct **ppqueue,
		       print_status_struct *status);
bool print_queue_pause(struct auth_serversupplied_info *server_info, int snum,
		       WERROR *errcode);
bool print_queue_resume(struct auth_serversupplied_info *server_info, int snum,
			WERROR *errcode);
bool print_queue_purge(struct auth_serversupplied_info *server_info, int snum,
		       WERROR *errcode);

/* The following definitions come from printing/printing_db.c  */

struct tdb_print_db *get_print_db_byname(const char *printername);
void release_print_db( struct tdb_print_db *pdb);
void close_all_print_db(void);
TDB_DATA get_printer_notify_pid_list(TDB_CONTEXT *tdb, const char *printer_name, bool cleanlist);

/* The following definitions come from profile/profile.c  */

void set_profile_level(int level, struct server_id src);
bool profile_setup(struct messaging_context *msg_ctx, bool rdonly);

/* The following definitions come from registry/reg_api.c  */

WERROR reg_openhive(TALLOC_CTX *mem_ctx, const char *hive,
		    uint32 desired_access,
		    const struct nt_user_token *token,
		    struct registry_key **pkey);
WERROR reg_openkey(TALLOC_CTX *mem_ctx, struct registry_key *parent,
		   const char *name, uint32 desired_access,
		   struct registry_key **pkey);
WERROR reg_enumkey(TALLOC_CTX *mem_ctx, struct registry_key *key,
		   uint32 idx, char **name, NTTIME *last_write_time);
WERROR reg_enumvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		     uint32 idx, char **pname, struct registry_value **pval);
WERROR reg_queryvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		      const char *name, struct registry_value **pval);
WERROR reg_queryinfokey(struct registry_key *key, uint32_t *num_subkeys,
			uint32_t *max_subkeylen, uint32_t *max_subkeysize, 
			uint32_t *num_values, uint32_t *max_valnamelen, 
			uint32_t *max_valbufsize, uint32_t *secdescsize,
			NTTIME *last_changed_time);
WERROR reg_createkey(TALLOC_CTX *ctx, struct registry_key *parent,
		     const char *subkeypath, uint32 desired_access,
		     struct registry_key **pkey,
		     enum winreg_CreateAction *paction);
WERROR reg_deletekey(struct registry_key *parent, const char *path);
WERROR reg_setvalue(struct registry_key *key, const char *name,
		    const struct registry_value *val);
WERROR reg_deletevalue(struct registry_key *key, const char *name);
WERROR reg_getkeysecurity(TALLOC_CTX *mem_ctx, struct registry_key *key,
			  struct security_descriptor **psecdesc);
WERROR reg_setkeysecurity(struct registry_key *key,
			  struct security_descriptor *psecdesc);
WERROR reg_getversion(uint32_t *version);
WERROR reg_restorekey(struct registry_key *key, const char *fname);
WERROR reg_savekey(struct registry_key *key, const char *fname);
WERROR reg_deleteallvalues(struct registry_key *key);
WERROR reg_open_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		     uint32 desired_access, const struct nt_user_token *token,
		     struct registry_key **pkey);
WERROR reg_deletekey_recursive(TALLOC_CTX *ctx,
			       struct registry_key *parent,
			       const char *path);
WERROR reg_deletesubkeys_recursive(TALLOC_CTX *ctx,
				   struct registry_key *parent,
				   const char *path);
WERROR reg_create_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		       uint32 desired_access,
		       const struct nt_user_token *token,
		       enum winreg_CreateAction *paction,
		       struct registry_key **pkey);
WERROR reg_delete_path(const struct nt_user_token *token,
		       const char *orig_path);

/* The following definitions come from registry/reg_backend_current_version.c  */


/* The following definitions come from registry/reg_backend_db.c  */

WERROR init_registry_key(const char *add_path);
WERROR init_registry_data(void);
WERROR regdb_init(void);
WERROR regdb_open( void );
int regdb_close( void );
WERROR regdb_transaction_start(void);
WERROR regdb_transaction_commit(void);
WERROR regdb_transaction_cancel(void);
int regdb_get_seqnum(void);
bool regdb_store_keys(const char *key, struct regsubkey_ctr *ctr);
int regdb_fetch_keys(const char *key, struct regsubkey_ctr *ctr);
int regdb_fetch_values( const char* key, REGVAL_CTR *values );
bool regdb_store_values( const char *key, REGVAL_CTR *values );
bool regdb_subkeys_need_update(struct regsubkey_ctr *subkeys);
bool regdb_values_need_update(REGVAL_CTR *values);

/* The following definitions come from registry/reg_backend_hkpt_params.c  */


/* The following definitions come from registry/reg_backend_netlogon_params.c  */


/* The following definitions come from registry/reg_backend_perflib.c  */


/* The following definitions come from registry/reg_backend_printing.c  */


/* The following definitions come from registry/reg_backend_prod_options.c  */


/* The following definitions come from registry/reg_backend_shares.c  */


/* The following definitions come from registry/reg_backend_smbconf.c  */


/* The following definitions come from registry/reg_backend_tcpip_params.c  */


/* The following definitions come from registry/reg_cachehook.c  */

WERROR reghook_cache_init(void);
WERROR reghook_cache_add(const char *keyname, REGISTRY_OPS *ops);
REGISTRY_OPS *reghook_cache_find(const char *keyname);
void reghook_dump_cache( int debuglevel );

/* The following definitions come from registry/reg_dispatcher.c  */

bool store_reg_keys( REGISTRY_KEY *key, struct regsubkey_ctr *subkeys );
bool store_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val );
WERROR create_reg_subkey(REGISTRY_KEY *key, const char *subkey);
WERROR delete_reg_subkey(REGISTRY_KEY *key, const char *subkey);
int fetch_reg_keys( REGISTRY_KEY *key, struct regsubkey_ctr *subkey_ctr );
int fetch_reg_values( REGISTRY_KEY *key, REGVAL_CTR *val );
bool regkey_access_check( REGISTRY_KEY *key, uint32 requested, uint32 *granted,
			  const struct nt_user_token *token );
WERROR regkey_get_secdesc(TALLOC_CTX *mem_ctx, REGISTRY_KEY *key,
			  struct security_descriptor **psecdesc);
WERROR regkey_set_secdesc(REGISTRY_KEY *key,
			  struct security_descriptor *psecdesc);
bool reg_subkeys_need_update(REGISTRY_KEY *key, struct regsubkey_ctr *subkeys);
bool reg_values_need_update(REGISTRY_KEY *key, REGVAL_CTR *values);

/* The following definitions come from registry/reg_eventlog.c  */

bool eventlog_init_keys(void);
bool eventlog_add_source( const char *eventlog, const char *sourcename,
			  const char *messagefile );

/* The following definitions come from registry/reg_init_basic.c  */

WERROR registry_init_common(void);
WERROR registry_init_basic(void);

/* The following definitions come from registry/reg_init_full.c  */

WERROR registry_init_full(void);

/* The following definitions come from registry/reg_init_smbconf.c  */

NTSTATUS registry_create_admin_token(TALLOC_CTX *mem_ctx,
				     NT_USER_TOKEN **ptoken);
WERROR registry_init_smbconf(const char *keyname);

/* The following definitions come from registry/reg_objects.c  */

WERROR regsubkey_ctr_init(TALLOC_CTX *mem_ctx, struct regsubkey_ctr **ctr);
WERROR regsubkey_ctr_set_seqnum(struct regsubkey_ctr *ctr, int seqnum);
int regsubkey_ctr_get_seqnum(struct regsubkey_ctr *ctr);
WERROR regsubkey_ctr_addkey( struct regsubkey_ctr *ctr, const char *keyname );
WERROR regsubkey_ctr_delkey( struct regsubkey_ctr *ctr, const char *keyname );
bool regsubkey_ctr_key_exists( struct regsubkey_ctr *ctr, const char *keyname );
int regsubkey_ctr_numkeys( struct regsubkey_ctr *ctr );
char* regsubkey_ctr_specific_key( struct regsubkey_ctr *ctr, uint32 key_index );
int regval_ctr_numvals( REGVAL_CTR *ctr );
REGISTRY_VALUE* dup_registry_value( REGISTRY_VALUE *val );
void free_registry_value( REGISTRY_VALUE *val );
uint8* regval_data_p( REGISTRY_VALUE *val );
uint32 regval_size( REGISTRY_VALUE *val );
char* regval_name( REGISTRY_VALUE *val );
uint32 regval_type( REGISTRY_VALUE *val );
REGISTRY_VALUE* regval_ctr_specific_value( REGVAL_CTR *ctr, uint32 idx );
bool regval_ctr_key_exists( REGVAL_CTR *ctr, const char *value );
REGISTRY_VALUE *regval_compose(TALLOC_CTX *ctx, const char *name, uint16 type,
			       const char *data_p, size_t size);
int regval_ctr_addvalue( REGVAL_CTR *ctr, const char *name, uint16 type,
                         const char *data_p, size_t size );
int regval_ctr_copyvalue( REGVAL_CTR *ctr, REGISTRY_VALUE *val );
int regval_ctr_delvalue( REGVAL_CTR *ctr, const char *name );
REGISTRY_VALUE* regval_ctr_getvalue( REGVAL_CTR *ctr, const char *name );
uint32 regval_dword( REGISTRY_VALUE *val );
char *regval_sz(REGISTRY_VALUE *val);

/* The following definitions come from registry/reg_perfcount.c  */

void perfcount_init_keys( void );
uint32 reg_perfcount_get_base_index(void);
uint32 reg_perfcount_get_last_counter(uint32 base_index);
uint32 reg_perfcount_get_last_help(uint32 last_counter);
uint32 reg_perfcount_get_counter_help(uint32 base_index, char **retbuf);
uint32 reg_perfcount_get_counter_names(uint32 base_index, char **retbuf);
bool _reg_perfcount_get_counter_data(TDB_DATA key, TDB_DATA *data);
bool _reg_perfcount_get_instance_info(PERF_INSTANCE_DEFINITION *inst,
				      prs_struct *ps,
				      int instId,
				      PERF_OBJECT_TYPE *obj,
				      TDB_CONTEXT *names);
bool _reg_perfcount_add_instance(PERF_OBJECT_TYPE *obj,
				 prs_struct *ps,
				 int instInd,
				 TDB_CONTEXT *names);
uint32 reg_perfcount_get_perf_data_block(uint32 base_index, 
					 prs_struct *ps, 
					 PERF_DATA_BLOCK *block,
					 const char *object_ids);
WERROR reg_perfcount_get_hkpd(prs_struct *ps, uint32 max_buf_size, uint32 *outbuf_len, const char *object_ids);

/* The following definitions come from registry/reg_util.c  */

bool reg_split_path(char *path, char **base, char **new_path);
bool reg_split_key(char *path, char **base, char **key);
char *normalize_reg_path(TALLOC_CTX *ctx, const char *keyname );
void normalize_dbkey(char *key);
char *reg_remaining_path(TALLOC_CTX *ctx, const char *key);
int regval_convert_multi_sz( uint16 *multi_string, size_t byte_len, char ***values );
size_t regval_build_multi_sz( char **values, uint16 **buffer );

/* The following definitions come from registry/reg_util_legacy.c  */

WERROR regkey_open_internal( TALLOC_CTX *ctx, REGISTRY_KEY **regkey,
			     const char *path,
                             const struct nt_user_token *token,
			     uint32 access_desired );

/* The following definitions come from registry/regfio.c  */


/* The following definitions come from rpc_client/cli_lsarpc.c  */

NTSTATUS rpccli_lsa_open_policy(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				bool sec_qos, uint32 des_access,
				POLICY_HND *pol);
NTSTATUS rpccli_lsa_open_policy2(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx, bool sec_qos,
				 uint32 des_access, POLICY_HND *pol);
NTSTATUS rpccli_lsa_lookup_sids(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				POLICY_HND *pol,
				int num_sids,
				const DOM_SID *sids,
				char ***pdomains,
				char ***pnames,
				enum lsa_SidType **ptypes);
NTSTATUS rpccli_lsa_lookup_names(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 POLICY_HND *pol, int num_names,
				 const char **names,
				 const char ***dom_names,
				 int level,
				 DOM_SID **sids,
				 enum lsa_SidType **types);
bool fetch_domain_sid( char *domain, char *remote_machine, DOM_SID *psid);

/* The following definitions come from rpc_client/cli_netlogon.c  */

NTSTATUS rpccli_netlogon_setup_creds(struct rpc_pipe_client *cli,
				     const char *server_name,
				     const char *domain,
				     const char *clnt_name,
				     const char *machine_account,
				     const unsigned char machine_pwd[16],
				     enum netr_SchannelType sec_chan_type,
				     uint32_t *neg_flags_inout);
NTSTATUS rpccli_netlogon_sam_logon(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint32 logon_parameters,
				   const char *domain,
				   const char *username,
				   const char *password,
				   const char *workstation,
				   int logon_type);
NTSTATUS rpccli_netlogon_sam_network_logon(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   uint32 logon_parameters,
					   const char *server,
					   const char *username,
					   const char *domain,
					   const char *workstation,
					   const uint8 chal[8],
					   DATA_BLOB lm_response,
					   DATA_BLOB nt_response,
					   struct netr_SamInfo3 **info3);
NTSTATUS rpccli_netlogon_sam_network_logon_ex(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      uint32 logon_parameters,
					      const char *server,
					      const char *username,
					      const char *domain,
					      const char *workstation,
					      const uint8 chal[8],
					      DATA_BLOB lm_response,
					      DATA_BLOB nt_response,
					      struct netr_SamInfo3 **info3);
NTSTATUS rpccli_netlogon_set_trust_password(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    const unsigned char orig_trust_passwd_hash[16],
					    const char *new_trust_pwd_cleartext,
					    const unsigned char new_trust_passwd_hash[16],
					    uint32_t sec_channel_type);

/* The following definitions come from rpc_client/cli_pipe.c  */

NTSTATUS rpc_api_pipe_req(struct rpc_pipe_client *cli,
			uint8 op_num,
			prs_struct *in_data,
			prs_struct *out_data);
NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct cli_pipe_auth_data *auth);
unsigned int rpccli_set_timeout(struct rpc_pipe_client *cli,
				unsigned int timeout);
bool rpccli_get_pwd_hash(struct rpc_pipe_client *cli, uint8_t nt_hash[16]);
struct cli_state *rpc_pipe_np_smb_conn(struct rpc_pipe_client *p);
NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_ntlmssp_bind_data(TALLOC_CTX *mem_ctx,
				  enum pipe_auth_type auth_type,
				  enum pipe_auth_level auth_level,
				  const char *domain,
				  const char *username,
				  const char *password,
				  struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_schannel_bind_data(TALLOC_CTX *mem_ctx, const char *domain,
				   enum pipe_auth_level auth_level,
				   const uint8_t sess_key[16],
				   struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_kerberos_bind_data(TALLOC_CTX *mem_ctx,
				   enum pipe_auth_level auth_level,
				   const char *service_princ,
				   const char *username,
				   const char *password,
				   struct cli_pipe_auth_data **presult);
NTSTATUS rpc_pipe_open_tcp(TALLOC_CTX *mem_ctx, const char *host,
			   const struct ndr_syntax_id *abstract_syntax,
			   struct rpc_pipe_client **presult);
NTSTATUS rpc_pipe_open_ncalrpc(TALLOC_CTX *mem_ctx, const char *socket_path,
			       const struct ndr_syntax_id *abstract_syntax,
			       struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
				  const struct ndr_syntax_id *interface,
				  struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_ntlmssp(struct cli_state *cli,
				   const struct ndr_syntax_id *interface,
				   enum pipe_auth_level auth_level,
				   const char *domain,
				   const char *username,
				   const char *password,
				   struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_spnego_ntlmssp(struct cli_state *cli,
					  const struct ndr_syntax_id *interface,
					  enum pipe_auth_level auth_level,
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
					     enum pipe_auth_level auth_level,
					     const char *domain,
					     const struct dcinfo *pdc,
					     struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_ntlmssp_auth_schannel(struct cli_state *cli,
						 const struct ndr_syntax_id *interface,
						 enum pipe_auth_level auth_level,
						 const char *domain,
						 const char *username,
						 const char *password,
						 struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_schannel(struct cli_state *cli,
				    const struct ndr_syntax_id *interface,
				    enum pipe_auth_level auth_level,
				    const char *domain,
				    struct rpc_pipe_client **presult);
NTSTATUS cli_rpc_pipe_open_krb5(struct cli_state *cli,
				const struct ndr_syntax_id *interface,
				enum pipe_auth_level auth_level,
				const char *service_princ,
				const char *username,
				const char *password,
				struct rpc_pipe_client **presult);
NTSTATUS cli_get_session_key(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *cli,
			     DATA_BLOB *session_key);


/* The following definitions come from rpc_client/cli_reg.c  */

NTSTATUS rpccli_winreg_Connect(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         uint32 reg_type, uint32 access_mask,
                         POLICY_HND *reg_hnd);
uint32 reg_init_regval_buffer( REGVAL_BUFFER *buf2, REGISTRY_VALUE *val );

/* The following definitions come from rpc_client/cli_samr.c  */

NTSTATUS rpccli_samr_chgpasswd_user(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    struct policy_handle *user_handle,
				    const char *newpassword,
				    const char *oldpassword);
NTSTATUS rpccli_samr_chgpasswd_user2(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword);
NTSTATUS rpccli_samr_chng_pswd_auth_crap(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 const char *username,
					 DATA_BLOB new_nt_password_blob,
					 DATA_BLOB old_nt_hash_enc_blob,
					 DATA_BLOB new_lm_password_blob,
					 DATA_BLOB old_lm_hash_enc_blob);
NTSTATUS rpccli_samr_chgpasswd_user3(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword,
				     struct samr_DomInfo1 **dominfo1,
				     struct samr_ChangeReject **reject);
void get_query_dispinfo_params(int loop_count, uint32 *max_entries,
			       uint32 *max_size);
NTSTATUS rpccli_try_samr_connects(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  uint32_t access_mask,
				  POLICY_HND *connect_pol);

/* The following definitions come from rpc_client/cli_spoolss.c  */

WERROR rpccli_spoolss_open_printer_ex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				const char *printername, const char *datatype, uint32 access_required,
				const char *station, const char *username, POLICY_HND *pol);
WERROR rpccli_spoolss_close_printer(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 POLICY_HND *pol);
WERROR rpccli_spoolss_enum_printers(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 char *name, uint32 flags, uint32 level,
				 uint32 *num_printers, PRINTER_INFO_CTR *ctr);
WERROR rpccli_spoolss_enum_ports(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      uint32 level, uint32 *num_ports, PORT_INFO_CTR *ctr);
WERROR rpccli_spoolss_getprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr);
WERROR rpccli_spoolss_setprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr, uint32 command);
WERROR rpccli_spoolss_getprinterdriver(struct rpc_pipe_client *cli, 
				    TALLOC_CTX *mem_ctx, 
				    POLICY_HND *pol, uint32 level, 
				    const char *env, int version, PRINTER_DRIVER_CTR *ctr);
WERROR rpccli_spoolss_enumprinterdrivers (struct rpc_pipe_client *cli, 
				       TALLOC_CTX *mem_ctx,
				       uint32 level, const char *env,
				       uint32 *num_drivers,
				       PRINTER_DRIVER_CTR *ctr);
WERROR rpccli_spoolss_getprinterdriverdir (struct rpc_pipe_client *cli, 
					TALLOC_CTX *mem_ctx,
					uint32 level, char *env,
					DRIVER_DIRECTORY_CTR *ctr);
WERROR rpccli_spoolss_addprinterdriver (struct rpc_pipe_client *cli, 
				     TALLOC_CTX *mem_ctx, uint32 level,
				     PRINTER_DRIVER_CTR *ctr);
WERROR rpccli_spoolss_addprinterex (struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 uint32 level, PRINTER_INFO_CTR*ctr);
WERROR rpccli_spoolss_deleteprinterdriverex(struct rpc_pipe_client *cli, 
                                         TALLOC_CTX *mem_ctx, const char *arch,
                                         const char *driver, int version);
WERROR rpccli_spoolss_deleteprinterdriver (struct rpc_pipe_client *cli, 
					TALLOC_CTX *mem_ctx, const char *arch,
					const char *driver);
WERROR rpccli_spoolss_getprintprocessordirectory(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      char *name, char *environment,
					      fstring procdir);
WERROR rpccli_spoolss_addform(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			   POLICY_HND *handle, uint32 level, FORM *form);
WERROR rpccli_spoolss_setform(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			   POLICY_HND *handle, uint32 level, 
			   const char *form_name, FORM *form);
WERROR rpccli_spoolss_getform(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			   POLICY_HND *handle, const char *formname, 
			   uint32 level, FORM_1 *form);
WERROR rpccli_spoolss_deleteform(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *handle, const char *form_name);
WERROR rpccli_spoolss_enumforms(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			     POLICY_HND *handle, int level, uint32 *num_forms,
			     FORM_1 **forms);
WERROR rpccli_spoolss_enumjobs(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    POLICY_HND *hnd, uint32 level, uint32 firstjob, 
			    uint32 num_jobs, uint32 *returned, JOB_INFO_CTR *ctr);
WERROR rpccli_spoolss_setjob(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			  POLICY_HND *hnd, uint32 jobid, uint32 level, 
			  uint32 command);
WERROR rpccli_spoolss_getjob(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			  POLICY_HND *hnd, uint32 jobid, uint32 level,
			  JOB_INFO_CTR *ctr);
WERROR rpccli_spoolss_startpageprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd);
WERROR rpccli_spoolss_endpageprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd);
WERROR rpccli_spoolss_startdocprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *hnd, char *docname, 
				   char *outputfile, char *datatype, 
				   uint32 *jobid);
WERROR rpccli_spoolss_enddocprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd);
WERROR rpccli_spoolss_getprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, const char *valuename, 
				  REGISTRY_VALUE *value);
WERROR rpccli_spoolss_getprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, const char *keyname, 
				    const char *valuename, 
				    REGISTRY_VALUE *value);
WERROR rpccli_spoolss_setprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, REGISTRY_VALUE *value);
WERROR rpccli_spoolss_setprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, char *keyname, 
				    REGISTRY_VALUE *value);
WERROR rpccli_spoolss_enumprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *hnd, uint32 ndx,
				   uint32 value_offered, uint32 data_offered,
				   uint32 *value_needed, uint32 *data_needed,
				   REGISTRY_VALUE *value);
WERROR rpccli_spoolss_enumprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				     POLICY_HND *hnd, const char *keyname, 
				     REGVAL_CTR *ctr);
WERROR rpccli_spoolss_writeprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				POLICY_HND *hnd, uint32 data_size, char *data,
				uint32 *num_written);
WERROR rpccli_spoolss_deleteprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				     POLICY_HND *hnd, char *valuename);
WERROR rpccli_spoolss_deleteprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				       POLICY_HND *hnd, char *keyname, 
				       char *valuename);
WERROR rpccli_spoolss_enumprinterkey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, const char *keyname,
				  uint16 **keylist, uint32 *len);
WERROR rpccli_spoolss_deleteprinterkey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, char *keyname);

/* The following definitions come from rpc_client/cli_spoolss_notify.c  */

WERROR rpccli_spoolss_reply_open_printer(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				      const char *printer, uint32 printerlocal, uint32 type, 
				      POLICY_HND *handle);
WERROR rpccli_spoolss_reply_close_printer(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				       POLICY_HND *handle);
WERROR rpccli_spoolss_routerreplyprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				      POLICY_HND *pol, uint32 condition, uint32 change_id);
WERROR rpccli_spoolss_rrpcn(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
			 POLICY_HND *pol, uint32 notify_data_len,
			 SPOOL_NOTIFY_INFO_DATA *notify_data,
			 uint32 change_low, uint32 change_high);
WERROR rpccli_spoolss_rffpcnex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    POLICY_HND *pol, uint32 flags, uint32 options,
			    const char *localmachine, uint32 printerlocal,
			    SPOOL_NOTIFY_OPTION *option);

/* The following definitions come from rpc_client/cli_svcctl.c  */

WERROR rpccli_svcctl_enumerate_services( struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                                      POLICY_HND *hSCM, uint32 type, uint32 state, 
				      uint32 *returned, ENUM_SERVICES_STATUS **service_array  );

/* The following definitions come from rpc_client/init_lsa.c  */

void init_lsa_String(struct lsa_String *name, const char *s);
void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s);
void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s);
void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s);
void init_lsa_sec_qos(struct lsa_QosInfo *r,
		      uint32_t len,
		      uint16_t impersonation_level,
		      uint8_t context_mode,
		      uint8_t effective_only);
void init_lsa_obj_attr(struct lsa_ObjectAttribute *r,
		       uint32_t len,
		       uint8_t *root_dir,
		       const char *object_name,
		       uint32_t attributes,
		       struct security_descriptor *sec_desc,
		       struct lsa_QosInfo *sec_qos);
void init_lsa_translated_sid(struct lsa_TranslatedSid *r,
			     enum lsa_SidType sid_type,
			     uint32_t rid,
			     uint32_t sid_index);
void init_lsa_translated_name2(struct lsa_TranslatedName2 *r,
			       enum lsa_SidType sid_type,
			       const char *name,
			       uint32_t sid_index,
			       uint32_t unknown);

/* The following definitions come from rpc_client/init_netlogon.c  */

void init_netr_SamBaseInfo(struct netr_SamBaseInfo *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME acct_expiry,
			   NTTIME last_password_change,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *logon_script,
			   const char *profile_path,
			   const char *home_directory,
			   const char *home_drive,
			   uint16_t logon_count,
			   uint16_t bad_password_count,
			   uint32_t rid,
			   uint32_t primary_gid,
			   struct samr_RidWithAttributeArray groups,
			   uint32_t user_flags,
			   struct netr_UserSessionKey key,
			   const char *logon_server,
			   const char *domain,
			   struct dom_sid2 *domain_sid,
			   struct netr_LMSessionKey LMSessKey,
			   uint32_t acct_flags);
void init_netr_SamInfo3(struct netr_SamInfo3 *r,
			NTTIME last_logon,
			NTTIME last_logoff,
			NTTIME acct_expiry,
			NTTIME last_password_change,
			NTTIME allow_password_change,
			NTTIME force_password_change,
			const char *account_name,
			const char *full_name,
			const char *logon_script,
			const char *profile_path,
			const char *home_directory,
			const char *home_drive,
			uint16_t logon_count,
			uint16_t bad_password_count,
			uint32_t rid,
			uint32_t primary_gid,
			struct samr_RidWithAttributeArray groups,
			uint32_t user_flags,
			struct netr_UserSessionKey key,
			const char *logon_server,
			const char *domain,
			struct dom_sid2 *domain_sid,
			struct netr_LMSessionKey LMSessKey,
			uint32_t acct_flags,
			uint32_t sidcount,
			struct netr_SidAttr *sids);
NTSTATUS serverinfo_to_SamInfo3(struct auth_serversupplied_info *server_info,
				uint8_t pipe_session_key[16],
				struct netr_SamInfo3 *sam3);
void init_netr_IdentityInfo(struct netr_IdentityInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation);
void init_netr_NetworkInfo(struct netr_NetworkInfo *r,
			   const char *domain_name,
			   uint32_t parameter_control,
			   uint32_t logon_id_low,
			   uint32_t logon_id_high,
			   const char *account_name,
			   const char *workstation,
			   uint8_t challenge[8],
			   struct netr_ChallengeResponse nt,
			   struct netr_ChallengeResponse lm);
void init_netr_PasswordInfo(struct netr_PasswordInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation,
			    struct samr_Password lmpassword,
			    struct samr_Password ntpassword);
void init_netr_CryptPassword(const char *pwd,
			     unsigned char session_key[16],
			     struct netr_CryptPassword *pwd_buf);

/* The following definitions come from rpc_client/init_samr.c  */

void init_samr_DomInfo1(struct samr_DomInfo1 *r,
			uint16_t min_password_length,
			uint16_t password_history_length,
			uint32_t password_properties,
			int64_t max_password_age,
			int64_t min_password_age);
void init_samr_DomInfo2(struct samr_DomInfo2 *r,
			NTTIME force_logoff_time,
			const char *comment,
			const char *domain_name,
			const char *primary,
			uint64_t sequence_num,
			uint32_t unknown2,
			enum samr_Role role,
			uint32_t unknown3,
			uint32_t num_users,
			uint32_t num_groups,
			uint32_t num_aliases);
void init_samr_DomInfo3(struct samr_DomInfo3 *r,
			NTTIME force_logoff_time);
void init_samr_DomInfo4(struct samr_DomInfo4 *r,
			const char *comment);
void init_samr_DomInfo5(struct samr_DomInfo5 *r,
			const char *domain_name);
void init_samr_DomInfo6(struct samr_DomInfo6 *r,
			const char *primary);
void init_samr_DomInfo7(struct samr_DomInfo7 *r,
			enum samr_Role role);
void init_samr_DomInfo8(struct samr_DomInfo8 *r,
			uint64_t sequence_num,
			NTTIME domain_create_time);
void init_samr_DomInfo9(struct samr_DomInfo9 *r,
			uint32_t unknown);
void init_samr_DomInfo12(struct samr_DomInfo12 *r,
			 uint64_t lockout_duration,
			 uint64_t lockout_window,
			 uint16_t lockout_threshold);
void init_samr_group_info1(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description);
void init_samr_group_info2(struct lsa_String *r, const char *group_name);
void init_samr_group_info3(struct samr_GroupInfoAttributes *r,
			   uint32_t attributes);
void init_samr_group_info4(struct lsa_String *r, const char *description);
void init_samr_group_info5(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description);
void init_samr_alias_info1(struct samr_AliasInfoAll *r,
			   const char *name,
			   uint32_t num_members,
			   const char *description);
void init_samr_alias_info3(struct lsa_String *r,
			   const char *description);
void init_samr_user_info5(struct samr_UserInfo5 *r,
			  const char *account_name,
			  const char *full_name,
			  uint32_t rid,
			  uint32_t primary_gid,
			  const char *home_directory,
			  const char *home_drive,
			  const char *logon_script,
			  const char *profile_path,
			  const char *description,
			  const char *workstations,
			  NTTIME last_logon,
			  NTTIME last_logoff,
			  struct samr_LogonHours logon_hours,
			  uint16_t bad_password_count,
			  uint16_t logon_count,
			  NTTIME last_password_change,
			  NTTIME acct_expiry,
			  uint32_t acct_flags);
void init_samr_user_info7(struct samr_UserInfo7 *r,
			  const char *account_name);
void init_samr_user_info9(struct samr_UserInfo9 *r,
			  uint32_t primary_gid);
void init_samr_user_info16(struct samr_UserInfo16 *r,
			   uint32_t acct_flags);
void init_samr_user_info18(struct samr_UserInfo18 *r,
			   const uint8 lm_pwd[16],
			   const uint8 nt_pwd[16],
			   uint8_t password_expired);
void init_samr_user_info20(struct samr_UserInfo20 *r,
			   struct lsa_BinaryString *parameters);
void init_samr_user_info21(struct samr_UserInfo21 *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME last_password_change,
			   NTTIME acct_expiry,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *home_directory,
			   const char *home_drive,
			   const char *logon_script,
			   const char *profile_path,
			   const char *description,
			   const char *workstations,
			   const char *comment,
			   struct lsa_BinaryString *parameters,
			   uint32_t rid,
			   uint32_t primary_gid,
			   uint32_t acct_flags,
			   uint32_t fields_present,
			   struct samr_LogonHours logon_hours,
			   uint16_t bad_password_count,
			   uint16_t logon_count,
			   uint16_t country_code,
			   uint16_t code_page,
			   uint8_t nt_password_set,
			   uint8_t lm_password_set,
			   uint8_t password_expired);
void init_samr_user_info23(struct samr_UserInfo23 *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME last_password_change,
			   NTTIME acct_expiry,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *home_directory,
			   const char *home_drive,
			   const char *logon_script,
			   const char *profile_path,
			   const char *description,
			   const char *workstations,
			   const char *comment,
			   struct lsa_BinaryString *parameters,
			   uint32_t rid,
			   uint32_t primary_gid,
			   uint32_t acct_flags,
			   uint32_t fields_present,
			   struct samr_LogonHours logon_hours,
			   uint16_t bad_password_count,
			   uint16_t logon_count,
			   uint16_t country_code,
			   uint16_t code_page,
			   uint8_t nt_password_set,
			   uint8_t lm_password_set,
			   uint8_t password_expired,
			   struct samr_CryptPassword *pwd_buf);
void init_samr_user_info24(struct samr_UserInfo24 *r,
			   struct samr_CryptPassword *pwd_buf,
			   uint8_t password_expired);
void init_samr_user_info25(struct samr_UserInfo25 *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME last_password_change,
			   NTTIME acct_expiry,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *home_directory,
			   const char *home_drive,
			   const char *logon_script,
			   const char *profile_path,
			   const char *description,
			   const char *workstations,
			   const char *comment,
			   struct lsa_BinaryString *parameters,
			   uint32_t rid,
			   uint32_t primary_gid,
			   uint32_t acct_flags,
			   uint32_t fields_present,
			   struct samr_LogonHours logon_hours,
			   uint16_t bad_password_count,
			   uint16_t logon_count,
			   uint16_t country_code,
			   uint16_t code_page,
			   uint8_t nt_password_set,
			   uint8_t lm_password_set,
			   uint8_t password_expired,
			   struct samr_CryptPasswordEx *pwd_buf);
void init_samr_user_info26(struct samr_UserInfo26 *r,
			   struct samr_CryptPasswordEx *pwd_buf,
			   uint8_t password_expired);
void init_samr_CryptPasswordEx(const char *pwd,
			       DATA_BLOB *session_key,
			       struct samr_CryptPasswordEx *pwd_buf);
void init_samr_CryptPassword(const char *pwd,
			     DATA_BLOB *session_key,
			     struct samr_CryptPassword *pwd_buf);

/* The following definitions come from rpc_client/init_srvsvc.c  */

void init_srvsvc_NetSrvInfo102(struct srvsvc_NetSrvInfo102 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment,
			       uint32_t users,
			       uint32_t disc,
			       uint32_t hidden,
			       uint32_t announce,
			       uint32_t anndelta,
			       uint32_t licenses,
			       const char *userpath);
void init_srvsvc_NetSrvInfo101(struct srvsvc_NetSrvInfo101 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment);
void init_srvsvc_NetSrvInfo100(struct srvsvc_NetSrvInfo100 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name);
void init_srvsvc_NetShareInfo0(struct srvsvc_NetShareInfo0 *r,
			       const char *name);
void init_srvsvc_NetShareInfo1(struct srvsvc_NetShareInfo1 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment);
void init_srvsvc_NetShareInfo2(struct srvsvc_NetShareInfo2 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment,
			       uint32_t permissions,
			       uint32_t max_users,
			       uint32_t current_users,
			       const char *path,
			       const char *password);
void init_srvsvc_NetShareInfo501(struct srvsvc_NetShareInfo501 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t csc_policy);
void init_srvsvc_NetShareInfo502(struct srvsvc_NetShareInfo502 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t permissions,
				 uint32_t max_users,
				 uint32_t current_users,
				 const char *path,
				 const char *password,
				 struct sec_desc_buf *sd_buf);
void init_srvsvc_NetShareInfo1004(struct srvsvc_NetShareInfo1004 *r,
				  const char *comment);
void init_srvsvc_NetShareInfo1005(struct srvsvc_NetShareInfo1005 *r,
				  uint32_t dfs_flags);
void init_srvsvc_NetShareInfo1006(struct srvsvc_NetShareInfo1006 *r,
				  uint32_t max_users);
void init_srvsvc_NetShareInfo1007(struct srvsvc_NetShareInfo1007 *r,
				  uint32_t flags,
				  const char *alternate_directory_name);
void init_srvsvc_NetRemoteTODInfo(struct srvsvc_NetRemoteTODInfo *r,
				  uint32_t elapsed,
				  uint32_t msecs,
				  uint32_t hours,
				  uint32_t mins,
				  uint32_t secs,
				  uint32_t hunds,
				  int32_t ttimezone,
				  uint32_t tinterval,
				  uint32_t day,
				  uint32_t month,
				  uint32_t year,
				  uint32_t weekday);
void init_srvsvc_NetSessInfo0(struct srvsvc_NetSessInfo0 *r,
			      const char *client);
void init_srvsvc_NetSessInfo1(struct srvsvc_NetSessInfo1 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags);
void init_srvsvc_NetSessInfo2(struct srvsvc_NetSessInfo2 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags,
			      const char *client_type);
void init_srvsvc_NetSessInfo10(struct srvsvc_NetSessInfo10 *r,
			       const char *client,
			       const char *user,
			       uint32_t _time,
			       uint32_t idle_time);
void init_srvsvc_NetSessInfo502(struct srvsvc_NetSessInfo502 *r,
			       const char *client,
			       const char *user,
			       uint32_t num_open,
			       uint32_t _time,
			       uint32_t idle_time,
			       uint32_t user_flags,
			       const char *client_type,
			       const char *transport);
void init_srvsvc_NetFileInfo2(struct srvsvc_NetFileInfo2 *r,
			      uint32_t fid);
void init_srvsvc_NetFileInfo3(struct srvsvc_NetFileInfo3 *r,
			      uint32_t fid,
			      uint32_t permissions,
			      uint32_t num_locks,
			      const char *path,
			      const char *user);
void init_srvsvc_NetConnInfo0(struct srvsvc_NetConnInfo0 *r,
			      uint32_t conn_id);
void init_srvsvc_NetConnInfo1(struct srvsvc_NetConnInfo1 *r,
			      uint32_t conn_id,
			      uint32_t conn_type,
			      uint32_t num_open,
			      uint32_t num_users,
			      uint32_t conn_time,
			      const char *user,
			      const char *share);

/* The following definitions come from rpc_client/ndr.c  */

NTSTATUS cli_do_rpc_ndr(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			const struct ndr_interface_table *table,
			uint32 opnum, void *r);

/* The following definitions come from rpc_parse/parse_buffer.c  */

bool rpcbuf_init(RPC_BUFFER *buffer, uint32 size, TALLOC_CTX *ctx);
bool prs_rpcbuffer(const char *desc, prs_struct *ps, int depth, RPC_BUFFER *buffer);
bool prs_rpcbuffer_p(const char *desc, prs_struct *ps, int depth, RPC_BUFFER **buffer);
bool rpcbuf_alloc_size(RPC_BUFFER *buffer, uint32 buffer_size);
void rpcbuf_move(RPC_BUFFER *src, RPC_BUFFER **dest);
uint32 rpcbuf_get_size(RPC_BUFFER *buffer);
bool smb_io_relstr(const char *desc, RPC_BUFFER *buffer, int depth, UNISTR *string);
bool smb_io_relarraystr(const char *desc, RPC_BUFFER *buffer, int depth, uint16 **string);
bool smb_io_relsecdesc(const char *desc, RPC_BUFFER *buffer, int depth, SEC_DESC **secdesc);
uint32 size_of_relative_string(UNISTR *string);

/* The following definitions come from rpc_parse/parse_eventlog.c  */

bool eventlog_io_q_read_eventlog(const char *desc, EVENTLOG_Q_READ_EVENTLOG *q_u,
				 prs_struct *ps, int depth);
bool eventlog_io_r_read_eventlog(const char *desc,
				 EVENTLOG_Q_READ_EVENTLOG *q_u,
				 EVENTLOG_R_READ_EVENTLOG *r_u,
				 prs_struct *ps,
				 int depth);

/* The following definitions come from rpc_parse/parse_misc.c  */

bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth);
bool smb_io_nttime(const char *desc, prs_struct *ps, int depth, NTTIME *nttime);
uint32 get_enum_hnd(ENUM_HND *enh);
void init_enum_hnd(ENUM_HND *enh, uint32 hnd);
bool smb_io_enum_hnd(const char *desc, ENUM_HND *hnd, prs_struct *ps, int depth);
bool smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth);
void init_dom_sid2(DOM_SID2 *sid2, const DOM_SID *sid);
bool smb_io_dom_sid2_p(const char *desc, prs_struct *ps, int depth, DOM_SID2 **sid2);
bool smb_io_dom_sid2(const char *desc, DOM_SID2 *sid, prs_struct *ps, int depth);
bool smb_io_uuid(const char *desc, struct GUID *uuid, 
		 prs_struct *ps, int depth);
void init_str_hdr(STRHDR *hdr, int max_len, int len, uint32 buffer);
bool smb_io_strhdr(const char *desc,  STRHDR *hdr, prs_struct *ps, int depth);
void init_uni_hdr(UNIHDR *hdr, UNISTR2 *str2);
bool smb_io_unihdr(const char *desc, UNIHDR *hdr, prs_struct *ps, int depth);
void init_buf_hdr(BUFHDR *hdr, int max_len, int len);
bool smb_io_hdrbuf_pre(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth, uint32 *offset);
bool smb_io_hdrbuf_post(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth, 
				uint32 ptr_hdrbuf, uint32 max_len, uint32 len);
bool smb_io_hdrbuf(const char *desc, BUFHDR *hdr, prs_struct *ps, int depth);
void init_unistr(UNISTR *str, const char *buf);
bool smb_io_unistr(const char *desc, UNISTR *uni, prs_struct *ps, int depth);
void init_rpc_blob_uint32(RPC_DATA_BLOB *str, uint32 val);
void init_rpc_blob_str(RPC_DATA_BLOB *str, const char *buf, int len);
void init_rpc_blob_hex(RPC_DATA_BLOB *str, const char *buf);
void init_rpc_blob_bytes(RPC_DATA_BLOB *str, uint8 *buf, size_t len);
bool smb_io_buffer5(const char *desc, BUFFER5 *buf5, prs_struct *ps, int depth);
void init_regval_buffer(REGVAL_BUFFER *str, const uint8 *buf, size_t len);
bool smb_io_regval_buffer(const char *desc, prs_struct *ps, int depth, REGVAL_BUFFER *buf2);
void init_buf_unistr2(UNISTR2 *str, uint32 *ptr, const char *buf);
void copy_unistr2(UNISTR2 *str, const UNISTR2 *from);
void init_string2(STRING2 *str, const char *buf, size_t max_len, size_t str_len);
bool smb_io_string2(const char *desc, STRING2 *str2, uint32 buffer, prs_struct *ps, int depth);
void init_unistr2(UNISTR2 *str, const char *buf, enum unistr2_term_codes flags);
void init_unistr4(UNISTR4 *uni4, const char *buf, enum unistr2_term_codes flags);
void init_unistr4_w( TALLOC_CTX *ctx, UNISTR4 *uni4, const smb_ucs2_t *buf );
void init_unistr2_w(TALLOC_CTX *ctx, UNISTR2 *str, const smb_ucs2_t *buf);
void init_unistr2_from_unistr(TALLOC_CTX *ctx, UNISTR2 *to, const UNISTR *from);
void init_unistr2_from_datablob(UNISTR2 *str, DATA_BLOB *blob) ;
bool prs_io_unistr2_p(const char *desc, prs_struct *ps, int depth, UNISTR2 **uni2);
bool prs_io_unistr2(const char *desc, prs_struct *ps, int depth, UNISTR2 *uni2 );
bool smb_io_unistr2(const char *desc, UNISTR2 *uni2, uint32 buffer, prs_struct *ps, int depth);
bool prs_unistr4(const char *desc, prs_struct *ps, int depth, UNISTR4 *uni4);
bool prs_unistr4_hdr(const char *desc, prs_struct *ps, int depth, UNISTR4 *uni4);
bool prs_unistr4_str(const char *desc, prs_struct *ps, int depth, UNISTR4 *uni4);
bool prs_unistr4_array(const char *desc, prs_struct *ps, int depth, UNISTR4_ARRAY *array );
bool init_unistr4_array( UNISTR4_ARRAY *array, uint32 count, const char **strings );
void init_dom_rid(DOM_RID *prid, uint32 rid, uint16 type, uint32 idx);
bool smb_io_dom_rid(const char *desc, DOM_RID *rid, prs_struct *ps, int depth);
bool smb_io_dom_rid2(const char *desc, DOM_RID2 *rid, prs_struct *ps, int depth);
void init_dom_rid3(DOM_RID3 *rid3, uint32 rid, uint8 type);
bool smb_io_dom_rid3(const char *desc, DOM_RID3 *rid3, prs_struct *ps, int depth);
void init_dom_rid4(DOM_RID4 *rid4, uint16 unknown, uint16 attr, uint32 rid);
void init_clnt_srv(DOM_CLNT_SRV *logcln, const char *logon_srv,
		   const char *comp_name);
bool smb_io_clnt_srv(const char *desc, DOM_CLNT_SRV *logcln, prs_struct *ps, int depth);
void init_log_info(DOM_LOG_INFO *loginfo, const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name);
bool smb_io_log_info(const char *desc, DOM_LOG_INFO *loginfo, prs_struct *ps, int depth);
bool smb_io_chal(const char *desc, DOM_CHAL *chal, prs_struct *ps, int depth);
bool smb_io_cred(const char *desc,  DOM_CRED *cred, prs_struct *ps, int depth);
void init_clnt_info2(DOM_CLNT_INFO2 *clnt,
				const char *logon_srv, const char *comp_name,
				const DOM_CRED *clnt_cred);
bool smb_io_clnt_info2(const char *desc, DOM_CLNT_INFO2 *clnt, prs_struct *ps, int depth);
void init_clnt_info(DOM_CLNT_INFO *clnt,
		const char *logon_srv, const char *acct_name,
		uint16 sec_chan, const char *comp_name,
		const DOM_CRED *cred);
bool smb_io_clnt_info(const char *desc,  DOM_CLNT_INFO *clnt, prs_struct *ps, int depth);
void init_logon_id(DOM_LOGON_ID *logonid, uint32 log_id_low, uint32 log_id_high);
bool smb_io_logon_id(const char *desc, DOM_LOGON_ID *logonid, prs_struct *ps, int depth);
void init_owf_info(OWF_INFO *hash, const uint8 data[16]);
bool smb_io_owf_info(const char *desc, OWF_INFO *hash, prs_struct *ps, int depth);
bool smb_io_gid(const char *desc,  DOM_GID *gid, prs_struct *ps, int depth);
bool smb_io_pol_hnd(const char *desc, POLICY_HND *pol, prs_struct *ps, int depth);
void init_unistr3(UNISTR3 *str, const char *buf);
bool smb_io_unistr3(const char *desc, UNISTR3 *name, prs_struct *ps, int depth);
bool prs_uint64(const char *name, prs_struct *ps, int depth, uint64 *data64);
bool smb_io_bufhdr2(const char *desc, BUFHDR2 *hdr, prs_struct *ps, int depth);
bool smb_io_bufhdr4(const char *desc, BUFHDR4 *hdr, prs_struct *ps, int depth);
bool smb_io_rpc_blob(const char *desc, RPC_DATA_BLOB *blob, prs_struct *ps, int depth);
bool make_uni_hdr(UNIHDR *hdr, int len);
bool make_bufhdr2(BUFHDR2 *hdr, uint32 info_level, uint32 length, uint32 buffer);
uint32 str_len_uni(UNISTR *source);
bool policy_handle_is_valid(const POLICY_HND *hnd);

/* The following definitions come from rpc_parse/parse_ntsvcs.c  */

bool ntsvcs_io_q_get_device_list(const char *desc, NTSVCS_Q_GET_DEVICE_LIST *q_u, prs_struct *ps, int depth);
bool ntsvcs_io_r_get_device_list(const char *desc, NTSVCS_R_GET_DEVICE_LIST *r_u, prs_struct *ps, int depth);
bool ntsvcs_io_q_get_device_reg_property(const char *desc, NTSVCS_Q_GET_DEVICE_REG_PROPERTY *q_u, prs_struct *ps, int depth);
bool ntsvcs_io_r_get_device_reg_property(const char *desc, NTSVCS_R_GET_DEVICE_REG_PROPERTY *r_u, prs_struct *ps, int depth);

/* The following definitions come from rpc_parse/parse_prs.c  */

void prs_dump(const char *name, int v, prs_struct *ps);
void prs_dump_before(const char *name, int v, prs_struct *ps);
void prs_dump_region(const char *name, int v, prs_struct *ps,
		     int from_off, int to_off);
void prs_debug(prs_struct *ps, int depth, const char *desc, const char *fn_name);
bool prs_init(prs_struct *ps, uint32 size, TALLOC_CTX *ctx, bool io);
void prs_mem_free(prs_struct *ps);
void prs_mem_clear(prs_struct *ps);
char *prs_alloc_mem_(prs_struct *ps, size_t size, unsigned int count);
char *prs_alloc_mem(prs_struct *ps, size_t size, unsigned int count);
TALLOC_CTX *prs_get_mem_context(prs_struct *ps);
void prs_give_memory(prs_struct *ps, char *buf, uint32 size, bool is_dynamic);
char *prs_take_memory(prs_struct *ps, uint32 *psize);
bool prs_set_buffer_size(prs_struct *ps, uint32 newsize);
bool prs_grow(prs_struct *ps, uint32 extra_space);
bool prs_force_grow(prs_struct *ps, uint32 extra_space);
char *prs_data_p(prs_struct *ps);
uint32 prs_data_size(prs_struct *ps);
uint32 prs_offset(prs_struct *ps);
bool prs_set_offset(prs_struct *ps, uint32 offset);
bool prs_append_prs_data(prs_struct *dst, prs_struct *src);
bool prs_append_some_prs_data(prs_struct *dst, prs_struct *src, int32 start, uint32 len);
bool prs_copy_data_in(prs_struct *dst, const char *src, uint32 len);
bool prs_copy_data_out(char *dst, prs_struct *src, uint32 len);
bool prs_copy_all_data_out(char *dst, prs_struct *src);
void prs_set_endian_data(prs_struct *ps, bool endian);
bool prs_align(prs_struct *ps);
bool prs_align_uint16(prs_struct *ps);
bool prs_align_uint64(prs_struct *ps);
bool prs_align_custom(prs_struct *ps, uint8 boundary);
bool prs_align_needed(prs_struct *ps, uint32 needed);
char *prs_mem_get(prs_struct *ps, uint32 extra_size);
void prs_switch_type(prs_struct *ps, bool io);
void prs_force_dynamic(prs_struct *ps);
void prs_set_session_key(prs_struct *ps, const char sess_key[16]);
bool prs_uint8(const char *name, prs_struct *ps, int depth, uint8 *data8);
bool prs_pointer( const char *name, prs_struct *ps, int depth, 
                 void *dta, size_t data_size,
                 bool (*prs_fn)(const char*, prs_struct*, int, void*) );
bool prs_uint16(const char *name, prs_struct *ps, int depth, uint16 *data16);
bool prs_uint32(const char *name, prs_struct *ps, int depth, uint32 *data32);
bool prs_int32(const char *name, prs_struct *ps, int depth, int32 *data32);
bool prs_ntstatus(const char *name, prs_struct *ps, int depth, NTSTATUS *status);
bool prs_dcerpc_status(const char *name, prs_struct *ps, int depth, NTSTATUS *status);
bool prs_werror(const char *name, prs_struct *ps, int depth, WERROR *status);
bool prs_uint8s(bool charmode, const char *name, prs_struct *ps, int depth, uint8 *data8s, int len);
bool prs_uint16s(bool charmode, const char *name, prs_struct *ps, int depth, uint16 *data16s, int len);
bool prs_uint16uni(bool charmode, const char *name, prs_struct *ps, int depth, uint16 *data16s, int len);
bool prs_uint32s(bool charmode, const char *name, prs_struct *ps, int depth, uint32 *data32s, int len);
bool prs_buffer5(bool charmode, const char *name, prs_struct *ps, int depth, BUFFER5 *str);
bool prs_regval_buffer(bool charmode, const char *name, prs_struct *ps, int depth, REGVAL_BUFFER *buf);
bool prs_string2(bool charmode, const char *name, prs_struct *ps, int depth, STRING2 *str);
bool prs_unistr2(bool charmode, const char *name, prs_struct *ps, int depth, UNISTR2 *str);
bool prs_unistr3(bool charmode, const char *name, UNISTR3 *str, prs_struct *ps, int depth);
bool prs_unistr(const char *name, prs_struct *ps, int depth, UNISTR *str);
bool prs_string(const char *name, prs_struct *ps, int depth, char *str, int max_buf_size);
bool prs_string_alloc(const char *name, prs_struct *ps, int depth, const char **str);
bool prs_uint16_pre(const char *name, prs_struct *ps, int depth, uint16 *data16, uint32 *offset);
bool prs_uint16_post(const char *name, prs_struct *ps, int depth, uint16 *data16,
				uint32 ptr_uint16, uint32 start_offset);
bool prs_uint32_pre(const char *name, prs_struct *ps, int depth, uint32 *data32, uint32 *offset);
bool prs_uint32_post(const char *name, prs_struct *ps, int depth, uint32 *data32,
				uint32 ptr_uint32, uint32 data_size);
int tdb_prs_store(TDB_CONTEXT *tdb, TDB_DATA kbuf, prs_struct *ps);
int tdb_prs_fetch(TDB_CONTEXT *tdb, TDB_DATA kbuf, prs_struct *ps, TALLOC_CTX *mem_ctx);
bool prs_hash1(prs_struct *ps, uint32 offset, int len);
void schannel_encode(struct schannel_auth_struct *a, enum pipe_auth_level auth_level,
		   enum schannel_direction direction,
		   RPC_AUTH_SCHANNEL_CHK * verf,
		   char *data, size_t data_len);
bool schannel_decode(struct schannel_auth_struct *a, enum pipe_auth_level auth_level,
		   enum schannel_direction direction, 
		   RPC_AUTH_SCHANNEL_CHK * verf, char *data, size_t data_len);
bool prs_init_data_blob(prs_struct *prs, DATA_BLOB *blob, TALLOC_CTX *mem_ctx);
bool prs_data_blob(prs_struct *prs, DATA_BLOB *blob, TALLOC_CTX *mem_ctx);

/* The following definitions come from rpc_parse/parse_rpc.c  */

const char *cli_get_pipe_name_from_iface(TALLOC_CTX *mem_ctx,
					 struct cli_state *cli,
					 const struct ndr_syntax_id *interface);
void init_rpc_hdr(RPC_HDR *hdr, enum RPC_PKT_TYPE pkt_type, uint8 flags,
				uint32 call_id, int data_len, int auth_len);
bool smb_io_rpc_hdr(const char *desc,  RPC_HDR *rpc, prs_struct *ps, int depth);
void init_rpc_context(RPC_CONTEXT *rpc_ctx, uint16 context_id,
		      const RPC_IFACE *abstract, const RPC_IFACE *transfer);
void init_rpc_hdr_rb(RPC_HDR_RB *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				RPC_CONTEXT *context);
bool smb_io_rpc_context(const char *desc, RPC_CONTEXT *rpc_ctx, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_rb(const char *desc, RPC_HDR_RB *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_ba(RPC_HDR_BA *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				const char *pipe_addr,
				uint8 num_results, uint16 result, uint16 reason,
				RPC_IFACE *transfer);
bool smb_io_rpc_hdr_ba(const char *desc, RPC_HDR_BA *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_req(RPC_HDR_REQ *hdr, uint32 alloc_hint, uint16 opnum);
bool smb_io_rpc_hdr_req(const char *desc, RPC_HDR_REQ *rpc, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_resp(const char *desc, RPC_HDR_RESP *rpc, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_fault(const char *desc, RPC_HDR_FAULT *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_auth(RPC_HDR_AUTH *rai,
				uint8 auth_type, uint8 auth_level,
				uint8 auth_pad_len,
				uint32 auth_context_id);
bool smb_io_rpc_hdr_auth(const char *desc, RPC_HDR_AUTH *rai, prs_struct *ps, int depth);
bool rpc_auth_verifier_chk(RPC_AUTH_VERIFIER *rav,
				const char *signature, uint32 msg_type);
void init_rpc_auth_verifier(RPC_AUTH_VERIFIER *rav,
				const char *signature, uint32 msg_type);
bool smb_io_rpc_auth_verifier(const char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth);
bool smb_io_rpc_schannel_verifier(const char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth);
void init_rpc_auth_schannel_neg(RPC_AUTH_SCHANNEL_NEG *neg,
			      const char *domain, const char *myname);
bool smb_io_rpc_auth_schannel_neg(const char *desc, RPC_AUTH_SCHANNEL_NEG *neg,
				prs_struct *ps, int depth);
bool smb_io_rpc_auth_schannel_chk(const char *desc, int auth_len, 
                                RPC_AUTH_SCHANNEL_CHK * chk,
				prs_struct *ps, int depth);

/* The following definitions come from rpc_parse/parse_sec.c  */

bool sec_io_desc(const char *desc, SEC_DESC **ppsd, prs_struct *ps, int depth);
bool sec_io_desc_buf(const char *desc, SEC_DESC_BUF **ppsdb, prs_struct *ps, int depth);

/* The following definitions come from rpc_parse/parse_spoolss.c  */

bool spoolss_io_system_time(const char *desc, prs_struct *ps, int depth, SYSTEMTIME *systime);
bool make_systemtime(SYSTEMTIME *systime, struct tm *unixtime);
bool smb_io_notify_info_data_strings(const char *desc,SPOOL_NOTIFY_INFO_DATA *data,
                                     prs_struct *ps, int depth);
bool spool_io_user_level_1( const char *desc, prs_struct *ps, int depth, SPOOL_USER_1 *q_u );
bool spoolss_io_devmode(const char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode);
bool make_spoolss_q_open_printer_ex(SPOOL_Q_OPEN_PRINTER_EX *q_u,
		const fstring printername, 
		const fstring datatype, 
		uint32 access_required,
		const fstring clientname,
		const fstring user_name);
bool make_spoolss_q_addprinterex( TALLOC_CTX *mem_ctx, SPOOL_Q_ADDPRINTEREX *q_u, 
	const char *srv_name, const char* clientname, const char* user_name,
	uint32 level, PRINTER_INFO_CTR *ctr);
bool make_spoolss_printer_info_2(TALLOC_CTX *ctx, SPOOL_PRINTER_INFO_LEVEL_2 **spool_info2, 
				PRINTER_INFO_2 *info);
bool make_spoolss_printer_info_3(TALLOC_CTX *mem_ctx, SPOOL_PRINTER_INFO_LEVEL_3 **spool_info3, 
				PRINTER_INFO_3 *info);
bool make_spoolss_printer_info_7(TALLOC_CTX *mem_ctx, SPOOL_PRINTER_INFO_LEVEL_7 **spool_info7, 
				PRINTER_INFO_7 *info);
bool spoolss_io_q_open_printer(const char *desc, SPOOL_Q_OPEN_PRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_open_printer(const char *desc, SPOOL_R_OPEN_PRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_open_printer_ex(const char *desc, SPOOL_Q_OPEN_PRINTER_EX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_open_printer_ex(const char *desc, SPOOL_R_OPEN_PRINTER_EX *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_deleteprinterdriverex( TALLOC_CTX *mem_ctx,
                                           SPOOL_Q_DELETEPRINTERDRIVEREX *q_u, 
                                           const char *server,
                                           const char* arch, 
                                           const char* driver,
                                           int version);
bool make_spoolss_q_deleteprinterdriver(
	TALLOC_CTX *mem_ctx,
	SPOOL_Q_DELETEPRINTERDRIVER *q_u, 
	const char *server,
	const char* arch, 
	const char* driver 
);
bool make_spoolss_q_getprinterdata(SPOOL_Q_GETPRINTERDATA *q_u,
				   const POLICY_HND *handle,
				   const char *valuename, uint32 size);
bool make_spoolss_q_getprinterdataex(SPOOL_Q_GETPRINTERDATAEX *q_u,
				     const POLICY_HND *handle,
				     const char *keyname, 
				     const char *valuename, uint32 size);
bool spoolss_io_q_getprinterdata(const char *desc, SPOOL_Q_GETPRINTERDATA *q_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteprinterdata(const char *desc, SPOOL_Q_DELETEPRINTERDATA *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinterdata(const char *desc, SPOOL_R_DELETEPRINTERDATA *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteprinterdataex(const char *desc, SPOOL_Q_DELETEPRINTERDATAEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinterdataex(const char *desc, SPOOL_R_DELETEPRINTERDATAEX *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprinterdata(const char *desc, SPOOL_R_GETPRINTERDATA *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_closeprinter(SPOOL_Q_CLOSEPRINTER *q_u, POLICY_HND *hnd);
bool spoolss_io_q_abortprinter(const char *desc, SPOOL_Q_ABORTPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_abortprinter(const char *desc, SPOOL_R_ABORTPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteprinter(const char *desc, SPOOL_Q_DELETEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinter(const char *desc, SPOOL_R_DELETEPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteprinterdriver(const char *desc, SPOOL_Q_DELETEPRINTERDRIVER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinterdriver(const char *desc, SPOOL_R_DELETEPRINTERDRIVER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteprinterdriverex(const char *desc, SPOOL_Q_DELETEPRINTERDRIVEREX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinterdriverex(const char *desc, SPOOL_R_DELETEPRINTERDRIVEREX *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_closeprinter(const char *desc, SPOOL_Q_CLOSEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_closeprinter(const char *desc, SPOOL_R_CLOSEPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_startdocprinter(const char *desc, SPOOL_Q_STARTDOCPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_startdocprinter(const char *desc, SPOOL_R_STARTDOCPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enddocprinter(const char *desc, SPOOL_Q_ENDDOCPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enddocprinter(const char *desc, SPOOL_R_ENDDOCPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_startpageprinter(const char *desc, SPOOL_Q_STARTPAGEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_startpageprinter(const char *desc, SPOOL_R_STARTPAGEPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_endpageprinter(const char *desc, SPOOL_Q_ENDPAGEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_endpageprinter(const char *desc, SPOOL_R_ENDPAGEPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_writeprinter(const char *desc, SPOOL_Q_WRITEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_writeprinter(const char *desc, SPOOL_R_WRITEPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_rffpcnex(const char *desc, SPOOL_Q_RFFPCNEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_rffpcnex(const char *desc, SPOOL_R_RFFPCNEX *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_rfnpcnex(const char *desc, SPOOL_Q_RFNPCNEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_rfnpcnex(const char *desc, SPOOL_R_RFNPCNEX *r_u, prs_struct *ps, int depth);
bool smb_io_printer_info_0(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_0 *info, int depth);
bool smb_io_printer_info_1(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_1 *info, int depth);
bool smb_io_printer_info_2(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_2 *info, int depth);
bool smb_io_printer_info_3(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_3 *info, int depth);
bool smb_io_printer_info_4(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_4 *info, int depth);
bool smb_io_printer_info_5(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_5 *info, int depth);
bool smb_io_printer_info_6(const char *desc, RPC_BUFFER *buffer,
			   PRINTER_INFO_6 *info, int depth);
bool smb_io_printer_info_7(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_7 *info, int depth);
bool smb_io_port_info_1(const char *desc, RPC_BUFFER *buffer, PORT_INFO_1 *info, int depth);
bool smb_io_port_info_2(const char *desc, RPC_BUFFER *buffer, PORT_INFO_2 *info, int depth);
bool smb_io_printer_driver_info_1(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_1 *info, int depth) ;
bool smb_io_printer_driver_info_2(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_2 *info, int depth) ;
bool smb_io_printer_driver_info_3(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_3 *info, int depth);
bool smb_io_printer_driver_info_6(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_6 *info, int depth);
bool smb_io_job_info_1(const char *desc, RPC_BUFFER *buffer, JOB_INFO_1 *info, int depth);
bool smb_io_job_info_2(const char *desc, RPC_BUFFER *buffer, JOB_INFO_2 *info, int depth);
bool smb_io_form_1(const char *desc, RPC_BUFFER *buffer, FORM_1 *info, int depth);
bool smb_io_driverdir_1(const char *desc, RPC_BUFFER *buffer, DRIVER_DIRECTORY_1 *info, int depth);
bool smb_io_port_1(const char *desc, RPC_BUFFER *buffer, PORT_INFO_1 *info, int depth);
bool smb_io_port_2(const char *desc, RPC_BUFFER *buffer, PORT_INFO_2 *info, int depth);
bool smb_io_printprocessor_info_1(const char *desc, RPC_BUFFER *buffer, PRINTPROCESSOR_1 *info, int depth);
bool smb_io_printprocdatatype_info_1(const char *desc, RPC_BUFFER *buffer, PRINTPROCDATATYPE_1 *info, int depth);
bool smb_io_printmonitor_info_1(const char *desc, RPC_BUFFER *buffer, PRINTMONITOR_1 *info, int depth);
bool smb_io_printmonitor_info_2(const char *desc, RPC_BUFFER *buffer, PRINTMONITOR_2 *info, int depth);
uint32 spoolss_size_printer_info_0(PRINTER_INFO_0 *info);
uint32 spoolss_size_printer_info_1(PRINTER_INFO_1 *info);
uint32 spoolss_size_printer_info_2(PRINTER_INFO_2 *info);
uint32 spoolss_size_printer_info_4(PRINTER_INFO_4 *info);
uint32 spoolss_size_printer_info_5(PRINTER_INFO_5 *info);
uint32 spoolss_size_printer_info_6(PRINTER_INFO_6 *info);
uint32 spoolss_size_printer_info_3(PRINTER_INFO_3 *info);
uint32 spoolss_size_printer_info_7(PRINTER_INFO_7 *info);
uint32 spoolss_size_printer_driver_info_1(DRIVER_INFO_1 *info);
uint32 spoolss_size_printer_driver_info_2(DRIVER_INFO_2 *info);
uint32 spoolss_size_string_array(uint16 *string);
uint32 spoolss_size_printer_driver_info_3(DRIVER_INFO_3 *info);
uint32 spoolss_size_printer_driver_info_6(DRIVER_INFO_6 *info);
uint32 spoolss_size_job_info_1(JOB_INFO_1 *info);
uint32 spoolss_size_job_info_2(JOB_INFO_2 *info);
uint32 spoolss_size_form_1(FORM_1 *info);
uint32 spoolss_size_port_info_1(PORT_INFO_1 *info);
uint32 spoolss_size_driverdir_info_1(DRIVER_DIRECTORY_1 *info);
uint32 spoolss_size_printprocessordirectory_info_1(PRINTPROCESSOR_DIRECTORY_1 *info);
uint32 spoolss_size_port_info_2(PORT_INFO_2 *info);
uint32 spoolss_size_printprocessor_info_1(PRINTPROCESSOR_1 *info);
uint32 spoolss_size_printprocdatatype_info_1(PRINTPROCDATATYPE_1 *info);
uint32 spoolss_size_printer_enum_values(PRINTER_ENUM_VALUES *p);
uint32 spoolss_size_printmonitor_info_1(PRINTMONITOR_1 *info);
uint32 spoolss_size_printmonitor_info_2(PRINTMONITOR_2 *info);
bool make_spoolss_q_getprinterdriver2(SPOOL_Q_GETPRINTERDRIVER2 *q_u, 
			       const POLICY_HND *hnd,
			       const fstring architecture,
			       uint32 level, uint32 clientmajor, uint32 clientminor,
			       RPC_BUFFER *buffer, uint32 offered);
bool spoolss_io_q_getprinterdriver2(const char *desc, SPOOL_Q_GETPRINTERDRIVER2 *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprinterdriver2(const char *desc, SPOOL_R_GETPRINTERDRIVER2 *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_enumprinters(
	SPOOL_Q_ENUMPRINTERS *q_u, 
	uint32 flags, 
	char *servername, 
	uint32 level, 
	RPC_BUFFER *buffer, 
	uint32 offered
);
bool make_spoolss_q_enumports(SPOOL_Q_ENUMPORTS *q_u, 
				fstring servername, uint32 level, 
				RPC_BUFFER *buffer, uint32 offered);
bool spoolss_io_q_enumprinters(const char *desc, SPOOL_Q_ENUMPRINTERS *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprinters(const char *desc, SPOOL_R_ENUMPRINTERS *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprinter(const char *desc, SPOOL_R_GETPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_getprinter(const char *desc, SPOOL_Q_GETPRINTER *q_u, prs_struct *ps, int depth);
bool make_spoolss_q_getprinter(
	TALLOC_CTX *mem_ctx,
	SPOOL_Q_GETPRINTER *q_u, 
	const POLICY_HND *hnd, 
	uint32 level, 
	RPC_BUFFER *buffer, 
	uint32 offered
);
bool make_spoolss_q_setprinter(TALLOC_CTX *mem_ctx, SPOOL_Q_SETPRINTER *q_u, 
				const POLICY_HND *hnd, uint32 level, PRINTER_INFO_CTR *info, 
				uint32 command);
bool spoolss_io_r_setprinter(const char *desc, SPOOL_R_SETPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_setprinter(const char *desc, SPOOL_Q_SETPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_fcpn(const char *desc, SPOOL_R_FCPN *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_fcpn(const char *desc, SPOOL_Q_FCPN *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addjob(const char *desc, SPOOL_R_ADDJOB *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_addjob(const char *desc, SPOOL_Q_ADDJOB *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumjobs(const char *desc, SPOOL_R_ENUMJOBS *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_enumjobs(SPOOL_Q_ENUMJOBS *q_u, const POLICY_HND *hnd,
				uint32 firstjob,
				uint32 numofjobs,
				uint32 level,
				RPC_BUFFER *buffer,
				uint32 offered);
bool spoolss_io_q_enumjobs(const char *desc, SPOOL_Q_ENUMJOBS *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_schedulejob(const char *desc, SPOOL_R_SCHEDULEJOB *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_schedulejob(const char *desc, SPOOL_Q_SCHEDULEJOB *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_setjob(const char *desc, SPOOL_R_SETJOB *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_setjob(const char *desc, SPOOL_Q_SETJOB *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprinterdrivers(const char *desc, SPOOL_R_ENUMPRINTERDRIVERS *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_enumprinterdrivers(SPOOL_Q_ENUMPRINTERDRIVERS *q_u,
                                const char *name,
                                const char *environment,
                                uint32 level,
                                RPC_BUFFER *buffer, uint32 offered);
bool spoolss_io_q_enumprinterdrivers(const char *desc, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumforms(const char *desc, SPOOL_Q_ENUMFORMS *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumforms(const char *desc, SPOOL_R_ENUMFORMS *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_getform(const char *desc, SPOOL_Q_GETFORM *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_getform(const char *desc, SPOOL_R_GETFORM *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumports(const char *desc, SPOOL_R_ENUMPORTS *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumports(const char *desc, SPOOL_Q_ENUMPORTS *q_u, prs_struct *ps, int depth);
bool spool_io_printer_info_level_1(const char *desc, SPOOL_PRINTER_INFO_LEVEL_1 *il, prs_struct *ps, int depth);
bool spool_io_printer_info_level_3(const char *desc, SPOOL_PRINTER_INFO_LEVEL_3 *il, prs_struct *ps, int depth);
bool spool_io_printer_info_level_2(const char *desc, SPOOL_PRINTER_INFO_LEVEL_2 *il, prs_struct *ps, int depth);
bool spool_io_printer_info_level_7(const char *desc, SPOOL_PRINTER_INFO_LEVEL_7 *il, prs_struct *ps, int depth);
bool spool_io_printer_info_level(const char *desc, SPOOL_PRINTER_INFO_LEVEL *il, prs_struct *ps, int depth);
bool spoolss_io_q_addprinterex(const char *desc, SPOOL_Q_ADDPRINTEREX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addprinterex(const char *desc, SPOOL_R_ADDPRINTEREX *r_u, 
			       prs_struct *ps, int depth);
bool spool_io_printer_driver_info_level_3(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **q_u, 
                                          prs_struct *ps, int depth);
bool spool_io_printer_driver_info_level_6(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 **q_u, 
                                          prs_struct *ps, int depth);
bool smb_io_unibuffer(const char *desc, UNISTR2 *buffer, prs_struct *ps, int depth);
bool spool_io_printer_driver_info_level(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL *il, prs_struct *ps, int depth);
bool make_spoolss_q_addprinterdriver(TALLOC_CTX *mem_ctx,
				SPOOL_Q_ADDPRINTERDRIVER *q_u, const char* srv_name, 
				uint32 level, PRINTER_DRIVER_CTR *info);
bool make_spoolss_driver_info_3(TALLOC_CTX *mem_ctx,
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **spool_drv_info,
				DRIVER_INFO_3 *info3);
bool make_spoolss_buffer5(TALLOC_CTX *mem_ctx, BUFFER5 *buf5, uint32 len, uint16 *src);
bool spoolss_io_q_addprinterdriver(const char *desc, SPOOL_Q_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addprinterdriver(const char *desc, SPOOL_R_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth);
bool spoolss_io_q_addprinterdriverex(const char *desc, SPOOL_Q_ADDPRINTERDRIVEREX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addprinterdriverex(const char *desc, SPOOL_R_ADDPRINTERDRIVEREX *q_u, prs_struct *ps, int depth);
bool uni_2_asc_printer_driver_3(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *uni,
                                NT_PRINTER_DRIVER_INFO_LEVEL_3 **asc);
bool uni_2_asc_printer_driver_6(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *uni,
                                NT_PRINTER_DRIVER_INFO_LEVEL_6 **asc);
bool uni_2_asc_printer_info_2(const SPOOL_PRINTER_INFO_LEVEL_2 *uni,
                              NT_PRINTER_INFO_LEVEL_2  *d);
bool make_spoolss_q_getprinterdriverdir(SPOOL_Q_GETPRINTERDRIVERDIR *q_u,
                                fstring servername, fstring env_name, uint32 level,
                                RPC_BUFFER *buffer, uint32 offered);
bool spoolss_io_q_getprinterdriverdir(const char *desc, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprinterdriverdir(const char *desc, SPOOL_R_GETPRINTERDRIVERDIR *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprintprocessors(const char *desc, SPOOL_R_ENUMPRINTPROCESSORS *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumprintprocessors(const char *desc, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *ps, int depth);
bool spoolss_io_q_addprintprocessor(const char *desc, SPOOL_Q_ADDPRINTPROCESSOR *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addprintprocessor(const char *desc, SPOOL_R_ADDPRINTPROCESSOR *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprintprocdatatypes(const char *desc, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumprintprocdatatypes(const char *desc, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumprintmonitors(const char *desc, SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprintmonitors(const char *desc, SPOOL_R_ENUMPRINTMONITORS *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprinterdata(const char *desc, SPOOL_R_ENUMPRINTERDATA *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumprinterdata(const char *desc, SPOOL_Q_ENUMPRINTERDATA *q_u, prs_struct *ps, int depth);
bool make_spoolss_q_enumprinterdata(SPOOL_Q_ENUMPRINTERDATA *q_u,
		const POLICY_HND *hnd,
		uint32 idx, uint32 valuelen, uint32 datalen);
bool make_spoolss_q_enumprinterdataex(SPOOL_Q_ENUMPRINTERDATAEX *q_u,
				      const POLICY_HND *hnd, const char *key,
				      uint32 size);
bool make_spoolss_q_setprinterdata(SPOOL_Q_SETPRINTERDATA *q_u, const POLICY_HND *hnd,
				   char* value, uint32 data_type, char* data, uint32 data_size);
bool make_spoolss_q_setprinterdataex(SPOOL_Q_SETPRINTERDATAEX *q_u, const POLICY_HND *hnd,
				     char *key, char* value, uint32 data_type, char* data, 
				     uint32 data_size);
bool spoolss_io_q_setprinterdata(const char *desc, SPOOL_Q_SETPRINTERDATA *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_setprinterdata(const char *desc, SPOOL_R_SETPRINTERDATA *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_resetprinter(const char *desc, SPOOL_Q_RESETPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_resetprinter(const char *desc, SPOOL_R_RESETPRINTER *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_deleteform(const char *desc, SPOOL_Q_DELETEFORM *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteform(const char *desc, SPOOL_R_DELETEFORM *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_addform(const char *desc, SPOOL_Q_ADDFORM *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_addform(const char *desc, SPOOL_R_ADDFORM *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_setform(const char *desc, SPOOL_Q_SETFORM *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_setform(const char *desc, SPOOL_R_SETFORM *r_u, prs_struct *ps, int depth);
bool spoolss_io_r_getjob(const char *desc, SPOOL_R_GETJOB *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_getjob(const char *desc, SPOOL_Q_GETJOB *q_u, prs_struct *ps, int depth);
void free_devmode(DEVICEMODE *devmode);
void free_printer_info_1(PRINTER_INFO_1 *printer);
void free_printer_info_2(PRINTER_INFO_2 *printer);
void free_printer_info_3(PRINTER_INFO_3 *printer);
void free_printer_info_4(PRINTER_INFO_4 *printer);
void free_printer_info_5(PRINTER_INFO_5 *printer);
void free_printer_info_6(PRINTER_INFO_6 *printer);
void free_printer_info_7(PRINTER_INFO_7 *printer);
void free_job_info_2(JOB_INFO_2 *job);
bool make_spoolss_q_replyopenprinter(SPOOL_Q_REPLYOPENPRINTER *q_u, 
			       const fstring string, uint32 printer, uint32 type);
bool spoolss_io_q_replyopenprinter(const char *desc, SPOOL_Q_REPLYOPENPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_replyopenprinter(const char *desc, SPOOL_R_REPLYOPENPRINTER *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_routerreplyprinter(SPOOL_Q_ROUTERREPLYPRINTER *q_u, POLICY_HND *hnd, 
					uint32 condition, uint32 change_id);
bool spoolss_io_q_routerreplyprinter (const char *desc, SPOOL_Q_ROUTERREPLYPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_routerreplyprinter (const char *desc, SPOOL_R_ROUTERREPLYPRINTER *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_reply_closeprinter(SPOOL_Q_REPLYCLOSEPRINTER *q_u, POLICY_HND *hnd);
bool spoolss_io_q_replycloseprinter(const char *desc, SPOOL_Q_REPLYCLOSEPRINTER *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_replycloseprinter(const char *desc, SPOOL_R_REPLYCLOSEPRINTER *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_reply_rrpcn(SPOOL_Q_REPLY_RRPCN *q_u, POLICY_HND *hnd,
			        uint32 change_low, uint32 change_high,
				SPOOL_NOTIFY_INFO *info);
bool spoolss_io_q_reply_rrpcn(const char *desc, SPOOL_Q_REPLY_RRPCN *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_reply_rrpcn(const char *desc, SPOOL_R_REPLY_RRPCN *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_getprinterdataex(const char *desc, SPOOL_Q_GETPRINTERDATAEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprinterdataex(const char *desc, SPOOL_R_GETPRINTERDATAEX *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_setprinterdataex(const char *desc, SPOOL_Q_SETPRINTERDATAEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_setprinterdataex(const char *desc, SPOOL_R_SETPRINTERDATAEX *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_enumprinterkey(SPOOL_Q_ENUMPRINTERKEY *q_u, 
				   POLICY_HND *hnd, const char *key, 
				   uint32 size);
bool spoolss_io_q_enumprinterkey(const char *desc, SPOOL_Q_ENUMPRINTERKEY *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprinterkey(const char *desc, SPOOL_R_ENUMPRINTERKEY *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_deleteprinterkey(SPOOL_Q_DELETEPRINTERKEY *q_u, 
				     POLICY_HND *hnd, char *keyname);
bool spoolss_io_q_deleteprinterkey(const char *desc, SPOOL_Q_DELETEPRINTERKEY *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_deleteprinterkey(const char *desc, SPOOL_R_DELETEPRINTERKEY *r_u, prs_struct *ps, int depth);
bool spoolss_io_q_enumprinterdataex(const char *desc, SPOOL_Q_ENUMPRINTERDATAEX *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_enumprinterdataex(const char *desc, SPOOL_R_ENUMPRINTERDATAEX *r_u, prs_struct *ps, int depth);
bool make_spoolss_q_getprintprocessordirectory(SPOOL_Q_GETPRINTPROCESSORDIRECTORY *q_u, const char *name, char *environment, int level, RPC_BUFFER *buffer, uint32 offered);
bool spoolss_io_q_getprintprocessordirectory(const char *desc, SPOOL_Q_GETPRINTPROCESSORDIRECTORY *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_getprintprocessordirectory(const char *desc, SPOOL_R_GETPRINTPROCESSORDIRECTORY *r_u, prs_struct *ps, int depth);
bool smb_io_printprocessordirectory_1(const char *desc, RPC_BUFFER *buffer, PRINTPROCESSOR_DIRECTORY_1 *info, int depth);
bool make_spoolss_q_addform(SPOOL_Q_ADDFORM *q_u, POLICY_HND *handle, 
			    int level, FORM *form);
bool make_spoolss_q_setform(SPOOL_Q_SETFORM *q_u, POLICY_HND *handle, 
			    int level, const char *form_name, FORM *form);
bool make_spoolss_q_deleteform(SPOOL_Q_DELETEFORM *q_u, POLICY_HND *handle, 
			       const char *form);
bool make_spoolss_q_getform(SPOOL_Q_GETFORM *q_u, POLICY_HND *handle, 
                            const char *formname, uint32 level, 
			    RPC_BUFFER *buffer, uint32 offered);
bool make_spoolss_q_enumforms(SPOOL_Q_ENUMFORMS *q_u, POLICY_HND *handle, 
			      uint32 level, RPC_BUFFER *buffer,
			      uint32 offered);
bool make_spoolss_q_setjob(SPOOL_Q_SETJOB *q_u, POLICY_HND *handle, 
			   uint32 jobid, uint32 level, uint32 command);
bool make_spoolss_q_getjob(SPOOL_Q_GETJOB *q_u, POLICY_HND *handle, 
			   uint32 jobid, uint32 level, RPC_BUFFER *buffer,
			   uint32 offered);
bool make_spoolss_q_startpageprinter(SPOOL_Q_STARTPAGEPRINTER *q_u, 
				     POLICY_HND *handle);
bool make_spoolss_q_endpageprinter(SPOOL_Q_ENDPAGEPRINTER *q_u, 
				   POLICY_HND *handle);
bool make_spoolss_q_startdocprinter(SPOOL_Q_STARTDOCPRINTER *q_u, 
				    POLICY_HND *handle, uint32 level,
				    char *docname, char *outputfile,
				    char *datatype);
bool make_spoolss_q_enddocprinter(SPOOL_Q_ENDDOCPRINTER *q_u, 
				  POLICY_HND *handle);
bool make_spoolss_q_writeprinter(SPOOL_Q_WRITEPRINTER *q_u, 
				 POLICY_HND *handle, uint32 data_size,
				 char *data);
bool make_spoolss_q_deleteprinterdata(SPOOL_Q_DELETEPRINTERDATA *q_u, 
				 POLICY_HND *handle, char *valuename);
bool make_spoolss_q_deleteprinterdataex(SPOOL_Q_DELETEPRINTERDATAEX *q_u, 
					POLICY_HND *handle, char *key,
					char *value);
bool make_spoolss_q_rffpcnex(SPOOL_Q_RFFPCNEX *q_u, POLICY_HND *handle,
			     uint32 flags, uint32 options, const char *localmachine,
			     uint32 printerlocal, SPOOL_NOTIFY_OPTION *option);
bool spoolss_io_q_xcvdataport(const char *desc, SPOOL_Q_XCVDATAPORT *q_u, prs_struct *ps, int depth);
bool spoolss_io_r_xcvdataport(const char *desc, SPOOL_R_XCVDATAPORT *r_u, prs_struct *ps, int depth);
bool make_monitorui_buf( RPC_BUFFER *buf, const char *dllname );
bool convert_port_data_1( NT_PORT_DATA_1 *port1, RPC_BUFFER *buf ) ;

/* The following definitions come from rpc_parse/parse_svcctl.c  */

bool svcctl_io_enum_services_status( const char *desc, ENUM_SERVICES_STATUS *enum_status, RPC_BUFFER *buffer, int depth );
bool svcctl_io_service_status_process( const char *desc, SERVICE_STATUS_PROCESS *status, RPC_BUFFER *buffer, int depth );
uint32 svcctl_sizeof_enum_services_status( ENUM_SERVICES_STATUS *status );
bool svcctl_io_q_enum_services_status(const char *desc, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, prs_struct *ps, int depth);
bool svcctl_io_r_enum_services_status(const char *desc, SVCCTL_R_ENUM_SERVICES_STATUS *r_u, prs_struct *ps, int depth);
bool svcctl_io_q_query_service_config2(const char *desc, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, prs_struct *ps, int depth);
void init_service_description_buffer(SERVICE_DESCRIPTION *desc, const char *service_desc );
bool svcctl_io_service_description( const char *desc, SERVICE_DESCRIPTION *description, RPC_BUFFER *buffer, int depth );
uint32 svcctl_sizeof_service_description( SERVICE_DESCRIPTION *desc );
bool svcctl_io_service_fa( const char *desc, SERVICE_FAILURE_ACTIONS *fa, RPC_BUFFER *buffer, int depth );
uint32 svcctl_sizeof_service_fa( SERVICE_FAILURE_ACTIONS *fa);
bool svcctl_io_r_query_service_config2(const char *desc, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u, prs_struct *ps, int depth);
bool svcctl_io_q_query_service_status_ex(const char *desc, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, prs_struct *ps, int depth);
bool svcctl_io_r_query_service_status_ex(const char *desc, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u, prs_struct *ps, int depth);

/* The following definitions come from rpc_server/srv_dfs_nt.c  */


/* The following definitions come from rpc_server/srv_dssetup_nt.c  */

/* The following definitions come from rpc_server/srv_echo_nt.c  */

/* The following definitions come from rpc_server/srv_eventlog.c  */

NTSTATUS rpc_eventlog2_init(void);
void eventlog2_get_pipe_fns(struct api_struct **fns, int *n_fns);

/* The following definitions come from rpc_server/srv_eventlog_lib.c  */

TDB_CONTEXT *elog_init_tdb( char *tdbfilename );
char *elog_tdbname(TALLOC_CTX *ctx, const char *name );
int elog_tdb_size( TDB_CONTEXT * tdb, int *MaxSize, int *Retention );
bool prune_eventlog( TDB_CONTEXT * tdb );
bool can_write_to_eventlog( TDB_CONTEXT * tdb, int32 needed );
ELOG_TDB *elog_open_tdb( char *logname, bool force_clear );
int elog_close_tdb( ELOG_TDB *etdb, bool force_close );
int write_eventlog_tdb( TDB_CONTEXT * the_tdb, Eventlog_entry * ee );
void fixup_eventlog_entry( Eventlog_entry * ee );
bool parse_logentry( char *line, Eventlog_entry * entry, bool * eor );

/* The following definitions come from rpc_server/srv_eventlog_nt.c  */

NTSTATUS _eventlog_read_eventlog( pipes_struct * p,
				EVENTLOG_Q_READ_EVENTLOG * q_u,
				EVENTLOG_R_READ_EVENTLOG * r_u );

/* The following definitions come from rpc_server/srv_initshutdown_nt.c  */

/* The following definitions come from rpc_server/srv_lsa_hnd.c  */

bool init_pipe_handle_list(pipes_struct *p, const char *pipe_name);
bool create_policy_hnd(pipes_struct *p, POLICY_HND *hnd, void (*free_fn)(void *), void *data_ptr);
bool find_policy_by_hnd(pipes_struct *p, POLICY_HND *hnd, void **data_p);
bool close_policy_hnd(pipes_struct *p, POLICY_HND *hnd);
void close_policy_by_pipe(pipes_struct *p);
bool pipe_access_check(pipes_struct *p);

/* The following definitions come from rpc_server/srv_lsa_nt.c  */

/* The following definitions come from rpc_server/srv_netlog_nt.c  */

/* The following definitions come from rpc_server/srv_ntsvcs.c  */

void ntsvcs2_get_pipe_fns( struct api_struct **fns, int *n_fns );
NTSTATUS rpc_ntsvcs2_init(void);

/* The following definitions come from rpc_server/srv_ntsvcs_nt.c  */

WERROR _ntsvcs_get_device_list( pipes_struct *p, NTSVCS_Q_GET_DEVICE_LIST *q_u, NTSVCS_R_GET_DEVICE_LIST *r_u );
WERROR _ntsvcs_get_device_reg_property( pipes_struct *p, NTSVCS_Q_GET_DEVICE_REG_PROPERTY *q_u, NTSVCS_R_GET_DEVICE_REG_PROPERTY *r_u );

/* The following definitions come from rpc_server/srv_pipe.c  */

bool create_next_pdu(pipes_struct *p);
bool api_pipe_bind_auth3(pipes_struct *p, prs_struct *rpc_in_p);
bool setup_fault_pdu(pipes_struct *p, NTSTATUS status);
bool setup_cancel_ack_reply(pipes_struct *p, prs_struct *rpc_in_p);
bool check_bind_req(struct pipes_struct *p, RPC_IFACE* abstract,
                    RPC_IFACE* transfer, uint32 context_id);
NTSTATUS rpc_pipe_register_commands(int version, const char *clnt,
				    const char *srv,
				    const struct ndr_syntax_id *interface,
				    const struct api_struct *cmds, int size);
bool is_known_pipename(const char *cli_filename);
bool api_pipe_bind_req(pipes_struct *p, prs_struct *rpc_in_p);
bool api_pipe_alter_context(pipes_struct *p, prs_struct *rpc_in_p);
bool api_pipe_ntlmssp_auth_process(pipes_struct *p, prs_struct *rpc_in,
					uint32 *p_ss_padding_len, NTSTATUS *pstatus);
bool api_pipe_schannel_process(pipes_struct *p, prs_struct *rpc_in, uint32 *p_ss_padding_len);
struct current_user *get_current_user(struct current_user *user, pipes_struct *p);
void free_pipe_rpc_context( PIPE_RPC_FNS *list );
bool api_pipe_request(pipes_struct *p);

/* The following definitions come from rpc_server/srv_pipe_hnd.c  */

pipes_struct *get_first_internal_pipe(void);
pipes_struct *get_next_internal_pipe(pipes_struct *p);
void set_pipe_handle_offset(int max_open_files);
void reset_chain_p(void);
void init_rpc_pipe_hnd(void);
smb_np_struct *open_rpc_pipe_p(const char *pipe_name, 
			      connection_struct *conn, uint16 vuid);
ssize_t write_to_pipe(smb_np_struct *p, char *data, size_t n);
ssize_t read_from_pipe(smb_np_struct *p, char *data, size_t n,
		bool *is_data_outstanding);
bool wait_rpc_pipe_hnd_state(smb_np_struct *p, uint16 priority);
bool set_rpc_pipe_hnd_state(smb_np_struct *p, uint16 device_state);
bool close_rpc_pipe_hnd(smb_np_struct *p);
void pipe_close_conn(connection_struct *conn);
smb_np_struct *get_rpc_pipe_p(uint16 pnum);
smb_np_struct *get_rpc_pipe(int pnum);
struct pipes_struct *make_internal_rpc_pipe_p(const char *pipe_name,
					      const char *client_address,
					      struct auth_serversupplied_info *server_info,
					      uint16_t vuid);
ssize_t read_from_internal_pipe(struct pipes_struct *p, char *data, size_t n,
				bool *is_data_outstanding);
ssize_t write_to_internal_pipe(struct pipes_struct *p, char *data, size_t n);

/* The following definitions come from rpc_server/srv_samr_nt.c  */

/* The following definitions come from rpc_server/srv_samr_util.c  */

void copy_id18_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo18 *from);
void copy_id20_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo20 *from);
void copy_id21_to_sam_passwd(const char *log_prefix,
			     struct samu *to,
			     struct samr_UserInfo21 *from);
void copy_id23_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo23 *from);
void copy_id24_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo24 *from);
void copy_id25_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo25 *from);
void copy_id26_to_sam_passwd(struct samu *to,
			     struct samr_UserInfo26 *from);

/* The following definitions come from rpc_server/srv_spoolss.c  */

void spoolss_get_pipe_fns( struct api_struct **fns, int *n_fns );
NTSTATUS rpc_spoolss_init(void);

/* The following definitions come from rpc_server/srv_spoolss_nt.c  */

WERROR delete_printer_hook(TALLOC_CTX *ctx, NT_USER_TOKEN *token, const char *sharename );
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
WERROR _spoolss_open_printer(pipes_struct *p, SPOOL_Q_OPEN_PRINTER *q_u, SPOOL_R_OPEN_PRINTER *r_u);
WERROR _spoolss_open_printer_ex( pipes_struct *p, SPOOL_Q_OPEN_PRINTER_EX *q_u, SPOOL_R_OPEN_PRINTER_EX *r_u);
bool convert_devicemode(const char *printername, const DEVICEMODE *devmode,
				NT_DEVICEMODE **pp_nt_devmode);
WERROR _spoolss_closeprinter(pipes_struct *p, SPOOL_Q_CLOSEPRINTER *q_u, SPOOL_R_CLOSEPRINTER *r_u);
WERROR _spoolss_deleteprinter(pipes_struct *p, SPOOL_Q_DELETEPRINTER *q_u, SPOOL_R_DELETEPRINTER *r_u);
WERROR _spoolss_deleteprinterdriver(pipes_struct *p, SPOOL_Q_DELETEPRINTERDRIVER *q_u, SPOOL_R_DELETEPRINTERDRIVER *r_u);
WERROR _spoolss_deleteprinterdriverex(pipes_struct *p, SPOOL_Q_DELETEPRINTERDRIVEREX *q_u, SPOOL_R_DELETEPRINTERDRIVEREX *r_u);
WERROR set_printer_dataex( NT_PRINTER_INFO_LEVEL *printer, const char *key, const char *value,
                                  uint32 type, uint8 *data, int real_len  );
WERROR _spoolss_getprinterdata(pipes_struct *p, SPOOL_Q_GETPRINTERDATA *q_u, SPOOL_R_GETPRINTERDATA *r_u);
WERROR _spoolss_rffpcnex(pipes_struct *p, SPOOL_Q_RFFPCNEX *q_u, SPOOL_R_RFFPCNEX *r_u);
void spoolss_notify_server_name(int snum,
				       SPOOL_NOTIFY_INFO_DATA *data,
				       print_queue_struct *queue,
				       NT_PRINTER_INFO_LEVEL *printer,
				       TALLOC_CTX *mem_ctx);
void spoolss_notify_printer_name(int snum,
					SPOOL_NOTIFY_INFO_DATA *data,
					print_queue_struct *queue,
					NT_PRINTER_INFO_LEVEL *printer,
					TALLOC_CTX *mem_ctx);
void spoolss_notify_share_name(int snum,
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx);
void spoolss_notify_port_name(int snum,
				     SPOOL_NOTIFY_INFO_DATA *data,
				     print_queue_struct *queue,
				     NT_PRINTER_INFO_LEVEL *printer,
				     TALLOC_CTX *mem_ctx);
void spoolss_notify_driver_name(int snum,
				       SPOOL_NOTIFY_INFO_DATA *data,
				       print_queue_struct *queue,
				       NT_PRINTER_INFO_LEVEL *printer,
				       TALLOC_CTX *mem_ctx);
void spoolss_notify_comment(int snum,
				   SPOOL_NOTIFY_INFO_DATA *data,
				   print_queue_struct *queue,
				   NT_PRINTER_INFO_LEVEL *printer,
				   TALLOC_CTX *mem_ctx);
void spoolss_notify_location(int snum,
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx);
void spoolss_notify_sepfile(int snum,
				   SPOOL_NOTIFY_INFO_DATA *data,
				   print_queue_struct *queue,
				   NT_PRINTER_INFO_LEVEL *printer,
				   TALLOC_CTX *mem_ctx);
void spoolss_notify_print_processor(int snum,
					   SPOOL_NOTIFY_INFO_DATA *data,
					   print_queue_struct *queue,
					   NT_PRINTER_INFO_LEVEL *printer,
					   TALLOC_CTX *mem_ctx);
void spoolss_notify_parameters(int snum,
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx);
void spoolss_notify_datatype(int snum,
				    SPOOL_NOTIFY_INFO_DATA *data,
				    print_queue_struct *queue,
				    NT_PRINTER_INFO_LEVEL *printer,
				    TALLOC_CTX *mem_ctx);
void spoolss_notify_attributes(int snum,
				      SPOOL_NOTIFY_INFO_DATA *data,
				      print_queue_struct *queue,
				      NT_PRINTER_INFO_LEVEL *printer,
				      TALLOC_CTX *mem_ctx);
void spoolss_notify_cjobs(int snum,
				 SPOOL_NOTIFY_INFO_DATA *data,
				 print_queue_struct *queue,
				 NT_PRINTER_INFO_LEVEL *printer,
				 TALLOC_CTX *mem_ctx);
void construct_info_data(SPOOL_NOTIFY_INFO_DATA *info_data, uint16 type, uint16 field, int id);
WERROR _spoolss_rfnpcnex( pipes_struct *p, SPOOL_Q_RFNPCNEX *q_u, SPOOL_R_RFNPCNEX *r_u);
DEVICEMODE *construct_dev_mode(const char *servicename);
WERROR _spoolss_enumprinters( pipes_struct *p, SPOOL_Q_ENUMPRINTERS *q_u, SPOOL_R_ENUMPRINTERS *r_u);
WERROR _spoolss_getprinter(pipes_struct *p, SPOOL_Q_GETPRINTER *q_u, SPOOL_R_GETPRINTER *r_u);
WERROR _spoolss_getprinterdriver2(pipes_struct *p, SPOOL_Q_GETPRINTERDRIVER2 *q_u, SPOOL_R_GETPRINTERDRIVER2 *r_u);
WERROR _spoolss_startpageprinter(pipes_struct *p, SPOOL_Q_STARTPAGEPRINTER *q_u, SPOOL_R_STARTPAGEPRINTER *r_u);
WERROR _spoolss_endpageprinter(pipes_struct *p, SPOOL_Q_ENDPAGEPRINTER *q_u, SPOOL_R_ENDPAGEPRINTER *r_u);
WERROR _spoolss_startdocprinter(pipes_struct *p, SPOOL_Q_STARTDOCPRINTER *q_u, SPOOL_R_STARTDOCPRINTER *r_u);
WERROR _spoolss_enddocprinter(pipes_struct *p, SPOOL_Q_ENDDOCPRINTER *q_u, SPOOL_R_ENDDOCPRINTER *r_u);
WERROR _spoolss_writeprinter(pipes_struct *p, SPOOL_Q_WRITEPRINTER *q_u, SPOOL_R_WRITEPRINTER *r_u);
WERROR _spoolss_abortprinter(pipes_struct *p, SPOOL_Q_ABORTPRINTER *q_u, SPOOL_R_ABORTPRINTER *r_u);
WERROR add_port_hook(TALLOC_CTX *ctx, NT_USER_TOKEN *token, const char *portname, const char *uri );
bool add_printer_hook(TALLOC_CTX *ctx, NT_USER_TOKEN *token, NT_PRINTER_INFO_LEVEL *printer);
WERROR _spoolss_setprinter(pipes_struct *p, SPOOL_Q_SETPRINTER *q_u, SPOOL_R_SETPRINTER *r_u);
WERROR _spoolss_fcpn(pipes_struct *p, SPOOL_Q_FCPN *q_u, SPOOL_R_FCPN *r_u);
WERROR _spoolss_addjob(pipes_struct *p, SPOOL_Q_ADDJOB *q_u, SPOOL_R_ADDJOB *r_u);
WERROR _spoolss_enumjobs( pipes_struct *p, SPOOL_Q_ENUMJOBS *q_u, SPOOL_R_ENUMJOBS *r_u);
WERROR _spoolss_schedulejob( pipes_struct *p, SPOOL_Q_SCHEDULEJOB *q_u, SPOOL_R_SCHEDULEJOB *r_u);
WERROR _spoolss_setjob(pipes_struct *p, SPOOL_Q_SETJOB *q_u, SPOOL_R_SETJOB *r_u);
WERROR _spoolss_enumprinterdrivers( pipes_struct *p, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, SPOOL_R_ENUMPRINTERDRIVERS *r_u);
WERROR _spoolss_enumforms(pipes_struct *p, SPOOL_Q_ENUMFORMS *q_u, SPOOL_R_ENUMFORMS *r_u);
WERROR _spoolss_getform(pipes_struct *p, SPOOL_Q_GETFORM *q_u, SPOOL_R_GETFORM *r_u);
WERROR enumports_hook(TALLOC_CTX *ctx, int *count, char ***lines );
WERROR _spoolss_enumports( pipes_struct *p, SPOOL_Q_ENUMPORTS *q_u, SPOOL_R_ENUMPORTS *r_u);
WERROR _spoolss_addprinterex( pipes_struct *p, SPOOL_Q_ADDPRINTEREX *q_u, SPOOL_R_ADDPRINTEREX *r_u);
WERROR _spoolss_addprinterdriver(pipes_struct *p, SPOOL_Q_ADDPRINTERDRIVER *q_u, SPOOL_R_ADDPRINTERDRIVER *r_u);
WERROR _spoolss_addprinterdriverex(pipes_struct *p, SPOOL_Q_ADDPRINTERDRIVEREX *q_u, SPOOL_R_ADDPRINTERDRIVEREX *r_u);
WERROR _spoolss_getprinterdriverdirectory(pipes_struct *p, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, SPOOL_R_GETPRINTERDRIVERDIR *r_u);
WERROR _spoolss_enumprinterdata(pipes_struct *p, SPOOL_Q_ENUMPRINTERDATA *q_u, SPOOL_R_ENUMPRINTERDATA *r_u);
WERROR _spoolss_setprinterdata( pipes_struct *p, SPOOL_Q_SETPRINTERDATA *q_u, SPOOL_R_SETPRINTERDATA *r_u);
WERROR _spoolss_resetprinter(pipes_struct *p, SPOOL_Q_RESETPRINTER *q_u, SPOOL_R_RESETPRINTER *r_u);
WERROR _spoolss_deleteprinterdata(pipes_struct *p, SPOOL_Q_DELETEPRINTERDATA *q_u, SPOOL_R_DELETEPRINTERDATA *r_u);
WERROR _spoolss_addform( pipes_struct *p, SPOOL_Q_ADDFORM *q_u, SPOOL_R_ADDFORM *r_u);
WERROR _spoolss_deleteform( pipes_struct *p, SPOOL_Q_DELETEFORM *q_u, SPOOL_R_DELETEFORM *r_u);
WERROR _spoolss_setform(pipes_struct *p, SPOOL_Q_SETFORM *q_u, SPOOL_R_SETFORM *r_u);
WERROR _spoolss_enumprintprocessors(pipes_struct *p, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, SPOOL_R_ENUMPRINTPROCESSORS *r_u);
WERROR _spoolss_enumprintprocdatatypes(pipes_struct *p, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u);
WERROR _spoolss_enumprintmonitors(pipes_struct *p, SPOOL_Q_ENUMPRINTMONITORS *q_u, SPOOL_R_ENUMPRINTMONITORS *r_u);
WERROR _spoolss_getjob( pipes_struct *p, SPOOL_Q_GETJOB *q_u, SPOOL_R_GETJOB *r_u);
WERROR _spoolss_getprinterdataex(pipes_struct *p, SPOOL_Q_GETPRINTERDATAEX *q_u, SPOOL_R_GETPRINTERDATAEX *r_u);
WERROR _spoolss_setprinterdataex(pipes_struct *p, SPOOL_Q_SETPRINTERDATAEX *q_u, SPOOL_R_SETPRINTERDATAEX *r_u);
WERROR _spoolss_deleteprinterdataex(pipes_struct *p, SPOOL_Q_DELETEPRINTERDATAEX *q_u, SPOOL_R_DELETEPRINTERDATAEX *r_u);
WERROR _spoolss_enumprinterkey(pipes_struct *p, SPOOL_Q_ENUMPRINTERKEY *q_u, SPOOL_R_ENUMPRINTERKEY *r_u);
WERROR _spoolss_deleteprinterkey(pipes_struct *p, SPOOL_Q_DELETEPRINTERKEY *q_u, SPOOL_R_DELETEPRINTERKEY *r_u);
WERROR _spoolss_enumprinterdataex(pipes_struct *p, SPOOL_Q_ENUMPRINTERDATAEX *q_u, SPOOL_R_ENUMPRINTERDATAEX *r_u);
WERROR _spoolss_getprintprocessordirectory(pipes_struct *p, SPOOL_Q_GETPRINTPROCESSORDIRECTORY *q_u, SPOOL_R_GETPRINTPROCESSORDIRECTORY *r_u);
WERROR _spoolss_xcvdataport(pipes_struct *p, SPOOL_Q_XCVDATAPORT *q_u, SPOOL_R_XCVDATAPORT *r_u);

/* The following definitions come from rpc_server/srv_srvsvc_nt.c  */

char *valid_share_pathname(TALLOC_CTX *ctx, const char *dos_pathname);

/* The following definitions come from rpc_server/srv_svcctl.c  */

void svcctl2_get_pipe_fns( struct api_struct **fns, int *n_fns );
NTSTATUS rpc_svcctl2_init(void);

/* The following definitions come from rpc_server/srv_svcctl_nt.c  */

bool init_service_op_table( void );
WERROR _svcctl_enum_services_status(pipes_struct *p, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, SVCCTL_R_ENUM_SERVICES_STATUS *r_u);
WERROR _svcctl_query_service_status_ex( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u );
WERROR _svcctl_query_service_config2( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u );

/* The following definitions come from rpc_server/srv_winreg_nt.c  */

/* The following definitions come from rpc_server/srv_wkssvc_nt.c  */

/* The following definitions come from rpcclient/cmd_dfs.c  */


/* The following definitions come from rpcclient/cmd_dssetup.c  */


/* The following definitions come from rpcclient/cmd_echo.c  */


/* The following definitions come from rpcclient/cmd_lsarpc.c  */


/* The following definitions come from rpcclient/cmd_netlogon.c  */


/* The following definitions come from rpcclient/cmd_ntsvcs.c  */


/* The following definitions come from rpcclient/cmd_samr.c  */


/* The following definitions come from rpcclient/cmd_shutdown.c  */


/* The following definitions come from rpcclient/cmd_spoolss.c  */

void set_drv_info_3_env (DRIVER_INFO_3 *info, const char *arch);

/* The following definitions come from rpcclient/cmd_srvsvc.c  */


/* The following definitions come from rpcclient/cmd_test.c  */


/* The following definitions come from rpcclient/cmd_wkssvc.c  */


/* The following definitions come from rpcclient/rpcclient.c  */


/* The following definitions come from services/services_db.c  */

void svcctl_init_keys( void );
SEC_DESC *svcctl_get_secdesc( TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
bool svcctl_set_secdesc( TALLOC_CTX *ctx, const char *name, SEC_DESC *sec_desc, NT_USER_TOKEN *token );
const char *svcctl_lookup_dispname(TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
const char *svcctl_lookup_description(TALLOC_CTX *ctx, const char *name, NT_USER_TOKEN *token );
REGVAL_CTR *svcctl_fetch_regvalues( const char *name, NT_USER_TOKEN *token );

/* The following definitions come from services/svc_netlogon.c  */


/* The following definitions come from services/svc_rcinit.c  */


/* The following definitions come from services/svc_spoolss.c  */


/* The following definitions come from services/svc_winreg.c  */


/* The following definitions come from services/svc_wins.c  */


/* The following definitions come from smbd/aio.c  */

void aio_request_done(uint16_t mid);
bool aio_finished(void);
void initialize_async_io_handler(void);
bool schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt);
bool schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, char *data,
			      SMB_OFF_T startpos,
			      size_t numtowrite);
int process_aio_queue(void);
int wait_for_aio_completion(files_struct *fsp);
void cancel_aio_by_fsp(files_struct *fsp);
bool aio_finished(void);
void initialize_async_io_handler(void);
int process_aio_queue(void);
bool schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, SMB_OFF_T startpos,
			     size_t smb_maxcnt);
bool schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, char *data,
			      SMB_OFF_T startpos,
			      size_t numtowrite);
void cancel_aio_by_fsp(files_struct *fsp);
int wait_for_aio_completion(files_struct *fsp);

/* The following definitions come from smbd/blocking.c  */

bool push_blocking_lock_request( struct byte_range_lock *br_lck,
		const struct smb_request *req,
		files_struct *fsp,
		int lock_timeout,
		int lock_num,
		uint32 lock_pid,
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		SMB_BIG_UINT offset,
		SMB_BIG_UINT count,
		uint32 blocking_pid);
void cancel_pending_lock_requests_by_fid(files_struct *fsp, struct byte_range_lock *br_lck);
void remove_pending_lock_requests_by_mid(int mid);
bool blocking_lock_was_deferred(int mid);
bool blocking_lock_cancel(files_struct *fsp,
			uint32 lock_pid,
			SMB_BIG_UINT offset,
			SMB_BIG_UINT count,
			enum brl_flavour lock_flav,
			unsigned char locktype,
                        NTSTATUS err);

/* The following definitions come from smbd/change_trust_pw.c  */

NTSTATUS change_trust_account_password( const char *domain, const char *remote_machine);

/* The following definitions come from smbd/chgpasswd.c  */

bool chgpasswd(const char *name, const struct passwd *pass,
	       const char *oldpass, const char *newpass, bool as_root);
bool chgpasswd(const char *name, const struct passwd *pass, 
	       const char *oldpass, const char *newpass, bool as_root);
bool check_lanman_password(char *user, uchar * pass1,
			   uchar * pass2, struct samu **hnd);
bool change_lanman_password(struct samu *sampass, uchar *pass2);
NTSTATUS pass_oem_change(char *user,
			 uchar password_encrypted_with_lm_hash[516],
			 const uchar old_lm_hash_encrypted[16],
			 uchar password_encrypted_with_nt_hash[516],
			 const uchar old_nt_hash_encrypted[16],
			 uint32 *reject_reason);
NTSTATUS change_oem_password(struct samu *hnd, char *old_passwd, char *new_passwd, bool as_root, uint32 *samr_reject_reason);

/* The following definitions come from smbd/close.c  */

void set_close_write_time(struct files_struct *fsp, struct timespec ts);
NTSTATUS close_file(files_struct *fsp, enum file_close_type close_type);
void msg_close_file(struct messaging_context *msg_ctx,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);
NTSTATUS delete_all_streams(connection_struct *conn, const char *fname);

/* The following definitions come from smbd/conn.c  */

void conn_init(void);
int conn_num_open(void);
bool conn_snum_used(int snum);
connection_struct *conn_find(unsigned cnum);
connection_struct *conn_new(void);
bool conn_close_all(void);
bool conn_idle_all(time_t t);
void conn_clear_vuid_caches(uint16 vuid);
void conn_free_internal(connection_struct *conn);
void conn_free(connection_struct *conn);
void msg_force_tdis(struct messaging_context *msg,
		    void *private_data,
		    uint32_t msg_type,
		    struct server_id server_id,
		    DATA_BLOB *data);

/* The following definitions come from smbd/connection.c  */

bool yield_connection(connection_struct *conn, const char *name);
int count_current_connections( const char *sharename, bool clear  );
int count_all_current_connections(void);
bool claim_connection(connection_struct *conn, const char *name,
		      uint32 msg_flags);
bool register_message_flags(bool doreg, uint32 msg_flags);
bool store_pipe_opendb( smb_np_struct *p );
bool delete_pipe_opendb( smb_np_struct *p );

/* The following definitions come from smbd/dfree.c  */

SMB_BIG_UINT sys_disk_free(connection_struct *conn, const char *path, bool small_query, 
                              SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize);
SMB_BIG_UINT get_dfree_info(connection_struct *conn,
			const char *path,
			bool small_query,
			SMB_BIG_UINT *bsize,
			SMB_BIG_UINT *dfree,
			SMB_BIG_UINT *dsize);

/* The following definitions come from smbd/dir.c  */

bool make_dir_struct(TALLOC_CTX *ctx,
			char *buf,
			const char *mask,
			const char *fname,
			SMB_OFF_T size,
			uint32 mode,
			time_t date,
			bool uc);
void init_dptrs(void);
char *dptr_path(int key);
char *dptr_wcard(int key);
uint16 dptr_attr(int key);
void dptr_close(int *key);
void dptr_closecnum(connection_struct *conn);
void dptr_idlecnum(connection_struct *conn);
void dptr_closepath(char *path,uint16 spid);
NTSTATUS dptr_create(connection_struct *conn, const char *path, bool old_handle, bool expect_close,uint16 spid,
		const char *wcard, bool wcard_has_wild, uint32 attr, struct dptr_struct **dptr_ret);
int dptr_CloseDir(struct dptr_struct *dptr);
void dptr_SeekDir(struct dptr_struct *dptr, long offset);
long dptr_TellDir(struct dptr_struct *dptr);
bool dptr_has_wild(struct dptr_struct *dptr);
int dptr_dnum(struct dptr_struct *dptr);
const char *dptr_ReadDirName(TALLOC_CTX *ctx,
			struct dptr_struct *dptr,
			long *poffset,
			SMB_STRUCT_STAT *pst);
bool dptr_SearchDir(struct dptr_struct *dptr, const char *name, long *poffset, SMB_STRUCT_STAT *pst);
void dptr_DirCacheAdd(struct dptr_struct *dptr, const char *name, long offset);
bool dptr_fill(char *buf1,unsigned int key);
struct dptr_struct *dptr_fetch(char *buf,int *num);
struct dptr_struct *dptr_fetch_lanman2(int dptr_num);
bool dir_check_ftype(connection_struct *conn, uint32 mode, uint32 dirtype);
bool get_dir_entry(TALLOC_CTX *ctx,
		connection_struct *conn,
		const char *mask,
		uint32 dirtype,
		char **pp_fname_out,
		SMB_OFF_T *size,
		uint32 *mode,
		time_t *date,
		bool check_descend,
		bool ask_sharemode);
bool is_visible_file(connection_struct *conn, const char *dir_path, const char *name, SMB_STRUCT_STAT *pst, bool use_veto);
struct smb_Dir *OpenDir(TALLOC_CTX *mem_ctx, connection_struct *conn,
			const char *name, const char *mask, uint32 attr);
const char *ReadDirName(struct smb_Dir *dirp, long *poffset);
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

void dns_register_close(struct dns_reg_state **dns_state_ptr);
void dns_register_smbd(struct dns_reg_state ** dns_state_ptr,
		unsigned port,
		int *maxfd,
		fd_set *listen_set,
		struct timeval *timeout);
bool dns_register_smbd_reply(struct dns_reg_state *dns_state,
		fd_set *lfds, struct timeval *timeout);

/* The following definitions come from smbd/dosmode.c  */

mode_t unix_mode(connection_struct *conn, int dosmode, const char *fname,
		 const char *inherit_from_dir);
uint32 dos_mode_msdfs(connection_struct *conn, const char *path,SMB_STRUCT_STAT *sbuf);
uint32 dos_mode(connection_struct *conn, const char *path,SMB_STRUCT_STAT *sbuf);
int file_set_dosmode(connection_struct *conn, const char *fname,
		     uint32 dosmode, SMB_STRUCT_STAT *st,
		     const char *parent_dir,
		     bool newfile);
int file_ntimes(connection_struct *conn, const char *fname, const struct timespec ts[2]);
bool set_sticky_write_time_path(connection_struct *conn, const char *fname,
			 struct file_id fileid, const struct timespec mtime);
bool set_sticky_write_time_fsp(struct files_struct *fsp, const struct timespec mtime);
bool update_write_time(struct files_struct *fsp);

/* The following definitions come from smbd/error.c  */

bool use_nt_status(void);
void error_packet_set(char *outbuf, uint8 eclass, uint32 ecode, NTSTATUS ntstatus, int line, const char *file);
int error_packet(char *outbuf, uint8 eclass, uint32 ecode, NTSTATUS ntstatus, int line, const char *file);
void reply_nt_error(struct smb_request *req, NTSTATUS ntstatus,
		    int line, const char *file);
void reply_force_nt_error(struct smb_request *req, NTSTATUS ntstatus,
			  int line, const char *file);
void reply_dos_error(struct smb_request *req, uint8 eclass, uint32 ecode,
		    int line, const char *file);
void reply_both_error(struct smb_request *req, uint8 eclass, uint32 ecode,
		      NTSTATUS status, int line, const char *file);
void reply_openerror(struct smb_request *req, NTSTATUS status);
void reply_unix_error(struct smb_request *req, uint8 defclass, uint32 defcode,
			NTSTATUS defstatus, int line, const char *file);

/* The following definitions come from smbd/fake_file.c  */

enum FAKE_FILE_TYPE is_fake_file(const char *fname);
NTSTATUS open_fake_file(connection_struct *conn,
				uint16_t current_vuid,
				enum FAKE_FILE_TYPE fake_file_type,
				const char *fname,
				uint32 access_mask,
				files_struct **result);
NTSTATUS close_fake_file(files_struct *fsp);

/* The following definitions come from smbd/file_access.c  */

bool can_access_file_acl(struct connection_struct *conn,
				const char * fname,
				uint32_t access_mask);
bool can_delete_file_in_directory(connection_struct *conn, const char *fname);
bool can_access_file_data(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf, uint32 access_mask);
bool can_write_to_file(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf);
bool directory_has_default_acl(connection_struct *conn, const char *fname);

/* The following definitions come from smbd/fileio.c  */

ssize_t read_file(files_struct *fsp,char *data,SMB_OFF_T pos,size_t n);
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
int fsp_stat(files_struct *fsp, SMB_STRUCT_STAT *pst);

/* The following definitions come from smbd/filename.c  */

NTSTATUS unix_convert(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *orig_path,
			bool allow_wcard_last_component,
			char **pp_conv_path,
			char **pp_saved_last_component,
			SMB_STRUCT_STAT *pst);
NTSTATUS check_name(connection_struct *conn, const char *name);
int get_real_filename(connection_struct *conn, const char *path,
		      const char *name, TALLOC_CTX *mem_ctx,
		      char **found_name);

/* The following definitions come from smbd/files.c  */

NTSTATUS file_new(connection_struct *conn, files_struct **result);
void file_close_conn(connection_struct *conn);
void file_close_pid(uint16 smbpid, int vuid);
void file_init(void);
void file_close_user(int vuid);
void file_dump_open_table(void);
files_struct *file_find_fd(int fd);
files_struct *file_find_dif(struct file_id id, unsigned long gen_id);
files_struct *file_find_fsp(files_struct *orig_fsp);
files_struct *file_find_di_first(struct file_id id);
files_struct *file_find_di_next(files_struct *start_fsp);
files_struct *file_find_print(void);
bool file_find_subpath(files_struct *dir_fsp);
void file_sync_all(connection_struct *conn);
void file_free(files_struct *fsp);
files_struct *file_fnum(uint16 fnum);
files_struct *file_fsp(uint16 fid);
void file_chain_reset(void);
void dup_file_fsp(files_struct *from,
				uint32 access_mask,
				uint32 share_access,
				uint32 create_options,
		      		files_struct *to);

/* The following definitions come from smbd/ipc.c  */

void send_trans_reply(connection_struct *conn,
		      const uint8_t *inbuf,
		      char *rparam, int rparam_len,
		      char *rdata, int rdata_len,
		      bool buffer_too_large);
void reply_trans(struct smb_request *req);
void reply_transs(struct smb_request *req);

/* The following definitions come from smbd/lanman.c  */

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

struct mangle_fns *mangle_hash_init(void);

/* The following definitions come from smbd/mangle_hash2.c  */

struct mangle_fns *mangle_hash2_init(void);
struct mangle_fns *posix_mangle_init(void);

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
				char **pp_name_out,
				bool *ppath_contains_wcard);
NTSTATUS create_conn_struct(TALLOC_CTX *ctx,
				connection_struct **pconn,
				int snum,
				const char *path,
			    char **poldcwd);

/* The following definitions come from smbd/negprot.c  */

void reply_negprot(struct smb_request *req);

/* The following definitions come from smbd/notify.c  */

void change_notify_reply(connection_struct *conn,
			const uint8 *request_buf, uint32 max_param,
			 struct notify_change_buf *notify_buf);
NTSTATUS change_notify_create(struct files_struct *fsp, uint32 filter,
			      bool recursive);
NTSTATUS change_notify_add_request(const struct smb_request *req,
				uint32 max_param,
				uint32 filter, bool recursive,
				struct files_struct *fsp);
void remove_pending_change_notify_requests_by_mid(uint16 mid);
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
NTSTATUS notify_add(struct notify_context *notify, struct notify_entry *e0,
		    void (*callback)(void *, const struct notify_event *), 
		    void *private_data);
NTSTATUS notify_remove(struct notify_context *notify, void *private_data);
void notify_trigger(struct notify_context *notify,
		    uint32_t action, uint32_t filter, const char *path);

/* The following definitions come from smbd/ntquotas.c  */

int vfs_get_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, DOM_SID *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_set_ntquota(files_struct *fsp, enum SMB_QUOTA_TYPE qtype, DOM_SID *psid, SMB_NTQUOTA_STRUCT *qt);
int vfs_get_user_ntquota_list(files_struct *fsp, SMB_NTQUOTA_LIST **qt_list);
void *init_quota_handle(TALLOC_CTX *mem_ctx);

/* The following definitions come from smbd/nttrans.c  */

void send_nt_replies(connection_struct *conn,
			struct smb_request *req, NTSTATUS nt_error,
		     char *params, int paramsize,
		     char *pdata, int datasize);
bool is_ntfs_stream_name(const char *fname);
void reply_ntcreate_and_X(struct smb_request *req);
void reply_ntcancel(struct smb_request *req);
void reply_ntrename(struct smb_request *req);
void reply_nttrans(struct smb_request *req);
void reply_nttranss(struct smb_request *req);

/* The following definitions come from smbd/open.c  */

NTSTATUS smb1_file_se_access_check(const struct security_descriptor *sd,
                          const NT_USER_TOKEN *token,
                          uint32_t access_desired,
                          uint32_t *access_granted);
NTSTATUS fd_close(files_struct *fsp);
bool map_open_params_to_ntcreate(const char *fname, int deny_mode, int open_func,
				 uint32 *paccess_mask,
				 uint32 *pshare_mode,
				 uint32 *pcreate_disposition,
				 uint32 *pcreate_options);
NTSTATUS open_file_ntcreate(connection_struct *conn,
			    struct smb_request *req,
			    const char *fname,
			    SMB_STRUCT_STAT *psbuf,
			    uint32 access_mask,		/* access bits (FILE_READ_DATA etc.) */
			    uint32 share_access,	/* share constants (FILE_SHARE_READ etc) */
			    uint32 create_disposition,	/* FILE_OPEN_IF etc. */
			    uint32 create_options,	/* options such as delete on close. */
			    uint32 new_dos_attributes,	/* attributes used for new file. */
			    int oplock_request, 	/* internal Samba oplock codes. */
				 			/* Information (FILE_EXISTS etc.) */
			    int *pinfo,
			    files_struct **result);
NTSTATUS open_file_fchmod(connection_struct *conn, const char *fname,
			  SMB_STRUCT_STAT *psbuf, files_struct **result);
NTSTATUS close_file_fchmod(files_struct *fsp);
NTSTATUS open_directory(connection_struct *conn,
			struct smb_request *req,
			const char *fname,
			SMB_STRUCT_STAT *psbuf,
			uint32 access_mask,
			uint32 share_access,
			uint32 create_disposition,
			uint32 create_options,
			uint32 file_attributes,
			int *pinfo,
			files_struct **result);
NTSTATUS create_directory(connection_struct *conn, struct smb_request *req, const char *directory);
void msg_file_was_renamed(struct messaging_context *msg,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id server_id,
			  DATA_BLOB *data);
NTSTATUS create_file_unixpath(connection_struct *conn,
			      struct smb_request *req,
			      const char *fname,
			      uint32_t access_mask,
			      uint32_t share_access,
			      uint32_t create_disposition,
			      uint32_t create_options,
			      uint32_t file_attributes,
			      uint32_t oplock_request,
			      SMB_BIG_UINT allocation_size,
			      struct security_descriptor *sd,
			      struct ea_list *ea_list,

			      files_struct **result,
			      int *pinfo,
			      SMB_STRUCT_STAT *psbuf);
NTSTATUS create_file(connection_struct *conn,
		     struct smb_request *req,
		     uint16_t root_dir_fid,
		     const char *fname,
		     uint32_t access_mask,
		     uint32_t share_access,
		     uint32_t create_disposition,
		     uint32_t create_options,
		     uint32_t file_attributes,
		     uint32_t oplock_request,
		     SMB_BIG_UINT allocation_size,
		     struct security_descriptor *sd,
		     struct ea_list *ea_list,

		     files_struct **result,
		     int *pinfo,
		     SMB_STRUCT_STAT *psbuf);

/* The following definitions come from smbd/oplock.c  */

int32 get_number_of_exclusive_open_oplocks(void);
bool oplock_message_waiting(fd_set *fds);
void process_kernel_oplocks(struct messaging_context *msg_ctx, fd_set *pfds);
bool set_file_oplock(files_struct *fsp, int oplock_type);
void release_file_oplock(files_struct *fsp);
bool remove_oplock(files_struct *fsp);
bool downgrade_oplock(files_struct *fsp);
int oplock_notify_fd(void);
void reply_to_oplock_break_requests(files_struct *fsp);
void release_level_2_oplocks_on_change(files_struct *fsp);
void share_mode_entry_to_message(char *msg, const struct share_mode_entry *e);
void message_to_share_mode_entry(struct share_mode_entry *e, char *msg);
bool init_oplocks(struct messaging_context *msg_ctx);

/* The following definitions come from smbd/oplock_irix.c  */

struct kernel_oplocks *irix_init_kernel_oplocks(void) ;

/* The following definitions come from smbd/oplock_linux.c  */

void linux_set_lease_capability(void);
int linux_set_lease_sighandler(int fd);
int linux_setlease(int fd, int leasetype);
struct kernel_oplocks *linux_init_kernel_oplocks(void) ;

/* The following definitions come from smbd/password.c  */

user_struct *get_valid_user_struct(uint16 vuid);
bool is_partial_auth_vuid(uint16 vuid);
user_struct *get_partial_auth_user_struct(uint16 vuid);
void invalidate_vuid(uint16 vuid);
void invalidate_all_vuids(void);
int register_initial_vuid(void);
int register_existing_vuid(uint16 vuid,
			auth_serversupplied_info *server_info,
			DATA_BLOB response_blob,
			const char *smb_name);
void add_session_user(const char *user);
void add_session_workgroup(const char *workgroup);
const char *get_session_workgroup(void);
bool user_in_netgroup(const char *user, const char *ngname);
bool user_in_list(const char *user,const char **list);
bool authorise_login(int snum, fstring user, DATA_BLOB password,
		     bool *guest);

/* The following definitions come from smbd/pipes.c  */

void reply_open_pipe_and_X(connection_struct *conn, struct smb_request *req);
void reply_pipe_write(struct smb_request *req);
void reply_pipe_write_and_X(struct smb_request *req);
void reply_pipe_read_and_X(struct smb_request *req);
void reply_pipe_close(connection_struct *conn, struct smb_request *req);

/* The following definitions come from smbd/posix_acls.c  */

void create_file_sids(const SMB_STRUCT_STAT *psbuf, DOM_SID *powner_sid, DOM_SID *pgroup_sid);
NTSTATUS unpack_nt_owners(int snum, uid_t *puser, gid_t *pgrp, uint32 security_info_sent, const SEC_DESC *psd);
SMB_ACL_T free_empty_sys_acl(connection_struct *conn, SMB_ACL_T the_acl);
NTSTATUS posix_fget_nt_acl(struct files_struct *fsp, uint32_t security_info,
			   SEC_DESC **ppdesc);
NTSTATUS posix_get_nt_acl(struct connection_struct *conn, const char *name,
			  uint32_t security_info, SEC_DESC **ppdesc);
int try_chown(connection_struct *conn, const char *fname, uid_t uid, gid_t gid);
NTSTATUS append_parent_acl(files_struct *fsp,
				const SEC_DESC *pcsd,
				SEC_DESC **pp_new_sd);
NTSTATUS set_nt_acl(files_struct *fsp, uint32 security_info_sent, const SEC_DESC *psd);
int get_acl_group_bits( connection_struct *conn, const char *fname, mode_t *mode );
int chmod_acl(connection_struct *conn, const char *name, mode_t mode);
int inherit_access_posix_acl(connection_struct *conn, const char *inherit_from_dir,
		       const char *name, mode_t mode);
int fchmod_acl(files_struct *fsp, mode_t mode);
bool set_unix_posix_default_acl(connection_struct *conn, const char *fname, SMB_STRUCT_STAT *psbuf,
				uint16 num_def_acls, const char *pdata);
bool set_unix_posix_acl(connection_struct *conn, files_struct *fsp, const char *fname, uint16 num_acls, const char *pdata);
SEC_DESC *get_nt_acl_no_snum( TALLOC_CTX *ctx, const char *fname);

/* The following definitions come from smbd/process.c  */

bool srv_send_smb(int fd, char *buffer, bool do_encrypt);
int srv_set_message(char *buf,
                        int num_words,
                        int num_bytes,
                        bool zero);
void init_smb_request(struct smb_request *req,
			const uint8 *inbuf,
			size_t unread_bytes,
			bool encrypted);
void remove_deferred_open_smb_message(uint16 mid);
void schedule_deferred_open_smb_message(uint16 mid);
bool open_was_deferred(uint16 mid);
struct pending_message_list *get_open_deferred_message(uint16 mid);
bool push_deferred_smb_message(struct smb_request *req,
			       struct timeval request_time,
			       struct timeval timeout,
			       char *private_data, size_t priv_len);
struct idle_event *event_add_idle(struct event_context *event_ctx,
				  TALLOC_CTX *mem_ctx,
				  struct timeval interval,
				  const char *name,
				  bool (*handler)(const struct timeval *now,
						  void *private_data),
				  void *private_data);
NTSTATUS allow_new_trans(struct trans_state *list, int mid);
void respond_to_all_remaining_local_messages(void);
bool create_outbuf(TALLOC_CTX *mem_ctx, const char *inbuf, char **outbuf,
		   uint8_t num_words, uint32_t num_bytes);
void reply_outbuf(struct smb_request *req, uint8 num_words, uint32 num_bytes);
const char *smb_fn_name(int type);
void add_to_common_flags2(uint32 v);
void remove_from_common_flags2(uint32 v);
void construct_reply_common(const char *inbuf, char *outbuf);
void chain_reply(struct smb_request *req);
void check_reload(time_t t);
void smbd_process(void);

/* The following definitions come from smbd/quotas.c  */

bool disk_quotas(const char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path,
		SMB_BIG_UINT *bsize,
		SMB_BIG_UINT *dfree,
		SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas_vxfs(const char *name, char *path, SMB_BIG_UINT *bsize, SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path,SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize);
bool disk_quotas(const char *path,SMB_BIG_UINT *bsize,SMB_BIG_UINT *dfree,SMB_BIG_UINT *dsize);

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
bool check_fsp_open(connection_struct *conn, struct smb_request *req,
		    files_struct *fsp);
bool check_fsp(connection_struct *conn, struct smb_request *req,
	       files_struct *fsp);
bool check_fsp_ntquota_handle(connection_struct *conn, struct smb_request *req,
			      files_struct *fsp);
bool fsp_belongs_conn(connection_struct *conn, struct smb_request *req,
		      files_struct *fsp);
void reply_special(char *inbuf);
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
			  uint32 dirtype, const char *name_in, bool has_wild);
void reply_unlink(struct smb_request *req);
void send_file_readbraw(connection_struct *conn,
			files_struct *fsp,
			SMB_OFF_T startpos,
			size_t nread,
			ssize_t mincount);
void reply_readbraw(struct smb_request *req);
void reply_lockread(struct smb_request *req);
void reply_read(struct smb_request *req);
void reply_read_and_X(struct smb_request *req);
void error_to_writebrawerr(struct smb_request *req);
void reply_writebraw(struct smb_request *req);
void reply_writeunlock(struct smb_request *req);
void reply_write(struct smb_request *req);
bool is_valid_writeX_buffer(const uint8_t *inbuf);
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
NTSTATUS rmdir_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *directory);
void reply_rmdir(struct smb_request *req);
NTSTATUS rename_internals_fsp(connection_struct *conn,
			files_struct *fsp,
			char *newname,
			const char *newname_last_component,
			uint32 attrs,
			bool replace_if_exists);
NTSTATUS rename_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			const char *name_in,
			const char *newname_in,
			uint32 attrs,
			bool replace_if_exists,
			bool src_has_wild,
			bool dest_has_wild,
			uint32_t access_mask);
void reply_mv(struct smb_request *req);
NTSTATUS copy_file(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *src,
			const char *dest1,
			int ofun,
			int count,
			bool target_is_directory);
void reply_copy(struct smb_request *req);
uint32 get_lock_pid( char *data, int data_offset, bool large_file_format);
SMB_BIG_UINT get_lock_count( char *data, int data_offset, bool large_file_format);
SMB_BIG_UINT get_lock_offset( char *data, int data_offset, bool large_file_format, bool *err);
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
connection_struct *make_connection_with_chdir(const char *service_in,
					      DATA_BLOB password, 
					      const char *dev, uint16 vuid,
					      NTSTATUS *status);
connection_struct *make_connection(const char *service_in, DATA_BLOB password, 
				   const char *pdev, uint16 vuid,
				   NTSTATUS *status);
void close_cnum(connection_struct *conn, uint16 vuid);

/* The following definitions come from smbd/session.c  */

bool session_init(void);
bool session_claim(user_struct *vuser);
void session_yield(user_struct *vuser);
int list_sessions(TALLOC_CTX *mem_ctx, struct sessionid **session_list);

/* The following definitions come from smbd/sesssetup.c  */

NTSTATUS parse_spnego_mechanisms(DATA_BLOB blob_in,
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

SMB_BIG_UINT smb_roundup(connection_struct *conn, SMB_BIG_UINT val);
SMB_BIG_UINT get_allocation_size(connection_struct *conn, files_struct *fsp, const SMB_STRUCT_STAT *sbuf);
NTSTATUS get_ea_value(TALLOC_CTX *mem_ctx, connection_struct *conn,
		      files_struct *fsp, const char *fname,
		      const char *ea_name, struct ea_struct *pea);
NTSTATUS get_ea_names_from_file(TALLOC_CTX *mem_ctx, connection_struct *conn,
				files_struct *fsp, const char *fname,
				char ***pnames, size_t *pnum_names);
NTSTATUS set_ea(connection_struct *conn, files_struct *fsp, const char *fname, struct ea_list *ea_list);
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
		const char *oldname_in,
		const char *newname_in);
NTSTATUS smb_set_file_time(connection_struct *conn,
			   files_struct *fsp,
			   const char *fname,
			   const SMB_STRUCT_STAT *psbuf,
			   struct timespec ts[2],
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
bool become_authenticated_pipe_user(pipes_struct *p);
bool unbecome_authenticated_pipe_user(void);
void become_root(void);
void unbecome_root(void);
bool become_user(connection_struct *conn, uint16 vuid);
bool unbecome_user(void);

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

NTSTATUS smb_register_vfs(int version, const char *name, const vfs_op_tuple *vfs_op_tuples);
bool vfs_init_custom(connection_struct *conn, const char *vfs_object);
void *vfs_add_fsp_extension_notype(vfs_handle_struct *handle, files_struct *fsp, size_t ext_size);
void vfs_remove_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void *vfs_memctx_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void *vfs_fetch_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
bool smbd_vfs_init(connection_struct *conn);
bool vfs_directory_exist(connection_struct *conn, const char *dname, SMB_STRUCT_STAT *st);
bool vfs_object_exist(connection_struct *conn,const char *fname,SMB_STRUCT_STAT *sbuf);
bool vfs_file_exist(connection_struct *conn, const char *fname,SMB_STRUCT_STAT *sbuf);
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
int vfs_allocate_file_space(files_struct *fsp, SMB_BIG_UINT len);
int vfs_set_filelen(files_struct *fsp, SMB_OFF_T len);
int vfs_fill_sparse(files_struct *fsp, SMB_OFF_T len);
SMB_OFF_T vfs_transfer_file(files_struct *in, files_struct *out, SMB_OFF_T n);
char *vfs_readdirname(connection_struct *conn, void *p);
int vfs_ChDir(connection_struct *conn, const char *path);
char *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn);
NTSTATUS check_reduced_name(connection_struct *conn, const char *fname);

/* The following definitions come from torture/denytest.c  */

bool torture_denytest1(int dummy);
bool torture_denytest2(int dummy);

/* The following definitions come from torture/mangle_test.c  */

bool torture_mangle(int dummy);

/* The following definitions come from torture/nbio.c  */

double nbio_total(void);
void nb_alarm(int ignore);
void nbio_shmem(int n);
void nb_setup(struct cli_state *cli);
void nb_unlink(const char *fname);
void nb_createx(const char *fname, 
		unsigned create_options, unsigned create_disposition, int handle);
void nb_writex(int handle, int offset, int size, int ret_size);
void nb_readx(int handle, int offset, int size, int ret_size);
void nb_close(int handle);
void nb_rmdir(const char *fname);
void nb_rename(const char *oldname, const char *newname);
void nb_qpathinfo(const char *fname);
void nb_qfileinfo(int fnum);
void nb_qfsinfo(int level);
void nb_findfirst(const char *mask);
void nb_flush(int fnum);
void nb_deltree(const char *dname);
void nb_cleanup(void);

/* The following definitions come from torture/scanner.c  */

bool torture_trans2_scan(int dummy);
bool torture_nttrans_scan(int dummy);

/* The following definitions come from torture/torture.c  */

void start_timer(void);
double end_timer(void);
void *shm_setup(int size);
bool smbcli_parse_unc(const char *unc_name, TALLOC_CTX *mem_ctx,
		      char **hostname, char **sharename);
void torture_open_connection_free_unclist(char **unc_list);
bool torture_open_connection(struct cli_state **c, int conn_index);
bool torture_cli_session_setup2(struct cli_state *cli, uint16 *new_vuid);
bool torture_close_connection(struct cli_state *c);
bool torture_ioctl_test(int dummy);
bool torture_chkpath_test(int dummy);

/* The following definitions come from torture/utable.c  */

bool torture_utable(int dummy);
bool torture_casetable(int dummy);

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

bool idmap_tdb_tdb_close(TDB_CONTEXT *tdbctx);
NTSTATUS idmap_alloc_tdb_init(void);
NTSTATUS idmap_tdb_init(void);

/* The following definitions come from winbindd/idmap_util.c  */

NTSTATUS idmap_uid_to_sid(const char *domname, DOM_SID *sid, uid_t uid);
NTSTATUS idmap_gid_to_sid(const char *domname, DOM_SID *sid, gid_t gid);
NTSTATUS idmap_sid_to_uid(const char *dom_name, DOM_SID *sid, uid_t *uid);
NTSTATUS idmap_sid_to_gid(const char *domname, DOM_SID *sid, gid_t *gid);

/* The following definitions come from winbindd/nss_info.c  */


/* The following definitions come from winbindd/nss_info_template.c  */

NTSTATUS nss_info_template_init( void );

/* The following definitions come from lib/avahi.c */

struct AvahiPoll *tevent_avahi_poll(TALLOC_CTX *mem_ctx,
				    struct event_context *ev);

/* The following definitions come from smbd/avahi_register.c */

void *avahi_start_register(TALLOC_CTX *mem_ctx, struct event_context *ev,
			   uint16_t port);

#endif /*  _PROTO_H_  */

/*
 *  Unix SMB/CIFS implementation.
 *  Password and authentication handling
 *
 *  Copyright (C) Andrew Tridgell		1992-2001
 *  Copyright (C) Luke Kenneth Casson Leighton	1996-2000
 *  Copyright (C) Jeremy Allison		1997-2001
 *  Copyright (C) John H Terpsta		1999-2001
 *  Copyright (C) Tim Potter			2000
 *  Copyright (C) Andrew Bartlett		2001-2003
 *  Copyright (C) Jelmer Vernooij		2002
 *  Copyright (C) Rafal Szczesniak		2002
 *  Copyright (C) Gerald Carter			2003
 *  Copyright (C) Volker Lendecke		2006,2010
 *  Copyright (C) Michael Adam			2007
 *  Copyright (C) Dan Sledz			2009
 *  Copyright (C) Simo Sorce			2010
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _AUTH_PROTO_H_
#define _AUTH_PROTO_H_

/* The following definitions come from auth/auth.c  */

NTSTATUS smb_register_auth(int version, const char *name, auth_init_function init);
bool load_auth_module(struct auth_context *auth_context,
		      const char *module,
		      struct auth_methods **ret) ;
NTSTATUS make_auth3_context_for_ntlm(TALLOC_CTX *mem_ctx,
				     struct auth_context **auth_context);
NTSTATUS make_auth3_context_for_netlogon(TALLOC_CTX *mem_ctx,
					 struct auth_context **auth_context);
NTSTATUS make_auth3_context_for_winbind(TALLOC_CTX *mem_ctx,
					struct auth_context **auth_context);
bool auth3_context_set_challenge(struct auth_context *ctx, uint8_t chal[8],
				 const char *challenge_set_by);

/****************************************************************************
 Try to get a challenge out of the various authentication modules.
 Returns a const char of length 8 bytes.
****************************************************************************/

NTSTATUS auth_get_ntlm_challenge(struct auth_context *auth_context,
				 uint8_t chal[8]);

/**
 * Check a user's Plaintext, LM or NTLM password.
 *
 * Check a user's password, as given in the user_info struct and return various
 * interesting details in the server_info struct.
 *
 * This function does NOT need to be in a become_root()/unbecome_root() pair
 * as it makes the calls itself when needed.
 *
 * The return value takes precedence over the contents of the server_info 
 * struct.  When the return is other than NT_STATUS_OK the contents 
 * of that structure is undefined.
 *
 * @param mem_ctx   The memory context to use to allocate server_info
 *
 * @param user_info Contains the user supplied components, including the passwords.
 *                  Must be created with make_user_info() or one of its wrappers.
 *
 * @param auth_context Supplies the challenges and some other data. 
 *                  Must be created with make_auth_context(), and the challenges should be 
 *                  filled in, either at creation or by calling the challenge geneation 
 *                  function auth_get_challenge().  
 *
 * @param pserver_info If successful, contains information about the authentication,
 *                     including a struct samu struct describing the user.
 *
 * @param pauthoritative Indicates if the result should be treated as final
 *                       result.
 *
 * @return An NTSTATUS with NT_STATUS_OK or an appropriate error.
 *
 **/
NTSTATUS auth_check_ntlm_password(TALLOC_CTX *mem_ctx,
				  const struct auth_context *auth_context,
				  const struct auth_usersupplied_info *user_info,
				  struct auth_serversupplied_info **pserver_info,
				  uint8_t *pauthoritative);

/* The following definitions come from auth/auth_builtin.c  */

NTSTATUS auth_builtin_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from auth/auth_generic.c  */

NTSTATUS make_auth4_context(TALLOC_CTX *mem_ctx, struct auth4_context **auth4_context_out);
NTSTATUS auth_generic_prepare(TALLOC_CTX *mem_ctx,
			      const struct tsocket_address *remote_address,
			      const struct tsocket_address *local_address,
			      const char *service_description,
			      struct gensec_security **gensec_security_out);

NTSTATUS auth_check_password_session_info(struct auth4_context *auth_context,
					  TALLOC_CTX *mem_ctx,
					  struct auth_usersupplied_info *user_info,
					  struct auth_session_info **session_info);

/* The following definitions come from auth/auth_ntlmssp.c  */

NTSTATUS auth3_generate_session_info(struct auth4_context *auth_context,
				     TALLOC_CTX *mem_ctx,
				     void *server_returned_info,
				     const char *original_user_name,
				     uint32_t session_info_flags,
				     struct auth_session_info **session_info);

NTSTATUS auth3_get_challenge(struct auth4_context *auth4_context,
			     uint8_t chal[8]);

NTSTATUS auth3_set_challenge(struct auth4_context *auth4_context, const uint8_t *chal,
			     const char *challenge_set_by);

struct tevent_req *auth3_check_password_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth4_context *auth4_context,
	const struct auth_usersupplied_info *user_info);
NTSTATUS auth3_check_password_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   uint8_t *pauthoritative,
				   void **server_returned_info,
				   DATA_BLOB *nt_session_key,
				   DATA_BLOB *lm_session_key);

/* The following definitions come from auth/auth_sam.c  */

NTSTATUS check_sam_security(const DATA_BLOB *challenge,
			    TALLOC_CTX *mem_ctx,
			    const struct auth_usersupplied_info *user_info,
			    struct auth_serversupplied_info **server_info);
NTSTATUS check_sam_security_info3(const DATA_BLOB *challenge,
				  TALLOC_CTX *mem_ctx,
				  const struct auth_usersupplied_info *user_info,
				  struct netr_SamInfo3 **pinfo3);
NTSTATUS auth_sam_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from auth/auth_unix.c  */

NTSTATUS auth_unix_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from auth/auth_util.c  */
struct tsocket_address;

NTSTATUS make_user_info_map(TALLOC_CTX *mem_ctx,
			    struct auth_usersupplied_info **user_info,
			    const char *smb_name,
			    const char *client_domain,
			    const char *workstation_name,
			    const struct tsocket_address *remote_address,
			    const struct tsocket_address *local_address,
			    const char *service_description,
			    const DATA_BLOB *lm_pwd,
			    const DATA_BLOB *nt_pwd,
			    const struct samr_Password *lm_interactive_pwd,
			    const struct samr_Password *nt_interactive_pwd,
			    const char *plaintext,
			    enum auth_password_state password_state);
bool make_user_info_netlogon_network(TALLOC_CTX *mem_ctx,
				     struct auth_usersupplied_info **user_info,
				     const char *smb_name,
				     const char *client_domain,
				     const char *workstation_name,
				     const struct tsocket_address *remote_address,
				     const struct tsocket_address *local_address,
				     uint32_t logon_parameters,
				     const uchar *lm_network_pwd,
				     int lm_pwd_len,
				     const uchar *nt_network_pwd,
				     int nt_pwd_len);
bool make_user_info_netlogon_interactive(TALLOC_CTX *mem_ctx,
					 struct auth_usersupplied_info **user_info,
					 const char *smb_name,
					 const char *client_domain,
					 const char *workstation_name,
					 const struct tsocket_address *remote_address,
					 const struct tsocket_address *local_address,
					 uint32_t logon_parameters,
					 const uchar chal[8],
					 const uchar lm_interactive_pwd[16],
					 const uchar nt_interactive_pwd[16]);
bool make_user_info_for_reply(TALLOC_CTX *mem_ctx,
			      struct auth_usersupplied_info **user_info,
			      const char *smb_name,
			      const char *client_domain,
			      const struct tsocket_address *remote_address,
			      const struct tsocket_address *local_address,
			      const char *service_description,
			      const uint8_t chal[8],
			      DATA_BLOB plaintext_password);
NTSTATUS make_user_info_for_reply_enc(TALLOC_CTX *mem_ctx,
				      struct auth_usersupplied_info **user_info,
                                      const char *smb_name,
                                      const char *client_domain,
				      const struct tsocket_address *remote_address,
				      const struct tsocket_address *local_address,
				      const char *service_description,
                                      DATA_BLOB lm_resp, DATA_BLOB nt_resp);
bool make_user_info_guest(TALLOC_CTX *mem_ctx,
			  const struct tsocket_address *remote_address,
			  const struct tsocket_address *local_address,
			  const char *service_description,
			  struct auth_usersupplied_info **user_info);

struct samu;
NTSTATUS make_server_info_sam(TALLOC_CTX *mem_ctx,
			      struct samu *sampass,
			      struct auth_serversupplied_info **pserver_info);
NTSTATUS create_local_token(TALLOC_CTX *mem_ctx,
			    const struct auth_serversupplied_info *server_info,
			    DATA_BLOB *session_key,
			    const char *smb_name,
			    struct auth_session_info **session_info_out);

/*
 * The unix name should be constructed as DOMAIN+ACCOUNT,
 * while '+' will be the "winbind separator" character.
 */
#define AUTH3_UNIX_HINT_QUALIFIED_NAME             0x00000001
/*
 * The unix name will be just ACCOUNT
 */
#define AUTH3_UNIX_HINT_ISLOLATED_NAME             0x00000002
/*
 * Don't translate the nt token SIDS into uid/gids
 */
#define AUTH3_UNIX_HINT_DONT_TRANSLATE_FROM_SIDS   0x00000004
/*
 * Don't translate the unix token uid/gids to S-1-22-X-Y SIDS
 */
#define AUTH3_UNIX_HINT_DONT_TRANSLATE_TO_SIDS     0x00000008
/*
 * The unix token won't get expanded gid values
 * from getgroups_unix_user()
 */
#define AUTH3_UNIX_HINT_DONT_EXPAND_UNIX_GROUPS    0x00000010
NTSTATUS auth3_user_info_dc_add_hints(struct auth_user_info_dc *user_info_dc,
				      uid_t uid,
				      gid_t gid,
				      uint32_t flags);
NTSTATUS auth3_session_info_create(TALLOC_CTX *mem_ctx,
				   const struct auth_user_info_dc *user_info_dc,
				   const char *original_user_name,
				   uint32_t session_info_flags,
				   struct auth_session_info **session_info_out);
NTSTATUS create_token_from_username(TALLOC_CTX *mem_ctx, const char *username,
				    bool is_guest,
				    uid_t *uid, gid_t *gid,
				    char **found_username,
				    struct security_token **token);
bool user_in_group_sid(const char *username, const struct dom_sid *group_sid);
bool user_sid_in_group_sid(const struct dom_sid *sid, const struct dom_sid *group_sid);
bool user_in_group(const char *username, const char *groupname);
struct passwd;
NTSTATUS make_server_info_pw(TALLOC_CTX *mem_ctx,
			     const char *unix_username,
			     const struct passwd *pwd,
			     struct auth_serversupplied_info **server_info);
NTSTATUS make_session_info_from_username(TALLOC_CTX *mem_ctx,
					 const char *username,
					 bool is_guest,
					 struct auth_session_info **session_info);
bool init_guest_session_info(TALLOC_CTX *mem_ctx);
bool reinit_guest_session_info(TALLOC_CTX *mem_ctx);
NTSTATUS init_system_session_info(TALLOC_CTX *mem_ctx);
bool session_info_set_session_key(struct auth_session_info *info,
				 DATA_BLOB session_key);
NTSTATUS make_server_info_guest(TALLOC_CTX *mem_ctx,
				struct auth_serversupplied_info **server_info);
NTSTATUS make_session_info_guest(TALLOC_CTX *mem_ctx,
				struct auth_session_info **server_info);
NTSTATUS make_server_info_anonymous(TALLOC_CTX *mem_ctx,
				    struct auth_serversupplied_info **server_info);
NTSTATUS make_session_info_anonymous(TALLOC_CTX *mem_ctx,
				     struct auth_session_info **psession_info);
NTSTATUS make_session_info_system(TALLOC_CTX *mem_ctx,
				 struct auth_session_info **session_info);
const struct auth_session_info *get_session_info_system(void);
struct passwd *smb_getpwnam( TALLOC_CTX *mem_ctx, const char *domuser,
			     char **p_save_username, bool create );
NTSTATUS make_server_info_info3(TALLOC_CTX *mem_ctx,
				const char *sent_nt_username,
				const char *domain,
				struct auth_serversupplied_info **server_info,
				const struct netr_SamInfo3 *info3);
struct wbcAuthUserInfo;
NTSTATUS make_server_info_wbcAuthUserInfo(TALLOC_CTX *mem_ctx,
					  const char *sent_nt_username,
					  const char *domain,
					  const struct wbcAuthUserInfo *info,
					  struct auth_serversupplied_info **server_info);
bool is_trusted_domain(const char* dom_name);
NTSTATUS session_extract_session_key(const struct auth_session_info *session_info, DATA_BLOB *session_key, enum session_key_use_intent intent);

/* The following definitions come from auth/user_info.c  */

NTSTATUS make_user_info(TALLOC_CTX *mem_ctx,
			struct auth_usersupplied_info **ret_user_info,
			const char *smb_name,
			const char *internal_username,
			const char *client_domain,
			const char *domain,
			const char *workstation_name,
			const struct tsocket_address *remote_address,
			const struct tsocket_address *local_address,
			const char *service_description,
			const DATA_BLOB *lm_pwd,
			const DATA_BLOB *nt_pwd,
			const struct samr_Password *lm_interactive_pwd,
			const struct samr_Password *nt_interactive_pwd,
			const char *plaintext_password,
			enum auth_password_state password_state);

NTSTATUS do_map_to_guest_server_info(TALLOC_CTX *mem_ctx,
				     NTSTATUS status,
				     const char *user,
				     const char *domain,
				     struct auth_serversupplied_info **server_info);

/* The following definitions come from auth/auth_winbind.c  */

NTSTATUS auth_winbind_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from auth/server_info.c  */

struct netr_SamInfo2;
struct netr_SamInfo3;
struct netr_SamInfo6;

struct auth_serversupplied_info *make_server_info(TALLOC_CTX *mem_ctx);
NTSTATUS serverinfo_to_SamInfo2(struct auth_serversupplied_info *server_info,
				struct netr_SamInfo2 *sam2);
NTSTATUS serverinfo_to_SamInfo3(const struct auth_serversupplied_info *server_info,
				struct netr_SamInfo3 *sam3);
NTSTATUS serverinfo_to_SamInfo6(struct auth_serversupplied_info *server_info,
				struct netr_SamInfo6 *sam6);
NTSTATUS create_info3_from_pac_logon_info(TALLOC_CTX *mem_ctx,
                                        const struct PAC_LOGON_INFO *logon_info,
                                        struct netr_SamInfo3 **pp_info3);
NTSTATUS create_info6_from_pac(TALLOC_CTX *mem_ctx,
			       const struct PAC_LOGON_INFO *logon_info,
			       const struct PAC_UPN_DNS_INFO *upn_dns_info,
			       struct netr_SamInfo6 **pp_info6);
NTSTATUS samu_to_SamInfo3(TALLOC_CTX *mem_ctx,
			  struct samu *samu,
			  const char *login_server,
			  struct netr_SamInfo3 **_info3,
			  struct extra_auth_info *extra);
NTSTATUS passwd_to_SamInfo3(TALLOC_CTX *mem_ctx,
			    const char *unix_username,
			    const struct passwd *pwd,
			    struct netr_SamInfo3 **pinfo3,
			    struct extra_auth_info *extra);

/* The following definitions come from auth/pampass.c  */

bool smb_pam_claim_session(const char *user, const char *tty, const char *rhost);
bool smb_pam_close_session(const char *user, const char *tty, const char *rhost);
NTSTATUS smb_pam_accountcheck(const char *user, const char *rhost);
NTSTATUS smb_pam_passcheck(const char * user, const char * rhost,
			   const char * password);
bool smb_pam_passchange(const char *user, const char *rhost,
			const char *oldpassword, const char *newpassword);

/* The following definitions come from auth/pass_check.c  */

NTSTATUS pass_check(const struct passwd *pass,
		    const char *user,
		    const char *rhost,
		    const char *password,
		    bool run_cracker);

/* The following definitions come from auth/token_util.c  */

bool nt_token_check_sid ( const struct dom_sid *sid, const struct security_token *token );
bool nt_token_check_domain_rid( struct security_token *token, uint32_t rid );
NTSTATUS get_root_nt_token( struct security_token **token );
NTSTATUS add_aliases(const struct dom_sid *domain_sid,
		     struct security_token *token);
NTSTATUS create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const struct dom_sid *user_sid,
					    bool is_guest,
					    int num_groupsids,
					    const struct dom_sid *groupsids,
					    struct security_token **token);
NTSTATUS finalize_local_nt_token(struct security_token *result,
				 uint32_t session_info_flags);
NTSTATUS get_user_sid_info3_and_extra(const struct netr_SamInfo3 *info3,
				      const struct extra_auth_info *extra,
				      struct dom_sid *sid);
NTSTATUS create_local_nt_token_from_info3(TALLOC_CTX *mem_ctx,
					  bool is_guest,
					  const struct netr_SamInfo3 *info3,
					  const struct extra_auth_info *extra,
					  struct security_token **ntok);
void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid,
			   int n_groups, gid_t *groups);

/* The following definitions come from auth/user_util.c  */

bool map_username(TALLOC_CTX *ctx, const char *user_in, char **p_user_out);
bool user_in_netgroup(TALLOC_CTX *ctx, const char *user, const char *ngname);
bool user_in_list(TALLOC_CTX *ctx, const char *user, const char * const *list);

/* The following definitions come from auth/user_krb5.c  */
struct PAC_LOGON_INFO;
NTSTATUS get_user_from_kerberos_info(TALLOC_CTX *mem_ctx,
				     const char *cli_name,
				     const char *princ_name,
				     bool *is_mapped,
				     bool *mapped_to_guest,
				     char **ntuser,
				     char **ntdomain,
				     char **username,
				     struct passwd **_pw);
NTSTATUS make_session_info_krb5(TALLOC_CTX *mem_ctx,
				char *ntuser,
				char *ntdomain,
				char *username,
				struct passwd *pw,
				const struct netr_SamInfo3 *info3,
				bool mapped_to_guest, bool username_was_mapped,
				DATA_BLOB *session_key,
				struct auth_session_info **session_info);

/* The following definitions come from auth/auth_samba4.c  */

NTSTATUS auth_samba4_init(TALLOC_CTX *mem_ctx);

#endif /* _AUTH_PROTO_H_ */

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

#ifndef _WINBINDD_PROTO_H_
#define _WINBINDD_PROTO_H_


/* The following definitions come from auth/token_util.c  */

bool nt_token_check_sid ( const DOM_SID *sid, const NT_USER_TOKEN *token );
bool nt_token_check_domain_rid( NT_USER_TOKEN *token, uint32 rid );
NT_USER_TOKEN *get_root_nt_token( void );
NTSTATUS add_aliases(const DOM_SID *domain_sid,
		     struct nt_user_token *token);
struct nt_user_token *create_local_nt_token(TALLOC_CTX *mem_ctx,
					    const DOM_SID *user_sid,
					    bool is_guest,
					    int num_groupsids,
					    const DOM_SID *groupsids);
void debug_nt_user_token(int dbg_class, int dbg_lev, NT_USER_TOKEN *token);
void debug_unix_user_token(int dbg_class, int dbg_lev, uid_t uid, gid_t gid,
			   int n_groups, gid_t *groups);

/* The following definitions come from smbd/connection.c  */

bool yield_connection(connection_struct *conn, const char *name);
int count_current_connections( const char *sharename, bool clear  );
int count_all_current_connections(void);
bool claim_connection(connection_struct *conn, const char *name,
		      uint32 msg_flags);
bool register_message_flags(bool doreg, uint32 msg_flags);
bool store_pipe_opendb( smb_np_struct *p );
bool delete_pipe_opendb( smb_np_struct *p );

/* The following definitions come from winbindd/winbindd.c  */

struct event_context *winbind_event_context(void);
struct messaging_context *winbind_messaging_context(void);
void add_fd_event(struct winbindd_fd_event *ev);
void remove_fd_event(struct winbindd_fd_event *ev);
void setup_async_read(struct winbindd_fd_event *event, void *data, size_t length,
		      void (*finished)(void *private_data, bool success),
		      void *private_data);
void setup_async_write(struct winbindd_fd_event *event, void *data, size_t length,
		       void (*finished)(void *private_data, bool success),
		       void *private_data);
void request_error(struct winbindd_cli_state *state);
void request_ok(struct winbindd_cli_state *state);
void winbind_check_sighup(const char *lfile);
void winbind_check_sigterm(bool in_parent);
bool winbindd_use_idmap_cache(void);
bool winbindd_use_cache(void);
int main(int argc, char **argv, char **envp);

/* The following definitions come from winbindd/winbindd_ads.c  */


/* The following definitions come from winbindd/winbindd_async.c  */

void do_async(TALLOC_CTX *mem_ctx, struct winbindd_child *child,
	      const struct winbindd_request *request,
	      void (*cont)(TALLOC_CTX *mem_ctx, bool success,
			   struct winbindd_response *response,
			   void *c, void *private_data),
	      void *c, void *private_data);
void do_async_domain(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		     const struct winbindd_request *request,
		     void (*cont)(TALLOC_CTX *mem_ctx, bool success,
				  struct winbindd_response *response,
				  void *c, void *private_data),
		     void *c, void *private_data);
void winbindd_lookupsid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			      void (*cont)(void *private_data, bool success,
					   const char *dom_name,
					   const char *name,
					   enum lsa_SidType type),
			      void *private_data);
enum winbindd_result winbindd_dual_lookupsid(struct winbindd_domain *domain,
					     struct winbindd_cli_state *state);
void winbindd_lookupname_async(TALLOC_CTX *mem_ctx,
			       const char *dom_name, const char *name,
			       void (*cont)(void *private_data, bool success,
					    const DOM_SID *sid,
					    enum lsa_SidType type),
			       enum winbindd_cmd orig_cmd,
			       void *private_data);
enum winbindd_result winbindd_dual_lookupname(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state);
void winbindd_listent_async(TALLOC_CTX *mem_ctx,
	                       struct winbindd_domain *domain,
	                       void (*cont)(void *private_data, bool success,
				     fstring dom_name, char* extra_data),
			       void *private_data, enum ent_type type);
enum winbindd_result winbindd_dual_list_users(struct winbindd_domain *domain,
                                              struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_list_groups(struct winbindd_domain *domain,
                                               struct winbindd_cli_state *state);
bool print_sidlist(TALLOC_CTX *mem_ctx, const DOM_SID *sids,
		   size_t num_sids, char **result, ssize_t *len);
enum winbindd_result winbindd_dual_lookuprids(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state);
void winbindd_getsidaliases_async(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *sids, size_t num_sids,
			 	  void (*cont)(void *private_data,
				 	       bool success,
					       const DOM_SID *aliases,
					       size_t num_aliases),
				  void *private_data);
enum winbindd_result winbindd_dual_getsidaliases(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state);
void winbindd_gettoken_async(TALLOC_CTX *mem_ctx, const DOM_SID *user_sid,
			     void (*cont)(void *private_data, bool success,
					  DOM_SID *sids, size_t num_sids),
			     void *private_data);
void query_user_async(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		      const DOM_SID *sid,
		      void (*cont)(void *private_data, bool success,
				   const char *acct_name,
				   const char *full_name,
				   const char *homedir,
				   const char *shell,
				   gid_t gid,
				   uint32 group_rid),
		      void *private_data);

/* The following definitions come from winbindd/winbindd_cache.c  */

void winbindd_check_cache_size(time_t t);
struct cache_entry *centry_start(struct winbindd_domain *domain, NTSTATUS status);
NTSTATUS wcache_cached_creds_exist(struct winbindd_domain *domain, const DOM_SID *sid);
NTSTATUS wcache_get_creds(struct winbindd_domain *domain, 
			  TALLOC_CTX *mem_ctx, 
			  const DOM_SID *sid,
			  const uint8 **cached_nt_pass,
			  const uint8 **cached_salt);
NTSTATUS wcache_save_creds(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   const DOM_SID *sid, 
			   const uint8 nt_pass[NT_HASH_LEN]);
void wcache_invalidate_samlogon(struct winbindd_domain *domain, 
				struct netr_SamInfo3 *info3);
bool wcache_invalidate_cache(void);
bool init_wcache(void);
bool initialize_winbindd_cache(void);
void close_winbindd_cache(void);
void cache_store_response(pid_t pid, struct winbindd_response *response);
bool cache_retrieve_response(pid_t pid, struct winbindd_response * response);
void cache_cleanup_response(pid_t pid);
bool lookup_cached_sid(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
		       char **domain_name, char **name,
		       enum lsa_SidType *type);
bool lookup_cached_name(TALLOC_CTX *mem_ctx,
			const char *domain_name,
			const char *name,
			DOM_SID *sid,
			enum lsa_SidType *type);
void cache_name2sid(struct winbindd_domain *domain, 
		    const char *domain_name, const char *name,
		    enum lsa_SidType type, const DOM_SID *sid);
void wcache_flush_cache(void);
NTSTATUS wcache_count_cached_creds(struct winbindd_domain *domain, int *count);
NTSTATUS wcache_remove_oldest_cached_creds(struct winbindd_domain *domain, const DOM_SID *sid) ;
bool set_global_winbindd_state_offline(void);
void set_global_winbindd_state_online(void);
bool get_global_winbindd_state_offline(void);
int winbindd_validate_cache(void);
int winbindd_validate_cache_nobackup(void);
bool winbindd_cache_validate_and_initialize(void);
bool wcache_tdc_fetch_list( struct winbindd_tdc_domain **domains, size_t *num_domains );
bool wcache_tdc_add_domain( struct winbindd_domain *domain );
struct winbindd_tdc_domain * wcache_tdc_fetch_domain( TALLOC_CTX *ctx, const char *name );
void wcache_tdc_clear( void );
NTSTATUS nss_get_info_cached( struct winbindd_domain *domain, 
			      const DOM_SID *user_sid,
			      TALLOC_CTX *ctx,
			      ADS_STRUCT *ads, LDAPMessage *msg,
			      char **homedir, char **shell, char **gecos,
			      gid_t *p_gid);

/* The following definitions come from winbindd/winbindd_ccache_access.c  */

void winbindd_ccache_ntlm_auth(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_ccache_ntlm_auth(struct winbindd_domain *domain,
						struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_cm.c  */

void set_domain_offline(struct winbindd_domain *domain);
void set_domain_online_request(struct winbindd_domain *domain);
void winbind_add_failed_connection_entry(const struct winbindd_domain *domain,
					const char *server,
					NTSTATUS result);
void invalidate_cm_connection(struct winbindd_cm_conn *conn);
void close_conns_after_fork(void);
NTSTATUS init_dc_connection(struct winbindd_domain *domain);
NTSTATUS cm_connect_sam(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, POLICY_HND *sam_handle);
NTSTATUS cm_connect_lsa(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, POLICY_HND *lsa_policy);
NTSTATUS cm_connect_netlogon(struct winbindd_domain *domain,
			     struct rpc_pipe_client **cli);

/* The following definitions come from winbindd/winbindd_cred_cache.c  */

bool ccache_entry_exists(const char *username);
bool ccache_entry_identical(const char *username,
			    uid_t uid,
			    const char *ccname);
void ccache_remove_all_after_fork(void);
void ccache_regain_all_now(void);
NTSTATUS add_ccache_to_list(const char *princ_name,
			    const char *ccname,
			    const char *service,
			    const char *username,
			    const char *realm,
			    uid_t uid,
			    time_t create_time,
			    time_t ticket_end,
			    time_t renew_until,
			    bool postponed_request);
NTSTATUS remove_ccache(const char *username);
struct WINBINDD_MEMORY_CREDS *find_memory_creds_by_name(const char *username);
NTSTATUS winbindd_add_memory_creds(const char *username,
				   uid_t uid,
				   const char *pass);
NTSTATUS winbindd_delete_memory_creds(const char *username);
NTSTATUS winbindd_replace_memory_creds(const char *username,
				       const char *pass);

/* The following definitions come from winbindd/winbindd_creds.c  */

NTSTATUS winbindd_get_creds(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const DOM_SID *sid,
			    struct netr_SamInfo3 **info3,
			    const uint8 *cached_nt_pass[NT_HASH_LEN],
			    const uint8 *cred_salt[NT_HASH_LEN]);
NTSTATUS winbindd_store_creds(struct winbindd_domain *domain,
			      TALLOC_CTX *mem_ctx, 
			      const char *user, 
			      const char *pass, 
			      struct netr_SamInfo3 *info3,
			      const DOM_SID *user_sid);
NTSTATUS winbindd_update_creds_by_info3(struct winbindd_domain *domain,
				        TALLOC_CTX *mem_ctx,
				        const char *user,
				        const char *pass,
				        struct netr_SamInfo3 *info3);
NTSTATUS winbindd_update_creds_by_sid(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      const DOM_SID *sid,
				      const char *pass);
NTSTATUS winbindd_update_creds_by_name(struct winbindd_domain *domain,
				       TALLOC_CTX *mem_ctx,
				       const char *user,
				       const char *pass);

/* The following definitions come from winbindd/winbindd_domain.c  */

void setup_domain_child(struct winbindd_domain *domain,
			struct winbindd_child *child);

/* The following definitions come from winbindd/winbindd_dual.c  */

void async_request(TALLOC_CTX *mem_ctx, struct winbindd_child *child,
		   struct winbindd_request *request,
		   struct winbindd_response *response,
		   void (*continuation)(void *private_data, bool success),
		   void *private_data);
void async_domain_request(TALLOC_CTX *mem_ctx,
			  struct winbindd_domain *domain,
			  struct winbindd_request *request,
			  struct winbindd_response *response,
			  void (*continuation)(void *private_data_data, bool success),
			  void *private_data_data);
void sendto_child(struct winbindd_cli_state *state,
		  struct winbindd_child *child);
void sendto_domain(struct winbindd_cli_state *state,
		   struct winbindd_domain *domain);
void setup_child(struct winbindd_child *child,
		 const struct winbindd_child_dispatch_table *table,
		 const char *logprefix,
		 const char *logname);
void winbind_child_died(pid_t pid);
void winbindd_flush_negative_conn_cache(struct winbindd_domain *domain);
void winbind_msg_debug(struct messaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data);
void winbind_msg_offline(struct messaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data);
void winbind_msg_online(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data);
void winbind_msg_onlinestatus(struct messaging_context *msg_ctx,
			      void *private_data,
			      uint32_t msg_type,
			      struct server_id server_id,
			      DATA_BLOB *data);
void winbind_msg_dump_event_list(struct messaging_context *msg_ctx,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id server_id,
				 DATA_BLOB *data);
void winbind_msg_dump_domain_list(struct messaging_context *msg_ctx,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data);
bool winbindd_reinit_after_fork(const char *logfilename);

/* The following definitions come from winbindd/winbindd_group.c  */

void winbindd_getgrnam(struct winbindd_cli_state *state);
void winbindd_getgrgid(struct winbindd_cli_state *state);
void winbindd_setgrent(struct winbindd_cli_state *state);
void winbindd_endgrent(struct winbindd_cli_state *state);
void winbindd_getgrent(struct winbindd_cli_state *state);
void winbindd_list_groups(struct winbindd_cli_state *state);
void winbindd_getgroups(struct winbindd_cli_state *state);
void winbindd_getusersids(struct winbindd_cli_state *state);
void winbindd_getuserdomgroups(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_getuserdomgroups(struct winbindd_domain *domain,
						    struct winbindd_cli_state *state);
bool get_sam_group_entries(struct getent_state *ent);


/* The following definitions come from winbindd/winbindd_idmap.c  */

void init_idmap_child(void);
struct winbindd_child *idmap_child(void);
void winbindd_set_mapping_async(TALLOC_CTX *mem_ctx, const struct id_map *map,
			     void (*cont)(void *private_data, bool success),
			     void *private_data);
enum winbindd_result winbindd_dual_set_mapping(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state);
void winbindd_remove_mapping_async(TALLOC_CTX *mem_ctx, const struct id_map *map,
			     void (*cont)(void *private_data, bool success),
			     void *private_data);
enum winbindd_result winbindd_dual_remove_mapping(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state);
void winbindd_set_hwm_async(TALLOC_CTX *mem_ctx, const struct unixid *xid,
			     void (*cont)(void *private_data, bool success),
			     void *private_data);
enum winbindd_result winbindd_dual_set_hwm(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state);
void winbindd_sids2xids_async(TALLOC_CTX *mem_ctx, void *sids, int size,
			 void (*cont)(void *private_data, bool success, void *data, int len),
			 void *private_data);
enum winbindd_result winbindd_dual_sids2xids(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state);
void winbindd_sid2uid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			 void (*cont)(void *private_data, bool success, uid_t uid),
			 void *private_data);
enum winbindd_result winbindd_dual_sid2uid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state);
void winbindd_sid2gid_async(TALLOC_CTX *mem_ctx, const DOM_SID *sid,
			 void (*cont)(void *private_data, bool success, gid_t gid),
			 void *private_data);
enum winbindd_result winbindd_dual_sid2gid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state);
void winbindd_uid2sid_async(TALLOC_CTX *mem_ctx, uid_t uid,
			    void (*cont)(void *private_data, bool success, const char *sid),
			    void *private_data);
enum winbindd_result winbindd_dual_uid2sid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state);
void winbindd_gid2sid_async(TALLOC_CTX *mem_ctx, gid_t gid,
			    void (*cont)(void *private_data, bool success, const char *sid),
			    void *private_data);
enum winbindd_result winbindd_dual_gid2sid(struct winbindd_domain *domain,
					   struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_locator.c  */

void init_locator_child(void);
struct winbindd_child *locator_child(void);
void winbindd_dsgetdcname(struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_misc.c  */

void winbindd_check_machine_acct(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_check_machine_acct(struct winbindd_domain *domain,
						      struct winbindd_cli_state *state);
void winbindd_list_ent(struct winbindd_cli_state *state, enum ent_type type);
void winbindd_list_trusted_domains(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_list_trusted_domains(struct winbindd_domain *domain,
							struct winbindd_cli_state *state);
void winbindd_getdcname(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_getdcname(struct winbindd_domain *domain,
					     struct winbindd_cli_state *state);
void winbindd_show_sequence(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_show_sequence(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state);
void winbindd_domain_info(struct winbindd_cli_state *state);
void winbindd_ping(struct winbindd_cli_state *state);
void winbindd_info(struct winbindd_cli_state *state);
void winbindd_interface_version(struct winbindd_cli_state *state);
void winbindd_domain_name(struct winbindd_cli_state *state);
void winbindd_netbios_name(struct winbindd_cli_state *state);
void winbindd_priv_pipe_dir(struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_ndr.c  */

void ndr_print_winbindd_child(struct ndr_print *ndr,
			      const char *name,
			      const struct winbindd_child *r);
void ndr_print_winbindd_cm_conn(struct ndr_print *ndr,
				const char *name,
				const struct winbindd_cm_conn *r);
void ndr_print_winbindd_methods(struct ndr_print *ndr,
				const char *name,
				const struct winbindd_methods *r);
void ndr_print_winbindd_domain(struct ndr_print *ndr,
			       const char *name,
			       const struct winbindd_domain *r);

/* The following definitions come from winbindd/winbindd_pam.c  */

struct winbindd_domain *find_auth_domain(struct winbindd_cli_state *state, 
					const char *domain_name);
void winbindd_pam_auth(struct winbindd_cli_state *state);
NTSTATUS winbindd_dual_pam_auth_cached(struct winbindd_domain *domain,
				       struct winbindd_cli_state *state,
				       struct netr_SamInfo3 **info3);
NTSTATUS winbindd_dual_pam_auth_kerberos(struct winbindd_domain *domain,
					 struct winbindd_cli_state *state, 
					 struct netr_SamInfo3 **info3);
NTSTATUS winbindd_dual_pam_auth_samlogon(struct winbindd_domain *domain,
					 struct winbindd_cli_state *state,
					 struct netr_SamInfo3 **info3);
enum winbindd_result winbindd_dual_pam_auth(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state) ;
void winbindd_pam_auth_crap(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_pam_auth_crap(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state) ;
void winbindd_pam_chauthtok(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_pam_chauthtok(struct winbindd_domain *contact_domain,
						 struct winbindd_cli_state *state);
void winbindd_pam_logoff(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_pam_logoff(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state) ;
void winbindd_pam_chng_pswd_auth_crap(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_pam_chng_pswd_auth_crap(struct winbindd_domain *domainSt, struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_passdb.c  */


/* The following definitions come from winbindd/winbindd_reconnect.c  */


/* The following definitions come from winbindd/winbindd_sid.c  */

void winbindd_lookupsid(struct winbindd_cli_state *state);
void winbindd_lookupname(struct winbindd_cli_state *state);
void winbindd_lookuprids(struct winbindd_cli_state *state);
void winbindd_sid_to_uid(struct winbindd_cli_state *state);
void winbindd_sid_to_gid(struct winbindd_cli_state *state);
void winbindd_sids_to_unixids(struct winbindd_cli_state *state);
void winbindd_set_mapping(struct winbindd_cli_state *state);
void winbindd_remove_mapping(struct winbindd_cli_state *state);
void winbindd_set_hwm(struct winbindd_cli_state *state);
void winbindd_uid_to_sid(struct winbindd_cli_state *state);
void winbindd_gid_to_sid(struct winbindd_cli_state *state);
void winbindd_allocate_uid(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_allocate_uid(struct winbindd_domain *domain,
						struct winbindd_cli_state *state);
void winbindd_allocate_gid(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_allocate_gid(struct winbindd_domain *domain,
						struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_user.c  */

enum winbindd_result winbindd_dual_userinfo(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state);
void winbindd_getpwnam(struct winbindd_cli_state *state);
void winbindd_getpwuid(struct winbindd_cli_state *state);
void winbindd_setpwent(struct winbindd_cli_state *state);
void winbindd_endpwent(struct winbindd_cli_state *state);
void winbindd_getpwent(struct winbindd_cli_state *state);
void winbindd_list_users(struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_util.c  */

struct winbindd_domain *domain_list(void);
void free_domain_list(void);
void rescan_trusted_domains( void );
enum winbindd_result init_child_connection(struct winbindd_domain *domain,
					   void (*continuation)(void *private_data,
								bool success),
					   void *private_data);
enum winbindd_result winbindd_dual_init_connection(struct winbindd_domain *domain,
						   struct winbindd_cli_state *state);
bool init_domain_list(void);
void check_domain_trusted( const char *name, const DOM_SID *user_sid );
struct winbindd_domain *find_domain_from_name_noinit(const char *domain_name);
struct winbindd_domain *find_domain_from_name(const char *domain_name);
struct winbindd_domain *find_domain_from_sid_noinit(const DOM_SID *sid);
struct winbindd_domain *find_domain_from_sid(const DOM_SID *sid);
struct winbindd_domain *find_our_domain(void);
struct winbindd_domain *find_root_domain(void);
struct winbindd_domain *find_builtin_domain(void);
struct winbindd_domain *find_lookup_domain_from_sid(const DOM_SID *sid);
struct winbindd_domain *find_lookup_domain_from_name(const char *domain_name);
bool winbindd_lookup_sid_by_name(TALLOC_CTX *mem_ctx,
				 enum winbindd_cmd orig_cmd,
				 struct winbindd_domain *domain, 
				 const char *domain_name,
				 const char *name, DOM_SID *sid, 
				 enum lsa_SidType *type);
bool winbindd_lookup_name_by_sid(TALLOC_CTX *mem_ctx,
				 struct winbindd_domain *domain,
				 DOM_SID *sid,
				 char **dom_name,
				 char **name,
				 enum lsa_SidType *type);
void free_getent_state(struct getent_state *state);
bool parse_domain_user(const char *domuser, fstring domain, fstring user);
bool parse_domain_user_talloc(TALLOC_CTX *mem_ctx, const char *domuser,
			      char **domain, char **user);
void parse_add_domuser(void *buf, char *domuser, int *len);
bool canonicalize_username(fstring username_inout, fstring domain, fstring user);
void fill_domain_username(fstring name, const char *domain, const char *user, bool can_assume);
char *fill_domain_username_talloc(TALLOC_CTX *ctx,
				  const char *domain,
				  const char *user,
				  bool can_assume);
const char *get_winbind_pipe_dir(void) ;
char *get_winbind_priv_pipe_dir(void) ;
int open_winbindd_socket(void);
int open_winbindd_priv_socket(void);
void close_winbindd_socket(void);
struct winbindd_cli_state *winbindd_client_list(void);
void winbindd_add_client(struct winbindd_cli_state *cli);
void winbindd_remove_client(struct winbindd_cli_state *cli);
void winbindd_kill_all_clients(void);
int winbindd_num_clients(void);
NTSTATUS lookup_usergroups_cached(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *user_sid,
				  uint32 *p_num_groups, DOM_SID **user_sids);

NTSTATUS normalize_name_map(TALLOC_CTX *mem_ctx,
			    struct winbindd_domain *domain,
			    char *name,
			    char **normalized);
NTSTATUS normalize_name_unmap(TALLOC_CTX *mem_ctx,
			      char *name,
			      char **normalized);

NTSTATUS resolve_username_to_alias(TALLOC_CTX *mem_ctx,
				   struct winbindd_domain *domain,
				   const char *name, char **alias);
NTSTATUS resolve_alias_to_username(TALLOC_CTX *mem_ctx,
				   struct winbindd_domain *domain,
				   const char *alias, char **name);

bool winbindd_can_contact_domain(struct winbindd_domain *domain);
bool winbindd_internal_child(struct winbindd_child *child);
void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain);
void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain);
void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain);
void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain);
void set_auth_errors(struct winbindd_response *resp, NTSTATUS result);

/* The following definitions come from winbindd/winbindd_wins.c  */

void winbindd_wins_byip(struct winbindd_cli_state *state);
void winbindd_wins_byname(struct winbindd_cli_state *state);

#endif /*  _WINBINDD_PROTO_H_  */

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

/* The following definitions come from winbindd/winbindd.c  */
struct imessaging_context *winbind_imessaging_context(void);
bool winbindd_setup_sig_term_handler(bool parent);
bool winbindd_setup_stdin_handler(bool parent, bool foreground);
bool winbindd_setup_sig_hup_handler(const char *lfile);
bool winbindd_use_idmap_cache(void);
bool winbindd_use_cache(void);
char *get_winbind_priv_pipe_dir(void);
void winbindd_flush_caches(void);
bool winbindd_reload_services_file(const char *lfile);

/* The following definitions come from winbindd/winbindd_ads.c  */

/* The following definitions come from winbindd/winbindd_rpc.c  */

NTSTATUS winbindd_lookup_sids(TALLOC_CTX *mem_ctx,
			      struct winbindd_domain *domain,
			      uint32_t num_sids,
			      const struct dom_sid *sids,
			      char ***domains,
			      char ***names,
			      enum lsa_SidType **types);
NTSTATUS rpc_lookup_sids(TALLOC_CTX *mem_ctx,
			 struct winbindd_domain *domain,
			 struct lsa_SidArray *sids,
			 struct lsa_RefDomainList **pdomains,
			 struct lsa_TransNameArray **pnames);

/* The following definitions come from winbindd/winbindd_cache.c  */

NTSTATUS wb_cache_query_user_list(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32_t **prids);
NTSTATUS wb_cache_enum_dom_groups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32_t *num_entries,
				  struct wb_acct_info **info);
NTSTATUS wb_cache_enum_local_groups(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *num_entries,
				    struct wb_acct_info **info);
NTSTATUS wb_cache_name_to_sid(struct winbindd_domain *domain,
			      TALLOC_CTX *mem_ctx,
			      const char *domain_name,
			      const char *name,
			      uint32_t flags,
			      struct dom_sid *sid,
			      enum lsa_SidType *type);
NTSTATUS wb_cache_sid_to_name(struct winbindd_domain *domain,
			      TALLOC_CTX *mem_ctx,
			      const struct dom_sid *sid,
			      char **domain_name,
			      char **name,
			      enum lsa_SidType *type);
NTSTATUS wb_cache_rids_to_names(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *domain_sid,
				uint32_t *rids,
				size_t num_rids,
				char **domain_name,
				char ***names,
				enum lsa_SidType **types);
NTSTATUS wb_cache_lookup_usergroups(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *user_sid,
				    uint32_t *pnum_sids,
				    struct dom_sid **psids);
NTSTATUS wb_cache_lookup_useraliases(struct winbindd_domain *domain,
				     TALLOC_CTX *mem_ctx,
				     uint32_t num_sids,
				     const struct dom_sid *sids,
				     uint32_t *num_aliases,
				     uint32_t **alias_rids);
NTSTATUS wb_cache_lookup_groupmem(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const struct dom_sid *group_sid,
				  enum lsa_SidType type,
				  uint32_t *num_names,
				  struct dom_sid **sid_mem,
				  char ***names,
				  uint32_t **name_types);
NTSTATUS wb_cache_sequence_number(struct winbindd_domain *domain,
				  uint32_t *seq);
NTSTATUS wb_cache_lockout_policy(struct winbindd_domain *domain,
				 TALLOC_CTX *mem_ctx,
				 struct samr_DomInfo12 *policy);
NTSTATUS wb_cache_password_policy(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  struct samr_DomInfo1 *policy);
NTSTATUS wb_cache_trusted_domains(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  struct netr_DomainTrustList *trusts);

NTSTATUS wcache_cached_creds_exist(struct winbindd_domain *domain, const struct dom_sid *sid);
NTSTATUS wcache_get_creds(struct winbindd_domain *domain, 
			  TALLOC_CTX *mem_ctx, 
			  const struct dom_sid *sid,
			  const uint8_t **cached_nt_pass,
			  const uint8_t **cached_salt);
NTSTATUS wcache_save_creds(struct winbindd_domain *domain, 
			   const struct dom_sid *sid,
			   const uint8_t nt_pass[NT_HASH_LEN]);
void wcache_invalidate_samlogon(struct winbindd_domain *domain, 
				const struct dom_sid *user_sid);
bool wcache_invalidate_cache(void);
bool wcache_invalidate_cache_noinit(void);
bool initialize_winbindd_cache(void);
void close_winbindd_cache(void);
bool lookup_cached_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
		       char **domain_name, char **name,
		       enum lsa_SidType *type);
bool lookup_cached_name(const char *namespace,
			const char *domain_name,
			const char *name,
			struct dom_sid *sid,
			enum lsa_SidType *type);
void cache_name2sid_trusted(struct winbindd_domain *domain,
			const char *domain_name,
			const char *name,
			enum lsa_SidType type,
			const struct dom_sid *sid);
void cache_name2sid(struct winbindd_domain *domain, 
		    const char *domain_name, const char *name,
		    enum lsa_SidType type, const struct dom_sid *sid);
NTSTATUS wcache_query_user_fullname(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *user_sid,
				    const char **full_name);

NTSTATUS wcache_count_cached_creds(struct winbindd_domain *domain, int *count);
NTSTATUS wcache_remove_oldest_cached_creds(struct winbindd_domain *domain, const struct dom_sid *sid) ;
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
bool wcache_store_seqnum(const char *domain_name, uint32_t seqnum,
			 time_t last_seq_check);
bool wcache_fetch_ndr(TALLOC_CTX *mem_ctx, struct winbindd_domain *domain,
		      uint32_t opnum, const DATA_BLOB *req, DATA_BLOB *resp);
void wcache_store_ndr(struct winbindd_domain *domain, uint32_t opnum,
		      const DATA_BLOB *req, const DATA_BLOB *resp);

/* The following definitions come from winbindd/winbindd_ccache_access.c  */

bool winbindd_ccache_ntlm_auth(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_ccache_ntlm_auth(struct winbindd_domain *domain,
						struct winbindd_cli_state *state);
bool winbindd_ccache_save(struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_cm.c  */
void winbind_msg_domain_offline(struct messaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data);
void winbind_msg_domain_online(struct messaging_context *msg_ctx,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data);

void set_domain_offline(struct winbindd_domain *domain);
void set_domain_online_request(struct winbindd_domain *domain);

struct ndr_interface_table;
NTSTATUS wb_open_internal_pipe(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *table,
			       struct rpc_pipe_client **ret_pipe);
void invalidate_cm_connection(struct winbindd_domain *domain);
void close_conns_after_fork(void);
NTSTATUS init_dc_connection(struct winbindd_domain *domain, bool need_rw_dc);
NTSTATUS cm_connect_sam(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			bool need_rw_dc,
			struct rpc_pipe_client **cli, struct policy_handle *sam_handle);
NTSTATUS cm_connect_lsa(struct winbindd_domain *domain, TALLOC_CTX *mem_ctx,
			struct rpc_pipe_client **cli, struct policy_handle *lsa_policy);
NTSTATUS cm_connect_lsat(struct winbindd_domain *domain,
			 TALLOC_CTX *mem_ctx,
			 struct rpc_pipe_client **cli,
			 struct policy_handle *lsa_policy);
NTSTATUS cm_connect_netlogon(struct winbindd_domain *domain,
			     struct rpc_pipe_client **cli);
NTSTATUS cm_connect_netlogon_secure(struct winbindd_domain *domain,
				    struct rpc_pipe_client **cli,
				    struct netlogon_creds_cli_context **ppdc);
bool fetch_current_dc_from_gencache(TALLOC_CTX *mem_ctx,
				    const char *domain_name,
				    char **p_dc_name, char **p_dc_ip);

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
			    const char *password,
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
			    const struct dom_sid *sid,
			    struct netr_SamInfo3 **info3,
			    const uint8_t *cached_nt_pass[NT_HASH_LEN],
			    const uint8_t *cred_salt[NT_HASH_LEN]);
NTSTATUS winbindd_store_creds(struct winbindd_domain *domain,
			      const char *user, 
			      const char *pass, 
			      struct netr_SamInfo3 *info3);
NTSTATUS winbindd_update_creds_by_info3(struct winbindd_domain *domain,
				        const char *user,
				        const char *pass,
				        struct netr_SamInfo3 *info3);
NTSTATUS winbindd_update_creds_by_name(struct winbindd_domain *domain,
				       const char *user,
				       const char *pass);

/* The following definitions come from winbindd/winbindd_domain.c  */

void setup_domain_child(struct winbindd_domain *domain);

/* The following definitions come from winbindd/winbindd_dual.c  */

struct dcerpc_binding_handle *dom_child_handle(struct winbindd_domain *domain);

struct tevent_req *wb_child_request_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct winbindd_child *child,
					 struct winbindd_request *request);
int wb_child_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct winbindd_response **presponse, int *err);
struct tevent_req *wb_domain_request_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_domain *domain,
					  struct winbindd_request *request);
int wb_domain_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct winbindd_response **presponse, int *err);

void setup_child(struct winbindd_domain *domain, struct winbindd_child *child,
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
void winbind_disconnect_dc_parent(struct messaging_context *msg_ctx,
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
void winbind_msg_ip_dropped(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data);
void winbind_msg_disconnect_dc(struct messaging_context *msg_ctx,
			       void *private_data,
			       uint32_t msg_type,
			       struct server_id server_id,
			       DATA_BLOB *data);
void winbind_msg_ip_dropped_parent(struct messaging_context *msg_ctx,
				   void *private_data,
				   uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data);
void winbindd_msg_reload_services_parent(struct messaging_context *msg,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id server_id,
					 DATA_BLOB *data);
NTSTATUS winbindd_reinit_after_fork(const struct winbindd_child *myself,
				    const char *logfilename);
struct winbindd_domain *wb_child_domain(void);

/* The following definitions come from winbindd/winbindd_group.c  */
bool fill_grent(TALLOC_CTX *mem_ctx, struct winbindd_gr *gr,
		const char *dom_name, const char *gr_name, gid_t unix_gid);

struct db_context;
NTSTATUS winbindd_print_groupmembers(struct db_context *members,
				     TALLOC_CTX *mem_ctx,
				     int *num_members, char **result);


/* The following definitions come from winbindd/winbindd_idmap.c  */

void init_idmap_child(void);
struct winbindd_child *idmap_child(void);
struct dcerpc_binding_handle *idmap_child_handle(void);
struct idmap_domain *idmap_find_domain_with_sid(const char *domname,
						const struct dom_sid *sid);
const char *idmap_config_const_string(const char *domname, const char *option,
				      const char *def);
bool idmap_config_bool(const char *domname, const char *option, bool def);
int idmap_config_int(const char *domname, const char *option, int def);
bool domain_has_idmap_config(const char *domname);
bool lp_scan_idmap_domains(bool (*fn)(const char *domname,
				      void *private_data),
			   void *private_data);

/* The following definitions come from winbindd/winbindd_locator.c  */

void init_locator_child(void);
struct winbindd_child *locator_child(void);
struct dcerpc_binding_handle *locator_child_handle(void);

/* The following definitions come from winbindd/winbindd_misc.c  */

bool winbindd_list_trusted_domains(struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_list_trusted_domains(struct winbindd_domain *domain,
							struct winbindd_cli_state *state);
bool winbindd_dc_info(struct winbindd_cli_state *state);
bool winbindd_ping(struct winbindd_cli_state *state);
bool winbindd_info(struct winbindd_cli_state *state);
bool winbindd_interface_version(struct winbindd_cli_state *state);
bool winbindd_domain_name(struct winbindd_cli_state *state);
bool winbindd_netbios_name(struct winbindd_cli_state *state);
bool winbindd_priv_pipe_dir(struct winbindd_cli_state *state);

/* The following definitions come from winbindd/winbindd_ndr.c  */
struct ndr_print;
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

bool check_request_flags(uint32_t flags);
NTSTATUS append_auth_data(TALLOC_CTX *mem_ctx,
			  struct winbindd_response *resp,
			  uint32_t request_flags,
			  uint16_t validation_level,
			  union netr_Validation *validation,
			  const char *name_domain,
			  const char *name_user);
uid_t get_uid_from_request(struct winbindd_request *request);
struct winbindd_domain *find_auth_domain(uint8_t flags,
					 const char *domain_name);
enum winbindd_result winbindd_dual_pam_auth(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state) ;
enum winbindd_result winbindd_dual_pam_auth_crap(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state) ;
enum winbindd_result winbindd_dual_pam_chauthtok(struct winbindd_domain *contact_domain,
						 struct winbindd_cli_state *state);
enum winbindd_result winbindd_dual_pam_logoff(struct winbindd_domain *domain,
					      struct winbindd_cli_state *state) ;
enum winbindd_result winbindd_dual_pam_chng_pswd_auth_crap(struct winbindd_domain *domainSt, struct winbindd_cli_state *state);
NTSTATUS winbindd_pam_auth_pac_verify(struct winbindd_cli_state *state,
				      bool *p_is_trusted,
				      uint16_t *p_validation_level,
				      union netr_Validation **p_validation);

NTSTATUS winbind_dual_SamLogon(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       bool interactive,
			       uint32_t logon_parameters,
			       const char *name_user,
			       const char *name_domain,
			       const char *workstation,
			       const uint64_t logon_id,
			       const char *client_name,
			       const int pid,
			       const uint8_t chal[8],
			       DATA_BLOB lm_response,
			       DATA_BLOB nt_response,
			       const struct tsocket_address *remote,
			       const struct tsocket_address *local,
			       uint8_t *authoritative,
			       bool skip_sam,
			       uint32_t *flags,
			       uint16_t *_validation_level,
			       union netr_Validation **_validation);

/* The following definitions come from winbindd/winbindd_util.c  */

struct winbindd_domain *domain_list(void);
struct winbindd_domain *wb_next_domain(struct winbindd_domain *domain);
bool set_routing_domain(struct winbindd_domain *domain,
			struct winbindd_domain *routing_domain);
bool add_trusted_domain_from_auth(uint16_t validation_level,
				  struct info3_text *info3,
				  struct info6_text *info6);
bool domain_is_forest_root(const struct winbindd_domain *domain);
void rescan_trusted_domains(struct tevent_context *ev, struct tevent_timer *te,
			    struct timeval now, void *private_data);
enum winbindd_result winbindd_dual_init_connection(struct winbindd_domain *domain,
						   struct winbindd_cli_state *state);
bool init_domain_list(void);
struct winbindd_domain *find_domain_from_name_noinit(const char *domain_name);
struct winbindd_domain *find_trust_from_name_noinit(const char *domain_name);
struct winbindd_domain *find_domain_from_name(const char *domain_name);
struct winbindd_domain *find_domain_from_sid_noinit(const struct dom_sid *sid);
struct winbindd_domain *find_trust_from_sid_noinit(const struct dom_sid *sid);
struct winbindd_domain *find_domain_from_sid(const struct dom_sid *sid);
struct winbindd_domain *find_our_domain(void);
struct winbindd_domain *find_default_route_domain(void);
struct winbindd_domain *find_lookup_domain_from_sid(const struct dom_sid *sid);
struct winbindd_domain *find_lookup_domain_from_name(const char *domain_name);
bool parse_domain_user(const char *domuser,
		       fstring namespace,
		       fstring domain,
		       fstring user);
bool canonicalize_username(fstring username_inout,
			   fstring namespace,
			   fstring domain,
			   fstring user);
char *fill_domain_username_talloc(TALLOC_CTX *ctx,
				  const char *domain,
				  const char *user,
				  bool can_assume);
struct winbindd_cli_state *winbindd_client_list(void);
struct winbindd_cli_state *winbindd_client_list_tail(void);
struct winbindd_cli_state *
winbindd_client_list_prev(struct winbindd_cli_state *cli);
void winbindd_add_client(struct winbindd_cli_state *cli);
void winbindd_remove_client(struct winbindd_cli_state *cli);
void winbindd_promote_client(struct winbindd_cli_state *cli);
int winbindd_num_clients(void);
NTSTATUS lookup_usergroups_cached(TALLOC_CTX *mem_ctx,
				  const struct dom_sid *user_sid,
				  uint32_t *p_num_groups, struct dom_sid **user_sids);

NTSTATUS normalize_name_map(TALLOC_CTX *mem_ctx,
			     const char *domain_name,
			     const char *name,
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
void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain);
void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain);
void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain);
void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain);
void set_auth_errors(struct winbindd_response *resp, NTSTATUS result);
bool is_domain_offline(const struct winbindd_domain *domain);
bool is_domain_online(const struct winbindd_domain *domain);
bool parse_sidlist(TALLOC_CTX *mem_ctx, const char *sidstr,
		   struct dom_sid **sids, uint32_t *num_sids);
bool parse_xidlist(TALLOC_CTX *mem_ctx, const char *xidstr,
		   struct unixid **pxids, uint32_t *pnum_xids);

/* The following definitions come from winbindd/winbindd_wins.c  */

void winbindd_wins_byname(struct winbindd_cli_state *state);

enum winbindd_result winbindd_dual_ping(struct winbindd_domain *domain,
					struct winbindd_cli_state *state);

struct dcerpc_binding_handle *wbint_binding_handle(TALLOC_CTX *mem_ctx,
						struct winbindd_domain *domain,
						struct winbindd_child *child);
enum winbindd_result winbindd_dual_ndrcmd(struct winbindd_domain *domain,
					  struct winbindd_cli_state *state);

struct tevent_req *wb_lookupsid_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *sid);
NTSTATUS wb_lookupsid_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   enum lsa_SidType *type, const char **domain,
			   const char **name);

struct tevent_req *winbindd_lookupsid_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request);
NTSTATUS winbindd_lookupsid_recv(struct tevent_req *req,
				 struct winbindd_response *response);

struct tevent_req *winbindd_lookupsids_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request);
NTSTATUS winbindd_lookupsids_recv(struct tevent_req *req,
				  struct winbindd_response *response);

struct tevent_req *wb_lookupname_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      const char *namespace,
				      const char *dom_name,
				      const char *name,
				      uint32_t flags);
NTSTATUS wb_lookupname_recv(struct tevent_req *req, struct dom_sid *sid,
			    enum lsa_SidType *type);

struct tevent_req *winbindd_lookupname_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request);
NTSTATUS winbindd_lookupname_recv(struct tevent_req *req,
				  struct winbindd_response *response);

struct tevent_req *winbindd_allocate_uid_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request);
NTSTATUS winbindd_allocate_uid_recv(struct tevent_req *req,
				    struct winbindd_response *response);

struct tevent_req *winbindd_allocate_gid_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request);
NTSTATUS winbindd_allocate_gid_recv(struct tevent_req *req,
				    struct winbindd_response *response);

struct tevent_req *wb_queryuser_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *user_sid);
NTSTATUS wb_queryuser_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct wbint_userinfo **pinfo);

struct tevent_req *wb_getpwsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *user_sid,
				    struct winbindd_pw *pw);
NTSTATUS wb_getpwsid_recv(struct tevent_req *req);

struct tevent_req *winbindd_getpwsid_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getpwsid_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_getpwnam_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getpwnam_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_getpwuid_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getpwuid_recv(struct tevent_req *req,
				struct winbindd_response *response);
struct tevent_req *wb_lookupuseraliases_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_domain *domain,
					     int num_sids,
					     const struct dom_sid *sids);
NTSTATUS wb_lookupuseraliases_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				   uint32_t *num_aliases, uint32_t **aliases);
struct tevent_req *winbindd_getsidaliases_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct winbindd_cli_state *cli,
					       struct winbindd_request *request);
NTSTATUS winbindd_getsidaliases_recv(struct tevent_req *req,
				     struct winbindd_response *response);
struct tevent_req *wb_lookupusergroups_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    const struct dom_sid *sid);
NTSTATUS wb_lookupusergroups_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  int *num_sids, struct dom_sid **sids);

struct tevent_req *winbindd_getuserdomgroups_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct winbindd_cli_state *cli,
						  struct winbindd_request *request);
NTSTATUS winbindd_getuserdomgroups_recv(struct tevent_req *req,
					struct winbindd_response *response);
struct tevent_req *wb_gettoken_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *sid,
				    bool expand_local_aliases);
NTSTATUS wb_gettoken_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  int *num_sids, struct dom_sid **sids);
struct tevent_req *winbindd_getgroups_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request);
NTSTATUS winbindd_getgroups_recv(struct tevent_req *req,
				 struct winbindd_response *response);

struct tevent_req *wb_seqnum_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct winbindd_domain *domain);
NTSTATUS wb_seqnum_recv(struct tevent_req *req, uint32_t *seqnum);

struct tevent_req *wb_seqnums_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev);
NTSTATUS wb_seqnums_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 int *num_domains, struct winbindd_domain ***domains,
			 NTSTATUS **stati, uint32_t **seqnums);

struct tevent_req *winbindd_show_sequence_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct winbindd_cli_state *cli,
					       struct winbindd_request *request);
NTSTATUS winbindd_show_sequence_recv(struct tevent_req *req,
				     struct winbindd_response *response);

struct tevent_req *wb_group_members_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 const struct dom_sid *sid,
					 enum lsa_SidType type,
					 int max_depth);
NTSTATUS wb_group_members_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       struct db_context **members);
NTSTATUS add_member_to_db(struct db_context *db, struct dom_sid *sid,
			  const char *name);

struct tevent_req *wb_getgrsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *group_sid,
				    int max_nesting);
NTSTATUS wb_getgrsid_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  const char **domname, const char **name, gid_t *gid,
			  struct db_context **members);

struct tevent_req *winbindd_getgrgid_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getgrgid_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_getgrnam_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getgrnam_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_getusersids_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_cli_state *cli,
					     struct winbindd_request *request);
NTSTATUS winbindd_getusersids_recv(struct tevent_req *req,
				   struct winbindd_response *response);

struct tevent_req *winbindd_lookuprids_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request);
NTSTATUS winbindd_lookuprids_recv(struct tevent_req *req,
				  struct winbindd_response *response);

struct tevent_req *wb_query_user_list_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_domain *domain);
NTSTATUS wb_query_user_list_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 char **users);

struct tevent_req *wb_query_group_list_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_domain *domain);
NTSTATUS wb_query_group_list_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  int *num_users,
				  struct wbint_Principal **groups);

struct tevent_req *wb_next_pwent_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct getpwent_state *gstate,
				      struct winbindd_pw *pw);
NTSTATUS wb_next_pwent_recv(struct tevent_req *req);

struct tevent_req *winbindd_setpwent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_setpwent_recv(struct tevent_req *req,
				struct winbindd_response *presp);

struct tevent_req *winbindd_getpwent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getpwent_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_endpwent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_endpwent_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_dsgetdcname_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_cli_state *cli,
					     struct winbindd_request *request);
NTSTATUS winbindd_dsgetdcname_recv(struct tevent_req *req,
				   struct winbindd_response *response);

struct tevent_req *wb_dsgetdcname_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       const char *domain_name,
				       const struct GUID *domain_guid,
				       const char *site_name,
				       uint32_t flags);
NTSTATUS wb_dsgetdcname_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			     struct netr_DsRGetDCNameInfo **pdcinfo);
NTSTATUS wb_dsgetdcname_gencache_set(const char *domname,
				     struct netr_DsRGetDCNameInfo *dcinfo);
NTSTATUS wb_dsgetdcname_gencache_get(TALLOC_CTX *mem_ctx,
				     const char *domname,
				     struct netr_DsRGetDCNameInfo **dcinfo);

struct tevent_req *winbindd_getdcname_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request);
NTSTATUS winbindd_getdcname_recv(struct tevent_req *req,
				 struct winbindd_response *response);

struct tevent_req *wb_next_grent_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int max_nesting,
				      struct getgrent_state *gstate,
				      struct winbindd_gr *gr);
NTSTATUS wb_next_grent_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    struct db_context **members);

struct tevent_req *winbindd_setgrent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_setgrent_recv(struct tevent_req *req,
				struct winbindd_response *response);
struct tevent_req *winbindd_getgrent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_getgrent_recv(struct tevent_req *req,
				struct winbindd_response *response);
struct tevent_req *winbindd_endgrent_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_endgrent_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_list_users_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request);
NTSTATUS winbindd_list_users_recv(struct tevent_req *req,
				  struct winbindd_response *response);

struct tevent_req *winbindd_list_groups_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_cli_state *cli,
					     struct winbindd_request *request);
NTSTATUS winbindd_list_groups_recv(struct tevent_req *req,
				   struct winbindd_response *response);

struct tevent_req *winbindd_check_machine_acct_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct winbindd_cli_state *cli,
						    struct winbindd_request *request);
NTSTATUS winbindd_check_machine_acct_recv(struct tevent_req *req,
					  struct winbindd_response *presp);

struct tevent_req *winbindd_ping_dc_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct winbindd_cli_state *cli,
					 struct winbindd_request *request);
NTSTATUS winbindd_ping_dc_recv(struct tevent_req *req,
			       struct winbindd_response *presp);

struct tevent_req *winbindd_change_machine_acct_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct winbindd_cli_state *cli,
						     struct winbindd_request *request);
NTSTATUS winbindd_change_machine_acct_recv(struct tevent_req *req,
					   struct winbindd_response *presp);

struct tevent_req *winbindd_pam_auth_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request);
NTSTATUS winbindd_pam_auth_recv(struct tevent_req *req,
				struct winbindd_response *response);

struct tevent_req *winbindd_pam_auth_crap_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request);
NTSTATUS winbindd_pam_auth_crap_recv(struct tevent_req *req,
				     struct winbindd_response *response);

struct tevent_req *winbindd_pam_chauthtok_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request);
NTSTATUS winbindd_pam_chauthtok_recv(struct tevent_req *req,
				     struct winbindd_response *response);

struct tevent_req *winbindd_pam_logoff_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request);
NTSTATUS winbindd_pam_logoff_recv(struct tevent_req *req,
				  struct winbindd_response *response);

struct tevent_req *winbindd_pam_chng_pswd_auth_crap_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request);
NTSTATUS winbindd_pam_chng_pswd_auth_crap_recv(
	struct tevent_req *req,
	struct winbindd_response *response);

struct tevent_req *wb_lookupsids_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct dom_sid *sids,
				      uint32_t num_sids);
NTSTATUS wb_lookupsids_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    struct lsa_RefDomainList **domains,
			    struct lsa_TransNameArray **names);

struct tevent_req *wb_sids2xids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *sids,
				     const uint32_t num_sids);
NTSTATUS wb_sids2xids_recv(struct tevent_req *req,
			   struct unixid xids[], uint32_t num_xids);
struct tevent_req *winbindd_sids_to_xids_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request);
NTSTATUS winbindd_sids_to_xids_recv(struct tevent_req *req,
				    struct winbindd_response *response);
struct tevent_req *wb_xids2sids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct unixid *xids,
				     uint32_t num_xids);
NTSTATUS wb_xids2sids_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct dom_sid **sids);
struct tevent_req *winbindd_xids_to_sids_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request);
NTSTATUS winbindd_xids_to_sids_recv(struct tevent_req *req,
				    struct winbindd_response *response);
struct tevent_req *winbindd_wins_byip_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request);
NTSTATUS winbindd_wins_byip_recv(struct tevent_req *req,
				 struct winbindd_response *presp);
struct tevent_req *winbindd_wins_byname_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_cli_state *cli,
					     struct winbindd_request *request);
NTSTATUS winbindd_wins_byname_recv(struct tevent_req *req,
				   struct winbindd_response *presp);
struct tevent_req *winbindd_domain_info_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request);
NTSTATUS winbindd_domain_info_recv(struct tevent_req *req,
				   struct winbindd_response *response);

/* The following definitions come from winbindd/winbindd_samr.c  */

NTSTATUS open_internal_samr_conn(TALLOC_CTX *mem_ctx,
				 struct winbindd_domain *domain,
				 struct rpc_pipe_client **samr_pipe,
				 struct policy_handle *samr_domain_hnd);
NTSTATUS open_internal_lsa_conn(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client **lsa_pipe,
				struct policy_handle *lsa_hnd);

/* The following definitions come from winbindd/winbindd_irpc.c  */
NTSTATUS wb_irpc_register(void);

/* The following definitions come from winbindd/winbindd_reconnect.c  */
bool reconnect_need_retry(NTSTATUS status, struct winbindd_domain *domain);

/* The following definitions come from winbindd/winbindd_gpupdate.c  */
void gpupdate_init(void);

/* The following comes from winbindd/winbindd_dual_srv.c */
bool reset_cm_connection_on_error(struct winbindd_domain *domain,
				  struct dcerpc_binding_handle *b,
				  NTSTATUS status);

#endif /*  _WINBINDD_PROTO_H_  */

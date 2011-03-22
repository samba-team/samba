
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
bool delete_uid_cache(uid_t uid);
bool delete_gid_cache(gid_t gid);
bool delete_sid_cache(const struct dom_sid* psid);
void flush_uid_cache(void);
void flush_gid_cache(void);

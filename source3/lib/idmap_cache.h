/* The following definitions come from lib/idmap_cache.c  */

bool idmap_cache_find_sid2uid(const struct dom_sid *sid, uid_t *puid,
			      bool *expired);
bool idmap_cache_find_uid2sid(uid_t uid, struct dom_sid *sid, bool *expired);
void idmap_cache_set_sid2uid(const struct dom_sid *sid, uid_t uid);
bool idmap_cache_find_sid2gid(const struct dom_sid *sid, gid_t *pgid,
			      bool *expired);
bool idmap_cache_find_gid2sid(gid_t gid, struct dom_sid *sid, bool *expired);
void idmap_cache_set_sid2gid(const struct dom_sid *sid, gid_t gid);

bool idmap_cache_del_uid(uid_t uid);
bool idmap_cache_del_gid(gid_t gid);
bool idmap_cache_del_sid(const struct dom_sid *sid);

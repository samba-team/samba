/* The following definitions come from winbindd/idmap.c  */

bool idmap_is_offline(void);
bool idmap_is_online(void);
NTSTATUS smb_register_idmap(int version, const char *name,
			    struct idmap_methods *methods);
void idmap_close(void);
NTSTATUS idmap_allocate_uid(struct unixid *id);
NTSTATUS idmap_allocate_gid(struct unixid *id);
NTSTATUS idmap_backends_unixid_to_sid(const char *domname,
				      struct id_map *id);
NTSTATUS idmap_backends_sid_to_unixid(const char *domname,
				      struct id_map *id);

/* The following definitions come from winbindd/idmap_nss.c  */

NTSTATUS idmap_nss_init(void);

/* The following definitions come from winbindd/idmap_passdb.c  */

NTSTATUS idmap_passdb_init(void);

/* The following definitions come from winbindd/idmap_tdb.c  */

NTSTATUS idmap_tdb_init(void);

/* The following definitions come from winbindd/idmap_util.c  */

NTSTATUS idmap_uid_to_sid(const char *domname, struct dom_sid *sid, uid_t uid);
NTSTATUS idmap_gid_to_sid(const char *domname, struct dom_sid *sid, gid_t gid);
NTSTATUS idmap_sid_to_uid(const char *dom_name, struct dom_sid *sid, uid_t *uid);
NTSTATUS idmap_sid_to_gid(const char *domname, struct dom_sid *sid, gid_t *gid);
bool idmap_unix_id_is_in_range(uint32_t id, struct idmap_domain *dom);

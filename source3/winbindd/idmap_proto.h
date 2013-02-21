/*
 *  Unix SMB/CIFS implementation.
 *  ID Mapping
 *
 *  Copyright (C) Tim Potter 2000
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
 *  Copyright (C) Simo Sorce 2003-2007
 *  Copyright (C) Jeremy Allison 2006
 *  Copyright (C) Michael Adam 2009-2010
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

#ifndef _WINBINDD_IDMAP_PROTO_H_
#define _WINBINDD_IDMAP_PROTO_H_

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

/* The following definitions come from winbindd/idmap_nss.c  */

NTSTATUS idmap_nss_init(void);

/* The following definitions come from winbindd/idmap_passdb.c  */

NTSTATUS idmap_passdb_init(void);

/* The following definitions come from winbindd/idmap_tdb.c  */

NTSTATUS idmap_tdb_init(void);

/* The following definitions come from winbindd/idmap_util.c  */

NTSTATUS idmap_uid_to_sid(const char *domname, struct dom_sid *sid, uid_t uid);
NTSTATUS idmap_gid_to_sid(const char *domname, struct dom_sid *sid, gid_t gid);
bool idmap_unix_id_is_in_range(uint32_t id, struct idmap_domain *dom);
struct id_map *idmap_find_map_by_id(struct id_map **maps, enum id_type type,
				    uint32_t id);
struct id_map *idmap_find_map_by_sid(struct id_map **maps, struct dom_sid *sid);
char *idmap_fetch_secret(const char *backend, const char *domain,
			 const char *identity);

/* max number of ids requested per LDAP batch query */
#define IDMAP_LDAP_MAX_IDS 30

#endif /* _WINBINDD_IDMAP_PROTO_H_ */

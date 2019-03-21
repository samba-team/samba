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
NTSTATUS smb_register_idmap(int version, const char *name,
			    const struct idmap_methods *methods);
void idmap_close(void);
NTSTATUS idmap_allocate_uid(struct unixid *id);
NTSTATUS idmap_allocate_gid(struct unixid *id);
NTSTATUS idmap_backend_unixids_to_sids(struct id_map **maps,
				       const char *domain_name,
				       struct dom_sid domain_sid);
struct idmap_domain *idmap_find_domain(const char *domname);

/* The following definitions come from winbindd/idmap_nss.c  */

NTSTATUS idmap_nss_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from winbindd/idmap_passdb.c  */

NTSTATUS idmap_passdb_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from winbindd/idmap_tdb.c  */

NTSTATUS idmap_tdb_init(TALLOC_CTX *mem_ctx);

/* The following definitions come from winbindd/idmap_util.c  */

bool idmap_unix_id_is_in_range(uint32_t id, struct idmap_domain *dom);
struct id_map *idmap_find_map_by_id(struct id_map **maps, enum id_type type,
				    uint32_t id);
struct id_map *idmap_find_map_by_sid(struct id_map **maps, struct dom_sid *sid);
char *idmap_fetch_secret(const char *backend, const char *domain,
			 const char *identity);

struct id_map **id_map_ptrs_init(TALLOC_CTX *mem_ctx, size_t num_ids);

/* max number of ids requested per LDAP batch query */
#define IDMAP_LDAP_MAX_IDS 30

NTSTATUS idmap_ad_nss_init(TALLOC_CTX *mem_ctx);

#endif /* _WINBINDD_IDMAP_PROTO_H_ */

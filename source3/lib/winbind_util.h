/*
   Unix SMB/CIFS implementation.
   Winbind Utility functions

   Copyright (C) Gerald (Jerry) Carter   2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __LIB__WINBIND_UTIL_H__
#define __LIB__WINBIND_UTIL_H__

#include "../librpc/gen_ndr/lsa.h"
#include "librpc/gen_ndr/idmap.h"

/* needed for wbcErr below */
#include "nsswitch/libwbclient/wbclient.h"

/* The following definitions come from lib/winbind_util.c  */

bool winbind_lookup_name(const char *dom_name, const char *name, struct dom_sid *sid,
                         enum lsa_SidType *name_type);
NTSTATUS winbind_lookup_name_ex(const char *dom_name,
				const char *name,
				struct dom_sid *sid,
				enum lsa_SidType *name_type);
bool winbind_lookup_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			const char **domain, const char **name,
                        enum lsa_SidType *name_type);
bool winbind_ping(void);
bool winbind_sid_to_uid(uid_t *puid, const struct dom_sid *sid);
bool winbind_sid_to_gid(gid_t *pgid, const struct dom_sid *sid);
bool winbind_xid_to_sid(struct dom_sid *sid, const struct unixid *xid);
struct passwd * winbind_getpwnam(const char * sname);
struct passwd * winbind_getpwsid(const struct dom_sid *sid);
wbcErr wb_is_trusted_domain(const char *domain);
bool winbind_lookup_rids(TALLOC_CTX *mem_ctx,
			 const struct dom_sid *domain_sid,
			 int num_rids, uint32_t *rids,
			 const char **domain_name,
			 const char ***names, enum lsa_SidType **types);
bool winbind_allocate_uid(uid_t *uid);
bool winbind_allocate_gid(gid_t *gid);
bool winbind_lookup_usersids(TALLOC_CTX *mem_ctx,
			     const struct dom_sid *user_sid,
			     uint32_t *p_num_sids,
			     struct dom_sid **p_sids);

#endif /* __LIB__WINBIND_UTIL_H__ */

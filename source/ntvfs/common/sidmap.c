/* 
   Unix SMB/CIFS implementation.

   mapping routines for SID <-> unix uid/gid

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/*
  private context for sid mapping routines
*/
struct sidmap_context {
	void *samctx;
};

/*
  open a sidmap context - use talloc_free to close
*/
struct sidmap_context *sidmap_open(TALLOC_CTX *mem_ctx)
{
	struct sidmap_context *sidmap;
	sidmap = talloc_p(mem_ctx, struct sidmap_context);
	if (sidmap == NULL) {
		return NULL;
	}
	sidmap->samctx = samdb_connect(sidmap);
	if (sidmap->samctx == NULL) {
		talloc_free(sidmap);
		return NULL;
	}

	return sidmap;
}

/*
  map a sid to a unix uid
*/
NTSTATUS sidmap_sid_to_unixuid(struct sidmap_context *sidmap, 
			       struct dom_sid *sid, uid_t *uid)
{
	const char *attrs[] = { "sAMAccountName", "unixID", 
				"unixName", "sAMAccountType", NULL };
	int ret;
	const char *s;
	void *ctx;
	struct ldb_message **res;
	const char *sidstr;
	uint_t atype;

	ctx = talloc(sidmap, 0);
	sidstr = dom_sid_string(ctx, sid);
	if (sidstr == NULL) {
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		DEBUG(0,("sid_to_unixuid: unable to find sam record for sid %s\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* make sure its a user, not a group */
	atype = samdb_result_uint(res[0], "sAMAccountType", 0);
	if (atype && (!(atype & ATYPE_ACCOUNT))) {
		DEBUG(0,("sid_to_unixuid: sid %s is not an account!\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* first try to get the uid directly */
	s = samdb_result_string(res[0], "unixID", NULL);
	if (s != NULL) {
		*uid = strtoul(s, NULL, 0);
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	/* next try via the UnixName attribute */
	s = samdb_result_string(res[0], "unixName", NULL);
	if (s != NULL) {
		struct passwd *pwd = getpwnam(s);
		if (!pwd) {
			DEBUG(0,("unixName %s for sid %s does not exist as a local user\n", s, sidstr));
			talloc_free(ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
		*uid = pwd->pw_uid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	/* finally try via the sAMAccountName attribute */
	s = samdb_result_string(res[0], "sAMAccountName", NULL);
	if (s != NULL) {
		struct passwd *pwd = getpwnam(s);
		if (!pwd) {
			DEBUG(0,("sAMAccountName '%s' for sid %s does not exist as a local user\n", s, sidstr));
			talloc_free(ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
		*uid = pwd->pw_uid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	DEBUG(0,("sid_to_unixuid: no unixID, unixName or sAMAccountName for sid %s\n", sidstr));

	talloc_free(ctx);
	return NT_STATUS_ACCESS_DENIED;
}


/*
  map a sid to a unix gid
*/
NTSTATUS sidmap_sid_to_unixgid(struct sidmap_context *sidmap,
			       struct dom_sid *sid, gid_t *gid)
{
	const char *attrs[] = { "sAMAccountName", "unixID", 
				"unixName", "sAMAccountType", NULL };
	int ret;
	const char *s;
	void *ctx;
	struct ldb_message **res;
	const char *sidstr;
	uint_t atype;

	ctx = talloc(sidmap, 0);
	sidstr = dom_sid_string(ctx, sid);
	if (sidstr == NULL) {
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		DEBUG(0,("sid_to_unixgid: unable to find sam record for sid %s\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* make sure its not a user */
	atype = samdb_result_uint(res[0], "sAMAccountType", 0);
	if (atype && atype == ATYPE_NORMAL_ACCOUNT) {
		DEBUG(0,("sid_to_unixgid: sid %s is a ATYPE_NORMAL_ACCOUNT\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* first try to get the gid directly */
	s = samdb_result_string(res[0], "unixID", NULL);
	if (s != NULL) {
		*gid = strtoul(s, NULL, 0);
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	/* next try via the UnixName attribute */
	s = samdb_result_string(res[0], "unixName", NULL);
	if (s != NULL) {
		struct group *grp = getgrnam(s);
		if (!grp) {
			DEBUG(0,("unixName '%s' for sid %s does not exist as a local group\n", 
				 s, sidstr));
			talloc_free(ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
		*gid = grp->gr_gid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	/* finally try via the sAMAccountName attribute */
	s = samdb_result_string(res[0], "sAMAccountName", NULL);
	if (s != NULL) {
		struct group *grp = getgrnam(s);
		if (!grp) {
			DEBUG(0,("sAMAccountName '%s' for sid %s does not exist as a local group\n", s, sidstr));
			talloc_free(ctx);
			return NT_STATUS_ACCESS_DENIED;
		}
		*gid = grp->gr_gid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

	DEBUG(0,("sid_to_unixgid: no unixID, unixName or sAMAccountName for sid %s\n", 
		 sidstr));

	talloc_free(ctx);
	return NT_STATUS_ACCESS_DENIED;
}

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
#include "librpc/gen_ndr/ndr_security.h"

/*
  these are used for the fallback local uid/gid to sid mapping
  code.
*/
#define SIDMAP_LOCAL_USER_BASE  0x80000000
#define SIDMAP_LOCAL_GROUP_BASE 0xC0000000
#define SIDMAP_MAX_LOCAL_UID    0x3fffffff
#define SIDMAP_MAX_LOCAL_GID    0x3fffffff

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
  check the sAMAccountType field of a search result to see if
  the account is a user account
*/
static BOOL is_user_account(struct ldb_message *res)
{
	uint_t atype = samdb_result_uint(res, "sAMAccountType", 0);
	if (atype && (!(atype & ATYPE_ACCOUNT))) {
		return False;
	}
	return True;
}

/*
  check the sAMAccountType field of a search result to see if
  the account is a group account
*/
static BOOL is_group_account(struct ldb_message *res)
{
	uint_t atype = samdb_result_uint(res, "sAMAccountType", 0);
	if (atype && atype == ATYPE_NORMAL_ACCOUNT) {
		return False;
	}
	return True;
}



/*
  return the dom_sid of our primary domain
*/
static NTSTATUS sidmap_primary_domain_sid(struct sidmap_context *sidmap, 
					  TALLOC_CTX *mem_ctx, struct dom_sid **sid)
{
	const char *attrs[] = { "objectSid", NULL };
	void *ctx = talloc(mem_ctx, 0);
	const char *sidstr;
	int ret;
	struct ldb_message **res;

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "(&(objectClass=domain)(name=%s))", lp_workgroup());
	if (ret != 1) {
		talloc_free(ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	
	sidstr = samdb_result_string(res[0], "objectSid", NULL);
	if (sidstr == NULL) {
		talloc_free(ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	*sid = dom_sid_parse_talloc(mem_ctx, sidstr);
	talloc_free(ctx);
	if (*sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
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
	struct dom_sid *domain_sid;
	NTSTATUS status;

	ctx = talloc(sidmap, 0);
	sidstr = dom_sid_string(ctx, sid);
	if (sidstr == NULL) {
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		goto allocated_sid;
	}

	/* make sure its a user, not a group */
	if (!is_user_account(res[0])) {
		DEBUG(0,("sid_to_unixuid: sid %s is not an account!\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_INVALID_SID;
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
			return NT_STATUS_NO_SUCH_USER;
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
			return NT_STATUS_NO_SUCH_USER;
		}
		*uid = pwd->pw_uid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}


allocated_sid:
	status = sidmap_primary_domain_sid(sidmap, ctx, &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	if (dom_sid_in_domain(domain_sid, sid)) {
		uint32_t rid = sid->sub_auths[sid->num_auths-1];
		if (rid >= SIDMAP_LOCAL_USER_BASE && 
		    rid <  SIDMAP_LOCAL_GROUP_BASE) {
			*uid = rid - SIDMAP_LOCAL_USER_BASE;
			talloc_free(ctx);
			return NT_STATUS_OK;
		}
	}
	

	DEBUG(0,("sid_to_unixuid: no unixID, unixName or sAMAccountName for sid %s\n", 
		 sidstr));

	talloc_free(ctx);
	return NT_STATUS_INVALID_SID;
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
	NTSTATUS status;
	struct dom_sid *domain_sid;

	ctx = talloc(sidmap, 0);
	sidstr = dom_sid_string(ctx, sid);
	if (sidstr == NULL) {
		talloc_free(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		goto allocated_sid;
	}

	/* make sure its not a user */
	if (!is_group_account(res[0])) {
		DEBUG(0,("sid_to_unixgid: sid %s is a ATYPE_NORMAL_ACCOUNT\n", sidstr));
		talloc_free(ctx);
		return NT_STATUS_INVALID_SID;
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
			return NT_STATUS_NO_SUCH_USER;
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
			return NT_STATUS_NO_SUCH_USER;
		}
		*gid = grp->gr_gid;
		talloc_free(ctx);
		return NT_STATUS_OK;
	}

allocated_sid:
	status = sidmap_primary_domain_sid(sidmap, ctx, &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	if (dom_sid_in_domain(domain_sid, sid)) {
		uint32_t rid = sid->sub_auths[sid->num_auths-1];
		if (rid >= SIDMAP_LOCAL_GROUP_BASE) {
			*gid = rid - SIDMAP_LOCAL_GROUP_BASE;
			talloc_free(ctx);
			return NT_STATUS_OK;
		}
	}

	DEBUG(0,("sid_to_unixgid: no unixID, unixName or sAMAccountName for sid %s\n", 
		 sidstr));

	talloc_free(ctx);
	return NT_STATUS_INVALID_SID;
}


/*
  map a unix uid to a dom_sid
  the returned sid is allocated in the supplied mem_ctx
*/
NTSTATUS sidmap_uid_to_sid(struct sidmap_context *sidmap,
			   TALLOC_CTX *mem_ctx,
			   uid_t uid, struct dom_sid **sid)
{
	const char *attrs[] = { "sAMAccountName", "objectSid", "sAMAccountType", NULL };
	int ret, i;
	void *ctx;
	struct ldb_message **res;
	struct passwd *pwd;
	struct dom_sid *domain_sid;
	NTSTATUS status;

	/*
	  we search for the mapping in the following order:

	    - check if the uid is in the dynamic uid range assigned for winbindd
	      use. If it is, then look in winbindd sid mapping
	      database (not implemented yet)
	    - look for a user account in samdb that has unixID set to the
	      given uid
	    - look for a user account in samdb that has unixName or
	      sAMAccountName set to the name given by getpwuid()
	    - assign a SID by adding the uid to SIDMAP_LOCAL_USER_BASE in the local
	      domain
	*/


	ctx = talloc(sidmap, 0);


	/*
	  step 2: look for a user account in samdb that has unixID set to the
                  given uid
	*/

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "unixID=%u", (unsigned int)uid);
	for (i=0;i<ret;i++) {
		const char *sidstr;

		if (!is_user_account(res[i])) continue;

		sidstr = samdb_result_string(res[i], "objectSid", NULL);
		if (sidstr == NULL) continue;

		*sid = dom_sid_parse_talloc(mem_ctx, sidstr);
		talloc_free(ctx);
		if (*sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	/*
	  step 3: look for a user account in samdb that has unixName
	          or sAMAccountName set to the name given by getpwuid()
	*/
	pwd = getpwuid(uid);
	if (pwd == NULL) {
		goto allocate_sid;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "(|(unixName=%s)(sAMAccountName=%s))", 
			   pwd->pw_name, pwd->pw_name);
	for (i=0;i<ret;i++) {
		const char *sidstr;

		if (!is_user_account(res[i])) continue;

		sidstr = samdb_result_string(res[i], "objectSid", NULL);
		if (sidstr == NULL) continue;

		*sid = dom_sid_parse_talloc(mem_ctx, sidstr);
		talloc_free(ctx);
		if (*sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}


	/*
	    step 4: assign a SID by adding the uid to
	            SIDMAP_LOCAL_USER_BASE in the local domain
	*/
allocate_sid:
	if (uid > SIDMAP_MAX_LOCAL_UID) {
		return NT_STATUS_INVALID_SID;
	}

	status = sidmap_primary_domain_sid(sidmap, mem_ctx, &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ctx);
		return status;
	}

	*sid = dom_sid_add_rid(mem_ctx, domain_sid, SIDMAP_LOCAL_USER_BASE + uid);
	talloc_free(ctx);

	if (*sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}


/*
  map a unix gid to a dom_sid
  the returned sid is allocated in the supplied mem_ctx
*/
NTSTATUS sidmap_gid_to_sid(struct sidmap_context *sidmap,
			   TALLOC_CTX *mem_ctx,
			   gid_t gid, struct dom_sid **sid)
{
	const char *attrs[] = { "sAMAccountName", "objectSid", "sAMAccountType", NULL };
	int ret, i;
	void *ctx;
	struct ldb_message **res;
	struct group *grp;
	struct dom_sid *domain_sid;
	NTSTATUS status;

	/*
	  we search for the mapping in the following order:

	    - check if the gid is in the dynamic gid range assigned for winbindd
	      use. If it is, then look in winbindd sid mapping
	      database (not implemented yet)
	    - look for a group account in samdb that has unixID set to the
	      given gid
	    - look for a group account in samdb that has unixName or
	      sAMAccountName set to the name given by getgrgid()
	    - assign a SID by adding the gid to SIDMAP_LOCAL_GROUP_BASE in the local
	      domain
	*/


	ctx = talloc(sidmap, 0);


	/*
	  step 2: look for a group account in samdb that has unixID set to the
                  given gid
	*/

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "unixID=%u", (unsigned int)gid);
	for (i=0;i<ret;i++) {
		const char *sidstr;

		if (!is_group_account(res[i])) continue;

		sidstr = samdb_result_string(res[i], "objectSid", NULL);
		if (sidstr == NULL) continue;

		*sid = dom_sid_parse_talloc(mem_ctx, sidstr);
		talloc_free(ctx);
		if (*sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	/*
	  step 3: look for a group account in samdb that has unixName
	          or sAMAccountName set to the name given by getgrgid()
	*/
	grp = getgrgid(gid);
	if (grp == NULL) {
		goto allocate_sid;
	}

	ret = samdb_search(sidmap->samctx, ctx, NULL, &res, attrs, 
			   "(|(unixName=%s)(sAMAccountName=%s))", 
			   grp->gr_name, grp->gr_name);
	for (i=0;i<ret;i++) {
		const char *sidstr;

		if (!is_group_account(res[i])) continue;

		sidstr = samdb_result_string(res[i], "objectSid", NULL);
		if (sidstr == NULL) continue;

		*sid = dom_sid_parse_talloc(mem_ctx, sidstr);
		talloc_free(ctx);
		if (*sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}


	/*
	    step 4: assign a SID by adding the gid to
	            SIDMAP_LOCAL_GROUP_BASE in the local domain
	*/
allocate_sid:
	if (gid > SIDMAP_MAX_LOCAL_GID) {
		return NT_STATUS_INVALID_SID;
	}

	status = sidmap_primary_domain_sid(sidmap, mem_ctx, &domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ctx);
		return status;
	}

	*sid = dom_sid_add_rid(mem_ctx, domain_sid, SIDMAP_LOCAL_GROUP_BASE + gid);
	talloc_free(ctx);

	if (*sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

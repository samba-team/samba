/*
 *  Unix SMB/CIFS implementation.
 *  Authentication utility functions
 *  Copyright (C) Andrew Tridgell 1992-1998
 *  Copyright (C) Andrew Bartlett 2001
 *  Copyright (C) Jeremy Allison 2000-2001
 *  Copyright (C) Rafal Szczesniak 2002
 *  Copyright (C) Volker Lendecke 2006
 *  Copyright (C) Michael Adam 2007
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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "lib/winbind_util.h"
#include "../librpc/gen_ndr/idmap.h"

/**
 * Add sid as a member of builtin_sid.
 *
 * @param[in] builtin_sid	An existing builtin group.
 * @param[in] dom_sid		sid to add as a member of builtin_sid.
 * @return Normal NTSTATUS return
 */
static NTSTATUS add_sid_to_builtin(const struct dom_sid *builtin_sid,
				   const struct dom_sid *dom_sid)
{
	NTSTATUS status;

	if (!dom_sid || !builtin_sid) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = pdb_add_aliasmem(builtin_sid, dom_sid);

	if (NT_STATUS_EQUAL(status, NT_STATUS_MEMBER_IN_ALIAS)) {
		struct dom_sid_buf buf1, buf2;
		DEBUG(5, ("add_sid_to_builtin %s is already a member of %s\n",
			  dom_sid_str_buf(dom_sid, &buf1),
			  dom_sid_str_buf(builtin_sid, &buf2)));
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		struct dom_sid_buf buf1, buf2;
		DEBUG(4, ("add_sid_to_builtin %s could not be added to %s: "
			  "%s\n",
			  dom_sid_str_buf(dom_sid, &buf1),
			  dom_sid_str_buf(builtin_sid, &buf2),
			  nt_errstr(status)));
	}
	return status;
}

/**
 * Create the requested BUILTIN if it doesn't already exist.  This requires
 * winbindd to be running.
 *
 * @param[in] rid BUILTIN rid to create
 * @return Normal NTSTATUS return.
 */
NTSTATUS pdb_create_builtin(uint32_t rid)
{
	NTSTATUS status = NT_STATUS_OK;
	struct dom_sid sid;
	gid_t gid;
	bool mapresult;

	if (!sid_compose(&sid, &global_sid_Builtin, rid)) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if (!pdb_is_responsible_for_builtin()) {
		/*
		 * if this backend is not responsible for BUILTIN
		 *
		 * Use the gid from the mapping request for entry.
		 * If the mapping fails, bail out
		 */
		mapresult = sid_to_gid(&sid, &gid);
		if (!mapresult) {
			status = NT_STATUS_NO_SUCH_GROUP;
		} else {
			status = pdb_create_builtin_alias(rid, gid);
		}
	} else {
		/*
		 * this backend is responsible for BUILTIN
		 *
		 * a failed mapping result means that the entry
		 * does not exist yet, so create it
		 *
		 * we use pdb_sid_to_id intentionally here to
		 * directly query the passdb backend (sid_to_gid
		 * would finally do the same)
		 */
		struct unixid id;
		mapresult = pdb_sid_to_id(&sid, &id);
		if (!mapresult) {
			if (!lp_winbind_nested_groups() || !winbind_ping()) {
				return NT_STATUS_PROTOCOL_UNREACHABLE;
			}
			status = pdb_create_builtin_alias(rid, 0);
		}
	}
	return status;
}

/*******************************************************************
*******************************************************************/

NTSTATUS create_builtin_users(const struct dom_sid *dom_sid)
{
	NTSTATUS status;
	struct dom_sid dom_users;

	status = pdb_create_builtin(BUILTIN_RID_USERS);
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("create_builtin_users: Failed to create Users\n"));
		return status;
	}

	/* add domain users */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER)) &&
	    (dom_sid != NULL) &&
	    sid_compose(&dom_users, dom_sid, DOMAIN_RID_USERS))
	{
		status = add_sid_to_builtin(&global_sid_Builtin_Users,
					    &dom_users);
	}

	return status;
}

/*******************************************************************
*******************************************************************/

NTSTATUS create_builtin_administrators(const struct dom_sid *dom_sid)
{
	NTSTATUS status;
	struct dom_sid dom_admins, root_sid;
	fstring root_name;
	enum lsa_SidType type;
	TALLOC_CTX *ctx;
	bool ret;

	status = pdb_create_builtin(BUILTIN_RID_ADMINISTRATORS);
	if ( !NT_STATUS_IS_OK(status) ) {
		DEBUG(5,("create_builtin_administrators: Failed to create Administrators\n"));
		return status;
	}

	/* add domain admins */
	if ((IS_DC || (lp_server_role() == ROLE_DOMAIN_MEMBER)) &&
	    (dom_sid != NULL) &&
	    sid_compose(&dom_admins, dom_sid, DOMAIN_RID_ADMINS))
	{
		status = add_sid_to_builtin(&global_sid_Builtin_Administrators,
					    &dom_admins);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* add root */
	if ( (ctx = talloc_init("create_builtin_administrators")) == NULL ) {
		return NT_STATUS_NO_MEMORY;
	}
	fstr_sprintf( root_name, "%s\\root", get_global_sam_name() );
	ret = lookup_name(ctx, root_name, LOOKUP_NAME_DOMAIN, NULL, NULL,
			  &root_sid, &type);
	TALLOC_FREE( ctx );

	if ( ret ) {
		status = add_sid_to_builtin(&global_sid_Builtin_Administrators,
					    &root_sid);
	}

	return status;
}

/*******************************************************************
*******************************************************************/

NTSTATUS create_builtin_guests(const struct dom_sid *dom_sid)
{
	NTSTATUS status;
	struct dom_sid tmp_sid = { 0, };

	status = pdb_create_builtin(BUILTIN_RID_GUESTS);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("create_builtin_guests: Failed to create Guests\n"));
		return status;
	}

	/* add local guest */
	if (sid_compose(&tmp_sid, get_global_sam_sid(), DOMAIN_RID_GUEST)) {
		status = add_sid_to_builtin(&global_sid_Builtin_Guests,
					    &tmp_sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* add local guests */
	if (sid_compose(&tmp_sid, get_global_sam_sid(), DOMAIN_RID_GUESTS)) {
		status = add_sid_to_builtin(&global_sid_Builtin_Guests,
					    &tmp_sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (lp_server_role() != ROLE_DOMAIN_MEMBER) {
		return NT_STATUS_OK;
	}

	if (dom_sid == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* add domain guests */
	if (sid_compose(&tmp_sid, dom_sid, DOMAIN_RID_GUESTS)) {
		status = add_sid_to_builtin(&global_sid_Builtin_Guests,
					    &tmp_sid);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

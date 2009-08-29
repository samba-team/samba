/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   Copyright (C) Jeremy Allison 2001.
   Copyright (C) Gerald (Jerry) Carter 2003.
   Copyright (C) Volker Lendecke 2005
   
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

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Fill a grent structure from various other information */

bool fill_grent(TALLOC_CTX *mem_ctx, struct winbindd_gr *gr,
		const char *dom_name, const char *gr_name, gid_t unix_gid)
{
	fstring full_group_name;
	char *mapped_name = NULL;
	struct winbindd_domain *domain = find_domain_from_name_noinit(dom_name);
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	nt_status = normalize_name_map(mem_ctx, domain, gr_name,
				       &mapped_name);

	/* Basic whitespace replacement */
	if (NT_STATUS_IS_OK(nt_status)) {
		fill_domain_username(full_group_name, dom_name,
				     mapped_name, true);
	}
	/* Mapped to an aliase */
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(full_group_name, mapped_name);
	}
	/* no change */
	else {
		fill_domain_username( full_group_name, dom_name,
				      gr_name, True );
	}

	gr->gr_gid = unix_gid;

	/* Group name and password */

	safe_strcpy(gr->gr_name, full_group_name, sizeof(gr->gr_name) - 1);
	safe_strcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);

	return True;
}

/* Get the list of domain groups and domain aliases for a domain.  We fill in
   the sam_entries and num_sam_entries fields with domain group information.
   Return True if some groups were returned, False otherwise. */

bool get_sam_group_entries(struct getent_state *ent)
{
	NTSTATUS status;
	uint32 num_entries;
	struct acct_info *name_list = NULL;
	TALLOC_CTX *mem_ctx;
	bool result = False;
	struct acct_info *sam_grp_entries = NULL;
	struct winbindd_domain *domain;

	if (ent->got_sam_entries)
		return False;

	if (!(mem_ctx = talloc_init("get_sam_group_entries(%s)",
					  ent->domain_name))) {
		DEBUG(1, ("get_sam_group_entries: "
			  "could not create talloc context!\n"));
		return False;
	}

	/* Free any existing group info */

	SAFE_FREE(ent->sam_entries);
	ent->num_sam_entries = 0;
	ent->got_sam_entries = True;

	/* Enumerate domain groups */

	num_entries = 0;

	if (!(domain = find_domain_from_name(ent->domain_name))) {
		DEBUG(3, ("no such domain %s in get_sam_group_entries\n",
			  ent->domain_name));
		goto done;
	}

	/* always get the domain global groups */

	status = domain->methods->enum_dom_groups(domain, mem_ctx, &num_entries,
						  &sam_grp_entries);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("get_sam_group_entries: "
			  "could not enumerate domain groups! Error: %s\n",
			  nt_errstr(status)));
		result = False;
		goto done;
	}

	/* Copy entries into return buffer */

	if (num_entries) {
		name_list = SMB_MALLOC_ARRAY(struct acct_info, num_entries);
		if (!name_list) {
			DEBUG(0,("get_sam_group_entries: Failed to malloc "
				 "memory for %d domain groups!\n",
				 num_entries));
			result = False;
			goto done;
		}
		memcpy(name_list, sam_grp_entries,
			num_entries * sizeof(struct acct_info));
	}

	ent->num_sam_entries = num_entries;

	/* get the domain local groups if we are a member of a native win2k
	 * domain and are not using LDAP to get the groups */

	if ( ( lp_security() != SEC_ADS && domain->native_mode
		&& domain->primary) || domain->internal )
	{
		DEBUG(4,("get_sam_group_entries: %s domain; "
			 "enumerating local groups as well\n",
			 domain->native_mode ? "Native Mode 2k":
						"BUILTIN or local"));

		status = domain->methods->enum_local_groups(domain, mem_ctx,
							    &num_entries,
							    &sam_grp_entries);

		if ( !NT_STATUS_IS_OK(status) ) {
			DEBUG(3,("get_sam_group_entries: "
				"Failed to enumerate "
				"domain local groups with error %s!\n",
				nt_errstr(status)));
			num_entries = 0;
		}
		else
			DEBUG(4,("get_sam_group_entries: "
				 "Returned %d local groups\n",
				 num_entries));

		/* Copy entries into return buffer */

		if ( num_entries ) {
			name_list = SMB_REALLOC_ARRAY(name_list,
						      struct acct_info,
						      ent->num_sam_entries+
							num_entries);
			if (!name_list) {
				DEBUG(0,("get_sam_group_entries: "
					 "Failed to realloc more memory "
					 "for %d local groups!\n",
					 num_entries));
				result = False;
				goto done;
			}

			memcpy(&name_list[ent->num_sam_entries],
				sam_grp_entries,
				num_entries * sizeof(struct acct_info));
		}

		ent->num_sam_entries += num_entries;
	}


	/* Fill in remaining fields */

	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;

	result = (ent->num_sam_entries > 0);

 done:
	talloc_destroy(mem_ctx);

	return result;
}

/* Get user supplementary groups.  This is much quicker than trying to
   invert the groups database.  We merge the groups from the gids and
   other_sids info3 fields as trusted domain, universal group
   memberships, and nested groups (win2k native mode only) are not
   returned by the getgroups RPC call but are present in the info3. */

struct getgroups_state {
	struct winbindd_cli_state *state;
	struct winbindd_domain *domain;
	char *domname;
	char *username;
	DOM_SID user_sid;

	const DOM_SID *token_sids;
	size_t i, num_token_sids;

	gid_t *token_gids;
	size_t num_token_gids;
};

enum winbindd_result winbindd_dual_getuserdomgroups(struct winbindd_domain *domain,
						    struct winbindd_cli_state *state)
{
	DOM_SID user_sid;
	NTSTATUS status;

	char *sidstring;
	ssize_t len;
	DOM_SID *groups;
	uint32 num_groups;

	/* Ensure null termination */
	state->request->data.sid[sizeof(state->request->data.sid)-1]='\0';

	if (!string_to_sid(&user_sid, state->request->data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request->data.sid));
		return WINBINDD_ERROR;
	}

	status = domain->methods->lookup_usergroups(domain, state->mem_ctx,
						    &user_sid, &num_groups,
						    &groups);
	if (!NT_STATUS_IS_OK(status))
		return WINBINDD_ERROR;

	if (num_groups == 0) {
		state->response->data.num_entries = 0;
		state->response->extra_data.data = NULL;
		return WINBINDD_OK;
	}

	if (!print_sidlist(state->mem_ctx,
			   groups, num_groups,
			   &sidstring, &len)) {
		DEBUG(0, ("talloc failed\n"));
		return WINBINDD_ERROR;
	}

	state->response->extra_data.data = sidstring;
	state->response->length += len+1;
	state->response->data.num_entries = num_groups;

	return WINBINDD_OK;
}

enum winbindd_result winbindd_dual_getsidaliases(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state)
{
	DOM_SID *sids = NULL;
	size_t num_sids = 0;
	char *sidstr = NULL;
	ssize_t len;
	size_t i;
	uint32 num_aliases;
	uint32 *alias_rids;
	NTSTATUS result;

	DEBUG(3, ("[%5lu]: getsidaliases\n", (unsigned long)state->pid));

	sidstr = state->request->extra_data.data;
	if (sidstr == NULL) {
		sidstr = talloc_strdup(state->mem_ctx, "\n"); /* No SID */
		if (!sidstr) {
			DEBUG(0, ("Out of memory\n"));
			return WINBINDD_ERROR;
		}
	}

	DEBUG(10, ("Sidlist: %s\n", sidstr));

	if (!parse_sidlist(state->mem_ctx, sidstr, &sids, &num_sids)) {
		DEBUG(0, ("Could not parse SID list: %s\n", sidstr));
		return WINBINDD_ERROR;
	}

	num_aliases = 0;
	alias_rids = NULL;

	result = domain->methods->lookup_useraliases(domain,
						     state->mem_ctx,
						     num_sids, sids,
						     &num_aliases,
						     &alias_rids);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(3, ("Could not lookup_useraliases: %s\n",
			  nt_errstr(result)));
		return WINBINDD_ERROR;
	}

	num_sids = 0;
	sids = NULL;
	sidstr = NULL;

	DEBUG(10, ("Got %d aliases\n", num_aliases));

	for (i=0; i<num_aliases; i++) {
		DOM_SID sid;
		DEBUGADD(10, (" rid %d\n", alias_rids[i]));
		sid_copy(&sid, &domain->sid);
		sid_append_rid(&sid, alias_rids[i]);
		result = add_sid_to_array(state->mem_ctx, &sid, &sids,
					  &num_sids);
		if (!NT_STATUS_IS_OK(result)) {
			return WINBINDD_ERROR;
		}
	}


	if (!print_sidlist(state->mem_ctx, sids, num_sids, &sidstr, &len)) {
		DEBUG(0, ("Could not print_sidlist\n"));
		state->response->extra_data.data = NULL;
		return WINBINDD_ERROR;
	}

	state->response->extra_data.data = NULL;

	if (sidstr) {
		state->response->extra_data.data = sidstr;
		DEBUG(10, ("aliases_list: %s\n",
			   (char *)state->response->extra_data.data));
		state->response->length += len+1;
		state->response->data.num_entries = num_sids;
	}

	return WINBINDD_OK;
}

struct getgr_countmem {
	int num;
	size_t len;
};

static int getgr_calc_memberlen(DATA_BLOB key, void *data, void *priv)
{
	struct wbint_Principal *m = talloc_get_type_abort(
		data, struct wbint_Principal);
	struct getgr_countmem *buf = (struct getgr_countmem *)priv;

	buf->num += 1;
	buf->len += strlen(m->name) + 1;
	return 0;
}

struct getgr_stringmem {
	size_t ofs;
	char *buf;
};

static int getgr_unparse_members(DATA_BLOB key, void *data, void *priv)
{
	struct wbint_Principal *m = talloc_get_type_abort(
		data, struct wbint_Principal);
	struct getgr_stringmem *buf = (struct getgr_stringmem *)priv;
	int len;

	len = strlen(m->name);

	memcpy(buf->buf + buf->ofs, m->name, len);
	buf->ofs += len;
	buf->buf[buf->ofs] = ',';
	buf->ofs += 1;
	return 0;
}

NTSTATUS winbindd_print_groupmembers(struct talloc_dict *members,
				     TALLOC_CTX *mem_ctx,
				     int *num_members, char **result)
{
	struct getgr_countmem c;
	struct getgr_stringmem m;
	int res;

	c.num = 0;
	c.len = 0;

	res = talloc_dict_traverse(members, getgr_calc_memberlen, &c);
	if (res != 0) {
		DEBUG(5, ("talloc_dict_traverse failed\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	m.ofs = 0;
	m.buf = talloc_array(mem_ctx, char, c.len);
	if (m.buf == NULL) {
		DEBUG(5, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	res = talloc_dict_traverse(members, getgr_unparse_members, &m);
	if (res != 0) {
		DEBUG(5, ("talloc_dict_traverse failed\n"));
		TALLOC_FREE(m.buf);
		return NT_STATUS_INTERNAL_ERROR;
	}
	m.buf[c.len-1] = '\0';

	*num_members = c.num;
	*result = m.buf;
	return NT_STATUS_OK;
}

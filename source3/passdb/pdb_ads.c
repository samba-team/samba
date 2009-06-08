/*
   Unix SMB/CIFS implementation.
   pdb_ldap with ads schema
   Copyright (C) Volker Lendecke 2009

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

static NTSTATUS pdb_ads_getsampwsid(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const DOM_SID *sid);
static bool pdb_ads_gid_to_sid(struct pdb_methods *m, gid_t gid,
			       DOM_SID *sid);


struct pdb_ads_state {
	struct tldap_context *ld;
	struct dom_sid domainsid;
	char *domaindn;
	char *configdn;
	char *netbiosname;
};

static bool pdb_ads_pull_time(struct tldap_message *msg, const char *attr,
			      time_t *ptime)
{
	uint64_t tmp;

	if (!tldap_pull_uint64(msg, attr, &tmp)) {
		return false;
	}
	*ptime = uint64s_nt_time_to_unix_abs(&tmp);
	return true;
}

static gid_t pdb_ads_sid2gid(const struct dom_sid *sid)
{
	uint32_t rid;
	sid_peek_rid(sid, &rid);
	return rid;
}

struct pdb_ads_samu_private {
	char *dn;
	struct tldap_message *ldapmsg;
};

static struct samu *pdb_ads_init_guest(TALLOC_CTX *mem_ctx,
				       struct pdb_methods *m)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct dom_sid guest_sid;
	struct samu *guest;
	NTSTATUS status;

	sid_compose(&guest_sid, &state->domainsid, DOMAIN_USER_RID_GUEST);

	guest = samu_new(mem_ctx);
	if (guest == NULL) {
		return NULL;
	}

	status = pdb_ads_getsampwsid(m, guest, &guest_sid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Could not init guest account: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(guest);
		return NULL;
	}
	return guest;
}

static struct pdb_ads_samu_private *pdb_ads_get_samu_private(
	struct pdb_methods *m, struct samu *sam)
{
	struct pdb_ads_samu_private *result;
	uint32_t rid;

	result = (struct pdb_ads_samu_private *)
		pdb_get_backend_private_data(sam, m);

	if (result != NULL) {
		return talloc_get_type_abort(
			result, struct pdb_ads_samu_private);
	}

	/*
	 * This is now a weirdness of the passdb API. For the guest user we
	 * are not asked first.
	 */
	sid_peek_rid(pdb_get_user_sid(sam), &rid);

	if (rid == DOMAIN_USER_RID_GUEST) {
		struct samu *guest = pdb_ads_init_guest(talloc_tos(), m);

		if (guest == NULL) {
			return NULL;
		}
		result = talloc_get_type_abort(
			pdb_get_backend_private_data(guest, m),
			struct pdb_ads_samu_private);
		pdb_set_backend_private_data(
			sam, talloc_move(sam, &result), NULL, m, PDB_SET);
		TALLOC_FREE(guest);
		return talloc_get_type_abort(
			pdb_get_backend_private_data(sam, m),
			struct pdb_ads_samu_private);
	}

	return NULL;
}

static NTSTATUS pdb_ads_init_sam_from_ads(struct pdb_methods *m,
					  struct samu *sam,
					  struct tldap_message *entry)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_ads_samu_private *priv;
	NTSTATUS status = NT_STATUS_INTERNAL_DB_CORRUPTION;
	char *str;
	time_t tmp_time;
	struct dom_sid sid;
	uint64_t n;
	DATA_BLOB blob;

	priv = talloc(sam, struct pdb_ads_samu_private);
	if (priv == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!tldap_entry_dn(entry, &priv->dn)) {
		TALLOC_FREE(priv);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	str = tldap_talloc_single_attribute(entry, "samAccountName", sam);
	if (str == NULL) {
		DEBUG(10, ("no samAccountName\n"));
		goto fail;
	}
	pdb_set_username(sam, str, PDB_SET);
	TALLOC_FREE(str);

	if (pdb_ads_pull_time(entry, "lastLogon", &tmp_time)) {
		pdb_set_logon_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_ads_pull_time(entry, "lastLogoff", &tmp_time)) {
		pdb_set_logoff_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_ads_pull_time(entry, "pwdLastSet", &tmp_time)) {
		pdb_set_pass_last_set_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_ads_pull_time(entry, "accountExpires", &tmp_time)) {
		pdb_set_pass_last_set_time(sam, tmp_time, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "samAccoutName",
					    talloc_tos());
	if (str != NULL) {
		pdb_set_username(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "displayName",
					    talloc_tos());
	if (str != NULL) {
		pdb_set_fullname(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "homeDirectory",
					    talloc_tos());
	if (str != NULL) {
		pdb_set_homedir(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "homeDrive", talloc_tos());
	if (str != NULL) {
		pdb_set_dir_drive(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "scriptPath", talloc_tos());
	if (str != NULL) {
		pdb_set_logon_script(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "profilePath",
					    talloc_tos());
	if (str != NULL) {
		pdb_set_profile_path(sam, str, PDB_SET);
	}

	str = tldap_talloc_single_attribute(entry, "profilePath",
					    talloc_tos());
	if (str != NULL) {
		pdb_set_profile_path(sam, str, PDB_SET);
	}

	if (!tldap_pull_binsid(entry, "objectSid", &sid)) {
		DEBUG(10, ("Could not pull SID\n"));
		goto fail;
	}
	pdb_set_user_sid(sam, &sid, PDB_SET);

	if (!tldap_pull_uint64(entry, "userAccountControl", &n)) {
		DEBUG(10, ("Could not pull userAccountControl\n"));
		goto fail;
	}
	pdb_set_acct_ctrl(sam, ads_uf2acb(n), PDB_SET);

	if (tldap_get_single_valueblob(entry, "unicodePwd", &blob)) {
		if (blob.length != NT_HASH_LEN) {
			DEBUG(0, ("Got NT hash of length %d, expected %d\n",
				  (int)blob.length, NT_HASH_LEN));
			goto fail;
		}
		pdb_set_nt_passwd(sam, blob.data, PDB_SET);
	}

	if (tldap_get_single_valueblob(entry, "dBCSPwd", &blob)) {
		if (blob.length != LM_HASH_LEN) {
			DEBUG(0, ("Got LM hash of length %d, expected %d\n",
				  (int)blob.length, LM_HASH_LEN));
			goto fail;
		}
		pdb_set_lanman_passwd(sam, blob.data, PDB_SET);
	}

	if (tldap_pull_uint64(entry, "primaryGroupID", &n)) {
		sid_compose(&sid, &state->domainsid, n);
		pdb_set_group_sid(sam, &sid, PDB_SET);

	}

	priv->ldapmsg = talloc_move(priv, &entry);
	pdb_set_backend_private_data(sam, priv, NULL, m, PDB_SET);

	status = NT_STATUS_OK;
fail:
	TALLOC_FREE(frame);
	return status;
}

static bool pdb_ads_init_ads_from_sam(struct pdb_ads_state *state,
				      struct tldap_message *existing,
				      TALLOC_CTX *mem_ctx,
				      int *pnum_mods, struct tldap_mod **pmods,
				      struct samu *sam)
{
	bool ret = true;

	/* TODO: All fields :-) */

	ret &= tldap_make_mod_fmt(
		existing, mem_ctx, pnum_mods, pmods, "displayName",
		"%s", pdb_get_fullname(sam));

	ret &= tldap_make_mod_blob(
		existing, mem_ctx, pnum_mods, pmods, "unicodePwd",
		data_blob_const(pdb_get_nt_passwd(sam), NT_HASH_LEN));

	ret &= tldap_make_mod_blob(
		existing, mem_ctx, pnum_mods, pmods, "dBCSPwd",
		data_blob_const(pdb_get_lanman_passwd(sam), NT_HASH_LEN));

	return ret;
}

static NTSTATUS pdb_ads_getsampwfilter(struct pdb_methods *m,
				       struct pdb_ads_state *state,
				       struct samu *sam_acct,
				       const char *filter)
{
	const char * attrs[] = {
		"lastLogon", "lastLogoff", "pwdLastSet", "accountExpires",
		"sAMAccountName", "displayName", "homeDirectory",
		"homeDrive", "scriptPath", "profilePath", "description",
		"userWorkstations", "comment", "userParameters", "objectSid",
		"primaryGroupID", "userAccountControl", "logonHours",
		"badPwdCount", "logonCount", "countryCode", "codePage",
		"unicodePwd", "dBCSPwd" };
	struct tldap_message **users;
	int rc, count;

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      attrs, ARRAY_SIZE(attrs), 0, talloc_tos(),
			      &users, "%s", filter);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}

	count = talloc_array_length(users);
	if (count != 1) {
		DEBUG(10, ("Expected 1 user, got %d\n", count));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return pdb_ads_init_sam_from_ads(m, sam_acct, users[0]);
}

static NTSTATUS pdb_ads_getsampwnam(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const char *username)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	char *filter;

	filter = talloc_asprintf(
		talloc_tos(), "(&(samaccountname=%s)(objectclass=user))",
		username);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	return pdb_ads_getsampwfilter(m, state, sam_acct, filter);
}

static NTSTATUS pdb_ads_getsampwsid(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const DOM_SID *sid)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	char *sidstr, *filter;

	sidstr = sid_binstring(talloc_tos(), sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	filter = talloc_asprintf(
		talloc_tos(), "(&(objectsid=%s)(objectclass=user))", sidstr);
	TALLOC_FREE(sidstr);
	NT_STATUS_HAVE_NO_MEMORY(filter);

	return pdb_ads_getsampwfilter(m, state, sam_acct, filter);
}

static NTSTATUS pdb_ads_create_user(struct pdb_methods *m,
				    TALLOC_CTX *tmp_ctx,
				    const char *name, uint32 acct_flags,
				    uint32 *rid)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	const char *attrs[1] = { "objectSid" };
	struct tldap_mod *mods = NULL;
	int num_mods = 0;
	struct tldap_message **user;
	struct dom_sid sid;
	char *dn;
	int rc;
	bool ok;

	dn = talloc_asprintf(talloc_tos(), "cn=%s,cn=users,%s", name,
			     state->domaindn);
	if (dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* TODO: Create machines etc */

	ok = true;
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "objectClass", "user");
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "samAccountName", "%s",
		name);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_add(state->ld, dn, num_mods, mods, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_add failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(dn);
		return NT_STATUS_LDAP(rc);
	}

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &user,
			     "(&(objectclass=user)(samaccountname=%s))",
			     name);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not find just created user %s: %s\n",
			   name, tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(dn);
		return NT_STATUS_LDAP(rc);
	}

	if (talloc_array_length(user) != 1) {
		DEBUG(10, ("Got %d users, expected one\n",
			   (int)talloc_array_length(user)));
		TALLOC_FREE(dn);
		return NT_STATUS_LDAP(rc);
	}

	if (!tldap_pull_binsid(user[0], "objectSid", &sid)) {
		DEBUG(10, ("Could not fetch objectSid from user %s\n",
			   name));
		TALLOC_FREE(dn);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	sid_peek_rid(&sid, rid);
	TALLOC_FREE(dn);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_delete_user(struct pdb_methods *m,
				    TALLOC_CTX *tmp_ctx,
				    struct samu *sam)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct pdb_ads_samu_private *priv = pdb_ads_get_samu_private(m, sam);
	int rc;

	rc = tldap_delete(state->ld, priv->dn, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_delete for %s failed: %s\n", priv->dn,
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_add_sam_account(struct pdb_methods *m,
					struct samu *sampass)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_update_sam_account(struct pdb_methods *m,
					   struct samu *sam)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct pdb_ads_samu_private *priv = pdb_ads_get_samu_private(m, sam);
	struct tldap_mod *mods = NULL;
	int rc, num_mods = 0;

	if (!pdb_ads_init_ads_from_sam(state, priv->ldapmsg, talloc_tos(),
				       &num_mods, &mods, sam)) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_modify(state->ld, priv->dn, num_mods, mods, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_modify for %s failed: %s\n", priv->dn,
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}

	TALLOC_FREE(mods);

	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_delete_sam_account(struct pdb_methods *m,
					   struct samu *username)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_rename_sam_account(struct pdb_methods *m,
					   struct samu *oldname,
					   const char *newname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_update_login_attempts(struct pdb_methods *m,
					      struct samu *sam_acct,
					      bool success)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_getgrfilter(struct pdb_methods *m, GROUP_MAP *map,
				    const char *filter)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	const char *attrs[4] = { "objectSid", "description", "samAccountName",
				 "groupType" };
	char *str;
	struct tldap_message **group;
	uint32_t grouptype;
	int rc;

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      attrs, ARRAY_SIZE(attrs), 0, talloc_tos(),
			      &group, "%s", filter);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}
	if (talloc_array_length(group) != 1) {
		DEBUG(10, ("Expected 1 user, got %d\n",
			   talloc_array_length(group)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (!tldap_pull_binsid(group[0], "objectSid", &map->sid)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	map->gid = pdb_ads_sid2gid(&map->sid);

	if (!tldap_pull_uint32(group[0], "groupType", &grouptype)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	switch (grouptype) {
	case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
	case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
		map->sid_name_use = SID_NAME_ALIAS;
		break;
	case GTYPE_SECURITY_GLOBAL_GROUP:
		map->sid_name_use = SID_NAME_DOM_GRP;
		break;
	default:
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	str = tldap_talloc_single_attribute(group[0], "samAccountName",
					    talloc_tos());
	if (str == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	fstrcpy(map->nt_name, str);
	TALLOC_FREE(str);

	str = tldap_talloc_single_attribute(group[0], "description",
					    talloc_tos());
	if (str != NULL) {
		fstrcpy(map->comment, str);
		TALLOC_FREE(str);
	} else {
		map->comment[0] = '\0';
	}

	TALLOC_FREE(group);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_getgrsid(struct pdb_methods *m, GROUP_MAP *map,
				 DOM_SID sid)
{
	char *filter;
	NTSTATUS status;

	filter = talloc_asprintf(talloc_tos(),
				 "(&(objectsid=%s)(objectclass=group))",
				 sid_string_talloc(talloc_tos(), &sid));
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_ads_getgrfilter(m, map, filter);
	TALLOC_FREE(filter);
	return status;
}

static NTSTATUS pdb_ads_getgrgid(struct pdb_methods *m, GROUP_MAP *map,
				 gid_t gid)
{
	struct dom_sid sid;
	pdb_ads_gid_to_sid(m, gid, &sid);
	return pdb_ads_getgrsid(m, map, sid);
}

static NTSTATUS pdb_ads_getgrnam(struct pdb_methods *m, GROUP_MAP *map,
				 const char *name)
{
	char *filter;
	NTSTATUS status;

	filter = talloc_asprintf(talloc_tos(),
				 "(&(samaccountname=%s)(objectclass=group))",
				 name);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_ads_getgrfilter(m, map, filter);
	TALLOC_FREE(filter);
	return status;
}

static NTSTATUS pdb_ads_create_dom_group(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx, const char *name,
					 uint32 *rid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	const char *attrs[1] = { "objectSid" };
	int num_mods = 0;
	struct tldap_mod *mods = NULL;
	struct tldap_message **alias;
	struct dom_sid sid;
	char *dn;
	int rc;
	bool ok = true;

	dn = talloc_asprintf(talloc_tos(), "cn=%s,cn=users,%s", name,
			     state->domaindn);
	if (dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "samAccountName", "%s",
		name);
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "objectClass", "group");
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "groupType",
		"%d", (int)GTYPE_SECURITY_GLOBAL_GROUP);

	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_add(state->ld, dn, num_mods, mods, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_add failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &alias,
		"(&(objectclass=group)(samaccountname=%s))", name);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not find just created alias %s: %s\n",
			   name, tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	if (talloc_array_length(alias) != 1) {
		DEBUG(10, ("Got %d alias, expected one\n",
			   (int)talloc_array_length(alias)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	if (!tldap_pull_binsid(alias[0], "objectSid", &sid)) {
		DEBUG(10, ("Could not fetch objectSid from alias %s\n",
			   name));
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	sid_peek_rid(&sid, rid);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_delete_dom_group(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx, uint32 rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_add_group_mapping_entry(struct pdb_methods *m,
						GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_update_group_mapping_entry(struct pdb_methods *m,
						   GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_delete_group_mapping_entry(struct pdb_methods *m,
						   DOM_SID sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_enum_group_mapping(struct pdb_methods *m,
					   const DOM_SID *sid,
					   enum lsa_SidType sid_name_use,
					   GROUP_MAP **pp_rmap,
					   size_t *p_num_entries,
					   bool unix_only)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_enum_group_members(struct pdb_methods *m,
					   TALLOC_CTX *mem_ctx,
					   const DOM_SID *group,
					   uint32 **pp_member_rids,
					   size_t *p_num_members)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_enum_group_memberships(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       struct samu *user,
					       DOM_SID **pp_sids,
					       gid_t **pp_gids,
					       size_t *p_num_groups)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct pdb_ads_samu_private *priv = pdb_ads_get_samu_private(
		m, user);
	const char *attrs[1] = { "objectSid" };
	struct tldap_message **groups;
	int i, rc, count;
	size_t num_groups;
	struct dom_sid *group_sids;
	gid_t *gids;

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &groups,
		"(&(member=%s)(grouptype=%d)(objectclass=group))",
		priv->dn, GTYPE_SECURITY_GLOBAL_GROUP);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}

	count = talloc_array_length(groups);

	group_sids = talloc_array(mem_ctx, struct dom_sid, count);
	if (group_sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gids = talloc_array(mem_ctx, gid_t, count);
	if (gids == NULL) {
		TALLOC_FREE(group_sids);
		return NT_STATUS_NO_MEMORY;
	}
	num_groups = 0;

	for (i=0; i<count; i++) {
		if (!tldap_pull_binsid(groups[i], "objectSid",
				       &group_sids[num_groups])) {
			continue;
		}
		gids[num_groups] = pdb_ads_sid2gid(&group_sids[num_groups]);

		num_groups += 1;
		if (num_groups == count) {
			break;
		}
	}

	*pp_sids = group_sids;
	*pp_gids = gids;
	*p_num_groups = num_groups;
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_set_unix_primary_group(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       struct samu *user)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_add_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32 group_rid, uint32 member_rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_del_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32 group_rid, uint32 member_rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_create_alias(struct pdb_methods *m,
				     const char *name, uint32 *rid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	const char *attrs[1] = { "objectSid" };
	int num_mods = 0;
	struct tldap_mod *mods = NULL;
	struct tldap_message **alias;
	struct dom_sid sid;
	char *dn;
	int rc;
	bool ok = true;

	dn = talloc_asprintf(talloc_tos(), "cn=%s,cn=users,%s", name,
			     state->domaindn);
	if (dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "samAccountName", "%s",
		name);
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "objectClass", "group");
	ok &= tldap_make_mod_fmt(
		NULL, talloc_tos(), &num_mods, &mods, "groupType",
		"%d", (int)GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_add(state->ld, dn, num_mods, mods, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_add failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &alias,
		"(&(objectclass=group)(samaccountname=%s))", name);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not find just created alias %s: %s\n",
			   name, tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	if (talloc_array_length(alias) != 1) {
		DEBUG(10, ("Got %d alias, expected one\n",
			   (int)talloc_array_length(alias)));
		TALLOC_FREE(frame);
		return NT_STATUS_LDAP(rc);
	}

	if (!tldap_pull_binsid(alias[0], "objectSid", &sid)) {
		DEBUG(10, ("Could not fetch objectSid from alias %s\n",
			   name));
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	sid_peek_rid(&sid, rid);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_delete_alias(struct pdb_methods *m,
				     const DOM_SID *sid)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct tldap_message **alias;
	char *sidstr, *dn;
	int rc;

	sidstr = sid_binstring(talloc_tos(), sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      NULL, 0, 0, talloc_tos(), &alias,
			      "(&(objectSid=%s)(objectclass=group)"
			      "(|(grouptype=%d)(grouptype=%d)))",
			      sidstr, GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
			      GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	TALLOC_FREE(sidstr);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(dn);
		return NT_STATUS_LDAP(rc);
	}
	if (talloc_array_length(alias) != 1) {
		DEBUG(10, ("Expected 1 alias, got %d\n",
			   talloc_array_length(alias)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (!tldap_entry_dn(alias[0], &dn)) {
		DEBUG(10, ("Could not get DN for alias %s\n",
			   sid_string_dbg(sid)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	rc = tldap_delete(state->ld, dn, NULL, NULL);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_delete failed: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		TALLOC_FREE(dn);
		return NT_STATUS_LDAP(rc);
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_get_aliasinfo(struct pdb_methods *m,
				      const DOM_SID *sid,
				      struct acct_info *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_set_aliasinfo(struct pdb_methods *m,
				      const DOM_SID *sid,
				      struct acct_info *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_sid2dn(struct pdb_ads_state *state,
			       const struct dom_sid *sid,
			       TALLOC_CTX *mem_ctx, char **pdn)
{
	struct tldap_message **msg;
	char *sidstr, *dn;
	int rc;

	sidstr = sid_binstring(talloc_tos(), sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      NULL, 0, 0, talloc_tos(), &msg,
			      "(objectsid=%s)", sidstr);
	TALLOC_FREE(sidstr);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}

	switch talloc_array_length(msg) {
	case 0:
		return NT_STATUS_NOT_FOUND;
	case 1:
		break;
	default:
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (!tldap_entry_dn(msg[0], &dn)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	dn = talloc_strdup(mem_ctx, dn);
	if (dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	TALLOC_FREE(msg);

	*pdn = dn;
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_mod_aliasmem(struct pdb_methods *m,
				     const DOM_SID *alias,
				     const DOM_SID *member,
				     int mod_op)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	TALLOC_CTX *frame = talloc_stackframe();
	struct tldap_mod *mods;
	int rc;
	char *aliasdn, *memberdn;
	NTSTATUS status;

	status = pdb_ads_sid2dn(state, alias, talloc_tos(), &aliasdn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_ads_sid2dn (%s) failed: %s\n",
			   sid_string_dbg(alias), nt_errstr(status)));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_SUCH_ALIAS;
	}
	status = pdb_ads_sid2dn(state, member, talloc_tos(), &memberdn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_ads_sid2dn (%s) failed: %s\n",
			   sid_string_dbg(member), nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	mods = NULL;

	if (!tldap_add_mod_str(talloc_tos(), &mods, mod_op,
			       "member", memberdn)) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	rc = tldap_modify(state->ld, aliasdn, 1, mods, NULL, NULL);
	TALLOC_FREE(frame);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_modify failed: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		if (rc == TLDAP_TYPE_OR_VALUE_EXISTS) {
			return NT_STATUS_MEMBER_IN_ALIAS;
		}
		if (rc == TLDAP_NO_SUCH_ATTRIBUTE) {
			return NT_STATUS_MEMBER_NOT_IN_ALIAS;
		}
		return NT_STATUS_LDAP(rc);
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_add_aliasmem(struct pdb_methods *m,
				     const DOM_SID *alias,
				     const DOM_SID *member)
{
	return pdb_ads_mod_aliasmem(m, alias, member, TLDAP_MOD_ADD);
}

static NTSTATUS pdb_ads_del_aliasmem(struct pdb_methods *m,
				     const DOM_SID *alias,
				     const DOM_SID *member)
{
	return pdb_ads_mod_aliasmem(m, alias, member, TLDAP_MOD_DELETE);
}

static bool pdb_ads_dnblob2sid(struct tldap_context *ld, DATA_BLOB *dnblob,
			       struct dom_sid *psid)
{
	const char *attrs[1] = { "objectSid" };
	struct tldap_message **msg;
	char *dn;
	size_t len;
	int rc;
	bool ret;

	if (!convert_string_talloc(talloc_tos(), CH_UTF8, CH_UNIX,
				   dnblob->data, dnblob->length, &dn, &len,
				   false)) {
		return false;
	}
	rc = tldap_search_fmt(ld, dn, TLDAP_SCOPE_BASE,
			      attrs, ARRAY_SIZE(attrs), 0, talloc_tos(),
			      &msg, "(objectclass=*)");
	TALLOC_FREE(dn);
	if (talloc_array_length(msg) != 1) {
		DEBUG(10, ("Got %d objects, expected one\n",
			   (int)talloc_array_length(msg)));
		TALLOC_FREE(msg);
		return false;
	}

	ret = tldap_pull_binsid(msg[0], "objectSid", psid);
	TALLOC_FREE(msg);
	return ret;
}

static NTSTATUS pdb_ads_enum_aliasmem(struct pdb_methods *m,
				      const DOM_SID *alias,
				      TALLOC_CTX *mem_ctx,
				      DOM_SID **pmembers,
				      size_t *pnum_members)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	const char *attrs[1] = { "member" };
	char *sidstr;
	struct tldap_message **msg;
	int i, rc, num_members;
	DATA_BLOB *blobs;
	struct dom_sid *members;

	sidstr = sid_binstring(talloc_tos(), alias);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	rc = tldap_search_fmt(state->ld, state->domaindn, TLDAP_SCOPE_SUB,
			      attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &msg,
			      "(objectsid=%s)", sidstr);
	TALLOC_FREE(sidstr);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return NT_STATUS_LDAP(rc);
	}
	switch talloc_array_length(msg) {
	case 0:
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		break;
	case 1:
		break;
	default:
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
		break;
	}

	if (!tldap_entry_values(msg[0], "member", &num_members, &blobs)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	members = talloc_array(mem_ctx, struct dom_sid, num_members);
	if (members == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_members; i++) {
		if (!pdb_ads_dnblob2sid(state->ld, &blobs[i], &members[i])) {
			TALLOC_FREE(members);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	*pmembers = members;
	*pnum_members = num_members;
	return NT_STATUS_OK;
}

static NTSTATUS pdb_ads_enum_alias_memberships(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       const DOM_SID *domain_sid,
					       const DOM_SID *members,
					       size_t num_members,
					       uint32 **pp_alias_rids,
					       size_t *p_num_alias_rids)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_lookup_rids(struct pdb_methods *m,
				    const DOM_SID *domain_sid,
				    int num_rids,
				    uint32 *rids,
				    const char **pp_names,
				    enum lsa_SidType *attrs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_lookup_names(struct pdb_methods *m,
				     const DOM_SID *domain_sid,
				     int num_names,
				     const char **pp_names,
				     uint32 *rids,
				     enum lsa_SidType *attrs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_ads_get_account_policy(struct pdb_methods *m,
					   int policy_index, uint32 *value)
{
	return account_policy_get(policy_index, value)
		? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_ads_set_account_policy(struct pdb_methods *m,
					   int policy_index, uint32 value)
{
	return account_policy_set(policy_index, value)
		? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_ads_get_seq_num(struct pdb_methods *m,
				    time_t *seq_num)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct pdb_ads_search_state {
	uint32_t acct_flags;
	struct samr_displayentry *entries;
	uint32_t num_entries;
	ssize_t array_size;
	uint32_t current;
};

static bool pdb_ads_next_entry(struct pdb_search *search,
			       struct samr_displayentry *entry)
{
	struct pdb_ads_search_state *state = talloc_get_type_abort(
		search->private_data, struct pdb_ads_search_state);

	if (state->current == state->num_entries) {
		return false;
	}

	entry->idx = state->entries[state->current].idx;
	entry->rid = state->entries[state->current].rid;
	entry->acct_flags = state->entries[state->current].acct_flags;

	entry->account_name = talloc_strdup(
		search, state->entries[state->current].account_name);
	entry->fullname = talloc_strdup(
		search, state->entries[state->current].fullname);
	entry->description = talloc_strdup(
		search, state->entries[state->current].description);

	if ((entry->account_name == NULL) || (entry->fullname == NULL)
	    || (entry->description == NULL)) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return false;
	}

	state->current += 1;
	return true;
}

static void pdb_ads_search_end(struct pdb_search *search)
{
	struct pdb_ads_search_state *state = talloc_get_type_abort(
		search->private_data, struct pdb_ads_search_state);
	TALLOC_FREE(state);
}

static bool pdb_ads_search_filter(struct pdb_methods *m,
				  struct pdb_search *search,
				  const char *filter,
				  struct pdb_ads_search_state **pstate)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct pdb_ads_search_state *sstate;
	const char * attrs[] = { "objectSid", "sAMAccountName", "displayName",
				 "userAccountControl", "description" };
	struct tldap_message **users;
	int i, rc, num_users;

	sstate = talloc_zero(search, struct pdb_ads_search_state);
	if (sstate == NULL) {
		return false;
	}

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		attrs, ARRAY_SIZE(attrs), 0, talloc_tos(), &users,
		"%s", filter);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("ldap_search_ext_s failed: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		return false;
	}

	num_users = talloc_array_length(users);

	sstate->entries = talloc_array(sstate, struct samr_displayentry,
				       num_users);
	if (sstate->entries == NULL) {
		DEBUG(10, ("talloc failed\n"));
		return false;
	}

	sstate->num_entries = 0;

	for (i=0; i<num_users; i++) {
		struct samr_displayentry *e;
		struct dom_sid sid;

		e = &sstate->entries[sstate->num_entries];

		e->idx = sstate->num_entries;
		if (!tldap_pull_binsid(users[i], "objectSid", &sid)) {
			DEBUG(10, ("Could not pull sid\n"));
			continue;
		}
		sid_peek_rid(&sid, &e->rid);
		e->acct_flags = ACB_NORMAL;
		e->account_name = tldap_talloc_single_attribute(
			users[i], "samAccountName", sstate->entries);
		if (e->account_name == NULL) {
			return false;
		}
		e->fullname = tldap_talloc_single_attribute(
                        users[i], "displayName", sstate->entries);
		if (e->fullname == NULL) {
			e->fullname = "";
		}
		e->description = tldap_talloc_single_attribute(
                        users[i], "description", sstate->entries);
		if (e->description == NULL) {
			e->description = "";
		}

		sstate->num_entries += 1;
		if (sstate->num_entries >= num_users) {
			break;
		}
	}

	search->private_data = sstate;
	search->next_entry = pdb_ads_next_entry;
	search->search_end = pdb_ads_search_end;
	*pstate = sstate;
	return true;
}

static bool pdb_ads_search_users(struct pdb_methods *m,
				 struct pdb_search *search,
				 uint32 acct_flags)
{
	struct pdb_ads_search_state *sstate;
	bool ret;

	ret = pdb_ads_search_filter(m, search, "(objectclass=user)", &sstate);
	if (!ret) {
		return false;
	}
	sstate->acct_flags = acct_flags;
	return true;
}

static bool pdb_ads_search_groups(struct pdb_methods *m,
				  struct pdb_search *search)
{
	struct pdb_ads_search_state *sstate;
	char *filter;
	bool ret;

	filter = talloc_asprintf(talloc_tos(),
				 "(&(grouptype=%d)(objectclass=group))",
				 GTYPE_SECURITY_GLOBAL_GROUP);
	if (filter == NULL) {
		return false;
	}
	ret = pdb_ads_search_filter(m, search, filter, &sstate);
	TALLOC_FREE(filter);
	if (!ret) {
		return false;
	}
	sstate->acct_flags = 0;
	return true;
}

static bool pdb_ads_search_aliases(struct pdb_methods *m,
				   struct pdb_search *search,
				   const DOM_SID *sid)
{
	struct pdb_ads_search_state *sstate;
	char *filter;
	bool ret;

	filter = talloc_asprintf(
		talloc_tos(), "(&(grouptype=%d)(objectclass=group))",
		sid_check_is_builtin(sid)
		? GTYPE_SECURITY_BUILTIN_LOCAL_GROUP
		: GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	if (filter == NULL) {
		return false;
	}
	ret = pdb_ads_search_filter(m, search, filter, &sstate);
	TALLOC_FREE(filter);
	if (!ret) {
		return false;
	}
	sstate->acct_flags = 0;
	return true;
}

static bool pdb_ads_uid_to_rid(struct pdb_methods *m, uid_t uid,
			       uint32 *rid)
{
	return false;
}

static bool pdb_ads_uid_to_sid(struct pdb_methods *m, uid_t uid,
			       DOM_SID *sid)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	sid_compose(sid, &state->domainsid, uid);
	return true;
}

static bool pdb_ads_gid_to_sid(struct pdb_methods *m, gid_t gid,
			       DOM_SID *sid)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	sid_compose(sid, &state->domainsid, gid);
	return true;
}

static bool pdb_ads_sid_to_id(struct pdb_methods *m, const DOM_SID *sid,
			      union unid_t *id, enum lsa_SidType *type)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_ads_state);
	struct tldap_message **msg;
	char *sidstr;
	uint32_t rid;
	int rc;

	/*
	 * This is a big, big hack: Just hard-code the rid as uid/gid.
	 */

	sid_peek_rid(sid, &rid);

	sidstr = sid_binstring(talloc_tos(), sid);
	if (sidstr == NULL) {
		return false;
	}

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		NULL, 0, 0, talloc_tos(), &msg,
		"(&(objectsid=%s)(objectclass=user))", sidstr);
	if ((rc == TLDAP_SUCCESS) && (talloc_array_length(msg) > 0)) {
		id->uid = rid;
		*type = SID_NAME_USER;
		TALLOC_FREE(sidstr);
		return true;
	}

	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_SUB,
		NULL, 0, 0, talloc_tos(), &msg,
		"(&(objectsid=%s)(objectclass=group))", sidstr);
	if ((rc == TLDAP_SUCCESS) && (talloc_array_length(msg) > 0)) {
		id->gid = rid;
		*type = SID_NAME_DOM_GRP;
		TALLOC_FREE(sidstr);
		return true;
	}

	TALLOC_FREE(sidstr);
	return false;
}

static bool pdb_ads_rid_algorithm(struct pdb_methods *m)
{
	return false;
}

static bool pdb_ads_new_rid(struct pdb_methods *m, uint32 *rid)
{
	return false;
}

static bool pdb_ads_get_trusteddom_pw(struct pdb_methods *m,
				      const char *domain, char** pwd,
				      DOM_SID *sid,
				      time_t *pass_last_set_time)
{
	return false;
}

static bool pdb_ads_set_trusteddom_pw(struct pdb_methods *m,
				      const char* domain, const char* pwd,
				      const DOM_SID *sid)
{
	return false;
}

static bool pdb_ads_del_trusteddom_pw(struct pdb_methods *m,
				      const char *domain)
{
	return false;
}

static NTSTATUS pdb_ads_enum_trusteddoms(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx,
					 uint32 *num_domains,
					 struct trustdom_info ***domains)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static void pdb_ads_init_methods(struct pdb_methods *m)
{
	m->name = "ads";
	m->getsampwnam = pdb_ads_getsampwnam;
	m->getsampwsid = pdb_ads_getsampwsid;
	m->create_user = pdb_ads_create_user;
	m->delete_user = pdb_ads_delete_user;
	m->add_sam_account = pdb_ads_add_sam_account;
	m->update_sam_account = pdb_ads_update_sam_account;
	m->delete_sam_account = pdb_ads_delete_sam_account;
	m->rename_sam_account = pdb_ads_rename_sam_account;
	m->update_login_attempts = pdb_ads_update_login_attempts;
	m->getgrsid = pdb_ads_getgrsid;
	m->getgrgid = pdb_ads_getgrgid;
	m->getgrnam = pdb_ads_getgrnam;
	m->create_dom_group = pdb_ads_create_dom_group;
	m->delete_dom_group = pdb_ads_delete_dom_group;
	m->add_group_mapping_entry = pdb_ads_add_group_mapping_entry;
	m->update_group_mapping_entry = pdb_ads_update_group_mapping_entry;
	m->delete_group_mapping_entry =	pdb_ads_delete_group_mapping_entry;
	m->enum_group_mapping = pdb_ads_enum_group_mapping;
	m->enum_group_members = pdb_ads_enum_group_members;
	m->enum_group_memberships = pdb_ads_enum_group_memberships;
	m->set_unix_primary_group = pdb_ads_set_unix_primary_group;
	m->add_groupmem = pdb_ads_add_groupmem;
	m->del_groupmem = pdb_ads_del_groupmem;
	m->create_alias = pdb_ads_create_alias;
	m->delete_alias = pdb_ads_delete_alias;
	m->get_aliasinfo = pdb_ads_get_aliasinfo;
	m->set_aliasinfo = pdb_ads_set_aliasinfo;
	m->add_aliasmem = pdb_ads_add_aliasmem;
	m->del_aliasmem = pdb_ads_del_aliasmem;
	m->enum_aliasmem = pdb_ads_enum_aliasmem;
	m->enum_alias_memberships = pdb_ads_enum_alias_memberships;
	m->lookup_rids = pdb_ads_lookup_rids;
	m->lookup_names = pdb_ads_lookup_names;
	m->get_account_policy = pdb_ads_get_account_policy;
	m->set_account_policy = pdb_ads_set_account_policy;
	m->get_seq_num = pdb_ads_get_seq_num;
	m->search_users = pdb_ads_search_users;
	m->search_groups = pdb_ads_search_groups;
	m->search_aliases = pdb_ads_search_aliases;
	m->uid_to_rid = pdb_ads_uid_to_rid;
	m->uid_to_sid = pdb_ads_uid_to_sid;
	m->gid_to_sid = pdb_ads_gid_to_sid;
	m->sid_to_id = pdb_ads_sid_to_id;
	m->rid_algorithm = pdb_ads_rid_algorithm;
	m->new_rid = pdb_ads_new_rid;
	m->get_trusteddom_pw = pdb_ads_get_trusteddom_pw;
	m->set_trusteddom_pw = pdb_ads_set_trusteddom_pw;
	m->del_trusteddom_pw = pdb_ads_del_trusteddom_pw;
	m->enum_trusteddoms = pdb_ads_enum_trusteddoms;
}

static void free_private_data(void **vp)
{
	struct pdb_ads_state *state = talloc_get_type_abort(
		*vp, struct pdb_ads_state);

	TALLOC_FREE(state->ld);
	return;
}

static NTSTATUS pdb_ads_connect(struct pdb_ads_state *state,
				const char *location)
{
	const char *rootdse_attrs[2] = {
		"defaultNamingContext", "configurationNamingContext" };
	const char *domain_attrs[1] = { "objectSid" };
	const char *ncname_attrs[1] = { "netbiosname" };
	struct tldap_message **rootdse, **domain, **ncname;
	TALLOC_CTX *frame = talloc_stackframe();
	struct sockaddr_un sunaddr;
	NTSTATUS status;
	int num_domains;
	int fd, rc;

	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, location, sizeof(sunaddr.sun_path) - 1);

	status = open_socket_out((struct sockaddr_storage *)(void *)&sunaddr,
				 0, 0, &fd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Could not connect to %s: %s\n", location,
			   nt_errstr(status)));
		goto done;
	}

	state->ld = tldap_context_create(state, fd);
	if (state->ld == NULL) {
		close(fd);
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	rc = tldap_search_fmt(
		state->ld, "", TLDAP_SCOPE_BASE,
		rootdse_attrs, ARRAY_SIZE(rootdse_attrs), 0,
		talloc_tos(), &rootdse, "(objectclass=*)");
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not retrieve rootdse: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		status = NT_STATUS_LDAP(rc);
		goto done;
	}
	if (talloc_array_length(rootdse) != 1) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	state->domaindn = tldap_talloc_single_attribute(
		rootdse[0], "defaultNamingContext", state);
	if (state->domaindn == NULL) {
		DEBUG(10, ("Could not get defaultNamingContext\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}
	DEBUG(10, ("defaultNamingContext = %s\n", state->domaindn));

	state->configdn = tldap_talloc_single_attribute(
		rootdse[0], "configurationNamingContext", state);
	if (state->domaindn == NULL) {
		DEBUG(10, ("Could not get configurationNamingContext\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}
	DEBUG(10, ("configurationNamingContext = %s\n", state->configdn));

	/*
	 * Figure out our domain's SID
	 */
	rc = tldap_search_fmt(
		state->ld, state->domaindn, TLDAP_SCOPE_BASE,
		domain_attrs, ARRAY_SIZE(domain_attrs), 0,
		talloc_tos(), &domain, "(objectclass=*)");
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not retrieve domain: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		status = NT_STATUS_LDAP(rc);
		goto done;
	}

	num_domains = talloc_array_length(domain);
	if (num_domains != 1) {
		DEBUG(10, ("Got %d domains, expected one\n", num_domains));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}
	if (!tldap_pull_binsid(domain[0], "objectSid", &state->domainsid)) {
		DEBUG(10, ("Could not retrieve domain SID\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}
	DEBUG(10, ("Domain SID: %s\n", sid_string_dbg(&state->domainsid)));

	/*
	 * Figure out our domain's short name
	 */
	rc = tldap_search_fmt(
		state->ld, state->configdn, TLDAP_SCOPE_SUB,
		ncname_attrs, ARRAY_SIZE(ncname_attrs), 0,
		talloc_tos(), &ncname, "(ncname=%s)", state->domaindn);
	if (rc != TLDAP_SUCCESS) {
		DEBUG(10, ("Could not retrieve ncname: %s\n",
			   tldap_errstr(debug_ctx(), state->ld, rc)));
		status = NT_STATUS_LDAP(rc);
		goto done;
	}
	if (talloc_array_length(ncname) != 1) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	state->netbiosname = tldap_talloc_single_attribute(
		ncname[0], "netbiosname", state);
	if (state->netbiosname == NULL) {
		DEBUG(10, ("Could not get netbiosname\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}
	DEBUG(10, ("netbiosname: %s\n", state->netbiosname));

	if (!strequal(lp_workgroup(), state->netbiosname)) {
		DEBUG(1, ("ADS is different domain (%s) than ours (%s)\n",
			  state->netbiosname, lp_workgroup()));
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto done;
	}

	secrets_store_domain_sid(state->netbiosname, &state->domainsid);

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS pdb_init_ads(struct pdb_methods **pdb_method,
			     const char *location)
{
	struct pdb_methods *m;
	struct pdb_ads_state *state;
	char *tmp = NULL;
	NTSTATUS status;

	m = talloc(talloc_autofree_context(), struct pdb_methods);
	if (m == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state = talloc(m, struct pdb_ads_state);
	if (state == NULL) {
		goto nomem;
	}
	m->private_data = state;
	m->free_private_data = free_private_data;
	pdb_ads_init_methods(m);

	if (location == NULL) {
		tmp = talloc_asprintf(talloc_tos(), "/%s/ldap_priv/ldapi",
				      lp_private_dir());
		location = tmp;
	}
	if (location == NULL) {
		goto nomem;
	}

	status = pdb_ads_connect(state, location);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_ads_connect failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	*pdb_method = m;
	return NT_STATUS_OK;
nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	TALLOC_FREE(m);
	return status;
}

NTSTATUS pdb_ads_init(void);
NTSTATUS pdb_ads_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "ads",
				   pdb_init_ads);
}

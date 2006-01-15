/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Jelmer Vernooij			2002
   Copyright (C) Simo Sorce				2003

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

static struct pdb_init_function_entry *backends = NULL;

static void lazy_initialize_passdb(void)
{
	static BOOL initialized = False;
	if(initialized)return;
	static_init_pdb;
	initialized = True;
}

static struct pdb_init_function_entry *pdb_find_backend_entry(const char *name);
static BOOL lookup_global_sam_rid(TALLOC_CTX *mem_ctx, uint32 rid,
				  const char **name,
				  enum SID_NAME_USE *psid_name_use,
				  union unid_t *unix_id);
/*******************************************************************
 Clean up uninitialised passwords.  The only way to tell 
 that these values are not 'real' is that they do not
 have a valid last set time.  Instead, the value is fixed at 0. 
 Therefore we use that as the key for 'is this a valid password'.
 However, it is perfectly valid to have a 'default' last change
 time, such LDAP with a missing attribute would produce.
********************************************************************/

static void pdb_force_pw_initialization(SAM_ACCOUNT *pass) 
{
	const uint8 *lm_pwd, *nt_pwd;
	
	/* only reset a password if the last set time has been 
	   explicitly been set to zero.  A default last set time 
	   is ignored */

	if ( (pdb_get_init_flags(pass, PDB_PASSLASTSET) != PDB_DEFAULT) 
		&& (pdb_get_pass_last_set_time(pass) == 0) ) 
	{
		
		if (pdb_get_init_flags(pass, PDB_LMPASSWD) != PDB_DEFAULT) 
		{
			lm_pwd = pdb_get_lanman_passwd(pass);
			if (lm_pwd) 
				pdb_set_lanman_passwd(pass, NULL, PDB_CHANGED);
		}
		if (pdb_get_init_flags(pass, PDB_NTPASSWD) != PDB_DEFAULT) 
		{
			nt_pwd = pdb_get_nt_passwd(pass);
			if (nt_pwd) 
				pdb_set_nt_passwd(pass, NULL, PDB_CHANGED);
		}
	}

	return;
}

NTSTATUS smb_register_passdb(int version, const char *name, pdb_init_function init) 
{
	struct pdb_init_function_entry *entry = backends;

	if(version != PASSDB_INTERFACE_VERSION) {
		DEBUG(0,("Can't register passdb backend!\n"
			 "You tried to register a passdb module with PASSDB_INTERFACE_VERSION %d, "
			 "while this version of samba uses version %d\n", 
			 version,PASSDB_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!name || !init) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Attempting to register passdb backend %s\n", name));

	/* Check for duplicates */
	if (pdb_find_backend_entry(name)) {
		DEBUG(0,("There already is a passdb backend registered with the name %s!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = SMB_XMALLOC_P(struct pdb_init_function_entry);
	entry->name = smb_xstrdup(name);
	entry->init = init;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added passdb backend '%s'\n", name));
	return NT_STATUS_OK;
}

static struct pdb_init_function_entry *pdb_find_backend_entry(const char *name)
{
	struct pdb_init_function_entry *entry = backends;

	while(entry) {
		if (strcmp(entry->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

static NTSTATUS context_setsampwent(struct pdb_context *context, BOOL update, uint16 acb_mask)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	context->pwent_methods = context->pdb_methods;

	if (!context->pwent_methods) {
		/* No passdbs at all */
		return ret;
	}

	while (NT_STATUS_IS_ERR(ret = context->pwent_methods->setsampwent(context->pwent_methods, update, acb_mask))) {
		context->pwent_methods = context->pwent_methods->next;
		if (context->pwent_methods == NULL) 
			return NT_STATUS_UNSUCCESSFUL;
	}
	return ret;
}

static void context_endsampwent(struct pdb_context *context)
{
	if ((!context)){
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return;
	}

	if (context->pwent_methods && context->pwent_methods->endsampwent)
		context->pwent_methods->endsampwent(context->pwent_methods);

	/* So we won't get strange data when calling getsampwent now */
	context->pwent_methods = NULL;
}

static NTSTATUS context_getsampwent(struct pdb_context *context, SAM_ACCOUNT *user)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pwent_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	/* Loop until we find something useful */
	while (NT_STATUS_IS_ERR(ret = context->pwent_methods->getsampwent(context->pwent_methods, user))) {

		context->pwent_methods->endsampwent(context->pwent_methods);

		context->pwent_methods = context->pwent_methods->next;

		/* All methods are checked now. There are no more entries */
		if (context->pwent_methods == NULL)
			return ret;
	
		context->pwent_methods->setsampwent(context->pwent_methods, False, 0);
	}
	user->methods = context->pwent_methods;
	pdb_force_pw_initialization(user);
	return ret;
}

static NTSTATUS context_getsampwnam(struct pdb_context *context, SAM_ACCOUNT *sam_acct, const char *username)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		if (NT_STATUS_IS_OK(ret = curmethods->getsampwnam(curmethods, sam_acct, username))) {
			pdb_force_pw_initialization(sam_acct);
			sam_acct->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_getsampwsid(struct pdb_context *context, SAM_ACCOUNT *sam_acct, const DOM_SID *sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	
	curmethods = context->pdb_methods;

	while (curmethods){
		if (NT_STATUS_IS_OK(ret = curmethods->getsampwsid(curmethods, sam_acct, sid))) {
			pdb_force_pw_initialization(sam_acct);
			sam_acct->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_add_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	const uint8 *lm_pw, *nt_pw;
	uint16 acb_flags;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	/* disable acccounts with no passwords (that has not 
	   been allowed by the  ACB_PWNOTREQ bit */
	
	lm_pw = pdb_get_lanman_passwd( sam_acct );
	nt_pw = pdb_get_nt_passwd( sam_acct );
	acb_flags = pdb_get_acct_ctrl( sam_acct );
	if ( !lm_pw && !nt_pw && !(acb_flags&ACB_PWNOTREQ) ) {
		acb_flags |= ACB_DISABLED;
		pdb_set_acct_ctrl( sam_acct, acb_flags, PDB_CHANGED );
	}
	
	/** @todo  This is where a 're-read on add' should be done */
	/* We now add a new account to the first database listed. 
	 * Should we? */

	return context->pdb_methods->add_sam_account(context->pdb_methods, sam_acct);
}

static NTSTATUS context_update_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	const uint8 *lm_pw, *nt_pw;
	uint16 acb_flags;

	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	if (!sam_acct || !sam_acct->methods){
		DEBUG(0, ("invalid sam_acct specified\n"));
		return ret;
	}

	/* disable acccounts with no passwords (that has not 
	   been allowed by the  ACB_PWNOTREQ bit */
	
	lm_pw = pdb_get_lanman_passwd( sam_acct );
	nt_pw = pdb_get_nt_passwd( sam_acct );
	acb_flags = pdb_get_acct_ctrl( sam_acct );
	if ( !lm_pw && !nt_pw && !(acb_flags&ACB_PWNOTREQ) ) {
		acb_flags |= ACB_DISABLED;
		pdb_set_acct_ctrl( sam_acct, acb_flags, PDB_CHANGED );
	}
	
	/** @todo  This is where a 're-read on update' should be done */

	return sam_acct->methods->update_sam_account(sam_acct->methods, sam_acct);
}

static NTSTATUS context_delete_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *pdb_selected;
	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	if (!sam_acct->methods){
		pdb_selected = context->pdb_methods;
		/* There's no passdb backend specified for this account.
		 * Try to delete it in every passdb available 
		 * Needed to delete accounts in smbpasswd that are not
		 * in /etc/passwd.
		 */
		while (pdb_selected){
			if (NT_STATUS_IS_OK(ret = pdb_selected->delete_sam_account(pdb_selected, sam_acct))) {
				return ret;
			}
			pdb_selected = pdb_selected->next;
		}
		return ret;
	}

	if (!sam_acct->methods->delete_sam_account){
		DEBUG(0,("invalid sam_acct->methods->delete_sam_account\n"));
		return ret;
	}
	
	return sam_acct->methods->delete_sam_account(sam_acct->methods, sam_acct);
}

static NTSTATUS context_rename_sam_account(struct pdb_context *context, SAM_ACCOUNT *oldname, const char *newname)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *pdb_selected;
	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	if (!oldname->methods){
		pdb_selected = context->pdb_methods;
		/* There's no passdb backend specified for this account.
		 * Try to delete it in every passdb available 
		 * Needed to delete accounts in smbpasswd that are not
		 * in /etc/passwd.
		 */
		while (pdb_selected){
			if (NT_STATUS_IS_OK(ret = pdb_selected->rename_sam_account(pdb_selected, oldname, newname))) {
				return ret;
			}
			pdb_selected = pdb_selected->next;
		}
		return ret;
	}

	if (!oldname->methods->rename_sam_account){
		DEBUG(0,("invalid oldname->methods->rename_sam_account\n"));
		return ret;
	}
	
	return oldname->methods->rename_sam_account(oldname->methods, oldname, newname);
}


static NTSTATUS context_update_login_attempts(struct pdb_context *context,
						SAM_ACCOUNT *sam_acct, BOOL success)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	if (!sam_acct || !sam_acct->methods){
		DEBUG(0, ("invalid sam_acct specified\n"));
		return ret;
	}

	return sam_acct->methods->update_login_attempts(sam_acct->methods, sam_acct, success);
}

static NTSTATUS context_getgrsid(struct pdb_context *context,
				 GROUP_MAP *map, DOM_SID sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrsid(curmethods, map, sid);
		if (NT_STATUS_IS_OK(ret)) {
			map->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_getgrgid(struct pdb_context *context,
				 GROUP_MAP *map, gid_t gid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrgid(curmethods, map, gid);
		if (NT_STATUS_IS_OK(ret)) {
			map->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_getgrnam(struct pdb_context *context,
				 GROUP_MAP *map, const char *name)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrnam(curmethods, map, name);
		if (NT_STATUS_IS_OK(ret)) {
			map->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_add_group_mapping_entry(struct pdb_context *context,
						GROUP_MAP *map)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->add_group_mapping_entry(context->pdb_methods,
							     map);
}

static NTSTATUS context_update_group_mapping_entry(struct pdb_context *context,
						   GROUP_MAP *map)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->
		pdb_methods->update_group_mapping_entry(context->pdb_methods, map);
}

static NTSTATUS context_delete_group_mapping_entry(struct pdb_context *context,
						   DOM_SID sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->
		pdb_methods->delete_group_mapping_entry(context->pdb_methods, sid);
}

static NTSTATUS context_enum_group_mapping(struct pdb_context *context,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **pp_rmap, size_t *p_num_entries,
					   BOOL unix_only)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_group_mapping(context->pdb_methods,
							sid_name_use, pp_rmap,
							p_num_entries, unix_only);
}

static NTSTATUS context_enum_group_members(struct pdb_context *context,
					   TALLOC_CTX *mem_ctx,
					   const DOM_SID *group,
					   uint32 **pp_member_rids,
					   size_t *p_num_members)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_group_members(context->pdb_methods,
							mem_ctx, group,
							pp_member_rids,
							p_num_members);
}

static NTSTATUS context_enum_group_memberships(struct pdb_context *context,
					       TALLOC_CTX *mem_ctx,
					       SAM_ACCOUNT *user,
					       DOM_SID **pp_sids,
					       gid_t **pp_gids,
					       size_t *p_num_groups)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->
		enum_group_memberships(context->pdb_methods, mem_ctx, user,
				       pp_sids, pp_gids, p_num_groups);
}

static NTSTATUS context_find_alias(struct pdb_context *context,
				   const char *name, DOM_SID *sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->find_alias(context->pdb_methods,
						name, sid);
}

static NTSTATUS context_create_alias(struct pdb_context *context,
				     const char *name, uint32 *rid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->create_alias(context->pdb_methods,
						  name, rid);
}

static NTSTATUS context_delete_alias(struct pdb_context *context,
				     const DOM_SID *sid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->delete_alias(context->pdb_methods, sid);
}

static NTSTATUS context_get_aliasinfo(struct pdb_context *context,
				      const DOM_SID *sid,
				      struct acct_info *info)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->get_aliasinfo(context->pdb_methods,
						   sid, info);
}

static NTSTATUS context_set_aliasinfo(struct pdb_context *context,
				      const DOM_SID *sid,
				      struct acct_info *info)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->set_aliasinfo(context->pdb_methods,
						   sid, info);
}

static NTSTATUS context_add_aliasmem(struct pdb_context *context,
				     const DOM_SID *alias,
				     const DOM_SID *member)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->add_aliasmem(context->pdb_methods,
						  alias, member);
}
	
static NTSTATUS context_del_aliasmem(struct pdb_context *context,
				     const DOM_SID *alias,
				     const DOM_SID *member)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->del_aliasmem(context->pdb_methods,
						  alias, member);
}
	
static NTSTATUS context_enum_aliasmem(struct pdb_context *context,
				      const DOM_SID *alias, DOM_SID **pp_members,
				      size_t *p_num)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_aliasmem(context->pdb_methods,
						   alias, pp_members, p_num);
}
	
static NTSTATUS context_enum_alias_memberships(struct pdb_context *context,
					       TALLOC_CTX *mem_ctx,
					       const DOM_SID *domain_sid,
					       const DOM_SID *members,
					       size_t num_members,
					       uint32 **pp_alias_rids,
					       size_t *p_num_alias_rids)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->
		enum_alias_memberships(context->pdb_methods, mem_ctx,
				       domain_sid, members, num_members,
				       pp_alias_rids, p_num_alias_rids);
}

static NTSTATUS context_lookup_rids(struct pdb_context *context,
				    const DOM_SID *domain_sid,
				    size_t num_rids,
				    uint32 *rids,
				    const char **pp_names,
				    uint32 *pp_attrs)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->lookup_rids(context->pdb_methods,
						 domain_sid, num_rids,
						 rids, pp_names, pp_attrs);
}

static NTSTATUS context_lookup_names(struct pdb_context *context,
				     const DOM_SID *domain_sid,
				     size_t num_names,
				     const char **pp_names,
				     uint32 *rids,
				     uint32 *pp_attrs)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->lookup_names(context->pdb_methods,
						  domain_sid, num_names,
						  pp_names, rids, pp_attrs);
}

static NTSTATUS context_get_account_policy(struct pdb_context *context,
					   int policy_index, uint32 *value)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->get_account_policy(context->pdb_methods,
							policy_index, value);
}

static NTSTATUS context_set_account_policy(struct pdb_context *context,
					   int policy_index, uint32 value)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->set_account_policy(context->pdb_methods,
							policy_index, value);
}

static NTSTATUS context_get_seq_num(struct pdb_context *context, time_t *seq_num)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->get_seq_num(context->pdb_methods, seq_num);
}

static BOOL context_uid_to_rid(struct pdb_context *context, uid_t uid,
			       uint32 *rid)
{
	if ((context == NULL) || (context->pdb_methods == NULL)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->uid_to_rid(context->pdb_methods, uid,
						rid);
}
	
static BOOL context_gid_to_sid(struct pdb_context *context, gid_t gid,
			       DOM_SID *sid)
{
	if ((context == NULL) || (context->pdb_methods == NULL)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->gid_to_sid(context->pdb_methods, gid,
						sid);
}

static BOOL context_sid_to_id(struct pdb_context *context,
			      const DOM_SID *sid,
			      union unid_t *id, enum SID_NAME_USE *type)
{
	if ((context == NULL) || (context->pdb_methods == NULL)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->sid_to_id(context->pdb_methods, sid,
					       id, type);
}
	
static BOOL context_rid_algorithm(struct pdb_context *context)
{
	if ((context == NULL) || (context->pdb_methods == NULL)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->rid_algorithm(context->pdb_methods);
}
	
static BOOL context_new_rid(struct pdb_context *context, uint32 *rid)
{
	if ((context == NULL) || (context->pdb_methods == NULL)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->new_rid(context->pdb_methods, rid);
}
	
/******************************************************************
  Free and cleanup a pdb context, any associated data and anything
  that the attached modules might have associated.
 *******************************************************************/

static void free_pdb_context(struct pdb_context **context)
{
	struct pdb_methods *pdb_selected = (*context)->pdb_methods;

	while (pdb_selected){
		if(pdb_selected->free_private_data)
			pdb_selected->free_private_data(&(pdb_selected->private_data));
		pdb_selected = pdb_selected->next;
	}

	talloc_destroy((*context)->mem_ctx);
	*context = NULL;
}

static BOOL context_search_users(struct pdb_context *context,
				 struct pdb_search *search, uint16 acct_flags)
{
	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->search_users(context->pdb_methods,
						  search, acct_flags);
}

static BOOL context_search_groups(struct pdb_context *context,
				  struct pdb_search *search)
{
	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->search_groups(context->pdb_methods,
						   search);
}

static BOOL context_search_aliases(struct pdb_context *context,
				   struct pdb_search *search,
				   const DOM_SID *sid)
{
	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	return context->pdb_methods->search_aliases(context->pdb_methods,
						    search, sid);
}

/******************************************************************
  Make a pdb_methods from scratch
 *******************************************************************/

static NTSTATUS make_pdb_methods_name(struct pdb_methods **methods, struct pdb_context *context, const char *selected)
{
	char *module_name = smb_xstrdup(selected);
	char *module_location = NULL, *p;
	struct pdb_init_function_entry *entry;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	lazy_initialize_passdb();

	p = strchr(module_name, ':');

	if (p) {
		*p = 0;
		module_location = p+1;
		trim_char(module_location, ' ', ' ');
	}

	trim_char(module_name, ' ', ' ');


	DEBUG(5,("Attempting to find an passdb backend to match %s (%s)\n", selected, module_name));

	entry = pdb_find_backend_entry(module_name);
	
	/* Try to find a module that contains this module */
	if (!entry) { 
		DEBUG(2,("No builtin backend found, trying to load plugin\n"));
		if(NT_STATUS_IS_OK(smb_probe_module("pdb", module_name)) && !(entry = pdb_find_backend_entry(module_name))) {
			DEBUG(0,("Plugin is available, but doesn't register passdb backend %s\n", module_name));
			SAFE_FREE(module_name);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	
	/* No such backend found */
	if(!entry) { 
		DEBUG(0,("No builtin nor plugin backend for %s found\n", module_name));
		SAFE_FREE(module_name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Found pdb backend %s\n", module_name));
	nt_status = entry->init(context, methods, module_location);
	if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5,("pdb backend %s has a valid init\n", selected));
	} else {
		DEBUG(0,("pdb backend %s did not correctly init (error was %s)\n", selected, nt_errstr(nt_status)));
	}
	SAFE_FREE(module_name);
	return nt_status;
}

/******************************************************************
  Make a pdb_context from scratch.
 *******************************************************************/

static NTSTATUS make_pdb_context(struct pdb_context **context) 
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("pdb_context internal allocation context");

	if (!mem_ctx) {
		DEBUG(0, ("make_pdb_context: talloc init failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}		

	*context = TALLOC_P(mem_ctx, struct pdb_context);
	if (!*context) {
		DEBUG(0, ("make_pdb_context: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*context);

	(*context)->mem_ctx = mem_ctx;

	(*context)->pdb_setsampwent = context_setsampwent;
	(*context)->pdb_endsampwent = context_endsampwent;
	(*context)->pdb_getsampwent = context_getsampwent;
	(*context)->pdb_getsampwnam = context_getsampwnam;
	(*context)->pdb_getsampwsid = context_getsampwsid;
	(*context)->pdb_add_sam_account = context_add_sam_account;
	(*context)->pdb_update_sam_account = context_update_sam_account;
	(*context)->pdb_delete_sam_account = context_delete_sam_account;
	(*context)->pdb_rename_sam_account = context_rename_sam_account;
	(*context)->pdb_update_login_attempts = context_update_login_attempts;
	(*context)->pdb_getgrsid = context_getgrsid;
	(*context)->pdb_getgrgid = context_getgrgid;
	(*context)->pdb_getgrnam = context_getgrnam;
	(*context)->pdb_add_group_mapping_entry = context_add_group_mapping_entry;
	(*context)->pdb_update_group_mapping_entry = context_update_group_mapping_entry;
	(*context)->pdb_delete_group_mapping_entry = context_delete_group_mapping_entry;
	(*context)->pdb_enum_group_mapping = context_enum_group_mapping;
	(*context)->pdb_enum_group_members = context_enum_group_members;
	(*context)->pdb_enum_group_memberships = context_enum_group_memberships;

	(*context)->pdb_find_alias = context_find_alias;
	(*context)->pdb_create_alias = context_create_alias;
	(*context)->pdb_delete_alias = context_delete_alias;
	(*context)->pdb_get_aliasinfo = context_get_aliasinfo;
	(*context)->pdb_set_aliasinfo = context_set_aliasinfo;
	(*context)->pdb_add_aliasmem = context_add_aliasmem;
	(*context)->pdb_del_aliasmem = context_del_aliasmem;
	(*context)->pdb_enum_aliasmem = context_enum_aliasmem;
	(*context)->pdb_enum_alias_memberships = context_enum_alias_memberships;
	(*context)->pdb_lookup_rids = context_lookup_rids;
	(*context)->pdb_lookup_names = context_lookup_names;

	(*context)->pdb_get_account_policy = context_get_account_policy;
	(*context)->pdb_set_account_policy = context_set_account_policy;

	(*context)->pdb_get_seq_num = context_get_seq_num;

	(*context)->pdb_search_users = context_search_users;
	(*context)->pdb_search_groups = context_search_groups;
	(*context)->pdb_search_aliases = context_search_aliases;

	(*context)->pdb_uid_to_rid = context_uid_to_rid;
	(*context)->pdb_gid_to_sid = context_gid_to_sid;
	(*context)->pdb_sid_to_id = context_sid_to_id;

	(*context)->pdb_rid_algorithm = context_rid_algorithm;
	(*context)->pdb_new_rid = context_new_rid;

	(*context)->free_fn = free_pdb_context;

	return NT_STATUS_OK;
}


/******************************************************************
  Make a pdb_context, given an array of strings
 *******************************************************************/

NTSTATUS make_pdb_context_list(struct pdb_context **context, const char **selected) 
{
	int i = 0;
	struct pdb_methods *curmethods, *tmpmethods;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	BOOL have_guest = False;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_context(context))) {
		return nt_status;
	}

	if (!selected) {
		DEBUG(0, ("ERROR: empty passdb backend list!\n"));
		return nt_status;
	}

	while (selected[i]){
		if (strcmp(selected[i], "guest") == 0) {
			have_guest = True;
		}
		/* Try to initialise pdb */
		DEBUG(5,("Trying to load: %s\n", selected[i]));
		if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods_name(&curmethods, *context, selected[i]))) {
			DEBUG(1, ("Loading %s failed!\n", selected[i]));
			free_pdb_context(context);
			return nt_status;
		}
		curmethods->parent = *context;
		DLIST_ADD_END((*context)->pdb_methods, curmethods, tmpmethods);
		i++;
	}

	if (have_guest)
		return NT_STATUS_OK;

	if ( (lp_guestaccount() == NULL) ||
	     (*lp_guestaccount() == '\0') ) {
		/* We explicitly don't want guest access. No idea what
		   else that breaks, but be it that way. */
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods_name(&curmethods,
							       *context,
							       "guest"))) {
		DEBUG(1, ("Loading guest module failed!\n"));
		free_pdb_context(context);
		return nt_status;
	}

	curmethods->parent = *context;
	DLIST_ADD_END((*context)->pdb_methods, curmethods, tmpmethods);
	
	return NT_STATUS_OK;
}

/******************************************************************
  Make a pdb_context, given a text string.
 *******************************************************************/

NTSTATUS make_pdb_context_string(struct pdb_context **context, const char *selected) 
{
	NTSTATUS ret;
	char **newsel = str_list_make(selected, NULL);
	ret = make_pdb_context_list(context, (const char **)newsel);
	str_list_free(&newsel);
	return ret;
}

/******************************************************************
 Return an already initialised pdb_context, to facilitate backward 
 compatibility (see functions below).
*******************************************************************/

static struct pdb_context *pdb_get_static_context(BOOL reload) 
{
	static struct pdb_context *pdb_context = NULL;

	if ((pdb_context) && (reload)) {
		pdb_context->free_fn(&pdb_context);
		if (!NT_STATUS_IS_OK(make_pdb_context_list(&pdb_context, lp_passdb_backend()))) {
			return NULL;
		}
	}

	if (!pdb_context) {
		if (!NT_STATUS_IS_OK(make_pdb_context_list(&pdb_context, lp_passdb_backend()))) {
			return NULL;
		}
	}

	return pdb_context;
}

/******************************************************************
 Backward compatibility functions for the original passdb interface
*******************************************************************/

BOOL pdb_setsampwent(BOOL update, uint16 acb_mask) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_setsampwent(pdb_context, update, acb_mask));
}

void pdb_endsampwent(void) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return;
	}

	pdb_context->pdb_endsampwent(pdb_context);
}

BOOL pdb_getsampwent(SAM_ACCOUNT *user) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_getsampwent(pdb_context, user));
}

static SAM_ACCOUNT *sam_account_cache = NULL;

BOOL pdb_getsampwnam(SAM_ACCOUNT *sam_acct, const char *username) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	if (!NT_STATUS_IS_OK(pdb_context->pdb_getsampwnam(pdb_context,
							  sam_acct, username)))
		return False;

	if (sam_account_cache != NULL) {
		pdb_free_sam(&sam_account_cache);
		sam_account_cache = NULL;
	}

	pdb_copy_sam_account(sam_acct, &sam_account_cache);
	return True;
}

BOOL pdb_getsampwsid(SAM_ACCOUNT *sam_acct, const DOM_SID *sid) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	if ((sam_account_cache != NULL) &&
	    (sid_equal(sid, pdb_get_user_sid(sam_account_cache))))
		return pdb_copy_sam_account(sam_account_cache, &sam_acct);

	return NT_STATUS_IS_OK(pdb_context->pdb_getsampwsid(pdb_context, sam_acct, sid));
}

BOOL pdb_add_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}
	
	return NT_STATUS_IS_OK(pdb_context->pdb_add_sam_account(pdb_context, sam_acct));
}

BOOL pdb_update_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	if (sam_account_cache != NULL) {
		pdb_free_sam(&sam_account_cache);
		sam_account_cache = NULL;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_update_sam_account(pdb_context, sam_acct));
}

BOOL pdb_delete_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	if (sam_account_cache != NULL) {
		pdb_free_sam(&sam_account_cache);
		sam_account_cache = NULL;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_delete_sam_account(pdb_context, sam_acct));
}

NTSTATUS pdb_rename_sam_account(SAM_ACCOUNT *oldname, const char *newname)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (sam_account_cache != NULL) {
		pdb_free_sam(&sam_account_cache);
		sam_account_cache = NULL;
	}

	return pdb_context->pdb_rename_sam_account(pdb_context, oldname, newname);
}

NTSTATUS pdb_update_login_attempts(SAM_ACCOUNT *sam_acct, BOOL success)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return pdb_context->pdb_update_login_attempts(pdb_context, sam_acct, success);
}

BOOL pdb_getgrsid(GROUP_MAP *map, DOM_SID sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrsid(pdb_context, map, sid));
}

BOOL pdb_getgrgid(GROUP_MAP *map, gid_t gid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrgid(pdb_context, map, gid));
}

BOOL pdb_getgrnam(GROUP_MAP *map, const char *name)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrnam(pdb_context, map, name));
}

BOOL pdb_add_group_mapping_entry(GROUP_MAP *map)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_add_group_mapping_entry(pdb_context, map));
}

BOOL pdb_update_group_mapping_entry(GROUP_MAP *map)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_update_group_mapping_entry(pdb_context, map));
}

BOOL pdb_delete_group_mapping_entry(DOM_SID sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_delete_group_mapping_entry(pdb_context, sid));
}

BOOL pdb_enum_group_mapping(enum SID_NAME_USE sid_name_use, GROUP_MAP **pp_rmap,
			    size_t *p_num_entries, BOOL unix_only)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_group_mapping(pdb_context, sid_name_use,
						      pp_rmap, p_num_entries, unix_only));
}

NTSTATUS pdb_enum_group_members(TALLOC_CTX *mem_ctx,
				const DOM_SID *sid,
				uint32 **pp_member_rids,
				size_t *p_num_members)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return pdb_context->pdb_enum_group_members(pdb_context, mem_ctx, sid, 
						   pp_member_rids, p_num_members);
}

NTSTATUS pdb_enum_group_memberships(TALLOC_CTX *mem_ctx, SAM_ACCOUNT *user,
				    DOM_SID **pp_sids, gid_t **pp_gids,
				    size_t *p_num_groups)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return pdb_context->pdb_enum_group_memberships(
		pdb_context, mem_ctx, user,
		pp_sids, pp_gids, p_num_groups);
}

BOOL pdb_find_alias(const char *name, DOM_SID *sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_find_alias(pdb_context,
							     name, sid));
}

NTSTATUS pdb_create_alias(const char *name, uint32 *rid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return pdb_context->pdb_create_alias(pdb_context, name, rid);
}

BOOL pdb_delete_alias(const DOM_SID *sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_delete_alias(pdb_context,
							     sid));
							    
}

BOOL pdb_get_aliasinfo(const DOM_SID *sid, struct acct_info *info)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_get_aliasinfo(pdb_context, sid,
							      info));
}

BOOL pdb_set_aliasinfo(const DOM_SID *sid, struct acct_info *info)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_set_aliasinfo(pdb_context, sid,
							      info));
}

BOOL pdb_add_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_add_aliasmem(pdb_context, alias, member));
}

BOOL pdb_del_aliasmem(const DOM_SID *alias, const DOM_SID *member)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_del_aliasmem(pdb_context, alias, member));
}

BOOL pdb_enum_aliasmem(const DOM_SID *alias,
		       DOM_SID **pp_members, size_t *p_num_members)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_aliasmem(pdb_context, alias,
						 pp_members, p_num_members));
}

NTSTATUS pdb_enum_alias_memberships(TALLOC_CTX *mem_ctx,
				    const DOM_SID *domain_sid,
				    const DOM_SID *members, size_t num_members,
				    uint32 **pp_alias_rids,
				    size_t *p_num_alias_rids)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return pdb_context->pdb_enum_alias_memberships(pdb_context, mem_ctx,
						       domain_sid,
						       members, num_members,
						       pp_alias_rids,
						       p_num_alias_rids);
}

NTSTATUS pdb_lookup_rids(const DOM_SID *domain_sid,
			 int num_rids,
			 uint32 *rids,
			 const char **names,
			 uint32 *attrs)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return pdb_context->pdb_lookup_rids(pdb_context, domain_sid,
					    num_rids, rids, names, attrs);
}

NTSTATUS pdb_lookup_names(const DOM_SID *domain_sid,
			  int num_names,
			  const char **names,
			  uint32 *rids,
			  uint32 *attrs)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return pdb_context->pdb_lookup_names(pdb_context, domain_sid,
					     num_names, names, rids, attrs);
}

BOOL pdb_get_account_policy(int policy_index, uint32 *value)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_get_account_policy(pdb_context, policy_index, value));
}

BOOL pdb_set_account_policy(int policy_index, uint32 value)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_set_account_policy(pdb_context, policy_index, value));
}

BOOL pdb_get_seq_num(time_t *seq_num)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_get_seq_num(pdb_context, seq_num));
}

BOOL pdb_uid_to_rid(uid_t uid, uint32 *rid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_uid_to_rid(pdb_context, uid, rid);
}

BOOL pdb_gid_to_sid(gid_t gid, DOM_SID *sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_gid_to_sid(pdb_context, gid, sid);
}

BOOL pdb_sid_to_id(const DOM_SID *sid, union unid_t *id,
		   enum SID_NAME_USE *type)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_sid_to_id(pdb_context, sid, id, type);
}

BOOL pdb_rid_algorithm(void)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_rid_algorithm(pdb_context);
}

BOOL pdb_new_rid(uint32 *rid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	if (pdb_rid_algorithm()) {
		DEBUG(0, ("Trying to allocate a RID when algorithmic RIDs "
			  "are active\n"));
		return False;
	}

	if (algorithmic_rid_base() != BASE_RID) {
		DEBUG(0, ("'algorithmic rid base' is set but a passdb backend "
			  "without algorithmic RIDs is chosen.\n"));
		DEBUGADD(0, ("Please map all used groups using 'net groupmap "
			     "add', set the maximum used RID using\n"));
		DEBUGADD(0, ("'net setmaxrid' and remove the parameter\n"));
		return False;
	}

	return pdb_context->pdb_new_rid(pdb_context, rid);
}

/***************************************************************
  Initialize the static context (at smbd startup etc). 

  If uninitialised, context will auto-init on first use.
 ***************************************************************/

BOOL initialize_password_db(BOOL reload)
{	
	return (pdb_get_static_context(reload) != NULL);
}


/***************************************************************************
  Default implementations of some functions.
 ****************************************************************************/

static NTSTATUS pdb_default_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *user, const char *sname)
{
	return NT_STATUS_NO_SUCH_USER;
}

static NTSTATUS pdb_default_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	return NT_STATUS_NO_SUCH_USER;
}

static NTSTATUS pdb_default_add_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	DEBUG(0,("this backend (%s) should not be listed as the first passdb backend! You can't add users to it.\n", methods->name));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_default_update_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *newpwd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_default_delete_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *pwd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_default_rename_sam_account (struct pdb_methods *methods, SAM_ACCOUNT *pwd, const char *newname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_default_update_login_attempts (struct pdb_methods *methods, SAM_ACCOUNT *newpwd, BOOL success)
{
	return NT_STATUS_OK;
}

static NTSTATUS pdb_default_setsampwent(struct pdb_methods *methods, BOOL update, uint16 acb_mask)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_default_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT *user)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static void pdb_default_endsampwent(struct pdb_methods *methods)
{
	return; /* NT_STATUS_NOT_IMPLEMENTED; */
}

static NTSTATUS pdb_default_get_account_policy(struct pdb_methods *methods, int policy_index, uint32 *value)
{
	return account_policy_get(policy_index, value) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_default_set_account_policy(struct pdb_methods *methods, int policy_index, uint32 value)
{
	return account_policy_set(policy_index, value) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_default_get_seq_num(struct pdb_methods *methods, time_t *seq_num)
{
	*seq_num = time(NULL);
	return NT_STATUS_OK;
}

static BOOL pdb_default_uid_to_rid(struct pdb_methods *methods, uid_t uid,
				   uint32 *rid)
{
	SAM_ACCOUNT *sampw = NULL;
	struct passwd *unix_pw;
	BOOL ret;
	
	unix_pw = sys_getpwuid( uid );

	if ( !unix_pw ) {
		DEBUG(4,("pdb_default_uid_to_rid: host has no idea of uid "
			 "%lu\n", (unsigned long)uid));
		return False;
	}
	
	if ( !NT_STATUS_IS_OK(pdb_init_sam(&sampw)) ) {
		DEBUG(0,("pdb_default_uid_to_rid: failed to allocate "
			 "SAM_ACCOUNT object\n"));
		return False;
	}
	
	become_root();
	ret = NT_STATUS_IS_OK(
		methods->getsampwnam(methods, sampw, unix_pw->pw_name ));
	unbecome_root();

	if (!ret) {
		DEBUG(5, ("pdb_default_uid_to_rid: Did not find user "
			  "%s (%d)\n", unix_pw->pw_name, uid));
		pdb_free_sam(&sampw);
		return False;
	}

	ret = sid_peek_check_rid(get_global_sam_sid(),
				 pdb_get_user_sid(sampw), rid);

	if (!ret) {
		DEBUG(1, ("Could not peek rid out of sid %s\n",
			  sid_string_static(pdb_get_user_sid(sampw))));
	}

	pdb_free_sam(&sampw);
	return ret;
}

static BOOL pdb_default_gid_to_sid(struct pdb_methods *methods, gid_t gid,
				   DOM_SID *sid)
{
	GROUP_MAP map;

	if (!NT_STATUS_IS_OK(methods->getgrgid(methods, &map, gid))) {
		return False;
	}

	sid_copy(sid, &map.sid);
	return True;
}

static BOOL pdb_default_sid_to_id(struct pdb_methods *methods,
				  const DOM_SID *sid,
				  union unid_t *id, enum SID_NAME_USE *type)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = False;
	const char *name;
	uint32 rid;

	mem_ctx = talloc_new(NULL);

	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_new failed\n"));
		return False;
	}

	if (sid_peek_check_rid(get_global_sam_sid(), sid, &rid)) {
		/* Here we might have users as well as groups and aliases */
		ret = lookup_global_sam_rid(mem_ctx, rid, &name, type, id);
		goto done;
	}

	if (sid_peek_check_rid(&global_sid_Builtin, sid, &rid)) {
		/* Here we only have aliases */
		GROUP_MAP map;
		if (!NT_STATUS_IS_OK(methods->getgrsid(methods, &map, *sid))) {
			DEBUG(10, ("Could not find map for sid %s\n",
				   sid_string_static(sid)));
			goto done;
		}
		if ((map.sid_name_use != SID_NAME_ALIAS) &&
		    (map.sid_name_use != SID_NAME_WKN_GRP)) {
			DEBUG(10, ("Map for sid %s is a %s, expected an "
				   "alias\n", sid_string_static(sid),
				   sid_type_lookup(map.sid_name_use)));
			goto done;
		}

		id->gid = map.gid;
		*type = SID_NAME_ALIAS;
		ret = True;
		goto done;
	}

	DEBUG(5, ("Sid %s is neither ours nor builtin, don't know it\n",
		  sid_string_static(sid)));

 done:

	talloc_free(mem_ctx);
	return ret;
}

static void add_uid_to_array_unique(TALLOC_CTX *mem_ctx,
				    uid_t uid, uid_t **pp_uids, size_t *p_num)
{
	size_t i;

	for (i=0; i<*p_num; i++) {
		if ((*pp_uids)[i] == uid)
			return;
	}
	
	*pp_uids = TALLOC_REALLOC_ARRAY(mem_ctx, *pp_uids, uid_t, *p_num+1);

	if (*pp_uids == NULL)
		return;

	(*pp_uids)[*p_num] = uid;
	*p_num += 1;
}

static BOOL get_memberuids(TALLOC_CTX *mem_ctx, gid_t gid, uid_t **pp_uids, size_t *p_num)
{
	struct group *grp;
	char **gr;
	struct sys_pwent *userlist, *user;
 
	*pp_uids = NULL;
	*p_num = 0;

	/* We only look at our own sam, so don't care about imported stuff */

	winbind_off();

	if ((grp = getgrgid(gid)) == NULL) {
		winbind_on();
		return False;
	}

	/* Primary group members */

	userlist = getpwent_list();

	for (user = userlist; user != NULL; user = user->next) {
		if (user->pw_gid != gid)
			continue;
		add_uid_to_array_unique(mem_ctx, user->pw_uid, pp_uids, p_num);
	}

	pwent_free(userlist);

	/* Secondary group members */

	for (gr = grp->gr_mem; (*gr != NULL) && ((*gr)[0] != '\0'); gr += 1) {
		struct passwd *pw = getpwnam(*gr);

		if (pw == NULL)
			continue;
		add_uid_to_array_unique(mem_ctx, pw->pw_uid, pp_uids, p_num);
	}

	winbind_on();

	return True;
}

NTSTATUS pdb_default_enum_group_members(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					const DOM_SID *group,
					uint32 **pp_member_rids,
					size_t *p_num_members)
{
	gid_t gid;
	uid_t *uids;
	size_t i, num_uids;

	*pp_member_rids = NULL;
	*p_num_members = 0;

	if (!sid_to_gid(group, &gid))
		return NT_STATUS_NO_SUCH_GROUP;

	if(!get_memberuids(mem_ctx, gid, &uids, &num_uids))
		return NT_STATUS_NO_SUCH_GROUP;

	if (num_uids == 0)
		return NT_STATUS_OK;

	*pp_member_rids = TALLOC_ZERO_ARRAY(mem_ctx, uint32, num_uids);

	for (i=0; i<num_uids; i++) {
		DOM_SID sid;

		uid_to_sid(&sid, uids[i]);

		if (!sid_check_is_in_our_domain(&sid)) {
			DEBUG(1, ("Inconsistent SAM -- group member uid not "
				  "in our domain\n"));
			continue;
		}

		sid_peek_rid(&sid, &(*pp_member_rids)[*p_num_members]);
		*p_num_members += 1;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Look up a rid in the SAM we're responsible for (i.e. passdb)
 ********************************************************************/

static BOOL lookup_global_sam_rid(TALLOC_CTX *mem_ctx, uint32 rid,
				  const char **name,
				  enum SID_NAME_USE *psid_name_use,
				  union unid_t *unix_id)
{
	SAM_ACCOUNT *sam_account = NULL;
	GROUP_MAP map;
	BOOL ret;
	DOM_SID sid;

	*psid_name_use = SID_NAME_UNKNOWN;
	
	DEBUG(5,("lookup_global_sam_rid: looking up RID %u.\n",
		 (unsigned int)rid));

	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, rid);
	
	/* see if the passdb can help us with the name of the user */
	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_account))) {
		return False;
	}

	/* BEING ROOT BLLOCK */
	become_root();
	if (pdb_getsampwsid(sam_account, &sid)) {
		struct passwd *pw;

		unbecome_root();		/* -----> EXIT BECOME_ROOT() */
		*name = talloc_strdup(mem_ctx, pdb_get_username(sam_account));
		*psid_name_use = SID_NAME_USER;

		pdb_free_sam(&sam_account);

		if (unix_id == NULL) {
			return True;
		}

		pw = Get_Pwnam(*name);
		if (pw == NULL) {
			return False;
		}
		unix_id->uid = pw->pw_uid;
		return True;
	}
	pdb_free_sam(&sam_account);
	
	ret = pdb_getgrsid(&map, sid);
	unbecome_root();
	/* END BECOME_ROOT BLOCK */
	
	if ( ret ) {
		if (map.gid!=(gid_t)-1) {
			DEBUG(5,("lookup_global_sam_rid: mapped group %s to "
				 "gid %u\n", map.nt_name,
				 (unsigned int)map.gid));
		} else {
			DEBUG(5,("lookup_global_sam_rid: mapped group %s to "
				 "no unix gid.  Returning name.\n",
				 map.nt_name));
		}

		*name = talloc_strdup(mem_ctx, map.nt_name);
		*psid_name_use = map.sid_name_use;

		if (unix_id == NULL) {
			return True;
		}

		if (map.gid == (gid_t)-1) {
			DEBUG(5, ("Can't find a unix id for an unmapped "
				  "group\n"));
			return False;
		}

		unix_id->gid = map.gid;
		return True;
	}

	return False;
}

NTSTATUS pdb_default_lookup_rids(struct pdb_methods *methods,
				 const DOM_SID *domain_sid,
				 int num_rids,
				 uint32 *rids,
				 const char **names,
				 uint32 *attrs)
{
	int i;
	NTSTATUS result;
	BOOL have_mapped = False;
	BOOL have_unmapped = False;

	if (sid_check_is_builtin(domain_sid)) {

		for (i=0; i<num_rids; i++) {
			const char *name;

			if (lookup_builtin_rid(names, rids[i], &name)) {
				attrs[i] = SID_NAME_ALIAS;
				names[i] = name;
				DEBUG(5,("lookup_rids: %s:%d\n",
					 names[i], attrs[i]));
				have_mapped = True;
			} else {
				have_unmapped = True;
				attrs[i] = SID_NAME_UNKNOWN;
			}
		}
		goto done;
	}

	/* Should not happen, but better check once too many */
	if (!sid_check_is_domain(domain_sid)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	for (i = 0; i < num_rids; i++) {
		const char *name;

		if (lookup_global_sam_rid(names, rids[i], &name, &attrs[i],
					  NULL)) {
			names[i] = name;
			DEBUG(5,("lookup_rids: %s:%d\n", names[i], attrs[i]));
			have_mapped = True;
		} else {
			have_unmapped = True;
			attrs[i] = SID_NAME_UNKNOWN;
		}
	}

 done:

	result = NT_STATUS_NONE_MAPPED;

	if (have_mapped)
		result = have_unmapped ? STATUS_SOME_UNMAPPED : NT_STATUS_OK;

	return result;
}

NTSTATUS pdb_default_lookup_names(struct pdb_methods *methods,
				  const DOM_SID *domain_sid,
				  int num_names,
				  const char **names,
				  uint32 *rids,
				  uint32 *attrs)
{
	int i;
	NTSTATUS result;
	BOOL have_mapped = False;
	BOOL have_unmapped = False;

	if (sid_check_is_builtin(domain_sid)) {

		for (i=0; i<num_names; i++) {
			uint32 rid;

			if (lookup_builtin_name(names[i], &rid)) {
				attrs[i] = SID_NAME_ALIAS;
				rids[i] = rid;
				DEBUG(5,("lookup_rids: %s:%d\n",
					 names[i], attrs[i]));
				have_mapped = True;
			} else {
				have_unmapped = True;
				attrs[i] = SID_NAME_UNKNOWN;
			}
		}
		goto done;
	}

	/* Should not happen, but better check once too many */
	if (!sid_check_is_domain(domain_sid)) {
		return NT_STATUS_INVALID_HANDLE;
	}

	for (i = 0; i < num_names; i++) {
		if (lookup_global_sam_name(names[i], 0, &rids[i], &attrs[i])) {
			DEBUG(5,("lookup_names: %s-> %d:%d\n", names[i],
				 rids[i], attrs[i]));
			have_mapped = True;
		} else {
			have_unmapped = True;
			attrs[i] = SID_NAME_UNKNOWN;
		}
	}

 done:

	result = NT_STATUS_NONE_MAPPED;

	if (have_mapped)
		result = have_unmapped ? STATUS_SOME_UNMAPPED : NT_STATUS_OK;

	return result;
}

static struct pdb_search *pdb_search_init(enum pdb_search_type type)
{
	TALLOC_CTX *mem_ctx;
	struct pdb_search *result;

	mem_ctx = talloc_init("pdb_search");
	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_init failed\n"));
		return NULL;
	}

	result = TALLOC_P(mem_ctx, struct pdb_search);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->mem_ctx = mem_ctx;
	result->type = type;
	result->cache = NULL;
	result->num_entries = 0;
	result->cache_size = 0;
	result->search_ended = False;

	/* Segfault appropriately if not initialized */
	result->next_entry = NULL;
	result->search_end = NULL;

	return result;
}

static void fill_displayentry(TALLOC_CTX *mem_ctx, uint32 rid,
			      uint16 acct_flags,
			      const char *account_name,
			      const char *fullname,
			      const char *description,
			      struct samr_displayentry *entry)
{
	entry->rid = rid;
	entry->acct_flags = acct_flags;

	if (account_name != NULL)
		entry->account_name = talloc_strdup(mem_ctx, account_name);
	else
		entry->account_name = "";

	if (fullname != NULL)
		entry->fullname = talloc_strdup(mem_ctx, fullname);
	else
		entry->fullname = "";

	if (description != NULL)
		entry->description = talloc_strdup(mem_ctx, description);
	else
		entry->description = "";
}

static BOOL user_search_in_progress = False;
struct user_search {
	uint16 acct_flags;
};

static BOOL next_entry_users(struct pdb_search *s,
			     struct samr_displayentry *entry)
{
	struct user_search *state = s->private_data;
	SAM_ACCOUNT *user = NULL;
	NTSTATUS status;

 next:
	status = pdb_init_sam(&user);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Could not pdb_init_sam\n"));
		return False;
	}

	if (!pdb_getsampwent(user)) {
		pdb_free_sam(&user);
		return False;
	}

 	if ((state->acct_flags != 0) &&
	    ((pdb_get_acct_ctrl(user) & state->acct_flags) == 0)) {
		pdb_free_sam(&user);
		goto next;
	}

	fill_displayentry(s->mem_ctx, pdb_get_user_rid(user),
			  pdb_get_acct_ctrl(user), pdb_get_username(user),
			  pdb_get_fullname(user), pdb_get_acct_desc(user),
			  entry);

	pdb_free_sam(&user);
	return True;
}

static void search_end_users(struct pdb_search *search)
{
	pdb_endsampwent();
	user_search_in_progress = False;
}

static BOOL pdb_default_search_users(struct pdb_methods *methods,
				     struct pdb_search *search,
				     uint16 acct_flags)
{
	struct user_search *state;

	if (user_search_in_progress) {
		DEBUG(1, ("user search in progress\n"));
		return False;
	}

	if (!pdb_setsampwent(False, acct_flags)) {
		DEBUG(5, ("Could not start search\n"));
		return False;
	}

	user_search_in_progress = True;

	state = TALLOC_P(search->mem_ctx, struct user_search);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return False;
	}

	state->acct_flags = acct_flags;

	search->private_data = state;
	search->next_entry = next_entry_users;
	search->search_end = search_end_users;
	return True;
}

struct group_search {
	GROUP_MAP *groups;
	size_t num_groups, current_group;
};

static BOOL next_entry_groups(struct pdb_search *s,
			      struct samr_displayentry *entry)
{
	struct group_search *state = s->private_data;
	uint32 rid;
	GROUP_MAP *map = &state->groups[state->current_group];

	if (state->current_group == state->num_groups)
		return False;

	sid_peek_rid(&map->sid, &rid);

	fill_displayentry(s->mem_ctx, rid, 0, map->nt_name, NULL, map->comment,
			  entry);

	state->current_group += 1;
	return True;
}

static void search_end_groups(struct pdb_search *search)
{
	struct group_search *state = search->private_data;
	SAFE_FREE(state->groups);
}

static BOOL pdb_search_grouptype(struct pdb_search *search,
				 enum SID_NAME_USE type)
{
	struct group_search *state;

	state = TALLOC_P(search->mem_ctx, struct group_search);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return False;
	}

	if (!pdb_enum_group_mapping(type, &state->groups, &state->num_groups,
				    True)) {
		DEBUG(0, ("Could not enum groups\n"));
		return False;
	}

	state->current_group = 0;
	search->private_data = state;
	search->next_entry = next_entry_groups;
	search->search_end = search_end_groups;
	return True;
}

static BOOL pdb_default_search_groups(struct pdb_methods *methods,
				      struct pdb_search *search)
{
	return pdb_search_grouptype(search, SID_NAME_DOM_GRP);
}

static BOOL pdb_default_search_aliases(struct pdb_methods *methods,
				       struct pdb_search *search,
				       const DOM_SID *sid)
{

	if (sid_equal(sid, get_global_sam_sid()))
		return pdb_search_grouptype(search, SID_NAME_ALIAS);

	if (sid_equal(sid, &global_sid_Builtin))
		return pdb_search_grouptype(search, SID_NAME_WKN_GRP);

	DEBUG(3, ("unknown domain sid: %s\n", sid_string_static(sid)));
	return False;
}

static struct samr_displayentry *pdb_search_getentry(struct pdb_search *search,
						     uint32 idx)
{
	if (idx < search->num_entries)
		return &search->cache[idx];

	if (search->search_ended)
		return NULL;

	while (idx >= search->num_entries) {
		struct samr_displayentry entry;

		if (!search->next_entry(search, &entry)) {
			search->search_end(search);
			search->search_ended = True;
			break;
		}

		ADD_TO_LARGE_ARRAY(search->mem_ctx, struct samr_displayentry,
				   entry, &search->cache, &search->num_entries,
				   &search->cache_size);
	}

	return (search->num_entries > idx) ? &search->cache[idx] : NULL;
}

struct pdb_search *pdb_search_users(uint16 acct_flags)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);
	struct pdb_search *result;

	if (pdb_context == NULL) return NULL;

	result = pdb_search_init(PDB_USER_SEARCH);
	if (result == NULL) return NULL;

	if (!pdb_context->pdb_search_users(pdb_context, result, acct_flags)) {
		talloc_destroy(result->mem_ctx);
		return NULL;
	}
	return result;
}

struct pdb_search *pdb_search_groups(void)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);
	struct pdb_search *result;

	if (pdb_context == NULL) return NULL;

	result = pdb_search_init(PDB_GROUP_SEARCH);
	if (result == NULL) return NULL;

	if (!pdb_context->pdb_search_groups(pdb_context, result)) {
		talloc_destroy(result->mem_ctx);
		return NULL;
	}
	return result;
}

struct pdb_search *pdb_search_aliases(const DOM_SID *sid)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);
	struct pdb_search *result;

	if (pdb_context == NULL) return NULL;

	result = pdb_search_init(PDB_ALIAS_SEARCH);
	if (result == NULL) return NULL;

	if (!pdb_context->pdb_search_aliases(pdb_context, result, sid)) {
		talloc_destroy(result->mem_ctx);
		return NULL;
	}
	return result;
}

uint32 pdb_search_entries(struct pdb_search *search,
			  uint32 start_idx, uint32 max_entries,
			  struct samr_displayentry **result)
{
	struct samr_displayentry *end_entry;
	uint32 end_idx = start_idx+max_entries-1;

	/* The first entry needs to be searched after the last. Otherwise the
	 * first entry might have moved due to a realloc during the search for
	 * the last entry. */

	end_entry = pdb_search_getentry(search, end_idx);
	*result = pdb_search_getentry(search, start_idx);

	if (end_entry != NULL)
		return max_entries;

	if (start_idx >= search->num_entries)
		return 0;

	return search->num_entries - start_idx;
}

void pdb_search_destroy(struct pdb_search *search)
{
	if (search == NULL)
		return;

	if (!search->search_ended)
		search->search_end(search);

	talloc_destroy(search->mem_ctx);
}

NTSTATUS make_pdb_methods(TALLOC_CTX *mem_ctx, PDB_METHODS **methods) 
{
	*methods = TALLOC_P(mem_ctx, struct pdb_methods);

	if (!*methods) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*methods);

	(*methods)->setsampwent = pdb_default_setsampwent;
	(*methods)->endsampwent = pdb_default_endsampwent;
	(*methods)->getsampwent = pdb_default_getsampwent;
	(*methods)->getsampwnam = pdb_default_getsampwnam;
	(*methods)->getsampwsid = pdb_default_getsampwsid;
	(*methods)->add_sam_account = pdb_default_add_sam_account;
	(*methods)->update_sam_account = pdb_default_update_sam_account;
	(*methods)->delete_sam_account = pdb_default_delete_sam_account;
	(*methods)->rename_sam_account = pdb_default_rename_sam_account;
	(*methods)->update_login_attempts = pdb_default_update_login_attempts;

	(*methods)->getgrsid = pdb_default_getgrsid;
	(*methods)->getgrgid = pdb_default_getgrgid;
	(*methods)->getgrnam = pdb_default_getgrnam;
	(*methods)->add_group_mapping_entry = pdb_default_add_group_mapping_entry;
	(*methods)->update_group_mapping_entry = pdb_default_update_group_mapping_entry;
	(*methods)->delete_group_mapping_entry = pdb_default_delete_group_mapping_entry;
	(*methods)->enum_group_mapping = pdb_default_enum_group_mapping;
	(*methods)->enum_group_members = pdb_default_enum_group_members;
	(*methods)->enum_group_memberships = pdb_default_enum_group_memberships;
	(*methods)->find_alias = pdb_default_find_alias;
	(*methods)->create_alias = pdb_default_create_alias;
	(*methods)->delete_alias = pdb_default_delete_alias;
	(*methods)->get_aliasinfo = pdb_default_get_aliasinfo;
	(*methods)->set_aliasinfo = pdb_default_set_aliasinfo;
	(*methods)->add_aliasmem = pdb_default_add_aliasmem;
	(*methods)->del_aliasmem = pdb_default_del_aliasmem;
	(*methods)->enum_aliasmem = pdb_default_enum_aliasmem;
	(*methods)->enum_alias_memberships = pdb_default_alias_memberships;
	(*methods)->lookup_rids = pdb_default_lookup_rids;
	(*methods)->get_account_policy = pdb_default_get_account_policy;
	(*methods)->set_account_policy = pdb_default_set_account_policy;
	(*methods)->get_seq_num = pdb_default_get_seq_num;
	(*methods)->uid_to_rid = pdb_default_uid_to_rid;
	(*methods)->gid_to_sid = pdb_default_gid_to_sid;
	(*methods)->sid_to_id = pdb_default_sid_to_id;

	(*methods)->search_users = pdb_default_search_users;
	(*methods)->search_groups = pdb_default_search_groups;
	(*methods)->search_aliases = pdb_default_search_aliases;

	return NT_STATUS_OK;
}

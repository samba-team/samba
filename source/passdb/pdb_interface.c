/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Jelmer Vernooij			2002

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
	const char *lm_pwd, *nt_pwd;
	
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

	entry = smb_xmalloc(sizeof(struct pdb_init_function_entry));
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

static NTSTATUS context_setsampwent(struct pdb_context *context, BOOL update)
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

	while (NT_STATUS_IS_ERR(ret = context->pwent_methods->setsampwent(context->pwent_methods, update))) {
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
	
		context->pwent_methods->setsampwent(context->pwent_methods, False);
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
	const char *lm_pw, *nt_pw;
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
	const char *lm_pw, *nt_pw;
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
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_group_mapping(context->pdb_methods,
							sid_name_use, rmap,
							num_entries, unix_only);
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

static NTSTATUS context_enum_aliases(struct pdb_context *context,
				     const DOM_SID *sid,
				     uint32 start_idx, uint32 max_entries,
				     uint32 *num_aliases,
				     struct acct_info **info)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_aliases(context->pdb_methods,
						  sid, start_idx, max_entries,
						  num_aliases, info);
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
				      const DOM_SID *alias, DOM_SID **members,
				      int *num)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_aliasmem(context->pdb_methods,
						   alias, members, num);
}
	
static NTSTATUS context_enum_alias_memberships(struct pdb_context *context,
					       const DOM_SID *sid,
					       DOM_SID **aliases, int *num)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->
		enum_alias_memberships(context->pdb_methods, sid, aliases,
				       num);
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

	*context = talloc(mem_ctx, sizeof(**context));
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
	(*context)->pdb_getgrsid = context_getgrsid;
	(*context)->pdb_getgrgid = context_getgrgid;
	(*context)->pdb_getgrnam = context_getgrnam;
	(*context)->pdb_add_group_mapping_entry = context_add_group_mapping_entry;
	(*context)->pdb_update_group_mapping_entry = context_update_group_mapping_entry;
	(*context)->pdb_delete_group_mapping_entry = context_delete_group_mapping_entry;
	(*context)->pdb_enum_group_mapping = context_enum_group_mapping;

	(*context)->pdb_find_alias = context_find_alias;
	(*context)->pdb_create_alias = context_create_alias;
	(*context)->pdb_delete_alias = context_delete_alias;
	(*context)->pdb_enum_aliases = context_enum_aliases;
	(*context)->pdb_get_aliasinfo = context_get_aliasinfo;
	(*context)->pdb_set_aliasinfo = context_set_aliasinfo;
	(*context)->pdb_add_aliasmem = context_add_aliasmem;
	(*context)->pdb_del_aliasmem = context_del_aliasmem;
	(*context)->pdb_enum_aliasmem = context_enum_aliasmem;
	(*context)->pdb_enum_alias_memberships = context_enum_alias_memberships;

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

BOOL pdb_setsampwent(BOOL update) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_setsampwent(pdb_context, update));
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

BOOL pdb_getsampwnam(SAM_ACCOUNT *sam_acct, const char *username) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_getsampwnam(pdb_context, sam_acct, username));
}

BOOL pdb_getsampwsid(SAM_ACCOUNT *sam_acct, const DOM_SID *sid) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

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

	return NT_STATUS_IS_OK(pdb_context->pdb_update_sam_account(pdb_context, sam_acct));
}

BOOL pdb_delete_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_delete_sam_account(pdb_context, sam_acct));
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

BOOL pdb_enum_group_mapping(enum SID_NAME_USE sid_name_use, GROUP_MAP **rmap,
			    int *num_entries, BOOL unix_only)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_group_mapping(pdb_context, sid_name_use,
						      rmap, num_entries, unix_only));
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

BOOL pdb_enum_aliases(const DOM_SID *sid, uint32 start_idx, uint32 max_entries,
		      uint32 *num_aliases, struct acct_info **info)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->pdb_enum_aliases(pdb_context, sid,
							     start_idx,
							     max_entries,
							     num_aliases,
							     info));
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
		       DOM_SID **members, int *num_members)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_aliasmem(pdb_context, alias,
						 members, num_members));
}

BOOL pdb_enum_alias_memberships(const DOM_SID *sid,
				DOM_SID **aliases, int *num)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_alias_memberships(pdb_context, sid,
							  aliases, num));
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

static NTSTATUS pdb_default_setsampwent(struct pdb_methods *methods, BOOL update)
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

NTSTATUS make_pdb_methods(TALLOC_CTX *mem_ctx, PDB_METHODS **methods) 
{
	*methods = talloc(mem_ctx, sizeof(struct pdb_methods));

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

	(*methods)->getgrsid = pdb_default_getgrsid;
	(*methods)->getgrgid = pdb_default_getgrgid;
	(*methods)->getgrnam = pdb_default_getgrnam;
	(*methods)->add_group_mapping_entry = pdb_default_add_group_mapping_entry;
	(*methods)->update_group_mapping_entry = pdb_default_update_group_mapping_entry;
	(*methods)->delete_group_mapping_entry = pdb_default_delete_group_mapping_entry;
	(*methods)->enum_group_mapping = pdb_default_enum_group_mapping;
	(*methods)->find_alias = pdb_default_find_alias;
	(*methods)->create_alias = pdb_default_create_alias;
	(*methods)->delete_alias = pdb_default_delete_alias;
	(*methods)->enum_aliases = pdb_default_enum_aliases;
	(*methods)->get_aliasinfo = pdb_default_get_aliasinfo;
	(*methods)->set_aliasinfo = pdb_default_set_aliasinfo;
	(*methods)->add_aliasmem = pdb_default_add_aliasmem;
	(*methods)->del_aliasmem = pdb_default_del_aliasmem;
	(*methods)->enum_aliasmem = pdb_default_enum_aliasmem;
	(*methods)->enum_alias_memberships = pdb_default_alias_memberships;

	return NT_STATUS_OK;
}

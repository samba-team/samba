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

/** List of various built-in passdb modules */

const struct pdb_init_function_entry builtin_pdb_init_functions[] = {
	{ "smbpasswd", pdb_init_smbpasswd },
	{ "smbpasswd_nua", pdb_init_smbpasswd_nua },
	{ "tdbsam", pdb_init_tdbsam },
	{ "tdbsam_nua", pdb_init_tdbsam_nua },
	{ "ldapsam", pdb_init_ldapsam },
	{ "ldapsam_nua", pdb_init_ldapsam_nua },
	{ "unixsam", pdb_init_unixsam },
	{ "nisplussam", pdb_init_nisplussam },
	{ "plugin", pdb_init_plugin },
	{ NULL, NULL}
};

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

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	/** @todo  This is where a 're-read on add' should be done */
	/* We now add a new account to the first database listed. 
	 * Should we? */

	return context->pdb_methods->add_sam_account(context->pdb_methods, sam_acct);
}

static NTSTATUS context_update_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
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
				 GROUP_MAP *map, DOM_SID sid, BOOL with_priv)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrsid(curmethods, map, sid, with_priv);
		if (NT_STATUS_IS_OK(ret)) {
			map->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_getgrgid(struct pdb_context *context,
				 GROUP_MAP *map, gid_t gid, BOOL with_priv)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrgid(curmethods, map, gid, with_priv);
		if (NT_STATUS_IS_OK(ret)) {
			map->methods = curmethods;
			return ret;
		}
		curmethods = curmethods->next;
	}

	return ret;
}

static NTSTATUS context_getgrnam(struct pdb_context *context,
				 GROUP_MAP *map, char *name, BOOL with_priv)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}
	curmethods = context->pdb_methods;
	while (curmethods){
		ret = curmethods->getgrnam(curmethods, map, name, with_priv);
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
					   BOOL unix_only, BOOL with_priv)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if ((!context) || (!context->pdb_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return ret;
	}

	return context->pdb_methods->enum_group_mapping(context->pdb_methods,
							sid_name_use, rmap,
							num_entries, unix_only,
							with_priv);
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
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	int i;

	p = strchr(module_name, ':');

	if (p) {
		*p = 0;
		module_location = p+1;
		trim_string(module_location, " ", " ");
	}

	trim_string(module_name, " ", " ");

	DEBUG(5,("Attempting to find an passdb backend to match %s (%s)\n", selected, module_name));
	for (i = 0; builtin_pdb_init_functions[i].name; i++)
	{
		if (strequal(builtin_pdb_init_functions[i].name, module_name))
		{
			DEBUG(5,("Found pdb backend %s (at pos %d)\n", module_name, i));
			nt_status = builtin_pdb_init_functions[i].init(context, methods, module_location);
			if (NT_STATUS_IS_OK(nt_status)) {
				DEBUG(5,("pdb backend %s has a valid init\n", selected));
			} else {
				DEBUG(0,("pdb backend %s did not correctly init (error was %s)\n", selected, nt_errstr(nt_status)));
			}
			SAFE_FREE(module_name);
			return nt_status;
			break; /* unreached */
		}
	}

	/* No such backend found */
	SAFE_FREE(module_name);
	return NT_STATUS_INVALID_PARAMETER;
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

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_context(context))) {
		return nt_status;
	}

	while (selected[i]){
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
		if (NT_STATUS_IS_ERR(make_pdb_context_list(&pdb_context, lp_passdb_backend()))) {
			return NULL;
		}
	}

	if (!pdb_context) {
		if (NT_STATUS_IS_ERR(make_pdb_context_list(&pdb_context, lp_passdb_backend()))) {
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

BOOL pdb_getgrsid(GROUP_MAP *map, DOM_SID sid, BOOL with_priv)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrsid(pdb_context, map, sid, with_priv));
}

BOOL pdb_getgrgid(GROUP_MAP *map, gid_t gid, BOOL with_priv)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrgid(pdb_context, map, gid, with_priv));
}

BOOL pdb_getgrnam(GROUP_MAP *map, char *name, BOOL with_priv)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_getgrnam(pdb_context, map, name, with_priv));
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
			    int *num_entries, BOOL unix_only, BOOL with_priv)
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return NT_STATUS_IS_OK(pdb_context->
			       pdb_enum_group_mapping(pdb_context, sid_name_use,
						      rmap, num_entries, unix_only,
						      with_priv));
}

/***************************************************************
  Initialize the static context (at smbd startup etc). 

  If uninitialised, context will auto-init on first use.
 ***************************************************************/

BOOL initialize_password_db(BOOL reload)
{	
	return (pdb_get_static_context(reload) != NULL);
}


NTSTATUS make_pdb_methods(TALLOC_CTX *mem_ctx, PDB_METHODS **methods) 
{
	*methods = talloc(mem_ctx, sizeof(struct pdb_methods));

	if (!*methods) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*methods);

	return NT_STATUS_OK;
}

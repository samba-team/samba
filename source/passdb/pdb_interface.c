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
static const struct {
    const char *name;
    /* Function to create a member of the pdb_methods list */
    pdb_init_function init;
} builtin_pdb_init_functions[] = {
	{ "smbpasswd", pdb_init_smbpasswd },
	{ "smbpasswd_nua", pdb_init_smbpasswd_nua },
	{ "tdbsam", pdb_init_tdbsam },
	{ "tdbsam_nua", pdb_init_tdbsam_nua },
	{ "ldapsam", pdb_init_ldapsam },
	{ "ldapsam_nua", pdb_init_ldapsam_nua },
	{ "unixsam", pdb_init_unixsam },
	{ "guest", pdb_init_guestsam },
	{ "nisplussam", pdb_init_nisplussam },
	{ NULL, NULL}
};

static struct pdb_init_function_entry *backends;
static void lazy_initialize_passdb(void);

static void lazy_initialize_passdb()
{
	int i;
	static BOOL initialised = False;
	
	if(!initialised) {
		initialised = True;

		for(i = 0; builtin_pdb_init_functions[i].name; i++) {
			smb_register_passdb(builtin_pdb_init_functions[i].name, builtin_pdb_init_functions[i].init, PASSDB_INTERFACE_VERSION);
		}
	}
}

BOOL smb_register_passdb(const char *name, pdb_init_function init, int version) 
{
	struct pdb_init_function_entry *entry = backends;

	if(version != PASSDB_INTERFACE_VERSION)
		return False;

	DEBUG(5,("Attempting to register passdb backend %s\n", name));

	/* Check for duplicates */
	while(entry) { 
		if(strcasecmp(name, entry->name) == 0) { 
			DEBUG(0,("There already is a passdb backend registered with the name %s!\n", name));
			return False;
		}
		entry = entry->next;
	}

	entry = smb_xmalloc(sizeof(struct pdb_init_function_entry));
	entry->name = name;
	entry->init = init;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added passdb backend '%s'\n", name));
	return True;
}

struct pdb_init_function_entry *pdb_find_backend_entry(const char *name)
{
	struct pdb_init_function_entry *entry = backends;

	while(entry) {
		if (strequal(entry->name, name)) return entry;
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
		trim_string(module_location, " ", " ");
	}

	trim_string(module_name, " ", " ");


	DEBUG(5,("Attempting to find an passdb backend to match %s (%s)\n", selected, module_name));

	entry = pdb_find_backend_entry(module_name);
	
	/* No such backend found */
	if(!entry) { 
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

	return NT_STATUS_OK;
}

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

/** List of various built-in passdb modules */

const struct pdb_init_function_entry builtin_pdb_init_functions[] = {
	{ "smbpasswd", pdb_init_smbpasswd },
	{ "smbpasswd_nua", pdb_init_smbpasswd_nua },
	{ "tdbsam", pdb_init_tdbsam },
	{ "tdbsam_nua", pdb_init_tdbsam_nua },
	{ "ldapsam", pdb_init_ldapsam },
	{ "ldapsam_nua", pdb_init_ldapsam_nua },
	{ "plugin", pdb_init_plugin },
	{ NULL, NULL}
};

static BOOL context_setsampwent(struct pdb_context *context, BOOL update)
{
	if ((!context) || (!context->pdb_methods) || (!context->pdb_methods->setsampwent)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	context->pwent_methods = context->pdb_methods;
	
	while(!(context->pwent_methods->setsampwent(context->pwent_methods, update))){
		context->pwent_methods = context->pwent_methods->next;
		if(context->pwent_methods == NULL)return False;
	}
	return True;
}

static void context_endsampwent(struct pdb_context *context)
{
	if ((!context)){
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return;
	}

	if(context->pwent_methods && context->pwent_methods->endsampwent)
		context->pwent_methods->endsampwent(context->pwent_methods);

	/* So we won't get strange data when calling getsampwent now */
	context->pwent_methods = NULL;
}

static BOOL context_getsampwent(struct pdb_context *context, SAM_ACCOUNT *user)
{
	if ((!context) || (!context->pwent_methods)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}
	/* Loop until we find something useful */
	while((!context->pwent_methods->getsampwent) || 
		  context->pwent_methods->getsampwent(context->pwent_methods, user) == False){

		if(context->pwent_methods->endsampwent)
			context->pwent_methods->endsampwent(context->pwent_methods);

		context->pwent_methods = context->pwent_methods->next;

		/* All methods are checked now. There are no more entries */
		if(context->pwent_methods == NULL)return False;
	
		if(!context->pwent_methods->setsampwent){
			DEBUG(0, ("invalid context->pwent_methods->setsampwent\n"));
			return False;
		}

		context->pwent_methods->setsampwent(context->pwent_methods, False);
	}
	user->methods = context->pwent_methods;
	return True;
}

static BOOL context_getsampwnam(struct pdb_context *context, SAM_ACCOUNT *sam_acct, const char *username)
{
	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}
	curmethods = context->pdb_methods;
	while(curmethods){
		if(curmethods->getsampwnam && curmethods->getsampwnam(curmethods, sam_acct, username) == True){
			sam_acct->methods = curmethods;
			return True;
		}
		curmethods = curmethods->next;
	}

	return False;
}

static BOOL context_getsampwrid(struct pdb_context *context, SAM_ACCOUNT *sam_acct, uint32 rid)
{
	struct pdb_methods *curmethods;
	if ((!context)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}
	
	curmethods = context->pdb_methods;

	while(curmethods){
		if(curmethods->getsampwrid && curmethods->getsampwrid(curmethods, sam_acct, rid) == True){
			sam_acct->methods = curmethods;
			return True;
		}
		curmethods = curmethods->next;
	}

	return False;
}

static BOOL context_add_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	if ((!context) || (!context->pdb_methods) || (!context->pdb_methods->add_sam_account)) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	/** @todo  This is where a 're-read on add' should be done */
	/* We now add a new account to the first database listed. 
	 * Should we? */

	return context->pdb_methods->add_sam_account(context->pdb_methods, sam_acct);
}

static BOOL context_update_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	if(!sam_acct || !sam_acct->methods){
		DEBUG(0, ("invalid sam_acct specified\n"));
		return False;
	}

	if(!sam_acct->methods->update_sam_account){
		DEBUG(0, ("invalid sam_acct->methods\n"));
		return False;
	}

	/** @todo  This is where a 're-read on update' should be done */

	return sam_acct->methods->update_sam_account(sam_acct->methods, sam_acct);
}

static BOOL context_delete_sam_account(struct pdb_context *context, SAM_ACCOUNT *sam_acct)
{
	struct pdb_methods *pdb_selected;
	if (!context) {
		DEBUG(0, ("invalid pdb_context specified!\n"));
		return False;
	}

	if(!sam_acct->methods){
		pdb_selected = context->pdb_methods;
		/* There's no passdb backend specified for this account.
		 * Try to delete it in every passdb available */
		while(pdb_selected){
			if(pdb_selected->delete_sam_account && pdb_selected->delete_sam_account(pdb_selected, sam_acct)){
				return True;
			}
			pdb_selected = pdb_selected->next;
		}
		return False;
	}

	if(!sam_acct->methods->delete_sam_account){
		DEBUG(0,("invalid sam_acct->methods->delete_sam_account\n"));
		return False;
	}
	
	return sam_acct->methods->delete_sam_account(sam_acct->methods, sam_acct);
}

static void free_pdb_context(struct pdb_context **context)
{
	struct pdb_methods *pdb_selected = (*context)->pdb_methods;

	while(pdb_selected){
		if(pdb_selected->free_private_data)
			pdb_selected->free_private_data(pdb_selected->private_data);
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
			if (NT_STATUS_IS_OK(nt_status 
								= builtin_pdb_init_functions[i].init(context, methods, module_location))) {
				DEBUG(5,("pdb backend %s has a valid init\n", selected));
			} else {
				DEBUG(0,("pdb backend %s did not correctly init (error was %s)\n", selected, nt_errstr(nt_status)));
			}
			break;
		}
	}

	if (!*methods) {
		DEBUG(0,("failed to select passdb backed!\n"));
		return nt_status;
	}
	return NT_STATUS_OK;
}

/******************************************************************
  Make a pdb_context from scratch.
 *******************************************************************/

static NTSTATUS make_pdb_context(struct pdb_context **context) 
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init_named("pdb_context internal allocation context");

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
	(*context)->pdb_getsampwrid = context_getsampwrid;
	(*context)->pdb_add_sam_account = context_add_sam_account;
	(*context)->pdb_update_sam_account = context_update_sam_account;
	(*context)->pdb_delete_sam_account = context_delete_sam_account;

	(*context)->pdb_methods = NULL;
	(*context)->pwent_methods = NULL;

	(*context)->free_fn = free_pdb_context;

	return NT_STATUS_OK;
}


/******************************************************************
  Make a pdb_context, given a text string.
 *******************************************************************/

NTSTATUS make_pdb_context_name(struct pdb_context **context, const char *selected) 
{
	/* HINT: Don't store 'selected' becouse its often an lp_ string and will 'go away' */
	char *conf = smb_xstrdup(selected);
	char *confcur = conf, *confnext;
	struct pdb_methods *curmethods, *tmpmethods;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	if(!NT_STATUS_IS_OK(nt_status = make_pdb_context(context))){
		return nt_status;
	}

	while(confcur){
		if(strchr(confcur, ' ')){
			confnext = strchr(confcur,' ');
			*confnext = '\0';
			confnext++;
		}else confnext = NULL;

		/* Try to initialise pdb */
		DEBUG(5,("Trying to load: %s\n", confcur));
		if(!NT_STATUS_IS_OK(make_pdb_methods_name(&curmethods, *context, confcur))){
			DEBUG(5, ("Loading %s failed!\n", confcur));
			SAFE_FREE(curmethods);
			continue;
		}
		curmethods->parent = *context;
		DLIST_ADD_END((*context)->pdb_methods, curmethods, tmpmethods);

		if(!confnext)break;
		confcur = confnext;
	}
	SAFE_FREE(conf);

	nt_status = NT_STATUS_OK;

	return nt_status;
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
		if (!NT_STATUS_IS_OK(make_pdb_context_name(&pdb_context, lp_passdb_backend()))) {
			return NULL;
		}
	}

	if (!pdb_context) {
		if (!NT_STATUS_IS_OK(make_pdb_context_name(&pdb_context, lp_passdb_backend()))) {
			return NULL;
		}
	}

	return pdb_context;
}

#if !defined(WITH_NISPLUS_SAM)

/******************************************************************
 Backward compatibility functions for the original passdb interface
*******************************************************************/

BOOL pdb_setsampwent(BOOL update) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_setsampwent(pdb_context, update);
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

	return pdb_context->pdb_getsampwent(pdb_context, user);
}

BOOL pdb_getsampwnam(SAM_ACCOUNT *sam_acct, const char *username) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_getsampwnam(pdb_context, sam_acct, username);
}

BOOL pdb_getsampwrid(SAM_ACCOUNT *sam_acct, uint32 rid) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_getsampwrid(pdb_context, sam_acct, rid);
}

BOOL pdb_add_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_add_sam_account(pdb_context, sam_acct);
}

BOOL pdb_update_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_update_sam_account(pdb_context, sam_acct);
}

BOOL pdb_delete_sam_account(SAM_ACCOUNT *sam_acct) 
{
	struct pdb_context *pdb_context = pdb_get_static_context(False);

	if (!pdb_context) {
		return False;
	}

	return pdb_context->pdb_delete_sam_account(pdb_context, sam_acct);
}

#endif /* !defined(WITH_NISPLUS_SAM) */

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

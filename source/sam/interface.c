/*
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett			2002
   Copyright (C) Jelmer Vernooij			2002
   Copyright (C) Stefan (metze) Metzmacher		2002
   Copyright (C) Kai Krüger				2002

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
#define DBGC_CLASS DBGC_SAM

extern DOM_SID global_sid_Builtin;

/** List of various built-in sam modules */

const struct sam_init_function_entry builtin_sam_init_functions[] = {
	{ "plugin", sam_init_plugin },
#ifdef HAVE_LDAP
	{ "ads", sam_init_ads },
#endif
	{ "skel", sam_init_skel },
	{ NULL, NULL}
};


static NTSTATUS sam_get_methods_by_sid(const SAM_CONTEXT *context, SAM_METHODS **sam_method, const DOM_SID *domainsid)
{
	SAM_METHODS	*tmp_methods;

	DEBUG(5,("sam_get_methods_by_sid: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods);

	tmp_methods = context->methods;

	while (tmp_methods) {
		if (sid_equal(domainsid, &(tmp_methods->domain_sid)))
		{
			(*sam_method) = tmp_methods;
			return NT_STATUS_OK;
		}
		tmp_methods = tmp_methods->next;
	}

	DEBUG(3,("sam_get_methods_by_sid: There is no backend specified for domain %s\n", sid_string_static(domainsid)));

	return NT_STATUS_NO_SUCH_DOMAIN;
}

static NTSTATUS sam_get_methods_by_name(const SAM_CONTEXT *context, SAM_METHODS **sam_method, const char *domainname)
{
	SAM_METHODS	*tmp_methods;

	DEBUG(5,("sam_get_methods_by_name: %d\n", __LINE__));

	/* invalid sam_context specified */
	SAM_ASSERT(context && context->methods);

	tmp_methods = context->methods;

	while (tmp_methods) {
		if (strequal(domainname, tmp_methods->domain_name))
		{
			(*sam_method) = tmp_methods;
			return NT_STATUS_OK;
		}
		tmp_methods = tmp_methods->next;
	}

	DEBUG(3,("sam_get_methods_by_sid: There is no backend specified for domain %s\n", domainname));

	return NT_STATUS_NO_SUCH_DOMAIN;
}

static NTSTATUS make_sam_methods(TALLOC_CTX *mem_ctx, SAM_METHODS **methods)
{
	*methods = talloc(mem_ctx, sizeof(SAM_METHODS));

	if (!*methods) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*methods);

	return NT_STATUS_OK;
}

/******************************************************************
  Free and cleanup a sam context, any associated data and anything
  that the attached modules might have associated.
 *******************************************************************/

void free_sam_context(SAM_CONTEXT **context)
{
	SAM_METHODS *sam_selected = (*context)->methods;

	while (sam_selected) {
		if (sam_selected->free_private_data) {
			sam_selected->free_private_data(&(sam_selected->private_data));
		}
		sam_selected = sam_selected->next;
	}

	talloc_destroy((*context)->mem_ctx);
	*context = NULL;
}

/******************************************************************
  Make a backend_entry from scratch
 *******************************************************************/
 
static NTSTATUS make_backend_entry(SAM_BACKEND_ENTRY *backend_entry, char *sam_backend_string)
{
	char *tmp = NULL;
	char *tmp_string = sam_backend_string;
	
	DEBUG(5,("make_backend_entry: %d\n", __LINE__));
	
	SAM_ASSERT(sam_backend_string && backend_entry);
	
	backend_entry->module_name = sam_backend_string;
	
	DEBUG(5,("makeing backend_entry for %s\n", backend_entry->module_name));
	
	if ((tmp = strrchr(tmp_string, '|')) != NULL) {
		DEBUGADD(20,("a domain name has been specified\n"));
		*tmp = 0;
		backend_entry->domain_name = smb_xstrdup(tmp + 1);
		tmp_string = tmp + 1;
	}
	
	if ((tmp = strchr(tmp_string, ':')) != NULL) {
		DEBUG(20,("options for the backend have been specified\n"));
		*tmp = 0;
		backend_entry->module_params = smb_xstrdup(tmp + 1);
		tmp_string = tmp + 1;
	}
		
	if (backend_entry->domain_name == NULL) {
		DEBUG(10,("make_backend_entry: no domain was specified for sam module %s. Using default domain %s\n",
			backend_entry->module_name, lp_workgroup()));
		backend_entry->domain_name = smb_xstrdup(lp_workgroup());
	}
	
	if ((backend_entry->domain_sid = (DOM_SID *)malloc(sizeof(DOM_SID))) == NULL) {
		DEBUG(0,("make_backend_entry: failed to malloc domain_sid\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	DEBUG(10,("looking up sid for domain %s\n", backend_entry->domain_name));
	
	if (!secrets_fetch_domain_sid(backend_entry->domain_name, backend_entry->domain_sid)) {
		DEBUG(2,("make_backend_entry: There is no SID stored for domain %s. Creating a new one.\n",
			backend_entry->domain_name));		
		DEBUG(0, ("FIXME in %s:%d\n", __FILE__, __LINE__));
		ZERO_STRUCTP(backend_entry->domain_sid);
	}
	
	DEBUG(5,("make_backend_entry: module name: %s, module parameters: %s, domain name: %s, domain sid: %s\n",
		backend_entry->module_name, backend_entry->module_params, backend_entry->domain_name, sid_string_static(backend_entry->domain_sid)));
	
	return NT_STATUS_OK;
}

/******************************************************************
 create sam_methods struct based on sam_backend_entry
 *****************************************************************/

static NTSTATUS make_sam_methods_backend_entry(SAM_CONTEXT *context, SAM_METHODS **methods_ptr, SAM_BACKEND_ENTRY *backend_entry)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	SAM_METHODS *methods;
	int i;

	DEBUG(5,("make_sam_methods_backend_entry: %d\n", __LINE__));

	if (!NT_STATUS_IS_OK(nt_status = make_sam_methods(context->mem_ctx, methods_ptr))) {
		return nt_status;
	}

	methods = *methods_ptr;
	methods->backendname = talloc_strdup(context->mem_ctx, backend_entry->module_name);
	methods->domain_name = talloc_strdup(context->mem_ctx, backend_entry->domain_name);
	sid_copy(&methods->domain_sid, backend_entry->domain_sid);
	methods->parent = context;

	DEBUG(5,("Attempting to find sam backend %s\n", backend_entry->module_name));
	for (i = 0; builtin_sam_init_functions[i].module_name; i++)
	{
		if (strequal(builtin_sam_init_functions[i].module_name, backend_entry->module_name))
		{
			DEBUG(5,("Found sam backend %s (at pos %d)\n", backend_entry->module_name, i));
			DEBUGADD(5,("initialising it with options=%s for domain %s\n", backend_entry->module_params, sid_string_static(backend_entry->domain_sid)));
			nt_status = builtin_sam_init_functions[i].init(methods, backend_entry->module_params);
			if (NT_STATUS_IS_OK(nt_status)) {
				DEBUG(5,("sam backend %s has a valid init\n", backend_entry->module_name));
			} else {
				DEBUG(2,("sam backend %s did not correctly init (error was %s)\n",
					backend_entry->module_name, nt_errstr(nt_status)));
			}
			return nt_status;
		}
	}
	
	DEBUG(2,("could not find backend %s\n", backend_entry->module_name));

	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS sam_context_check_default_backends(SAM_CONTEXT *context)
{
	SAM_BACKEND_ENTRY entry;
	DOM_SID *global_sam_sid  = get_global_sam_sid(); /* lp_workgroup doesn't play nicely with multiple domains */
	SAM_METHODS *methods, *tmpmethods;
	NTSTATUS ntstatus;
	
	DEBUG(5,("sam_context_check_default_backends: %d\n", __LINE__));

	/* Make sure domain lp_workgroup() is available */
	
	ntstatus = sam_get_methods_by_sid(context, &methods, &global_sid_Builtin);

	if (NT_STATUS_EQUAL(ntstatus, NT_STATUS_NO_SUCH_DOMAIN)) {
		DEBUG(4,("There was no backend specified for domain %s(%s); using %s\n",
			lp_workgroup(), sid_string_static(global_sam_sid), SAM_DEFAULT_BACKEND));

		SAM_ASSERT(global_sam_sid);

		entry.module_name = SAM_DEFAULT_BACKEND;
		entry.module_params = NULL;
		entry.domain_name = lp_workgroup();
		entry.domain_sid = (DOM_SID *)malloc(sizeof(DOM_SID));
		sid_copy(entry.domain_sid, global_sam_sid);

		if (!NT_STATUS_IS_OK(ntstatus = make_sam_methods_backend_entry(context, &methods, &entry))) {
			DEBUG(4,("make_sam_methods_backend_entry failed\n"));
			return ntstatus;
		}

		DLIST_ADD_END(context->methods, methods, tmpmethods);

	} else if (!NT_STATUS_IS_OK(ntstatus)) {
		DEBUG(2, ("sam_get_methods_by_sid failed for %s\n", lp_workgroup()));
		return ntstatus;
	}

	/* Make sure the BUILTIN domain is available */

	ntstatus = sam_get_methods_by_sid(context, &methods, global_sam_sid);
	
	if (NT_STATUS_EQUAL(ntstatus, NT_STATUS_NO_SUCH_DOMAIN)) {
		DEBUG(4,("There was no backend specified for domain BUILTIN; using %s\n", 
				 SAM_DEFAULT_BACKEND));
		entry.module_name = SAM_DEFAULT_BACKEND;
		entry.module_params = NULL;
		entry.domain_name = "BUILTIN";
		entry.domain_sid    = (DOM_SID *)malloc(sizeof(DOM_SID)); 
		sid_copy(entry.domain_sid, &global_sid_Builtin);

		if (!NT_STATUS_IS_OK(ntstatus = make_sam_methods_backend_entry(context, &methods,  &entry))) {
			DEBUG(4,("make_sam_methods_backend_entry failed\n"));
			return ntstatus;
		}

		DLIST_ADD_END(context->methods, methods, tmpmethods);
	} else if (!NT_STATUS_IS_OK(ntstatus)) {
		DEBUG(2, ("sam_get_methods_by_sid failed for BUILTIN\n"));
		return ntstatus;
	}

	return NT_STATUS_OK;
}

static NTSTATUS check_duplicate_backend_entries(SAM_BACKEND_ENTRY **backend_entries, int *nBackends)
{
	int i, j;
	
	DEBUG(5,("check_duplicate_backend_entries: %d\n", __LINE__));
	
	for (i = 0; i < *nBackends; i++) {
		for (j = i + 1; j < *nBackends; j++) {
			if (sid_equal((*backend_entries)[i].domain_sid, (*backend_entries)[j].domain_sid)) {
				DEBUG(0,("two backend modules claim the same domain %s\n",
					sid_string_static((*backend_entries)[j].domain_sid)));
				return NT_STATUS_INVALID_PARAMETER;			
			}
		}		
	}

	return NT_STATUS_OK;
}

NTSTATUS make_sam_context_list(SAM_CONTEXT **context, char **sam_backends_param)
{
	int i = 0, j = 0;
	SAM_METHODS *curmethods, *tmpmethods;
	int nBackends               = 0;
	SAM_BACKEND_ENTRY *backends = NULL;
	NTSTATUS nt_status          = NT_STATUS_UNSUCCESSFUL;

	DEBUG(5,("make_sam_context_from_conf: %d\n", __LINE__));

	if (!sam_backends_param) {
		DEBUG(1, ("no SAM backeds specified!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_sam_context(context))) {
		DEBUG(4,("make_sam_context failed\n"));
		return nt_status;
	}

	while (sam_backends_param[nBackends])
		nBackends++;

	DEBUG(6,("There are %d domains listed with their backends\n", nBackends));

	if ((backends = (SAM_BACKEND_ENTRY *)malloc(sizeof(*backends)*nBackends)) == NULL) {
		DEBUG(0,("make_sam_context_list: failed to allocate backends\n"));
		return NT_STATUS_NO_MEMORY;
	}

	memset(backends, '\0', sizeof(*backends)*nBackends);

	for (i = 0; i < nBackends; i++) {
		DEBUG(8,("processing %s\n",sam_backends_param[i]));
		if (!NT_STATUS_IS_OK(nt_status = make_backend_entry(&backends[i], sam_backends_param[i]))) {
			DEBUG(4,("make_backend_entry failed\n"));
			for (j = 0; j < nBackends; j++) SAFE_FREE(backends[j].domain_sid);
			SAFE_FREE(backends);
			free_sam_context(context);
			return nt_status;
		}
	}

	if (!NT_STATUS_IS_OK(nt_status = check_duplicate_backend_entries(&backends, &nBackends))) {
		DEBUG(4,("check_duplicate_backend_entries failed\n"));
		for (j = 0; j < nBackends; j++) SAFE_FREE(backends[j].domain_sid);
		SAFE_FREE(backends);
		free_sam_context(context);
		return nt_status;
	}

	for (i = 0; i < nBackends; i++) {
		if (!NT_STATUS_IS_OK(nt_status = make_sam_methods_backend_entry(*context, &curmethods,  &backends[i]))) {
			DEBUG(4,("make_sam_methods_backend_entry failed\n"));
			for (j = 0; j < nBackends; j++) SAFE_FREE(backends[j].domain_sid);
			SAFE_FREE(backends);
			free_sam_context(context);
			return nt_status;
		}
		DLIST_ADD_END((*context)->methods, curmethods, tmpmethods);
	}
	
	for (i = 0; i < nBackends; i++) SAFE_FREE(backends[i].domain_sid);

	SAFE_FREE(backends);
	return NT_STATUS_OK;
}

/******************************************************************
  Make a sam_context from scratch.
 *******************************************************************/

NTSTATUS make_sam_context(SAM_CONTEXT **context) 
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init_named("sam_context internal allocation context");

	if (!mem_ctx) {
		DEBUG(0, ("make_sam_context: talloc init failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}		

	*context = talloc(mem_ctx, sizeof(**context));
	if (!*context) {
		DEBUG(0, ("make_sam_context: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*context);

	(*context)->mem_ctx = mem_ctx;

	(*context)->free_fn = free_sam_context;

	return NT_STATUS_OK;
}

/******************************************************************
  Return an already initialised sam_context, to facilitate backward 
  compatibility (see functions below).
 *******************************************************************/

static struct sam_context *sam_get_static_context(BOOL reload) 
{
	static SAM_CONTEXT *sam_context = NULL;

	if ((sam_context) && (reload)) {
		sam_context->free_fn(&sam_context);
		sam_context = NULL;
	}

	if (!sam_context) {
		if (!NT_STATUS_IS_OK(make_sam_context_list(&sam_context, lp_sam_backend()))) {
			DEBUG(4,("make_sam_context_list failed\n"));
			return NULL;
		}

		/* Make sure the required domains (default domain, builtin) are available */
		if (!NT_STATUS_IS_OK(sam_context_check_default_backends(sam_context))) {
			DEBUG(4,("sam_context_check_default_backends failed\n"));
			return NULL;
		}
	}

	return sam_context;
}

/***************************************************************
  Initialize the static context (at smbd startup etc). 

  If uninitialised, context will auto-init on first use.
 ***************************************************************/

BOOL initialize_sam(BOOL reload)
{	
	return (sam_get_static_context(reload) != NULL);
}


/**************************************************************
 External API.  This is what the rest of the world calls...
***************************************************************/

/******************************************************************
  sam_* functions are used to link the external SAM interface
  with the internal backends. These functions lookup the appropriate
  backends for the domain and pass on to the function in sam_methods
  in the selected backend

  When the context parmater is NULL, the default is used.
 *******************************************************************/

#define SAM_SETUP_CONTEXT if (!context) \
		context = sam_get_static_context(False);\
	if (!context) {\
		return NT_STATUS_UNSUCCESSFUL; \
	}\
	


NTSTATUS sam_get_sec_desc(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS        nt_status;

	DEBUG(5,("sam_get_sec_desc: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, sid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_sec_desc) {
		DEBUG(3, ("sam_get_sec_desc: sam_methods of the domain did not specify sam_get_sec_desc\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_sec_desc(tmp_methods, access_token, sid, sd))) {
		DEBUG(4,("sam_get_sec_desc for %s in backend %s failed\n", sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_set_sec_desc(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_set_sec_desc: %d\n", __LINE__));
	
	SAM_SETUP_CONTEXT;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, sid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_set_sec_desc) {
		DEBUG(3, ("sam_set_sec_desc: sam_methods of the domain did not specify sam_set_sec_desc\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_set_sec_desc(tmp_methods, access_token, sid, sd))) {
		DEBUG(4,("sam_set_sec_desc for %s in backend %s failed\n", sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS sam_lookup_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const char *domain, const char *name, DOM_SID *sid, uint32 *type)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_lookup_name: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_lookup_name) {
		DEBUG(3, ("sam_lookup_name: sam_methods of the domain did not specify sam_lookup_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_lookup_name(tmp_methods, access_token, name, sid, type))) {
		DEBUG(4,("sam_lookup_name for %s\\%s in backend %s failed\n",
				 tmp_methods->domain_name, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_lookup_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, TALLOC_CTX *mem_ctx, const DOM_SID *sid, char **name, uint32 *type)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	DOM_SID		domainsid;

	DEBUG(5,("sam_lookup_sid: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	sid_copy(&domainsid, sid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("sam_lookup_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_lookup_sid) {
		DEBUG(3, ("sam_lookup_sid: sam_methods of the domain did not specify sam_lookup_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_lookup_sid(tmp_methods, access_token, mem_ctx, sid, name, type))) {
		DEBUG(4,("sam_lookup_name for %s in backend %s failed\n",
				 sid_string_static(sid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS sam_update_domain(const SAM_CONTEXT *context, const SAM_DOMAIN_HANDLE *domain)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;

	DEBUG(5,("sam_update_domain: %d\n", __LINE__));
	
	SAM_SETUP_CONTEXT;

	/* invalid domain specified */
	SAM_ASSERT(domain && domain->current_sam_methods);
	
	tmp_methods = domain->current_sam_methods;
	
	if (!tmp_methods->sam_update_domain) {
		DEBUG(3, ("sam_update_domain: sam_methods of the domain did not specify sam_update_domain\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_update_domain(tmp_methods, domain))){
		DEBUG(4,("sam_update_domain in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_enum_domains(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, int32 *domain_count, DOM_SID **domains, char ***domain_names)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	 nt_status;

	SEC_DESC	*sd;
	size_t		sd_size;
	uint32		acc_granted;
	int		i = 0;

	DEBUG(5,("sam_enum_domains: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	/* invalid parmaters specified */
	SAM_ASSERT(domain_count && domains && domain_names);

	if (!NT_STATUS_IS_OK(nt_status = samr_make_sam_obj_sd(context->mem_ctx, &sd, &sd_size))) {
		DEBUG(4,("samr_make_sam_obj_sd failed\n"));
		return nt_status;
	}

	if (!se_access_check(sd, access_token, SA_RIGHT_SAM_ENUM_DOMAINS, &acc_granted, &nt_status)) {
		DEBUG(3,("sam_enum_domains: ACCESS DENIED\n"));
			return nt_status;
	}

	tmp_methods= context->methods;
	*domain_count = 0;

	while (tmp_methods) {
		(*domain_count)++;
		tmp_methods= tmp_methods->next;
	}

	DEBUG(6,("sam_enum_domains: enumerating %d domains\n", (*domain_count)));

	tmp_methods = context->methods;

	if (((*domains) = malloc( sizeof(DOM_SID) * (*domain_count))) == NULL) {
		DEBUG(0,("sam_enum_domains: Out of memory allocating domain SID list\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (((*domain_names) = malloc( sizeof(char*) * (*domain_count))) == NULL) {
		DEBUG(0,("sam_enum_domains: Out of memory allocating domain name list\n"));
		SAFE_FREE((*domains));
		return NT_STATUS_NO_MEMORY;
	}

	while (tmp_methods) {
		DEBUGADD(7,("    [%d] %s: %s\n", i, tmp_methods->domain_name, sid_string_static(&tmp_methods->domain_sid)));
		sid_copy(domains[i],&tmp_methods->domain_sid);
		*domain_names[i] = smb_xstrdup(tmp_methods->domain_name);
		i++;
		tmp_methods= tmp_methods->next;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_lookup_domain(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const char *domain, DOM_SID **domainsid)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	SEC_DESC	*sd;
	size_t		sd_size;
	uint32		acc_granted;

	DEBUG(5,("sam_lookup_domain: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	/* invalid paramters */
	SAM_ASSERT(access_token && domain && domainsid);

	if (!NT_STATUS_IS_OK(nt_status = samr_make_sam_obj_sd(context->mem_ctx, &sd, &sd_size))) {
		DEBUG(4,("samr_make_sam_obj_sd failed\n"));
		return nt_status;
	}

	if (!se_access_check(sd, access_token, SA_RIGHT_SAM_OPEN_DOMAIN, &acc_granted, &nt_status)) {
		DEBUG(3,("sam_lookup_domain: ACCESS DENIED\n"));
			return nt_status;
	}

	tmp_methods= context->methods;

	while (tmp_methods) {
		if (strcmp(domain, tmp_methods->domain_name) == 0) {
			(*domainsid) = (DOM_SID *)malloc(sizeof(DOM_SID));
			sid_copy((*domainsid), &tmp_methods->domain_sid);
			return NT_STATUS_OK;
		}
		tmp_methods= tmp_methods->next;
	}

	return NT_STATUS_NO_SUCH_DOMAIN;
}


NTSTATUS sam_get_domain_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *domainsid, SAM_DOMAIN_HANDLE **domain)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_get_domain_by_sid: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domainsid && domain);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_domain_handle) {
		DEBUG(3, ("sam_get_domain_by_sid: sam_methods of the domain did not specify sam_get_domain_handle\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_domain_handle(tmp_methods, access_token, access_desired, domain))) {
		DEBUG(4,("sam_get_domain_handle for %s in backend %s failed\n",
				 sid_string_static(domainsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_create_account(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *domainsid, const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_create_account: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	/* invalid parmaters */
	SAM_ASSERT(access_token && domainsid && account_name && account);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_create_account) {
		DEBUG(3, ("sam_create_account: sam_methods of the domain did not specify sam_create_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_create_account(tmp_methods, access_token, access_desired, account_name, acct_ctrl, account))) {
		DEBUG(4,("sam_create_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_add_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	DOM_SID		domainsid;
	const DOM_SID		*accountsid;
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	
	DEBUG(5,("sam_add_account: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	/* invalid parmaters */
	SAM_ASSERT(account);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_account_sid(account, &accountsid))) {
		DEBUG(0,("Can't get account SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_add_account) {
		DEBUG(3, ("sam_add_account: sam_methods of the domain did not specify sam_add_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_add_account(tmp_methods, account))){
		DEBUG(4,("sam_add_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_update_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	DEBUG(5,("sam_update_account: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	/* invalid account specified */
	SAM_ASSERT(account && account->current_sam_methods);
	
	tmp_methods = account->current_sam_methods;
		
	if (!tmp_methods->sam_update_account) {
		DEBUG(3, ("sam_update_account: sam_methods of the domain did not specify sam_update_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_update_account(tmp_methods, account))){
		DEBUG(4,("sam_update_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_delete_account(const SAM_CONTEXT *context, const SAM_ACCOUNT_HANDLE *account)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	DEBUG(5,("sam_delete_account: %d\n", __LINE__));
	
	SAM_SETUP_CONTEXT;

	/* invalid account specified */
	SAM_ASSERT(account && account->current_sam_methods);
	
	tmp_methods = account->current_sam_methods;

	if (!tmp_methods->sam_delete_account) {
		DEBUG(3, ("sam_delete_account: sam_methods of the domain did not specify sam_delete_account\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_delete_account(tmp_methods, account))){
		DEBUG(4,("sam_delete_account in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_enum_accounts(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, uint16 acct_ctrl, int32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_enum_accounts: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domainsid && account_count && accounts);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_enum_accounts) {
		DEBUG(3, ("sam_enum_accounts: sam_methods of the domain did not specify sam_enum_accounts\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_enum_accounts(tmp_methods, access_token, acct_ctrl, account_count, accounts))) {
		DEBUG(4,("sam_enum_accounts for domain %s in backend %s failed\n",
				 tmp_methods->domain_name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}


NTSTATUS sam_get_account_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	DOM_SID		domainsid;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_get_account_by_sid: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && accountsid && account);

	sid_copy(&domainsid, accountsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("sam_get_account_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}


	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_account_by_sid) {
		DEBUG(3, ("sam_get_account_by_sid: sam_methods of the domain did not specify sam_get_account_by_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_account_by_sid(tmp_methods, access_token, access_desired, accountsid, account))) {
		DEBUG(4,("sam_get_account_by_sid for %s in backend %s failed\n",
				 sid_string_static(accountsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_get_account_by_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *domain, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_get_account_by_name: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domain && name && account);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_account_by_name) {
		DEBUG(3, ("sam_get_account_by_name: sam_methods of the domain did not specify sam_get_account_by_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_account_by_name(tmp_methods, access_token, access_desired, name, account))) {
		DEBUG(4,("sam_get_account_by_name for %s\\%s in backend %s failed\n",
				 domain, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_create_group(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *domainsid, const char *group_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_create_group: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domainsid && group_name && group);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_create_group) {
		DEBUG(3, ("sam_create_group: sam_methods of the domain did not specify sam_create_group\n"));
		return NT_STATUS_UNSUCCESSFUL; 
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_create_group(tmp_methods, access_token, access_desired, group_name, group_ctrl, group))) {
		DEBUG(4,("sam_create_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_add_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	DOM_SID		domainsid;
	const DOM_SID		*groupsid;
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	
	DEBUG(5,("sam_add_group: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(group);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_group_sid(group, &groupsid))) {
		DEBUG(0,("Can't get group SID\n"));
		return nt_status;
	}

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_add_group) {
		DEBUG(3, ("sam_add_group: sam_methods of the domain did not specify sam_add_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_add_group(tmp_methods, group))){
		DEBUG(4,("sam_add_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_update_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	DEBUG(5,("sam_update_group: %d\n", __LINE__));
	
	SAM_SETUP_CONTEXT;

	/* invalid group specified */
	SAM_ASSERT(group && group->current_sam_methods);
	
	tmp_methods = group->current_sam_methods;
	
	if (!tmp_methods->sam_update_group) {
		DEBUG(3, ("sam_update_group: sam_methods of the domain did not specify sam_update_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_update_group(tmp_methods, group))){
		DEBUG(4,("sam_update_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_delete_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	DEBUG(5,("sam_delete_group: %d\n", __LINE__));
	
	SAM_SETUP_CONTEXT;

	/* invalid group specified */
	SAM_ASSERT(group && group->current_sam_methods);
	
	tmp_methods = group->current_sam_methods;

	if (!tmp_methods->sam_delete_group) {
		DEBUG(3, ("sam_delete_group: sam_methods of the domain did not specify sam_delete_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_delete_group(tmp_methods, group))){
		DEBUG(4,("sam_delete_group in backend %s failed\n",
				 tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_enum_groups(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID *domainsid, uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_enum_groups: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domainsid && groups_count && groups);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_enum_accounts) {
		DEBUG(3, ("sam_enum_groups: sam_methods of the domain did not specify sam_enum_groups\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_enum_groups(tmp_methods, access_token, group_ctrl, groups_count, groups))) {
		DEBUG(4,("sam_enum_groups for domain %s in backend %s failed\n",
				 tmp_methods->domain_name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_by_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	uint32		rid;
	NTSTATUS	nt_status;
	DOM_SID		domainsid;

	DEBUG(5,("sam_get_group_by_sid: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && groupsid && group);

	sid_copy(&domainsid, groupsid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(3,("sam_get_group_by_sid: failed to split the sid\n"));
		return NT_STATUS_INVALID_SID;
	}


	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_sid(context, &tmp_methods, &domainsid))) {
		DEBUG(4,("sam_get_methods_by_sid failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_group_by_sid) {
		DEBUG(3, ("sam_get_group_by_sid: sam_methods of the domain did not specify sam_get_group_by_sid\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_group_by_sid(tmp_methods, access_token, access_desired, groupsid, group))) {
		DEBUG(4,("sam_get_group_by_sid for %s in backend %s failed\n",
				 sid_string_static(groupsid), tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_get_group_by_name(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *domain, const char *name, SAM_GROUP_HANDLE **group)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;

	DEBUG(5,("sam_get_group_by_name: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;

	SAM_ASSERT(access_token && domain && name && group);

	if (!NT_STATUS_IS_OK(nt_status = sam_get_methods_by_name(context, &tmp_methods, domain))) {
		DEBUG(4,("sam_get_methods_by_name failed\n"));
		return nt_status;
	}

	if (!tmp_methods->sam_get_group_by_name) {
		DEBUG(3, ("sam_get_group_by_name: sam_methods of the domain did not specify sam_get_group_by_name\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_group_by_name(tmp_methods, access_token, access_desired, name, group))) {
		DEBUG(4,("sam_get_group_by_name for %s\\%s in backend %s failed\n",
				 domain, name, tmp_methods->backendname));
		return nt_status;
	}

	return NT_STATUS_OK;
}

NTSTATUS sam_add_member_to_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	SAM_SETUP_CONTEXT;
	
	/* invalid group or member specified */
	SAM_ASSERT(group && group->current_sam_methods && member);
	
	tmp_methods = group->current_sam_methods;
			
	if (!tmp_methods->sam_add_member_to_group) {
		DEBUG(3, ("sam_add_member_to_group: sam_methods of the domain did not specify sam_add_member_to_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	
	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_add_member_to_group(tmp_methods, group, member))) {
		DEBUG(4,("sam_add_member_to_group in backend %s failed\n", tmp_methods->backendname));
		return nt_status;
	}
	
	return NT_STATUS_OK;	
	
}

NTSTATUS sam_delete_member_from_group(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;

	SAM_SETUP_CONTEXT;
	
	/* invalid group or member specified */
	SAM_ASSERT(group && group->current_sam_methods && member);
	
	tmp_methods = group->current_sam_methods;
	
	if (!tmp_methods->sam_delete_member_from_group) {
		DEBUG(3, ("sam_delete_member_from_group: sam_methods of the domain did not specify sam_delete_member_from_group\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	
	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_delete_member_from_group(tmp_methods, group, member))) {
		DEBUG(4,("sam_delete_member_from_group in backend %s failed\n", tmp_methods->backendname));
		return nt_status;
	}
	
	return NT_STATUS_OK;	
}

NTSTATUS sam_enum_groupmembers(const SAM_CONTEXT *context, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	const SAM_METHODS *tmp_methods;
	NTSTATUS     nt_status;
	
	SAM_SETUP_CONTEXT;
	
	/* invalid group specified */
	SAM_ASSERT(group && group->current_sam_methods && members_count && members);
	
	tmp_methods = group->current_sam_methods;

	if (!tmp_methods->sam_enum_groupmembers) {
		DEBUG(3, ("sam_enum_groupmembers: sam_methods of the domain did not specify sam_enum_group_members\n"));
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	
	if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_enum_groupmembers(tmp_methods, group, members_count, members))) {
		DEBUG(4,("sam_enum_groupmembers in backend %s failed\n", tmp_methods->backendname));
		return nt_status;
	}
	
	return NT_STATUS_OK;	
}

NTSTATUS sam_get_groups_of_sid(const SAM_CONTEXT *context, const NT_USER_TOKEN *access_token, const DOM_SID **sids, uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	SAM_METHODS	*tmp_methods;
	NTSTATUS	nt_status;
	
	uint32          tmp_group_count;
	SAM_GROUP_ENUM *tmp_groups;
	
	DEBUG(5,("sam_get_groups_of_sid: %d\n", __LINE__));

	SAM_SETUP_CONTEXT;
	
	/* invalid sam_context specified */
	SAM_ASSERT(access_token && sids && context && context->methods);
	
	*group_count = 0;
	
	*groups = NULL;

	tmp_methods= context->methods;

	while (tmp_methods) {
		DEBUG(5,("getting groups from domain \n"));
		if (!tmp_methods->sam_get_groups_of_sid) {
			DEBUG(3, ("sam_get_groups_of_sid: sam_methods of domain did not specify sam_get_groups_of_sid\n"));
			SAFE_FREE(*groups);
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		
		if (!NT_STATUS_IS_OK(nt_status = tmp_methods->sam_get_groups_of_sid(tmp_methods, access_token, sids, group_ctrl, &tmp_group_count, &tmp_groups))) {
			DEBUG(4,("sam_get_groups_of_sid in backend %s failed\n", tmp_methods->backendname));
			SAFE_FREE(*groups);
			return nt_status;
		}
		
		*groups = Realloc(*groups, ((*group_count)  + tmp_group_count) * sizeof(SAM_GROUP_ENUM));

		memcpy(&(*groups)[*group_count], tmp_groups, tmp_group_count);		
		
		SAFE_FREE(tmp_groups);
		
		*group_count += tmp_group_count;
		
		tmp_methods = tmp_methods->next;
	}
	
	return NT_STATUS_OK;	
}



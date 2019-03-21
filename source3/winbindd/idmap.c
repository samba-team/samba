/*
   Unix SMB/CIFS implementation.
   ID Mapping
   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com>	2003
   Copyright (C) Simo Sorce 2003-2007
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Michael Adam 2010

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
#include "idmap.h"
#include "lib/util_sid_passdb.h"
#include "libcli/security/dom_sid.h"
#include "passdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

static_decl_idmap;

/**
 * Pointer to the backend methods. Modules register themselves here via
 * smb_register_idmap.
 */

struct idmap_backend {
	const char *name;
	const struct idmap_methods *methods;
	struct idmap_backend *prev, *next;
};
static struct idmap_backend *backends = NULL;

/**
 * Default idmap domain configured via "idmap backend".
 */
static struct idmap_domain *default_idmap_domain;

/**
 * Passdb idmap domain, not configurable. winbind must always give passdb a
 * chance to map ids.
 */
static struct idmap_domain *passdb_idmap_domain;

/**
 * List of specially configured idmap domains. This list is filled on demand
 * in the winbind idmap child when the parent winbind figures out via the
 * special range parameter or via the domain SID that a special "idmap config
 * domain" configuration is present.
 */
static struct idmap_domain **idmap_domains = NULL;
static int num_domains = 0;

static struct idmap_domain *idmap_init_named_domain(TALLOC_CTX *mem_ctx,
						    const char *domname);
static struct idmap_domain *idmap_init_domain(TALLOC_CTX *mem_ctx,
					      const char *domainname,
					      const char *modulename,
					      bool check_range);

struct lp_scan_idmap_domains_state {
	bool (*fn)(const char *domname, void *private_data);
	void *private_data;
};

static bool lp_scan_idmap_found_domain(
	const char *string, regmatch_t matches[], void *private_data);

bool lp_scan_idmap_domains(bool (*fn)(const char *domname,
				      void *private_data),
			   void *private_data)
{
	struct lp_scan_idmap_domains_state state = {
		.fn = fn, .private_data = private_data };
	int ret;

	ret = lp_wi_scan_global_parametrics(
		"idmapconfig\\(.*\\):backend", 2,
		lp_scan_idmap_found_domain, &state);
	if (ret != 0) {
		DBG_WARNING("wi_scan_global_parametrics returned %d\n", ret);
		return false;
	}

	return true;
}

static bool lp_scan_idmap_found_domain(
	const char *string, regmatch_t matches[], void *private_data)
{
	bool ok;

	if (matches[1].rm_so == -1) {
		DBG_WARNING("Found match, but no name??\n");
		return false;
	}
	if (matches[1].rm_eo <= matches[1].rm_so) {
		DBG_WARNING("Invalid match\n");
		return false;
	}

	{
		struct lp_scan_idmap_domains_state *state = private_data;
		regoff_t len = matches[1].rm_eo - matches[1].rm_so;
		char domname[len+1];

		memcpy(domname, string + matches[1].rm_so, len);
		domname[len] = '\0';

		DBG_DEBUG("Found idmap domain \"%s\"\n", domname);

		ok = state->fn(domname, state->private_data);
	}

	return ok;
}

static bool idmap_found_domain_backend(const char *domname,
				       void *private_data);

static bool idmap_init(void)
{
	static bool initialized;
	bool ok;

	if (initialized) {
		return true;
	}

	DEBUG(10, ("idmap_init(): calling static_init_idmap\n"));

	static_init_idmap(NULL);

	initialized = true;

	if (!pdb_is_responsible_for_everything_else()) {
		default_idmap_domain = idmap_init_named_domain(NULL, "*");
		if (default_idmap_domain == NULL) {
			return false;
		}
	}

	passdb_idmap_domain = idmap_init_domain(
		NULL, get_global_sam_name(), "passdb", false);
	if (passdb_idmap_domain == NULL) {
		TALLOC_FREE(default_idmap_domain);
		return false;
	}

	idmap_domains = talloc_array(NULL, struct idmap_domain *, 0);
	if (idmap_domains == NULL) {
		TALLOC_FREE(passdb_idmap_domain);
		TALLOC_FREE(default_idmap_domain);
		return false;
	}

	ok = lp_scan_idmap_domains(idmap_found_domain_backend, NULL);
	if (!ok) {
		DBG_WARNING("lp_scan_idmap_domains failed\n");
		return false;
	}

	return true;
}

const char *idmap_config_const_string(const char *domname, const char *option,
				      const char *def)
{
	int len = snprintf(NULL, 0, "idmap config %s", domname);

	if (len == -1) {
		return NULL;
	}
	{
		char config_option[len+1];
		snprintf(config_option, sizeof(config_option),
			 "idmap config %s", domname);
		return lp_parm_const_string(-1, config_option, option, def);
	}
}

bool idmap_config_bool(const char *domname, const char *option, bool def)
{
	int len = snprintf(NULL, 0, "idmap config %s", domname);

	if (len == -1) {
		return def;
	}
	{
		char config_option[len+1];
		snprintf(config_option, sizeof(config_option),
			 "idmap config %s", domname);
		return lp_parm_bool(-1, config_option, option, def);
	}
}

int idmap_config_int(const char *domname, const char *option, int def)
{
	int len = snprintf(NULL, 0, "idmap config %s", domname);

	if (len == -1) {
		return def;
	}
	{
		char config_option[len+1];
		snprintf(config_option, sizeof(config_option),
			 "idmap config %s", domname);
		return lp_parm_int(-1, config_option, option, def);
	}
}

bool domain_has_idmap_config(const char *domname)
{
	int i;
	const char *range = NULL;
	const char *backend = NULL;
	bool ok;

	ok = idmap_init();
	if (!ok) {
		return false;
	}

	for (i=0; i<num_domains; i++) {
		if (strequal(idmap_domains[i]->name, domname)) {
			return true;
		}
	}

	/* fallback: also check loadparm */

	range = idmap_config_const_string(domname, "range", NULL);
	backend = idmap_config_const_string(domname, "backend", NULL);
	if (range != NULL && backend != NULL) {
		DEBUG(5, ("idmap configuration specified for domain '%s'\n",
			domname));
		return true;
	}

	return false;
}

static bool idmap_found_domain_backend(const char *domname,
				       void *private_data)
{
	struct idmap_domain *dom, **tmp;

	DBG_DEBUG("Found idmap domain \"%s\"\n", domname);

	if (strcmp(domname, "*") == 0) {
		return false;
	}

	dom = idmap_init_named_domain(idmap_domains, domname);
	if (dom == NULL) {
		DBG_NOTICE("Could not init idmap domain %s\n", domname);
		return false;
	}

	tmp = talloc_realloc(idmap_domains, idmap_domains,
			     struct idmap_domain *, num_domains + 1);
	if (tmp == NULL) {
		DBG_WARNING("talloc_realloc failed\n");
		TALLOC_FREE(dom);
		return false;
	}
	idmap_domains = tmp;
	idmap_domains[num_domains] = dom;
	num_domains += 1;

	return false;
}

static const struct idmap_methods *get_methods(const char *name)
{
	struct idmap_backend *b;

	for (b = backends; b; b = b->next) {
		if (strequal(b->name, name)) {
			return b->methods;
		}
	}

	return NULL;
}

bool idmap_is_offline(void)
{
	return ( lp_winbind_offline_logon() &&
	     get_global_winbindd_state_offline() );
}

/**********************************************************************
 Allow a module to register itself as a method.
**********************************************************************/

NTSTATUS smb_register_idmap(int version, const char *name,
			    const struct idmap_methods *methods)
{
	struct idmap_backend *entry;

 	if ((version != SMB_IDMAP_INTERFACE_VERSION)) {
		DEBUG(0, ("Failed to register idmap module.\n"
		          "The module was compiled against "
			  "SMB_IDMAP_INTERFACE_VERSION %d,\n"
		          "current SMB_IDMAP_INTERFACE_VERSION is %d.\n"
		          "Please recompile against the current version "
			  "of samba!\n",
			  version, SMB_IDMAP_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
  	}

	if (!name || !name[0] || !methods) {
		DEBUG(0,("Called with NULL pointer or empty name!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (entry = backends; entry != NULL; entry = entry->next) {
		if (strequal(entry->name, name)) {
			DEBUG(5,("Idmap module %s already registered!\n",
				 name));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}

	entry = talloc(NULL, struct idmap_backend);
	if ( ! entry) {
		DEBUG(0,("Out of memory!\n"));
		TALLOC_FREE(entry);
		return NT_STATUS_NO_MEMORY;
	}
	entry->name = talloc_strdup(entry, name);
	if ( ! entry->name) {
		DEBUG(0,("Out of memory!\n"));
		TALLOC_FREE(entry);
		return NT_STATUS_NO_MEMORY;
	}
	entry->methods = methods;

	DLIST_ADD(backends, entry);
	DEBUG(5, ("Successfully added idmap backend '%s'\n", name));
	return NT_STATUS_OK;
}

/**
 * Initialize a domain structure
 * @param[in] mem_ctx		memory context for the result
 * @param[in] domainname	which domain is this for
 * @param[in] modulename	which backend module
 * @param[in] check_range	whether range checking should be done
 * @result The initialized structure
 */
static struct idmap_domain *idmap_init_domain(TALLOC_CTX *mem_ctx,
					      const char *domainname,
					      const char *modulename,
					      bool check_range)
{
	struct idmap_domain *result;
	NTSTATUS status;
	const char *range;
	unsigned low_id = 0;
	unsigned high_id = 0;

	result = talloc_zero(mem_ctx, struct idmap_domain);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->name = talloc_strdup(result, domainname);
	if (result->name == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	/*
	 * Check whether the requested backend module exists and
	 * load the methods.
	 */

	result->methods = get_methods(modulename);
	if (result->methods == NULL) {
		DEBUG(3, ("idmap backend %s not found\n", modulename));

		status = smb_probe_module("idmap", modulename);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Could not probe idmap module %s\n",
				  modulename));
			goto fail;
		}

		result->methods = get_methods(modulename);
	}
	if (result->methods == NULL) {
		DEBUG(1, ("idmap backend %s not found\n", modulename));
		goto fail;
	}

	/*
	 * load ranges and read only information from the config
	 */

	result->read_only = idmap_config_bool(result->name, "read only", false);
	range = idmap_config_const_string(result->name, "range", NULL);

	if (range == NULL) {
		if (check_range) {
			DEBUG(1, ("idmap range not specified for domain %s\n",
				  result->name));
			goto fail;
		}
	} else if (sscanf(range, "%u - %u", &low_id, &high_id) != 2)
	{
		DEBUG(1, ("invalid range '%s' specified for domain "
			  "'%s'\n", range, result->name));
		if (check_range) {
			goto fail;
		}
	} else if (low_id > high_id) {
		DEBUG(1, ("Error: invalid idmap range detected: %u - %u\n",
			  low_id, high_id));
		if (check_range) {
			goto fail;
		}
	}

	result->low_id = low_id;
	result->high_id = high_id;

	status = result->methods->init(result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("idmap initialization returned %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	return result;

fail:
	TALLOC_FREE(result);
	return NULL;
}

/**
 * Initialize a named domain structure
 * @param[in] mem_ctx		memory context for the result
 * @param[in] domname		the domain name
 * @result The default domain structure
 *
 * This routine looks at the "idmap config <domname>" parameters to figure out
 * the configuration.
 */

static struct idmap_domain *idmap_init_named_domain(TALLOC_CTX *mem_ctx,
						    const char *domname)
{
	struct idmap_domain *result = NULL;
	const char *backend;
	bool ok;

	ok = idmap_init();
	if (!ok) {
		return NULL;
	}

	backend = idmap_config_const_string(domname, "backend", NULL);
	if (backend == NULL) {
		DEBUG(10, ("no idmap backend configured for domain '%s'\n",
			   domname));
		goto fail;
	}

	result = idmap_init_domain(mem_ctx, domname, backend, true);
	if (result == NULL) {
		goto fail;
	}

	return result;

fail:
	TALLOC_FREE(result);
	return NULL;
}

/**
 * Find a domain struct according to a domain name
 * @param[in] domname		Domain name to get the config for
 * @result The default domain structure that fits
 *
 * This is the central routine in the winbindd-idmap child to pick the correct
 * domain for looking up IDs. If domname is NULL or empty, we use the default
 * domain. If it contains something, we try to use idmap_init_named_domain()
 * to fetch the correct backend.
 *
 * The choice about "domname" is being made by the winbind parent, look at the
 * "have_idmap_config" of "struct winbindd_domain" which is set in
 * add_trusted_domain.
 */

struct idmap_domain *idmap_find_domain(const char *domname)
{
	bool ok;
	int i;

	DEBUG(10, ("idmap_find_domain called for domain '%s'\n",
		   domname?domname:"NULL"));

	ok = idmap_init();
	if (!ok) {
		return NULL;
	}

	if ((domname == NULL) || (domname[0] == '\0')) {
		return default_idmap_domain;
	}

	for (i=0; i<num_domains; i++) {
		if (strequal(idmap_domains[i]->name, domname)) {
			return idmap_domains[i];
		}
	}

	return default_idmap_domain;
}

struct idmap_domain *idmap_find_domain_with_sid(const char *domname,
						const struct dom_sid *sid)
{
	bool ok;

	ok = idmap_init();
	if (!ok) {
		return NULL;
	}

	if (sid_check_is_for_passdb(sid)) {
		return passdb_idmap_domain;
	}

	return idmap_find_domain(domname);
}

void idmap_close(void)
{
	TALLOC_FREE(default_idmap_domain);
	TALLOC_FREE(passdb_idmap_domain);
	TALLOC_FREE(idmap_domains);
	num_domains = 0;
}

/**************************************************************************
 idmap allocator interface functions
**************************************************************************/

static NTSTATUS idmap_allocate_unixid(struct unixid *id)
{
	struct idmap_domain *dom;
	NTSTATUS ret;

	dom = idmap_find_domain(NULL);

	if (dom == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (dom->methods->allocate_id == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ret = dom->methods->allocate_id(dom, id);

	return ret;
}


NTSTATUS idmap_allocate_uid(struct unixid *id)
{
	id->type = ID_TYPE_UID;
	return idmap_allocate_unixid(id);
}

NTSTATUS idmap_allocate_gid(struct unixid *id)
{
	id->type = ID_TYPE_GID;
	return idmap_allocate_unixid(id);
}

NTSTATUS idmap_backend_unixids_to_sids(struct id_map **maps,
				       const char *domain_name,
				       struct dom_sid domain_sid)
{
	struct idmap_domain *dom = NULL;
	NTSTATUS status;
	bool ok;

	ok = idmap_init();
	if (!ok) {
		return NT_STATUS_NONE_MAPPED;
	}

	if (strequal(domain_name, get_global_sam_name())) {
		dom = passdb_idmap_domain;
	}
	if (dom == NULL) {
		dom = idmap_find_domain(domain_name);
	}
	if (dom == NULL) {
		return NT_STATUS_NONE_MAPPED;
	}

	dom->dom_sid = domain_sid;
	status = dom->methods->unixids_to_sids(dom, maps);

	DBG_DEBUG("unixid_to_sids for domain %s returned %s\n",
		  domain_name, nt_errstr(status));

	return status;
}

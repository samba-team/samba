/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   
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

#include "winbindd.h"
#include "sids.h"

/**
 * @file winbindd_util.c
 *
 * Winbind daemon for NT domain authentication nss module.
 **/


/**
 * Used to clobber name fields that have an undefined value.
 *
 * Correct code should never look at a field that has this value.
 **/

static const fstring name_deadbeef = "<deadbeef>";

/* The list of trusted domains.  Note that the list can be deleted and
   recreated using the init_domain_list() function so pointers to
   individual winbindd_domain structures cannot be made.  Keep a copy of
   the domain name instead. */

static struct winbindd_domain *_domain_list;

struct winbindd_domain *domain_list(void)
{
	/* Initialise list */

	if (!_domain_list)
		init_domain_list();

	return _domain_list;
}

/* Free all entries in the trusted domain list */

void free_domain_list(void)
{
	struct winbindd_domain *domain = _domain_list;

	while(domain) {
		struct winbindd_domain *next = domain->next;
		
		DLIST_REMOVE(_domain_list, domain);
		SAFE_FREE(domain);
		domain = next;
	}
}


/* Add a trusted domain to our list of domains */

static struct winbindd_domain *add_trusted_domain(const char *domain_name,
						  struct winbindd_methods *methods)
{
	struct winbindd_domain *domain;
        
	/* We can't call domain_list() as this function is called from
	   init_domain_list() and we'll get stuck in a loop. */

	for (domain = _domain_list; domain; domain = domain->next) {
		if (strcmp(domain_name, domain->name) == 0) {
			DEBUG(3, ("domain %s already in domain list\n", 
				  domain_name));
			return domain;
		}
	}
        
	/* Create new domain entry */

	if ((domain = (struct winbindd_domain *)
	     malloc(sizeof(*domain))) == NULL)
		return NULL;

	/* Fill in fields */
        
	ZERO_STRUCTP(domain);

	fstrcpy(domain->name, domain_name);
	domain->methods = methods;
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	
	/* see if this is a native mode win2k domain, but only for our own domain */
	   
	if ( strequal_unix( lp_workgroup_unix(), domain_name) )	{
		domain->native_mode = cm_check_for_native_mode_win2k( domain_name );
		DEBUG(3,("add_trusted_domain: %s is a %s mode domain\n", domain_name,
					domain->native_mode ? "native" : "mixed" ));
	}

	/* Link to domain list */
        
	DLIST_ADD(_domain_list, domain);
        
	return domain;
}

/* Look up global info for the winbind daemon */

BOOL init_domain_list(void)
{
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	extern struct winbindd_methods cache_methods;
	struct winbindd_domain *domain;
	DOM_SID *dom_sids;
	char **names;
	int num_domains = 0;

	if (!(mem_ctx = talloc_init_named("init_domain_list")))
		return False;

	/* Free existing list */

	free_domain_list();

	/* Add ourselves as the first entry */

	domain = add_trusted_domain(lp_workgroup_unix(), &cache_methods);

	/* Now we *must* get the domain sid for our primary domain. Go into
	   a holding pattern until that is available */

	result = cache_methods.domain_sid(domain, &domain->sid);
	while (!NT_STATUS_IS_OK(result)) {

		sleep(10);
		DEBUG(1,("Retrying startup domain sid fetch for %s\n",
			 domain->name));
		result = cache_methods.domain_sid(domain, &domain->sid);

		/* If we don't call lp_talloc_free() here we end up 
		   accumulating memory in the "global" lp_talloc in
		   param/loadparm.c */

		lp_talloc_free();
	}
       
	DEBUG(1,("Added domain %s (%s)\n", 
		 domain->name, 
		 sid_string_static(&domain->sid)));

	DEBUG(1, ("getting trusted domain list\n"));

	result = cache_methods.trusted_domains(domain, mem_ctx, (uint *)&num_domains,
					       &names, &dom_sids);

	/* Add each domain to the trusted domain list */
	if (NT_STATUS_IS_OK(result)) {
		int i;
		for(i = 0; i < num_domains; i++) {
			domain = add_trusted_domain(names[i], &cache_methods);
			if (!domain) continue;
			sid_copy(&domain->sid, &dom_sids[i]);
			DEBUG(1,("Added domain %s (%s)\n", 
				 domain->name, 
				 sid_string_static(&domain->sid)));
		}
	}

	talloc_destroy(mem_ctx);
	return True;
}

/* Given a domain name, return the struct winbindd domain info for it 
   if it is actually working. */

struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (strequal_unix(domain_name, domain->name) ||
		    strequal_unix(domain_name, domain->full_name))
			return domain;
	}

	/* Not found */

	return NULL;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(DOM_SID *sid)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (sid_compare_domain(sid, &domain->sid) == 0)
			return domain;
	}

	/* Not found */

	return NULL;
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(struct winbindd_domain *domain, 
				 const char *name, DOM_SID *sid, 
				 enum SID_NAME_USE *type)
{
	NTSTATUS result;
        
	/* Don't bother with machine accounts */
        
	if (name[strlen(name) - 1] == '$')
		return False;

	/* Lookup name */
	result = domain->methods->name_to_sid(domain, name, sid, type);
        
	/* Return rid and type if lookup successful */
	if (!NT_STATUS_IS_OK(result)) {
		*type = SID_NAME_UNKNOWN;
	}

	return NT_STATUS_IS_OK(result);
}

/**
 * @brief Lookup a name in a domain from a sid.
 *
 * @param sid Security ID you want to look up.
 *
 * @param name On success, set to the name corresponding to @p sid.
 * 
 * @param dom_name On success, set to the 'domain name' corresponding to @p sid.
 * 
 * @param type On success, contains the type of name: alias, group or
 * user.
 *
 * @retval True if the name exists, in which case @p name and @p type
 * are set, otherwise False.
 **/
BOOL winbindd_lookup_name_by_sid(DOM_SID *sid,
				 fstring dom_name,
				 fstring name,
				 enum SID_NAME_USE *type)
{
	char *names;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	BOOL rv = False;
	struct winbindd_domain *domain;

	domain = find_domain_from_sid(sid);

	if (!domain) {
		DEBUG(1,("Can't find domain from sid\n"));
		return False;
	}

	/* Lookup name */

	if (!(mem_ctx = talloc_init_named("winbindd_lookup_name_by_sid")))
		return False;
        
	result = domain->methods->sid_to_name(domain, mem_ctx, sid, &names, type);

	/* Return name and type if successful */
        
	if ((rv = NT_STATUS_IS_OK(result))) {
		fstrcpy(dom_name, domain->name);
		fstrcpy(name, names);
	} else {
		*type = SID_NAME_UNKNOWN;
		fstrcpy(name, name_deadbeef);
	}
        
	talloc_destroy(mem_ctx);

	return rv;
}


/* Free state information held for {set,get,end}{pw,gr}ent() functions */

void free_getent_state(struct getent_state *state)
{
	struct getent_state *temp;

	/* Iterate over state list */

	temp = state;

	while(temp != NULL) {
		struct getent_state *next;

		/* Free sam entries then list entry */

		SAFE_FREE(state->sam_entries);
		DLIST_REMOVE(state, state);
		next = temp->next;

		SAFE_FREE(temp);
		temp = next;
	}
}

/* Parse winbindd related parameters */

BOOL winbindd_param_init(void)
{
	/* We must be in domain mode otherwise there really is no point. */

	if (lp_security() != SEC_DOMAIN) {
		DEBUG(0, ("must be in security = domain mode to run winbindd\n"));
		return False;
	}

	/* Parse winbind uid and winbind_gid parameters */

	if (!lp_winbind_uid(&server_state.uid_low, &server_state.uid_high)) {
		DEBUG(0, ("winbind uid range missing or invalid\n"));
		return False;
	}
	
	if (!lp_winbind_gid(&server_state.gid_low, &server_state.gid_high)) {
		DEBUG(0, ("winbind gid range missing or invalid\n"));
		return False;
	}
	
	return True;
}

/* Check if a domain is present in a comma-separated list of domains */

BOOL check_domain_env(char *domain_env, char *domain)
{
	fstring name;
	char *tmp = domain_env;

	while(next_token(&tmp, name, ",", sizeof(fstring))) {
		if (strequal_unix(name, domain))
			return True;
	}

	return False;
}

/* Parse a string of the form DOMAIN/user into a domain and a user */
extern fstring global_myworkgroup;

BOOL parse_domain_user(const char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if (!(p || lp_winbind_use_default_domain()))
		return False;
	
	if(!p && lp_winbind_use_default_domain()) {
		fstrcpy(user, domuser);
		fstrcpy(domain, lp_workgroup_unix());
	} else {
		fstrcpy(user, p+1);
		fstrcpy(domain, domuser);
		domain[PTR_DIFF(p, domuser)] = 0;
	}
	strupper_unix(domain);
	return True;
}

/*
    Fill DOMAIN\\USERNAME entry accounting 'winbind use default domain' and
    'winbind separator' options.
    This means:
	- omit DOMAIN when 'winbind use default domain = true' and DOMAIN is
	global_myworkgroup
	 
*/
void fill_domain_username(fstring name, const char *domain, const char *user)
{
	if(lp_winbind_use_default_domain() &&
	    strequal_unix(lp_workgroup_unix(), domain)) {
		strlcpy(name, user, sizeof(fstring));
	} else {
		slprintf(name, sizeof(fstring) - 1, "%s%s%s",
			 domain, lp_winbind_separator(),
			 user);
	}
}

/*
 * Winbindd socket accessor functions
 */

/* Open the winbindd socket */

static int _winbindd_socket = -1;

int open_winbindd_socket(void)
{
	if (_winbindd_socket == -1) {
		_winbindd_socket = create_pipe_sock(
			WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME, 0755);
		DEBUG(10, ("open_winbindd_socket: opened socket fd %d\n",
			   _winbindd_socket));
	}

	return _winbindd_socket;
}

/* Close the winbindd socket */

void close_winbindd_socket(void)
{
	if (_winbindd_socket != -1) {
		DEBUG(10, ("close_winbindd_socket: closing socket fd %d\n",
			   _winbindd_socket));
		close(_winbindd_socket);
		_winbindd_socket = -1;
	}
}

/*
 * Client list accessor functions
 */

static struct winbindd_cli_state *_client_list;
static int _num_clients;

/* Return list of all connected clients */

struct winbindd_cli_state *winbindd_client_list(void)
{
	return _client_list;
}

/* Add a connection to the list */

void winbindd_add_client(struct winbindd_cli_state *cli)
{
	DLIST_ADD(_client_list, cli);
	_num_clients++;
}

/* Remove a client from the list */

void winbindd_remove_client(struct winbindd_cli_state *cli)
{
	DLIST_REMOVE(_client_list, cli);
	_num_clients--;
}

/* Close all open clients */

void winbindd_kill_all_clients(void)
{
	struct winbindd_cli_state *cl = winbindd_client_list();

	DEBUG(10, ("winbindd_kill_all_clients: going postal\n"));

	while (cl) {
		struct winbindd_cli_state *next;
		
		next = cl->next;
		winbindd_remove_client(cl);
		cl = next;
	}
}

/* Return number of open clients */

int winbindd_num_clients(void)
{
	return _num_clients;
}

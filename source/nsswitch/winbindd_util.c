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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

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
static struct winbindd_domain *add_trusted_domain(const char *domain_name, const char *alt_name,
						  struct winbindd_methods *methods,
						  DOM_SID *sid)
{
	struct winbindd_domain *domain;
        
	/* We can't call domain_list() as this function is called from
	   init_domain_list() and we'll get stuck in a loop. */
	for (domain = _domain_list; domain; domain = domain->next) {
		if (strcasecmp(domain_name, domain->name) == 0 ||
		    strcasecmp(domain_name, domain->alt_name) == 0) {
			return domain;
		}
		if (alt_name && *alt_name) {
			if (strcasecmp(alt_name, domain->name) == 0 ||
			    strcasecmp(alt_name, domain->alt_name) == 0) {
				return domain;
			}
		}
	}
        
	/* Create new domain entry */

	if ((domain = (struct winbindd_domain *)
	     malloc(sizeof(*domain))) == NULL)
		return NULL;

	/* Fill in fields */
        
	ZERO_STRUCTP(domain);

	/* prioritise the short name */
	if (strchr_m(domain_name, '.') && alt_name && *alt_name) {
		fstrcpy(domain->name, alt_name);
		fstrcpy(domain->alt_name, domain_name);
	} else {
	fstrcpy(domain->name, domain_name);
		if (alt_name) {
			fstrcpy(domain->alt_name, alt_name);
		}
	}

	domain->methods = methods;
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	if (sid) {
		sid_copy(&domain->sid, sid);
	}
	
	/* see if this is a native mode win2k domain, but only for our own domain */
	   
	if ( strequal( lp_workgroup(), domain_name) ) 	{
		domain->native_mode = cm_check_for_native_mode_win2k( domain_name );
		DEBUG(3,("add_trusted_domain: %s is a %s mode domain\n", domain_name,
					domain->native_mode ? "native" : "mixed" ));
	}	

	/* Link to domain list */
	DLIST_ADD(_domain_list, domain);
        
	DEBUG(1,("Added domain %s %s %s\n", 
		 domain->name, domain->alt_name,
		 sid?sid_string_static(&domain->sid):""));
        
	return domain;
}


/*
  rescan our domains looking for new trusted domains
 */
void rescan_trusted_domains(BOOL force)
{
	struct winbindd_domain *domain;
	TALLOC_CTX *mem_ctx;
	static time_t last_scan;
	time_t t = time(NULL);

	/* trusted domains might be disabled */
	if (!lp_allow_trusted_domains()) {
		return;
	}

	/* Only rescan every few minutes but force if necessary */

	if (((unsigned)(t - last_scan) < WINBINDD_RESCAN_FREQ) && !force)
		return;

	last_scan = t;

	DEBUG(1, ("scanning trusted domain list\n"));

	if (!(mem_ctx = talloc_init("init_domain_list")))
		return;

	for (domain = _domain_list; domain; domain = domain->next) {
		NTSTATUS result;
		char **names;
		char **alt_names;
		int num_domains = 0;
		DOM_SID *dom_sids;
		int i;

		result = domain->methods->trusted_domains(domain, mem_ctx, &num_domains,
							  &names, &alt_names, &dom_sids);
		if (!NT_STATUS_IS_OK(result)) {
			continue;
		}

		/* Add each domain to the trusted domain list. Each domain inherits
		   the access methods of its parent */
		for(i = 0; i < num_domains; i++) {
			DEBUG(10,("Found domain %s\n", names[i]));
			add_trusted_domain(names[i], 
					   alt_names?alt_names[i]:NULL, 
					   domain->methods, &dom_sids[i]);
		}
	}

	talloc_destroy(mem_ctx);
}

/* Look up global info for the winbind daemon */
BOOL init_domain_list(void)
{
	extern struct winbindd_methods cache_methods;
	struct winbindd_domain *domain;

	/* Free existing list */
	free_domain_list();

	/* Add ourselves as the first entry */
	domain = add_trusted_domain(lp_workgroup(), NULL, &cache_methods, NULL);
	if (!secrets_fetch_domain_sid(domain->name, &domain->sid)) {
		DEBUG(1, ("Could not fetch sid for our domain %s\n",
			  domain->name));
		return False;
	}

	/* get any alternate name for the primary domain */
	cache_methods.alternate_name(domain);

	/* do an initial scan for trusted domains */
	rescan_trusted_domains(True);

	return True;
}

/* Given a domain name, return the struct winbindd domain info for it 
   if it is actually working. */

struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (strequal(domain_name, domain->name) ||
		    (domain->alt_name[0] && strequal(domain_name, domain->alt_name)))
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

	if (!(mem_ctx = talloc_init("winbindd_lookup_name_by_sid")))
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
	const char *tmp = domain_env;

	while(next_token(&tmp, name, ",", sizeof(fstring))) {
		if (strequal(name, domain))
			return True;
	}

	return False;
}

/* Parse a string of the form DOMAIN/user into a domain and a user */

BOOL parse_domain_user(const char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if (!(p || lp_winbind_use_default_domain()))
		return False;
	
	if(!p && lp_winbind_use_default_domain()) {
		fstrcpy(user, domuser);
		fstrcpy(domain, lp_workgroup());
	} else {
		fstrcpy(user, p+1);
		fstrcpy(domain, domuser);
		domain[PTR_DIFF(p, domuser)] = 0;
	}
	strupper(domain);
	return True;
}

/*
    Fill DOMAIN\\USERNAME entry accounting 'winbind use default domain' and
    'winbind separator' options.
    This means:
	- omit DOMAIN when 'winbind use default domain = true' and DOMAIN is
	lp_workgroup
	 
*/
void fill_domain_username(fstring name, const char *domain, const char *user)
{
	if(lp_winbind_use_default_domain() &&
	    !strcmp(lp_workgroup(), domain)) {
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

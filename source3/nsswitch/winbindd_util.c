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

#include "includes.h"
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

/**
   When was the last scan of trusted domains done?
   
   0 == not ever
*/

static time_t last_trustdom_scan;

struct winbindd_domain *domain_list(void)
{
	/* Initialise list */

	if (!_domain_list) 
		if (!init_domain_list()) 
			return NULL;

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

static BOOL is_internal_domain(const DOM_SID *sid)
{
	extern DOM_SID global_sid_Builtin;

	if (sid == NULL)
		return False;

	if (sid_compare_domain(sid, get_global_sam_sid()) == 0)
		return True;

	if (sid_compare_domain(sid, &global_sid_Builtin) == 0)
		return True;

	return False;
}


/* Add a trusted domain to our list of domains */
static struct winbindd_domain *add_trusted_domain(const char *domain_name, const char *alt_name,
						  struct winbindd_methods *methods,
						  DOM_SID *sid)
{
	struct winbindd_domain *domain;
	const char *alternative_name = NULL;
	static const DOM_SID null_sid;
	
	/* ignore alt_name if we are not in an AD domain */
	
	if ( (lp_security() == SEC_ADS) && alt_name && *alt_name) {
		alternative_name = alt_name;
	}
        
	/* We can't call domain_list() as this function is called from
	   init_domain_list() and we'll get stuck in a loop. */
	for (domain = _domain_list; domain; domain = domain->next) {
		if (strequal(domain_name, domain->name) ||
		    strequal(domain_name, domain->alt_name)) {
			return domain;
		}
		if (alternative_name && *alternative_name) {
			if (strequal(alternative_name, domain->name) ||
			    strequal(alternative_name, domain->alt_name)) {
				return domain;
			}
		}
		if (sid) {
			if (sid_equal(sid, &null_sid) ) {
				
			} else if (sid_equal(sid, &domain->sid)) {
				return domain;
			}
		}
	}
        
	/* Create new domain entry */

	if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain))) == NULL)
		return NULL;

	/* Fill in fields */
        
	ZERO_STRUCTP(domain);

	/* prioritise the short name */
	if (strchr_m(domain_name, '.') && alternative_name && *alternative_name) {
		fstrcpy(domain->name, alternative_name);
		fstrcpy(domain->alt_name, domain_name);
	} else {
		fstrcpy(domain->name, domain_name);
		if (alternative_name) {
			fstrcpy(domain->alt_name, alternative_name);
		}
	}

	domain->methods = methods;
	domain->backend = NULL;
	domain->internal = is_internal_domain(sid);
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	domain->initialized = False;
	if (sid) {
		sid_copy(&domain->sid, sid);
	}
	
	DEBUG(3,("add_trusted_domain: %s is an %s %s domain\n", domain->name,
		 domain->active_directory ? "ADS" : "NT4", 
		 domain->native_mode ? "native mode" : 
		 ((domain->active_directory && !domain->native_mode) ? "mixed mode" : "")));

	/* Link to domain list */
	DLIST_ADD(_domain_list, domain);
        
	DEBUG(1,("Added domain %s %s %s\n", 
		 domain->name, domain->alt_name,
		 &domain->sid?sid_string_static(&domain->sid):""));
        
	return domain;
}

/********************************************************************
  rescan our domains looking for new trusted domains
********************************************************************/

static void add_trusted_domains( struct winbindd_domain *domain )
{
	extern struct winbindd_methods cache_methods;
	TALLOC_CTX *mem_ctx;
	NTSTATUS result;
	time_t t;
	char **names;
	char **alt_names;
	int num_domains = 0;
	DOM_SID *dom_sids, null_sid;
	int i;
	struct winbindd_domain *new_domain;

	/* trusted domains might be disabled */
	if (!lp_allow_trusted_domains()) {
		return;
	}

	DEBUG(5, ("scanning trusted domain list\n"));

	if (!(mem_ctx = talloc_init("init_domain_list")))
		return;
	   
	ZERO_STRUCTP(&null_sid);

	t = time(NULL);
	
	/* ask the DC what domains it trusts */
	
	result = domain->methods->trusted_domains(domain, mem_ctx, (unsigned int *)&num_domains,
		&names, &alt_names, &dom_sids);
		
	if ( NT_STATUS_IS_OK(result) ) {

		/* Add each domain to the trusted domain list */
		
		for(i = 0; i < num_domains; i++) {
			DEBUG(10,("Found domain %s\n", names[i]));
			add_trusted_domain(names[i], alt_names?alt_names[i]:NULL,
					   &cache_methods, &dom_sids[i]);
					   
			/* if the SID was empty, we better set it now */
			
			if ( sid_equal(&dom_sids[i], &null_sid) ) {
			
				new_domain = find_domain_from_name(names[i]);
				 
				/* this should never happen */
				if ( !new_domain ) { 	
					DEBUG(0,("rescan_trust_domains: can't find the domain I just added! [%s]\n",
						names[i]));
					break;
				}
				 
				/* call the cache method; which will operate on the winbindd_domain \
				   passed in and choose either rpc or ads as appropriate */

				result = domain->methods->domain_sid( new_domain, &new_domain->sid );
				 
				if ( NT_STATUS_IS_OK(result) )
				 	sid_copy( &dom_sids[i], &new_domain->sid );
			}
			
			/* store trusted domain in the cache */
			trustdom_cache_store(names[i], alt_names ? alt_names[i] : NULL,
			                     &dom_sids[i], t + WINBINDD_RESCAN_FREQ);
		}
	}

	talloc_destroy(mem_ctx);
}

/********************************************************************
 Periodically we need to refresh the trusted domain cache for smbd 
********************************************************************/

void rescan_trusted_domains( void )
{
	time_t now = time(NULL);
	struct winbindd_domain *mydomain = NULL;
	
	/* see if the time has come... */
	
	if ( (now > last_trustdom_scan) && ((now-last_trustdom_scan) < WINBINDD_RESCAN_FREQ) )
		return;
		
	if ( (mydomain = find_our_domain()) == NULL ) {
		DEBUG(0,("rescan_trusted_domains: Can't find my own domain!\n"));
		return;
	}
	
	/* this will only add new domains we didn't already know about */
	
	add_trusted_domains( mydomain );

	last_trustdom_scan = now;
	
	return;	
}

/* Look up global info for the winbind daemon */
BOOL init_domain_list(void)
{
	extern DOM_SID global_sid_Builtin;
	extern struct winbindd_methods cache_methods;
	extern struct winbindd_methods passdb_methods;
	struct winbindd_domain *domain;

	/* Free existing list */
	free_domain_list();

	/* Add ourselves as the first entry. */

	if (IS_DC) {
		domain = add_trusted_domain(get_global_sam_name(), NULL,
					    &passdb_methods, get_global_sam_sid());
	} else {
	
		domain = add_trusted_domain( lp_workgroup(), lp_realm(),
					     &cache_methods, NULL);
	
		/* set flags about native_mode, active_directory */
		set_dc_type_and_flags(domain);
	}

	domain->primary = True;

	/* get any alternate name for the primary domain */
	
	cache_methods.alternate_name(domain);
	
	/* now we have the correct netbios (short) domain name */
	
	if ( *domain->name )
		set_global_myworkgroup( domain->name );
		
	if (!secrets_fetch_domain_sid(domain->name, &domain->sid)) {
		DEBUG(1, ("Could not fetch sid for our domain %s\n",
			  domain->name));
		return False;
	}

	/* do an initial scan for trusted domains */
	add_trusted_domains(domain);


	/* Add our local SAM domains */

	add_trusted_domain("BUILTIN", NULL, &passdb_methods,
			   &global_sid_Builtin);

	if (!IS_DC) {
		add_trusted_domain(get_global_sam_name(), NULL,
				   &passdb_methods, get_global_sam_sid());
	}
	
	/* avoid rescanning this right away */
	last_trustdom_scan = time(NULL);
	return True;
}

/** 
 * Given a domain name, return the struct winbindd domain info for it 
 *
 * @note Do *not* pass lp_workgroup() to this function.  domain_list
 *       may modify it's value, and free that pointer.  Instead, our local
 *       domain may be found by calling find_our_domain().
 *       directly.
 *
 *
 * @return The domain structure for the named domain, if it is working.
 */

struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (strequal(domain_name, domain->name) ||
		    (domain->alt_name[0] && strequal(domain_name, domain->alt_name))) {
			if (!domain->initialized)
				set_dc_type_and_flags(domain);

			return domain;
		}
	}

	/* Not found */

	return NULL;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(const DOM_SID *sid)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (sid_compare_domain(sid, &domain->sid) == 0) {
			if (!domain->initialized)
				set_dc_type_and_flags(domain);
			return domain;
		}
	}

	/* Not found */

	return NULL;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_our_domain(void)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (domain->primary)
			return domain;
	}

	/* Not found */

	return NULL;
}

/* Find the appropriate domain to lookup a name or SID */

struct winbindd_domain *find_lookup_domain_from_sid(const DOM_SID *sid)
{
	/* A DC can't ask the local smbd for remote SIDs, here winbindd is the
	 * one to contact the external DC's. On member servers the internal
	 * domains are different: These are part of the local SAM. */

	if (IS_DC || is_internal_domain(sid))
		return find_domain_from_sid(sid);

	/* On a member server a query for SID or name can always go to our
	 * primary DC. */

	return find_our_domain();
}

struct winbindd_domain *find_lookup_domain_from_name(const char *domain_name)
{
	if (IS_DC || strequal(domain_name, "BUILTIN") ||
	    strequal(domain_name, get_global_sam_name()))
		return find_domain_from_name(domain_name);

	return find_our_domain();
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(struct winbindd_domain *domain, 
				 const char *domain_name,
				 const char *name, DOM_SID *sid, 
				 enum SID_NAME_USE *type)
{
	NTSTATUS result;
        TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("lookup_sid_by_name for %s\\%s\n",
			      domain_name, name);
	if (!mem_ctx) 
		return False;
        
	/* Lookup name */
	result = domain->methods->name_to_sid(domain, mem_ctx, domain_name, name, sid, type);

	talloc_destroy(mem_ctx);
        
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
 * @param name On success, set to the name corresponding to @p sid.
 * @param dom_name On success, set to the 'domain name' corresponding to @p sid.
 * @param type On success, contains the type of name: alias, group or
 * user.
 * @retval True if the name exists, in which case @p name and @p type
 * are set, otherwise False.
 **/
BOOL winbindd_lookup_name_by_sid(DOM_SID *sid,
				 fstring dom_name,
				 fstring name,
				 enum SID_NAME_USE *type)
{
	char *names;
	char *dom_names;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	BOOL rv = False;
	struct winbindd_domain *domain;

	domain = find_lookup_domain_from_sid(sid);

	if (!domain) {
		DEBUG(1,("Can't find domain from sid\n"));
		return False;
	}

	/* Lookup name */

	if (!(mem_ctx = talloc_init("winbindd_lookup_name_by_sid")))
		return False;
        
	result = domain->methods->sid_to_name(domain, mem_ctx, sid, &dom_names, &names, type);

	/* Return name and type if successful */
        
	if ((rv = NT_STATUS_IS_OK(result))) {
		fstrcpy(dom_name, dom_names);
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

	if (!lp_idmap_uid(&server_state.uid_low, &server_state.uid_high)) {
		DEBUG(0, ("winbindd: idmap uid range missing or invalid\n"));
		DEBUG(0, ("winbindd: cannot continue, exiting.\n"));
		return False;
	}
	
	if (!lp_idmap_gid(&server_state.gid_low, &server_state.gid_high)) {
		DEBUG(0, ("winbindd: idmap gid range missing or invalid\n"));
		DEBUG(0, ("winbindd: cannot continue, exiting.\n"));
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

/* Is this a domain which we may assume no DOMAIN\ prefix? */

static BOOL assume_domain(const char *domain) {
	if ((lp_winbind_use_default_domain()  
		  || lp_winbind_trusted_domains_only()) &&
	    strequal(lp_workgroup(), domain)) 
		return True;

	if (strequal(get_global_sam_name(), domain)) 
		return True;
	
	return False;
}

/* Parse a string of the form DOMAIN/user into a domain and a user */

BOOL parse_domain_user(const char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if ( !p ) {
		fstrcpy(user, domuser);
		
		if ( assume_domain(lp_workgroup())) {
			fstrcpy(domain, lp_workgroup());
		} else {
			fstrcpy( domain, get_global_sam_name() ); 
		}
	} 
	else {
		fstrcpy(user, p+1);
		fstrcpy(domain, domuser);
		domain[PTR_DIFF(p, domuser)] = 0;
	}
	
	strupper_m(domain);
	
	return True;
}

/*
    Fill DOMAIN\\USERNAME entry accounting 'winbind use default domain' and
    'winbind separator' options.
    This means:
	- omit DOMAIN when 'winbind use default domain = true' and DOMAIN is
	lp_workgroup()

    If we are a PDC or BDC, and this is for our domain, do likewise.

    Also, if omit DOMAIN if 'winbind trusted domains only = true', as the 
    username is then unqualified in unix
	 
*/
void fill_domain_username(fstring name, const char *domain, const char *user)
{
	if (assume_domain(domain)) {
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

char *get_winbind_priv_pipe_dir(void) 
{
	return lock_path(WINBINDD_PRIV_SOCKET_SUBDIR);
}

/* Open the winbindd socket */

static int _winbindd_socket = -1;
static int _winbindd_priv_socket = -1;

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

int open_winbindd_priv_socket(void)
{
	if (_winbindd_priv_socket == -1) {
		_winbindd_priv_socket = create_pipe_sock(
			get_winbind_priv_pipe_dir(), WINBINDD_SOCKET_NAME, 0750);
		DEBUG(10, ("open_winbindd_priv_socket: opened socket fd %d\n",
			   _winbindd_priv_socket));
	}

	return _winbindd_priv_socket;
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
	if (_winbindd_priv_socket != -1) {
		DEBUG(10, ("close_winbindd_socket: closing socket fd %d\n",
			   _winbindd_priv_socket));
		close(_winbindd_priv_socket);
		_winbindd_priv_socket = -1;
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

/* Help with RID -> SID conversion */

DOM_SID *rid_to_talloced_sid(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32 rid) 
{
	DOM_SID *sid;
	sid = talloc(mem_ctx, sizeof(*sid));
	if (!sid) {
		smb_panic("rid_to_to_talloced_sid: talloc for DOM_SID failed!\n");
	}
	sid_copy(sid, &domain->sid);
	sid_append_rid(sid, rid);
	return sid;
}
	
/*****************************************************************************
 For idmap conversion: convert one record to new format
 Ancient versions (eg 2.2.3a) of winbindd_idmap.tdb mapped DOMAINNAME/rid
 instead of the SID.
*****************************************************************************/
static int convert_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	struct winbindd_domain *domain;
	char *p;
	DOM_SID sid;
	uint32 rid;
	fstring keystr;
	fstring dom_name;
	TDB_DATA key2;
	BOOL *failed = (BOOL *)state;

	DEBUG(10,("Converting %s\n", key.dptr));

	p = strchr(key.dptr, '/');
	if (!p)
		return 0;

	*p = 0;
	fstrcpy(dom_name, key.dptr);
	*p++ = '/';

	domain = find_domain_from_name(dom_name);
	if (domain == NULL) {
		/* We must delete the old record. */
		DEBUG(0,("Unable to find domain %s\n", dom_name ));
		DEBUG(0,("deleting record %s\n", key.dptr ));

		if (tdb_delete(tdb, key) != 0) {
			DEBUG(0, ("Unable to delete record %s\n", key.dptr));
			*failed = True;
			return -1;
		}

		return 0;
	}

	rid = atoi(p);

	sid_copy(&sid, &domain->sid);
	sid_append_rid(&sid, rid);

	sid_to_string(keystr, &sid);
	key2.dptr = keystr;
	key2.dsize = strlen(keystr) + 1;

	if (tdb_store(tdb, key2, data, TDB_INSERT) != 0) {
		DEBUG(0,("Unable to add record %s\n", key2.dptr ));
		*failed = True;
		return -1;
	}

	if (tdb_store(tdb, data, key2, TDB_REPLACE) != 0) {
		DEBUG(0,("Unable to update record %s\n", data.dptr ));
		*failed = True;
		return -1;
	}

	if (tdb_delete(tdb, key) != 0) {
		DEBUG(0,("Unable to delete record %s\n", key.dptr ));
		*failed = True;
		return -1;
	}

	return 0;
}

/* These definitions are from sam/idmap_tdb.c. Replicated here just
   out of laziness.... :-( */

/* High water mark keys */
#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

/* idmap version determines auto-conversion */
#define IDMAP_VERSION 2


/*****************************************************************************
 Convert the idmap database from an older version.
*****************************************************************************/

static BOOL idmap_convert(const char *idmap_name)
{
	int32 vers;
	BOOL bigendianheader;
	BOOL failed = False;
	TDB_CONTEXT *idmap_tdb;

	if (!(idmap_tdb = tdb_open_log(idmap_name, 0,
					TDB_DEFAULT, O_RDWR,
					0600))) {
		DEBUG(0, ("idmap_convert: Unable to open idmap database\n"));
		return False;
	}

	bigendianheader = (idmap_tdb->flags & TDB_BIGENDIAN) ? True : False;

	vers = tdb_fetch_int32(idmap_tdb, "IDMAP_VERSION");

	if (((vers == -1) && bigendianheader) || (IREV(vers) == IDMAP_VERSION)) {
		/* Arrggghh ! Bytereversed or old big-endian - make order independent ! */
		/*
		 * high and low records were created on a
		 * big endian machine and will need byte-reversing.
		 */

		int32 wm;

		wm = tdb_fetch_int32(idmap_tdb, HWM_USER);

		if (wm != -1) {
			wm = IREV(wm);
		}  else {
			wm = server_state.uid_low;
		}

		if (tdb_store_int32(idmap_tdb, HWM_USER, wm) == -1) {
			DEBUG(0, ("idmap_convert: Unable to byteswap user hwm in idmap database\n"));
			tdb_close(idmap_tdb);
			return False;
		}

		wm = tdb_fetch_int32(idmap_tdb, HWM_GROUP);
		if (wm != -1) {
			wm = IREV(wm);
		} else {
			wm = server_state.gid_low;
		}

		if (tdb_store_int32(idmap_tdb, HWM_GROUP, wm) == -1) {
			DEBUG(0, ("idmap_convert: Unable to byteswap group hwm in idmap database\n"));
			tdb_close(idmap_tdb);
			return False;
		}
	}

	/* the old format stored as DOMAIN/rid - now we store the SID direct */
	tdb_traverse(idmap_tdb, convert_fn, &failed);

	if (failed) {
		DEBUG(0, ("Problem during conversion\n"));
		tdb_close(idmap_tdb);
		return False;
	}

	if (tdb_store_int32(idmap_tdb, "IDMAP_VERSION", IDMAP_VERSION) == -1) {
		DEBUG(0, ("idmap_convert: Unable to dtore idmap version in databse\n"));
		tdb_close(idmap_tdb);
		return False;
	}

	tdb_close(idmap_tdb);
	return True;
}

/*****************************************************************************
 Convert the idmap database from an older version if necessary
*****************************************************************************/

BOOL winbindd_upgrade_idmap(void)
{
	pstring idmap_name;
	pstring backup_name;
	SMB_STRUCT_STAT stbuf;
	TDB_CONTEXT *idmap_tdb;

	pstrcpy(idmap_name, lock_path("winbindd_idmap.tdb"));

	if (!file_exist(idmap_name, &stbuf)) {
		/* nothing to convert return */
		return True;
	}

	if (!(idmap_tdb = tdb_open_log(idmap_name, 0,
					TDB_DEFAULT, O_RDWR,
					0600))) {
		DEBUG(0, ("idmap_convert: Unable to open idmap database\n"));
		return False;
	}

	if (tdb_fetch_int32(idmap_tdb, "IDMAP_VERSION") == IDMAP_VERSION) {
		/* nothing to convert return */
		tdb_close(idmap_tdb);
		return True;
	}

	/* backup_tdb expects the tdb not to be open */
	tdb_close(idmap_tdb);

	DEBUG(0, ("Upgrading winbindd_idmap.tdb from an old version\n"));

	pstrcpy(backup_name, idmap_name);
	pstrcat(backup_name, ".bak");

	if (backup_tdb(idmap_name, backup_name) != 0) {
		DEBUG(0, ("Could not backup idmap database\n"));
		return False;
	}

	return idmap_convert(idmap_name);
}

/*******************************************************************
 wrapper around retrieving the trust account password
*******************************************************************/

BOOL get_trust_pw(const char *domain, uint8 ret_pwd[16],
                          time_t *pass_last_set_time, uint32 *channel)
{
	DOM_SID sid;
	char *pwd;

	/* if we are a DC and this is not our domain, then lookup an account
	   for the domain trust */
	   
	if ( IS_DC && !strequal(domain, lp_workgroup()) && lp_allow_trusted_domains() ) 
	{
		if ( !secrets_fetch_trusted_domain_password(domain, &pwd, &sid, 
			pass_last_set_time) ) 
		{
			DEBUG(0, ("get_trust_pw: could not fetch trust account "
				  "password for trusted domain %s\n", domain));
			return False;
		}
		
		*channel = SEC_CHAN_DOMAIN;
		E_md4hash(pwd, ret_pwd);
		SAFE_FREE(pwd);

		return True;
	}
	else 	/* just get the account for our domain (covers 
		   ROLE_DOMAIN_MEMBER as well */
	{
		/* get the machine trust account for our domain */

		if ( !secrets_fetch_trust_account_password (lp_workgroup(), ret_pwd,
			pass_last_set_time, channel) ) 
		{
			DEBUG(0, ("get_trust_pw: could not fetch trust account "
				  "password for my domain %s\n", domain));
			return False;
		}
		
		return True;
	}
	
	/* Failure */
}


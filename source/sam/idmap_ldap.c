/* 
   Unix SMB/CIFS implementation.

   idmap LDAP backend

   Copyright (C) Tim Potter 		2000
   Copyright (C) Anthony Liguori 	2003
   Copyright (C) Simo Sorce 		2003
   Copyright (C) Gerald Carter 		2003
   
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
#define DBGC_CLASS DBGC_IDMAP


#include <lber.h>
#include <ldap.h>

#include "smbldap.h"


struct ldap_idmap_state {
	LDAP *ldap_struct;
	time_t last_ping;
	const char *uri;
	char *bind_dn;
	char *bind_secret;
	unsigned int num_failures;
	struct ldap_idmap_state *prev, *next;
};

#define LDAP_IDMAP_DONT_PING_TIME 10       /* ping only all 10 seconds */
#define LDAP_MAX_ALLOC_ID 128              /* number tries while allocating
					      new id */

static struct ldap_idmap_state ldap_state;

static int ldap_idmap_connect_system(struct ldap_idmap_state *state);
static NTSTATUS ldap_set_mapping(const DOM_SID *sid, unid_t id, int id_type);
static NTSTATUS ldap_idmap_close(void);


/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static int ldap_idmap_open_connection(struct ldap_idmap_state *state)
{
	int rc = LDAP_SUCCESS;
	int version;
	BOOL ldap_v3 = False;

#ifdef HAVE_LDAP_INITIALIZE
	DEBUG(10, ("ldap_idmap_open_connection: %s\n", state->uri));
	
	if ((rc = ldap_initialize(&state->ldap_struct, state->uri)) 
	    != LDAP_SUCCESS) {
		DEBUG(0, ("ldap_initialize: %s\n", ldap_err2string(rc)));
		return rc;
	}
#else 
	/* Parse the string manually */
	{
		int port = 0;
		fstring protocol;
		fstring host;
		const char *p = state->uri; 
		SMB_ASSERT(sizeof(protocol)>10 && sizeof(host)>254);
		
		/* skip leading "URL:" (if any) */
		if ( strncasecmp( p, "URL:", 4 ) == 0 ) {
			p += 4;
		}
		
		sscanf(p, "%10[^:]://%254s[^:]:%d", protocol, host, &port);
		
		if (port == 0) {
			if (strequal(protocol, "ldap")) {
				port = LDAP_PORT;
			} else if (strequal(protocol, "ldaps")) {
				port = LDAPS_PORT;
			} else {
				DEBUG(0, ("unrecognised protocol (%s)!\n",
					  protocol));
			}
		}
		
		if ((state->ldap_struct = ldap_init(host, port)) == NULL) {
			DEBUG(0, ("ldap_init failed !\n"));
			return LDAP_OPERATIONS_ERROR;
		}
		
	        if (strequal(protocol, "ldaps")) {
#ifdef LDAP_OPT_X_TLS
			int tls = LDAP_OPT_X_TLS_HARD;
			if (ldap_set_option (state->ldap_struct, 
					     LDAP_OPT_X_TLS, &tls) != 
			    LDAP_SUCCESS)
			{
				DEBUG(0, ("Failed to setup a TLS session\n"));
			}
			
			DEBUG(3,("LDAPS option set...!\n"));
#else
			DEBUG(0,("ldap_idmap_open_connection: Secure "
				 "connection not supported by LDAP client "
				 "libraries!\n"));
			return LDAP_OPERATIONS_ERROR;
#endif
		}
	}
#endif

	if (ldap_get_option(state->ldap_struct, LDAP_OPT_PROTOCOL_VERSION,
			    &version) == LDAP_OPT_SUCCESS) {
		if (version != LDAP_VERSION3) {
			version = LDAP_VERSION3;
			if (ldap_set_option(state->ldap_struct,
					    LDAP_OPT_PROTOCOL_VERSION,
					    &version) == LDAP_OPT_SUCCESS) {
				ldap_v3 = True;
			}
		} else {
			ldap_v3 = True;
		}
	}

	if (lp_ldap_ssl() == LDAP_SSL_START_TLS) {
#ifdef LDAP_OPT_X_TLS
		if (ldap_v3) {
			if ((rc = ldap_start_tls_s(state->ldap_struct, NULL,
						   NULL)) != LDAP_SUCCESS) {
				DEBUG(0,("Failed to issue the StartTLS "
					 "instruction: %s\n",
					 ldap_err2string(rc)));
				return rc;
			}
			DEBUG (3, ("StartTLS issued: using a TLS "
				   "connection\n"));
		} else {
			
			DEBUG(0, ("Need LDAPv3 for Start TLS\n"));
			return LDAP_OPERATIONS_ERROR;
		}
#else
		DEBUG(0,("ldap_idmap_open_connection: StartTLS not supported by "
			 "LDAP client libraries!\n"));
		return LDAP_OPERATIONS_ERROR;
#endif
	}

	DEBUG(2, ("ldap_idmap_open_connection: connection opened\n"));
	return rc;
}

/**********************************************************************
Connect to LDAP server 
*********************************************************************/
static int ldap_idmap_open(struct ldap_idmap_state *state)
{
	int rc;
	SMB_ASSERT(state);
		
#ifndef NO_LDAP_SECURITY
	if (geteuid() != 0) {
		DEBUG(0, 
		      ("ldap_idmap_open: cannot access LDAP when not root\n"));
		return  LDAP_INSUFFICIENT_ACCESS;
	}
#endif

	if ((state->ldap_struct != NULL) && 
	    ((state->last_ping + LDAP_IDMAP_DONT_PING_TIME)<time(NULL))) {
		struct sockaddr_un addr;
		socklen_t len = sizeof(addr);
		int sd;

		if (!ldap_get_option(state->ldap_struct,  LDAP_OPT_DESC, &sd)&&
		    getpeername(sd, (struct sockaddr *) &addr, &len) < 0) {
		    	/* the other end has died. reopen. */
		    	ldap_unbind_ext(state->ldap_struct, NULL, NULL);
		    	state->ldap_struct = NULL;
		    	state->last_ping = (time_t)0;
		} else {
			state->last_ping = time(NULL);
		} 
    	}

	if (state->ldap_struct != NULL) {
		DEBUG(5,("ldap_idmap_open: already connected to the LDAP "
			 "server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = ldap_idmap_open_connection(state))) {
		return rc;
	}

	if ((rc = ldap_idmap_connect_system(state))) {
		ldap_unbind_ext(state->ldap_struct, NULL, NULL);
		state->ldap_struct = NULL;
		return rc;
	}


	state->last_ping = time(NULL);
	DEBUG(4,("The LDAP server is succesful connected\n"));

	return LDAP_SUCCESS;
}

/*******************************************************************
******************************************************************/

static int ldap_idmap_retry_open(struct ldap_idmap_state *state, int *attempts)
{
	int rc;

	SMB_ASSERT(state && attempts);

	if (*attempts != 0) {
		unsigned int sleep_time;
		uint8 rand_byte = 128; /* a reasonable place to start */

		generate_random_buffer(&rand_byte, 1, False);

		sleep_time = (((*attempts)*(*attempts))/2)*rand_byte*2; 
		/* we retry after (0.5, 1, 2, 3, 4.5, 6) seconds
		   on average.  
		 */
		DEBUG(3, ("Sleeping for %u milliseconds before reconnecting\n",
			  sleep_time));
		msleep(sleep_time);
	}
	(*attempts)++;

	if ((rc = ldap_idmap_open(state))) {
		DEBUG(1,("Connection to LDAP Server failed for the %d try!\n",
			 *attempts));
		return rc;
	} 
	
	return LDAP_SUCCESS;		
}

/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
******************************************************************/

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
static int rebindproc_with_state  (LDAP * ld, char **whop, char **credp, 
				   int *methodp, int freeit, void *arg)
{
	struct ldap_idmap_state *state = arg;
	
	/** @TODO Should we be doing something to check what servers we rebind
	    to?  Could we get a referral to a machine that we don't want to
	    give our username and password to? */
	
	if (freeit) {
		SAFE_FREE(*whop);
		memset(*credp, '\0', strlen(*credp));
		SAFE_FREE(*credp);
	} else {
		DEBUG(5,("rebind_proc_with_state: Rebinding as \"%s\"\n", 
			  state->bind_dn));

		*whop = strdup(state->bind_dn);
		if (!*whop) {
			return LDAP_NO_MEMORY;
		}
		*credp = strdup(state->bind_secret);
		if (!*credp) {
			SAFE_FREE(*whop);
			return LDAP_NO_MEMORY;
		}
		*methodp = LDAP_AUTH_SIMPLE;
	}
	return 0;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 This version takes a void* that we can shove useful stuff in :-)
 and actually does the connection.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int rebindproc_connect_with_state (LDAP *ldap_struct, 
					  LDAP_CONST char *url, 
					  ber_tag_t request,
					  ber_int_t msgid, void *arg)
{
	struct ldap_idmap_state *state = arg;
	int rc;
	DEBUG(5,("rebindproc_connect_with_state: Rebinding as \"%s\"\n", 
		 state->bind_dn));
	
	/** @TODO Should we be doing something to check what servers we rebind
	    to?  Could we get a referral to a machine that we don't want to
	    give our username and password to? */

	rc = ldap_simple_bind_s(ldap_struct, state->bind_dn, 
				state->bind_secret);
	
	return rc;
}
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 Add a rebind function for authenticated referrals
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#else
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc (LDAP *ldap_struct, char **whop, char **credp,
		       int *method, int freeit )
{
	return rebindproc_with_state(ldap_struct, whop, credp,
				   method, freeit, &ldap_state);
	
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 a rebind function for authenticated referrals
 this also does the connection, but no void*.
******************************************************************/
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2
static int rebindproc_connect (LDAP * ld, LDAP_CONST char *url, int request,
			       ber_int_t msgid)
{
	return rebindproc_connect_with_state(ld, url, (ber_tag_t)request,
					     msgid, &ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static int ldap_idmap_connect_system(struct ldap_idmap_state *state)
{
	int rc;
	char *ldap_dn;
	char *ldap_secret;

	/* get the password */
	if (!fetch_ldap_pw(&ldap_dn, &ldap_secret))
	{
		DEBUG(0, ("ldap_idmap_connect_system: Failed to retrieve "
			  "password from secrets.tdb\n"));
		return LDAP_INVALID_CREDENTIALS;
	}

	state->bind_dn = ldap_dn;
	state->bind_secret = ldap_secret;

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesnt' seem to support it */
	   
	DEBUG(10,("ldap_idmap_connect_system: Binding to ldap server %s as "
		  "\"%s\"\n", state->uri, ldap_dn));

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(state->ldap_struct, &rebindproc_connect);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(state->ldap_struct, 
			     &rebindproc_connect_with_state, (void *)state);
# endif
#else /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(state->ldap_struct, &rebindproc);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(state->ldap_struct, &rebindproc_with_state,
			     (void *)state);	
# endif
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

	rc = ldap_simple_bind_s(state->ldap_struct, ldap_dn, ldap_secret);

	if (rc != LDAP_SUCCESS) {
		char *ld_error = NULL;
		ldap_get_option(state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(state->num_failures ? 2 : 0,
		      ("failed to bind to server with dn= %s Error: "
		       "%s\n\t%s\n",
		       ldap_dn ? ld_error : "(unknown)",
		       ldap_err2string(rc), ld_error));
		SAFE_FREE(ld_error);
		state->num_failures++;
		return rc;
	}

	state->num_failures = 0;

	DEBUG(3, ("ldap_idmap_connect_system: succesful connection to the "
		  "LDAP server\n"));
	return rc;
}

/*****************************************************************************
 wrapper around ldap_search()
*****************************************************************************/

static int ldap_idmap_search(struct ldap_idmap_state *state, 
			     const char *base, int scope, const char *filter, 
			     char *attrs[], int attrsonly, 
			     LDAPMessage **res)
{
	int rc = LDAP_SERVER_DOWN;
	int attempts = 0;
	char *utf8_filter;

	SMB_ASSERT(state);

	if (push_utf8_allocate(&utf8_filter, filter) == (size_t)-1) {
		return LDAP_NO_MEMORY;
	}

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		if ((rc = ldap_idmap_retry_open(state, &attempts)) !=
		    LDAP_SUCCESS) continue;
		
		rc = ldap_search_s(state->ldap_struct, base, scope, 
				   utf8_filter, (char**)attrs, attrsonly, res);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("ldap_idmap_search: LDAP server is down!\n"));
		ldap_idmap_close();
	}

	SAFE_FREE(utf8_filter);
	return rc;
}

/***********************************************************************
 search an attribute and return the first value found.
***********************************************************************/

static BOOL ldap_idmap_attribute (struct ldap_idmap_state *state,
				  LDAPMessage * entry,
				  const char *attribute, pstring value)
{
	char **values;
	value[0] = '\0';

	if ( !entry )
		return False;
		 
	if ((values = ldap_get_values (state->ldap_struct, entry, attribute)) == NULL) 
	{
		DEBUG(10,("get_single_attribute: [%s] = [<does not exist>]\n",
			  attribute));
		return False;
	}
	
	if (convert_string(CH_UTF8, CH_UNIX,
		values[0], -1,
		value, sizeof(pstring)) == (size_t)-1)
	{
		DEBUG(1, ("ldap_idmap_attribute: string conversion of [%s] = "
			  "[%s] failed!\n",  attribute, values[0]));
		ldap_value_free(values);
		return False;
	}
	ldap_value_free(values);

	return True;
}

/*****************************************************************************
 Allocate a new uid or gid
*****************************************************************************/

static NTSTATUS ldap_allocate_id(unid_t *id, int id_type)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	int rc = LDAP_SERVER_DOWN;
	int count = 0;
	LDAPMessage *result = 0;
	LDAPMessage *entry = 0;
	pstring id_str, new_id_str;
	LDAPMod mod[2];
	LDAPMod *mods[3];
	const char *type;
	char *val[4];
	char *dn;
	char **attr_list;
	pstring filter;


	type = (id_type & ID_USERID) ?
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER ) : 
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );

	snprintf(filter, sizeof(filter)-1, "(objectClass=%s)", LDAP_OBJ_IDPOOL);

	attr_list = get_attr_list( idpool_attr_list );
	
	rc = ldap_idmap_search(&ldap_state, lp_ldap_suffix(),
			       LDAP_SCOPE_SUBTREE, filter,
			       attr_list, 0, &result);
	free_attr_list( attr_list );
	 
	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_allocate_id: %s object not found\n", LDAP_OBJ_IDPOOL));
		goto out;
	}
	
	count = ldap_count_entries(ldap_state.ldap_struct, result);
	if (count != 1) {
		DEBUG(0,("ldap_allocate_id: single %s object not found\n", LDAP_OBJ_IDPOOL));
		goto out;
	}

	dn = ldap_get_dn(ldap_state.ldap_struct, result);
	entry = ldap_first_entry(ldap_state.ldap_struct, result);

	if (!ldap_idmap_attribute(&ldap_state, entry, type, id_str)) {
		DEBUG(0,("ldap_allocate_id: %s attribute not found\n",
			 type));
		goto out;
	}
	
	if (id_type & ID_USERID) 
		id->uid = strtoul(id_str, NULL, 10);
	else 
		id->gid = strtoul(id_str, NULL, 10);
	

	mod[0].mod_op = LDAP_MOD_DELETE;
	mod[0].mod_type = strdup(type);
	val[0] = id_str;
	val[1] = NULL;
	mod[0].mod_values = val;

	snprintf(new_id_str, sizeof(new_id_str), "%u", 
		 ((id_type & ID_USERID) ? id->uid : id->gid) + 1);
	mod[1].mod_op = LDAP_MOD_ADD;
	mod[1].mod_type = strdup(type);
	val[2] = new_id_str; 
	val[3] = NULL; 
	mod[1].mod_values = val + 2;

	mods[0] = mod; \
	mods[1] = mod + 1; 
	mods[2] = NULL;
	
	rc = ldap_modify_s(ldap_state.ldap_struct, dn, mods);

	ldap_memfree(dn);
	
	SAFE_FREE( mod[0].mod_type );
	SAFE_FREE( mod[1].mod_type );

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_allocate_id: Failed to allocate new %s.  ldap_modify() failed.\n",
			type));
		goto out;
	}
	
	ret = NT_STATUS_OK;
out:
	return ret;
}

/*****************************************************************************
 get a sid from an id
*****************************************************************************/

static NTSTATUS ldap_get_sid_from_id(DOM_SID *sid, unid_t id, int id_type)
{
	LDAPMessage *result = 0;
	LDAPMessage *entry = 0;
	pstring sid_str;
	pstring filter;
	const char *type;
	int rc;
	int count;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	char **attr_list;

	type = (id_type & ID_USERID) ?
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER ) : 
		get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );
		
	/* first we try for a samba user or group mapping */
	
	if ( id_type & ID_USERID ) {
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%u))",
			LDAP_OBJ_SAMBASAMACCOUNT, type, id.uid );
	}
	else {
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%u))",
			LDAP_OBJ_GROUPMAP, type, id.gid );	
	}
		 
	attr_list = get_attr_list( sidmap_attr_list );
	rc = ldap_idmap_search(&ldap_state, lp_ldap_suffix(), LDAP_SCOPE_SUBTREE, 
		filter, attr_list, 0, &result);
	
	if (rc != LDAP_SUCCESS) 
		goto out;
	   
	count = ldap_count_entries(ldap_state.ldap_struct, result);

	/* fall back to looking up an idmap entry if we didn't find and 
	   actual user or group */
	
	if (count == 0) {
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%u))",
			LDAP_OBJ_IDMAP_ENTRY, type,  ((id_type & ID_USERID) ? id.uid : id.gid));
			    
		rc = ldap_idmap_search(&ldap_state, lp_ldap_suffix(),
			LDAP_SCOPE_SUBTREE, filter, attr_list, 0, &result);
		if (rc != LDAP_SUCCESS)
			   goto out;
			   
		count = ldap_count_entries(ldap_state.ldap_struct, result);
	}
	
	if (count != 1) {
		DEBUG(0,("ldap_get_sid_from_id: mapping not found for %s: %u\n", 
			type, ((id_type & ID_USERID) ? id.uid : id.gid)));
		goto out;
	}
	
	entry = ldap_first_entry(ldap_state.ldap_struct, result);
	
	if ( !ldap_idmap_attribute(&ldap_state, entry, LDAP_ATTRIBUTE_SID, sid_str) )
		goto out;
	   
	if (!string_to_sid(sid, sid_str)) 
		goto out;

	ret = NT_STATUS_OK;
out:
	free_attr_list( attr_list );	 

	return ret;
}

/***********************************************************************
 Get an id from a sid 
***********************************************************************/

static NTSTATUS ldap_get_id_from_sid(unid_t *id, int *id_type, const DOM_SID *sid)
{
	LDAPMessage *result = 0;
	LDAPMessage *entry = 0;
	pstring sid_str;
	pstring filter;
	pstring id_str;
	const char *type;
	const char *obj_class;
	int rc;
	int count;
	char **attr_list;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	/* first try getting the mapping from a samba user or group */
	
	if ( *id_type & ID_USERID ) {
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER );
		obj_class = LDAP_OBJ_SAMBASAMACCOUNT;
	}
	else {
		type = get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER );
		obj_class = LDAP_OBJ_GROUPMAP;
	}	
	   
	sid_to_string(sid_str, sid);
	snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%s))", obj_class, 
		LDAP_ATTRIBUTE_SID, sid_str);

	attr_list = get_attr_list( sidmap_attr_list );
	rc = ldap_idmap_search(&ldap_state, lp_ldap_suffix(), LDAP_SCOPE_SUBTREE, 
		filter, attr_list, 0, &result);
		
	if (rc != LDAP_SUCCESS)
		goto out;

	count = ldap_count_entries(ldap_state.ldap_struct, result);
	
	/* fall back to looking up an idmap entry if we didn't find and 
	   actual user or group */

	if (count == 0) {
		snprintf(filter, sizeof(filter), "(&(objectClass=%s)(%s=%s))", 
			LDAP_OBJ_IDMAP_ENTRY, LDAP_ATTRIBUTE_SID, sid_str);

		rc = ldap_idmap_search(&ldap_state, lp_ldap_suffix(), 
			LDAP_SCOPE_SUBTREE, filter, attr_list, 0, &result);
			
		if (rc != LDAP_SUCCESS)
			goto out;
			
		count = ldap_count_entries(ldap_state.ldap_struct, result);
	}
	   
	if ( count > 1 ) {
		DEBUG(0, ("ldap_get_id_from_sid: search %s returned more than on entry!\n",
			filter));
		goto out;
	}

	/* we might have an existing entry to work with so pull out the requested information */
	
	if ( count )
		entry = ldap_first_entry(ldap_state.ldap_struct, result);
	
	/* if entry == NULL, then we will default to allocating a new id */
	
	if ( !ldap_idmap_attribute(&ldap_state, entry, type, id_str) ) 
	{
		int i;

		for (i = 0; i < LDAP_MAX_ALLOC_ID; i++) 
		{
			ret = ldap_allocate_id(id, *id_type);
			if ( NT_STATUS_IS_OK(ret) )
				break;
		}
		
		if ( !NT_STATUS_IS_OK(ret) ) {
			DEBUG(0,("ldap_allocate_id: cannot acquire id lock!\n"));
			goto out;
		}
		
		ret = ldap_set_mapping(sid, *id, *id_type);
		
	} 
	else 
	{
		if ( (*id_type & ID_USERID) )
			id->uid = strtoul(id_str, NULL, 10);
		else
			id->gid = strtoul(id_str, NULL, 10);
			
		ret = NT_STATUS_OK;
	}
out:
	free_attr_list( attr_list );
	
	return ret;
}

/***********************************************************************
 This function cannot be called to modify a mapping, only set a new one 
***********************************************************************/

static NTSTATUS ldap_set_mapping(const DOM_SID *sid, unid_t id, int id_type)
{
	pstring dn, sid_str, id_str;
	fstring type, obj_str, obj_str_val, attr_sid;
	LDAPMod *mods[4];
	LDAPMod mod[3];
	char *val[6];
	int rc;
	int attempts = 0;

	if ( id_type & ID_USERID ) 
		fstrcpy( type, get_attr_key2string( idpool_attr_list, LDAP_ATTR_UIDNUMBER ) );
	else
		fstrcpy( type, get_attr_key2string( idpool_attr_list, LDAP_ATTR_GIDNUMBER ) );

	snprintf(dn, sizeof(dn), "%s=%u,%s", type, ((id_type & ID_USERID) ? id.uid : id.gid), 
		lp_ldap_suffix());

	fstrcpy( obj_str, "objectClass" );
	fstrcpy( obj_str_val, LDAP_OBJ_IDMAP_ENTRY );
	fstrcpy( attr_sid, LDAP_ATTRIBUTE_SID );

	/* objectClass */
	
	mod[0].mod_op = LDAP_MOD_ADD;
	mod[0].mod_type = obj_str;
	val[0] = obj_str_val;
	val[1] = NULL;
	mod[0].mod_values = val;

	/* uid or gid */
	
	snprintf(id_str, sizeof(id_str), "%u", ((id_type & ID_USERID) ? id.uid : id.gid));	
	mod[1].mod_op = LDAP_MOD_ADD;
	mod[1].mod_type = type;
	val[2] = id_str; 
	val[3] = NULL;
	mod[1].mod_values = val+2;

	/* SID */
	
	sid_to_string(sid_str, sid);
	mod[2].mod_op = LDAP_MOD_ADD;
	mod[2].mod_type = attr_sid;
	val[4] = sid_str; 
	val[5] = NULL;
	mod[2].mod_values = val+4;

	mods[0] = mod; 
	mods[1] = mod + 1; 
	mods[2] = mod + 2; 
	mods[3] = NULL;

	do {
		if ((rc = ldap_idmap_retry_open(&ldap_state, &attempts)) != LDAP_SUCCESS) 
			continue;
		
		rc = ldap_add_s(ldap_state.ldap_struct, dn, mods);
	} while ((rc == LDAP_SERVER_DOWN) && (attempts <= 8));
	

	if (rc != LDAP_SUCCESS) {
		DEBUG(0,("ldap_set_mapping: Failed to create mapping from %s to %d [%s]\n",
			sid_str, ((id_type & ID_USERID) ? id.uid : id.gid), type));
		return NT_STATUS_UNSUCCESSFUL;
	}
		
	DEBUG(10,("ldap_set_mapping: Successfully created mapping from %s to %d [%s]\n",
		sid_str, ((id_type & ID_USERID) ? id.uid : id.gid), type));

	return NT_STATUS_OK;
}

/*****************************************************************************
 Initialise idmap database. 
*****************************************************************************/
static NTSTATUS ldap_idmap_init(void)
{
	/* We wait for the first search request before we try to connect to
	   the LDAP server.  We may want to connect upon initialization though
	   -- aliguori */
	return NT_STATUS_OK;
}

/*****************************************************************************
 End the LDAP session
*****************************************************************************/

static NTSTATUS ldap_idmap_close(void)
{
	if (ldap_state.ldap_struct != NULL) {
		ldap_unbind_ext(ldap_state.ldap_struct, NULL, NULL);
		ldap_state.ldap_struct = NULL;
	}
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	return NT_STATUS_OK;
}


/* This function doesn't make as much sense in an LDAP world since the calling
   node doesn't really control the ID ranges */
static void ldap_idmap_status(void)
{
	DEBUG(0, ("LDAP IDMAP Status not available\n"));
}

static struct idmap_methods ldap_methods = {
	ldap_idmap_init,
	ldap_get_sid_from_id,
	ldap_get_id_from_sid,
	ldap_set_mapping,
	ldap_idmap_close,
	ldap_idmap_status

};

NTSTATUS idmap_ldap_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "ldap", &ldap_methods);
}

/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jim McDonough                  2003
    
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

#ifdef HAVE_LDAP
/* TODO:
*  persistent connections: if using NSS LDAP, many connections are made
*      however, using only one within Samba would be nice
*  
*  Clean up SSL stuff, compile on OpenLDAP 1.x, 2.x, and Netscape SDK
*
*  Other LDAP based login attributes: accountExpires, etc.
*  (should be the domain of Samba proper, but the sam_password/SAM_ACCOUNT
*  structures don't have fields for some of these attributes)
*
*  SSL is done, but can't get the certificate based authentication to work
*  against on my test platform (Linux 2.4, OpenLDAP 2.x)
*/

/* NOTE: this will NOT work against an Active Directory server
*  due to the fact that the two password fields cannot be retrieved
*  from a server; recommend using security = domain in this situation
*  and/or winbind
*/

#include "smb_ldap.h"

/* We need an internal mapping of LDAP * -> smb_ldap_privates so we implement
   it in terms of a VK list.  It's a little backwards but its quite efficent */
static struct smb_ldap_privates *head;

static struct smb_ldap_privates *get_internal(LDAP *ldap_struct)
{
	struct smb_ldap_privates *ret = head;

	while (NULL != ret && ret->ldap_struct != ldap_struct) {
		ret = ret->next;
	}

	return ret;
}

#define SMB_LDAP_DONT_PING_TIME 10	/* ping only all 10 seconds */

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL smb_ldap_fetch_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size;
	
	*dn = smb_xstrdup(lp_ldap_admin_dn());
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("smb_ldap_fetch_pw: asprintf failed!\n"));
	}
	
	*pw=secrets_fetch(key, &size);
	if (!size) {
		/* Upgrade 2.2 style entry */
		char *p;
	        char* old_style_key = strdup(*dn);
		char *data;
		fstring old_style_pw;
		
		if (!old_style_key) {
			DEBUG(0, ("smb_ldap_fetch_pw: strdup failed!\n"));
			return False;
		}

		for (p=old_style_key; *p; p++)
			if (*p == ',') *p = '/';
	
		data=secrets_fetch(old_style_key, &size);
		if (!size && size < sizeof(old_style_pw)) {
			DEBUG(0,("fetch_ldap_pw: neither ldap secret retrieved!\n"));
			SAFE_FREE(old_style_key);
			SAFE_FREE(*dn);
			return False;
		}

		strncpy(old_style_pw, data, size);
		old_style_pw[size] = 0;

		SAFE_FREE(data);

		if (!secrets_store_ldap_pw(*dn, old_style_pw)) {
			DEBUG(0,("fetch_ldap_pw: ldap secret could not be upgraded!\n"));
			SAFE_FREE(old_style_key);
			SAFE_FREE(*dn);
			return False;			
		}
		if (!secrets_delete(old_style_key)) {
			DEBUG(0,("fetch_ldap_pw: old ldap secret could not be deleted!\n"));
		}

		SAFE_FREE(old_style_key);

		*pw = smb_xstrdup(old_style_pw);		
	}
	
	return True;
}

/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
int smb_ldap_open_connection (struct smb_ldap_privates *ldap_state, 
			      LDAP ** ldap_struct)
{
	int rc = LDAP_SUCCESS;
	int version;
	BOOL ldap_v3 = False;

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
	DEBUG(10, ("smb_ldap_open_connection: %s\n", ldap_state->uri));
	
	if ((rc = ldap_initialize(ldap_struct, ldap_state->uri)) != LDAP_SUCCESS) {
		DEBUG(0, ("ldap_initialize: %s\n", ldap_err2string(rc)));
		return rc;
	}
	
#else 

	/* Parse the string manually */

	{
		int port = 0;
		fstring protocol;
		fstring host;
		const char *p = ldap_state->uri; 
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
				DEBUG(0, ("unrecognised protocol (%s)!\n", protocol));
			}
		}
		
		if ((*ldap_struct = ldap_init(host, port)) == NULL)	{
			DEBUG(0, ("ldap_init failed !\n"));
			return LDAP_OPERATIONS_ERROR;
		}
		
	        if (strequal(protocol, "ldaps")) {
#ifdef LDAP_OPT_X_TLS
			int tls = LDAP_OPT_X_TLS_HARD;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_X_TLS, &tls) != LDAP_SUCCESS)
			{
				DEBUG(0, ("Failed to setup a TLS session\n"));
			}
			
			DEBUG(3,("LDAPS option set...!\n"));
#else
			DEBUG(0,("smb_ldap_open_connection: Secure connection not supported by LDAP client libraries!\n"));
			return LDAP_OPERATIONS_ERROR;
#endif
		}
	}
#endif

	if (ldap_get_option(*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS)
	{
		if (version != LDAP_VERSION3)
		{
			version = LDAP_VERSION3;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS) {
				ldap_v3 = True;
			}
		} else {
			ldap_v3 = True;
		}
	}

	if (lp_ldap_ssl() == LDAP_SSL_START_TLS) {
#ifdef LDAP_OPT_X_TLS
		if (ldap_v3) {
			if ((rc = ldap_start_tls_s (*ldap_struct, NULL, NULL)) != LDAP_SUCCESS)
			{
				DEBUG(0,("Failed to issue the StartTLS instruction: %s\n",
					 ldap_err2string(rc)));
				return rc;
			}
			DEBUG (3, ("StartTLS issued: using a TLS connection\n"));
		} else {
			
			DEBUG(0, ("Need LDAPv3 for Start TLS\n"));
			return LDAP_OPERATIONS_ERROR;
		}
#else
		DEBUG(0,("smb_ldap_open_connection: StartTLS not supported by LDAP client libraries!\n"));
		return LDAP_OPERATIONS_ERROR;
#endif
	}

	DEBUG(2, ("smb_ldap_open_connection: connection opened\n"));
	return rc;
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
	struct smb_ldap_privates *ldap_state = arg;
	
	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */
	
	if (freeit) {
		SAFE_FREE(*whop);
		memset(*credp, '\0', strlen(*credp));
		SAFE_FREE(*credp);
	} else {
		DEBUG(5,("rebind_proc_with_state: Rebinding as \"%s\"\n", 
			  ldap_state->bind_dn));

		*whop = strdup(ldap_state->bind_dn);
		if (!*whop) {
			return LDAP_NO_MEMORY;
		}
		*credp = strdup(ldap_state->bind_secret);
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
	struct smb_ldap_privates *ldap_state = arg;
	int rc;
	DEBUG(5,("rebindproc_connect_with_state: Rebinding as \"%s\"\n", 
		 ldap_state->bind_dn));
	
	/** @TODO Should we be doing something to check what servers we rebind to?
	    Could we get a referral to a machine that we don't want to give our
	    username and password to? */

	rc = ldap_simple_bind_s(ldap_struct, ldap_state->bind_dn, ldap_state->bind_secret);
	
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
				   method, freeit, get_internal(ldap_struct));
	
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
	return rebindproc_connect_with_state(ld, url, (ber_tag_t)request, msgid, 
					     get_internal(ld));
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
int smb_ldap_connect_system(struct smb_ldap_privates *ldap_state,
			    LDAP * ldap_struct)
{
	int rc;
	char *ldap_dn;
	char *ldap_secret;

	if (NULL == get_internal(ldap_struct)) {
		ldap_state->next = head;
	}

	/* get the password */
	if (!smb_ldap_fetch_pw(&ldap_dn, &ldap_secret))
	{
		DEBUG(0, ("ldap_connect_system: Failed to retrieve password from secrets.tdb\n"));
		return LDAP_INVALID_CREDENTIALS;
	}

	ldap_state->bind_dn = ldap_dn;
	ldap_state->bind_secret = ldap_secret;

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesnt' seem to support it */
	   
	DEBUG(10,("ldap_connect_system: Binding to ldap server %s as \"%s\"\n",
		  ldap_state->uri, ldap_dn));

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_connect_with_state, (void *)ldap_state);	
# endif
#else /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/
# if LDAP_SET_REBIND_PROC_ARGS == 2	
	ldap_set_rebind_proc(ldap_struct, &rebindproc);	
# endif
# if LDAP_SET_REBIND_PROC_ARGS == 3	
	ldap_set_rebind_proc(ldap_struct, &rebindproc_with_state, (void *)ldap_state);	
# endif
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

	rc = ldap_simple_bind_s(ldap_struct, ldap_dn, ldap_secret);

	if (rc != LDAP_SUCCESS) {
		char *ld_error;
		ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,
		      ("failed to bind to server with dn= %s Error: %s\n\t%s\n",
			       ldap_dn, ldap_err2string(rc),
			       ld_error));
		free(ld_error);
		return rc;
	}
	
	DEBUG(2, ("ldap_connect_system: succesful connection to the LDAP server\n"));
	return rc;
}

/**********************************************************************
Connect to LDAP server 
*********************************************************************/
int smb_ldap_open(struct smb_ldap_privates *ldap_state)
{
	int rc;
	SMB_ASSERT(ldap_state);
		
#ifndef NO_LDAP_SECURITY
	if (geteuid() != 0) {
		DEBUG(0, ("smb_ldap_open: cannot access LDAP when not root..\n"));
		return  LDAP_INSUFFICIENT_ACCESS;
	}
#endif

	if ((ldap_state->ldap_struct != NULL) && ((ldap_state->last_ping + SMB_LDAP_DONT_PING_TIME) < time(NULL))) {
		struct sockaddr_un addr;
		socklen_t len;
		int sd;
		if (ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_DESC, &sd) == 0 &&
		    getpeername(sd, (struct sockaddr *) &addr, &len) < 0) {
		    	/* the other end has died. reopen. */
		    	ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		    	ldap_state->ldap_struct = NULL;
		    	ldap_state->last_ping = (time_t)0;
		} else {
			ldap_state->last_ping = time(NULL);
		} 
    	}

	if (ldap_state->ldap_struct != NULL) {
		DEBUG(5,("smb_ldap_open: allready connected to the LDAP server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = smb_ldap_open_connection(ldap_state, &ldap_state->ldap_struct))) {
		return rc;
	}

	if ((rc = smb_ldap_connect_system(ldap_state, ldap_state->ldap_struct))) {
		ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		ldap_state->ldap_struct = NULL;
		return rc;
	}


	ldap_state->last_ping = time(NULL);
	DEBUG(4,("The LDAP server is succesful connected\n"));

	return LDAP_SUCCESS;
}

/**********************************************************************
Disconnect from LDAP server 
*********************************************************************/
NTSTATUS smb_ldap_close(struct smb_ldap_privates *ldap_state)
{
	if (!ldap_state)
		return NT_STATUS_INVALID_PARAMETER;
		
	if (ldap_state->ldap_struct != NULL) {
		ldap_unbind_ext(ldap_state->ldap_struct, NULL, NULL);
		ldap_state->ldap_struct = NULL;
	}
	
	DEBUG(5,("The connection to the LDAP server was closed\n"));
	/* maybe free the results here --metze */
	
	return NT_STATUS_OK;
}

static int smb_ldap_retry_open(struct smb_ldap_privates *ldap_state, int *attempts)
{
	int rc;

	SMB_ASSERT(ldap_state && attempts);
		
	if (*attempts != 0) {
		/* we retry after 0.5, 2, 4.5, 8, 12.5, 18, 24.5 seconds */
		msleep((((*attempts)*(*attempts))/2)*1000);
	}
	(*attempts)++;

	if ((rc = smb_ldap_open(ldap_state))) {
		DEBUG(0,("Connection to LDAP Server failed for the %d try!\n",*attempts));
		return rc;
	} 
	
	return LDAP_SUCCESS;		
}


int smb_ldap_search(struct smb_ldap_privates *ldap_state, 
		    const char *base, int scope, const char *filter, 
		    const char *attrs[], int attrsonly, 
		    LDAPMessage **res)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	SMB_ASSERT(ldap_state);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = smb_ldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_search_s(ldap_state->ldap_struct, base, scope, 
				   filter, attrs, attrsonly, res);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smb_ldap_close(ldap_state);	
	}
	
	return rc;
}

int smb_ldap_modify(struct smb_ldap_privates *ldap_state, char *dn, 
		    LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = smb_ldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_modify_s(ldap_state->ldap_struct, dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smb_ldap_close(ldap_state);	
	}
	
	return rc;
}

int smb_ldap_add(struct smb_ldap_privates *ldap_state, const char *dn,
		 LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = smb_ldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_add_s(ldap_state->ldap_struct, dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smb_ldap_close(ldap_state);	
	}
		
	return rc;
}

int smb_ldap_delete(struct smb_ldap_privates *ldap_state, char *dn)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = smb_ldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_delete_s(ldap_state->ldap_struct, dn);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smb_ldap_close(ldap_state);	
	}
		
	return rc;
}

int smb_ldap_extended_operation(struct smb_ldap_privates *ldap_state,
				LDAP_CONST char *reqoid,
				struct berval *reqdata,
				LDAPControl **serverctrls,
				LDAPControl **clientctrls, char **retoidp,
				struct berval **retdatap)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = smb_ldap_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_extended_operation_s(ldap_state->ldap_struct, reqoid, reqdata, serverctrls, clientctrls, retoidp, retdatap);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		smb_ldap_close(ldap_state);	
	}
		
	return rc;
}

/*******************************************************************
search an attribute and return the first value found.
******************************************************************/
BOOL smb_ldap_get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				   const char *attribute, pstring value)
{
	char **values;

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		value = NULL;
		DEBUG (10, ("smb_ldap_get_single_attribute: [%s] = [<does not exist>]\n", attribute));
		
		return False;
	}
	
	pstrcpy(value, values[0]);
	ldap_value_free(values);
#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("smb_ldap_get_single_attribute: [%s] = [%s]\n", attribute, value));
#endif	
	return True;
}
  

/************************************************************************
Routine to manage the LDAPMod structure array
manage memory used by the array, by each struct, and values

************************************************************************/
void smb_ldap_make_a_mod (LDAPMod *** modlist, int modop, 
			  const char *attribute, const char *value)
{
	LDAPMod **mods;
	int i;
	int j;

	mods = *modlist;

	if (attribute == NULL || *attribute == '\0')
		return;

	if (value == NULL || *value == '\0')
		return;

	if (mods == NULL) 
	{
		mods = (LDAPMod **) malloc(sizeof(LDAPMod *));
		if (mods == NULL)
		{
			DEBUG(0, ("smb_ldap_make_a_mod: out of memory!\n"));
			return;
		}
		mods[0] = NULL;
	}

	for (i = 0; mods[i] != NULL; ++i) {
		if (mods[i]->mod_op == modop && !strcasecmp(mods[i]->mod_type, attribute))
			break;
	}

	if (mods[i] == NULL)
	{
		mods = (LDAPMod **) Realloc (mods, (i + 2) * sizeof (LDAPMod *));
		if (mods == NULL)
		{
			DEBUG(0, ("smb_ldap_make_a_mod: out of memory!\n"));
			return;
		}
		mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
		if (mods[i] == NULL)
		{
			DEBUG(0, ("smb_ldap_make_a_mod: out of memory!\n"));
			return;
		}
		mods[i]->mod_op = modop;
		mods[i]->mod_values = NULL;
		mods[i]->mod_type = strdup(attribute);
		mods[i + 1] = NULL;
	}

	if (value != NULL)
	{
		j = 0;
		if (mods[i]->mod_values != NULL) {
			for (; mods[i]->mod_values[j] != NULL; j++);
		}
		mods[i]->mod_values = (char **)Realloc(mods[i]->mod_values,
					       (j + 2) * sizeof (char *));
					       
		if (mods[i]->mod_values == NULL) {
			DEBUG (0, ("smb_ldap_make_a_mod: Memory allocation failure!\n"));
			return;
		}
		mods[i]->mod_values[j] = strdup(value);
		mods[i]->mod_values[j + 1] = NULL;
	}
	*modlist = mods;
}

#endif

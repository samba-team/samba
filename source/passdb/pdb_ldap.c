/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Jean François Micouleau	1998
   Copyright (C) Gerald Carter			2001
   Copyright (C) Shahms King			2001
   Copyright (C) Andrew Bartlett		2002
   Copyright (C) Stefan (metze) Metzmacher	2002
    
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

#include <lber.h>
#include <ldap.h>

#ifndef SAM_ACCOUNT
#define SAM_ACCOUNT struct sam_passwd
#endif

struct ldapsam_privates {

	/* Former statics */
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;
	
	time_t last_ping;
	/* retrive-once info */
	const char *uri;
	
	BOOL permit_non_unix_accounts;
	
	uint32 low_nua_rid; 
	uint32 high_nua_rid; 

	char *bind_dn;
	char *bind_secret;
};

#define LDAPSAM_DONT_PING_TIME 10	/* ping only all 10 seconds */

static struct ldapsam_privates *static_ldap_state;

static uint32 ldapsam_get_next_available_nua_rid(struct ldapsam_privates *ldap_state);

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL fetch_ldapsam_pw(char **dn, char** pw)
{
	char *key = NULL;
	size_t size;
	
	*dn = smb_xstrdup(lp_ldap_admin_dn());
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, *dn) < 0) {
		SAFE_FREE(*dn);
		DEBUG(0, ("fetch_ldapsam_pw: asprintf failed!\n"));
	}
	
	*pw=secrets_fetch(key, &size);
	if (!size) {
		/* Upgrade 2.2 style entry */
		char *p;
	        char* old_style_key = strdup(*dn);
		char *data;
		fstring old_style_pw;
		
		if (!old_style_key) {
			DEBUG(0, ("fetch_ldapsam_pw: strdup failed!\n"));
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

static const char *attr[] = {"uid", "pwdLastSet", "logonTime",
			     "logoffTime", "kickoffTime", "cn",
			     "pwdCanChange", "pwdMustChange",
			     "displayName", "homeDrive",
			     "smbHome", "scriptPath",
			     "profilePath", "description",
			     "userWorkstations", "rid",
			     "primaryGroupID", "lmPassword",
			     "ntPassword", "acctFlags",
			     "domain", "objectClass", 
			     "uidNumber", "gidNumber", 
			     "homeDirectory", NULL };

/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static int ldapsam_open_connection (struct ldapsam_privates *ldap_state, LDAP ** ldap_struct)
{
	int rc = LDAP_SUCCESS;
	int version;
	BOOL ldap_v3 = False;

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
	DEBUG(10, ("ldapsam_open_connection: %s\n", ldap_state->uri));
	
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
			DEBUG(0,("ldapsam_open_connection: Secure connection not supported by LDAP client libraries!\n"));
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
		DEBUG(0,("ldapsam_open_connection: StartTLS not supported by LDAP client libraries!\n"));
		return LDAP_OPERATIONS_ERROR;
#endif
	}

	DEBUG(2, ("ldapsam_open_connection: connection opened\n"));
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
	struct ldapsam_privates *ldap_state = arg;
	
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
	struct ldapsam_privates *ldap_state = arg;
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
				   method, freeit, static_ldap_state);
	
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
					     static_ldap_state);
}
# endif /*LDAP_SET_REBIND_PROC_ARGS == 2*/
#endif /*defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)*/

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static int ldapsam_connect_system(struct ldapsam_privates *ldap_state, LDAP * ldap_struct)
{
	int rc;
	char *ldap_dn;
	char *ldap_secret;

	/* The rebind proc needs this *HACK*.  We are not multithreaded, so
	   this will work, but it's not nice. */
	static_ldap_state = ldap_state;

	/* get the password */
	if (!fetch_ldapsam_pw(&ldap_dn, &ldap_secret))
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
static int ldapsam_open(struct ldapsam_privates *ldap_state)
{
	int rc;
	SMB_ASSERT(ldap_state);
		
#ifndef NO_LDAP_SECURITY
	if (geteuid() != 0) {
		DEBUG(0, ("ldapsam_open: cannot access LDAP when not root..\n"));
		return  LDAP_INSUFFICIENT_ACCESS;
	}
#endif

	if ((ldap_state->ldap_struct != NULL) && ((ldap_state->last_ping + LDAPSAM_DONT_PING_TIME) < time(NULL))) {
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
		DEBUG(5,("ldapsam_open: allready connected to the LDAP server\n"));
		return LDAP_SUCCESS;
	}

	if ((rc = ldapsam_open_connection(ldap_state, &ldap_state->ldap_struct))) {
		return rc;
	}

	if ((rc = ldapsam_connect_system(ldap_state, ldap_state->ldap_struct))) {
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
static NTSTATUS ldapsam_close(struct ldapsam_privates *ldap_state)
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

static int ldapsam_retry_open(struct ldapsam_privates *ldap_state, int *attempts)
{
	int rc;

	SMB_ASSERT(ldap_state && attempts);
		
	if (*attempts != 0) {
		/* we retry after 0.5, 2, 4.5, 8, 12.5, 18, 24.5 seconds */
		msleep((((*attempts)*(*attempts))/2)*1000);
	}
	(*attempts)++;

	if ((rc = ldapsam_open(ldap_state))) {
		DEBUG(0,("Connection to LDAP Server failed for the %d try!\n",*attempts));
		return rc;
	} 
	
	return LDAP_SUCCESS;		
}


static int ldapsam_search(struct ldapsam_privates *ldap_state, 
			  const char *base, int scope, const char *filter, 
			  const char *attrs[], int attrsonly, 
			  LDAPMessage **res)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	SMB_ASSERT(ldap_state);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_search_s(ldap_state->ldap_struct, base, scope, 
				   filter, attrs, attrsonly, res);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
	
	return rc;
}

static int ldapsam_modify(struct ldapsam_privates *ldap_state, char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_modify_s(ldap_state->ldap_struct, dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
	
	return rc;
}

static int ldapsam_add(struct ldapsam_privates *ldap_state, const char *dn, LDAPMod *attrs[])
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_add_s(ldap_state->ldap_struct, dn, attrs);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	return rc;
}

static int ldapsam_delete(struct ldapsam_privates *ldap_state, char *dn)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_delete_s(ldap_state->ldap_struct, dn);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	return rc;
}

static int ldapsam_extended_operation(struct ldapsam_privates *ldap_state, LDAP_CONST char *reqoid, struct berval *reqdata, LDAPControl **serverctrls, LDAPControl **clientctrls, char **retoidp, struct berval **retdatap)
{
	int 		rc = LDAP_SERVER_DOWN;
	int 		attempts = 0;
	
	if (!ldap_state)
		return (-1);

	while ((rc == LDAP_SERVER_DOWN) && (attempts < 8)) {
		
		if ((rc = ldapsam_retry_open(ldap_state,&attempts)) != LDAP_SUCCESS)
			continue;
		
		rc = ldap_extended_operation_s(ldap_state->ldap_struct, reqoid, reqdata, serverctrls, clientctrls, retoidp, retdatap);
	}
	
	if (rc == LDAP_SERVER_DOWN) {
		DEBUG(0,("%s: LDAP server is down!\n",FUNCTION_MACRO));
		ldapsam_close(ldap_state);	
	}
		
	return rc;
}

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldapsam_search_one_user (struct ldapsam_privates *ldap_state, const char *filter, LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;

	DEBUG(2, ("ldapsam_search_one_user: searching for:[%s]\n", filter));

	rc = ldapsam_search(ldap_state, lp_ldap_suffix (), scope, filter, attr, 0, result);

	if (rc != LDAP_SUCCESS)	{
		DEBUG(0,("ldapsam_search_one_user: Problem during the LDAP search: %s\n", 
			ldap_err2string (rc)));
		DEBUG(3,("ldapsam_search_one_user: Query was: %s, %s\n", lp_ldap_suffix(), 
			filter));
	}
	
	return rc;
}

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldapsam_search_one_user_by_name (struct ldapsam_privates *ldap_state, const char *user,
			     LDAPMessage ** result)
{
	pstring filter;
	char *escape_user = escape_ldap_string_alloc(user);

	if (!escape_user) {
		return LDAP_NO_MEMORY;
	}

	/*
	 * in the filter expression, replace %u with the real name
	 * so in ldap filter, %u MUST exist :-)
	 */
	pstrcpy(filter, lp_ldap_filter());

	/* 
	 * have to use this here because $ is filtered out
	   * in pstring_sub
	 */
	

	all_string_sub(filter, "%u", escape_user, sizeof(pstring));
	SAFE_FREE(escape_user);

	return ldapsam_search_one_user(ldap_state, filter, result);
}

/*******************************************************************
 run the search by uid.
******************************************************************/
static int ldapsam_search_one_user_by_uid(struct ldapsam_privates *ldap_state, 
					  int uid,
					  LDAPMessage ** result)
{
	struct passwd *user;
	pstring filter;
	char *escape_user;

	/* Get the username from the system and look that up in the LDAP */
	
	if ((user = getpwuid_alloc(uid)) == NULL) {
		DEBUG(3,("ldapsam_search_one_user_by_uid: Failed to locate uid [%d]\n", uid));
		return LDAP_NO_SUCH_OBJECT;
	}
	
	pstrcpy(filter, lp_ldap_filter());
	
	escape_user = escape_ldap_string_alloc(user->pw_name);
	if (!escape_user) {
		passwd_free(&user);
		return LDAP_NO_MEMORY;
	}

	all_string_sub(filter, "%u", escape_user, sizeof(pstring));

	passwd_free(&user);
	SAFE_FREE(escape_user);

	return ldapsam_search_one_user(ldap_state, filter, result);
}

/*******************************************************************
 run the search by rid.
******************************************************************/
static int ldapsam_search_one_user_by_rid (struct ldapsam_privates *ldap_state, 
					   uint32 rid,
					   LDAPMessage ** result)
{
	pstring filter;
	int rc;

	/* check if the user rid exsists, if not, try searching on the uid */
	
	snprintf(filter, sizeof(filter) - 1, "rid=%i", rid);
	rc = ldapsam_search_one_user(ldap_state, filter, result);
	
	if (rc != LDAP_SUCCESS)
		rc = ldapsam_search_one_user_by_uid(ldap_state,
						    fallback_pdb_user_rid_to_uid(rid), 
						    result);

	return rc;
}

/*******************************************************************
search an attribute and return the first value found.
******************************************************************/
static BOOL get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				  const char *attribute, pstring value)
{
	char **values;

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		value = NULL;
		DEBUG (10, ("get_single_attribute: [%s] = [<does not exist>]\n", attribute));
		
		return False;
	}
	
	pstrcpy(value, values[0]);
	ldap_value_free(values);
#ifdef DEBUG_PASSWORDS
	DEBUG (100, ("get_single_attribute: [%s] = [%s]\n", attribute, value));
#endif	
	return True;
}

/************************************************************************
Routine to manage the LDAPMod structure array
manage memory used by the array, by each struct, and values

************************************************************************/
static void make_a_mod (LDAPMod *** modlist, int modop, const char *attribute, const char *value)
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
			DEBUG(0, ("make_a_mod: out of memory!\n"));
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
			DEBUG(0, ("make_a_mod: out of memory!\n"));
			return;
		}
		mods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
		if (mods[i] == NULL)
		{
			DEBUG(0, ("make_a_mod: out of memory!\n"));
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
			DEBUG (0, ("make_a_mod: Memory allocation failure!\n"));
			return;
		}
		mods[i]->mod_values[j] = strdup(value);
		mods[i]->mod_values[j + 1] = NULL;
	}
	*modlist = mods;
}

/* New Interface is being implemented here */

/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query (unix attributes only)
*********************************************************************/
static BOOL get_unix_attributes (struct ldapsam_privates *ldap_state, 
				SAM_ACCOUNT * sampass,
				LDAPMessage * entry)
{
	pstring  homedir;
	pstring  temp;
	uid_t uid;
	gid_t gid;
	char **ldap_values;
	char **values;

	if ((ldap_values = ldap_get_values (ldap_state->ldap_struct, entry, "objectClass")) == NULL) {
		DEBUG (1, ("get_unix_attributes: no objectClass! \n"));
		return False;
	}

	for (values=ldap_values;*values;values++) {
		if (strcasecmp(*values, "posixAccount") == 0) {
			break;
		}
	}
	
	if (!*values) { /*end of array, no posixAccount */
		DEBUG(10, ("user does not have posixAcccount attributes\n"));
		ldap_value_free(ldap_values);
		return False;
	}
	ldap_value_free(ldap_values);

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "homeDirectory", homedir)) 
		return False;
	
	if (!get_single_attribute(ldap_state->ldap_struct, entry, "uidNumber", temp))
		return False;
	
	uid = (uid_t)atol(temp);
	
	if (!get_single_attribute(ldap_state->ldap_struct, entry, "gidNumber", temp))
		return False;
	
	gid = (gid_t)atol(temp);

	pdb_set_unix_homedir(sampass, homedir, PDB_SET);
	pdb_set_uid(sampass, uid, PDB_SET);
	pdb_set_gid(sampass, gid, PDB_SET);
	
	DEBUG(10, ("user has posixAcccount attributes\n"));
	return True;
}


/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_sam_from_buffer in pdb_tdb.c)
*********************************************************************/
static BOOL init_sam_from_ldap (struct ldapsam_privates *ldap_state, 
				SAM_ACCOUNT * sampass,
				LDAPMessage * entry)
{
	time_t  logon_time,
			logoff_time,
			kickoff_time,
			pass_last_set_time, 
			pass_can_change_time, 
			pass_must_change_time;
	pstring 	username, 
			domain,
			nt_username,
			fullname,
			homedir,
			dir_drive,
			logon_script,
			profile_path,
			acct_desc,
			munged_dial,
			workstations;
	struct passwd	*pw;
	uint32 		user_rid, 
			group_rid;
	uint8 		smblmpwd[LM_HASH_LEN],
			smbntpwd[NT_HASH_LEN];
	uint16 		acct_ctrl = 0, 
			logon_divs;
	uint32 hours_len;
	uint8 		hours[MAX_HOURS_LEN];
	pstring temp;
	uid_t		uid = -1;
	gid_t 		gid = getegid();


	/*
	 * do a little initialization
	 */
	username[0] 	= '\0';
	domain[0] 	= '\0';
	nt_username[0] 	= '\0';
	fullname[0] 	= '\0';
	homedir[0] 	= '\0';
	dir_drive[0] 	= '\0';
	logon_script[0] = '\0';
	profile_path[0] = '\0';
	acct_desc[0] 	= '\0';
	munged_dial[0] 	= '\0';
	workstations[0] = '\0';
	 

	if (sampass == NULL || ldap_state == NULL || entry == NULL) {
		DEBUG(0, ("init_sam_from_ldap: NULL parameters found!\n"));
		return False;
	}

	if (ldap_state->ldap_struct == NULL) {
		DEBUG(0, ("init_sam_from_ldap: ldap_state->ldap_struct is NULL!\n"));
		return False;
	}
	
	get_single_attribute(ldap_state->ldap_struct, entry, "uid", username);
	DEBUG(2, ("Entry found for user: %s\n", username));

	pstrcpy(nt_username, username);

	pstrcpy(domain, lp_workgroup());
	
	pdb_set_username(sampass, username, PDB_SET);

	pdb_set_domain(sampass, domain, PDB_DEFAULT);
	pdb_set_nt_username(sampass, nt_username, PDB_SET);

	get_single_attribute(ldap_state->ldap_struct, entry, "rid", temp);
	user_rid = (uint32)atol(temp);

	pdb_set_user_sid_from_rid(sampass, user_rid, PDB_SET);

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "primaryGroupID", temp)) {
		group_rid = 0;
	} else {
		group_rid = (uint32)atol(temp);
		pdb_set_group_sid_from_rid(sampass, group_rid, PDB_SET);
	}


	/* 
	 * If so configured, try and get the values from LDAP 
	 */

	if (!lp_ldap_trust_ids() || (!get_unix_attributes(ldap_state, sampass, entry))) {
		
		/* 
		 * Otherwise just ask the system getpw() calls.
		 */
	
		pw = getpwnam_alloc(username);
		if (pw == NULL) {
			if (! ldap_state->permit_non_unix_accounts) {
				DEBUG (2,("init_sam_from_ldap: User [%s] does not exist via system getpwnam!\n", username));
				return False;
			}
		} else {
			uid = pw->pw_uid;
			pdb_set_uid(sampass, uid, PDB_SET);
			gid = pw->pw_gid;
			pdb_set_gid(sampass, gid, PDB_SET);
			
			pdb_set_unix_homedir(sampass, pw->pw_dir, PDB_SET);

			passwd_free(&pw);
		}
	}

	if (group_rid == 0 && pdb_get_init_flags(sampass,PDB_GID) != PDB_DEFAULT) {
		GROUP_MAP map;
		gid = pdb_get_gid(sampass);
		/* call the mapping code here */
		if(pdb_getgrgid(&map, gid, MAPPING_WITHOUT_PRIV)) {
			pdb_set_group_sid(sampass, &map.sid, PDB_SET);
		} 
		else {
			pdb_set_group_sid_from_rid(sampass, pdb_gid_to_group_rid(gid), PDB_SET);
		}
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "pwdLastSet", temp)) {
		/* leave as default */
	} else {
		pass_last_set_time = (time_t) atol(temp);
		pdb_set_pass_last_set_time(sampass, pass_last_set_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "logonTime", temp)) {
		/* leave as default */
	} else {
		logon_time = (time_t) atol(temp);
		pdb_set_logon_time(sampass, logon_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "logoffTime", temp)) {
		/* leave as default */
	} else {
		logoff_time = (time_t) atol(temp);
		pdb_set_logoff_time(sampass, logoff_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "kickoffTime", temp)) {
		/* leave as default */
	} else {
		kickoff_time = (time_t) atol(temp);
		pdb_set_kickoff_time(sampass, kickoff_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "pwdCanChange", temp)) {
		/* leave as default */
	} else {
		pass_can_change_time = (time_t) atol(temp);
		pdb_set_pass_can_change_time(sampass, pass_can_change_time, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "pwdMustChange", temp)) {
		/* leave as default */
	} else {
		pass_must_change_time = (time_t) atol(temp);
		pdb_set_pass_must_change_time(sampass, pass_must_change_time, PDB_SET);
	}

	/* recommend that 'gecos' and 'displayName' should refer to the same
	 * attribute OID.  userFullName depreciated, only used by Samba
	 * primary rules of LDAP: don't make a new attribute when one is already defined
	 * that fits your needs; using cn then displayName rather than 'userFullName'
	 */

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "cn", fullname)) {
		if (!get_single_attribute(ldap_state->ldap_struct, entry, "displayName", fullname)) {
			/* leave as default */
		} else {
			pdb_set_fullname(sampass, fullname, PDB_SET);
		}
	} else {
		pdb_set_fullname(sampass, fullname, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "homeDrive", dir_drive)) {
		pdb_set_dir_drive(sampass, talloc_sub_specified(sampass->mem_ctx, 
								  lp_logon_drive(),
								  username, domain, 
								  uid, gid),
				  PDB_DEFAULT);
	} else {
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "smbHome", homedir)) {
		pdb_set_homedir(sampass, talloc_sub_specified(sampass->mem_ctx, 
								  lp_logon_home(),
								  username, domain, 
								  uid, gid), 
				  PDB_DEFAULT);
	} else {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "scriptPath", logon_script)) {
		pdb_set_logon_script(sampass, talloc_sub_specified(sampass->mem_ctx, 
								     lp_logon_script(),
								     username, domain, 
								     uid, gid), 
				     PDB_DEFAULT);
	} else {
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "profilePath", profile_path)) {
		pdb_set_profile_path(sampass, talloc_sub_specified(sampass->mem_ctx, 
								     lp_logon_path(),
								     username, domain, 
								     uid, gid), 
				     PDB_DEFAULT);
	} else {
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "description", acct_desc)) {
		/* leave as default */
	} else {
		pdb_set_acct_desc(sampass, acct_desc, PDB_SET);
	}

	if (!get_single_attribute(ldap_state->ldap_struct, entry, "userWorkstations", workstations)) {
		/* leave as default */;
	} else {
		pdb_set_workstations(sampass, workstations, PDB_SET);
	}

	/* FIXME: hours stuff should be cleaner */
	
	logon_divs = 168;
	hours_len = 21;
	memset(hours, 0xff, hours_len);

	if (!get_single_attribute (ldap_state->ldap_struct, entry, "lmPassword", temp)) {
		/* leave as default */
	} else {
		pdb_gethexpwd(temp, smblmpwd);
		memset((char *)temp, '\0', strlen(temp)+1);
		if (!pdb_set_lanman_passwd(sampass, smblmpwd, PDB_SET))
			return False;
		ZERO_STRUCT(smblmpwd);
	}

	if (!get_single_attribute (ldap_state->ldap_struct, entry, "ntPassword", temp)) {
		/* leave as default */
	} else {
		pdb_gethexpwd(temp, smbntpwd);
		memset((char *)temp, '\0', strlen(temp)+1);
		if (!pdb_set_nt_passwd(sampass, smbntpwd, PDB_SET))
			return False;
		ZERO_STRUCT(smbntpwd);
	}

	if (!get_single_attribute (ldap_state->ldap_struct, entry, "acctFlags", temp)) {
		acct_ctrl |= ACB_NORMAL;
	} else {
		acct_ctrl = pdb_decode_acct_ctrl(temp);

		if (acct_ctrl == 0)
			acct_ctrl |= ACB_NORMAL;

		pdb_set_acct_ctrl(sampass, acct_ctrl, PDB_SET);
	}

	pdb_set_hours_len(sampass, hours_len, PDB_SET);
	pdb_set_logon_divs(sampass, logon_divs, PDB_SET);

	pdb_set_munged_dial(sampass, munged_dial, PDB_SET);
	
	/* pdb_set_unknown_3(sampass, unknown3, PDB_SET); */
	/* pdb_set_unknown_5(sampass, unknown5, PDB_SET); */
	/* pdb_set_unknown_6(sampass, unknown6, PDB_SET); */

	pdb_set_hours(sampass, hours, PDB_SET);

	return True;
}

static BOOL need_ldap_mod(BOOL pdb_add, const SAM_ACCOUNT * sampass, enum pdb_elements element) {
	if (pdb_add) {
		return (!IS_SAM_DEFAULT(sampass, element));
	} else {
		return IS_SAM_CHANGED(sampass, element);
	}
}

/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_buffer_from_sam in pdb_tdb.c)
*********************************************************************/
static BOOL init_ldap_from_sam (struct ldapsam_privates *ldap_state, 
				LDAPMod *** mods, int ldap_op, 
				BOOL pdb_add,
				const SAM_ACCOUNT * sampass)
{
	pstring temp;
	uint32 rid;

	if (mods == NULL || sampass == NULL) {
		DEBUG(0, ("init_ldap_from_sam: NULL parameters found!\n"));
		return False;
	}

	*mods = NULL;

	/* 
	 * took out adding "objectclass: sambaAccount"
	 * do this on a per-mod basis
	 */
	if (need_ldap_mod(pdb_add, sampass, PDB_USERNAME)) {
		make_a_mod(mods, ldap_op, "uid", pdb_get_username(sampass));
		DEBUG(2, ("Setting entry for user: %s\n", pdb_get_username(sampass)));
	}
	
	if ((rid = pdb_get_user_rid(sampass))!=0 ) {
		if (need_ldap_mod(pdb_add, sampass, PDB_USERSID)) {		
			slprintf(temp, sizeof(temp) - 1, "%i", rid);
			make_a_mod(mods, ldap_op, "rid", temp);
		}
	} else if (!IS_SAM_DEFAULT(sampass, PDB_UID)) {
		rid = fallback_pdb_uid_to_user_rid(pdb_get_uid(sampass));
		slprintf(temp, sizeof(temp) - 1, "%i", rid);
		make_a_mod(mods, ldap_op, "rid", temp);
	} else if (ldap_state->permit_non_unix_accounts) {
		rid = ldapsam_get_next_available_nua_rid(ldap_state);
		if (rid == 0) {
			DEBUG(0, ("NO user RID specified on account %s, and findining next available NUA RID failed, cannot store!\n", pdb_get_username(sampass)));
			return False;
		}
		slprintf(temp, sizeof(temp) - 1, "%i", rid);
		make_a_mod(mods, ldap_op, "rid", temp);
	} else {
		DEBUG(0, ("NO user RID specified on account %s, cannot store!\n", pdb_get_username(sampass)));
		return False;
	}



	if ((rid = pdb_get_group_rid(sampass))!=0 ) {
		if (need_ldap_mod(pdb_add, sampass, PDB_GROUPSID)) {		
			slprintf(temp, sizeof(temp) - 1, "%i", rid);
			make_a_mod(mods, ldap_op, "primaryGroupID", temp);
		}
	} else if (!IS_SAM_DEFAULT(sampass, PDB_GID)) {
		rid = pdb_gid_to_group_rid(pdb_get_gid(sampass));
		slprintf(temp, sizeof(temp) - 1, "%i", rid);
		make_a_mod(mods, ldap_op, "primaryGroupID", temp);
	} else if (ldap_state->permit_non_unix_accounts) {
		rid = DOMAIN_GROUP_RID_USERS;
		slprintf(temp, sizeof(temp) - 1, "%i", rid);
		make_a_mod(mods, ldap_op, "primaryGroupID", temp);
	} else {
		DEBUG(0, ("NO group RID specified on account %s, cannot store!\n", pdb_get_username(sampass)));
		return False;
	}


	/* displayName, cn, and gecos should all be the same
	 *  most easily accomplished by giving them the same OID
	 *  gecos isn't set here b/c it should be handled by the 
	 *  add-user script
	 */
	if (need_ldap_mod(pdb_add, sampass, PDB_FULLNAME)) {
		make_a_mod(mods, ldap_op, "displayName", pdb_get_fullname(sampass));
		make_a_mod(mods, ldap_op, "cn", pdb_get_fullname(sampass));
	}
	if (need_ldap_mod(pdb_add, sampass, PDB_ACCTDESC)) {	
		make_a_mod(mods, ldap_op, "description", pdb_get_acct_desc(sampass));
	}
	if (need_ldap_mod(pdb_add, sampass, PDB_WORKSTATIONS)) {	
		make_a_mod(mods, ldap_op, "userWorkstations", pdb_get_workstations(sampass));
	}
	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */

	if (need_ldap_mod(pdb_add, sampass, PDB_SMBHOME)) {
		make_a_mod(mods, ldap_op, "smbHome", pdb_get_homedir(sampass));
	}
			
	if (need_ldap_mod(pdb_add, sampass, PDB_DRIVE)) {
		make_a_mod(mods, ldap_op, "homeDrive", pdb_get_dir_drive(sampass));
	}
	
	if (need_ldap_mod(pdb_add, sampass, PDB_LOGONSCRIPT)) {
		make_a_mod(mods, ldap_op, "scriptPath", pdb_get_logon_script(sampass));
	}
	
	if (need_ldap_mod(pdb_add, sampass, PDB_PROFILE))
		make_a_mod(mods, ldap_op, "profilePath", pdb_get_profile_path(sampass));

	if (need_ldap_mod(pdb_add, sampass, PDB_LOGONTIME)) {
		slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logon_time(sampass));
		make_a_mod(mods, ldap_op, "logonTime", temp);
	}

	if (need_ldap_mod(pdb_add, sampass, PDB_LOGOFFTIME)) {
		slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logoff_time(sampass));
		make_a_mod(mods, ldap_op, "logoffTime", temp);
	}

	if (need_ldap_mod(pdb_add, sampass, PDB_KICKOFFTIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_kickoff_time(sampass));
		make_a_mod(mods, ldap_op, "kickoffTime", temp);
	}


	if (need_ldap_mod(pdb_add, sampass, PDB_CANCHANGETIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_can_change_time(sampass));
		make_a_mod(mods, ldap_op, "pwdCanChange", temp);
	}

	if (need_ldap_mod(pdb_add, sampass, PDB_MUSTCHANGETIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_must_change_time(sampass));
		make_a_mod(mods, ldap_op, "pwdMustChange", temp);
	}

	if ((pdb_get_acct_ctrl(sampass)&(ACB_WSTRUST|ACB_SVRTRUST|ACB_DOMTRUST))||
		(lp_ldap_passwd_sync()!=LDAP_PASSWD_SYNC_ONLY)) {

		if (need_ldap_mod(pdb_add, sampass, PDB_LMPASSWD)) {
			pdb_sethexpwd (temp, pdb_get_lanman_passwd(sampass), pdb_get_acct_ctrl(sampass));
			make_a_mod (mods, ldap_op, "lmPassword", temp);
		}
		
		if (need_ldap_mod(pdb_add, sampass, PDB_NTPASSWD)) {
			pdb_sethexpwd (temp, pdb_get_nt_passwd(sampass), pdb_get_acct_ctrl(sampass));
			make_a_mod (mods, ldap_op, "ntPassword", temp);
		}
		
		if (need_ldap_mod(pdb_add, sampass, PDB_PASSLASTSET)) {
			slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_last_set_time(sampass));
			make_a_mod(mods, ldap_op, "pwdLastSet", temp);
		}
	}

	/* FIXME: Hours stuff goes in LDAP  */
	if (need_ldap_mod(pdb_add, sampass, PDB_ACCTCTRL)) {
		make_a_mod (mods, ldap_op, "acctFlags", pdb_encode_acct_ctrl (pdb_get_acct_ctrl(sampass),
			NEW_PW_FORMAT_SPACE_PADDED_LEN));
	}
	
	return True;
}


/**********************************************************************
Connect to LDAP server and find the next available RID.
*********************************************************************/
static uint32 check_nua_rid_is_avail(struct ldapsam_privates *ldap_state, uint32 top_rid) 
{
	LDAPMessage *result;
	uint32 final_rid = (top_rid & (~USER_RID_TYPE)) + RID_MULTIPLIER;
	if (top_rid == 0) {
		return 0;
	}
	
	if (final_rid < ldap_state->low_nua_rid || final_rid > ldap_state->high_nua_rid) {
		return 0;
	}

	if (ldapsam_search_one_user_by_rid(ldap_state, final_rid, &result) != LDAP_SUCCESS) {
		DEBUG(0, ("Cannot allocate NUA RID %d (0x%x), as the confirmation search failed!\n", final_rid, final_rid));
		return 0;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) != 0) {
		DEBUG(0, ("Cannot allocate NUA RID %d (0x%x), as the RID is already in use!!\n", final_rid, final_rid));
		ldap_msgfree(result);
		return 0;
	}

	DEBUG(5, ("NUA RID %d (0x%x), declared valid\n", final_rid, final_rid));
	ldap_msgfree(result);
	return final_rid;
}

/**********************************************************************
Extract the RID from an LDAP entry
*********************************************************************/
static uint32 entry_to_user_rid(struct ldapsam_privates *ldap_state, LDAPMessage *entry) {
	uint32 rid;
	SAM_ACCOUNT *user = NULL;
	if (!NT_STATUS_IS_OK(pdb_init_sam(&user))) {
		return 0;
	}

	if (init_sam_from_ldap(ldap_state, user, entry)) {
		rid = pdb_get_user_rid(user);
	} else {
		rid =0;
	}
     	pdb_free_sam(&user);
	if (rid >= ldap_state->low_nua_rid && rid <= ldap_state->high_nua_rid) {
		return rid;
	}
	return 0;
}


/**********************************************************************
Connect to LDAP server and find the next available RID.
*********************************************************************/
static uint32 search_top_nua_rid(struct ldapsam_privates *ldap_state)
{
	int rc;
	pstring filter;
	LDAPMessage *result;
	LDAPMessage *entry;
	char *final_filter = NULL;
	uint32 top_rid = 0;
	uint32 count;
	uint32 rid;

	pstrcpy(filter, lp_ldap_filter());
	all_string_sub(filter, "%u", "*", sizeof(pstring));

#if 0
	asprintf(&final_filter, "(&(%s)(&(rid>=%d)(rid<=%d)))", filter, ldap_state->low_nua_rid, ldap_state->high_nua_rid);
#else 
	final_filter = strdup(filter);
#endif	
	DEBUG(2, ("ldapsam_get_next_available_nua_rid: searching for:[%s]\n", final_filter));

	rc = ldapsam_search(ldap_state, lp_ldap_suffix(),
			   LDAP_SCOPE_SUBTREE, final_filter, attr, 0,
			   &result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(3, ("LDAP search failed! cannot find base for NUA RIDs: %s\n", ldap_err2string(rc)));
		DEBUGADD(3, ("Query was: %s, %s\n", lp_ldap_suffix(), final_filter));

		free(final_filter);
		result = NULL;
		return 0;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	DEBUG(2, ("search_top_nua_rid: %d entries in the base!\n", count));
	
	if (count == 0) {
		DEBUG(3, ("LDAP search returned no records, assuming no non-unix-accounts present!: %s\n", ldap_err2string(rc)));
		DEBUGADD(3, ("Query was: %s, %s\n", lp_ldap_suffix(), final_filter));
		free(final_filter);
		ldap_msgfree(result);
		result = NULL;
		return ldap_state->low_nua_rid;
	}
	
	free(final_filter);
	entry = ldap_first_entry(ldap_state->ldap_struct,result);

	top_rid = entry_to_user_rid(ldap_state, entry);

	while ((entry = ldap_next_entry(ldap_state->ldap_struct, entry))) {

		rid = entry_to_user_rid(ldap_state, entry);
		if (rid > top_rid) {
			top_rid = rid;
		}
	}

	ldap_msgfree(result);

	if (top_rid < ldap_state->low_nua_rid) 
		top_rid = ldap_state->low_nua_rid;

	return top_rid;
}

/**********************************************************************
Connect to LDAP server and find the next available RID.
*********************************************************************/
static uint32 ldapsam_get_next_available_nua_rid(struct ldapsam_privates *ldap_state) {
	uint32 next_nua_rid;
	uint32 top_nua_rid;

	top_nua_rid = search_top_nua_rid(ldap_state);

	next_nua_rid = check_nua_rid_is_avail(ldap_state, 
					      top_nua_rid);
	
	return next_nua_rid;
}

/**********************************************************************
Connect to LDAP server for password enumeration
*********************************************************************/
static NTSTATUS ldapsam_setsampwent(struct pdb_methods *my_methods, BOOL update)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	pstring filter;

	pstrcpy(filter, lp_ldap_filter());
	all_string_sub(filter, "%u", "*", sizeof(pstring));

	rc = ldapsam_search(ldap_state, lp_ldap_suffix(),
			   LDAP_SCOPE_SUBTREE, filter, attr, 0,
			   &ldap_state->result);

	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("LDAP search failed: %s\n", ldap_err2string(rc)));
		DEBUG(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
		ldap_msgfree(ldap_state->result);
		ldap_state->result = NULL;
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("ldapsam_setsampwent: %d entries in the base!\n",
		ldap_count_entries(ldap_state->ldap_struct,
		ldap_state->result)));

	ldap_state->entry = ldap_first_entry(ldap_state->ldap_struct,
				 ldap_state->result);
	ldap_state->index = 0;

	return NT_STATUS_OK;
}

/**********************************************************************
End enumeration of the LDAP password list 
*********************************************************************/
static void ldapsam_endsampwent(struct pdb_methods *my_methods)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	if (ldap_state->result) {
		ldap_msgfree(ldap_state->result);
		ldap_state->result = NULL;
	}
}

/**********************************************************************
Get the next entry in the LDAP password database 
*********************************************************************/
static NTSTATUS ldapsam_getsampwent(struct pdb_methods *my_methods, SAM_ACCOUNT *user)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	BOOL bret = False;

	/* The rebind proc needs this *HACK*.  We are not multithreaded, so
	   this will work, but it's not nice. */
	static_ldap_state = ldap_state;

	while (!bret) {
		if (!ldap_state->entry)
			return ret;
		
		ldap_state->index++;
		bret = init_sam_from_ldap(ldap_state, user, ldap_state->entry);
		
		ldap_state->entry = ldap_next_entry(ldap_state->ldap_struct,
					    ldap_state->entry);	
	}

	return NT_STATUS_OK;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by username 
*********************************************************************/
static NTSTATUS ldapsam_getsampwnam(struct pdb_methods *my_methods, SAM_ACCOUNT *user, const char *sname)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	LDAPMessage *result;
	LDAPMessage *entry;
	int count;
	
	if (ldapsam_search_one_user_by_name(ldap_state, sname, &result) != LDAP_SUCCESS) {
		return NT_STATUS_NO_SUCH_USER;
	}
	
	count = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (count < 1) {
		DEBUG(4,
		      ("We don't find this user [%s] count=%d\n", sname,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	} else if (count > 1) {
		DEBUG(1,
		      ("Duplicate entries for this user [%s] Failing. count=%d\n", sname,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	if (entry) {
		if (!init_sam_from_ldap(ldap_state, user, entry)) {
			DEBUG(1,("ldapsam_getsampwnam: init_sam_from_ldap failed for user '%s'!\n", sname));
			ldap_msgfree(result);
			return NT_STATUS_NO_SUCH_USER;
		}
		ldap_msgfree(result);
		ret = NT_STATUS_OK;
	} else {
		ldap_msgfree(result);
	}
	return ret;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by rid 
*********************************************************************/
static NTSTATUS ldapsam_getsampwrid(struct pdb_methods *my_methods, SAM_ACCOUNT *user, uint32 rid)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = 
		(struct ldapsam_privates *)my_methods->private_data;
	LDAPMessage *result;
	LDAPMessage *entry;
	int count;

	if (ldapsam_search_one_user_by_rid(ldap_state, rid, &result) != LDAP_SUCCESS) {
		return NT_STATUS_NO_SUCH_USER;
	}

	count = ldap_count_entries(ldap_state->ldap_struct, result);
		
	if (count < 1) {
		DEBUG(4,
		      ("We don't find this rid [%i] count=%d\n", rid,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	} else if (count > 1) {
		DEBUG(1,
		      ("More than one user with rid [%i]. Failing. count=%d\n", rid,
		       count));
		return NT_STATUS_NO_SUCH_USER;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	if (entry) {
		if (!init_sam_from_ldap(ldap_state, user, entry)) {
			DEBUG(1,("ldapsam_getsampwrid: init_sam_from_ldap failed!\n"));
			ldap_msgfree(result);
			return NT_STATUS_NO_SUCH_USER;
		}
		ldap_msgfree(result);
		ret = NT_STATUS_OK;
	} else {
		ldap_msgfree(result);
	}
	return ret;
}

static NTSTATUS ldapsam_getsampwsid(struct pdb_methods *my_methods, SAM_ACCOUNT * user, const DOM_SID *sid)
{
	uint32 rid;
	if (!sid_peek_check_rid(get_global_sam_sid(), sid, &rid))
		return NT_STATUS_NO_SUCH_USER;
	return ldapsam_getsampwrid(my_methods, user, rid);
}	

/********************************************************************
Do the actual modification - also change a plaittext passord if 
it it set.
**********************************************************************/

static NTSTATUS ldapsam_modify_entry(struct pdb_methods *my_methods, 
				     SAM_ACCOUNT *newpwd, char *dn,
				     LDAPMod **mods, int ldap_op, BOOL pdb_add)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	
	if (!my_methods || !newpwd || !dn) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (!mods) {
		DEBUG(5,("mods is empty: nothing to modify\n"));
		/* may be password change below however */
	} else {
		switch(ldap_op)
		{
			case LDAP_MOD_ADD: 
				make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", "account");
				rc = ldapsam_add(ldap_state, dn, mods);
				break;
			case LDAP_MOD_REPLACE: 
				rc = ldapsam_modify(ldap_state, dn ,mods);
				break;
			default: 	
				DEBUG(0,("Wrong LDAP operation type: %d!\n", ldap_op));
				return NT_STATUS_UNSUCCESSFUL;
		}
		
		if (rc!=LDAP_SUCCESS) {
			char *ld_error;
			ldap_get_option(ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING,
					&ld_error);
			DEBUG(1,
			      ("failed to %s user dn= %s with: %s\n\t%s\n",
			       ldap_op == LDAP_MOD_ADD ? "add" : "modify",
			       dn, ldap_err2string(rc),
			       ld_error));
			free(ld_error);
			return NT_STATUS_UNSUCCESSFUL;
		}  
	}
	
#ifdef LDAP_EXOP_X_MODIFY_PASSWD
	if (!(pdb_get_acct_ctrl(newpwd)&(ACB_WSTRUST|ACB_SVRTRUST|ACB_DOMTRUST))&&
		(lp_ldap_passwd_sync()!=LDAP_PASSWD_SYNC_OFF)&&
		need_ldap_mod(pdb_add, newpwd, PDB_PLAINTEXT_PW)&&
		(pdb_get_plaintext_passwd(newpwd)!=NULL)) {
		BerElement *ber;
		struct berval *bv;
		char *retoid;
		struct berval *retdata;

		if ((ber = ber_alloc_t(LBER_USE_DER))==NULL) {
			DEBUG(0,("ber_alloc_t returns NULL\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
		ber_printf (ber, "{");
		ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID,dn);
	        ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW, pdb_get_plaintext_passwd(newpwd));
	        ber_printf (ber, "N}");

	        if ((rc = ber_flatten (ber, &bv))<0) {
			DEBUG(0,("ber_flatten returns a value <0\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		ber_free(ber,1);

		if ((rc = ldapsam_extended_operation(ldap_state, LDAP_EXOP_X_MODIFY_PASSWD,
						    bv, NULL, NULL, &retoid, &retdata))!=LDAP_SUCCESS) {
			DEBUG(0,("LDAP Password could not be changed for user %s: %s\n",
				pdb_get_username(newpwd),ldap_err2string(rc)));
		} else {
			DEBUG(3,("LDAP Password changed for user %s\n",pdb_get_username(newpwd)));
    
			ber_bvfree(retdata);
			ber_memfree(retoid);
		}
		ber_bvfree(bv);
	}
#else
	DEBUG(10,("LDAP PASSWORD SYNC is not supported!\n"));
#endif /* LDAP_EXOP_X_MODIFY_PASSWD */
	return NT_STATUS_OK;
}

/**********************************************************************
Delete entry from LDAP for username 
*********************************************************************/
static NTSTATUS ldapsam_delete_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * sam_acct)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	const char *sname;
	int rc;
	char *dn;
	LDAPMessage *entry;
	LDAPMessage *result;

	if (!sam_acct) {
		DEBUG(0, ("sam_acct was NULL!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sname = pdb_get_username(sam_acct);

	DEBUG (3, ("Deleting user %s from LDAP.\n", sname));

	rc = ldapsam_search_one_user_by_name(ldap_state, sname, &result);
	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ldap_count_entries (ldap_state->ldap_struct, result) == 0) {
		DEBUG (0, ("User doesn't exit!\n"));
		ldap_msgfree (result);
		return NT_STATUS_NO_SUCH_USER;
	}

	entry = ldap_first_entry (ldap_state->ldap_struct, result);
	dn = ldap_get_dn (ldap_state->ldap_struct, entry);
	ldap_msgfree(result);
	
	rc = ldapsam_delete(ldap_state, dn);

	ldap_memfree (dn);
	if (rc != LDAP_SUCCESS) {
		char *ld_error;
		ldap_get_option (ldap_state->ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG (0,("failed to delete user with uid = %s with: %s\n\t%s\n",
			sname, ldap_err2string (rc), ld_error));
		free (ld_error);
		return NT_STATUS_CANNOT_DELETE;
	}

	DEBUG (2,("successfully deleted uid = %s from the LDAP database\n", sname));
	return NT_STATUS_OK;
}

/**********************************************************************
Update SAM_ACCOUNT 
*********************************************************************/
static NTSTATUS ldapsam_update_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * newpwd)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	char *dn;
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAPMod **mods;

	if (!init_ldap_from_sam(ldap_state, &mods, LDAP_MOD_REPLACE, False, newpwd)) {
		DEBUG(0, ("ldapsam_update_sam_account: init_ldap_from_sam failed!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	if (mods == NULL) {
		DEBUG(4,("mods is empty: nothing to update for user: %s\n",pdb_get_username(newpwd)));
		return NT_STATUS_OK;
	}
	
	rc = ldapsam_search_one_user_by_name(ldap_state, pdb_get_username(newpwd), &result);
	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) == 0) {
		DEBUG(0, ("No user to modify!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ldap_state->ldap_struct, result);
	dn = ldap_get_dn(ldap_state->ldap_struct, entry);
        ldap_msgfree(result);
	
	ret = ldapsam_modify_entry(my_methods,newpwd,dn,mods,LDAP_MOD_REPLACE, False);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0,("failed to modify user with uid = %s\n",
					pdb_get_username(newpwd)));
		ldap_mods_free(mods,1);
		return ret;
	}


	DEBUG(2,
	      ("successfully modified uid = %s in the LDAP database\n",
	       pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	return NT_STATUS_OK;
}

/**********************************************************************
Add SAM_ACCOUNT to LDAP 
*********************************************************************/
static NTSTATUS ldapsam_add_sam_account(struct pdb_methods *my_methods, SAM_ACCOUNT * newpwd)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)my_methods->private_data;
	int rc;
	pstring filter;
	LDAPMessage *result = NULL;
	pstring dn;
	LDAPMod **mods = NULL;
	int 		ldap_op;
	uint32		num_result;
	
	const char *username = pdb_get_username(newpwd);
	if (!username || !*username) {
		DEBUG(0, ("Cannot add user without a username!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	rc = ldapsam_search_one_user_by_name (ldap_state, username, &result);
	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ldap_count_entries(ldap_state->ldap_struct, result) != 0) {
		DEBUG(0,("User '%s' already in the base, with samba properties\n", 
			 username));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	ldap_msgfree(result);

	slprintf (filter, sizeof (filter) - 1, "uid=%s", username);
	rc = ldapsam_search_one_user(ldap_state, filter, &result);
	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	num_result = ldap_count_entries(ldap_state->ldap_struct, result);
	
	if (num_result > 1) {
		DEBUG (0, ("More than one user with that uid exists: bailing out!\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* Check if we need to update an existing entry */
	if (num_result == 1) {
		char *tmp;
		LDAPMessage *entry;
		
		DEBUG(3,("User exists without samba properties: adding them\n"));
		ldap_op = LDAP_MOD_REPLACE;
		entry = ldap_first_entry (ldap_state->ldap_struct, result);
		tmp = ldap_get_dn (ldap_state->ldap_struct, entry);
		slprintf (dn, sizeof (dn) - 1, "%s", tmp);
		ldap_memfree (tmp);
	} else {
		/* Check if we need to add an entry */
		DEBUG(3,("Adding new user\n"));
		ldap_op = LDAP_MOD_ADD;
		if (username[strlen(username)-1] == '$') {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", username, lp_ldap_machine_suffix ());
                } else {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", username, lp_ldap_user_suffix ());
                }
	}

	ldap_msgfree(result);

	if (!init_ldap_from_sam(ldap_state, &mods, ldap_op, True, newpwd)) {
		DEBUG(0, ("ldapsam_add_sam_account: init_ldap_from_sam failed!\n"));
		ldap_mods_free(mods, 1);
		return NT_STATUS_UNSUCCESSFUL;		
	}
	
	if (mods == NULL) {
		DEBUG(0,("mods is empty: nothing to add for user: %s\n",pdb_get_username(newpwd)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", "sambaAccount");

	ret = ldapsam_modify_entry(my_methods,newpwd,dn,mods,ldap_op, True);
	if (NT_STATUS_IS_ERR(ret)) {
		DEBUG(0,("failed to modify/add user with uid = %s (dn = %s)\n",
			 pdb_get_username(newpwd),dn));
		ldap_mods_free(mods,1);
		return ret;
	}

	DEBUG(2,("added: uid = %s in the LDAP database\n", pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	return NT_STATUS_OK;
}

static NTSTATUS ldapsam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid, BOOL with_priv)
{
	return get_group_map_from_sid(sid, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid, BOOL with_priv)
{
	return get_group_map_from_gid(gid, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 char *name, BOOL with_priv)
{
	return get_group_map_from_ntname(name, map, with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_INSERT) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	return add_mapping_entry(map, TDB_REPLACE) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	return group_map_remove(sid) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ldapsam_enum_group_mapping(struct pdb_methods *methods,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only, BOOL with_priv)
{
	return enum_group_mapping(sid_name_use, rmap, num_entries, unix_only,
				  with_priv) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static void free_private_data(void **vp) 
{
	struct ldapsam_privates **ldap_state = (struct ldapsam_privates **)vp;

	ldapsam_close(*ldap_state);

	if ((*ldap_state)->bind_secret) {
		memset((*ldap_state)->bind_secret, '\0', strlen((*ldap_state)->bind_secret));
	}

	ldapsam_close(*ldap_state);
		
	SAFE_FREE((*ldap_state)->bind_dn);
	SAFE_FREE((*ldap_state)->bind_secret);

	*ldap_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}

NTSTATUS pdb_init_ldapsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct ldapsam_privates *ldap_state;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "ldapsam";

	(*pdb_method)->setsampwent = ldapsam_setsampwent;
	(*pdb_method)->endsampwent = ldapsam_endsampwent;
	(*pdb_method)->getsampwent = ldapsam_getsampwent;
	(*pdb_method)->getsampwnam = ldapsam_getsampwnam;
	(*pdb_method)->getsampwsid = ldapsam_getsampwsid;
	(*pdb_method)->add_sam_account = ldapsam_add_sam_account;
	(*pdb_method)->update_sam_account = ldapsam_update_sam_account;
	(*pdb_method)->delete_sam_account = ldapsam_delete_sam_account;
	(*pdb_method)->getgrsid = ldapsam_getgrsid;
	(*pdb_method)->getgrgid = ldapsam_getgrgid;
	(*pdb_method)->getgrnam = ldapsam_getgrnam;
	(*pdb_method)->add_group_mapping_entry = ldapsam_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = ldapsam_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = ldapsam_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = ldapsam_enum_group_mapping;

	/* TODO: Setup private data and free */

	ldap_state = talloc_zero(pdb_context->mem_ctx, sizeof(struct ldapsam_privates));

	if (!ldap_state) {
		DEBUG(0, ("talloc() failed for ldapsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		ldap_state->uri = talloc_strdup(pdb_context->mem_ctx, location);
#ifdef WITH_LDAP_SAMCONFIG
	} else {
		int ldap_port = lp_ldap_port();
			
		/* remap default port if not using SSL (ie clear or TLS) */
		if ( (lp_ldap_ssl() != LDAP_SSL_ON) && (ldap_port == 636) ) {
			ldap_port = 389;
		}

		ldap_state->uri = talloc_asprintf(pdb_context->mem_ctx, "%s://%s:%d", lp_ldap_ssl() == LDAP_SSL_ON ? "ldaps" : "ldap", lp_ldap_server(), ldap_port);
		if (!ldap_state->uri) {
			return NT_STATUS_NO_MEMORY;
		}
#else
	} else {
		ldap_state->uri = "ldap://localhost";
#endif
	}

	(*pdb_method)->private_data = ldap_state;

	(*pdb_method)->free_private_data = free_private_data;

	return NT_STATUS_OK;
}

NTSTATUS pdb_init_ldapsam_nua(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	struct ldapsam_privates *ldap_state;
	uint32 low_nua_uid, high_nua_uid;

	if (!NT_STATUS_IS_OK(nt_status = pdb_init_ldapsam(pdb_context, pdb_method, location))) {
		return nt_status;
	}

	(*pdb_method)->name = "ldapsam_nua";

	ldap_state = (*pdb_method)->private_data;
	
	ldap_state->permit_non_unix_accounts = True;

	if (!lp_non_unix_account_range(&low_nua_uid, &high_nua_uid)) {
		DEBUG(0, ("cannot use ldapsam_nua without 'non unix account range' in smb.conf!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ldap_state->low_nua_rid=fallback_pdb_uid_to_user_rid(low_nua_uid);

	ldap_state->high_nua_rid=fallback_pdb_uid_to_user_rid(high_nua_uid);

	return NT_STATUS_OK;
}


#else

NTSTATUS pdb_init_ldapsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("ldap not detected at configure time, ldapsam not availalble!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_init_ldapsam_nua(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("ldap not dectected at configure time, ldapsam_nua not available!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


#endif

/* 
   Unix SMB/Netbios implementation.
   Version 2.9.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Gerald Carter 2001
   Copyright (C) Shahms King 2001
   Copyright (C) Jean François Micouleau 1998
   
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

#ifdef WITH_LDAP_SAM
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

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifndef SAM_ACCOUNT
#define SAM_ACCOUNT struct sam_passwd
#endif

struct ldap_enum_info {
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;
};

static struct ldap_enum_info global_ldap_ent;
static pstring ldap_secret;


extern pstring samlogon_user;
extern BOOL sam_logon_in_ssb;

/* 
 * attributes needed from sambaAccount
 * 
 * objectclass ( 1.3.6.1.4.1.7165.2.2.3 NAME 'sambaAccount' SUP top AUXILIARY
 *       DESC 'Samba Auxilary Account'
 *       MUST ( uid $ rid )
 *       MAY  ( cn $ lmPassword $ ntPassword $ pwdLastSet $ logonTime $
 *              logoffTime $ kickoffTime $ pwdCanChange $ pwdMustChange $ acctFlags $
 *              displayName $ smbHome $ homeDrive $ scriptPath $ profilePath $
 *              description $ userWorkstations $ primaryGroupID $ domain ))
 */

char* attribs[] = {
	"uid",	
	"rid",
	"cn",
	"lmPassword",
	"ntPassword",
	"pwdLastSet",
	"logonTime",
	"logoffTime",
	"kickoffTime",
	"pwdCanChange",
	"pwdMustChange",
	"acctFlags",
	"displayName",
	"smbHome",
	"homeDrive",
	"scriptPath",
	"profilePath",
	"description",
	"userWorkstations",
	"primaryGroupID",
	"domain",
	NULL
};


/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static BOOL ldap_open_connection (LDAP ** ldap_struct)
{
	int port;
	int version;
	int tls, rc;
	uid_t uid = geteuid();
	struct passwd* pass;
	
	DEBUG(5,("ldap_open_connection: starting...\n"));
	/*
	 * using sys_getpwnam() here since I'm assuming that the 
 	 * ldapsam is only used on a standalone server or PDC.
	 * winbind not in the picture....
	 */
	
	if ( (pass=sys_getpwuid(uid)) == NULL ) {
		DEBUG(0,("ldap_open_connection: Can't determine user of running process!\n"));
		return False;
	}

	/* check that the user is in the domain admin group for connecting */

	if ( (uid != 0) && !user_in_list(pass->pw_name, lp_domain_admin_group()) ) {
		DEBUG(0, ("ldap_open_connection: cannot access LDAP when not root or a member of domain admin group..\n"));
		return False;
	}

	port = lp_ldap_port();
	
	/* remap default port is no SSL */
	if ( (lp_ldap_ssl() != LDAP_SSL_ON) && (lp_ldap_port() == 636) ) {
		port = 389;
	}

	DEBUG(10,("Initializing connection to %s on port %d\n", 
		lp_ldap_server(), port ));
		
	if ((*ldap_struct = ldap_init(lp_ldap_server(), port)) == NULL)	{
		DEBUG(0, ("The LDAP server is not responding !\n"));
		return False;
	}

	/* Connect to older servers using SSL and V2 rather than Start TLS */
	if (ldap_get_option(*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS)
	{
		if (version != LDAP_VERSION3)
		{
			version = LDAP_VERSION3;
			ldap_set_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version);
		}
	}

	switch (lp_ldap_ssl())
	{
		case LDAP_SSL_START_TLS:
#ifdef HAVE_LDAP_START_TLS_S
			if (ldap_get_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, 
				&version) == LDAP_OPT_SUCCESS)
			{
				if (version < LDAP_VERSION3)
				{
					version = LDAP_VERSION3;
					ldap_set_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION,
							&version);
				}
			}
			if ((rc = ldap_start_tls_s (*ldap_struct, NULL, NULL)) != LDAP_SUCCESS)
			{
				DEBUG(0,("Failed to issue the StartTLS instruction: %s\n",
				       ldap_err2string(rc)));
				return False;
			}
			DEBUG (2, ("StartTLS issued: using a TLS connection\n"));
#else
			DEBUG(0,("ldap_open_connection: StartTLS not supported by LDAP client libraries!\n"));
                        return False;
#endif
			break;
			
		case LDAP_SSL_ON:
#ifdef LDAP_OPT_X_TLS
			tls = LDAP_OPT_X_TLS_HARD;
			if (ldap_set_option (*ldap_struct, LDAP_OPT_X_TLS, &tls) != LDAP_SUCCESS)
			{
				DEBUG(0, ("Failed to setup a TLS session\n"));
			}
			
			DEBUG(0,("LDAPS option set...!\n"));
#else
			DEBUG(0,("ldap_open_connection: Secure connection not supported by LDAP client libraries!\n"));
			return False;
#endif
			break;
			
		case LDAP_SSL_OFF:
		default:
			/* 
			 * No special needs to setup options prior to the LDAP
			 * bind (which should be called next via ldap_connect_system()
			 */
			break;
	}

	DEBUG(2, ("ldap_open_connection: connection opened\n"));
	return True;
}


/*******************************************************************
 ldap rebind proc to rebind w/ the admin dn when following referrals
*******************************************************************/

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
# if LDAP_SET_REBIND_PROC_ARGS == 3
static int rebindproc_with_state (LDAP *ldap_struct,
                                          LDAP_CONST char *url,
                                          ber_tag_t request,
                                          ber_int_t msgid, void *arg)
# else  /* LDAP_SET_REBIND_PROC_ARGS == 2 */
static int rebindproc (LDAP *ldap_struct,
                                          LDAP_CONST char *url,
                                          ber_tag_t request,
                                          ber_int_t msgid)
# endif  /*  LDAP_SET_REBIND_PROC_ARGS */
{

        int rc = 0;

        DEBUG(2,("ldap_connect_system: Rebinding as \"%s\", API: %d, PROC_ARGS: %d\n",
                  lp_ldap_admin_dn(), LDAP_API_VERSION, LDAP_SET_REBIND_PROC_ARGS));

        /** @TODO Should we be doing something to check what servers we rebind to?
            Could we get a referral to a machine that we don't want to give our
            username and password to? */

	if ( ( rc = ldap_simple_bind_s( ldap_struct, lp_ldap_admin_dn(), ldap_secret ) ) == LDAP_SUCCESS )
	{
        	DEBUG( 2, ( "Rebind successful\n" ) );
	}
	else {
		DEBUG( 2, ( "Rebind failed: %s\n", ldap_err2string( rc ) ) );
	}
	return rc;
}
#else /* other Vendor or LDAP_API_VERSION  */
# if LDAP_SET_REBIND_PROC_ARGS ==3 
static int rebindproc_with_state  (LDAP * ld, char **whop, char **credp,
                                   int *methodp, int freeit, void *arg)

# else  /* LDAP_SET_REBIND_PROC_ARGS == 2 */
static int rebindproc (LDAP *ldap_struct, char **whop, char **credp,
                       int *method, int freeit )
# endif
{
    register char   *to_clear = *credp;


	if (freeit) {
                SAFE_FREE(*whop);
                memset(*credp, '\0', strlen(*credp));
                SAFE_FREE(*credp);
	} else {
                *whop = strdup(ldap_state->bind_dn);
                if (!*whop) {
                        return LDAP_NO_MEMORY;
                }
                DEBUG(5,("ldap_connect_system: Rebinding as \"%s\"\n",
                          whop));

                *credp = strdup(ldap_secret);
                if (!*credp) {
                        SAFE_FREE(*whop);
                        return LDAP_NO_MEMORY;
                }
                *methodp = LDAP_AUTH_SIMPLE;
	}
	return LDAP_SUCCESS;
}
#endif



/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static BOOL ldap_connect_system(LDAP * ldap_struct)
{
	int rc;
	static BOOL got_pw = False;

	/* get the password if we don't have it already */
	if (!got_pw && !(got_pw=fetch_ldap_pw(lp_ldap_admin_dn(), ldap_secret, sizeof(pstring)))) 
	{
		DEBUG(0, ("ldap_connect_system: Failed to retrieve password for %s from secrets.tdb\n",
			lp_ldap_admin_dn()));
		return False;
	}

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesnt' seem to support it */

	DEBUG(0,("ldap_connect_system: Binding to ldap server as \"%s\"\n",
		lp_ldap_admin_dn()));
	   
#if LDAP_SET_REBIND_PROC_ARGS == 2 
        ldap_set_rebind_proc(ldap_struct, rebindproc);
#else /* LDAP_SET_REBIND_PROC_ARGS == 3 */
        ldap_set_rebind_proc(ldap_struct, rebindproc_with_state, NULL);
#endif

	if ((rc = ldap_simple_bind_s(ldap_struct, lp_ldap_admin_dn(), 
		ldap_secret)) != LDAP_SUCCESS)
	{
		DEBUG(0, ("Bind failed: %s\n", ldap_err2string(rc)));
		return False;
	}
	
	DEBUG(2, ("ldap_connect_system: succesful connection to the LDAP server\n"));
	return True;
}

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldap_search_one_user (LDAP * ldap_struct, const char *filter, LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;

	DEBUG(2, ("ldap_search_one_user: searching for:[%s]\n", filter));

	rc = ldap_search_s(ldap_struct, lp_ldap_suffix (), scope, (char*)filter, attribs, 0, result);

	if (rc != LDAP_SUCCESS)	{
		DEBUG(0,("ldap_search_one_user: Problem during the LDAP search: %s\n", 
			ldap_err2string (rc)));
		DEBUG(3,("ldap_search_one_user: Query was: %s, %s\n", lp_ldap_suffix(), 
			filter));
	}
	
	return rc;
}

/*******************************************************************
 run the search by name.
******************************************************************/
static int ldap_search_one_user_by_name (LDAP * ldap_struct, const char *user,
			     LDAPMessage ** result)
{
	pstring filter;
	
	/*
	 * in the filter expression, replace %u with the real name
	 * so in ldap filter, %u MUST exist :-)
	 */
	pstrcpy(filter, lp_ldap_filter());

	/* 
	 * have to use this here because $ is filtered out
	 * in pstring_sub
	 */
	all_string_sub(filter, "%u", user, sizeof(pstring));

	return ldap_search_one_user(ldap_struct, filter, result);
}

/*******************************************************************
 run the search by uid.
******************************************************************/
static int ldap_search_one_user_by_uid(LDAP * ldap_struct, int uid,
			    LDAPMessage ** result)
{
	struct passwd *user;
	pstring filter;

	/* Get the username from the system and look that up in the LDAP */
	
	if ((user = sys_getpwuid(uid)) == NULL) {
		DEBUG(3,("ldap_search_one_user_by_uid: Failed to locate uid [%d]\n", uid));
		return LDAP_NO_SUCH_OBJECT;
	}
	
	pstrcpy(filter, lp_ldap_filter());
	
	all_string_sub(filter, "%u", user->pw_name, sizeof(pstring));

	return ldap_search_one_user(ldap_struct, filter, result);
}

/*******************************************************************
 run the search by rid.
******************************************************************/
static int ldap_search_one_user_by_rid (LDAP * ldap_struct, uint32 rid,
			    LDAPMessage ** result)
{
	pstring filter;
	int rc;

	/* check if the user rid exsists, if not, try searching on the uid */
	
	snprintf(filter, sizeof(filter) - 1, "rid=%i", rid);
	rc = ldap_search_one_user(ldap_struct, filter, result);
	
	if (rc != LDAP_SUCCESS)
		rc = ldap_search_one_user_by_uid(ldap_struct, 
			pdb_user_rid_to_uid(rid), result);

	return rc;
}

/*******************************************************************
 search an attribute and return the first value found.
 the string in 'value' is unchanged if the attribute does not exist
******************************************************************/

static BOOL get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
		     char *attribute, char *value)
{
	char **values;

	if ((values = ldap_get_values (ldap_struct, entry, attribute)) == NULL) {
		DEBUG (2, ("get_single_attribute: [%s] = [<does not exist>]\n", attribute));	
		return False;
	}

	pstrcpy(value, values[0]);
	ldap_value_free(values);
	DEBUG (2, ("get_single_attribute: [%s] = [%s]\n", attribute, value));
		
	return True;
}

/************************************************************************
 Routine to manage the LDAPMod structure array
 manage memory used by the array, by each struct, and values
************************************************************************/

static void make_a_mod (LDAPMod *** modlist, int modop, char *attribute, char *value)
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
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_sam_from_buffer in pdb_tdb.c)
*********************************************************************/
static BOOL init_sam_from_ldap (SAM_ACCOUNT * sampass,
		   LDAP * ldap_struct, LDAPMessage * entry)
{
	time_t  	logon_time,
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
	struct passwd 	*sys_user;
	uint32 		user_rid, 
			group_rid;
	uint8 		smblmpwd[16],
			smbntpwd[16];
	uint16 		acct_ctrl, 
			logon_divs;
	uint32 		hours_len;
	uint8 		hours[MAX_HOURS_LEN];
	pstring 	temp;
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
	 

	get_single_attribute(ldap_struct, entry, "uid", username);
	DEBUG(2, ("Entry found for user: %s\n", username));
	
	pstrcpy(samlogon_user, username);
	
	pstrcpy(nt_username, username);

	pstrcpy(domain, lp_workgroup());

	pass_last_set_time 	= TIME_T_MAX;
	logon_time 		= TIME_T_MAX;
	logoff_time 		= TIME_T_MAX;
	kickoff_time 		= TIME_T_MAX;
	pass_can_change_time 	= TIME_T_MAX;
	pass_must_change_time 	= TIME_T_MAX;
	

	if (get_single_attribute(ldap_struct, entry, "pwdLastSet", temp))
		pass_last_set_time = (time_t) atol(temp);

	if (get_single_attribute(ldap_struct, entry, "logonTime", temp))
		logon_time = (time_t) atol(temp);

	if (get_single_attribute(ldap_struct, entry, "logoffTime", temp))
		logoff_time = (time_t) atol(temp);

	if (get_single_attribute(ldap_struct, entry, "kickoffTime", temp))
		kickoff_time = (time_t) atol(temp);

	if (get_single_attribute(ldap_struct, entry, "pwdCanChange", temp))
		pass_can_change_time = (time_t) atol(temp);

	if (get_single_attribute(ldap_struct, entry, "pwdMustChange", temp))
		pass_must_change_time = (time_t) atol(temp);

	/* recommend that 'gecos' and 'displayName' should refer to the same
	 * attribute OID.  userFullName depreciated, only used by Samba
	 * primary rules of LDAP: don't make a new attribute when one is already defined
	 * that fits your needs; using cn then displayName rather than 'userFullName'
	 */
	 
	sam_logon_in_ssb = True;

	if (!get_single_attribute(ldap_struct, entry, "cn", fullname)) {
		get_single_attribute(ldap_struct, entry, "displayName", fullname);
	}


	if (!get_single_attribute(ldap_struct, entry, "homeDrive", dir_drive)) {
		pstrcpy(dir_drive, lp_logon_drive());
		standard_sub_advanced(-1, username, "", gid, dir_drive, sizeof(dir_drive));
		DEBUG(5,("homeDrive fell back to %s\n",dir_drive));
		pdb_set_dir_drive(sampass, dir_drive, False);
	}
	else
		pdb_set_dir_drive(sampass, dir_drive, True);

	if (!get_single_attribute(ldap_struct, entry, "smbHome", homedir)) {
		pstrcpy(homedir, lp_logon_home());
		standard_sub_advanced(-1, username, "", gid, homedir, sizeof(homedir));
		DEBUG(5,("smbHome fell back to %s\n",homedir));
		pdb_set_homedir(sampass, homedir, False);
	}
	else
		pdb_set_homedir(sampass, homedir, True);

	if (!get_single_attribute(ldap_struct, entry, "scriptPath", logon_script)) {
		pstrcpy(logon_script, lp_logon_script());
		standard_sub_advanced(-1, username, "", gid, logon_script, sizeof(logon_script));
		DEBUG(5,("scriptPath fell back to %s\n",logon_script));
		pdb_set_logon_script(sampass, logon_script, False);
	}
	else
		pdb_set_logon_script(sampass, logon_script, True);

	if (!get_single_attribute(ldap_struct, entry, "profilePath", profile_path)) {
		pstrcpy(profile_path, lp_logon_path());
		standard_sub_advanced(-1, username, "", gid, profile_path, sizeof(profile_path));
		DEBUG(5,("profilePath fell back to %s\n",profile_path));
		pdb_set_profile_path(sampass, profile_path, False);
	}
	else
		pdb_set_profile_path(sampass, profile_path, True);
		
	sam_logon_in_ssb = False;

	get_single_attribute(ldap_struct, entry, "description", acct_desc);
	get_single_attribute(ldap_struct, entry, "userWorkstations", workstations);
	get_single_attribute(ldap_struct, entry, "rid", temp);
	user_rid = (uint32)atol(temp);
	get_single_attribute(ldap_struct, entry, "primaryGroupID", temp);
	group_rid = (uint32)atol(temp);


	/* These values MAY be in LDAP, but they can also be retrieved through 
	 *  sys_getpw*() which is how we're doing it 
	 */
	sys_user = sys_getpwnam(username);
	if (sys_user == NULL) {
		DEBUG (2,("init_sam_from_ldap: User [%s] does not ave a uid!\n", username));
		return False;
	}


	/* FIXME: hours stuff should be cleaner */
	
	logon_divs = 168;
	hours_len = 21;
	memset(hours, 0xff, hours_len);

	get_single_attribute (ldap_struct, entry, "lmPassword", temp);
	pdb_gethexpwd(temp, smblmpwd);
	memset((char *)temp, '\0', sizeof(temp));
	get_single_attribute (ldap_struct, entry, "ntPassword", temp);
	pdb_gethexpwd(temp, smbntpwd);
	memset((char *)temp, '\0', sizeof(temp));
	get_single_attribute (ldap_struct, entry, "acctFlags", temp);
	acct_ctrl = pdb_decode_acct_ctrl(temp);

	if (acct_ctrl == 0)
		acct_ctrl |= ACB_NORMAL;


	pdb_set_acct_ctrl(sampass, acct_ctrl);
	pdb_set_logon_time(sampass, logon_time);
	pdb_set_logoff_time(sampass, logoff_time);
	pdb_set_kickoff_time(sampass, kickoff_time);
	pdb_set_pass_can_change_time(sampass, pass_can_change_time);
	pdb_set_pass_must_change_time(sampass, pass_must_change_time);
	pdb_set_pass_last_set_time(sampass, pass_last_set_time);

	pdb_set_hours_len(sampass, hours_len);
	pdb_set_logon_divs(sampass, logon_divs);

	pdb_set_uid(sampass, sys_user->pw_uid);
	pdb_set_gid(sampass, sys_user->pw_gid);
	pdb_set_user_rid(sampass, user_rid);
	pdb_set_group_rid(sampass, group_rid);

	pdb_set_username(sampass, username);

	pdb_set_domain(sampass, domain);
	pdb_set_nt_username(sampass, nt_username);

	pdb_set_fullname(sampass, fullname);

	pdb_set_acct_desc(sampass, acct_desc);
	pdb_set_workstations(sampass, workstations);
	pdb_set_munged_dial(sampass, munged_dial);
	
	if (!pdb_set_nt_passwd(sampass, smbntpwd))
		return False;
	if (!pdb_set_lanman_passwd(sampass, smblmpwd))
		return False;

	/* pdb_set_unknown_3(sampass, unknown3); */
	/* pdb_set_unknown_5(sampass, unknown5); */
	/* pdb_set_unknown_6(sampass, unknown6); */

	pdb_set_hours(sampass, hours);

	return True;
}

/**********************************************************************
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_buffer_from_sam in pdb_tdb.c)
*********************************************************************/
static BOOL init_ldap_from_sam (LDAPMod *** mods, int ldap_state, SAM_ACCOUNT * sampass)
{
	pstring temp;

	*mods = NULL;

	/* 
	 * took out adding "objectclass: sambaAccount"
	 * do this on a per-mod basis
	 */


	make_a_mod(mods, ldap_state, "uid", pdb_get_username(sampass));
	DEBUG(2, ("Setting entry for user: %s\n", pdb_get_username(sampass)));

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_last_set_time(sampass));
	make_a_mod(mods, ldap_state, "pwdLastSet", temp);

	slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logon_time(sampass));
	make_a_mod(mods, ldap_state, "logonTime", temp);

	slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logoff_time(sampass));
	make_a_mod(mods, ldap_state, "logoffTime", temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_kickoff_time(sampass));
	make_a_mod(mods, ldap_state, "kickoffTime", temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_can_change_time(sampass));
	make_a_mod(mods, ldap_state, "pwdCanChange", temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_must_change_time(sampass));
	make_a_mod(mods, ldap_state, "pwdMustChange", temp);

	/* displayName, cn, and gecos should all be the same
	 *  most easily accomplished by giving them the same OID
	 *  gecos isn't set here b/c it should be handled by the 
	 *  add-user script
	 */

	make_a_mod(mods, ldap_state, "displayName", pdb_get_fullname(sampass));
	make_a_mod(mods, ldap_state, "cn", pdb_get_fullname(sampass));
	make_a_mod(mods, ldap_state, "description", pdb_get_acct_desc(sampass));
	make_a_mod(mods, ldap_state, "userWorkstations", pdb_get_workstations(sampass));

	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */
	 
	if (IS_SAM_SET(sampass, FLAG_SAM_SMBHOME))
		make_a_mod(mods, ldap_state, "smbHome", pdb_get_homedir(sampass));
		
	if (IS_SAM_SET(sampass, FLAG_SAM_DRIVE))
		make_a_mod(mods, ldap_state, "homeDrive", pdb_get_dirdrive(sampass));
		
	if (IS_SAM_SET(sampass, FLAG_SAM_LOGONSCRIPT))
		make_a_mod(mods, ldap_state, "scriptPath", pdb_get_logon_script(sampass));

	if (IS_SAM_SET(sampass, FLAG_SAM_PROFILE))
		make_a_mod(mods, ldap_state, "profilePath", pdb_get_profile_path(sampass));
	

	if ( !pdb_get_user_rid(sampass))
		slprintf(temp, sizeof(temp) - 1, "%i", pdb_uid_to_user_rid(pdb_get_uid(sampass)));
	else
	slprintf(temp, sizeof(temp) - 1, "%i", pdb_get_user_rid(sampass));
	make_a_mod(mods, ldap_state, "rid", temp);

	if ( !pdb_get_group_rid(sampass))
		slprintf(temp, sizeof(temp) - 1, "%i", pdb_gid_to_group_rid(pdb_get_gid(sampass)));
	else
	slprintf(temp, sizeof(temp) - 1, "%i", pdb_get_group_rid(sampass));
	make_a_mod(mods, ldap_state, "primaryGroupID", temp);

	/* FIXME: Hours stuff goes in LDAP  */
	pdb_sethexpwd (temp, pdb_get_lanman_passwd(sampass), pdb_get_acct_ctrl(sampass));
	make_a_mod (mods, ldap_state, "lmPassword", temp);
	
	pdb_sethexpwd (temp, pdb_get_nt_passwd(sampass), pdb_get_acct_ctrl(sampass));
	make_a_mod (mods, ldap_state, "ntPassword", temp);
	
	make_a_mod (mods, ldap_state, "acctFlags", pdb_encode_acct_ctrl (pdb_get_acct_ctrl(sampass),
		NEW_PW_FORMAT_SPACE_PADDED_LEN));

	return True;
}

/**********************************************************************
Connect to LDAP server for password enumeration
*********************************************************************/
BOOL pdb_setsampwent(BOOL update)
{
	int rc;
	pstring filter;

	if (!ldap_open_connection(&global_ldap_ent.ldap_struct))
	{
		return False;
	}
	if (!ldap_connect_system(global_ldap_ent.ldap_struct))
	{
		ldap_unbind(global_ldap_ent.ldap_struct);
		return False;
	}

	pstrcpy(filter, lp_ldap_filter());
	all_string_sub(filter, "%u", "*", sizeof(pstring));

	rc = ldap_search_s(global_ldap_ent.ldap_struct, lp_ldap_suffix(),
			   LDAP_SCOPE_SUBTREE, filter, attribs, 0,
			   &global_ldap_ent.result);

	if (rc != LDAP_SUCCESS)
	{
		DEBUG(0, ("LDAP search failed: %s\n", ldap_err2string(rc)));
		DEBUG(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
		ldap_msgfree(global_ldap_ent.result);
		ldap_unbind(global_ldap_ent.ldap_struct);
		global_ldap_ent.ldap_struct = NULL;
		global_ldap_ent.result = NULL;
		return False;
	}

	DEBUG(2, ("pdb_setsampwent: %d entries in the base!\n",
		ldap_count_entries(global_ldap_ent.ldap_struct,
		global_ldap_ent.result)));

	global_ldap_ent.entry = ldap_first_entry(global_ldap_ent.ldap_struct,
				 global_ldap_ent.result);
	global_ldap_ent.index = -1;

	return True;
}

/**********************************************************************
End enumeration of the LDAP password list 
*********************************************************************/
void pdb_endsampwent(void)
{
	if (global_ldap_ent.ldap_struct && global_ldap_ent.result)
	{
		ldap_msgfree(global_ldap_ent.result);
		ldap_unbind(global_ldap_ent.ldap_struct);
		global_ldap_ent.ldap_struct = NULL;
		global_ldap_ent.result = NULL;
	}
}

/**********************************************************************
Get the next entry in the LDAP password database 
*********************************************************************/
BOOL pdb_getsampwent(SAM_ACCOUNT * user)
{
	if (!global_ldap_ent.entry)
		return False;

	global_ldap_ent.index++;
	if (global_ldap_ent.index > 0)
	{
		global_ldap_ent.entry =	ldap_next_entry(global_ldap_ent.ldap_struct, global_ldap_ent.entry);
	}

	if (global_ldap_ent.entry != NULL)
	{
		return init_sam_from_ldap(user, global_ldap_ent.ldap_struct,
					  global_ldap_ent.entry);
	}
	return False;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by username 
*********************************************************************/
BOOL pdb_getsampwnam(SAM_ACCOUNT * user, const char *sname)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;

	if (!ldap_open_connection(&ldap_struct))
		return False;
	if (!ldap_connect_system(ldap_struct))
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldap_search_one_user_by_name(ldap_struct, sname, &result) != LDAP_SUCCESS)
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldap_count_entries(ldap_struct, result) < 1)
	{
		pstring filter;

		pstrcpy(filter, lp_ldap_filter());
		standard_sub_advanced(-1, sname, "", -1, filter, sizeof(filter));
		DEBUG(0,("LDAP search \"%s\" returned %d entries.\n",  filter, 
		       ldap_count_entries(ldap_struct, result)));
		ldap_unbind(ldap_struct);
		return False;
	}
	entry = ldap_first_entry(ldap_struct, result);
	if (entry)
	{
		init_sam_from_ldap(user, ldap_struct, entry);
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return True;
	}
	else
	{
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by rid 
*********************************************************************/
BOOL pdb_getsampwrid(SAM_ACCOUNT * user, uint32 rid)
{
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;

	if (!ldap_open_connection(&ldap_struct))
		return False;

	if (!ldap_connect_system(ldap_struct))
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldap_search_one_user_by_rid(ldap_struct, rid, &result) !=
	    LDAP_SUCCESS)
	{
		ldap_unbind(ldap_struct);
		return False;
	}

	if (ldap_count_entries(ldap_struct, result) < 1)
	{
		DEBUG(0,
		      ("We don't find this rid [%i] count=%d\n", rid,
		       ldap_count_entries(ldap_struct, result)));
		ldap_unbind(ldap_struct);
		return False;
	}

	entry = ldap_first_entry(ldap_struct, result);
	if (entry)
	{
		init_sam_from_ldap(user, ldap_struct, entry);
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return True;
	}
	else
	{
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}
}

/**********************************************************************
Delete entry from LDAP for username 
*********************************************************************/

BOOL pdb_delete_sam_account(const char *sname)
{
	int rc;
	char *dn;
	LDAP *ldap_struct;
	LDAPMessage *entry;
	LDAPMessage *result;

	/* Ensure we have euid as root - else deny this. */
	if (!ldap_open_connection (&ldap_struct))
		return False;

	DEBUG (3, ("Deleting user %s from LDAP.\n", sname));
	
	if (!ldap_connect_system (ldap_struct)) {
		ldap_unbind (ldap_struct);
		DEBUG(0, ("Failed to delete user %s from LDAP.\n", sname));
		return False;
	}

	rc = ldap_search_one_user_by_name (ldap_struct, sname, &result);
	if (ldap_count_entries (ldap_struct, result) == 0) {
		DEBUG (0, ("User doesn't exit!\n"));
		ldap_msgfree (result);
		ldap_unbind (ldap_struct);
		return False;
	}

	entry = ldap_first_entry (ldap_struct, result);
	dn = ldap_get_dn (ldap_struct, entry);

	rc = ldap_delete_s (ldap_struct, dn);

	ldap_memfree (dn);
	if (rc != LDAP_SUCCESS) {
		char *ld_error;
		ldap_get_option (ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG (0,("failed to delete user with uid = %s with: %s\n\t%s\n",
			sname, ldap_err2string (rc), ld_error));
		free (ld_error);
		ldap_unbind (ldap_struct);
		return False;
	}

	DEBUG (2,("successfully deleted uid = %s from the LDAP database\n", sname));
	ldap_unbind (ldap_struct);
	return True;
}

/**********************************************************************
Update SAM_ACCOUNT 
*********************************************************************/

BOOL pdb_update_sam_account(SAM_ACCOUNT * newpwd, BOOL override)
{
	int rc;
	char *dn;
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAPMod **mods;

	if (!ldap_open_connection(&ldap_struct)) /* open a connection to the server */
		return False;

	if (!ldap_connect_system(ldap_struct))	/* connect as system account */ {
		ldap_unbind(ldap_struct);
		return False;
	}

	rc = ldap_search_one_user_by_name(ldap_struct,
					  pdb_get_username(newpwd), &result);

	if (ldap_count_entries(ldap_struct, result) == 0) {
		DEBUG(0, ("No user to modify!\n"));
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}

	init_ldap_from_sam(&mods, LDAP_MOD_REPLACE, newpwd);

	entry = ldap_first_entry(ldap_struct, result);
	dn = ldap_get_dn(ldap_struct, entry);

	rc = ldap_modify_s(ldap_struct, dn, mods);

	if (rc != LDAP_SUCCESS) {
		char *ld_error;
		ldap_get_option(ldap_struct, LDAP_OPT_ERROR_STRING,
				&ld_error);
		DEBUG(0,
		      ("failed to modify user with uid = %s with: %s\n\t%s\n",
		       pdb_get_username(newpwd), ldap_err2string(rc),
		       ld_error));
		free(ld_error);
		ldap_unbind(ldap_struct);
		return False;
	}

	DEBUG(2, ("successfully modified uid = %s in the LDAP database\n",
	       pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	ldap_unbind(ldap_struct);
	return True;
}

/**********************************************************************
Add SAM_ACCOUNT to LDAP 
*********************************************************************/

BOOL pdb_add_sam_account(SAM_ACCOUNT * newpwd)
{
	int 		rc;
	pstring 	filter;
	LDAP 		*ldap_struct;
	LDAPMessage 	*result;
	pstring 	dn;
	LDAPMod 	**mods;
	int 		ldap_op;
	uint32		num_result;

	if (!ldap_open_connection(&ldap_struct))	/* open a connection to the server */
		return False;

	if (!ldap_connect_system(ldap_struct))	/* connect as system account */ {
		ldap_unbind(ldap_struct);
		return False;
	}

	rc = ldap_search_one_user_by_name (ldap_struct, pdb_get_username(newpwd), &result);

	if (ldap_count_entries(ldap_struct, result) != 0) {
		DEBUG(0,("User already in the base, with samba properties\n"));
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}
	ldap_msgfree(result);

	slprintf (filter, sizeof (filter) - 1, "uid=%s", pdb_get_username(newpwd));
	rc = ldap_search_one_user(ldap_struct, filter, &result);
	num_result = ldap_count_entries(ldap_struct, result);
	
	if (num_result > 1) {
		DEBUG (0, ("More than one user with that uid exists: bailing out!\n"));
		return False;
	}
	
	/* Check if we need to update an existing entry */
	if (num_result == 1) {
		char *tmp;
		LDAPMessage *entry;
		
		DEBUG(3,("User exists without samba properties: adding them\n"));
		ldap_op = LDAP_MOD_REPLACE;
		entry = ldap_first_entry (ldap_struct, result);
		tmp = ldap_get_dn (ldap_struct, entry);
		slprintf (dn, sizeof (dn) - 1, "%s", tmp);
		ldap_memfree (tmp);
	} else {
		/* Check if we need to add an entry */
		DEBUG(3,("Adding new user\n"));
		ldap_op = LDAP_MOD_ADD;
		slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", pdb_get_username(newpwd), lp_ldap_suffix ());
	}

	ldap_msgfree(result);

	init_ldap_from_sam(&mods, ldap_op, newpwd);
	make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", "sambaAccount");

	if (ldap_op == LDAP_MOD_REPLACE) {
		rc = ldap_modify_s(ldap_struct, dn, mods);
	} else {
		make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", "account");
		rc = ldap_add_s(ldap_struct, dn, mods);
	}

	if (rc != LDAP_SUCCESS) {
		char *ld_error;

		ldap_get_option (ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(0,("failed to modify user with uid = %s with: %s\n\t%s\n",
			pdb_get_username(newpwd), ldap_err2string (rc), ld_error));
		free(ld_error);
		ldap_mods_free(mods, 1);
		ldap_unbind(ldap_struct);
		return False;
	}
	
	DEBUG(2,("added: uid = %s in the LDAP database\n", pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	ldap_unbind(ldap_struct);
	return True;
}

#else
void dummy_function(void);
void
dummy_function (void)
{
}				/* stop some compilers complaining */
#endif

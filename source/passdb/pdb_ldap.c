/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   Copyright (C) Gerald Carter 2001
   Copyright (C) Shahms King 2001
   Copyright (C) Jean François Micouleau 1998
   Copyright (C) Andrew Bartlett 2002
   
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

#ifndef SAM_ACCOUNT
#define SAM_ACCOUNT struct sam_passwd
#endif

struct ldapsam_privates {

	/* Former statics */
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	int index;
	
	/* retrive-once info */
	const char *uri;
	
	BOOL permit_non_unix_accounts;
	
	uint32 low_nua_rid; 
	uint32 high_nua_rid; 
};

static uint32 ldapsam_get_next_available_nua_rid(struct ldapsam_privates *ldap_state);

/*******************************************************************
 Converts NT user RID to a UNIX uid.
 ********************************************************************/

static uid_t pdb_user_rid_to_uid(uint32 user_rid)
{
	return (uid_t)(((user_rid & (~USER_RID_TYPE))- 1000)/RID_MULTIPLIER);
}

/*******************************************************************
 converts UNIX uid to an NT User RID.
 ********************************************************************/

static uint32 pdb_uid_to_user_rid(uid_t uid)
{
	return (((((uint32)uid)*RID_MULTIPLIER) + 1000) | USER_RID_TYPE);
}

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL fetch_ldapsam_pw(char *dn, char* pw, int len)
{
	fstring key;
	char *p;
	void *data = NULL;
	size_t size;
	
	pstrcpy(key, dn);
	for (p=key; *p; p++)
		if (*p == ',') *p = '/';
	
	data=secrets_fetch(key, &size);
	if (!size) {
		DEBUG(0,("fetch_ldap_pw: no ldap secret retrieved!\n"));
		return False;
	}
	
	if (size > len-1)
	{
		DEBUG(0,("fetch_ldap_pw: ldap secret is too long (%d > %d)!\n", size, len-1));
		return False;
	}

	memcpy(pw, data, size);
	pw[size] = '\0';
	
	return True;
}


/*******************************************************************
 open a connection to the ldap server.
******************************************************************/
static BOOL ldapsam_open_connection (struct ldapsam_privates *ldap_state, LDAP ** ldap_struct)
{

	if (geteuid() != 0) {
		DEBUG(0, ("ldap_open_connection: cannot access LDAP when not root..\n"));
		return False;
	}
	
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
	DEBUG(10, ("ldapsam_open_connection: %s\n", ldap_state->uri));
	
	if (ldap_initialize(ldap_struct, ldap_state->uri) != LDAP_SUCCESS) {
		DEBUG(0, ("ldap_initialize: %s\n", strerror(errno)));
		return (False);
	}
#else 

	/* Parse the string manually */

	{
		int rc;
		int tls = LDAP_OPT_X_TLS_HARD;
		int port = 0;
		int version;
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
			return False;
		}

		/* Connect to older servers using SSL and V2 rather than Start TLS */
		if (ldap_get_option(*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS)
		{
			if (version != LDAP_VERSION2)
			{
				version = LDAP_VERSION2;
				ldap_set_option (*ldap_struct, LDAP_OPT_PROTOCOL_VERSION, &version);
			}
		}

		if (strequal(protocol, "ldaps")) { 
			if (lp_ldap_ssl() == LDAP_SSL_START_TLS) {
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
			} else {
				
				if (ldap_set_option (*ldap_struct, LDAP_OPT_X_TLS, &tls) != LDAP_SUCCESS)
				{
					DEBUG(0, ("Failed to setup a TLS session\n"));
				}
			}
		} else {
			/* 
			 * No special needs to setup options prior to the LDAP
			 * bind (which should be called next via ldap_connect_system()
			 */
		}
	}
#endif

	DEBUG(2, ("ldap_open_connection: connection opened\n"));
	return True;
}

/*******************************************************************
 connect to the ldap server under system privilege.
******************************************************************/
static BOOL ldapsam_connect_system(struct ldapsam_privates *ldap_state, LDAP * ldap_struct)
{
	int rc;
	static BOOL got_pw = False;
	static pstring ldap_secret;

	/* get the password if we don't have it already */
	if (!got_pw && !(got_pw=fetch_ldapsam_pw(lp_ldap_admin_dn(), ldap_secret, sizeof(pstring)))) 
	{
		DEBUG(0, ("ldap_connect_system: Failed to retrieve password for %s from secrets.tdb\n",
			lp_ldap_admin_dn()));
		return False;
	}

	/* removed the sasl_bind_s "EXTERNAL" stuff, as my testsuite 
	   (OpenLDAP) doesnt' seem to support it */
	   
	DEBUG(10,("ldap_connect_system: Binding to ldap server as \"%s\"\n",
		lp_ldap_admin_dn()));
		
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
static int ldapsam_search_one_user (struct ldapsam_privates *ldap_state, LDAP * ldap_struct, const char *filter, LDAPMessage ** result)
{
	int scope = LDAP_SCOPE_SUBTREE;
	int rc;

	DEBUG(2, ("ldapsam_search_one_user: searching for:[%s]\n", filter));

	rc = ldap_search_s(ldap_struct, lp_ldap_suffix (), scope, filter, NULL, 0, result);

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
static int ldapsam_search_one_user_by_name (struct ldapsam_privates *ldap_state, LDAP * ldap_struct, const char *user,
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

	return ldapsam_search_one_user(ldap_state, ldap_struct, filter, result);
}

/*******************************************************************
 run the search by uid.
******************************************************************/
static int ldapsam_search_one_user_by_uid(struct ldapsam_privates *ldap_state, 
					  LDAP * ldap_struct, int uid,
					  LDAPMessage ** result)
{
	struct passwd *user;
	pstring filter;

	/* Get the username from the system and look that up in the LDAP */
	
	if ((user = getpwuid_alloc(uid)) == NULL) {
		DEBUG(3,("ldapsam_search_one_user_by_uid: Failed to locate uid [%d]\n", uid));
		return LDAP_NO_SUCH_OBJECT;
	}
	
	pstrcpy(filter, lp_ldap_filter());
	
	all_string_sub(filter, "%u", user->pw_name, sizeof(pstring));

	passwd_free(&user);

	return ldapsam_search_one_user(ldap_state, ldap_struct, filter, result);
}

/*******************************************************************
 run the search by rid.
******************************************************************/
static int ldapsam_search_one_user_by_rid (struct ldapsam_privates *ldap_state, 
					   LDAP * ldap_struct, uint32 rid,
					   LDAPMessage ** result)
{
	pstring filter;
	int rc;

	/* check if the user rid exsists, if not, try searching on the uid */
	
	snprintf(filter, sizeof(filter) - 1, "rid=%i", rid);
	rc = ldapsam_search_one_user(ldap_state, ldap_struct, filter, result);
	
	if (rc != LDAP_SUCCESS)
		rc = ldapsam_search_one_user_by_uid(ldap_state, ldap_struct, 
						    pdb_user_rid_to_uid(rid), 
						    result);

	return rc;
}

/*******************************************************************
search an attribute and return the first value found.
******************************************************************/
static BOOL get_single_attribute (LDAP * ldap_struct, LDAPMessage * entry,
				  char *attribute, char *value)
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
Initialize SAM_ACCOUNT from an LDAP query
(Based on init_sam_from_buffer in pdb_tdb.c)
*********************************************************************/
static BOOL init_sam_from_ldap (struct ldapsam_privates *ldap_state, 
				SAM_ACCOUNT * sampass,
				LDAP * ldap_struct, LDAPMessage * entry)
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
	uint8 		smblmpwd[16],
			smbntpwd[16];
	uint16 		acct_ctrl, 
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
	 

	if (sampass == NULL || ldap_struct == NULL || entry == NULL) {
		DEBUG(0, ("init_sam_from_ldap: NULL parameters found!\n"));
		return False;
	}

	get_single_attribute(ldap_struct, entry, "uid", username);
	DEBUG(2, ("Entry found for user: %s\n", username));

	pstrcpy(nt_username, username);

	pstrcpy(domain, lp_workgroup());

	get_single_attribute(ldap_struct, entry, "rid", temp);
	user_rid = (uint32)atol(temp);
	if (!get_single_attribute(ldap_struct, entry, "primaryGroupID", temp)) {
		group_rid = 0;
	} else {
		group_rid = (uint32)atol(temp);
	}

	if ((ldap_state->permit_non_unix_accounts) 
	    && (user_rid >= ldap_state->low_nua_rid)
	    && (user_rid <= ldap_state->high_nua_rid)) {
		
	} else {
		
		/* These values MAY be in LDAP, but they can also be retrieved through 
		 *  sys_getpw*() which is how we're doing it 
		 */
	
		pw = getpwnam_alloc(username);
		if (pw == NULL) {
			DEBUG (2,("init_sam_from_ldap: User [%s] does not ave a uid!\n", username));
			return False;
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;

		passwd_free(&pw);

		pdb_set_uid(sampass, uid);
		pdb_set_gid(sampass, gid);

		if (group_rid == 0) {
			GROUP_MAP map;
			/* call the mapping code here */
			if(get_group_map_from_gid(gid, &map, MAPPING_WITHOUT_PRIV)) {
				sid_peek_rid(&map.sid, &group_rid);
			} 
			else {
				group_rid=pdb_gid_to_group_rid(gid);
			}
		}
	}

	get_single_attribute(ldap_struct, entry, "pwdLastSet", temp);
	pass_last_set_time = (time_t) atol(temp);

	if (!get_single_attribute(ldap_struct, entry, "logonTime", temp)) {
		logon_time = (time_t) atol(temp);
		pdb_set_logon_time(sampass, logon_time, True);
	}

	if (!get_single_attribute(ldap_struct, entry, "logoffTime", temp)) {
		logoff_time = (time_t) atol(temp);
		pdb_set_logoff_time(sampass, logoff_time, True);
	}

	if (!get_single_attribute(ldap_struct, entry, "kickoffTime", temp)) {
		kickoff_time = (time_t) atol(temp);
		pdb_set_kickoff_time(sampass, kickoff_time, True);
	}

	if (!get_single_attribute(ldap_struct, entry, "pwdCanChange", temp)) {
		pass_can_change_time = (time_t) atol(temp);
		pdb_set_pass_can_change_time(sampass, pass_can_change_time, True);
	}

	if (!get_single_attribute(ldap_struct, entry, "pwdMustChange", temp)) {
		pass_must_change_time = (time_t) atol(temp);
		pdb_set_pass_must_change_time(sampass, pass_must_change_time, True);
	}

	/* recommend that 'gecos' and 'displayName' should refer to the same
	 * attribute OID.  userFullName depreciated, only used by Samba
	 * primary rules of LDAP: don't make a new attribute when one is already defined
	 * that fits your needs; using cn then displayName rather than 'userFullName'
	 */

	if (!get_single_attribute(ldap_struct, entry, "cn", fullname)) {
		get_single_attribute(ldap_struct, entry, "displayName", fullname);
	}


	if (!get_single_attribute(ldap_struct, entry, "homeDrive", dir_drive)) {
		pstrcpy(dir_drive, lp_logon_drive());
		standard_sub_advanced(-1, username, "", gid, username, dir_drive);
		DEBUG(5,("homeDrive fell back to %s\n",dir_drive));
		pdb_set_dir_drive(sampass, dir_drive, False);
	}
	else
		pdb_set_dir_drive(sampass, dir_drive, True);

	if (!get_single_attribute(ldap_struct, entry, "smbHome", homedir)) {
		pstrcpy(homedir, lp_logon_home());
		standard_sub_advanced(-1, username, "", gid, username, homedir);
		DEBUG(5,("smbHome fell back to %s\n",homedir));
		pdb_set_homedir(sampass, homedir, False);
	}
	else
		pdb_set_homedir(sampass, homedir, True);

	if (!get_single_attribute(ldap_struct, entry, "scriptPath", logon_script)) {
		pstrcpy(logon_script, lp_logon_script());
		standard_sub_advanced(-1, username, "", gid, username, logon_script);
		DEBUG(5,("scriptPath fell back to %s\n",logon_script));
		pdb_set_logon_script(sampass, logon_script, False);
	}
	else
		pdb_set_logon_script(sampass, logon_script, True);

	if (!get_single_attribute(ldap_struct, entry, "profilePath", profile_path)) {
		pstrcpy(profile_path, lp_logon_path());
		standard_sub_advanced(-1, username, "", gid, username, profile_path);
		DEBUG(5,("profilePath fell back to %s\n",profile_path));
		pdb_set_profile_path(sampass, profile_path, False);
	}
	else
		pdb_set_profile_path(sampass, profile_path, True);
		
	get_single_attribute(ldap_struct, entry, "description", acct_desc);
	get_single_attribute(ldap_struct, entry, "userWorkstations", workstations);
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
	pdb_set_pass_last_set_time(sampass, pass_last_set_time);

	pdb_set_hours_len(sampass, hours_len);
	pdb_set_logon_divs(sampass, logon_divs);

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
static BOOL init_ldap_from_sam (struct ldapsam_privates *ldap_state, 
				LDAPMod *** mods, int ldap_op, 
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

	make_a_mod(mods, ldap_op, "uid", pdb_get_username(sampass));
	DEBUG(2, ("Setting entry for user: %s\n", pdb_get_username(sampass)));

	if ( pdb_get_user_rid(sampass) ) {
		rid = pdb_get_user_rid(sampass);
	} else if (IS_SAM_SET(sampass, FLAG_SAM_UID)) {
		rid = pdb_uid_to_user_rid(pdb_get_uid(sampass));
	} else if (ldap_state->permit_non_unix_accounts) {
		rid = ldapsam_get_next_available_nua_rid(ldap_state);
		if (rid == 0) {
			DEBUG(0, ("NO user RID specified on account %s, and findining next available NUA RID failed, cannot store!\n", pdb_get_username(sampass)));
			return False;
		}
	} else {
		DEBUG(0, ("NO user RID specified on account %s, cannot store!\n", pdb_get_username(sampass)));
		return False;
	}

	slprintf(temp, sizeof(temp) - 1, "%i", rid);
	make_a_mod(mods, ldap_op, "rid", temp);

	if ( pdb_get_group_rid(sampass) ) {
		rid = pdb_get_group_rid(sampass);
	} else if (IS_SAM_SET(sampass, FLAG_SAM_GID)) {
		rid = pdb_gid_to_group_rid(pdb_get_gid(sampass));
	} else if (ldap_state->permit_non_unix_accounts) {
		rid = DOMAIN_GROUP_RID_USERS;
	} else {
		DEBUG(0, ("NO group RID specified on account %s, cannot store!\n", pdb_get_username(sampass)));
		return False;
	}

	slprintf(temp, sizeof(temp) - 1, "%i", rid);
	make_a_mod(mods, ldap_op, "primaryGroupID", temp);

	slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_last_set_time(sampass));
	make_a_mod(mods, ldap_op, "pwdLastSet", temp);

	/* displayName, cn, and gecos should all be the same
	   *  most easily accomplished by giving them the same OID
	   *  gecos isn't set here b/c it should be handled by the 
	   *  add-user script
	 */

	make_a_mod(mods, ldap_op, "displayName", pdb_get_fullname(sampass));
	make_a_mod(mods, ldap_op, "cn", pdb_get_fullname(sampass));
	make_a_mod(mods, ldap_op, "description", pdb_get_acct_desc(sampass));
	make_a_mod(mods, ldap_op, "userWorkstations", pdb_get_workstations(sampass));

	/*
	 * Only updates fields which have been set (not defaults from smb.conf)
	 */

	if (IS_SAM_SET(sampass, FLAG_SAM_SMBHOME))
		make_a_mod(mods, ldap_op, "smbHome", pdb_get_homedir(sampass));
		
	if (IS_SAM_SET(sampass, FLAG_SAM_DRIVE))
		make_a_mod(mods, ldap_op, "homeDrive", pdb_get_dirdrive(sampass));
	
	if (IS_SAM_SET(sampass, FLAG_SAM_LOGONSCRIPT))
		make_a_mod(mods, ldap_op, "scriptPath", pdb_get_logon_script(sampass));

	if (IS_SAM_SET(sampass, FLAG_SAM_PROFILE))
		make_a_mod(mods, ldap_op, "profilePath", pdb_get_profile_path(sampass));

	if (IS_SAM_SET(sampass, FLAG_SAM_LOGONTIME)) {
		slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logon_time(sampass));
		make_a_mod(mods, ldap_op, "logonTime", temp);
	}

	if (IS_SAM_SET(sampass, FLAG_SAM_LOGOFFTIME)) {
		slprintf(temp, sizeof(temp) - 1, "%li", pdb_get_logoff_time(sampass));
		make_a_mod(mods, ldap_op, "logoffTime", temp);
	}

	if (IS_SAM_SET(sampass, FLAG_SAM_KICKOFFTIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_kickoff_time(sampass));
		make_a_mod(mods, ldap_op, "kickoffTime", temp);
	}

	if (IS_SAM_SET(sampass, FLAG_SAM_CANCHANGETIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_can_change_time(sampass));
		make_a_mod(mods, ldap_op, "pwdCanChange", temp);
	}

	if (IS_SAM_SET(sampass, FLAG_SAM_MUSTCHANGETIME)) {
		slprintf (temp, sizeof (temp) - 1, "%li", pdb_get_pass_must_change_time(sampass));
		make_a_mod(mods, ldap_op, "pwdMustChange", temp);
	}

	/* FIXME: Hours stuff goes in LDAP  */
	pdb_sethexpwd (temp, pdb_get_lanman_passwd(sampass), pdb_get_acct_ctrl(sampass));
	make_a_mod (mods, ldap_op, "lmPassword", temp);
	
	pdb_sethexpwd (temp, pdb_get_nt_passwd(sampass), pdb_get_acct_ctrl(sampass));
	make_a_mod (mods, ldap_op, "ntPassword", temp);
	
	make_a_mod (mods, ldap_op, "acctFlags", pdb_encode_acct_ctrl (pdb_get_acct_ctrl(sampass),
		NEW_PW_FORMAT_SPACE_PADDED_LEN));

	return True;
}


/**********************************************************************
Connect to LDAP server and find the next available RID.
*********************************************************************/
static uint32 check_nua_rid_is_avail(struct ldapsam_privates *ldap_state, uint32 top_rid, LDAP *ldap_struct) 
{
	LDAPMessage *result;
	uint32 final_rid = (top_rid & (~USER_RID_TYPE)) + RID_MULTIPLIER;
	if (top_rid == 0) {
		return 0;
	}
	
	if (final_rid < ldap_state->low_nua_rid || final_rid > ldap_state->high_nua_rid) {
		return 0;
	}

	if (ldapsam_search_one_user_by_rid(ldap_state, ldap_struct, final_rid, &result) != LDAP_SUCCESS) {
		DEBUG(0, ("Cannot allocate NUA RID %d (0x%x), as the confirmation search failed!\n", final_rid, final_rid));
		final_rid = 0;
		ldap_msgfree(result);
	}

	if (ldap_count_entries(ldap_struct, result) != 0)
	{
		DEBUG(0, ("Cannot allocate NUA RID %d (0x%x), as the RID is already in use!!\n", final_rid, final_rid));
		final_rid = 0;
		ldap_msgfree(result);
	}

	DEBUG(5, ("NUA RID %d (0x%x), declared valid\n", final_rid, final_rid));
	return final_rid;
}

/**********************************************************************
Extract the RID from an LDAP entry
*********************************************************************/
static uint32 entry_to_user_rid(struct ldapsam_privates *ldap_state, LDAPMessage *entry, LDAP *ldap_struct) {
	uint32 rid;
	SAM_ACCOUNT *user = NULL;
	if (!NT_STATUS_IS_OK(pdb_init_sam(&user))) {
		return 0;
	}

	if (init_sam_from_ldap(ldap_state, user, ldap_struct, entry)) {
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
static uint32 search_top_nua_rid(struct ldapsam_privates *ldap_state, LDAP *ldap_struct)
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

	rc = ldap_search_s(ldap_struct, lp_ldap_suffix(),
			   LDAP_SCOPE_SUBTREE, final_filter, NULL, 0,
			   &result);

	if (rc != LDAP_SUCCESS)
	{
		
		DEBUG(3, ("LDAP search failed! cannot find base for NUA RIDs: %s\n", ldap_err2string(rc)));
		DEBUGADD(3, ("Query was: %s, %s\n", lp_ldap_suffix(), final_filter));

		free(final_filter);
		ldap_msgfree(result);
		result = NULL;
		return 0;
	}
	
	count = ldap_count_entries(ldap_struct, result);
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
	entry = ldap_first_entry(ldap_struct,result);

	top_rid = entry_to_user_rid(ldap_state, entry, ldap_struct);

	while ((entry = ldap_next_entry(ldap_struct, entry))) {

		rid = entry_to_user_rid(ldap_state, entry, ldap_struct);
		if (rid > top_rid) {
			top_rid = rid;
		}
	}

	ldap_msgfree(result);
	return top_rid;
}

/**********************************************************************
Connect to LDAP server and find the next available RID.
*********************************************************************/
static uint32 ldapsam_get_next_available_nua_rid(struct ldapsam_privates *ldap_state) {
	LDAP *ldap_struct;
	uint32 next_nua_rid;
	uint32 top_nua_rid;

	if (!ldapsam_open_connection(ldap_state, &ldap_struct))
	{
		return 0;
	}
	if (!ldapsam_connect_system(ldap_state, ldap_struct))
	{
		ldap_unbind(ldap_struct);
		return 0;
	}
	
	top_nua_rid = search_top_nua_rid(ldap_state, ldap_struct);

	next_nua_rid = check_nua_rid_is_avail(ldap_state, 
					      top_nua_rid, ldap_struct);
	
	ldap_unbind(ldap_struct);
	return next_nua_rid;
}

/**********************************************************************
Connect to LDAP server for password enumeration
*********************************************************************/
static BOOL ldapsam_setsampwent(struct pdb_context *context, BOOL update)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	int rc;
	pstring filter;

	if (!ldapsam_open_connection(ldap_state, &ldap_state->ldap_struct))
	{
		return False;
	}
	if (!ldapsam_connect_system(ldap_state, ldap_state->ldap_struct))
	{
		ldap_unbind(ldap_state->ldap_struct);
		return False;
	}

	pstrcpy(filter, lp_ldap_filter());
	all_string_sub(filter, "%u", "*", sizeof(pstring));

	rc = ldap_search_s(ldap_state->ldap_struct, lp_ldap_suffix(),
			   LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			   &ldap_state->result);

	if (rc != LDAP_SUCCESS)
	{
		DEBUG(0, ("LDAP search failed: %s\n", ldap_err2string(rc)));
		DEBUG(3, ("Query was: %s, %s\n", lp_ldap_suffix(), filter));
		ldap_msgfree(ldap_state->result);
		ldap_unbind(ldap_state->ldap_struct);
		ldap_state->ldap_struct = NULL;
		ldap_state->result = NULL;
		return False;
	}

	DEBUG(2, ("ldapsam_setsampwent: %d entries in the base!\n",
		ldap_count_entries(ldap_state->ldap_struct,
		ldap_state->result)));

	ldap_state->entry = ldap_first_entry(ldap_state->ldap_struct,
				 ldap_state->result);
	ldap_state->index = 0;

	return True;
}

/**********************************************************************
End enumeration of the LDAP password list 
*********************************************************************/
static void ldapsam_endsampwent(struct pdb_context *context)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	if (ldap_state->ldap_struct && ldap_state->result)
	{
		ldap_msgfree(ldap_state->result);
		ldap_unbind(ldap_state->ldap_struct);
		ldap_state->ldap_struct = NULL;
		ldap_state->result = NULL;
	}
}

/**********************************************************************
Get the next entry in the LDAP password database 
*********************************************************************/
static BOOL ldapsam_getsampwent(struct pdb_context *context, SAM_ACCOUNT * user)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	BOOL ret = False;

	while (!ret) {
		if (!ldap_state->entry)
			return False;
		
		ldap_state->index++;
		ret = init_sam_from_ldap(ldap_state, user, ldap_state->ldap_struct,
					 ldap_state->entry);
		
		ldap_state->entry = ldap_next_entry(ldap_state->ldap_struct,
					    ldap_state->entry);
		
	}

	return True;
}

/**********************************************************************
Get SAM_ACCOUNT entry from LDAP by username 
*********************************************************************/
static BOOL ldapsam_getsampwnam(struct pdb_context *context, SAM_ACCOUNT * user, const char *sname)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;

	if (!ldapsam_open_connection(ldap_state, &ldap_struct))
		return False;
	if (!ldapsam_connect_system(ldap_state, ldap_struct))
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldapsam_search_one_user_by_name(ldap_state, ldap_struct, sname, &result) != LDAP_SUCCESS)
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldap_count_entries(ldap_struct, result) < 1)
	{
		DEBUG(4,
		      ("We don't find this user [%s] count=%d\n", sname,
		       ldap_count_entries(ldap_struct, result)));
		ldap_unbind(ldap_struct);
		return False;
	}
	entry = ldap_first_entry(ldap_struct, result);
	if (entry)
	{
		if (!init_sam_from_ldap(ldap_state, user, ldap_struct, entry)) {
			DEBUG(0,("ldapsam_getsampwnam: init_sam_from_ldap failed!\n"));
			ldap_msgfree(result);
			ldap_unbind(ldap_struct);
			return False;
		}
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
static BOOL ldapsam_getsampwrid(struct pdb_context *context, SAM_ACCOUNT * user, uint32 rid)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;

	if (!ldapsam_open_connection(ldap_state, &ldap_struct))
		return False;

	if (!ldapsam_connect_system(ldap_state, ldap_struct))
	{
		ldap_unbind(ldap_struct);
		return False;
	}
	if (ldapsam_search_one_user_by_rid(ldap_state, ldap_struct, rid, &result) !=
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
		if (!init_sam_from_ldap(ldap_state, user, ldap_struct, entry)) {
			DEBUG(0,("ldapsam_getsampwrid: init_sam_from_ldap failed!\n"));
			ldap_msgfree(result);
			ldap_unbind(ldap_struct);
			return False;
		}
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
static BOOL ldapsam_delete_sam_account(struct pdb_context *context, const SAM_ACCOUNT * sam_acct)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	const char *sname;
	int rc;
	char *dn;
	LDAP *ldap_struct;
	LDAPMessage *entry;
	LDAPMessage *result;

	if (!sam_acct) {
		DEBUG(0, ("sam_acct was NULL!\n"));
		return False;
	}

	sname = pdb_get_username(sam_acct);

	if (!ldapsam_open_connection(ldap_state, &ldap_struct))
		return False;

	DEBUG (3, ("Deleting user %s from LDAP.\n", sname));
	
	if (!ldapsam_connect_system(ldap_state, ldap_struct)) {
		ldap_unbind (ldap_struct);
		DEBUG(0, ("Failed to delete user %s from LDAP.\n", sname));
		return False;
	}

	rc = ldapsam_search_one_user_by_name(ldap_state, ldap_struct, sname, &result);
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
static BOOL ldapsam_update_sam_account(struct pdb_context *context, const SAM_ACCOUNT * newpwd)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	int rc;
	char *dn;
	LDAP *ldap_struct;
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAPMod **mods;

	if (!ldapsam_open_connection(ldap_state, &ldap_struct)) /* open a connection to the server */
		return False;

	if (!ldapsam_connect_system(ldap_state, ldap_struct))	/* connect as system account */
	{
		ldap_unbind(ldap_struct);
		return False;
	}

	rc = ldapsam_search_one_user_by_name(ldap_state, ldap_struct,
					     pdb_get_username(newpwd), &result);

	if (ldap_count_entries(ldap_struct, result) == 0)
	{
		DEBUG(0, ("No user to modify!\n"));
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}

	if (!init_ldap_from_sam(ldap_state, &mods, LDAP_MOD_REPLACE, newpwd)) {
		DEBUG(0, ("ldapsam_update_sam_account: init_ldap_from_sam failed!\n"));
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}

	entry = ldap_first_entry(ldap_struct, result);
	dn = ldap_get_dn(ldap_struct, entry);

	rc = ldap_modify_s(ldap_struct, dn, mods);

	if (rc != LDAP_SUCCESS)
	{
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

	DEBUG(2,
	      ("successfully modified uid = %s in the LDAP database\n",
	       pdb_get_username(newpwd)));
	ldap_mods_free(mods, 1);
	ldap_unbind(ldap_struct);
	return True;
}

/**********************************************************************
Add SAM_ACCOUNT to LDAP 
*********************************************************************/
static BOOL ldapsam_add_sam_account(struct pdb_context *context, const SAM_ACCOUNT * newpwd)
{
	struct ldapsam_privates *ldap_state = (struct ldapsam_privates *)context->pdb_selected->private_data;
	int rc;
	pstring filter;
	LDAP *ldap_struct = NULL;
	LDAPMessage *result = NULL;
	pstring dn;
	LDAPMod **mods = NULL;
	int 		ldap_op;
	uint32		num_result;

	if (!ldapsam_open_connection(ldap_state, &ldap_struct))	/* open a connection to the server */
	{
		return False;
	}

	if (!ldapsam_connect_system(ldap_state, ldap_struct))	/* connect as system account */
	{
		ldap_unbind(ldap_struct);
		return False;
	}

	rc = ldapsam_search_one_user_by_name (ldap_state, ldap_struct, pdb_get_username(newpwd), &result);

	if (ldap_count_entries(ldap_struct, result) != 0)
	{
		DEBUG(0,("User already in the base, with samba properties\n"));
		ldap_msgfree(result);
		ldap_unbind(ldap_struct);
		return False;
	}
	ldap_msgfree(result);

	slprintf (filter, sizeof (filter) - 1, "uid=%s", pdb_get_username(newpwd));
	rc = ldapsam_search_one_user(ldap_state, ldap_struct, filter, &result);
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
	}
	else {
		/* Check if we need to add an entry */
		DEBUG(3,("Adding new user\n"));
		ldap_op = LDAP_MOD_ADD;
                if ( pdb_get_acct_ctrl( newpwd ) & ACB_WSTRUST ) {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", pdb_get_username(newpwd), lp_ldap_machine_suffix ());
                }
                else {
                        slprintf (dn, sizeof (dn) - 1, "uid=%s,%s", pdb_get_username(newpwd), lp_ldap_user_suffix ());
                }
	}

	ldap_msgfree(result);

	if (!init_ldap_from_sam(ldap_state, &mods, ldap_op, newpwd)) {
		DEBUG(0, ("ldapsam_add_sam_account: init_ldap_from_sam failed!\n"));
		ldap_mods_free(mods, 1);
		ldap_unbind(ldap_struct);
		return False;		
	}
	make_a_mod(&mods, LDAP_MOD_ADD, "objectclass", "sambaAccount");

	if (ldap_op == LDAP_MOD_REPLACE) {
		rc = ldap_modify_s(ldap_struct, dn, mods);
	}
	else {
		rc = ldap_add_s(ldap_struct, dn, mods);
	}

	if (rc != LDAP_SUCCESS)
	{
		char *ld_error;

		ldap_get_option (ldap_struct, LDAP_OPT_ERROR_STRING, &ld_error);
		DEBUG(0,("failed to modify/add user with uid = %s (dn = %s) with: %s\n\t%s\n",
			pdb_get_username(newpwd), dn, ldap_err2string (rc), ld_error));
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

static void free_private_data(void **vp) 
{
	struct ldapsam_privates **ldap_state = (struct ldapsam_privates **)vp;

	if ((*ldap_state)->ldap_struct) {
		ldap_unbind((*ldap_state)->ldap_struct);
	}

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
	(*pdb_method)->getsampwrid = ldapsam_getsampwrid;
	(*pdb_method)->add_sam_account = ldapsam_add_sam_account;
	(*pdb_method)->update_sam_account = ldapsam_update_sam_account;
	(*pdb_method)->delete_sam_account = ldapsam_delete_sam_account;

	/* TODO: Setup private data and free */

	ldap_state = talloc_zero(pdb_context->mem_ctx, sizeof(struct ldapsam_privates));

	if (!ldap_state) {
		DEBUG(0, ("talloc() failed for ldapsam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (location) {
		ldap_state->uri = talloc_strdup(pdb_context->mem_ctx, location);
	} else {
		ldap_state->uri = "ldap://localhost";
		return NT_STATUS_INVALID_PARAMETER;
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

	ldap_state->low_nua_rid=pdb_uid_to_user_rid(low_nua_uid);

	ldap_state->high_nua_rid=pdb_uid_to_user_rid(high_nua_uid);

	return NT_STATUS_OK;
}


#else

NTSTATUS pdb_init_ldapsam(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("ldapsam not compiled in!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS pdb_init_ldapsam_nua(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	DEBUG(0, ("ldapsam_nua not compiled in!\n"));
	return NT_STATUS_UNSUCCESSFUL;
}


#endif

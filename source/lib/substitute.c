/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   string substitution functions
   Copyright (C) Andrew Tridgell 1992-2000
   
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

fstring local_machine="";
fstring remote_arch="UNKNOWN";
userdom_struct current_user_info;
pstring samlogon_user="";
BOOL sam_logon_in_ssb = False;
fstring remote_proto="UNKNOWN";
fstring remote_machine="";
static fstring smb_user_name;


/*
  setup the string used by %U substitution 
*/
void sub_set_smb_name(const char *name)
{
	fstring tmp;

	/* ignore anonymous settings */
	if (! *name) return;

	fstrcpy(tmp,name);
	trim_string(tmp," "," ");
	strlower(tmp);
	alpha_strcpy(smb_user_name,tmp,SAFE_NETBIOS_CHARS,sizeof(smb_user_name)-1);
}

const char* get_remote_machine_name(void)
{
	        return remote_machine;
}


/*******************************************************************
 Given a pointer to a %$(NAME) expand it as an environment variable.
 Return the number of characters by which the pointer should be advanced.
 Based on code by Branko Cibej <branko.cibej@hermes.si>
 When this is called p points at the '%' character.
********************************************************************/

static size_t expand_env_var(char *p, int len)
{
	fstring envname;
	char *envval;
	char *q, *r;
	int copylen;

	if (p[1] != '$')
		return 1;

	if (p[2] != '(')
		return 2;

	/*
	 * Look for the terminating ')'.
	 */

	if ((q = strchr(p,')')) == NULL) {
		DEBUG(0,("expand_env_var: Unterminated environment variable [%s]\n", p));
		return 2;
	}

	/*
	 * Extract the name from within the %$(NAME) string.
	 */

	r = p+3;
	copylen = MIN((q-r),(sizeof(envname)-1));
	strncpy(envname,r,copylen);
	envname[copylen] = '\0';

	if ((envval = getenv(envname)) == NULL) {
		DEBUG(0,("expand_env_var: Environment variable [%s] not set\n", envname));
		return 2;
	}

	/*
	 * Copy the full %$(NAME) into envname so it
	 * can be replaced.
	 */

	copylen = MIN((q+1-p),(sizeof(envname)-1));
	strncpy(envname,p,copylen);
	envname[copylen] = '\0';
	string_sub(p,envname,envval,len);
	return 0; /* Allow the environment contents to be parsed. */
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Added this to implement %p (NIS auto-map version of %H)
*******************************************************************/

static char *automount_path(char *user_name)
{
	static pstring server_path;

	/* use the passwd entry as the default */
	/* this will be the default if WITH_AUTOMOUNT is not used or fails */

	pstrcpy(server_path, get_user_home_dir(user_name));

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))

	if (lp_nis_home_map()) {
		char *home_path_start;
		char *automount_value = automount_lookup(user_name);

		if(strlen(automount_value) > 0) {
			home_path_start = strchr(automount_value,':');
			if (home_path_start != NULL) {
				DEBUG(5, ("NIS lookup succeeded.  Home path is: %s\n",
						home_path_start?(home_path_start+1):""));
				pstrcpy(server_path, home_path_start+1);
			}
		} else {
			/* NIS key lookup failed: default to user home directory from password file */
			DEBUG(5, ("NIS lookup failed. Using Home path from passwd file. Home path is: %s\n", server_path ));
		}
	}
#endif

	DEBUG(4,("Home server path: %s\n", server_path));

	return server_path;
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 This is Luke's original function with the NIS lookup code
 moved out to a separate function.
*******************************************************************/

static char *automount_server(char *user_name)
{
	extern pstring global_myname;
	static pstring server_name;

	/* use the local machine name as the default */
	/* this will be the default if WITH_AUTOMOUNT is not used or fails */
	if (*local_machine)
		pstrcpy(server_name, local_machine);
	else
		pstrcpy(server_name, global_myname);

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))

	if (lp_nis_home_map()) {
	        int home_server_len;
		char *automount_value = automount_lookup(user_name);
		home_server_len = strcspn(automount_value,":");
		DEBUG(5, ("NIS lookup succeeded.  Home server length: %d\n",home_server_len));
		if (home_server_len > sizeof(pstring))
			home_server_len = sizeof(pstring);
		strncpy(server_name, automount_value, home_server_len);
                server_name[home_server_len] = '\0';
	}
#endif

	DEBUG(4,("Home server: %s\n", server_name));

	return server_name;
}

/****************************************************************************
 Do some standard substitutions in a string.
****************************************************************************/

void standard_sub_basic(char *str, int len)
{
	extern pstring global_myname;
	char *p, *s;
	fstring pidstr;
	struct passwd *pass;

	for (s=str; (p=strchr(s, '%'));s=p) {
		fstring tmp_str;

		int l = len - (int)(p-str);
		
		switch (*(p+1)) {
		case 'U' : 
			fstrcpy(tmp_str, sam_logon_in_ssb?samlogon_user:smb_user_name);
			strlower(tmp_str);
			string_sub(p,"%U",tmp_str,l);
			break;
		case 'G' :
			fstrcpy(tmp_str, sam_logon_in_ssb?samlogon_user:smb_user_name);
			if ((pass = Get_Pwnam(tmp_str, False))!=NULL) {
				string_sub(p,"%G",gidtoname(pass->pw_gid),l);
			} else {
				p += 2;
			}
			break;
		case 'D' :
			fstrcpy(tmp_str, current_user_info.domain);
			strupper(tmp_str);
			string_sub(p,"%D", tmp_str,l);
			break;
		case 'I' : string_sub(p,"%I", client_addr(),l); break;
		case 'L' : 
			if (*local_machine)
				string_sub(p,"%L", local_machine,l); 
			else {
				pstring temp_name;

				pstrcpy(temp_name, global_myname);
				strlower(temp_name);
				string_sub(p,"%L", temp_name,l); 
			}
			break;
		case 'M' : string_sub(p,"%M", client_name(),l); break;
		case 'R' : string_sub(p,"%R", remote_proto,l); break;
		case 'T' : string_sub(p,"%T", timestring(False),l); break;
		case 'a' : string_sub(p,"%a", remote_arch,l); break;
		case 'd' :
			slprintf(pidstr,sizeof(pidstr)-1, "%d",(int)sys_getpid());
			string_sub(p,"%d", pidstr,l);
			break;
		case 'h' : string_sub(p,"%h", myhostname(),l); break;
		case 'm' : string_sub(p,"%m", remote_machine,l); break;
		case 'v' : string_sub(p,"%v", VERSION,l); break;
		case '$' : p += expand_env_var(p,l); break; /* Expand environment variables */
		case '\0': 
			p++; 
			break; /* don't run off the end of the string */
			
		default: p+=2; 
			break;
		}
	}
}

/****************************************************************************
 Do some standard substitutions in a string.
****************************************************************************/

void standard_sub_advanced(int snum, char *user, const char *connectpath, gid_t gid, char *str, int len)
{
	char *p, *s, *home;

	for (s=str; (p=strchr(s, '%'));s=p) {
		int l = len - (int)(p-str);
		
		switch (*(p+1)) {
		case 'N' : string_sub(p,"%N", automount_server(user),l); break;
		case 'H':
			if ((home = get_user_home_dir(user))) {
				string_sub(p,"%H",home, l);
			} else {
				p += 2;
			}
			break;
		case 'P': 
			string_sub(p,"%P", connectpath, l); 
			break;
			
		case 'S': 
			string_sub(p,"%S", lp_servicename(snum), l); 
			break;
			
		case 'g': 
			string_sub(p,"%g", gidtoname(gid), l); 
			break;
		case 'u': 
			string_sub(p,"%u", user, l); 
			break;
			
			/* Patch from jkf@soton.ac.uk Left the %N (NIS
			 * server name) in standard_sub_basic as it is
			 * a feature for logon servers, hence uses the
			 * username.  The %p (NIS server path) code is
			 * here as it is used instead of the default
			 * "path =" string in [homes] and so needs the
			 * service name, not the username.  */
		case 'p': 
			string_sub(p,"%p", automount_path(lp_servicename(snum)), l); 
			break;
		case '\0': 
			p++; 
			break; /* don't run off the end of the string */
			
		default: p+=2; 
			break;
		}
	}

	standard_sub_basic(str,len);
}

/****************************************************************************
 Do some standard substitutions in a string.
****************************************************************************/

void standard_sub_conn(connection_struct *conn, char *str, int len)
{
	standard_sub_advanced(SNUM(conn), conn->user, conn->connectpath, conn->gid, str, len);
}

/****************************************************************************
 Like standard_sub but for a homes share where snum still points to the [homes]
 share. No user specific snum created yet so servicename should be the username.
****************************************************************************/

void standard_sub_home(int snum, char *user, char *str, int len)
{
	char *p, *s;

	for (s=str; (p=strchr(s, '%'));s=p) {
		int l = len - (int)(p-str);
		
		switch (*(p+1)) {
		case 'S': 
			string_sub(p,"%S", user, l); 
			break;
		case 'p': 
			string_sub(p,"%p", automount_path(user), l); 
			break;
		case '\0': 
			p++; 
			break; /* don't run off the end of the string */
			
		default: p+=2; 
			break;
		}
	}

	standard_sub_advanced(snum, user, "", -1, str, len);
}

/****************************************************************************
 Like standard_sub but by snum.
****************************************************************************/

void standard_sub_snum(int snum, char *str, int len)
{
	extern struct current_user current_user;
	static uid_t cached_uid = -1;
	static fstring cached_user;
	/* calling uidtoname() on every substitute would be too expensive, so
	   we cache the result here as nearly every call is for the same uid */

	if (cached_uid != current_user.uid) {
		fstrcpy(cached_user, uidtoname(current_user.uid));
		cached_uid = current_user.uid;
	}

	standard_sub_advanced(snum, cached_user, "", -1, str, len);
}

/*******************************************************************
 Substitute strings with useful parameters.
********************************************************************/

void standard_sub_vuser(char *str, int len, user_struct *vuser)
{
	standard_sub_advanced(-1, vuser->user.unix_name, "", -1, str, len);
}

/*******************************************************************
 Substitute strings with useful parameters.
********************************************************************/

void standard_sub_vsnum(char *str, int len, user_struct *vuser, int snum)
{
	standard_sub_advanced(snum, vuser->user.unix_name, "", -1, str, len);
}

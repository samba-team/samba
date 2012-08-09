/* 
   Unix SMB/CIFS implementation.
   string substitution functions
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Gerald Carter   2006

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
#include "system/passwd.h"
#include "secrets.h"
#include "auth.h"

userdom_struct current_user_info;
fstring remote_proto="UNKNOWN";

/**
 * Set the 'local' machine name
 * @param local_name the name we are being called
 * @param if this is the 'final' name for us, not be be changed again
 */

static char *local_machine;

void free_local_machine_name(void)
{
	TALLOC_FREE(local_machine);
}

bool set_local_machine_name(const char *local_name, bool perm)
{
	static bool already_perm = false;
	char *tmp_local_machine = NULL;
	size_t len;

	if (already_perm) {
		return true;
	}

	tmp_local_machine = talloc_strdup(NULL, local_name);
	if (!tmp_local_machine) {
		return false;
	}
	trim_char(tmp_local_machine,' ',' ');

	TALLOC_FREE(local_machine);
	len = strlen(tmp_local_machine);
	local_machine = (char *)TALLOC_ZERO(NULL, len+1);
	if (!local_machine) {
		TALLOC_FREE(tmp_local_machine);
		return false;
	}
	/* alpha_strcpy includes the space for the terminating nul. */
	alpha_strcpy(local_machine,tmp_local_machine,
			SAFE_NETBIOS_CHARS,len+1);
	if (!strlower_m(local_machine)) {
		TALLOC_FREE(tmp_local_machine);
		return false;
	}
	TALLOC_FREE(tmp_local_machine);

	already_perm = perm;

	return true;
}

const char *get_local_machine_name(void)
{
	if (!local_machine || !*local_machine) {
		return lp_netbios_name();
	}

	return local_machine;
}

/**
 * Set the 'remote' machine name
 * @param remote_name the name our client wants to be called by
 * @param if this is the 'final' name for them, not be be changed again
 */

static char *remote_machine;

bool set_remote_machine_name(const char *remote_name, bool perm)
{
	static bool already_perm = False;
	char *tmp_remote_machine;
	size_t len;

	if (already_perm) {
		return true;
	}

	tmp_remote_machine = talloc_strdup(NULL, remote_name);
	if (!tmp_remote_machine) {
		return false;
	}
	trim_char(tmp_remote_machine,' ',' ');

	TALLOC_FREE(remote_machine);
	len = strlen(tmp_remote_machine);
	remote_machine = (char *)TALLOC_ZERO(NULL, len+1);
	if (!remote_machine) {
		TALLOC_FREE(tmp_remote_machine);
		return false;
	}

	/* alpha_strcpy includes the space for the terminating nul. */
	alpha_strcpy(remote_machine,tmp_remote_machine,
			SAFE_NETBIOS_CHARS,len+1);
	if (!strlower_m(remote_machine)) {
		TALLOC_FREE(tmp_remote_machine);
		return false;
	}
	TALLOC_FREE(tmp_remote_machine);

	already_perm = perm;

	return true;
}

const char *get_remote_machine_name(void)
{
	return remote_machine ? remote_machine : "";
}

/*******************************************************************
 Setup the string used by %U substitution.
********************************************************************/

static char *smb_user_name;

void sub_set_smb_name(const char *name)
{
	char *tmp;
	size_t len;
	bool is_machine_account = false;

	/* don't let anonymous logins override the name */
	if (!name || !*name) {
		return;
	}

	tmp = talloc_strdup(NULL, name);
	if (!tmp) {
		return;
	}
	trim_char(tmp, ' ', ' ');
	if (!strlower_m(tmp)) {
		TALLOC_FREE(tmp);
		return;
	}

	len = strlen(tmp);

	if (len == 0) {
		TALLOC_FREE(tmp);
		return;
	}

	/* long story but here goes....we have to allow usernames
	   ending in '$' as they are valid machine account names.
	   So check for a machine account and re-add the '$'
	   at the end after the call to alpha_strcpy().   --jerry  */

	if (tmp[len-1] == '$') {
		is_machine_account = True;
	}

	TALLOC_FREE(smb_user_name);
	smb_user_name = (char *)TALLOC_ZERO(NULL, len+1);
	if (!smb_user_name) {
		TALLOC_FREE(tmp);
		return;
	}

	/* alpha_strcpy includes the space for the terminating nul. */
	alpha_strcpy(smb_user_name, tmp,
			SAFE_NETBIOS_CHARS,
			len+1);

	TALLOC_FREE(tmp);

	if (is_machine_account) {
		len = strlen(smb_user_name);
		smb_user_name[len-1] = '$';
	}
}

static char sub_peeraddr[INET6_ADDRSTRLEN];
static const char *sub_peername = NULL;
static char sub_sockaddr[INET6_ADDRSTRLEN];

void sub_set_socket_ids(const char *peeraddr, const char *peername,
			const char *sockaddr)
{
	const char *addr = peeraddr;

	if (strnequal(addr, "::ffff:", 7)) {
		addr += 7;
	}
	strlcpy(sub_peeraddr, addr, sizeof(sub_peeraddr));

	if (sub_peername != NULL &&
			sub_peername != sub_peeraddr) {
		talloc_free(discard_const_p(char,sub_peername));
		sub_peername = NULL;
	}
	sub_peername = talloc_strdup(NULL, peername);
	if (sub_peername == NULL) {
		sub_peername = sub_peeraddr;
	}

	/*
	 * Shouldn't we do the ::ffff: cancellation here as well? The
	 * original code in talloc_sub_basic() did not do it, so I'm
	 * leaving it out here as well for compatibility.
	 */
	strlcpy(sub_sockaddr, sockaddr, sizeof(sub_sockaddr));
}

static const char *get_smb_user_name(void)
{
	return smb_user_name ? smb_user_name : "";
}

/*******************************************************************
 Setup the strings used by substitutions. Called per packet. Ensure
 %U name is set correctly also.

 smb_name must be sanitized by alpha_strcpy
********************************************************************/

void set_current_user_info(const char *smb_name, const char *unix_name,
			   const char *domain)
{
	fstrcpy(current_user_info.smb_name, smb_name);
	fstrcpy(current_user_info.unix_name, unix_name);
	fstrcpy(current_user_info.domain, domain);

	/* The following is safe as current_user_info.smb_name
	 * has already been sanitised in register_existing_vuid. */

	sub_set_smb_name(current_user_info.smb_name);
}

/*******************************************************************
 Return the current active user name.
*******************************************************************/

const char *get_current_username(void)
{
	if (current_user_info.smb_name[0] == '\0' ) {
		return get_smb_user_name();
	}

	return current_user_info.smb_name;
}

/*******************************************************************
 Given a pointer to a %$(NAME) in p and the whole string in str
 expand it as an environment variable.
 str must be a talloced string.
 Return a new allocated and expanded string.
 Based on code by Branko Cibej <branko.cibej@hermes.si>
 When this is called p points at the '%' character.
 May substitute multiple occurrencies of the same env var.
********************************************************************/

static char *realloc_expand_env_var(char *str, char *p)
{
	char *envname;
	char *envval;
	char *q, *r;
	int copylen;

	if (p[0] != '%' || p[1] != '$' || p[2] != '(') {
		return str;
	}

	/*
	 * Look for the terminating ')'.
	 */

	if ((q = strchr_m(p,')')) == NULL) {
		DEBUG(0,("expand_env_var: Unterminated environment variable [%s]\n", p));
		return str;
	}

	/*
	 * Extract the name from within the %$(NAME) string.
	 */

	r = p + 3;
	copylen = q - r;

	/* reserve space for use later add %$() chars */
	if ( (envname = talloc_array(talloc_tos(), char, copylen + 1 + 4)) == NULL ) {
		return NULL;
	}

	strncpy(envname,r,copylen);
	envname[copylen] = '\0';

	if ((envval = getenv(envname)) == NULL) {
		DEBUG(0,("expand_env_var: Environment variable [%s] not set\n", envname));
		TALLOC_FREE(envname);
		return str;
	}

	/*
	 * Copy the full %$(NAME) into envname so it
	 * can be replaced.
	 */

	copylen = q + 1 - p;
	strncpy(envname,p,copylen);
	envname[copylen] = '\0';
	r = realloc_string_sub(str, envname, envval);
	TALLOC_FREE(envname);

	return r;
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Added this to implement %p (NIS auto-map version of %H)
*******************************************************************/

static const char *automount_path(const char *user_name)
{
	TALLOC_CTX *ctx = talloc_tos();
	const char *server_path;

	/* use the passwd entry as the default */
	/* this will be the default if WITH_AUTOMOUNT is not used or fails */

	server_path = talloc_strdup(ctx, get_user_home_dir(ctx, user_name));
	if (!server_path) {
		return "";
	}

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))

	if (lp_nis_home_map()) {
		const char *home_path_start;
		char *automount_value = automount_lookup(ctx, user_name);

		if(automount_value && strlen(automount_value) > 0) {
			home_path_start = strchr_m(automount_value,':');
			if (home_path_start != NULL) {
				DEBUG(5, ("NIS lookup succeeded. "
					"Home path is: %s\n",
					home_path_start ?
						(home_path_start+1):""));
				server_path = talloc_strdup(ctx,
							home_path_start+1);
				if (!server_path) {
					server_path = "";
				}
			}
		} else {
			/* NIS key lookup failed: default to
			 * user home directory from password file */
			DEBUG(5, ("NIS lookup failed. Using Home path from "
			"passwd file. Home path is: %s\n", server_path ));
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

static const char *automount_server(const char *user_name)
{
	TALLOC_CTX *ctx = talloc_tos();
	const char *server_name;
	const char *local_machine_name = get_local_machine_name();

	/* use the local machine name as the default */
	/* this will be the default if WITH_AUTOMOUNT is not used or fails */
	if (local_machine_name && *local_machine_name) {
		server_name = talloc_strdup(ctx, local_machine_name);
	} else {
		server_name = talloc_strdup(ctx, lp_netbios_name());
	}

	if (!server_name) {
		return "";
	}

#if (defined(HAVE_NETGROUP) && defined (WITH_AUTOMOUNT))
	if (lp_nis_home_map()) {
		char *p;
		char *srv;
		char *automount_value = automount_lookup(ctx, user_name);
		if (!automount_value) {
			return "";
		}
		srv = talloc_strdup(ctx, automount_value);
		if (!srv) {
			return "";
		}
		p = strchr_m(srv, ':');
		if (!p) {
			return "";
		}
		*p = '\0';
		server_name = srv;
		DEBUG(5, ("NIS lookup succeeded.  Home server %s\n",
					server_name));
	}
#endif

	DEBUG(4,("Home server: %s\n", server_name));
	return server_name;
}

/****************************************************************************
 Do some standard substitutions in a string.
 len is the length in bytes of the space allowed in string str. If zero means
 don't allow expansions.
****************************************************************************/

void standard_sub_basic(const char *smb_name, const char *domain_name,
			char *str, size_t len)
{
	char *s;

	if ( (s = talloc_sub_basic(talloc_tos(), smb_name, domain_name, str )) != NULL ) {
		strncpy( str, s, len );
	}

	TALLOC_FREE( s );
}

/****************************************************************************
 Do some standard substitutions in a string.
 This function will return an talloced string that has to be freed.
****************************************************************************/

char *talloc_sub_basic(TALLOC_CTX *mem_ctx,
			const char *smb_name,
			const char *domain_name,
			const char *str)
{
	char *b, *p, *s, *r, *a_string;
	fstring pidstr, vnnstr;
	const char *local_machine_name = get_local_machine_name();
	TALLOC_CTX *tmp_ctx = NULL;

	/* workaround to prevent a crash while looking at bug #687 */

	if (!str) {
		DEBUG(0,("talloc_sub_basic: NULL source string!  This should not happen\n"));
		return NULL;
	}

	a_string = talloc_strdup(mem_ctx, str);
	if (a_string == NULL) {
		DEBUG(0, ("talloc_sub_basic: Out of memory!\n"));
		return NULL;
	}

	tmp_ctx = talloc_stackframe();

	for (b = s = a_string; (p = strchr_m(s, '%')); s = a_string + (p - b)) {

		r = NULL;
		b = a_string;

		switch (*(p+1)) {
		case 'U' : 
			r = strlower_talloc(tmp_ctx, smb_name);
			if (r == NULL) {
				goto error;
			}
			a_string = realloc_string_sub(a_string, "%U", r);
			break;
		case 'G' : {
			struct passwd *pass;
			r = talloc_strdup(tmp_ctx, smb_name);
			if (r == NULL) {
				goto error;
			}
			pass = Get_Pwnam_alloc(tmp_ctx, r);
			if (pass != NULL) {
				a_string = realloc_string_sub(
					a_string, "%G",
					gidtoname(pass->pw_gid));
			}
			TALLOC_FREE(pass);
			break;
		}
		case 'D' :
			r = strupper_talloc(tmp_ctx, domain_name);
			if (r == NULL) {
				goto error;
			}
			a_string = realloc_string_sub(a_string, "%D", r);
			break;
		case 'I' : {
			a_string = realloc_string_sub(
				a_string, "%I",
				sub_peeraddr[0] ? sub_peeraddr : "0.0.0.0");
			break;
		}
		case 'i': 
			a_string = realloc_string_sub(
				a_string, "%i",
				sub_sockaddr[0] ? sub_sockaddr : "0.0.0.0");
			break;
		case 'L' : 
			if ( strncasecmp_m(p, "%LOGONSERVER%", strlen("%LOGONSERVER%")) == 0 ) {
				break;
			}
			if (local_machine_name && *local_machine_name) {
				a_string = realloc_string_sub(a_string, "%L", local_machine_name); 
			} else {
				a_string = realloc_string_sub(a_string, "%L", lp_netbios_name());
			}
			break;
		case 'N':
			a_string = realloc_string_sub(a_string, "%N", automount_server(smb_name));
			break;
		case 'M' :
			a_string = realloc_string_sub(a_string, "%M",
						      sub_peername ? sub_peername : "");
			break;
		case 'R' :
			a_string = realloc_string_sub(a_string, "%R", remote_proto);
			break;
		case 'T' :
			a_string = realloc_string_sub(a_string, "%T", current_timestring(tmp_ctx, False));
			break;
		case 'a' :
			a_string = realloc_string_sub(a_string, "%a",
					get_remote_arch_str());
			break;
		case 'd' :
			slprintf(pidstr,sizeof(pidstr)-1, "%d",(int)getpid());
			a_string = realloc_string_sub(a_string, "%d", pidstr);
			break;
		case 'h' :
			a_string = realloc_string_sub(a_string, "%h", myhostname());
			break;
		case 'm' :
			a_string = realloc_string_sub(a_string, "%m",
						      remote_machine
						      ? remote_machine
						      : "");
			break;
		case 'v' :
			a_string = realloc_string_sub(a_string, "%v", samba_version_string());
			break;
		case 'w' :
			a_string = realloc_string_sub(a_string, "%w", lp_winbind_separator());
			break;
		case '$' :
			a_string = realloc_expand_env_var(a_string, p); /* Expand environment variables */
			break;
		case 'V' :
			slprintf(vnnstr,sizeof(vnnstr)-1, "%u", get_my_vnn());
			a_string = realloc_string_sub(a_string, "%V", vnnstr);
			break;
		default: 
			break;
		}

		p++;
		TALLOC_FREE(r);

		if (a_string == NULL) {
			goto done;
		}
	}

	goto done;

error:
	TALLOC_FREE(a_string);

done:
	TALLOC_FREE(tmp_ctx);
	return a_string;
}

/****************************************************************************
 Do some specific substitutions in a string.
 This function will return an allocated string that have to be freed.
****************************************************************************/

char *talloc_sub_specified(TALLOC_CTX *mem_ctx,
			const char *input_string,
			const char *username,
			const char *domain,
			uid_t uid,
			gid_t gid)
{
	char *a_string;
	char *ret_string = NULL;
	char *b, *p, *s;
	TALLOC_CTX *tmp_ctx;

	if (!(tmp_ctx = talloc_new(mem_ctx))) {
		DEBUG(0, ("talloc_new failed\n"));
		return NULL;
	}

	a_string = talloc_strdup(tmp_ctx, input_string);
	if (a_string == NULL) {
		DEBUG(0, ("talloc_sub_specified: Out of memory!\n"));
		goto done;
	}

	for (b = s = a_string; (p = strchr_m(s, '%')); s = a_string + (p - b)) {

		b = a_string;

		switch (*(p+1)) {
		case 'U' : 
			a_string = talloc_string_sub(
				tmp_ctx, a_string, "%U", username);
			break;
		case 'u' : 
			a_string = talloc_string_sub(
				tmp_ctx, a_string, "%u", username);
			break;
		case 'G' :
			if (gid != -1) {
				a_string = talloc_string_sub(
					tmp_ctx, a_string, "%G",
					gidtoname(gid));
			} else {
				a_string = talloc_string_sub(
					tmp_ctx, a_string,
					"%G", "NO_GROUP");
			}
			break;
		case 'g' :
			if (gid != -1) {
				a_string = talloc_string_sub(
					tmp_ctx, a_string, "%g",
					gidtoname(gid));
			} else {
				a_string = talloc_string_sub(
					tmp_ctx, a_string, "%g", "NO_GROUP");
			}
			break;
		case 'D' :
			a_string = talloc_string_sub(tmp_ctx, a_string,
						     "%D", domain);
			break;
		case 'N' : 
			a_string = talloc_string_sub(
				tmp_ctx, a_string, "%N",
				automount_server(username)); 
			break;
		default: 
			break;
		}

		p++;
		if (a_string == NULL) {
			goto done;
		}
	}

	/* Watch out, using "mem_ctx" here, so all intermediate stuff goes
	 * away with the TALLOC_FREE(tmp_ctx) further down. */

	ret_string = talloc_sub_basic(mem_ctx, username, domain, a_string);

 done:
	TALLOC_FREE(tmp_ctx);
	return ret_string;
}

/****************************************************************************
****************************************************************************/

char *talloc_sub_advanced(TALLOC_CTX *ctx,
			const char *servicename,
			const char *user,
			const char *connectpath,
			gid_t gid,
			const char *smb_name,
			const char *domain_name,
			const char *str)
{
	char *a_string, *ret_string;
	char *b, *p, *s;

	a_string = talloc_strdup(talloc_tos(), str);
	if (a_string == NULL) {
		DEBUG(0, ("talloc_sub_advanced: Out of memory!\n"));
		return NULL;
	}

	for (b = s = a_string; (p = strchr_m(s, '%')); s = a_string + (p - b)) {

		b = a_string;

		switch (*(p+1)) {
		case 'N' :
			a_string = realloc_string_sub(a_string, "%N", automount_server(user));
			break;
		case 'H': {
			char *h;
			if ((h = get_user_home_dir(talloc_tos(), user)))
				a_string = realloc_string_sub(a_string, "%H", h);
			TALLOC_FREE(h);
			break;
		}
		case 'P': 
			a_string = realloc_string_sub(a_string, "%P", connectpath); 
			break;
		case 'S': 
			a_string = realloc_string_sub(a_string, "%S", servicename);
			break;
		case 'g': 
			a_string = realloc_string_sub(a_string, "%g", gidtoname(gid)); 
			break;
		case 'u': 
			a_string = realloc_string_sub(a_string, "%u", user); 
			break;

			/* Patch from jkf@soton.ac.uk Left the %N (NIS
			 * server name) in standard_sub_basic as it is
			 * a feature for logon servers, hence uses the
			 * username.  The %p (NIS server path) code is
			 * here as it is used instead of the default
			 * "path =" string in [homes] and so needs the
			 * service name, not the username.  */
		case 'p': 
			a_string = realloc_string_sub(a_string, "%p",
						      automount_path(servicename)); 
			break;

		default: 
			break;
		}

		p++;
		if (a_string == NULL) {
			return NULL;
		}
	}

	ret_string = talloc_sub_basic(ctx, smb_name, domain_name, a_string);
	TALLOC_FREE(a_string);
	return ret_string;
}

void standard_sub_advanced(const char *servicename, const char *user,
			   const char *connectpath, gid_t gid,
			   const char *smb_name, const char *domain_name,
			   char *str, size_t len)
{
	char *s = talloc_sub_advanced(talloc_tos(),
				servicename, user, connectpath,
				gid, smb_name, domain_name, str);

	if (!s) {
		return;
	}
	strlcpy( str, s, len );
	TALLOC_FREE( s );
}

/******************************************************************************
 version of standard_sub_basic() for string lists; uses talloc_sub_basic()
 for the work
 *****************************************************************************/

bool str_list_sub_basic( char **list, const char *smb_name,
			 const char *domain_name )
{
	TALLOC_CTX *ctx = list;
	char *s, *tmpstr;

	while ( *list ) {
		s = *list;
		tmpstr = talloc_sub_basic(ctx, smb_name, domain_name, s);
		if ( !tmpstr ) {
			DEBUG(0,("str_list_sub_basic: "
				"talloc_sub_basic() return NULL!\n"));
			return false;
		}

		TALLOC_FREE(*list);
		*list = tmpstr;

		list++;
	}

	return true;
}

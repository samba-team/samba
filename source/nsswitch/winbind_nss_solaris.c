/*
  Solaris NSS wrapper for winbind 
  - Shirish Kalele 2000
  
  Based on Luke Howard's ldap_nss module for Solaris 
  */

/*
  Copyright (C) 1997-2003 Luke Howard.
  This file is part of the nss_ldap library.

  The nss_ldap library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.

  The nss_ldap library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with the nss_ldap library; see the file COPYING.LIB.  If not,
  write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
*/

#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <pwd.h>
#include "includes.h"
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#include "winbind_nss_config.h"

#if defined(HAVE_NSS_COMMON_H) || defined(HPUX)

#undef NSS_DEBUG

#ifdef NSS_DEBUG
#define NSS_DEBUG(str) syslog(LOG_DEBUG, "nss_winbind: %s", str);
#else
#define NSS_DEBUG(str) ;
#endif

#define NSS_ARGS(args) ((nss_XbyY_args_t *)args)

#define make_pwent_str(dest, src) 					\
{									\
  if((dest = get_static(buffer, buflen, strlen(src)+1)) == NULL)	\
    {									\
      *errnop = ERANGE;							\
      NSS_DEBUG("ERANGE error");					\
      return NSS_STATUS_TRYAGAIN; 		       			\
    }									\
  strcpy(dest, src);							\
}

static NSS_STATUS _nss_winbind_setpwent_solwrap (nss_backend_t* be, void* args)
{
	NSS_DEBUG("_nss_winbind_setpwent_solwrap");
	return _nss_winbind_setpwent();
}

static NSS_STATUS
_nss_winbind_endpwent_solwrap (nss_backend_t * be, void *args)
{
	NSS_DEBUG("_nss_winbind_endpwent_solwrap");
	return _nss_winbind_endpwent();
}

static NSS_STATUS
_nss_winbind_getpwent_solwrap (nss_backend_t* be, void *args)
{
	NSS_STATUS ret;
	char* buffer = NSS_ARGS(args)->buf.buffer;
	int buflen = NSS_ARGS(args)->buf.buflen;
	struct passwd* result = (struct passwd*) NSS_ARGS(args)->buf.result;
	int* errnop = &NSS_ARGS(args)->erange;
	char logmsg[80];

	ret = _nss_winbind_getpwent_r(result, buffer, 
				      buflen, errnop);

	if(ret == NSS_STATUS_SUCCESS)
		{
			snprintf(logmsg, 79, "_nss_winbind_getpwent_solwrap: Returning user: %s\n",
				 result->pw_name);
			NSS_DEBUG(logmsg);
			NSS_ARGS(args)->returnval = (void*) result;
		} else {
			snprintf(logmsg, 79, "_nss_winbind_getpwent_solwrap: Returning error: %d.\n",ret);
			NSS_DEBUG(logmsg);
		}
    
	return ret;
}

static NSS_STATUS
_nss_winbind_getpwnam_solwrap (nss_backend_t* be, void* args)
{
	NSS_STATUS ret;
	struct passwd* result = (struct passwd*) NSS_ARGS(args)->buf.result;

	NSS_DEBUG("_nss_winbind_getpwnam_solwrap");

	ret = _nss_winbind_getpwnam_r (NSS_ARGS(args)->key.name,
						result,
						NSS_ARGS(args)->buf.buffer,
						NSS_ARGS(args)->buf.buflen,
						&NSS_ARGS(args)->erange);
	if(ret == NSS_STATUS_SUCCESS)
		NSS_ARGS(args)->returnval = (void*) result;
  
	return ret;
}

static NSS_STATUS
_nss_winbind_getpwuid_solwrap(nss_backend_t* be, void* args)
{
	NSS_STATUS ret;
	struct passwd* result = (struct passwd*) NSS_ARGS(args)->buf.result;
  
	NSS_DEBUG("_nss_winbind_getpwuid_solwrap");
	ret = _nss_winbind_getpwuid_r (NSS_ARGS(args)->key.uid,
				       result,
				       NSS_ARGS(args)->buf.buffer,
				       NSS_ARGS(args)->buf.buflen,
				       &NSS_ARGS(args)->erange);
	if(ret == NSS_STATUS_SUCCESS)
		NSS_ARGS(args)->returnval = (void*) result;
  
	return ret;
}

static NSS_STATUS _nss_winbind_passwd_destr (nss_backend_t * be, void *args)
{
	SAFE_FREE(be);
	NSS_DEBUG("_nss_winbind_passwd_destr");
	return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t passwd_ops[] =
{
	_nss_winbind_passwd_destr,
	_nss_winbind_endpwent_solwrap,		/* NSS_DBOP_ENDENT */
	_nss_winbind_setpwent_solwrap,		/* NSS_DBOP_SETENT */
	_nss_winbind_getpwent_solwrap,		/* NSS_DBOP_GETENT */
	_nss_winbind_getpwnam_solwrap,		/* NSS_DBOP_PASSWD_BYNAME */
	_nss_winbind_getpwuid_solwrap		/* NSS_DBOP_PASSWD_BYUID */
};

nss_backend_t*
_nss_winbind_passwd_constr (const char* db_name,
			    const char* src_name,
			    const char* cfg_args)
{
	nss_backend_t *be;
  
	if(!(be = (nss_backend_t*) malloc(sizeof(nss_backend_t))) )
		return NULL;

	be->ops = passwd_ops;
	be->n_ops = sizeof(passwd_ops) / sizeof(nss_backend_op_t);

	NSS_DEBUG("Initialized nss_winbind passwd backend");
	return be;
}

/*****************************************************************
 GROUP database backend
 *****************************************************************/

static NSS_STATUS _nss_winbind_setgrent_solwrap (nss_backend_t* be, void* args)
{
	NSS_DEBUG("_nss_winbind_setgrent_solwrap");
	return _nss_winbind_setgrent();
}

static NSS_STATUS
_nss_winbind_endgrent_solwrap (nss_backend_t * be, void *args)
{
	NSS_DEBUG("_nss_winbind_endgrent_solwrap");
	return _nss_winbind_endgrent();
}

static NSS_STATUS
_nss_winbind_getgrent_solwrap(nss_backend_t* be, void* args)
{
	NSS_STATUS ret;
	char* buffer = NSS_ARGS(args)->buf.buffer;
	int buflen = NSS_ARGS(args)->buf.buflen;
	struct group* result = (struct group*) NSS_ARGS(args)->buf.result;
	int* errnop = &NSS_ARGS(args)->erange;
	char logmsg[80];

	ret = _nss_winbind_getgrent_r(result, buffer, 
				      buflen, errnop);

	if(ret == NSS_STATUS_SUCCESS)
		{
			snprintf(logmsg, 79, "_nss_winbind_getgrent_solwrap: Returning group: %s\n", result->gr_name);
			NSS_DEBUG(logmsg);
			NSS_ARGS(args)->returnval = (void*) result;
		} else {
			snprintf(logmsg, 79, "_nss_winbind_getgrent_solwrap: Returning error: %d.\n", ret);
			NSS_DEBUG(logmsg);
		}

	return ret;
	
}

static NSS_STATUS
_nss_winbind_getgrnam_solwrap(nss_backend_t* be, void* args)
{
	NSS_STATUS ret;
	struct group* result = (struct group*) NSS_ARGS(args)->buf.result;

	NSS_DEBUG("_nss_winbind_getgrnam_solwrap");
	ret = _nss_winbind_getgrnam_r(NSS_ARGS(args)->key.name,
				      result,
				      NSS_ARGS(args)->buf.buffer,
				      NSS_ARGS(args)->buf.buflen,
				      &NSS_ARGS(args)->erange);

	if(ret == NSS_STATUS_SUCCESS)
		NSS_ARGS(args)->returnval = (void*) result;
  
	return ret;
}
  
static NSS_STATUS
_nss_winbind_getgrgid_solwrap(nss_backend_t* be, void* args)
{
	NSS_STATUS ret;
	struct group* result = (struct group*) NSS_ARGS(args)->buf.result;

	NSS_DEBUG("_nss_winbind_getgrgid_solwrap");
	ret = _nss_winbind_getgrgid_r (NSS_ARGS(args)->key.gid,
				       result,
				       NSS_ARGS(args)->buf.buffer,
				       NSS_ARGS(args)->buf.buflen,
				       &NSS_ARGS(args)->erange);

	if(ret == NSS_STATUS_SUCCESS)
		NSS_ARGS(args)->returnval = (void*) result;

	return ret;
}

static NSS_STATUS
_nss_winbind_getgroupsbymember_solwrap(nss_backend_t* be, void* args)
{
	NSS_DEBUG("_nss_winbind_getgroupsbymember");
	return NSS_STATUS_NOTFOUND;
}

static NSS_STATUS
_nss_winbind_group_destr (nss_backend_t* be, void* args)
{
	SAFE_FREE(be);
	NSS_DEBUG("_nss_winbind_group_destr");
	return NSS_STATUS_SUCCESS;
}

static nss_backend_op_t group_ops[] = 
{
	_nss_winbind_group_destr,
	_nss_winbind_endgrent_solwrap,
	_nss_winbind_setgrent_solwrap,
	_nss_winbind_getgrent_solwrap,
	_nss_winbind_getgrnam_solwrap,
	_nss_winbind_getgrgid_solwrap,
	_nss_winbind_getgroupsbymember_solwrap
}; 

nss_backend_t*
_nss_winbind_group_constr (const char* db_name,
			   const char* src_name,
			   const char* cfg_args)
{
	nss_backend_t* be;

	if(!(be = (nss_backend_t*) malloc(sizeof(nss_backend_t))) )
		return NULL;

	be->ops = group_ops;
	be->n_ops = sizeof(group_ops) / sizeof(nss_backend_op_t);
  
	NSS_DEBUG("Initialized nss_winbind group backend");
	return be;
}

#endif /* SUN_NSS */



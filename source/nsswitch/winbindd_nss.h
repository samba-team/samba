/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#ifndef _WINBINDD_NTDOM_H
#define _WINBINDD_NTDOM_H

#define WINBINDD_SOCKET_NAME "pipe"            /* Name of PF_UNIX socket */
#define WINBINDD_SOCKET_DIR  "/tmp/.winbindd"  /* Name of PF_UNIX dir */
#define WINBINDD_DOMAIN_ENV  "WINBINDD_DOMAIN" /* Environment variables */
#define WINBINDD_DONT_ENV    "_NO_WINBINDD"

/* Socket commands */

enum winbindd_cmd {

	/* Get users and groups */

	WINBINDD_GETPWNAM_FROM_USER,
	WINBINDD_GETPWNAM_FROM_UID,
	WINBINDD_GETGRNAM_FROM_GROUP,
	WINBINDD_GETGRNAM_FROM_GID,

	/* Enumerate users and groups */

	WINBINDD_SETPWENT,
	WINBINDD_ENDPWENT,
	WINBINDD_GETPWENT,
	WINBINDD_SETGRENT,
	WINBINDD_ENDGRENT,
	WINBINDD_GETGRENT,

	/* PAM authenticate and password change */

	WINBINDD_PAM_AUTH,
	WINBINDD_PAM_CHAUTHTOK,

	/* List various things */

        WINBINDD_LIST_USERS,         /* List w/o rid->id mapping */
        WINBINDD_LIST_GROUPS,        /* Ditto */
	WINBINDD_LIST_TRUSTDOM,

	/* SID conversion */

	WINBINDD_LOOKUPSID,
	WINBINDD_LOOKUPNAME,

	/* S*RS functions */

	WINBINDD_SID_TO_UID,       
	WINBINDD_SID_TO_GID,
	WINBINDD_UID_TO_SID,
	WINBINDD_GID_TO_SID,

	/* Miscellaneous other stuff */

	WINBINDD_CHECK_MACHACC,     /* Check machine account pw works */

	/* Placeholder for end of cmd list */

	WINBINDD_NUM_CMDS
};

/* Winbind request structure */

struct winbindd_request {
	enum winbindd_cmd cmd;   /* Winbindd command to execute */
	pid_t pid;               /* pid of calling process */

	union {
		fstring username;    /* getpwnam */
		fstring groupname;   /* getgrnam */
		uid_t uid;           /* getpwuid, uid_to_sid */
		gid_t gid;           /* getgrgid, gid_to_sid */
		struct {
			fstring user;
			fstring pass;
		} auth;              /* pam_winbind auth module */
                struct {
                    fstring user;
                    fstring oldpass;
                    fstring newpass;
                } chauthtok;         /* pam_winbind passwd module */
		fstring sid;         /* lookupsid, sid_to_[ug]id */
		fstring name;        /* lookupname */
	} data;
        fstring domain;      /* {set,get,end}{pw,gr}ent() */
};

/* Response values */

enum winbindd_result {
	WINBINDD_ERROR,
	WINBINDD_OK
};

/* Winbind response structure */

struct winbindd_response {
    
	/* Header information */

	int length;                           /* Length of response */
	enum winbindd_result result;          /* Result code */

	/* Fixed length return data */
	
	union {
		
		/* getpwnam, getpwuid, getpwent */
		
		struct winbindd_pw {
			fstring pw_name;
			fstring pw_passwd;
			uid_t pw_uid;
			gid_t pw_gid;
			fstring pw_gecos;
			fstring pw_dir;
			fstring pw_shell;
			int pwent_ndx;
		} pw;

		/* getgrnam, getgrgid, getgrent */

		struct winbindd_gr {
			fstring gr_name;
			fstring gr_passwd;
			gid_t gr_gid;
			int num_gr_mem;
			int grent_ndx;
		} gr;

		fstring sid;        /* lookupname, [ug]id_to_sid */
		struct {
			fstring name;       /* lookupsid */
			int type;
		} name;
		uid_t uid;          /* sid_to_uid */
		gid_t gid;          /* sid_to_gid */
	} data;

	/* Variable length return data */

	void *extra_data;               /* getgrnam, getgrgid, getgrent */
};

#endif

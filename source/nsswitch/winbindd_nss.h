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
#define WINBINDD_DOMAIN_ENV  "WINBINDD_DOMAIN" /* Environment variable */

/* Socket commands */

enum winbindd_cmd {
    WINBINDD_GETPWNAM_FROM_USER,     /* getpwnam stuff */
    WINBINDD_GETPWNAM_FROM_UID,
    WINBINDD_GETGRNAM_FROM_GROUP,    /* getgrnam stuff */
    WINBINDD_GETGRNAM_FROM_GID,
    WINBINDD_SETPWENT,               /* get/set/endpwent */
    WINBINDD_ENDPWENT,
    WINBINDD_GETPWENT,
    WINBINDD_SETGRENT,               /* get/set/endgrent */
    WINBINDD_ENDGRENT,
    WINBINDD_GETGRENT
};

/* Winbind request structure */

struct winbindd_request {
    enum winbindd_cmd cmd;   /* Winbindd command to execute */
    pid_t pid;               /* pid of calling process */

    union {
        pstring username;    /* getpwnam() */
        pstring groupname;   /* getgrnam() */
        uid_t uid;           /* getpwuid() */
        gid_t gid;           /* getgrgid() */
        pstring domain;      /* {set,get,end}{pw,gr}ent() */
    } data;
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
            pstring pw_name;
            pstring pw_passwd;
            uid_t pw_uid;
            gid_t pw_gid;
            pstring pw_gecos;
            pstring pw_dir;
            pstring pw_shell;
            int pwent_ndx;
        } pw;

        /* getgrnam, getgrgid, getgrent */

        struct winbindd_gr {
            pstring gr_name;
            pstring gr_passwd;
            gid_t gr_gid;
            int num_gr_mem;
            int grent_ndx;
        } gr;

    } data;

    /* Variable length return data */

    void *extra_data;                    /* getgrnam, getgrgid, getgrent */
};

#endif

/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Winbind daemon for ntdom nss module
   Copyright (C) Tim Potter 2000
   
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

#ifndef _WINBINDD_H
#define _WINBINDD_H

#define WINBINDD_SOCKET_NAME "/tmp/winbindd" /* Name of PF_UNIX socket */
#define WINBINDD_TIMEOUT_SEC 30              /* Read/write timeout on socket */

/* Naughty global stuff */

extern int DEBUGLEVEL;
extern pstring debugf;

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
    enum winbindd_cmd cmd;
    pid_t pid;

    union {
        char username[1024];
        char groupname[1024];
        uid_t uid;
        gid_t gid;
    } data;
};

/* Response values */

enum winbindd_result {
    WINBINDD_ERROR,
    WINBINDD_OK
};

/* Winbind response structure */

struct winbindd_response {
    enum winbindd_result result;

    union {
        
        /* getpwnam_from_user, getpwnam_from_uid */

        struct winbindd_pw {
            char pw_name[1024];
            char pw_passwd[1024];
            uid_t pw_uid;
            gid_t pw_gid;
            char pw_gecos[1024];
            char pw_dir[1024];
            char pw_shell[1024];
        } pw;

        /* getgrnam_from_group, get_grnam_from_gid */

        struct winbindd_gr {
            char gr_name[1024];
            char gr_passwd[1024];
            gid_t gr_gid;
            char gr_mem[1024];
            int num_gr_mem;
        } gr;

    } data;
};

/* Structures to hold domain list */

struct winbind_domain_uid {
    pstring domain_name;                     /* Domain name */
    fstring domain_controller;               /* Domain controller */
    uid_t uid_low, uid_high;                 /* Range of uids to allocate */
    DOM_SID domain_sid;                      /* SID for this domain */
    struct winbind_domain_uid *prev, *next;
};

struct winbind_domain_gid {
    pstring domain_name;                     /* Domain name */
    fstring domain_controller;               /* Domain controller */
    gid_t gid_low, gid_high;                 /* Range of gids to allocate */
    DOM_SID domain_sid;                      /* SID for this domain */
    struct winbind_domain_gid *prev, *next;
};

#include "rpc_parse.h"
#include "rpc_client.h"

#endif /* _WINBINDD_H */

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

#define WINBINDD_SOCKET_NAME "/tmp/winbindd"    /* Name of PF_UNIX socket */
#define SERVER "nt4pdc"                     /* NT machine to contact */

#define WINBINDD_TIMEOUT 2                      /* Read/write timeout on socket */

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

#include "winbindd_proto.h"

#endif /* _WINBINDD_H */

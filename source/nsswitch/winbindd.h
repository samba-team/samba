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

#define SOCKET_NAME "/tmp/winbindd"
#define SERVER "controller"

/* Naughty global stuff */

extern int DEBUGLEVEL;
extern pstring debugf;

/* uid/gid/rid translation */

#define WINBINDD_UID_BASE 1000       /* All rid user mappings >= this */
#define WINBINDD_GID_BASE 1000       /* All rid group mappings >= this */

/* Socket commands */

enum winbindd_cmd {
    WINBINDD_GETPWNAM_FROM_USER,
    WINBINDD_GETPWNAM_FROM_UID,
    WINBINDD_GETGRNAM_FROM_GROUP,
    WINBINDD_GETGRNAM_FROM_GID
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
        struct winbindd_pw {
            char pw_name[1024];
            char pw_passwd[1024];
            uid_t pw_uid;
            gid_t pw_gid;
            char pw_gecos[1024];
            char pw_dir[1024];
            char pw_shell[1024];
        } pw;
        struct winbindd_gr {
            char gr_name[1024];
            char gr_passwd[1024];
            gid_t gr_gid;
            char gr_mem[1024];
        } gr;
    } data;
};

/* Well known rids */

struct wkrid_map
{
    uint32 rid;
    char *name;
    enum SID_NAME_USE type;
};

extern struct wkrid_map wkrid_namemap[];

#endif /* _WINBINDD_H */

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

#define WINBINDD_SOCKET_NAME "pipe"            /* Name of PF_UNIX socket */
#define WINBINDD_SOCKET_DIR  "/tmp/.winbindd"  /* Name of PF_UNIX dir */

/* Naughty global stuff */

extern int DEBUGLEVEL;

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
        pstring username;
        pstring groupname;
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
            pstring pw_name;
            pstring pw_passwd;
            uid_t pw_uid;
            gid_t pw_gid;
            pstring pw_gecos;
            pstring pw_dir;
            pstring pw_shell;
        } pw;

        /* getgrnam_from_group, get_grnam_from_gid */

        struct winbindd_gr {
            pstring gr_name;
            pstring gr_passwd;
            gid_t gr_gid;
            pstring gr_mem;
            int num_gr_mem;
        } gr;

    } data;
};

/* Client state structure */

struct winbindd_state {
    struct winbindd_state *prev, *next;       /* Linked list pointers */
    int sock;                                 /* Open socket from client */
    int read_buf_len, write_buf_len;          /* Indexes in request/response */
    BOOL finished;                            /* Can delete from list */
    struct winbindd_request request;          /* Request from client */
    struct winbindd_response response;        /* Respose to client */
    struct getent_state *getpwent_state;      /* State for getpwent() */
    struct getent_state *getgrent_state;      /* State for getgrent() */
};

struct getent_state {
    struct getent_state *prev, *next;
    struct acct_info *sam_entries;
    uint32 sam_entry_index, num_sam_entries;  
    struct winbindd_domain *domain;
    BOOL got_sam_entries;
};

extern struct winbindd_domain *domain_list;

/* Structures to hold domain list */

struct winbindd_domain {

    /* Domain information */

    fstring name;                          /* Domain name */

    fstring controller;                    /* NetBIOS name of DC */
    DOM_SID sid;                           /* SID for this domain */
    BOOL got_domain_info;                  /* Got controller and sid */

    uid_t uid_low, uid_high;               /* Range of uids to allocate */
    gid_t gid_low, gid_high;               /* Range of gids to allocate */

    /* Cached handle to lsa pipe */

    POLICY_HND lsa_handle;
    BOOL lsa_handle_open;

    /* Cached handles to samr pipe */

    POLICY_HND sam_handle, sam_dom_handle;
    BOOL sam_handle_open, sam_dom_handle_open;

    struct winbindd_domain *prev, *next;   /* Linked list info */
};

#include "rpc_parse.h"
#include "rpc_client.h"

#endif /* _WINBINDD_H */

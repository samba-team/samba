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

#ifndef _WINBINDD_H
#define _WINBINDD_H

#include "includes.h"
#include "nterr.h"

#include "winbindd_nss.h"

/* Client state structure */

struct winbindd_cli_state {
    struct winbindd_cli_state *prev, *next;   /* Linked list pointers */
    int sock;                                 /* Open socket from client */
    pid_t pid;                                /* pid of client */
    int read_buf_len, write_buf_len;          /* Indexes in request/response */
    BOOL finished;                            /* Can delete from list */
    BOOL write_extra_data;                    /* Write extra_data field */
    struct winbindd_request request;          /* Request from client */
    struct winbindd_response response;        /* Respose to client */
    struct getent_state *getpwent_state;      /* State for getpwent() */
    struct getent_state *getgrent_state;      /* State for getgrent() */
};

/* State between get{pw,gr}ent() calls */

struct getent_state {
	struct getent_state *prev, *next;
	void *sam_entries;
	uint32 sam_entry_index, num_sam_entries;
	uint32 dispinfo_ndx;
	uint32 grp_query_start_ndx;
	BOOL got_all_sam_entries, got_sam_entries;
	struct winbindd_domain *domain;
};

/* Storage for cached getpwent() user entries */

struct getpwent_user {
	fstring name;                        /* Account name */
	fstring gecos;                       /* User information */
	uint32 user_rid, group_rid;          /* NT user and group rids */
};

/* Server state structure */

struct winbindd_state {

	/* User and group id pool */

	uid_t uid_low, uid_high;               /* Range of uids to allocate */
	gid_t gid_low, gid_high;               /* Range of gids to allocate */
};

extern struct winbindd_state server_state;  /* Server information */

typedef struct {
	char *acct_name;
	char *full_name;
	uint32 user_rid;
	uint32 group_rid; /* primary group */
} WINBIND_DISPINFO;

/* per-domain methods. This is how LDAP vs RPC is selected
   This will eventually be the sole entry point to all the methods,
   I'm just starting small
 */
struct winbindd_methods {
	NTSTATUS (*query_dispinfo)(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32 *start_ndx, uint32 *num_entries, 
				   WINBIND_DISPINFO **info);

	NTSTATUS (*enum_dom_groups)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32 *start_ndx, uint32 *num_entries, 
				    struct acct_info **info);
};

/* Structures to hold per domain information */
struct winbindd_domain {
	fstring name;                          /* Domain name */	
	DOM_SID sid;                           /* SID for this domain */
	struct winbindd_methods *methods;      /* lookup methods for
                                                  this domain (LDAP or
                                                  RPC) */
	struct winbindd_domain *prev, *next;   /* Linked list info */
};

extern struct winbindd_domain *domain_list;  /* List of domains we know */

/* Used to glue a policy handle and cli_state together */

typedef struct {
	struct cli_state *cli;
	POLICY_HND pol;
} CLI_POLICY_HND;

#include "winbindd_proto.h"

#include "rpc_parse.h"
#include "rpc_client.h"

#define WINBINDD_ESTABLISH_LOOP 30
#define DOM_SEQUENCE_NONE ((uint32)-1)

/* SETENV */
#if HAVE_SETENV
#define SETENV(name, value, overwrite) setenv(name,value,overwrite)
#elif HAVE_PUTENV
#define SETENV(name, value, overwrite)					 \
{									 \
	fstring envvar;							 \
	slprintf(envvar, sizeof(fstring), "%s=%s", name, value);	 \
	putenv(envvar);							 \
}
#else
#define SETENV(name, value, overwrite) ;
#endif

#endif /* _WINBINDD_H */

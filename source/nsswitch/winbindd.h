/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   
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

#include "nterr.h"

#include "winbindd_nss.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Client state structure */

struct winbindd_cli_state {
	struct winbindd_cli_state *prev, *next;   /* Linked list pointers */
	int sock;                                 /* Open socket from client */
	pid_t pid;                                /* pid of client */
	int read_buf_len, write_buf_len;          /* Indexes in request/response */
	BOOL finished;                            /* Can delete from list */
	BOOL write_extra_data;                    /* Write extra_data field */
	time_t last_access;                       /* Time of last access (read or write) */
	BOOL privileged;                           /* Is the client 'privileged' */

	struct winbindd_request request;          /* Request from client */
	struct winbindd_response response;        /* Respose to client */
	BOOL getpwent_initialized;                /* Has getpwent_state been initialized? */
	BOOL getgrent_initialized;                /* Has getgrent_state been initialized? */
	struct getent_state *getpwent_state;      /* State for getpwent() */
	struct getent_state *getgrent_state;      /* State for getgrent() */
};

/* State between get{pw,gr}ent() calls */

struct getent_state {
	struct getent_state *prev, *next;
	void *sam_entries;
	uint32 sam_entry_index, num_sam_entries;
	BOOL got_sam_entries;
	fstring domain_name;
};

/* Storage for cached getpwent() user entries */

struct getpwent_user {
	fstring name;                        /* Account name */
	fstring gecos;                       /* User information */
	DOM_SID user_sid;                    /* NT user and primary group SIDs */
	DOM_SID group_sid;
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
	DOM_SID *user_sid;                    /* NT user and primary group SIDs */
	DOM_SID *group_sid;
} WINBIND_USERINFO;

/* Structures to hold per domain information */

struct winbindd_domain {
	fstring name;                          /* Domain name */	
	fstring alt_name;                      /* alt Domain name (if any) */
	DOM_SID sid;                           /* SID for this domain */
	BOOL initialized;		       /* Did we already ask for the domain mode? */
	BOOL native_mode;                      /* is this a win2k domain in native mode ? */
	BOOL active_directory;                 /* is this a win2k active directory ? */
	BOOL primary;                          /* is this our primary domain ? */
	BOOL internal;		/* BUILTIN and member SAM */

	/* Lookup methods for this domain (LDAP or RPC) */
	struct winbindd_methods *methods;

	/* the backend methods are used by the cache layer to find the right
	   backend */
	struct winbindd_methods *backend;

        /* Private data for the backends (used for connection cache) */

	void *private; 

	/* Sequence number stuff */

	time_t last_seq_check;
	uint32 sequence_number;
	NTSTATUS last_status;

	/* Linked list info */

	struct winbindd_domain *prev, *next;
};

/* per-domain methods. This is how LDAP vs RPC is selected
 */
struct winbindd_methods {
	/* does this backend provide a consistent view of the data? (ie. is the primary group
	   always correct) */
	BOOL consistent;

	/* get a list of users, returning a WINBIND_USERINFO for each one */
	NTSTATUS (*query_user_list)(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32 *num_entries, 
				   WINBIND_USERINFO **info);

	/* get a list of domain groups */
	NTSTATUS (*enum_dom_groups)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32 *num_entries, 
				    struct acct_info **info);

	/* get a list of domain local groups */
	NTSTATUS (*enum_local_groups)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32 *num_entries, 
				    struct acct_info **info);
				    
	/* convert one user or group name to a sid */
	NTSTATUS (*name_to_sid)(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const char *domain_name,
				const char *name,
				DOM_SID *sid,
				enum SID_NAME_USE *type);

	/* convert a sid to a user or group name */
	NTSTATUS (*sid_to_name)(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const DOM_SID *sid,
				char **domain_name,
				char **name,
				enum SID_NAME_USE *type);

	/* lookup user info for a given SID */
	NTSTATUS (*query_user)(struct winbindd_domain *domain, 
			       TALLOC_CTX *mem_ctx, 
			       const DOM_SID *user_sid,
			       WINBIND_USERINFO *user_info);

	/* lookup all groups that a user is a member of. The backend
	   can also choose to lookup by username or rid for this
	   function */
	NTSTATUS (*lookup_usergroups)(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      const DOM_SID *user_sid,
				      uint32 *num_groups, DOM_SID ***user_gids);

	/* find all members of the group with the specified group_rid */
	NTSTATUS (*lookup_groupmem)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const DOM_SID *group_sid,
				    uint32 *num_names, 
				    DOM_SID ***sid_mem, char ***names, 
				    uint32 **name_types);

	/* return the current global sequence number */
	NTSTATUS (*sequence_number)(struct winbindd_domain *domain, uint32 *seq);

	/* enumerate trusted domains */
	NTSTATUS (*trusted_domains)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32 *num_domains,
				    char ***names,
				    char ***alt_names,
				    DOM_SID **dom_sids);

	/* find the domain sid */
	NTSTATUS (*domain_sid)(struct winbindd_domain *domain,
			       DOM_SID *sid);

	/* setup the list of alternate names for the domain, if any */
	NTSTATUS (*alternate_name)(struct winbindd_domain *domain);
};

/* Used to glue a policy handle and cli_state together */

typedef struct {
	struct cli_state *cli;
	POLICY_HND pol;
} CLI_POLICY_HND;

/* Filled out by IDMAP backends */
struct winbindd_idmap_methods {
  /* Called when backend is first loaded */
  BOOL (*init)(void);

  BOOL (*get_sid_from_uid)(uid_t uid, DOM_SID *sid);
  BOOL (*get_sid_from_gid)(gid_t gid, DOM_SID *sid);

  BOOL (*get_uid_from_sid)(DOM_SID *sid, uid_t *uid);
  BOOL (*get_gid_from_sid)(DOM_SID *sid, gid_t *gid);

  /* Called when backend is unloaded */
  BOOL (*close)(void);
  /* Called to dump backend status */
  void (*status)(void);
};

#include "../nsswitch/winbindd_proto.h"

#include "rpc_parse.h"
#include "rpc_client.h"

#define WINBINDD_ESTABLISH_LOOP 30
#define WINBINDD_RESCAN_FREQ 300

#define DOM_SEQUENCE_NONE ((uint32)-1)

#endif /* _WINBINDD_H */

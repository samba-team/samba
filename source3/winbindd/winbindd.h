/*
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WINBINDD_H
#define _WINBINDD_H

#include "nsswitch/winbind_struct_protocol.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "librpc/gen_ndr/winbind.h"
#include "librpc/gen_ndr/drsblobs.h"

#include "../lib/util/tevent_ntstatus.h"

#ifdef HAVE_LIBNSCD
#include <libnscd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

#define WB_REPLACE_CHAR		'_'

struct winbind_internal_pipes;
struct ads_struct;

struct winbindd_cli_state {
	struct winbindd_cli_state *prev, *next;   /* Linked list pointers */
	int sock;                                 /* Open socket from client */
	pid_t pid;                                /* pid of client */
	char client_name[32];                     /* The process name of the client */
	time_t last_access;                       /* Time of last access (read or write) */
	bool privileged;                           /* Is the client 'privileged' */

	TALLOC_CTX *mem_ctx;			  /* memory per request */
	const char *cmd_name;
	NTSTATUS (*recv_fn)(struct tevent_req *req,
			    struct winbindd_response *presp);
	struct winbindd_request *request;         /* Request from client */
	struct tevent_queue *out_queue;
	struct winbindd_response *response;        /* Response to client */
	struct tevent_req *io_req; /* wb_req_read_* or wb_resp_write_* */

	struct getpwent_state *pwent_state; /* State for getpwent() */
	struct getgrent_state *grent_state; /* State for getgrent() */
};

struct winbindd_domain;

struct winbindd_domain_ref_internals {
	const char *location;
	const char *func;
	bool stale;
	struct dom_sid sid;
	uint64_t generation;
	struct winbindd_domain *domain; /* might be stale */
};

struct winbindd_domain_ref {
	struct winbindd_domain_ref_internals internals;
};

void _winbindd_domain_ref_set(struct winbindd_domain_ref *ref,
			      struct winbindd_domain *domain,
			      const char *location,
			      const char *func);
#define winbindd_domain_ref_set(__ref, __domain) \
	_winbindd_domain_ref_set(__ref, __domain, __location__, __func__)

bool _winbindd_domain_ref_get(struct winbindd_domain_ref *ref,
			      struct winbindd_domain **_domain,
			      const char *location,
			      const char *func);
#define winbindd_domain_ref_get(__ref, __domain) \
	_winbindd_domain_ref_get(__ref, __domain, __location__, __func__)

struct getpwent_state {
	struct winbindd_domain_ref domain;
	uint32_t next_user;
	struct wbint_RidArray rids;
};

struct getgrent_state {
	struct winbindd_domain_ref domain;
	uint32_t next_group;
	uint32_t num_groups;
	struct wbint_Principal *groups;
};

/* Our connection to the DC */

struct winbindd_cm_conn {
	struct cli_state *cli;

	enum dcerpc_AuthLevel auth_level;

	struct rpc_pipe_client *samr_pipe;
	struct policy_handle sam_connect_handle, sam_domain_handle;

	struct rpc_pipe_client *lsa_pipe;
	struct rpc_pipe_client *lsa_pipe_tcp;
	struct policy_handle lsa_policy;

	struct rpc_pipe_client *netlogon_pipe;
	struct netlogon_creds_cli_context *netlogon_creds_ctx;
	bool netlogon_force_reauth;
};

/* Async child */

struct winbindd_child {
	pid_t pid;
	struct winbindd_domain *domain; /* if valid also talloc (grant) parent */
	char *logfilename;

	int sock;
	struct tevent_fd *monitor_fde; /* Watch for dead children/sockets */
	struct tevent_queue *queue;
	struct dcerpc_binding_handle *binding_handle;

	struct tevent_timer *lockout_policy_event;
	struct tevent_timer *machine_password_change_event;
};

/* Structures to hold per domain information */

struct winbindd_domain {
	char *name;                            /* Domain name (NetBIOS) */
	char *alt_name;                        /* alt Domain name, if any (FQDN for ADS) */
	char *forest_name;                     /* Name of the AD forest we're in */
	struct dom_sid sid;                           /* SID for this domain */
	enum netr_SchannelType secure_channel_type;
	uint32_t domain_flags;                   /* Domain flags from netlogon.h */
	uint32_t domain_type;                    /* Domain type from netlogon.h */
	uint32_t domain_trust_attribs;           /* Trust attribs from netlogon.h */
	struct lsa_ForestTrustInformation2 *fti;
	struct winbindd_domain *routing_domain;
	bool initialized;		       /* Did we already ask for the domain mode? */
	bool active_directory;                 /* is this a win2k active directory ? */
	bool primary;                          /* is this our primary domain ? */
	bool internal;                         /* BUILTIN and member SAM */
	bool rodc;                             /* Are we an RODC for this AD domain? (do some operations locally) */
	bool online;			       /* is this domain available ? */
	time_t startup_time;		       /* When we set "startup" true. monotonic clock */
	bool startup;                          /* are we in the first 30 seconds after startup_time ? */

	bool can_do_ncacn_ip_tcp;

	/*
	 * Lookup methods for this domain (LDAP or RPC). The backend
	 * methods are used by the cache layer.
	 */
	struct winbindd_methods *backend;

	struct {
		struct winbind_internal_pipes *samr_pipes;
		struct ads_struct *ads_conn;
	} backend_data;

	/* A working DC */
	bool force_dc;
	char *dcname;
	const char *ping_dcname;
	struct sockaddr_storage dcaddr;

	/* Sequence number stuff */

	time_t last_seq_check;
	uint32_t sequence_number;
	NTSTATUS last_status;

	/* The smb connection */

	struct winbindd_cm_conn conn;

	/* The child pid we're talking to */

	struct winbindd_child *children;

	struct tevent_queue *queue;
	struct dcerpc_binding_handle *binding_handle;

	struct tevent_req *check_online_event;

	/* Linked list info */

	struct winbindd_domain *prev, *next;
};

struct wb_parent_idmap_config_dom {
	unsigned low_id;
	unsigned high_id;
	const char *name;
	struct dom_sid sid;
};

struct wb_parent_idmap_config {
	struct tevent_queue *queue;
	uint32_t num_doms;
	bool initialized;
	struct wb_parent_idmap_config_dom *doms;
};

struct wb_acct_info {
	const char *acct_name; /* account name */
	const char *acct_desc; /* account name */
	uint32_t rid; /* domain-relative RID */
};

/* per-domain methods. This is how LDAP vs RPC is selected
 */
struct winbindd_methods {
	/* does this backend provide a consistent view of the data? (ie. is the primary group
	   always correct) */
	bool consistent;

	/* get a list of users, returning a wbint_userinfo for each one */
	NTSTATUS (*query_user_list)(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32_t **rids);

	/* get a list of domain groups */
	NTSTATUS (*enum_dom_groups)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *num_entries,
				    struct wb_acct_info **info);

	/* get a list of domain local groups */
	NTSTATUS (*enum_local_groups)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *num_entries,
				    struct wb_acct_info **info);

	/* convert one user or group name to a sid */
	NTSTATUS (*name_to_sid)(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const char *domain_name,
				const char *name,
				uint32_t flags,
				const char **pdom_name,
				struct dom_sid *sid,
				enum lsa_SidType *type);

	/* convert a sid to a user or group name */
	NTSTATUS (*sid_to_name)(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *sid,
				char **domain_name,
				char **name,
				enum lsa_SidType *type);

	NTSTATUS (*rids_to_names)(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const struct dom_sid *domain_sid,
				  uint32_t *rids,
				  size_t num_rids,
				  char **domain_name,
				  char ***names,
				  enum lsa_SidType **types);

	/* lookup all groups that a user is a member of. The backend
	   can also choose to lookup by username or rid for this
	   function */
	NTSTATUS (*lookup_usergroups)(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      const struct dom_sid *user_sid,
				      uint32_t *num_groups, struct dom_sid **user_gids);

	/* Lookup all aliases that the sids delivered are member of. This is
	 * to implement 'domain local groups' correctly */
	NTSTATUS (*lookup_useraliases)(struct winbindd_domain *domain,
				       TALLOC_CTX *mem_ctx,
				       uint32_t num_sids,
				       const struct dom_sid *sids,
				       uint32_t *num_aliases,
				       uint32_t **alias_rids);

	/* find all members of the group with the specified group_rid */
	NTSTATUS (*lookup_groupmem)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *group_sid,
				    enum lsa_SidType type,
				    uint32_t *num_names,
				    struct dom_sid **sid_mem, char ***names,
				    uint32_t **name_types);

	/* find all members of the alias with the specified alias_sid */
	NTSTATUS (*lookup_aliasmem)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *alias_sid,
				    enum lsa_SidType type,
				    uint32_t *num_sids,
				    struct dom_sid **sid_mem);

	/* return the lockout policy */
	NTSTATUS (*lockout_policy)(struct winbindd_domain *domain,
 				   TALLOC_CTX *mem_ctx,
				   struct samr_DomInfo12 *lockout_policy);

	/* return the lockout policy */
	NTSTATUS (*password_policy)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    struct samr_DomInfo1 *password_policy);

	/* enumerate trusted domains */
	NTSTATUS (*trusted_domains)(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    struct netr_DomainTrustList *trusts);
};

/* Filled out by IDMAP backends */
struct winbindd_idmap_methods {
  /* Called when backend is first loaded */
  bool (*init)(void);

  bool (*get_sid_from_uid)(uid_t uid, struct dom_sid *sid);
  bool (*get_sid_from_gid)(gid_t gid, struct dom_sid *sid);

  bool (*get_uid_from_sid)(struct dom_sid *sid, uid_t *uid);
  bool (*get_gid_from_sid)(struct dom_sid *sid, gid_t *gid);

  /* Called when backend is unloaded */
  bool (*close)(void);
  /* Called to dump backend status */
  void (*status)(void);
};

/* Data structures for dealing with the trusted domain cache */

struct winbindd_tdc_domain {
	const char *domain_name;
	const char *dns_name;
        struct dom_sid sid;
	uint32_t trust_flags;
	uint32_t trust_attribs;
	uint32_t trust_type;
};

struct WINBINDD_MEMORY_CREDS {
	struct WINBINDD_MEMORY_CREDS *next, *prev;
	const char *username; /* lookup key. */
	uid_t uid;
	int ref_count;
	size_t len;
	uint8_t *nt_hash; /* Base pointer for the following 2 */
	uint8_t *lm_hash;
	char *pass;
};

struct WINBINDD_CCACHE_ENTRY {
	struct WINBINDD_CCACHE_ENTRY *next, *prev;
	const char *principal_name;
	const char *ccname;
	const char *service;
	const char *username;
	const char *realm;
	const char *canon_principal;
	const char *canon_realm;
	struct WINBINDD_MEMORY_CREDS *cred_ptr;
	int ref_count;
	uid_t uid;
	time_t create_time;
	time_t renew_until;
	time_t refresh_time;
	struct tevent_timer *event;
};

#include "winbindd/winbindd_proto.h"

#define WINBINDD_ESTABLISH_LOOP 30
#define WINBINDD_RESCAN_FREQ lp_winbind_cache_time()
#define WINBINDD_PAM_AUTH_KRB5_RENEW_TIME 2592000 /* one month */
#define DOM_SEQUENCE_NONE ((uint32_t)-1)

#endif /* _WINBINDD_H */

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"

/* what user is current? */
extern struct current_user current_user;

/****************************************************************************
 Become the guest user without changing the security context stack.
****************************************************************************/

BOOL change_to_guest(void)
{
	static struct passwd *pass=NULL;
	static uid_t guest_uid = (uid_t)-1;
	static gid_t guest_gid = (gid_t)-1;
	static fstring guest_name;

	if (!pass) {
		pass = Get_Pwnam(lp_guestaccount(-1),True);
		if (!pass)
			return(False);
		guest_uid = pass->pw_uid;
		guest_gid = pass->pw_gid;
		fstrcpy(guest_name, pass->pw_name);
	}
	
#ifdef AIX
	/* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before 
	   setting IDs */
	initgroups(guest_name, guest_gid);
#endif
	
	set_sec_ctx(guest_uid, guest_gid, 0, NULL, NULL);
	
	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;
	
	return True;
}

/*******************************************************************
 Check if a username is OK.
********************************************************************/

static BOOL check_user_ok(connection_struct *conn, user_struct *vuser,int snum)
{
	int i;
	for (i=0;i<conn->uid_cache.entries;i++)
		if (conn->uid_cache.list[i] == vuser->uid)
			return(True);

	if (!user_ok(vuser->user.unix_name,snum))
		return(False);

	i = conn->uid_cache.entries % UID_CACHE_SIZE;
	conn->uid_cache.list[i] = vuser->uid;

	if (conn->uid_cache.entries < UID_CACHE_SIZE)
		conn->uid_cache.entries++;

	return(True);
}

/****************************************************************************
 Become the user of a connection number without changing the security context
 stack, but modify the currnet_user entries.
****************************************************************************/

BOOL change_to_user(connection_struct *conn, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int snum;
	gid_t gid;
	uid_t uid;
	char group_c;
	BOOL must_free_token = False;
	NT_USER_TOKEN *token = NULL;

	if (!conn) {
		DEBUG(2,("change_to_user: Connection not open\n"));
		return(False);
	}

	/*
	 * We need a separate check in security=share mode due to vuid
	 * always being UID_FIELD_INVALID. If we don't do this then
	 * in share mode security we are *always* changing uid's between
	 * SMB's - this hurts performance - Badly.
	 */

	if((lp_security() == SEC_SHARE) && (current_user.conn == conn) &&
	   (current_user.uid == conn->uid)) {
		DEBUG(4,("change_to_user: Skipping user change - already user\n"));
		return(True);
	} else if ((current_user.conn == conn) && 
		   (vuser != 0) && (current_user.vuid == vuid) && 
		   (current_user.uid == vuser->uid)) 
	{
		DEBUG(4,("change_to_user: Skipping user change - already user\n"));
		return True;
	}

	snum = SNUM(conn);

	if((vuser != NULL) && !check_user_ok(conn, vuser, snum))
		return False;

	if (conn->force_user || 
		conn->admin_user ||
	    (lp_security() == SEC_SHARE)) {
		uid = conn->uid;
		gid = conn->gid;
		current_user.groups = conn->groups;
		current_user.ngroups = conn->ngroups;
		token = conn->nt_user_token;
	} else {
		if (!vuser) {
			DEBUG(2,("change_to_user: Invalid vuid used %d\n",vuid));
			return(False);
		}
		uid = vuser->uid;
		gid = vuser->gid;
		current_user.ngroups = vuser->n_groups;
		current_user.groups  = vuser->groups;
		token = vuser->nt_user_token;
	}

	/*
	 * See if we should force group for this service.
	 * If so this overrides any group set in the force
	 * user code.
	 */

	if((group_c = *lp_force_group(snum))) {
		BOOL is_guest = False;

		if(group_c == '+') {

			/*
			 * Only force group if the user is a member of
			 * the service group. Check the group memberships for
			 * this user (we already have this) to
			 * see if we should force the group.
			 */

			int i;
			for (i = 0; i < current_user.ngroups; i++) {
				if (current_user.groups[i] == conn->gid) {
					gid = conn->gid;
					break;
				}
			}
		} else {
			gid = conn->gid;
		}

		/*
		 * We've changed the group list in the token - we must
		 * re-create it.
		 */

		if (vuser && vuser->guest)
			is_guest = True;

		token = create_nt_token(uid, gid, current_user.ngroups, current_user.groups, is_guest, NULL);
		must_free_token = True;
	}
	
	set_sec_ctx(uid, gid, current_user.ngroups, current_user.groups, token);

	/*
	 * Free the new token (as set_sec_ctx copies it).
	 */

	if (must_free_token)
		delete_nt_token(&token);

	current_user.conn = conn;
	current_user.vuid = vuid;

	DEBUG(5,("change_to_user uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
 Go back to being root without changing the security context stack,
 but modify the current_user entries.
****************************************************************************/

BOOL change_to_root_user(void)
{
	set_root_sec_ctx();

	DEBUG(5,("change_to_root_user: now uid=(%d,%d) gid=(%d,%d)\n",
		(int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;

	return(True);
}

/****************************************************************************
 Become the user of an authenticated connected named pipe.
 When this is called we are currently running as the connection
 user. Doesn't modify current_user.
****************************************************************************/

BOOL become_authenticated_pipe_user(pipes_struct *p)
{
	if (!push_sec_ctx())
		return False;

	set_sec_ctx(p->pipe_user.uid, p->pipe_user.gid, 
		    p->pipe_user.ngroups, p->pipe_user.groups, p->pipe_user.nt_user_token);

	return True;
}

/****************************************************************************
 Unbecome the user of an authenticated connected named pipe.
 When this is called we are running as the authenticated pipe
 user and need to go back to being the connection user. Doesn't modify
 current_user.
****************************************************************************/

BOOL unbecome_authenticated_pipe_user(void)
{
	return pop_sec_ctx();
}

/****************************************************************************
 Utility functions used by become_xxx/unbecome_xxx.
****************************************************************************/

struct conn_ctx {
	connection_struct *conn;
	uint16 vuid;
};
 
/* A stack of current_user connection contexts. */
 
static struct conn_ctx conn_ctx_stack[MAX_SEC_CTX_DEPTH];
static int conn_ctx_stack_ndx;

static void push_conn_ctx(void)
{
	struct conn_ctx *ctx_p;
 
	/* Check we don't overflow our stack */
 
	if (conn_ctx_stack_ndx == MAX_SEC_CTX_DEPTH) {
		DEBUG(0, ("Connection context stack overflow!\n"));
		smb_panic("Connection context stack overflow!\n");
	}
 
	/* Store previous user context */
	ctx_p = &conn_ctx_stack[conn_ctx_stack_ndx];
 
	ctx_p->conn = current_user.conn;
	ctx_p->vuid = current_user.vuid;
 
	DEBUG(3, ("push_conn_ctx(%u) : conn_ctx_stack_ndx = %d\n",
		(unsigned int)ctx_p->vuid, conn_ctx_stack_ndx ));

	conn_ctx_stack_ndx++;
}

static void pop_conn_ctx(void)
{
	struct conn_ctx *ctx_p;
 
	/* Check for stack underflow. */

	if (conn_ctx_stack_ndx == 0) {
		DEBUG(0, ("Connection context stack underflow!\n"));
		smb_panic("Connection context stack underflow!\n");
	}

	conn_ctx_stack_ndx--;
	ctx_p = &conn_ctx_stack[conn_ctx_stack_ndx];

	current_user.conn = ctx_p->conn;
	current_user.vuid = ctx_p->vuid;

	ctx_p->conn = NULL;
	ctx_p->vuid = UID_FIELD_INVALID;
}

void init_conn_ctx(void)
{
    int i;
 
    /* Initialise connection context stack */
	for (i = 0; i < MAX_SEC_CTX_DEPTH; i++) {
		conn_ctx_stack[i].conn = NULL;
		conn_ctx_stack[i].vuid = UID_FIELD_INVALID;
    }
}

/****************************************************************************
 Temporarily become a root user.  Must match with unbecome_root(). Saves and
 restores the connection context.
****************************************************************************/

void become_root(void)
{
	push_sec_ctx();
	push_conn_ctx();
	set_root_sec_ctx();
}

/* Unbecome the root user */

void unbecome_root(void)
{
	pop_sec_ctx();
	pop_conn_ctx();
}

/****************************************************************************
 Push the current security context then force a change via change_to_user().
 Saves and restores the connection context.
****************************************************************************/

BOOL become_user(connection_struct *conn, uint16 vuid)
{
	if (!push_sec_ctx())
		return False;

	push_conn_ctx();

	if (!change_to_user(conn, vuid)) {
		pop_sec_ctx();
		pop_conn_ctx();
		return False;
	}

	return True;
}

BOOL unbecome_user(void)
{
	pop_sec_ctx();
	pop_conn_ctx();
	return True;
}

/*****************************************************************
 Convert the suplimentary SIDs returned in a netlogon into UNIX
 group gid_t's. Add to the total group array.
*****************************************************************/
 
void add_supplementary_nt_login_groups(int *n_groups, gid_t **pp_groups, NT_USER_TOKEN **pptok)
{
	int total_groups;
	int current_n_groups = *n_groups;
	gid_t *final_groups = NULL;
	size_t i;
	NT_USER_TOKEN *ptok = *pptok;
	NT_USER_TOKEN *new_tok = NULL;
 
	if (!ptok || (ptok->num_sids == 0))
		return;

	new_tok = dup_nt_token(ptok);
	if (!new_tok) {
		DEBUG(0,("add_supplementary_nt_login_groups: Failed to malloc new token\n"));
		return;
	}
	/* Leave the allocated space but empty the number of SIDs. */
	new_tok->num_sids = 0;

	total_groups = current_n_groups + ptok->num_sids;
 
	final_groups = (gid_t *)malloc(total_groups * sizeof(gid_t));
	if (!final_groups) {
		DEBUG(0,("add_supplementary_nt_login_groups: Failed to malloc new groups.\n"));
		delete_nt_token(&new_tok);
		return;
	}
 
	memcpy(final_groups, *pp_groups, current_n_groups * sizeof(gid_t));
	for (i = 0; i < ptok->num_sids; i++) {
		enum SID_NAME_USE sid_type;
		gid_t new_grp;
 
		if (sid_to_gid(&ptok->user_sids[i], &new_grp, &sid_type)) {
			/*
			 * Don't add the gid_t if it is already in the current group
			 * list. Some UNIXen don't like the same group more than once.
			 */
			int j;

			for (j = 0; j < current_n_groups; j++)
				if (final_groups[j] == new_grp)
					break;
		
			if ( j == current_n_groups) {
				/* Group not already present. */
				final_groups[current_n_groups++] = new_grp;
			}
		} else {
			/* SID didn't map. Copy to the new token to be saved. */
			sid_copy(&new_tok->user_sids[new_tok->num_sids++], &ptok->user_sids[i]);
		}
	}
 
	SAFE_FREE(*pp_groups);
	*pp_groups = final_groups;
	*n_groups = current_n_groups;

	/* Replace the old token with the truncated one. */
	delete_nt_token(&ptok);
	*pptok = new_tok;
}

/*****************************************************************
 *THE CANONICAL* convert name to SID function.
 Tries winbind first - then uses local lookup.
*****************************************************************/  

BOOL lookup_name(const char *name, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	extern pstring global_myname;
	extern fstring global_myworkgroup;
	fstring sid;
	char *sep = lp_winbind_separator();

	*name_type = SID_NAME_UNKNOWN;

	if (!winbind_lookup_name(NULL, name, psid, name_type) || (*name_type != SID_NAME_USER) ) {
		BOOL ret = False;

		DEBUG(10, ("lookup_name: winbind lookup for %s failed - trying local\n", name));

		/* If we are looking up a domain user, make sure it is
		   for the local machine only */

		if (strchr(name, sep[0]) || strchr(name, '\\')) {
			fstring domain, username;

			split_domain_name(name, domain, username);

			switch (lp_server_role()) {
				case ROLE_DOMAIN_PDC:
				case ROLE_DOMAIN_BDC:
					if (strequal(domain, global_myworkgroup)) {
						fstrcpy(domain, global_myname);
						ret = local_lookup_name(domain, username, psid, name_type);
					}
					/* No break is deliberate here. JRA. */
				default:
					if (strcasecmp(global_myname, domain) != 0) {
						DEBUG(5, ("lookup_name: domain %s is not local\n", domain));
						ret = local_lookup_name(global_myname, username, psid, name_type);
					}
			}
		} else {
			ret = local_lookup_name(global_myname, name, psid, name_type);
		}

		if (ret) {
			DEBUG(10,
			      ("lookup_name: (local) %s -> SID %s (type %u)\n",
			       name, sid_to_string(sid,psid),
			       (unsigned int)*name_type ));
		} else {
			DEBUG(10,("lookup name: (local) %s failed.\n", name));
		}

		return ret;
	}

	DEBUG(10,("lookup_name (winbindd): %s -> SID %s (type %u)\n",
		  name, sid_to_string(sid, psid), 
		  (unsigned int)*name_type));
	return True;
}

/*****************************************************************
 *THE CANONICAL* convert SID to name function.
 Tries winbind first - then uses local lookup.
*****************************************************************/  

BOOL lookup_sid(DOM_SID *sid, fstring dom_name, fstring name, enum SID_NAME_USE *name_type)
{
	if (!name_type)
		return False;

	*name_type = SID_NAME_UNKNOWN;

	/* Check if this is our own sid.  This should perhaps be done by
	   winbind?  For the moment handle it here. */

	if (sid->num_auths == 5) {
		DOM_SID tmp_sid;
		uint32 rid;

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);

		if (sid_equal(&global_sam_sid, &tmp_sid)) {

			return map_domain_sid_to_name(&tmp_sid, dom_name) &&
				local_lookup_rid(rid, name, name_type);
		}
	}

	if (!winbind_lookup_sid(sid, dom_name, name, name_type)) {
		fstring sid_str;
		DOM_SID tmp_sid;
		uint32 rid;

		DEBUG(10,("lookup_sid: winbind lookup for SID %s failed - trying local.\n", sid_to_string(sid_str, sid) ));

		sid_copy(&tmp_sid, sid);
		sid_split_rid(&tmp_sid, &rid);
		return map_domain_sid_to_name(&tmp_sid, dom_name) &&
				lookup_known_rid(&tmp_sid, rid, name, name_type);
	}
	return True;
}

/*****************************************************************
 Id mapping cache.  This is to avoid Winbind mappings already
 seen by smbd to be queried too frequently, keeping winbindd
 busy, and blocking smbd while winbindd is busy with other
 stuff. Written by Michael Steffens <michael.steffens@hp.com>,
 modified to use linked lists by jra.
*****************************************************************/  

#define MAX_UID_SID_CACHE_SIZE 100
#define TURNOVER_UID_SID_CACHE_SIZE 10
#define MAX_GID_SID_CACHE_SIZE 100
#define TURNOVER_GID_SID_CACHE_SIZE 10

static size_t n_uid_sid_cache = 0;
static size_t n_gid_sid_cache = 0;

static struct uid_sid_cache {
	struct uid_sid_cache *next, *prev;
	uid_t uid;
	DOM_SID sid;
	enum SID_NAME_USE sidtype;
} *uid_sid_cache_head;

static struct gid_sid_cache {
	struct gid_sid_cache *next, *prev;
	gid_t gid;
	DOM_SID sid;
	enum SID_NAME_USE sidtype;
} *gid_sid_cache_head;

/*****************************************************************
  Find a SID given a uid.
*****************************************************************/  

static BOOL fetch_sid_from_uid_cache(DOM_SID *psid, enum SID_NAME_USE *psidtype, uid_t uid)
{
	struct uid_sid_cache *pc;

	for (pc = uid_sid_cache_head; pc; pc = pc->next) {
		if (pc->uid == uid) {
			fstring sid;
			*psid = pc->sid;
			*psidtype = pc->sidtype;
			DEBUG(3,("fetch sid from uid cache %u -> %s\n",
				(unsigned int)uid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(uid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
  Find a uid given a SID.
*****************************************************************/  

static BOOL fetch_uid_from_cache(uid_t *puid, const DOM_SID *psid, enum SID_NAME_USE sidtype)
{
	struct uid_sid_cache *pc;

	for (pc = uid_sid_cache_head; pc; pc = pc->next) {
		if (sid_compare(&pc->sid, psid) == 0) {
			fstring sid;
			*puid = pc->uid;
			DEBUG(3,("fetch uid from cache %u -> %s\n",
				(unsigned int)*puid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(uid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
 Store uid to SID mapping in cache.
*****************************************************************/  

static void store_uid_sid_cache(const DOM_SID *psid, const enum SID_NAME_USE sidtype, uid_t uid)
{
	struct uid_sid_cache *pc;

	if (n_uid_sid_cache >= MAX_UID_SID_CACHE_SIZE && n_uid_sid_cache > TURNOVER_UID_SID_CACHE_SIZE) {
		/* Delete the last TURNOVER_UID_SID_CACHE_SIZE entries. */
		struct uid_sid_cache *pc_next;
		size_t i;

		for (i = 0, pc = uid_sid_cache_head; i < (n_uid_sid_cache - TURNOVER_UID_SID_CACHE_SIZE); i++, pc = pc->next)
			;
		for(; pc; pc = pc_next) {
			pc_next = pc->next;
			DLIST_REMOVE(uid_sid_cache_head,pc);
			SAFE_FREE(pc);
			n_uid_sid_cache--;
		}
	}

	pc = (struct uid_sid_cache *)malloc(sizeof(struct uid_sid_cache));
	if (!pc)
		return;
	pc->uid = uid;
	sid_copy(&pc->sid, psid);
	pc->sidtype = sidtype;
	DLIST_ADD(uid_sid_cache_head, pc);
	n_uid_sid_cache++;
}

/*****************************************************************
  Find a SID given a gid.
*****************************************************************/  

static BOOL fetch_sid_from_gid_cache(DOM_SID *psid, enum SID_NAME_USE *psidtype, gid_t gid)
{
	struct gid_sid_cache *pc;

	for (pc = gid_sid_cache_head; pc; pc = pc->next) {
		if (pc->gid == gid) {
			fstring sid;
			*psid = pc->sid;
			*psidtype = pc->sidtype;
			DEBUG(3,("fetch sid from gid cache %u -> %s\n",
				(unsigned int)gid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(gid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
  Find a gid given a SID.
*****************************************************************/  

static BOOL fetch_gid_from_cache(gid_t *pgid, const DOM_SID *psid, enum SID_NAME_USE sidtype)
{
	struct gid_sid_cache *pc;

	for (pc = gid_sid_cache_head; pc; pc = pc->next) {
		if (sid_compare(&pc->sid, psid) == 0) {
			fstring sid;
			*pgid = pc->gid;
			DEBUG(3,("fetch uid from cache %u -> %s\n",
				(unsigned int)*pgid, sid_to_string(sid, psid)));
			DLIST_PROMOTE(gid_sid_cache_head, pc);
			return True;
		}
	}
	return False;
}

/*****************************************************************
 Store gid to SID mapping in cache.
*****************************************************************/  

static void store_gid_sid_cache(const DOM_SID *psid, const enum SID_NAME_USE sidtype, gid_t gid)
{
	struct gid_sid_cache *pc;

	if (n_gid_sid_cache >= MAX_GID_SID_CACHE_SIZE && n_gid_sid_cache > TURNOVER_GID_SID_CACHE_SIZE) {
		/* Delete the last TURNOVER_GID_SID_CACHE_SIZE entries. */
		struct gid_sid_cache *pc_next;
		size_t i;

		for (i = 0, pc = gid_sid_cache_head; i < (n_gid_sid_cache - TURNOVER_GID_SID_CACHE_SIZE); i++, pc = pc->next)
			;
		for(; pc; pc = pc_next) {
			pc_next = pc->next;
			DLIST_REMOVE(gid_sid_cache_head,pc);
			SAFE_FREE(pc);
			n_gid_sid_cache--;
		}
	}

	pc = (struct gid_sid_cache *)malloc(sizeof(struct gid_sid_cache));
	if (!pc)
		return;
	pc->gid = gid;
	sid_copy(&pc->sid, psid);
	pc->sidtype = sidtype;
	DLIST_ADD(gid_sid_cache_head, pc);
	n_gid_sid_cache++;
}

/*****************************************************************
 *THE CANONICAL* convert uid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *uid_to_sid(DOM_SID *psid, uid_t uid)
{
	uid_t low, high;
	enum SID_NAME_USE sidtype;
	fstring sid;

	if (fetch_sid_from_uid_cache(psid, &sidtype, uid))
		return psid;

	if (lp_winbind_uid(&low, &high) && uid >= low && uid <= high) {
		if (winbind_uid_to_sid(psid, uid)) {

			DEBUG(10,("uid_to_sid: winbindd %u -> %s\n",
				(unsigned int)uid, sid_to_string(sid, psid)));

			if (psid)
				store_uid_sid_cache(psid, SID_NAME_USER, uid);
			return psid;
		}
	}

	local_uid_to_sid(psid, uid);
        
	DEBUG(10,("uid_to_sid: local %u -> %s\n", (unsigned int)uid, sid_to_string(sid, psid)));

	if (psid)
		store_uid_sid_cache(psid, SID_NAME_USER, uid);

	return psid;
}

/*****************************************************************
 *THE CANONICAL* convert gid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *gid_to_sid(DOM_SID *psid, gid_t gid)
{
	gid_t low, high;
	enum SID_NAME_USE sidtype;
	fstring sid;

	if (fetch_sid_from_gid_cache(psid, &sidtype, gid))
		return psid;

	if (lp_winbind_gid(&low, &high) && gid >= low && gid <= high) {
		if (winbind_gid_to_sid(psid, gid)) {

			DEBUG(10,("gid_to_sid: winbindd %u -> %s\n",
				(unsigned int)gid, sid_to_string(sid, psid)));
                        
			if (psid)
				store_gid_sid_cache(psid, SID_NAME_DOM_GRP, gid);
			return psid;
		}
	}

	local_gid_to_sid(psid, gid);
        
	DEBUG(10,("gid_to_sid: local %u -> %s\n", (unsigned int)gid, sid_to_string(sid, psid)));

	if (psid)
		store_gid_sid_cache(psid, SID_NAME_DOM_GRP, gid);

	return psid;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not. sidtype is set by this function.
*****************************************************************/  

BOOL sid_to_uid(DOM_SID *psid, uid_t *puid, enum SID_NAME_USE *sidtype)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;
	BOOL ret;

	if (fetch_uid_from_cache(puid, psid, *sidtype))
		return True;

	/* if we know its local then don't try winbindd */
	if (sid_compare_domain(&global_sam_sid, psid) == 0) {
		ret = local_sid_to_uid(puid, psid, sidtype);
		if (ret)
			store_uid_sid_cache(psid, *sidtype, *puid);
		return ret;
	}

	*sidtype = SID_NAME_UNKNOWN;

	/*
	 * First we must look up the name and decide if this is a user sid.
	 */

	if ( (!winbind_lookup_sid(psid, dom_name, name, &name_type)) || (name_type != SID_NAME_USER) ) {
		DEBUG(10,("sid_to_uid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str, psid) ));

		ret = local_sid_to_uid(puid, psid, sidtype);
		if (ret)
			store_uid_sid_cache(psid, *sidtype, *puid);
		return ret;
	}

	/*
	 * Ensure this is a user sid.
	 */

	if (name_type != SID_NAME_USER) {
		DEBUG(10,("sid_to_uid: winbind lookup succeeded but SID is not a uid (%u)\n",
				(unsigned int)name_type ));
		return False;
	}

	*sidtype = SID_NAME_USER;

	/*
	 * Get the uid for this SID.
	 */

	if (!winbind_sid_to_uid(puid, psid)) {
		DEBUG(10,("sid_to_uid: winbind lookup for sid %s failed.\n",
				sid_to_string(sid_str, psid) ));
		ret = local_sid_to_uid(puid, psid, sidtype);;
		if (ret)
			store_uid_sid_cache(psid, *sidtype, *puid);
		return ret;
	}

	DEBUG(10,("sid_to_uid: winbindd %s -> %u\n",
		sid_to_string(sid_str, psid),
		(unsigned int)*puid ));

	store_uid_sid_cache(psid, *sidtype, *puid);
	return True;
}

/*****************************************************************
 *THE CANONICAL* convert SID to gid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

BOOL sid_to_gid(DOM_SID *psid, gid_t *pgid, enum SID_NAME_USE *sidtype)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;
	BOOL ret;

	*sidtype = SID_NAME_UNKNOWN;

	if (fetch_gid_from_cache(pgid, psid, *sidtype))
		return True;

	/*
	 * First we must look up the name and decide if this is a group sid.
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str, psid) ));

		ret = local_sid_to_gid(pgid, psid, sidtype);
		if (ret)
			store_gid_sid_cache(psid, *sidtype, *pgid);
		return ret;
	}

	/*
	 * Ensure this is a group sid.
	 */

	if ((name_type != SID_NAME_DOM_GRP) && (name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_WKN_GRP)) {
		DEBUG(10,("sid_to_gid: winbind lookup succeeded but SID is not a known group (%u)\n",
				(unsigned int)name_type ));

		ret = local_sid_to_gid(pgid, psid, sidtype);
		if (ret)
			store_gid_sid_cache(psid, *sidtype, *pgid);
		return ret;
	}

	*sidtype = name_type;

	/*
	 * Get the gid for this SID.
	 */

	if (!winbind_sid_to_gid(pgid, psid)) {
		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed.\n",
				sid_to_string(sid_str, psid) ));
		return False;
	}

	DEBUG(10,("sid_to_gid: winbindd %s -> %u\n",
		sid_to_string(sid_str, psid),
		(unsigned int)*pgid ));

	store_gid_sid_cache(psid, *sidtype, *pgid);
	return True;
}

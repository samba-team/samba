#define OLD_NTDOMAIN 1

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

extern int DEBUGLEVEL;

/* what user is current? */
extern struct current_user current_user;

/****************************************************************************
 Become the guest user.
****************************************************************************/

BOOL become_guest(void)
{
	static struct passwd *pass=NULL;
	
	if (!pass)
		pass = Get_Pwnam(lp_guestaccount(-1),True);
	if (!pass)
		return(False);
	
#ifdef AIX
	/* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before 
	   setting IDs */
	initgroups(pass->pw_name, (gid_t)pass->pw_gid);
#endif
	
	set_sec_ctx(pass->pw_uid, pass->pw_gid, 0, NULL, NULL);
	
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
 Become the user of a connection number.
****************************************************************************/

BOOL become_user(connection_struct *conn, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int snum;
	gid_t gid;
	uid_t uid;
	char group_c;
	BOOL must_free_token = False;
	NT_USER_TOKEN *token = NULL;

	if (!conn) {
		DEBUG(2,("Connection not open\n"));
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
		DEBUG(4,("Skipping become_user - already user\n"));
		return(True);
	} else if ((current_user.conn == conn) && 
		   (vuser != 0) && (current_user.vuid == vuid) && 
		   (current_user.uid == vuser->uid)) {
		DEBUG(4,("Skipping become_user - already user\n"));
		return(True);
	}

	snum = SNUM(conn);

	if((vuser != NULL) && !check_user_ok(conn, vuser, snum))
		return False;

	if (conn->force_user || 
		conn->admin_user ||
	    lp_security() == SEC_SHARE ||
	    !(vuser) || (vuser->guest)) {
		uid = conn->uid;
		gid = conn->gid;
		current_user.groups = conn->groups;
		current_user.ngroups = conn->ngroups;
		token = conn->nt_user_token;
	} else {
		if (!vuser) {
			DEBUG(2,("Invalid vuid used %d\n",vuid));
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

        token = create_nt_token(uid, gid, current_user.ngroups,
                                current_user.groups, is_guest, NULL);

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

	DEBUG(5,("become_user uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
 Unbecome the user of a connection number.
****************************************************************************/

BOOL unbecome_user(void )
{
	set_root_sec_ctx();

	DEBUG(5,("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n",
		(int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;

	return(True);
}

/****************************************************************************
 Become the user of an authenticated connected named pipe.
 When this is called we are currently running as the connection
 user.
****************************************************************************/

BOOL become_authenticated_pipe_user(pipes_struct *p)
{
	BOOL res = push_sec_ctx();

	if (!res) {
		return False;
	}

	set_sec_ctx(p->pipe_user.uid, p->pipe_user.gid, 
		    p->pipe_user.ngroups, p->pipe_user.groups, p->pipe_user.nt_user_token);

	return True;
}

/****************************************************************************
 Unbecome the user of an authenticated connected named pipe.
 When this is called we are running as the authenticated pipe
 user and need to go back to being the connection user.
****************************************************************************/

BOOL unbecome_authenticated_pipe_user(pipes_struct *p)
{
	return pop_sec_ctx();
}

/* Temporarily become a root user.  Must match with unbecome_root(). */

void become_root(void)
{
	push_sec_ctx();
	set_root_sec_ctx();
}

/* Unbecome the root user */

void unbecome_root(void)
{
	pop_sec_ctx();
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
			size_t j;
 
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

BOOL lookup_name(char *name, DOM_SID *psid, enum SID_NAME_USE *name_type)
{
	extern pstring global_myname;
	fstring sid;
	char *sep = lp_winbind_separator();

	if (!winbind_lookup_name(name, psid, name_type)) {
		BOOL ret;

		DEBUG(10, ("lookup_name: winbind lookup for %s failed - trying local\n", name));

		/* If we are looking up a domain user, make sure it is
		   for the local machine only */

		if (strchr(name, sep[0]) || strchr(name, '\\')) {
			fstring domain, username;

			split_domain_name(name, domain, username);

			if (strcasecmp(global_myname, domain) != 0) {
				DEBUG(5, ("domain %s is not local\n", domain));
				return False;
			}

			ret = local_lookup_name(domain, username, psid, 
						name_type);
		} else {

			ret = local_lookup_name(global_myname, name, psid, 
						name_type);
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
 *THE CANONICAL* convert uid_t to SID function.
 Tries winbind first - then uses local lookup.
 Returns SID pointer.
*****************************************************************/  

DOM_SID *uid_to_sid(DOM_SID *psid, uid_t uid)
{
        uid_t low, high;
	fstring sid;

        if (lp_winbind_uid(&low, &high) && uid >= low && uid <= high) {
                if (winbind_uid_to_sid(psid, uid))                        
                        return psid;
                DEBUG(10,("uid_to_sid: winbind lookup for uid %u failed, trying local\n", (unsigned int)uid));
        }

        local_uid_to_sid(psid, uid);
        
	DEBUG(10,("uid_to_sid: winbindd %u -> %s\n",
                  (unsigned int)uid, sid_to_string(sid, psid) ));

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
	fstring sid;

        if (lp_winbind_gid(&low, &high) && gid >= low && gid <= high) {
                if (winbind_gid_to_sid(psid, gid))                        
                        return psid;
                DEBUG(10,("gid_to_sid: winbind lookup for gid %u failed, trying local\n", (unsigned int)gid));
        }

        local_gid_to_sid(psid, gid);
        
	DEBUG(10,("gid_to_sid: winbindd %u -> %s\n",
                  (unsigned int)gid, sid_to_string(sid, psid) ));

	return psid;
}

/*****************************************************************
 *THE CANONICAL* convert SID to uid function.
 Tries winbind first - then uses local lookup.
 Returns True if this name is a user sid and the conversion
 was done correctly, False if not.
*****************************************************************/  

BOOL sid_to_uid(DOM_SID *psid, uid_t *puid, enum SID_NAME_USE *sidtype)
{
	fstring dom_name, name, sid_str;
	enum SID_NAME_USE name_type;

	*sidtype = SID_NAME_UNKNOWN;

	/*
	 * First we must look up the name and decide if this is a user sid.
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		DEBUG(10,("sid_to_uid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str, psid) ));

		return local_sid_to_uid(puid, psid, sidtype);
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
		return False;
	}

	DEBUG(10,("sid_to_uid: winbindd %s -> %u\n",
		sid_to_string(sid_str, psid),
		(unsigned int)*puid ));

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

	*sidtype = SID_NAME_UNKNOWN;

	/*
	 * First we must look up the name and decide if this is a group sid.
	 */

	if (!winbind_lookup_sid(psid, dom_name, name, &name_type)) {
		DEBUG(10,("sid_to_gid: winbind lookup for sid %s failed - trying local.\n",
				sid_to_string(sid_str, psid) ));

		return local_sid_to_gid(pgid, psid, sidtype);
	}

	/*
	 * Ensure this is a group sid.
	 */

	if ((name_type != SID_NAME_DOM_GRP) && (name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_WKN_GRP)) {
		DEBUG(10,("sid_to_gid: winbind lookup succeeded but SID is not a known group (%u)\n",
				(unsigned int)name_type ));

		return local_sid_to_gid(pgid, psid, sidtype);
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

	return True;
}

#undef OLD_NTDOMAIN

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
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

#include "includes.h"

extern int DEBUGLEVEL;
extern struct current_user current_user;

struct sec_ctx {
	uid_t uid;
	uid_t gid;
	int ngroups;
	gid_t *groups;
};

/* A stack of security contexts.  We include the current context as being
   the first one, so there is room for another MAX_SEC_CTX_DEPTH more. */

static struct sec_ctx sec_ctx_stack[MAX_SEC_CTX_DEPTH + 1];
static int sec_ctx_stack_ndx;

/* Become the specified uid */

static BOOL become_uid(uid_t uid)
{
	/* Check for dodgy uid values */

	if (uid == (uid_t)-1 || 
	    ((sizeof(uid_t) == 2) && (uid == (uid_t)65535))) {
		static int done;
 
		if (!done) {
			DEBUG(1,("WARNING: using uid %d is a security risk\n",
				 (int)uid));
			done = 1;
		}
	}

	/* Set effective user id */

	set_effective_uid(uid);
	current_user.uid = uid;

#ifdef WITH_PROFILE
	profile_p->uid_changes++;
#endif

	return True;
}

/* Become the specified gid */

static BOOL become_gid(gid_t gid)
{
	/* Check for dodgy gid values */

	if (gid == (gid_t)-1 || ((sizeof(gid_t) == 2) && 
				 (gid == (gid_t)65535))) {
		static int done;
		
		if (!done) {
			DEBUG(1,("WARNING: using gid %d is a security risk\n",
				 (int)gid));  
			done = 1;
		}
	}
  
	/* Set effective group id */

	set_effective_gid(gid);
	current_user.gid = gid;
	
	return True;
}

/* Become the specified uid and gid */

static BOOL become_id(uid_t uid, gid_t gid)
{
	return become_gid(gid) && become_uid(uid);
}

/* Drop back to root privileges in order to change to another user */

static void gain_root(void)
{
	if (geteuid() != 0) {
		set_effective_uid(0);

		if (geteuid() != 0) {
			DEBUG(0,
			      ("Warning: You appear to have a trapdoor "
			       "uid system\n"));
		}
	}

	if (getegid() != 0) {
		set_effective_gid(0);

		if (getegid() != 0) {
			DEBUG(0,
			      ("Warning: You appear to have a trapdoor "
			       "gid system\n"));
		}
	}
}

/* Get the list of current groups */

static void get_current_groups(int *ngroups, gid_t **groups)
{
	*ngroups = getgroups(0, NULL);
	*groups = (gid_t *)malloc(*ngroups * sizeof(gid_t));

	if (!groups) {
		DEBUG(0, ("Out of memory in get_current_groups\n"));
		return;
	}

	getgroups(*ngroups, *groups);
}

/* Create a new security context on the stack.  It is the same as the old
   one.  User changes are done using the set_sec_ctx() function. */

BOOL push_sec_ctx(void)
{
	/* Check we don't overflow our stack */

	if (sec_ctx_stack_ndx == (MAX_SEC_CTX_DEPTH)) {
		DEBUG(0, ("Security context stack overflow!\n"));
		return False;
	}

	/* Store previous user context */

	sec_ctx_stack_ndx++;

	sec_ctx_stack[sec_ctx_stack_ndx].uid = geteuid();
	sec_ctx_stack[sec_ctx_stack_ndx].gid = getegid();

	sec_ctx_stack[sec_ctx_stack_ndx].ngroups = sys_getgroups(0, NULL);

	if (!(sec_ctx_stack[sec_ctx_stack_ndx].groups = 
	      malloc(sec_ctx_stack[sec_ctx_stack_ndx].ngroups * 
		     sizeof(gid_t)))) {
		DEBUG(0, ("Out of memory in push_sec_ctx()\n"));
		return False;
	}

	sys_getgroups(sec_ctx_stack[sec_ctx_stack_ndx].ngroups,
		  sec_ctx_stack[sec_ctx_stack_ndx].groups);

	return True;
}

/* Set the current security context to a given user */

void set_sec_ctx(uid_t uid, gid_t gid, int ngroups, gid_t *groups)
{
	/* Set the security context */

	DEBUG(3, ("setting sec ctx (%d, %d)\n", uid, gid));

	gain_root();

#ifdef HAVE_SETGROUPS
	sys_setgroups(ngroups, groups);
#endif

	sec_ctx_stack[sec_ctx_stack_ndx].ngroups = ngroups;

	if (sec_ctx_stack[sec_ctx_stack_ndx].groups != NULL)
		free(sec_ctx_stack[sec_ctx_stack_ndx].groups);

	sec_ctx_stack[sec_ctx_stack_ndx].groups = 
		memdup(groups, sizeof(gid_t) * ngroups);

	become_id(uid, gid);

	sec_ctx_stack[sec_ctx_stack_ndx].uid = uid;
	sec_ctx_stack[sec_ctx_stack_ndx].gid = gid;

	/* Update current_user stuff */

	current_user.uid = uid;
	current_user.gid = gid;
	current_user.ngroups = ngroups;
	current_user.groups = groups;
}

/* Become root context */

void set_root_sec_ctx(void)
{
	/* May need to worry about supplementary groups at some stage */

	set_sec_ctx(0, 0, 0, NULL);
}

/* Pop a security context from the stack */

BOOL pop_sec_ctx(void)
{
	/* Check for stack underflow */

	if (sec_ctx_stack_ndx == 0) {
		DEBUG(0, ("Security context stack underflow!\n"));
		return False;
	}

	/* Clear previous user info */

	sec_ctx_stack[sec_ctx_stack_ndx].uid = (uid_t)-1;
	sec_ctx_stack[sec_ctx_stack_ndx].gid = (gid_t)-1;

	safe_free(sec_ctx_stack[sec_ctx_stack_ndx].groups);
	sec_ctx_stack[sec_ctx_stack_ndx].ngroups = 0;

	/* Pop back previous user */

	sec_ctx_stack_ndx--;

	gain_root();

#ifdef HAVE_SETGROUPS
	sys_setgroups(sec_ctx_stack[sec_ctx_stack_ndx].ngroups,
		      sec_ctx_stack[sec_ctx_stack_ndx].groups);
#endif

	become_id(sec_ctx_stack[sec_ctx_stack_ndx].uid,
		  sec_ctx_stack[sec_ctx_stack_ndx].gid);

	/* Update current_user stuff */

	current_user.uid = sec_ctx_stack[sec_ctx_stack_ndx].uid;
	current_user.gid = sec_ctx_stack[sec_ctx_stack_ndx].gid;
	current_user.ngroups = sec_ctx_stack[sec_ctx_stack_ndx].ngroups;
	current_user.groups = sec_ctx_stack[sec_ctx_stack_ndx].groups;

	DEBUG(3, ("popped off to sec ctx (%d, %d)\n", geteuid(), getegid()));

	return True;
}

/* Initialise the security context system */

void init_sec_ctx(void)
{
	int i;

	/* Initialise security context stack */

	memset(sec_ctx_stack, 0, sizeof(struct sec_ctx) * MAX_SEC_CTX_DEPTH);

	for (i = 0; i < MAX_SEC_CTX_DEPTH; i++) {
		sec_ctx_stack[i].uid = (uid_t)-1;
		sec_ctx_stack[i].gid = (gid_t)-1;
	}

	/* Initialise first level of stack.  It is the current context */

	sec_ctx_stack[0].uid = geteuid();
	sec_ctx_stack[0].gid = getegid();

	get_current_groups(&sec_ctx_stack[0].ngroups,
			   &sec_ctx_stack[0].groups);

	/* Initialise current_user global */

	current_user.uid = sec_ctx_stack[sec_ctx_stack_ndx].uid;
	current_user.gid = sec_ctx_stack[sec_ctx_stack_ndx].gid;
	current_user.ngroups = sec_ctx_stack[sec_ctx_stack_ndx].ngroups;
	current_user.groups = sec_ctx_stack[sec_ctx_stack_ndx].groups;

	/* The conn and vuid are usually taken care of by other modules.
	   We initialise them here. */

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;
}

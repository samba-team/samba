/*
   Unix SMB/Netbios implementation.
   Version 2.0
   Copyright (C) Jeremy Allison 1998.

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

/****************************************************************************
 Gain root privilege before doing something.
****************************************************************************/

void gain_root_privilege(void)
{
#if defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID)

    /*
     * Ensure all our uids are set to root.
	 * Easy method - just use setresuid().
     */
    setresuid(0,0,0);

#else /* ! (defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID) ) */

    /*
     * Ensure all our uids are set to root.
	 * Older method - first use setuid.
     */

    setuid(0);

#if defined(HAVE_SETREUID) && !defined(HAVE_SETEUID)
	setreuid(0,0);
#else
    seteuid(0);
#endif

#endif /* (defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID) ) */
}

/****************************************************************************
 Ensure our real and effective groups are zero.
****************************************************************************/

void gain_root_group_privilege(void)
{
#ifdef HAVE_SETRESGID
	setresgid(0,0,0);
#elif defined(HAVE_SETREGID)
	setregid(0,0);
#elif defined(HAVE_SETEGID)
	setegid(0);
#endif
	setgid(0);
}

/****************************************************************************
 Set *only* the effective uid.
****************************************************************************/

int set_effective_uid(uid_t uid)
{
#if defined(HAVE_TRAPDOOR_UID)
#if defined(HAVE_SETUIDX)
	/* AIX3 has setuidx which is NOT a trapoor function (tridge) */
	if (setuidx(ID_EFFECTIVE, uid) != 0) {
		if (seteuid(uid) != 0) {
			return -1;
		}
	}
	return 0;
#endif
#endif

#if defined(HAVE_SETRESUID)
    return setresuid(-1,uid,-1);
#elif defined(HAVE_SETREUID) && !defined(HAVE_SETEUID)
	return setreuid(-1,uid);
#else
    if ((seteuid(uid) != 0) && (setuid(uid) != 0))
		return -1;
	return 0;
#endif
}

/****************************************************************************
 Set *only* the effective gid.
****************************************************************************/

int set_effective_gid(gid_t gid)
{
#if defined(HAVE_SETRESGID)
	return setresgid(-1,gid,-1);
#elif defined(HAVE_SETREGID) && !defined(HAVE_SETEGID)
	return setregid(-1,gid);
#else
	if ((setegid(gid) != 0) && (setgid(gid) != 0))
		return -1;
	return 0;
#endif
}

/****************************************************************************
 Set *only* the real uid.
****************************************************************************/

int set_real_uid(uid_t uid)
{
#if defined(HAVE_TRAPDOOR_UID)
#if defined(HAVE_SETUIDX)
    /* AIX3 has setuidx which is NOT a trapoor function (tridge) */
    return setuidx(ID_REAL,uid);
#endif
#endif

#if defined(HAVE_SETRESUID)
    return setresuid(uid,-1,-1);
#elif defined(HAVE_SETREUID) && !defined(HAVE_SETEUID)
    return setreuid(uid,-1);
#else
	/* 
	 * Without either setresuid or setreuid we cannot
	 * independently set the real uid.
	 */
    return -1;
#endif
}

/****************************************************************************
 Become the specified uid - permanently !
****************************************************************************/

BOOL become_user_permanently(uid_t uid, gid_t gid)
{
	/* 
	 * Now completely lose our privileges. This is a fairly paranoid
	 * way of doing it, but it does work on all systems that I know of.
	 */

	/*
	 * First - gain root privilege. We do this to ensure
	 * we can lose it again.
	 */

	gain_root_privilege();
	gain_root_group_privilege();

#if defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID)
	/*
	 * Ensure we change all our gids.
	 */
	setresgid(gid,gid,gid);
	
	/*
	 * Ensure all the uids are the user.
	 */
	setresuid(uid,uid,uid);
#else /* !( defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID) ) */

	/*
	 * Ensure we change all our gids.
	 */
	setgid(gid);
#if defined(HAVE_SETREGID) && !defined(HAVE_SETEGID)
	setregid(gid,gid);
#else
	setegid(gid);
#endif
	
	/*
	 * Ensure all the uids are the user.
	 */
	setuid(uid);

#if defined(HAVE_SETREUID) && !defined(HAVE_SETEUID)
	setreuid(uid,uid);
#else
	seteuid(uid);
#endif

#endif /* !( defined(HAVE_SETRESUID) && defined(HAVE_SETRESGID) ) */
	
	if (getuid() != uid || geteuid() != uid ||
	    getgid() != gid || getegid() != gid) {
		/* We failed to lose our privileges. */
		return False;
	}
	
	return(True);
}

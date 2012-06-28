/*
   Unix SMB/CIFS implementation.
   setXXid() functions for Samba.
   Copyright (C) Jeremy Allison 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SETID_H
#define _SETID_H

/*
 * NB. We don't wrap initgroups although on some systems
 * this can call setgroups. On systems with thread-specific
 * credentials (Linux so far) we know they have getgrouplist()
 * which doesn't make a system call.
 */

/* All the setXX[ug]id functions and setgroups Samba uses. */
int samba_setresuid(uid_t ruid, uid_t euid, uid_t suid);
int samba_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int samba_setreuid(uid_t ruid, uid_t euid);
int samba_setregid(gid_t rgid, gid_t egid);
int samba_seteuid(uid_t euid);
int samba_setegid(gid_t egid);
int samba_setuid(uid_t uid);
int samba_setgid(gid_t gid);
int samba_setuidx(int flags, uid_t uid);
int samba_setgidx(int flags, gid_t gid);
int samba_setgroups(size_t setlen, const gid_t *gidset);

#endif

/*
   Copyright (C) Andrew Tridgell 2009
   Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 
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

#ifndef __UID_WRAPPER_H__
#define __UID_WRAPPER_H__
#ifndef uwrap_enabled

int uwrap_enabled(void);
int uwrap_seteuid(uid_t euid);
int uwrap_setreuid(uid_t reuid, uid_t euid);
int uwrap_setresuid(uid_t reuid, uid_t euid, uid_t suid);
uid_t uwrap_geteuid(void);
int uwrap_setegid(gid_t egid);
int uwrap_setregid(gid_t rgid, gid_t egid);
int uwrap_setresgid(gid_t regid, gid_t egid, gid_t sgid);
uid_t uwrap_getegid(void);
int uwrap_setgroups(size_t size, const gid_t *list);
int uwrap_getgroups(int size, gid_t *list);
uid_t uwrap_getuid(void);
gid_t uwrap_getgid(void);

#ifdef UID_WRAPPER_REPLACE

#ifdef samba_seteuid
#undef samba_seteuid
#endif
#define samba_seteuid	uwrap_seteuid

#ifdef samba_setreuid
#undef samba_setreuid
#endif
#define samba_setreuid	uwrap_setreuid

#ifdef samba_setresuid
#undef samba_setresuid
#endif
#define samba_setresuid	uwrap_setresuid

#ifdef samba_setegid
#undef samba_setegid
#endif
#define samba_setegid	uwrap_setegid

#ifdef samba_setregid
#undef samba_setregid
#endif
#define samba_setregid	uwrap_setregid

#ifdef samba_setresgid
#undef samba_setresgid
#endif
#define samba_setresgid	uwrap_setresgid

#ifdef geteuid
#undef geteuid
#endif
#define geteuid	uwrap_geteuid

#ifdef getegid
#undef getegid
#endif
#define getegid	uwrap_getegid

#ifdef samba_setgroups
#undef samba_setgroups
#endif
#define samba_setgroups uwrap_setgroups

#ifdef getgroups
#undef getgroups
#endif
#define getgroups uwrap_getgroups

#ifdef getuid
#undef getuid
#endif
#define getuid	uwrap_getuid

#ifdef getgid
#undef getgid
#endif
#define getgid	uwrap_getgid

#endif /* UID_WRAPPER_REPLACE */
#endif /* uwrap_enabled */
#endif /* __UID_WRAPPER_H__ */

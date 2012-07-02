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

#ifndef AUTOCONF_TEST
#include "replace.h"
#include "system/passwd.h"
#include "include/includes.h"

#ifdef UID_WRAPPER_REPLACE

#ifdef samba_seteuid
#undef samba_seteuid
#endif

#ifdef samba_setreuid
#undef samba_setreuid
#endif

#ifdef samba_setresuid
#undef samba_setresuid
#endif

#ifdef samba_setegid
#undef samba_setegid
#endif

#ifdef samba_setregid
#undef samba_setregid
#endif

#ifdef samba_setresgid
#undef samba_setresgid
#endif

#ifdef samba_setgroups
#undef samba_setgroups
#endif

/* uid_wrapper will have redefined these. */
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

#include "../lib/util/setid.h"

#else

/* Inside autoconf test. */
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>

#ifdef HAVE_SYS_PRIV_H
#include <sys/priv.h>
#endif
#ifdef HAVE_SYS_ID_H
#include <sys/id.h>
#endif

/* autoconf tests don't include setid.h */
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

#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(HAVE_SYSCALL_H)
#include <syscall.h>
#endif

#if defined(HAVE_SYS_SYSCALL_H)
#include <sys/syscall.h>
#endif

/* Ensure we can't compile in a mixed syscall setup. */
#if !defined(USE_LINUX_32BIT_SYSCALLS)
#if defined(SYS_setresuid32) || defined(SYS_setresgid32) || defined(SYS_setreuid32) || defined(SYS_setregid32) || defined(SYS_setuid32) || defined(SYS_setgid32) || defined(SYS_setgroups32)
#error Mixture of 32-bit Linux system calls and 64-bit calls.
#endif
#endif

#endif

/* All the setXX[ug]id functions and setgroups Samba uses. */
int samba_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setresuid32, ruid, euid, suid);
#else
	return syscall(SYS_setresuid, ruid, euid, suid);
#endif
#elif defined(HAVE_SETRESUID)
	return setresuid(ruid, euid, suid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setresgid32, rgid, egid, sgid);
#else
	return syscall(SYS_setresgid, rgid, egid, sgid);
#endif
#elif defined(HAVE_SETRESGID)
	return setresgid(rgid, egid, sgid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setreuid(uid_t ruid, uid_t euid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setreuid32, ruid, euid);
#else
	return syscall(SYS_setreuid, ruid, euid);
#endif
#elif defined(HAVE_SETREUID)
	return setreuid(ruid, euid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setregid(gid_t rgid, gid_t egid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setregid32, rgid, egid);
#else
	return syscall(SYS_setregid, rgid, egid);
#endif
#elif defined(HAVE_SETREGID)
	return setregid(rgid, egid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_seteuid(uid_t euid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	/* seteuid is not a separate system call. */
	return syscall(SYS_setresuid32, -1, euid, -1);
#else
	/* seteuid is not a separate system call. */
	return syscall(SYS_setresuid, -1, euid, -1);
#endif
#elif defined(HAVE_SETEUID)
	return seteuid(euid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setegid(gid_t egid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	/* setegid is not a separate system call. */
	return syscall(SYS_setresgid32, -1, egid, -1);
#else
	/* setegid is not a separate system call. */
	return syscall(SYS_setresgid, -1, egid, -1);
#endif
#elif defined(HAVE_SETEGID)
	return setegid(egid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setuid(uid_t uid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setuid32, uid);
#else
	return syscall(SYS_setuid, uid);
#endif
#elif defined(HAVE_SETUID)
	return setuid(uid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setgid(gid_t gid)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setgid32, gid);
#else
	return syscall(SYS_setgid, gid);
#endif
#elif defined(HAVE_SETGID)
	return setgid(gid);
#else
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setuidx(int flags, uid_t uid)
{
#if defined(HAVE_SETUIDX)
	return setuidx(flags, uid);
#else
	/* USE_LINUX_THREAD_CREDENTIALS doesn't have this. */
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setgidx(int flags, gid_t gid)
{
#if defined(HAVE_SETGIDX)
	return setgidx(flags, gid);
#else
	/* USE_LINUX_THREAD_CREDENTIALS doesn't have this. */
	errno = ENOSYS;
	return -1;
#endif
}

int samba_setgroups(size_t setlen, const gid_t *gidset)
{
#if defined(USE_LINUX_THREAD_CREDENTIALS)
#if defined(USE_LINUX_32BIT_SYSCALLS)
	return syscall(SYS_setgroups32, setlen, gidset);
#else
	return syscall(SYS_setgroups, setlen, gidset);
#endif
#elif defined(HAVE_SETGROUPS)
	return setgroups(setlen, gidset);
#else
	errno = ENOSYS;
	return -1;
#endif
}

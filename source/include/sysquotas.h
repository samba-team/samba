/* 
    Unix SMB/CIFS implementation.
    SYS QUOTA code constants
    Copyright (C) Stefan (metze) Metzmacher	2003
    
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
 
#ifndef _SYSQUOTAS_H
#define _SYSQUOTAS_H
 
#ifdef HAVE_SYS_QUOTAS

/* Sometimes we need this on linux for linux/quota.h */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

/*
 * This shouldn't be neccessary - it should be /usr/include/sys/quota.h
 * Unfortunately, RH7.1 ships with a different quota system using struct mem_dqblk
 * rather than the struct dqblk defined in /usr/include/sys/quota.h.
 * This means we must include linux/quota.h to have a hope of working on
 * RH7.1 systems. And it also means this breaks if the kernel is upgraded
 * to a Linus 2.4.x (where x > the minor number shipped with RH7.1) until
 * Linus synchronises with the AC patches. Sometimes I *hate* Linux :-). JRA.
 */
#ifdef HAVE_LINUX_QUOTA_H
#include <linux/quota.h>
#elif defined(HAVE_SYS_QUOTA_H)
#include <sys/quota.h>
#endif

#if defined(HAVE_STRUCT_IF_DQBLK)
# define SYS_DQBLK if_dqblk
# define dqb_curblocks dqb_curspace/bsize
#elif defined(HAVE_STRUCT_MEM_DQBLK)
# define SYS_DQBLK mem_dqblk
# define dqb_curblocks dqb_curspace/bsize
#else /* STRUCT_DQBLK */
# define SYS_DQBLK dqblk
#endif

#ifndef Q_SETQLIM
#define Q_SETQLIM Q_SETQUOTA
#endif

/*********************************************
 check for XFS QUOTA MANAGER 
 *********************************************/
/* on linux */
#ifdef HAVE_LINUX_XQM_H
# include <linux/xqm.h>
# define HAVE_XFS_QUOTA
#else
# ifdef HAVE_XFS_XQM_H
#  include <xfs/xqm.h>
#  define HAVE_XFS_QUOTA
# else
#  ifdef HAVE_LINUX_DQBLK_XFS_H
#   include <linux/dqblk_xfs.h>
#   define HAVE_XFS_QUOTA
#  endif 
# endif
#endif
/* on IRIX */
#ifdef Q_XGETQUOTA
# ifndef HAVE_XFS_QUOTA
#  define HAVE_XFS_QUOTA
#  ifndef Q_XQUOTAON
#   define Q_XQUOTAON Q_QUOTAON
#  endif /* Q_XQUOTAON */
#  ifndef Q_XQUOTAOFF
#   define Q_XQUOTAOFF Q_QUOTAOFF
#  endif /* Q_XQUOTAOFF */
#  ifndef Q_XGETQSTAT
#   define Q_XGETQSTAT Q_GETQSTAT
#  endif /* Q_XGETQSTAT */
# endif /* HAVE_XFS_QUOTA */
#endif /* Q_XGETQUOTA */

#ifdef HAVE_XFS_QUOTA
/* Linux has BBSIZE in <linux/xfs_fs.h>
 * or <xfs/xfs_fs.h>
 * IRIX has BBSIZE in <sys/param.h>
 */
#ifdef HAVE_LINUX_XFS_FS_H
#include <linux/xfs_fs.h>
#elif defined(HAVE_XFS_XFS_FS_H)
#include <xfs/xfs_fs.h>
#endif /* *_XFS_FS_H */

#ifndef BBSHIFT
#define	BBSHIFT		9
#endif /* BBSHIFT */
#ifndef BBSIZE
#define	BBSIZE		(1<<BBSHIFT)
#endif /* BBSIZE */

#endif /* HAVE_XFS_QUOTA */

#ifdef LINUX
# ifndef QUOTABLOCK_SIZE
#  define QUOTABLOCK_SIZE 1024
# endif
/* end LINUX */
#elif defined(IRIX6)
# ifndef QUOTABLOCK_SIZE
#  define QUOTABLOCK_SIZE BBSIZE
# endif
/* end IRIX6 */
#else /* HPUP,... */
# ifndef QUOTABLOCK_SIZE
#  define QUOTABLOCK_SIZE DEV_BSIZE
# endif
#endif /* HPUP,... */

#if !defined(QUOTAFILENAME) && defined(QFILENAME)
#define QUOTAFILENAME QFILENAME
#endif

#ifdef INITQFNAMES
#define USERQUOTAFILE_EXTENSION ".user"
#else
#define USERQUOTAFILE_EXTENSION ""
#endif

/* this check should be before the QCMD fake! */
#if defined(QCMD)&&defined(GRPQUOTA)
#define HAVE_GROUP_QUOTA
#endif

/* on some systems we have to fake this up ...*/
#ifndef QCMD
#define QCMD(cmd,type)	(cmd)
#endif /* QCMD */


#ifdef HAVE_DQB_FSOFTLIMIT
#define dqb_isoftlimit	dqb_fsoftlimit
#define dqb_ihardlimit	dqb_fhardlimit
#define dqb_curinodes	dqb_curfiles
#endif

/* maybe we can add a configure test for HAVE_CADDR_T,
 * but it's not needed
 */
#ifdef HAVE_CADDR_T
#define CADDR_T caddr_t
#else /* CADDR_T */
#define CADDR_T void*
#endif /* CADDR_T */

#if defined(HAVE_MNTENT_H)&&defined(HAVE_SETMNTENT)&&defined(HAVE_GETMNTENT)&&defined(HAVE_ENDMNTENT)
#include <mntent.h>
#define HAVE_MNTENT 1
/*#endif defined(HAVE_MNTENT_H)&&defined(HAVE_SETMNTENT)&&defined(HAVE_GETMNTENT)&&defined(HAVE_ENDMNTENT) */
#elif defined(HAVE_DEVNM_H)&&defined(HAVE_DEVNM)
#include <devnm.h>
#endif /* defined(HAVE_DEVNM_H)&&defined(HAVE_DEVNM) */

#endif /* HAVE_SYS_QUOTAS */


#ifndef QUOTABLOCK_SIZE
#define QUOTABLOCK_SIZE	1024
#endif

/**************************************************
 Some stuff for the sys_quota api.
 **************************************************/ 

#define SMB_QUOTAS_NO_LIMIT	((SMB_BIG_UINT)(0))
#define SMB_QUOTAS_NO_SPACE	((SMB_BIG_UINT)(1))

#define SMB_QUOTAS_SET_NO_LIMIT(dp) \
{\
	(dp)->softlimit = SMB_QUOTAS_NO_LIMIT;\
	(dp)->hardlimit = SMB_QUOTAS_NO_LIMIT;\
	(dp)->isoftlimit = SMB_QUOTAS_NO_LIMIT;\
	(dp)->ihardlimit = SMB_QUOTAS_NO_LIMIT;\
}

#define SMB_QUOTAS_SET_NO_SPACE(dp) \
{\
	(dp)->softlimit = SMB_QUOTAS_NO_SPACE;\
	(dp)->hardlimit = SMB_QUOTAS_NO_SPACE;\
	(dp)->isoftlimit = SMB_QUOTAS_NO_SPACE;\
	(dp)->ihardlimit = SMB_QUOTAS_NO_SPACE;\
}

typedef struct _SMB_DISK_QUOTA {
	enum SMB_QUOTA_TYPE qtype;
	SMB_BIG_UINT bsize;
	SMB_BIG_UINT hardlimit; /* In bsize units. */
	SMB_BIG_UINT softlimit; /* In bsize units. */
	SMB_BIG_UINT curblocks; /* In bsize units. */
	SMB_BIG_UINT ihardlimit; /* inode hard limit. */
	SMB_BIG_UINT isoftlimit; /* inode soft limit. */
	SMB_BIG_UINT curinodes; /* Current used inodes. */
	uint32       qflags;
} SMB_DISK_QUOTA;

#endif /*_SYSQUOTAS_H */

/* 
   Unix SMB/CIFS implementation.
   System QUOTA function wrappers for XFS
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


#include "includes.h"

#ifdef HAVE_XFS_QUOTA
#include "samba_xfs_quota.h"
#define HAVE_LINUX_XFS_QUOTA
#endif

#ifdef HAVE_LINUX_XFS_QUOTA

/* Linux has BBSIZE in <linux/xfs_fs.h>
 * or <xfs/xfs_fs.h>
 * IRIX has BBSIZE in <sys/param.h>
 */
#ifdef HAVE_XFS_FS_HEADER
#include HAVE_XFS_FS_HEADER
#endif

/* on IRIX */
#ifndef Q_XQUOTAON
#define Q_XQUOTAON Q_QUOTAON
#endif /* Q_XQUOTAON */
#ifndef Q_XQUOTAOFF
#define Q_XQUOTAOFF Q_QUOTAOFF
#endif /* Q_XQUOTAOFF */
#ifndef Q_XGETQSTAT
#define Q_XGETQSTAT Q_GETQSTAT
#endif /* Q_XGETQSTAT */


#ifndef BBSHIFT
#define	BBSHIFT		9
#endif /* BBSHIFT */
#ifndef BBSIZE
#define	BBSIZE		(1<<BBSHIFT)
#endif /* BBSIZE */

#ifdef IRIX6
#ifndef QUOTABLOCK_SIZE
#define QUOTABLOCK_SIZE BBSIZE
#endif
#endif

/****************************************************************************
 Abstract out the XFS Quota Manager quota get call.
****************************************************************************/
int sys_get_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	uint32 qflags = 0;
	SMB_BIG_UINT bsize = (SMB_BIG_UINT)BBSIZE;
	struct fs_disk_quota D;
	struct fs_quota_stat F;
	ZERO_STRUCT(D);
	ZERO_STRUCT(F);

	if (!bdev||!dp)
		smb_panic("sys_get_xfs_quota: called with NULL pointer");
		
	ZERO_STRUCT(*dp);
	dp->qtype = qtype;
		
	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			if ((ret=quotactl(QCMD(Q_XGETQUOTA,XFS_USER_QUOTA), bdev, id.uid, (caddr_t)&D)))
				return ret;
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			if ((ret=quotactl(QCMD(Q_XGETQUOTA,XFS_GROUP_QUOTA), bdev, id.gid, (caddr_t)&D)))
				return ret;
			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:	
			quotactl(QCMD(Q_XGETQSTAT,XFS_USER_QUOTA), bdev, -1, (caddr_t)&F);

			if (F.qs_flags & XFS_QUOTA_UDQ_ENFD) {
				qflags |= QUOTAS_DENY_DISK;
			}
			else if (F.qs_flags & XFS_QUOTA_UDQ_ACCT) {
				qflags |= QUOTAS_ENABLED;
			}

			ret = 0;

			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_FS_QUOTA_TYPE:	
			quotactl(QCMD(Q_XGETQSTAT,XFS_GROUP_QUOTA), bdev, -1, (caddr_t)&F);

			if (F.qs_flags & XFS_QUOTA_UDQ_ENFD) {
				qflags |= QUOTAS_DENY_DISK;
			}
			else if (F.qs_flags & XFS_QUOTA_UDQ_ACCT) {
				qflags |= QUOTAS_ENABLED;
			}

			ret = 0;

			break;
#endif /* HAVE_GROUP_QUOTA */
		default:
			errno = ENOSYS;
			return -1;
	}

	dp->bsize = bsize;
	dp->softlimit = (SMB_BIG_UINT)D.d_blk_softlimit;
	dp->hardlimit = (SMB_BIG_UINT)D.d_blk_hardlimit;
	dp->ihardlimit = (SMB_BIG_UINT)D.d_ino_hardlimit;
	dp->isoftlimit = (SMB_BIG_UINT)D.d_ino_softlimit;
	dp->curinodes = (SMB_BIG_UINT)D.d_icount;
	dp->curblocks = (SMB_BIG_UINT)D.d_bcount;
	dp->qflags = qflags;

	return ret;
}

/****************************************************************************
 Abstract out the XFS Quota Manager quota set call.
****************************************************************************/
int sys_set_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	uint32 qflags = 0;
	SMB_BIG_UINT bsize = (SMB_BIG_UINT)BBSIZE;
	struct fs_disk_quota D;
	struct fs_quota_stat F;
	int q_on = 0;
	int q_off = 0;
	ZERO_STRUCT(D);
	ZERO_STRUCT(F);

	if (!bdev||!dp)
		smb_panic("sys_set_xfs_quota: called with NULL pointer");
	
	if (bsize == dp->bsize) {
		D.d_blk_softlimit = dp->softlimit;
		D.d_blk_hardlimit = dp->hardlimit;
		D.d_ino_hardlimit = dp->ihardlimit;
		D.d_ino_softlimit = dp->isoftlimit;
	} else {
		D.d_blk_softlimit = (dp->softlimit*dp->bsize)/bsize;
		D.d_blk_hardlimit = (dp->hardlimit*dp->bsize)/bsize;
		D.d_ino_hardlimit = (dp->ihardlimit*dp->bsize)/bsize;
		D.d_ino_softlimit = (dp->isoftlimit*dp->bsize)/bsize;		
	}

	qflags = dp->qflags;

	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			D.d_fieldmask |= FS_DQ_LIMIT_MASK;
			ret = quotactl(QCMD(Q_XSETQLIM,XFS_USER_QUOTA), bdev, id.uid, (caddr_t)&D);
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			D.d_fieldmask |= FS_DQ_LIMIT_MASK;
			ret = quotactl(QCMD(Q_XSETQLIM,XFS_GROUP_QUOTA), bdev, id.gid, (caddr_t)&D);
			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:
			quotactl(QCMD(Q_XGETQSTAT,XFS_USER_QUOTA), bdev, -1, (caddr_t)&F);
			
			if (qflags & QUOTAS_DENY_DISK) {
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ENFD))
					q_on |= XFS_QUOTA_UDQ_ENFD;
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;
				
				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,XFS_USER_QUOTA),bdev, -1, (caddr_t)&q_on);
				} else {
					ret = 0;
				}

			} else if (qflags & QUOTAS_ENABLED) {
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;

				if (q_off != 0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,XFS_USER_QUOTA),bdev, -1, (caddr_t)&q_off);
				} else {
					ret = 0;
				}

				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;

				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,XFS_USER_QUOTA),bdev, -1, (caddr_t)&q_on);
				} else {
					ret = 0;
				}
			} else {
#if 0
			/* Switch on XFS_QUOTA_UDQ_ACCT didn't work!
			 * only swittching off XFS_QUOTA_UDQ_ACCT work
			 */
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;
				if (F.qs_flags & XFS_QUOTA_UDQ_ACCT)
					q_off |= XFS_QUOTA_UDQ_ACCT;

				if (q_off !=0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,XFS_USER_QUOTA),bdev, -1, (caddr_t)&q_off);
				} else {
					ret = 0;
				}
#else
				ret = -1;
#endif
			}

			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_FS_QUOTA_TYPE:
			quotactl(QCMD(Q_XGETQSTAT,XFS_GROUP_QUOTA), bdev, -1, (caddr_t)&F);
			
			if (qflags & QUOTAS_DENY_DISK) {
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ENFD))
					q_on |= XFS_QUOTA_UDQ_ENFD;
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;
				
				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,XFS_GROUP_QUOTA),bdev, -1, (caddr_t)&q_on);
				} else {
					ret = 0;
				}

			} else if (qflags & QUOTAS_ENABLED) {
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;

				if (q_off != 0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,XFS_GROUP_QUOTA),bdev, -1, (caddr_t)&q_off);
				} else {
					ret = 0;
				}

				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;

				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,XFS_GROUP_QUOTA),bdev, -1, (caddr_t)&q_on);
				} else {
					ret = 0;
				}
			} else {
#if 0
			/* Switch on XFS_QUOTA_UDQ_ACCT didn't work!
			 * only swittching off XFS_QUOTA_UDQ_ACCT work
			 */
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;
				if (F.qs_flags & XFS_QUOTA_UDQ_ACCT)
					q_off |= XFS_QUOTA_UDQ_ACCT;

				if (q_off !=0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,XFS_GROUP_QUOTA),bdev, -1, (caddr_t)&q_off);
				} else {
					ret = 0;
				}
#else
				ret = -1;
#endif
			}

			break;
#endif /* HAVE_GROUP_QUOTA */
		default:
			errno = ENOSYS;
			return -1;
	}

	return ret;
}

#endif /* HAVE_LINUX_XFS_QUOTA */

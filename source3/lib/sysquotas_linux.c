/* 
   Unix SMB/CIFS implementation.
   System QUOTA function wrappers for LINUX
   Copyright (C) Stefan (metze) Metzmacher	2003
   
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


#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

#ifndef HAVE_SYS_QUOTAS
#ifdef HAVE_QUOTACTL_LINUX
#undef HAVE_QUOTACTL_LINUX
#endif
#endif

#ifdef HAVE_QUOTACTL_LINUX

#include <sys/quota.h>

/****************************************************************************
 Linux quota get calls.
****************************************************************************/
int sys_get_vfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	uint32_t qflags = 0;
	struct dqblk D;
	uint64_t bsize = (uint64_t)QUOTABLOCK_SIZE;

	if (!path || !bdev || !dp) {
		smb_panic("sys_get_vfs_quota: called with NULL pointer");
	}

	ZERO_STRUCT(*dp);
	dp->qtype = qtype;

	ZERO_STRUCT(D);

	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			DEBUG(10, ("sys_get_vfs_quota: path[%s] bdev[%s] "
				   "SMB_USER_QUOTA_TYPE uid[%u]\n",
				   path, bdev, (unsigned)id.uid));

			if ((ret = quotactl(QCMD(Q_GETQUOTA, USRQUOTA), bdev,
					    id.uid, (caddr_t)&D))) {
				return ret;
			}

			break;
		case SMB_GROUP_QUOTA_TYPE:
			DEBUG(10, ("sys_get_vfs_quota: path[%s] bdev[%s] "
				   "SMB_GROUP_QUOTA_TYPE gid[%u]\n",
				   path, bdev, (unsigned)id.gid));

			if ((ret = quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), bdev,
					    id.gid, (caddr_t)&D))) {
				return ret;
			}

			break;
		case SMB_USER_FS_QUOTA_TYPE:
			DEBUG(10, ("sys_get_vfs_quota: path[%s] bdev[%s] "
				   "SMB_USER_FS_QUOTA_TYPE (uid[%u])\n",
				   path, bdev, (unsigned)geteuid()));

			if ((ret = quotactl(QCMD(Q_GETQUOTA, USRQUOTA), bdev,
					    geteuid(), (caddr_t)&D)) == 0) {
				qflags |= QUOTAS_DENY_DISK;
			}

			ret = 0;

			break;
		case SMB_GROUP_FS_QUOTA_TYPE:
			DEBUG(10, ("sys_get_vfs_quota: path[%s] bdev[%s] "
				   "SMB_GROUP_FS_QUOTA_TYPE (gid[%u])\n",
				   path, bdev, (unsigned)getegid()));

			if ((ret = quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), bdev,
					    getegid(), (caddr_t)&D)) == 0) {
				qflags |= QUOTAS_DENY_DISK;
			}

			ret = 0;
			break;
		default:
			errno = ENOSYS;
			return -1;
	}

	dp->bsize = bsize;
	dp->softlimit = (uint64_t)D.dqb_bsoftlimit;
	dp->hardlimit = (uint64_t)D.dqb_bhardlimit;
	dp->ihardlimit = (uint64_t)D.dqb_ihardlimit;
	dp->isoftlimit = (uint64_t)D.dqb_isoftlimit;
	dp->curinodes = (uint64_t)D.dqb_curinodes;
	dp->curblocks = (uint64_t)D.dqb_curspace/bsize;


	dp->qflags = qflags;

	return ret;
}

/****************************************************************************
 Linux quota set calls.
****************************************************************************/
int sys_set_vfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	struct dqblk D;
	uint64_t bsize = (uint64_t)QUOTABLOCK_SIZE;
	bool cur_enf, new_enf;

	if (!path || !bdev || !dp) {
		smb_panic("sys_set_vfs_quota: called with NULL pointer");
	}

	ZERO_STRUCT(D);

	if (bsize == dp->bsize) {
		D.dqb_bsoftlimit = dp->softlimit;
		D.dqb_bhardlimit = dp->hardlimit;
	} else {
		D.dqb_bsoftlimit = (dp->softlimit*dp->bsize)/bsize;
		D.dqb_bhardlimit = (dp->hardlimit*dp->bsize)/bsize;
	}
	D.dqb_ihardlimit = dp->ihardlimit;
	D.dqb_isoftlimit = dp->isoftlimit;
	D.dqb_valid = QIF_LIMITS;

	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			DEBUG(10, ("sys_set_vfs_quota: path[%s] bdev[%s] "
				   "SMB_USER_QUOTA_TYPE uid[%u]\n",
				   path, bdev, (unsigned)id.uid));

			ret = quotactl(QCMD(Q_SETQUOTA,USRQUOTA), bdev, id.uid, (caddr_t)&D);
			break;
		case SMB_GROUP_QUOTA_TYPE:
			DEBUG(10, ("sys_set_vfs_quota: path[%s] bdev[%s] "
				   "SMB_GROUP_QUOTA_TYPE gid[%u]\n",
				   path, bdev, (unsigned)id.gid));

			ret = quotactl(QCMD(Q_SETQUOTA,GRPQUOTA), bdev, id.gid, (caddr_t)&D);
			break;
		case SMB_USER_FS_QUOTA_TYPE:
			DEBUG(10, ("sys_set_vfs_quota: path[%s] bdev[%s] "
				   "SMB_USER_FS_QUOTA_TYPE (uid[%u])\n",
				   path, bdev, (unsigned)geteuid()));

			ret = quotactl(QCMD(Q_GETQUOTA, USRQUOTA), bdev,
				       geteuid(), (caddr_t)&D);
			cur_enf = (ret == 0);
			new_enf = ((dp->qflags & QUOTAS_DENY_DISK) != 0);
			/* We're not changing quota enforcement, so return
			 * success
			 * IFF the wanted state is identical to the current
			 * state */
			if (cur_enf == new_enf) {
				ret = 0;
			} else {
				errno = EPERM;
				ret = -1;
			}

			break;
		case SMB_GROUP_FS_QUOTA_TYPE:
			DEBUG(10, ("sys_set_vfs_quota: path[%s] bdev[%s] "
				   "SMB_GROUP_FS_QUOTA_TYPE (gid[%u])\n",
				   path, bdev, (unsigned)getegid()));

			ret = quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), bdev,
				       getegid(), (caddr_t)&D);
			cur_enf = (ret == 0);
			new_enf = ((dp->qflags & QUOTAS_DENY_DISK) != 0);
			/* We're not changing quota enforcement, so return
			 * success
			 * IFF the wanted state is identical to the current
			 * state */
			if (cur_enf == new_enf) {
				ret = 0;
			} else {
				errno = EPERM;
				ret = -1;
			}

			break;
		default:
			errno = ENOSYS;
			return -1;
	}

	return ret;
}

#else /* HAVE_QUOTACTL_LINUX */
 void dummy_sysquotas_linux(void);

 void dummy_sysquotas_linux(void){}
#endif /* HAVE_QUOTACTL_LINUX */

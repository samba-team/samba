/*
 * Unix SMB/CIFS implementation.
 * System QUOTA function wrappers for QUOTACTL_4B

 * Copyright (C) 2011 James Peach.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

#ifndef HAVE_SYS_QUOTAS
#undef HAVE_QUOTACTL_4B
#endif

#ifdef HAVE_QUOTACTL_4B
/* int quotactl(const char *path, int cmd, int id, char *addr)
 *
 * This is used by many (all?) BSD-derived systems. This implementation has
 * been developed and tested on Darwin, but may also work on other BSD systems.
 */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_QUOTA_H
#include <sys/quota.h>
#endif

#ifdef HAVE_UFS_UFS_QUOTA_H
#include <ufs/ufs/quota.h>
#endif

#ifdef HAVE_JFS_QUOTA_H
#include <jfs/quota.h>
#endif

#if defined(DARWINOS)
/* WorkARound broken HFS access checks in hfs_quotactl. Darwin only(?) */
#define HFS_QUOTACTL_WAR 1
#endif

#ifdef HAVE_STRUCT_DQBLK_DQB_CURBYTES
/* we handle the byte vs. block count dynamically via QUOTABLOCK_SIZE 1 */
#define dqb_curblocks dqb_curbytes
#endif

static void xlate_qblk_to_smb(const struct dqblk * const qblk,
			SMB_DISK_QUOTA *dp)
{
	ZERO_STRUCTP(dp);

	DEBUG(10, ("unix softlimit=%u hardlimit=%u curblock=%u\n",
	    (unsigned)qblk->dqb_bsoftlimit, (unsigned)qblk->dqb_bhardlimit,
	    (unsigned)qblk->dqb_curblocks));

	DEBUGADD(10, ("unix softinodes=%u hardinodes=%u curinodes=%u\n",
	    (unsigned)qblk->dqb_isoftlimit, (unsigned)qblk->dqb_ihardlimit,
	    (unsigned)qblk->dqb_curinodes));

	dp->bsize = QUOTABLOCK_SIZE;

	dp->softlimit = qblk->dqb_bsoftlimit;
	dp->hardlimit = qblk->dqb_bhardlimit;
	dp->curblocks = qblk->dqb_curblocks;
/* our Darwin quotas used to never return 0byte usage but this is probably not needed,
 * let's comment this out for now
#ifdef HAVE_STRUCT_DQBLK_DQB_CURBYTES
	if (dp->curblocks == 0) {
		dp->curblocks = 1;
	}
#endif
 */

	dp->ihardlimit = qblk->dqb_ihardlimit;
	dp->isoftlimit = qblk->dqb_isoftlimit;
	dp->curinodes = qblk->dqb_curinodes;

	dp->qflags = QUOTAS_ENABLED | QUOTAS_DENY_DISK;

	DEBUG(10, ("softlimit=%u hardlimit=%u curblock=%u\n",
	    (unsigned)dp->softlimit, (unsigned)dp->hardlimit,
	    (unsigned)dp->curblocks));

	DEBUGADD(10, ("softinodes=%u hardinodes=%u curinodes=%u\n",
	    (unsigned)dp->isoftlimit, (unsigned)dp->ihardlimit,
	    (unsigned)dp->curinodes));

}

static void xlate_smb_to_qblk(const SMB_DISK_QUOTA * const dp,
			struct dqblk *qblk)
{
	ZERO_STRUCTP(qblk);

	if (dp->bsize == QUOTABLOCK_SIZE) {
		qblk->dqb_bsoftlimit = dp->softlimit;
		qblk->dqb_bhardlimit = dp->hardlimit;
	} else {
		qblk->dqb_bsoftlimit = dp->softlimit * dp->bsize / QUOTABLOCK_SIZE;
		qblk->dqb_bhardlimit = dp->hardlimit * dp->bsize / QUOTABLOCK_SIZE;
	}
	qblk->dqb_ihardlimit = dp->ihardlimit;
	qblk->dqb_isoftlimit = dp->isoftlimit;
}

static int sys_quotactl_4B(const char * path, int cmd,
		int id, struct dqblk *qblk)
{
	int ret;

	/* NB: We must test GRPQUOTA here, because USRQUOTA is 0. */
	DEBUG(10, ("%s quota for %s ID %u on %s\n",
		    (cmd & QCMD(Q_GETQUOTA, 0)) ? "getting" : "setting",
		    (cmd & QCMD(0, GRPQUOTA)) ? "group" : "user",
		    (unsigned)id, path));

#ifdef HFS_QUOTACTL_WAR
	become_root();
#endif  /* HFS_QUOTACTL_WAR */

	ret = quotactl(path, cmd, id, qblk);
	if (ret == -1) {
		/* ENOTSUP means quota support is not compiled in. EINVAL
		 * means that quotas are not configured (commonly).
		 */
		if (errno != ENOTSUP && errno != EINVAL) {
			DEBUG(5, ("failed to %s quota for %s ID %u on %s: %s\n",
				    (cmd & QCMD(Q_GETQUOTA, 0)) ? "get" : "set",
				    (cmd & QCMD(0, GRPQUOTA)) ? "group" : "user",
				    (unsigned)id, path, strerror(errno)));
		}

#ifdef HFS_QUOTACTL_WAR
		unbecome_root();
#endif  /* HFS_QUOTACTL_WAR */


		return -1;
	}

#ifdef HFS_QUOTACTL_WAR
		unbecome_root();
#endif  /* HFS_QUOTACTL_WAR */

	return 0;
}

int sys_get_vfs_quota(const char *path, const char *bdev,
	enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret;
	struct dqblk qblk;

	ZERO_STRUCT(qblk);

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
		/* Get quota for provided UID. */
		ret = sys_quotactl_4B(path, QCMD(Q_GETQUOTA, USRQUOTA),
					id.uid, &qblk);
		break;
	case SMB_USER_FS_QUOTA_TYPE:
		/* Get quota for current UID. */
		ret = sys_quotactl_4B(path, QCMD(Q_GETQUOTA, USRQUOTA),
					geteuid(), &qblk);
		break;
	case SMB_GROUP_QUOTA_TYPE:
		/* Get quota for provided GID. */
		ret = sys_quotactl_4B(path, QCMD(Q_GETQUOTA, GRPQUOTA),
					id.gid, &qblk);
		break;
	case SMB_GROUP_FS_QUOTA_TYPE:
		/* Get quota for current GID. */
		ret = sys_quotactl_4B(path, QCMD(Q_GETQUOTA, GRPQUOTA),
					getegid(), &qblk);
		break;
	default:
		DEBUG(0, ("cannot get unsupported quota type: %u\n",
			    (unsigned)qtype));
		errno = ENOSYS;
		return -1;
	}

	if (ret == -1) {
		return -1;
	}

	xlate_qblk_to_smb(&qblk, dp);
	dp->qtype = qtype;

	return ret;
}

int sys_set_vfs_quota(const char *path, const char *bdev,
	enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	struct dqblk qblk;

	xlate_smb_to_qblk(dp, &qblk);

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
		/* Set quota for provided UID. */
		return sys_quotactl_4B(path, QCMD(Q_SETQUOTA, USRQUOTA),
					id.uid, &qblk);
	case SMB_USER_FS_QUOTA_TYPE:
		/* Set quota for current UID. */
		return sys_quotactl_4B(path, QCMD(Q_SETQUOTA, USRQUOTA),
					geteuid(), &qblk);
	case SMB_GROUP_QUOTA_TYPE:
		/* Set quota for provided GID. */
		return sys_quotactl_4B(path, QCMD(Q_SETQUOTA, GRPQUOTA),
					id.gid, &qblk);
	case SMB_GROUP_FS_QUOTA_TYPE:
		/* Set quota for current GID. */
		return sys_quotactl_4B(path, QCMD(Q_SETQUOTA, GRPQUOTA),
					getegid(), &qblk);
	default:
		DEBUG(0, ("cannot set unsupported quota type: %u\n",
			    (unsigned)qtype));
		errno = ENOSYS;
		return -1;
	}
}

#endif /* HAVE_QUOTACTL_4B */

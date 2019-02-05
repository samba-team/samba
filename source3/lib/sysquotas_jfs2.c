/*
 * Unix SMB/CIFS implementation.
 * System QUOTA function wrappers for JFS2 on AIX

 * Copyright (C) 2019 Bjoern Jacke
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

#if defined(HAVE_JFS_QUOTA_H)
#include <jfs/quota.h>

#if defined(Q_J2GETQUOTA) /* when have JFS2 */

/* int quotactl(const char *path, int cmd, int id, char *addr)
 *
 * This is very similar to sysquotas_4B but JFS2 has different quota cmds
 * (why?) and for some reason wants root even for querying your own quota,
 * which seems to be an AIX bug because the docs say root is only
 * required for querying other users' quota
 */


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_JFS_QUOTA_H
#include <jfs/quota.h>
#endif


static int sys_quotactl_JFS2(const char * path, int cmd,
		int id, quota64_t *quota)
{
	int ret;

	/* NB: We must test GRPQUOTA here, because USRQUOTA is 0. */
	DEBUG(10, ("%s quota for %s ID %u on %s\n",
		    (cmd & QCMD(Q_J2GETQUOTA, 0)) ? "getting" : "setting",
		    (cmd & QCMD(0, GRPQUOTA)) ? "group" : "user",
		    (unsigned)id, path));

	become_root();

	ret = quotactl((char *) path, cmd, id, (char *) quota);
	if (ret == -1) {
		/* ENOTSUP means quota support is not compiled in. EINVAL
		 * means that quotas are not configured (commonly).
		 */
		if (errno != ENOTSUP && errno != EINVAL) {
			DEBUG(0, ("failed to %s quota for %s ID %u on %s: %s\n",
				    (cmd & QCMD(Q_J2GETQUOTA, 0)) ? "get" : "set",
				    (cmd & QCMD(0, GRPQUOTA)) ? "group" : "user",
				    (unsigned)id, path, strerror(errno)));
		}
	}

	unbecome_root();

	return ret;
}


int sys_get_jfs2_quota(const char *path, const char *bdev,
	enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret;
	quota64_t quota;

	ZERO_STRUCT(quota);

	switch (qtype) {
	case SMB_USER_QUOTA_TYPE:
		/* Get quota for provided UID. */
		ret = sys_quotactl_JFS2(path, QCMD(Q_J2GETQUOTA, USRQUOTA),
					id.uid, &quota);
		break;
	case SMB_USER_FS_QUOTA_TYPE:
		/* Get quota for current UID. */
		ret = sys_quotactl_JFS2(path, QCMD(Q_J2GETQUOTA, USRQUOTA),
					geteuid(), &quota);
		break;
	case SMB_GROUP_QUOTA_TYPE:
		/* Get quota for provided GID. */
		ret = sys_quotactl_JFS2(path, QCMD(Q_J2GETQUOTA, GRPQUOTA),
					id.gid, &quota);
		break;
	case SMB_GROUP_FS_QUOTA_TYPE:
		/* Get quota for current GID. */
		ret = sys_quotactl_JFS2(path, QCMD(Q_J2GETQUOTA, GRPQUOTA),
					getegid(), &quota);
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

	dp->softlimit = quota.bsoft;
	dp->hardlimit = quota.bhard;
	dp->ihardlimit = quota.ihard;
	dp->isoftlimit = quota.isoft;
	dp->curinodes = quota.iused;
	dp->curblocks = quota.bused;

	dp->qflags = QUOTAS_ENABLED | QUOTAS_DENY_DISK;
	dp->qtype = qtype;
	dp->bsize = QUOTABLOCK_SIZE;

	return ret;
}

int sys_set_jfs2_quota(const char *path, const char *bdev,
	enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	/* JFS2 supports fancy quota limit classes for setting user quota.
	 * Unfortunately, this makes them quite unmanagable for Samba.
	 */
	DEBUG(1, ("cannot set quota on JFS2!\n"));
	errno = ENOSYS;
	return -1;
}


#endif /* JFS2 */
#endif /* AIX quotas */

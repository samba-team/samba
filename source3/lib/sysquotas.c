/* 
   Unix SMB/CIFS implementation.
   System QUOTA function wrappers
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


#ifndef AUTOCONF_TEST

#include "includes.h"

#ifdef HAVE_SYS_QUOTAS

#if defined(HAVE_QUOTACTL_4A) 
/* long quotactl(int cmd, char *special, qid_t id, caddr_t addr) */
/* this is used by: linux,HPUX,IRIX */

/****************************************************************************
 Abstract out the old and new Linux quota get calls.
****************************************************************************/
static int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	uint32 qflags = 0;
	struct SYS_DQBLK D;
	SMB_BIG_UINT bsize = (SMB_BIG_UINT)QUOTABLOCK_SIZE;

	if (!path||!bdev||!dp)
		smb_panic("sys_get_vfs_quota: called with NULL pointer");

	ZERO_STRUCT(D);
	ZERO_STRUCT(*dp);
	dp->qtype = qtype;

	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			if ((ret = quotactl(QCMD(Q_GETQUOTA,USRQUOTA), bdev, id.uid, (CADDR_T)&D))) {
				return ret;
			}

			if ((D.dqb_curblocks==0)&&
				(D.dqb_bsoftlimit==0)&&
				(D.dqb_bhardlimit==0)) {
				/* the upper layer functions don't want empty quota records...*/
				return -1;
			}

			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			if ((ret = quotactl(QCMD(Q_GETQUOTA,GRPQUOTA), bdev, id.gid, (CADDR_T)&D))) {
				return ret;
			}

			if ((D.dqb_curblocks==0)&&
				(D.dqb_bsoftlimit==0)&&
				(D.dqb_bhardlimit==0)) {
				/* the upper layer functions don't want empty quota records...*/
				return -1;
			}

			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:
			id.uid = getuid();

			if ((ret = quotactl(QCMD(Q_GETQUOTA,USRQUOTA), bdev, id.uid, (CADDR_T)&D))==0) {
				qflags |= QUOTAS_DENY_DISK;
			}

			ret = 0;
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_FS_QUOTA_TYPE:
			id.gid = getgid();

			if ((ret = quotactl(QCMD(Q_GETQUOTA,GRPQUOTA), bdev, id.gid, (CADDR_T)&D))==0) {
				qflags |= QUOTAS_DENY_DISK;
			}

			ret = 0;
			break;
#endif /* HAVE_GROUP_QUOTA */
		default:
			errno = ENOSYS;
			return -1;
	}

	dp->bsize = bsize;
	dp->softlimit = (SMB_BIG_UINT)D.dqb_bsoftlimit;
	dp->hardlimit = (SMB_BIG_UINT)D.dqb_bhardlimit;
	dp->ihardlimit = (SMB_BIG_UINT)D.dqb_ihardlimit;
	dp->isoftlimit = (SMB_BIG_UINT)D.dqb_isoftlimit;
	dp->curinodes = (SMB_BIG_UINT)D.dqb_curinodes;
	dp->curblocks = (SMB_BIG_UINT)D.dqb_curblocks;


	dp->qflags = qflags;

	return ret;
}

/****************************************************************************
 Abstract out the old and new Linux quota set calls.
****************************************************************************/

static int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	uint32 qflags = 0;
	uint32 oldqflags = 0;
	struct SYS_DQBLK D;
	SMB_BIG_UINT bsize = (SMB_BIG_UINT)QUOTABLOCK_SIZE;

	if (!path||!bdev||!dp)
		smb_panic("sys_set_vfs_quota: called with NULL pointer");

	ZERO_STRUCT(D);

	if (bsize == dp->bsize) {
		D.dqb_bsoftlimit = dp->softlimit;
		D.dqb_bhardlimit = dp->hardlimit;
		D.dqb_ihardlimit = dp->ihardlimit;
		D.dqb_isoftlimit = dp->isoftlimit;
	} else {
		D.dqb_bsoftlimit = (dp->softlimit*dp->bsize)/bsize;
		D.dqb_bhardlimit = (dp->hardlimit*dp->bsize)/bsize;
		D.dqb_ihardlimit = (dp->ihardlimit*dp->bsize)/bsize;
		D.dqb_isoftlimit = (dp->isoftlimit*dp->bsize)/bsize;
	}

	qflags = dp->qflags;

	switch (qtype) {
		case SMB_USER_QUOTA_TYPE:
			ret = quotactl(QCMD(Q_SETQLIM,USRQUOTA), bdev, id.uid, (CADDR_T)&D);
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			ret = quotactl(QCMD(Q_SETQLIM,GRPQUOTA), bdev, id.gid, (CADDR_T)&D);
			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:
			/* this stuff didn't work as it should:
			 * switching on/off quota via quotactl()
			 * didn't work!
			 * So we just return 0
			 * --metze
			 * 
			 * On HPUX we didn't have the mount path,
			 * we need to fix sys_path_to_bdev()
			 *
			 */
#if 0
			id.uid = getuid();

			ret = quotactl(QCMD(Q_GETQUOTA,USRQUOTA), bdev, id.uid, (CADDR_T)&D);

			if ((qflags&QUOTAS_DENY_DISK)||(qflags&QUOTAS_ENABLED)) {
				if (ret == 0) {
					char *quota_file = NULL;
					
					asprintf(&quota_file,"/%s/%s%s",path, QUOTAFILENAME,USERQUOTAFILE_EXTENSION);
					if (quota_file == NULL) {
						DEBUG(0,("asprintf() failed!\n"));
						errno = ENOMEM;
						return -1;
					}
					
					ret = quotactl(QCMD(Q_QUOTAON,USRQUOTA), bdev, -1,(CADDR_T)quota_file);
				} else {
					ret = 0;	
				}
			} else {
				if (ret != 0) {
					/* turn off */
					ret = quotactl(QCMD(Q_QUOTAOFF,USRQUOTA), bdev, -1, (CADDR_T)0);	
				} else {
					ret = 0;
				}		
			}

			DEBUG(0,("vfs_fs_quota: ret(%d) errno(%d)[%s] uid(%d) bdev[%s]\n",
				ret,errno,strerror(errno),id.uid,bdev));
#else
			id.uid = getuid();

			if ((ret = quotactl(QCMD(Q_GETQUOTA,USRQUOTA), bdev, id.uid, (CADDR_T)&D))==0) {
				oldqflags |= QUOTAS_DENY_DISK;
			}

			if (oldqflags == qflags) {
				ret = 0;
			} else {
				ret = -1;
			}
#endif
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_FS_QUOTA_TYPE:
			/* this stuff didn't work as it should:
			 * switching on/off quota via quotactl()
			 * didn't work!
			 * So we just return 0
			 * --metze
			 * 
			 * On HPUX we didn't have the mount path,
			 * we need to fix sys_path_to_bdev()
			 *
			 */
#if 0
			id.gid = getgid();

			ret = quotactl(QCMD(Q_GETQUOTA,GRPQUOTA), bdev, id, (CADDR_T)&D);

			if ((qflags&QUOTAS_DENY_DISK)||(qflags&QUOTAS_ENABLED)) {
				if (ret == 0) {
					char *quota_file = NULL;
					
					asprintf(&quota_file,"/%s/%s%s",path, QUOTAFILENAME,GROUPQUOTAFILE_EXTENSION);
					if (quota_file == NULL) {
						DEBUG(0,("asprintf() failed!\n"));
						errno = ENOMEM;
						return -1;
					}
					
					ret = quotactl(QCMD(Q_QUOTAON,GRPQUOTA), bdev, -1,(CADDR_T)quota_file);
				} else {
					ret = 0;	
				}
			} else {
				if (ret != 0) {
					/* turn off */
					ret = quotactl(QCMD(Q_QUOTAOFF,GRPQUOTA), bdev, -1, (CADDR_T)0);	
				} else {
					ret = 0;
				}		
			}

			DEBUG(0,("vfs_fs_quota: ret(%d) errno(%d)[%s] uid(%d) bdev[%s]\n",
				ret,errno,strerror(errno),id.gid,bdev));
#else
			id.gid = getgid();

			if ((ret = quotactl(QCMD(Q_GETQUOTA,GRPQUOTA), bdev, id.gid, (CADDR_T)&D))==0) {
				oldqflags |= QUOTAS_DENY_DISK;
			}

			if (oldqflags == qflags) {
				ret = 0;
			} else {
				ret = -1;
			}
#endif
			break;
#endif /* HAVE_GROUP_QUOTA */
		default:
			errno = ENOSYS;
			return -1;
	}

	return ret;
}

/*#endif HAVE_QUOTACTL_4A */
#elif defined(HAVE_QUOTACTL_4B)

#error HAVE_QUOTACTL_4B not implemeted

/*#endif HAVE_QUOTACTL_4B */
#elif defined(HAVE_QUOTACTL_3)

#error HAVE_QUOTACTL_3 not implemented

/* #endif  HAVE_QUOTACTL_3 */
#else /* NO_QUOTACTL_USED */

static int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;

	if (!path||!bdev||!dp)
		smb_panic("sys_get_vfs_quota: called with NULL pointer");
		
	errno = ENOSYS;

	return ret;
}

static int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;

	if (!path||!bdev||!dp)
		smb_panic("sys_set_vfs_quota: called with NULL pointer");

	errno = ENOSYS;

	return ret;
}

#endif /* NO_QUOTACTL_USED */

#ifdef HAVE_MNTENT
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;
	SMB_STRUCT_STAT S;
	FILE *fp;
	struct mntent *mnt;
	SMB_DEV_T devno;

	/* find the block device file */

	if (!path||!mntpath||!bdev||!fs)
		smb_panic("sys_path_to_bdev: called with NULL pointer");

	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;
	
	if ( sys_stat(path, &S) == -1 )
		return (-1);

	devno = S.st_dev ;

	fp = setmntent(MOUNTED,"r");
  
	while ((mnt = getmntent(fp))) {
		if ( sys_stat(mnt->mnt_dir,&S) == -1 )
			continue ;

		if (S.st_dev == devno) {
			(*mntpath) = strdup(mnt->mnt_dir);
			(*bdev) = strdup(mnt->mnt_fsname);
			(*fs)   = strdup(mnt->mnt_type);
			if ((*mntpath)&&(*bdev)&&(*fs)) {
				ret = 0;
			} else {
				SAFE_FREE(*mntpath);
				SAFE_FREE(*bdev);
				SAFE_FREE(*fs);
				ret = -1;
			}

			break;
		}
	}

	endmntent(fp) ;

	return ret;
}
/* #endif HAVE_MNTENT */
#elif defined(HAVE_DEVNM)

/* we have this on HPUX, ... */
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;
	char dev_disk[256];
	SMB_STRUCT_STAT S;

	if (!path||!mntpath||!bdev||!fs)
		smb_panic("sys_path_to_bdev: called with NULL pointer");

	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;
	
	/* find the block device file */

	if ((ret=sys_stat(path, &S))!=0) {
		return ret;
	}
	
	if ((ret=devnm(S_IFBLK, S.st_dev, dev_disk, 256, 1))!=0) {
		return ret;	
	}

	/* we should get the mntpath right...
	 * but I don't know how
	 * --metze
	 */
	(*mntpath) = strdup(path);
	(*bdev) = strdup(dev_disk);
	if ((*mntpath)&&(*bdev)) {
		ret = 0;
	} else {
		SAFE_FREE(*mntpath);
		SAFE_FREE(*bdev);
		ret = -1;
	}	
	
	
	return ret;	
}

/* #endif HAVE_DEVNM */
#else
/* we should fake this up...*/
static int sys_path_to_bdev(const char *path, char **mntpath, char **bdev, char **fs)
{
	int ret = -1;

	if (!path||!mntpath||!bdev||!fs)
		smb_panic("sys_path_to_bdev: called with NULL pointer");

	(*mntpath) = NULL;
	(*bdev) = NULL;
	(*fs) = NULL;
	
	(*mntpath) = strdup(path);
	if (*mntpath) {
		ret = 0;
	} else {
		SAFE_FREE(*mntpath);
		ret = -1;
	}

	return ret;
}
#endif


/*********************************************************
 if we have XFS QUOTAS we should use them
 *********************************************************/
#ifdef HAVE_XFS_QUOTA
/****************************************************************************
 Abstract out the XFS Quota Manager quota get call.
****************************************************************************/
static int sys_get_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
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
			if ((ret=quotactl(QCMD(Q_XGETQUOTA,USRQUOTA), bdev, id.uid, (CADDR_T)&D)))
				return ret;
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			if ((ret=quotactl(QCMD(Q_XGETQUOTA,GRPQUOTA), bdev, id.gid, (CADDR_T)&D)))
				return ret;
			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:	
			quotactl(QCMD(Q_XGETQSTAT,USRQUOTA), bdev, -1, (CADDR_T)&F);

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
			quotactl(QCMD(Q_XGETQSTAT,GRPQUOTA), bdev, -1, (CADDR_T)&F);

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
static int sys_set_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
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
			ret = quotactl(QCMD(Q_XSETQLIM,USRQUOTA), bdev, id.uid, (CADDR_T)&D);
			break;
#ifdef HAVE_GROUP_QUOTA
		case SMB_GROUP_QUOTA_TYPE:
			D.d_fieldmask |= FS_DQ_LIMIT_MASK;
			ret = quotactl(QCMD(Q_XSETQLIM,GRPQUOTA), bdev, id.gid, (CADDR_T)&D);
			break;
#endif /* HAVE_GROUP_QUOTA */
		case SMB_USER_FS_QUOTA_TYPE:
			quotactl(QCMD(Q_XGETQSTAT,USRQUOTA), bdev, -1, (CADDR_T)&F);
			
			if (qflags & QUOTAS_DENY_DISK) {
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ENFD))
					q_on |= XFS_QUOTA_UDQ_ENFD;
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;
				
				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,USRQUOTA),bdev, -1, (CADDR_T)&q_on);
				} else {
					ret = 0;
				}

			} else if (qflags & QUOTAS_ENABLED) {
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;

				if (q_off != 0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,USRQUOTA),bdev, -1, (CADDR_T)&q_off);
				} else {
					ret = 0;
				}

				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;

				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,USRQUOTA),bdev, -1, (CADDR_T)&q_on);
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
					ret = quotactl(QCMD(Q_XQUOTAOFF,USRQUOTA),bdev, -1, (CADDR_T)&q_off);
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
			quotactl(QCMD(Q_XGETQSTAT,GRPQUOTA), bdev, -1, (CADDR_T)&F);
			
			if (qflags & QUOTAS_DENY_DISK) {
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ENFD))
					q_on |= XFS_QUOTA_UDQ_ENFD;
				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;
				
				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,GRPQUOTA),bdev, -1, (CADDR_T)&q_on);
				} else {
					ret = 0;
				}

			} else if (qflags & QUOTAS_ENABLED) {
				if (F.qs_flags & XFS_QUOTA_UDQ_ENFD)
					q_off |= XFS_QUOTA_UDQ_ENFD;

				if (q_off != 0) {
					ret = quotactl(QCMD(Q_XQUOTAOFF,GRPQUOTA),bdev, -1, (CADDR_T)&q_off);
				} else {
					ret = 0;
				}

				if (!(F.qs_flags & XFS_QUOTA_UDQ_ACCT))
					q_on |= XFS_QUOTA_UDQ_ACCT;

				if (q_on != 0) {
					ret = quotactl(QCMD(Q_XQUOTAON,GRPQUOTA),bdev, -1, (CADDR_T)&q_on);
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
					ret = quotactl(QCMD(Q_XQUOTAOFF,GRPQUOTA),bdev, -1, (CADDR_T)&q_off);
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
#endif /* HAVE_XFS_QUOTA */















/*********************************************************************
 Now the list of all filesystem specific quota systems we have found
**********************************************************************/
static struct {
	const char *name;
	int (*get_quota)(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
	int (*set_quota)(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
} sys_quota_backends[] = {
#ifdef HAVE_XFS_QUOTA
	{"xfs", sys_get_xfs_quota, 	sys_set_xfs_quota},
#endif /* HAVE_XFS_QUOTA */
	{NULL, 	NULL, 			NULL}	
};

static int command_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	const char *get_quota_command;
	
	get_quota_command = lp_get_quota_command();
	if (get_quota_command && *get_quota_command) {
		const char *p;
		char *p2;
		char **lines;
		pstring syscmd;
		int _id = -1;

		switch(qtype) {
			case SMB_USER_QUOTA_TYPE:
			case SMB_USER_FS_QUOTA_TYPE:
				_id = id.uid;
				break;
			case SMB_GROUP_QUOTA_TYPE:
			case SMB_GROUP_FS_QUOTA_TYPE:
				_id = id.gid;
				break;
			default:
				DEBUG(0,("invalid quota type.\n"));
				return -1;
		}

		slprintf(syscmd, sizeof(syscmd)-1, 
			"%s \"%s\" %d %d", 
			get_quota_command, path, qtype, _id);

		DEBUG (3, ("get_quota: Running command %s\n", syscmd));

		lines = file_lines_pload(syscmd, NULL);
		if (lines) {
			char *line = lines[0];

			DEBUG (3, ("Read output from get_quota, \"r%s\"\n", line));

			/* we need to deal with long long unsigned here, if supported */

			dp->qflags = (enum SMB_QUOTA_TYPE)strtoul(line, &p2, 10);
			p = p2;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->curblocks = STR_TO_SMB_BIG_UINT(p, &p);
			else 
				goto invalid_param;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->softlimit = STR_TO_SMB_BIG_UINT(p, &p);
			else
				goto invalid_param;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->hardlimit = STR_TO_SMB_BIG_UINT(p, &p);
			else 
				goto invalid_param;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->curinodes = STR_TO_SMB_BIG_UINT(p, &p);
			else
				goto invalid_param;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->isoftlimit = STR_TO_SMB_BIG_UINT(p, &p);
			else
				goto invalid_param;
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->ihardlimit = STR_TO_SMB_BIG_UINT(p, &p);
			else
				goto invalid_param;	
			while (p && *p && isspace(*p))
				p++;
			if (p && *p)
				dp->bsize = STR_TO_SMB_BIG_UINT(p, NULL);
			else
				dp->bsize = 1024;
			file_lines_free(lines);
			DEBUG (3, ("Parsed output of get_quota, ...\n"));

#ifdef LARGE_SMB_OFF_T
			DEBUGADD (5,( 
				"qflags:%u curblocks:%llu softlimit:%llu hardlimit:%llu\n"
				"curinodes:%llu isoftlimit:%llu ihardlimit:%llu bsize:%llu\n", 
				dp->qflags,(long long unsigned)dp->curblocks,
				(long long unsigned)dp->softlimit,(long long unsigned)dp->hardlimit,
				(long long unsigned)dp->curinodes,
				(long long unsigned)dp->isoftlimit,(long long unsigned)dp->ihardlimit,
				(long long unsigned)dp->bsize));
#else /* LARGE_SMB_OFF_T */
			DEBUGADD (5,( 
				"qflags:%u curblocks:%lu softlimit:%lu hardlimit:%lu\n"
				"curinodes:%lu isoftlimit:%lu ihardlimit:%lu bsize:%lu\n", 
				dp->qflags,(long unsigned)dp->curblocks,
				(long unsigned)dp->softlimit,(long unsigned)dp->hardlimit,
				(long unsigned)dp->curinodes,
				(long unsigned)dp->isoftlimit,(long unsigned)dp->ihardlimit,
				(long unsigned)dp->bsize));
#endif /* LARGE_SMB_OFF_T */
			return 0;
		}

		DEBUG (0, ("get_quota_command failed!\n"));
		return -1;
	}

	errno = ENOSYS;
	return -1;
	
invalid_param:
	DEBUG(0,("The output of get_quota_command is invalid!\n"));
	return -1;
}

static int command_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	const char *set_quota_command;
	
	set_quota_command = lp_set_quota_command();
	if (set_quota_command && *set_quota_command) {
		char **lines;
		pstring syscmd;
		int _id = -1;

		switch(qtype) {
			case SMB_USER_QUOTA_TYPE:
			case SMB_USER_FS_QUOTA_TYPE:
				_id = id.uid;
				break;
			case SMB_GROUP_QUOTA_TYPE:
			case SMB_GROUP_FS_QUOTA_TYPE:
				_id = id.gid;
				break;
			default:
				return -1;
		}

#ifdef LARGE_SMB_OFF_T
		slprintf(syscmd, sizeof(syscmd)-1, 
			"%s \"%s\" %d %d "
			"%u %llu %llu "
			"%llu %llu %llu ", 
			set_quota_command, path, qtype, _id, dp->qflags,
			(long long unsigned)dp->softlimit,(long long unsigned)dp->hardlimit,
			(long long unsigned)dp->isoftlimit,(long long unsigned)dp->ihardlimit,
			(long long unsigned)dp->bsize);
#else /* LARGE_SMB_OFF_T */
		slprintf(syscmd, sizeof(syscmd)-1, 
			"%s \"%s\" %d %d "
			"%u %lu %lu "
			"%lu %lu %lu ", 
			set_quota_command, path, qtype, _id, dp->qflags,
			(long unsigned)dp->softlimit,(long unsigned)dp->hardlimit,
			(long unsigned)dp->isoftlimit,(long unsigned)dp->ihardlimit,
			(long unsigned)dp->bsize);
#endif /* LARGE_SMB_OFF_T */



		DEBUG (3, ("get_quota: Running command %s\n", syscmd));

		lines = file_lines_pload(syscmd, NULL);
		if (lines) {
			char *line = lines[0];

			DEBUG (3, ("Read output from set_quota, \"%s\"\n", line));

			file_lines_free(lines);
			
			return 0;
		}
		DEBUG (0, ("set_quota_command failed!\n"));
		return -1;
	}

	errno = ENOSYS;
	return -1;
}

int sys_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	int i;
	BOOL ready = False;
	char *mntpath = NULL;
	char *bdev = NULL;
	char *fs = NULL;

	if (!path||!dp)
		smb_panic("sys_get_quota: called with NULL pointer");

	if (command_get_quota(path, qtype, id, dp)==0) {	
		return 0;
	} else if (errno != ENOSYS) {
		return -1;
	}

	if ((ret=sys_path_to_bdev(path,&mntpath,&bdev,&fs))!=0) {
		DEBUG(0,("sys_path_to_bdev() failed for path [%s]!\n",path));
		return ret;
	}

	for (i=0;(fs && sys_quota_backends[i].name && sys_quota_backends[i].get_quota);i++) {
		if (strcmp(fs,sys_quota_backends[i].name)==0) {
			ret = sys_quota_backends[i].get_quota(mntpath, bdev, qtype, id, dp);
			if (ret!=0) {
				DEBUG(10,("sys_get_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d] ret[%d].\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),ret));
			}
			ready = True;
			break;	
		}		
	}

	if (!ready) {
		/* use the default vfs quota functions */
		ret=sys_get_vfs_quota(mntpath, bdev, qtype, id, dp);
		if (ret!=0) {
			DEBUG(10,("sys_get_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d] ret[%d].\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),ret));
		}
	}

	SAFE_FREE(mntpath);
	SAFE_FREE(bdev);
	SAFE_FREE(fs);

	if ((ret!=0)&& (errno == EDQUOT)) {
		return 0;
	}

	return ret;
}

int sys_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp)
{
	int ret = -1;
	int i;
	BOOL ready = False;
	char *mntpath = NULL;
	char *bdev = NULL;
	char *fs = NULL;

	/* find the block device file */

	if (!path||!dp)
		smb_panic("get_smb_quota: called with NULL pointer");

	if (command_set_quota(path, qtype, id, dp)==0) {	
		return 0;
	} else if (errno != ENOSYS) {
		return -1;
	}

	if ((ret=sys_path_to_bdev(path,&mntpath,&bdev,&fs))!=0) {
		DEBUG(0,("sys_path_to_bdev() failed for path [%s]!\n",path));
		return ret;
	}

	for (i=0;(fs && sys_quota_backends[i].name && sys_quota_backends[i].set_quota);i++) {
		if (strcmp(fs,sys_quota_backends[i].name)==0) {
			ret = sys_quota_backends[i].set_quota(mntpath, bdev, qtype, id, dp);
			if (ret!=0) {
				DEBUG(10,("sys_set_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d] ret[%d].\n",
					fs,mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),ret));
			}
			ready = True;
			break;
		}		
	}

	if (!ready) {
		/* use the default vfs quota functions */
		ret=sys_set_vfs_quota(mntpath, bdev, qtype, id, dp);
		if (ret!=0) {
			DEBUG(10,("sys_set_%s_quota() failed for mntpath[%s] bdev[%s] qtype[%d] id[%d] ret[%d].\n",
				"vfs",mntpath,bdev,qtype,(qtype==SMB_GROUP_QUOTA_TYPE?id.gid:id.uid),ret));
		}
	}

	SAFE_FREE(mntpath);
	SAFE_FREE(bdev);
	SAFE_FREE(fs);

	if ((ret!=0)&& (errno == EDQUOT)) {
		return 0;
	}

	return ret;		
}

#else /* HAVE_SYS_QUOTAS */
 void dummy_sysquotas_c(void)
{
	return;
}
#endif /* HAVE_SYS_QUOTAS */

#else /* ! AUTOCONF_TEST */
/* this is the autoconf driver to test witch quota system we should use */

#if defined(HAVE_QUOTACTL_4A)
/* long quotactl(int cmd, char *special, qid_t id, caddr_t addr) */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#if defined(HAVE_LINUX_QUOTA_H)
# include <linux/quota.h>
# if defined(HAVE_STRUCT_IF_DQBLK)
#  define SYS_DQBLK if_dqblk
# elif defined(HAVE_STRUCT_MEM_DQBLK)
#  define SYS_DQBLK mem_dqblk
# endif
#elif defined(HAVE_SYS_QUOTA_H)
# include <sys/quota.h>
#endif

#ifndef SYS_DQBLK
#define SYS_DQBLK dqblk
#endif

 int autoconf_quota(void)
{
	int ret = -1;
	struct SYS_DQBLK D;

	ret = quotactl(Q_GETQUOTA,"/dev/hda1",0,(void *)&D);
	
	return ret;
}

#elif defined(HAVE_QUOTACTL_4B)
/* int quotactl(const char *path, int cmd, int id, char *addr); */

#ifdef HAVE_SYS_QUOTA_H
#include <sys/quota.h>
#else /* *BSD */
#include <sys/types.h>
#include <ufs/ufs/quota.h>
#include <machine/param.h>
#endif

 int autoconf_quota(void)
{
	int ret = -1;
	struct dqblk D;

	ret = quotactl("/",Q_GETQUOTA,0,(char *) &D);

	return ret;
}

#elif defined(HAVE_QUOTACTL_3)
/* int quotactl (char *spec, int request, char *arg); */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_QUOTA_H
#include <sys/quota.h>
#endif

 int autoconf_quota(void)
{
	int ret = -1;
	struct q_request request;

	ret = quotactl("/", Q_GETQUOTA, &request);

	return ret;
}

#elif defined(HAVE_QUOTACTL_2)

#error HAVE_QUOTACTL_2 not implemented

#else

#error Unknow QUOTACTL prototype

#endif

 int main(void)
{	
	autoconf_quota();
	return 0;
}
#endif /* AUTOCONF_TEST */

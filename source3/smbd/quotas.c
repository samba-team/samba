/* 
   Unix SMB/CIFS implementation.
   support for quotas
   Copyright (C) Andrew Tridgell 1992-1998
   
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


/* 
 * This is one of the most system dependent parts of Samba, and its
 * done a litle differently. Each system has its own way of doing 
 * things :-(
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_QUOTA

#ifndef HAVE_SYS_QUOTAS

/* just a quick hack because sysquotas.h is included before linux/quota.h */
#ifdef QUOTABLOCK_SIZE
#undef QUOTABLOCK_SIZE
#endif

#ifdef WITH_QUOTAS

#if defined(SUNOS5) /* Solaris */

#include <fcntl.h>
#include <sys/param.h>
#include <sys/fs/ufs_quota.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>

/****************************************************************************
 Allows querying of remote hosts for quotas on NFS mounted shares.
 Supports normal NFS and AMD mounts.
 Alan Romeril <a.romeril@ic.ac.uk> July 2K.
****************************************************************************/

#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpcsvc/rquota.h>
#include <rpc/nettype.h>
#include <rpc/xdr.h>

static int my_xdr_getquota_rslt(XDR *xdrsp, struct getquota_rslt *gqr)
{
	int quotastat;

	if (!xdr_int(xdrsp, &quotastat)) {
		DEBUG(6,("nfs_quotas: Status bad or zero\n"));
		return 0;
	}
	gqr->status = quotastat;

	if (!xdr_int(xdrsp, &gqr->getquota_rslt_u.gqr_rquota.rq_bsize)) {
		DEBUG(6,("nfs_quotas: Block size bad or zero\n"));
		return 0;
	}
	if (!xdr_bool(xdrsp, &gqr->getquota_rslt_u.gqr_rquota.rq_active)) {
		DEBUG(6,("nfs_quotas: Active bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, &gqr->getquota_rslt_u.gqr_rquota.rq_bhardlimit)) {
		DEBUG(6,("nfs_quotas: Hardlimit bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, &gqr->getquota_rslt_u.gqr_rquota.rq_bsoftlimit)) {
		DEBUG(6,("nfs_quotas: Softlimit bad or zero\n"));
		return 0;
	}
	if (!xdr_int(xdrsp, &gqr->getquota_rslt_u.gqr_rquota.rq_curblocks)) {
		DEBUG(6,("nfs_quotas: Currentblocks bad or zero\n"));
		return 0;
	}
	return (1);
}

static int my_xdr_getquota_args(XDR *xdrsp, struct getquota_args *args)
{
	if (!xdr_string(xdrsp, &args->gqa_pathp, RQ_PATHLEN ))
		return(0);
	if (!xdr_int(xdrsp, &args->gqa_uid))
		return(0);
	return (1);
}

/* Restricted to SUNOS5 for the moment, I haven`t access to others to test. */
static bool nfs_quotas(char *nfspath, uid_t euser_id, uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	uid_t uid = euser_id;
	struct dqblk D;
	char *mnttype = nfspath;
	CLIENT *clnt;
	struct getquota_rslt gqr;
	struct getquota_args args;
	char *cutstr, *pathname, *host, *testpath;
	int len;
	static struct timeval timeout = {2,0};
	enum clnt_stat clnt_stat;
	bool ret = True;

	*bsize = *dfree = *dsize = (uint64_t)0;

	len=strcspn(mnttype, ":");
	pathname=strstr(mnttype, ":");
	cutstr = (char *) SMB_MALLOC(len+1);
	if (!cutstr)
		return False;

	memset(cutstr, '\0', len+1);
	host = strncat(cutstr,mnttype, sizeof(char) * len );
	DEBUG(5,("nfs_quotas: looking for mount on \"%s\"\n", cutstr));
	DEBUG(5,("nfs_quotas: of path \"%s\"\n", mnttype));
	testpath=strchr_m(mnttype, ':');
	args.gqa_pathp = testpath+1;
	args.gqa_uid = uid;

	DEBUG(5,("nfs_quotas: Asking for host \"%s\" rpcprog \"%i\" rpcvers \"%i\" network \"%s\"\n", host, RQUOTAPROG, RQUOTAVERS, "udp"));

	if ((clnt = clnt_create(host, RQUOTAPROG, RQUOTAVERS, "udp")) == NULL) {
		ret = False;
		goto out;
	}

	clnt->cl_auth = authunix_create_default();
	DEBUG(9,("nfs_quotas: auth_success\n"));

	clnt_stat=clnt_call(clnt, RQUOTAPROC_GETQUOTA, my_xdr_getquota_args, (caddr_t)&args, my_xdr_getquota_rslt, (caddr_t)&gqr, timeout);

	if (clnt_stat != RPC_SUCCESS) {
		DEBUG(9,("nfs_quotas: clnt_call fail\n"));
		ret = False;
		goto out;
	}

	/*
	 * gqr.status returns 1 if quotas exist, 2 if there is
	 * no quota set, and 3 if no permission to get the quota.
	 * If 3, return something sensible.
	 */

	switch (gqr.status) {
	case 1:
		DEBUG(9,("nfs_quotas: Good quota data\n"));
		D.dqb_bsoftlimit = gqr.getquota_rslt_u.gqr_rquota.rq_bsoftlimit;
		D.dqb_bhardlimit = gqr.getquota_rslt_u.gqr_rquota.rq_bhardlimit;
		D.dqb_curblocks = gqr.getquota_rslt_u.gqr_rquota.rq_curblocks;
		break;

	case 2:
	case 3:
		D.dqb_bsoftlimit = 1;
		D.dqb_curblocks = 1;
		DEBUG(9,("nfs_quotas: Remote Quotas returned \"%i\" \n", gqr.status));
		break;

	default:
		DEBUG(9, ("nfs_quotas: Unknown Remote Quota Status \"%i\"\n",
				gqr.status));
		ret = false;
		goto out;
	}

	DEBUG(10,("nfs_quotas: Let`s look at D a bit closer... status \"%i\" bsize \"%i\" active? \"%i\" bhard \"%i\" bsoft \"%i\" curb \"%i\" \n",
			gqr.status,
			gqr.getquota_rslt_u.gqr_rquota.rq_bsize,
			gqr.getquota_rslt_u.gqr_rquota.rq_active,
			gqr.getquota_rslt_u.gqr_rquota.rq_bhardlimit,
			gqr.getquota_rslt_u.gqr_rquota.rq_bsoftlimit,
			gqr.getquota_rslt_u.gqr_rquota.rq_curblocks));

	*bsize = gqr.getquota_rslt_u.gqr_rquota.rq_bsize;
	*dsize = D.dqb_bsoftlimit;

	if (D.dqb_curblocks > D.dqb_bsoftlimit) {
		*dfree = 0;
		*dsize = D.dqb_curblocks;
	} else
		*dfree = D.dqb_bsoftlimit - D.dqb_curblocks;

  out:

	if (clnt) {
		if (clnt->cl_auth)
			auth_destroy(clnt->cl_auth);
		clnt_destroy(clnt);
	}

	DEBUG(5,("nfs_quotas: For path \"%s\" returning  bsize %.0f, dfree %.0f, dsize %.0f\n",args.gqa_pathp,(double)*bsize,(double)*dfree,(double)*dsize));

	SAFE_FREE(cutstr);
	DEBUG(10,("nfs_quotas: End of nfs_quotas\n" ));
	return ret;
}

/****************************************************************************
try to get the disk space from disk quotas (SunOS & Solaris2 version)
Quota code by Peter Urbanec (amiga@cse.unsw.edu.au).
****************************************************************************/

bool disk_quotas(connection_struct *conn, struct smb_filename *fname,
		 uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	uid_t euser_id;
	int ret;
	struct dqblk D;
	struct quotctl command;
	int file;
	struct mnttab mnt;
	char *name = NULL;
	FILE *fd;
	SMB_STRUCT_STAT sbuf;
	SMB_DEV_T devno;
	bool found = false;
	const char *path = fname->base_name;

	euser_id = geteuid();

	devno = fname->st.st_ex_dev;
	DEBUG(5,("disk_quotas: looking for path \"%s\" devno=%x\n",
		path, (unsigned int)devno));
	if ((fd = fopen(MNTTAB, "r")) == NULL) {
		return false;
	}

	while (getmntent(fd, &mnt) == 0) {
		if (sys_stat(mnt.mnt_mountp, &sbuf, false) == -1) {
			continue;
		}

		DEBUG(5,("disk_quotas: testing \"%s\" devno=%x\n",
			mnt.mnt_mountp, (unsigned int)devno));

		/* quotas are only on vxfs, UFS or NFS */
		if ((sbuf.st_ex_dev == devno) && (
			strcmp( mnt.mnt_fstype, MNTTYPE_UFS ) == 0 ||
			strcmp( mnt.mnt_fstype, "nfs" ) == 0    ||
			strcmp( mnt.mnt_fstype, "vxfs" ) == 0 )) {
				found = true;
				name = talloc_asprintf(talloc_tos(),
						"%s/quotas",
						mnt.mnt_mountp);
				break;
		}
	}

	fclose(fd);
	if (!found) {
		return false;
	}

	if (!name) {
		return false;
	}
	become_root();

	if (strcmp(mnt.mnt_fstype, "nfs") == 0) {
		bool retval;
		DEBUG(5,("disk_quotas: looking for mountpath (NFS) \"%s\"\n",
					mnt.mnt_special));
		retval = nfs_quotas(mnt.mnt_special,
				euser_id, bsize, dfree, dsize);
		unbecome_root();
		return retval;
	}

	DEBUG(5,("disk_quotas: looking for quotas file \"%s\"\n", name));
	if((file=open(name, O_RDONLY,0))<0) {
		unbecome_root();
		return false;
	}
	command.op = Q_GETQUOTA;
	command.uid = euser_id;
	command.addr = (caddr_t) &D;
	ret = ioctl(file, Q_QUOTACTL, &command);
	close(file);

	unbecome_root();

	if (ret < 0) {
		DEBUG(5,("disk_quotas ioctl (Solaris) failed. Error = %s\n",
					strerror(errno) ));

		return false;
	}

	/* If softlimit is zero, set it equal to hardlimit.
	 */

	if (D.dqb_bsoftlimit==0) {
		D.dqb_bsoftlimit = D.dqb_bhardlimit;
	}

	/* Use softlimit to determine disk space. A user exceeding the quota
	 * is told that there's no space left. Writes might actually work for
	 * a bit if the hardlimit is set higher than softlimit. Effectively
	 * the disk becomes made of rubber latex and begins to expand to
	 * accommodate the user :-)
	 */

	if (D.dqb_bsoftlimit==0)
		return(False);
	*bsize = DEV_BSIZE;
	*dsize = D.dqb_bsoftlimit;

	if (D.dqb_curblocks > D.dqb_bsoftlimit) {
		*dfree = 0;
		*dsize = D.dqb_curblocks;
	} else {
		*dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
	}

	DEBUG(5,("disk_quotas for path \"%s\" returning "
		"bsize %.0f, dfree %.0f, dsize %.0f\n",
		path,(double)*bsize,(double)*dfree,(double)*dsize));

	return true;
}

#endif /* Solaris */

#else /* WITH_QUOTAS */

bool disk_quotas(connection_struct *conn, struct smb_filename *fname,
		 uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	(*bsize) = 512; /* This value should be ignored */

	/* And just to be sure we set some values that hopefully */
	/* will be larger that any possible real-world value     */
	(*dfree) = (uint64_t)-1;
	(*dsize) = (uint64_t)-1;

	/* As we have select not to use quotas, allways fail */
	return false;
}
#endif /* WITH_QUOTAS */

#else /* HAVE_SYS_QUOTAS */
/* wrapper to the new sys_quota interface
   this file should be removed later
   */
bool disk_quotas(connection_struct *conn, struct smb_filename *fname,
		 uint64_t *bsize, uint64_t *dfree, uint64_t *dsize)
{
	int r;
	SMB_DISK_QUOTA D;
	unid_t id;

	/*
	 * First of all, check whether user quota is
	 * enforced. If the call fails, assume it is
	 * not enforced.
	 */
	ZERO_STRUCT(D);
	id.uid = -1;
	r = SMB_VFS_GET_QUOTA(conn, fname, SMB_USER_FS_QUOTA_TYPE,
			      id, &D);
	if (r == -1 && errno != ENOSYS) {
		goto try_group_quota;
	}
	if (r == 0 && (D.qflags & QUOTAS_DENY_DISK) == 0) {
		goto try_group_quota;
	}

	ZERO_STRUCT(D);
	id.uid = geteuid();

	/* if new files created under this folder get this
	 * folder's UID, then available space is governed by
	 * the quota of the folder's UID, not the creating user.
	 */
	if (lp_inherit_owner(SNUM(conn)) != INHERIT_OWNER_NO &&
	    id.uid != fname->st.st_ex_uid && id.uid != sec_initial_uid()) {
		int save_errno;

		id.uid = fname->st.st_ex_uid;
		become_root();
		r = SMB_VFS_GET_QUOTA(conn, fname,
				      SMB_USER_QUOTA_TYPE, id, &D);
		save_errno = errno;
		unbecome_root();
		errno = save_errno;
	} else {
		r = SMB_VFS_GET_QUOTA(conn, fname,
				      SMB_USER_QUOTA_TYPE, id, &D);
	}

	if (r == -1) {
		goto try_group_quota;
	}

	*bsize = D.bsize;
	/* Use softlimit to determine disk space, except when it has been exceeded */
	if (
		(D.softlimit && D.curblocks >= D.softlimit) ||
		(D.hardlimit && D.curblocks >= D.hardlimit) ||
		(D.isoftlimit && D.curinodes >= D.isoftlimit) ||
		(D.ihardlimit && D.curinodes>=D.ihardlimit)
	) {
		*dfree = 0;
		*dsize = D.curblocks;
	} else if (D.softlimit==0 && D.hardlimit==0) {
		goto try_group_quota;
	} else {
		if (D.softlimit == 0) {
			D.softlimit = D.hardlimit;
		}
		*dfree = D.softlimit - D.curblocks;
		*dsize = D.softlimit;
	}

	return True;
	
try_group_quota:
	/*
	 * First of all, check whether group quota is
	 * enforced. If the call fails, assume it is
	 * not enforced.
	 */
	ZERO_STRUCT(D);
	id.gid = -1;
	r = SMB_VFS_GET_QUOTA(conn, fname, SMB_GROUP_FS_QUOTA_TYPE,
			      id, &D);
	if (r == -1 && errno != ENOSYS) {
		return false;
	}
	if (r == 0 && (D.qflags & QUOTAS_DENY_DISK) == 0) {
		return false;
	}

	ZERO_STRUCT(D);

	/*
	 * If new files created under this folder get this folder's
	 * GID, then available space is governed by the quota of the
	 * folder's GID, not the primary group of the creating user.
	 */
	if (VALID_STAT(fname->st) &&
	    S_ISDIR(fname->st.st_ex_mode) &&
	    fname->st.st_ex_mode & S_ISGID) {
		id.gid = fname->st.st_ex_gid;
		become_root();
		r = SMB_VFS_GET_QUOTA(conn, fname, SMB_GROUP_QUOTA_TYPE, id,
				      &D);
		unbecome_root();
	} else {
		id.gid = getegid();
		r = SMB_VFS_GET_QUOTA(conn, fname, SMB_GROUP_QUOTA_TYPE, id,
				      &D);
	}

	if (r == -1) {
		return False;
	}

	*bsize = D.bsize;
	/* Use softlimit to determine disk space, except when it has been exceeded */
	if (
		(D.softlimit && D.curblocks >= D.softlimit) ||
		(D.hardlimit && D.curblocks >= D.hardlimit) ||
		(D.isoftlimit && D.curinodes >= D.isoftlimit) ||
		(D.ihardlimit && D.curinodes>=D.ihardlimit)
	) {
		*dfree = 0;
		*dsize = D.curblocks;
	} else if (D.softlimit==0 && D.hardlimit==0) {
		return False;
	} else {
		if (D.softlimit == 0) {
			D.softlimit = D.hardlimit;
		}
		*dfree = D.softlimit - D.curblocks;
		*dsize = D.softlimit;
	}

	return (True);
}
#endif /* HAVE_SYS_QUOTAS */

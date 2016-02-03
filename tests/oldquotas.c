/* this test should find out whether legacy quota code in disk_quotas.c
 * compiles. It is a stripped-down version of disk_quotas.c, with samba
 * stuff removed and only system calls, header files, and constants left.
 */

#ifndef HAVE_SYS_QUOTAS

/* just a quick hack because sysquotas.h is included before linux/quota.h */
#ifdef QUOTABLOCK_SIZE
#undef QUOTABLOCK_SIZE
#endif

#ifdef WITH_QUOTAS

#if defined(VXFS_QUOTA)

bool disk_quotas_vxfs(const char *name, char *path, uint64_t *bsize,
		      uint64_t *dfree, uint64_t *dsize);

#endif /* VXFS_QUOTA */

#if defined(SUNOS5) || defined(SUNOS4)

#include <fcntl.h>
#include <sys/param.h>
#if defined(SUNOS5)
#include <sys/fs/ufs_quota.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else /* defined(SUNOS4) */
#include <ufs/quota.h>
#include <mntent.h>
#endif

#if defined(SUNOS5)

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

static bool nfs_quotas(char *nfspath, uid_t euser_id, uint64_t *bsize,
		       uint64_t *dfree, uint64_t *dsize)
{
	CLIENT *clnt;
	clnt = clnt_create("host", RQUOTAPROG, RQUOTAVERS, "udp");
	return true;
}
#endif

/****************************************************************************
try to get the disk space from disk quotas (SunOS & Solaris2 version)
Quota code by Peter Urbanec (amiga@cse.unsw.edu.au).
****************************************************************************/

bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree,
		 uint64_t *dsize)
{
	int ret;
#if defined(SUNOS5)
	struct quotctl command;
#else /* SunOS4 */
	struct mntent *mnt;
#endif
#if defined(SUNOS5)
	nfs_quotas("", 0, bsize, dfree, dsize);

	command.op = Q_GETQUOTA;
	command.uid = 0;
	command.addr = NULL;
	ret = ioctl(1, Q_QUOTACTL, &command);
#else
	ret = quotactl(Q_GETQUOTA, "", 0, NULL);
#endif

#if defined(SUNOS5) && defined(VXFS_QUOTA)
	disk_quotas_vxfs("", path, bsize, dfree, dsize);
#endif
	return true;
}

#else

#if AIX
/* AIX quota patch from Ole Holm Nielsen <ohnielse@fysik.dtu.dk> */
#include <jfs/quota.h>
/* AIX 4.X: Rename members of the dqblk structure (ohnielse@fysik.dtu.dk) */
#define dqb_curfiles dqb_curinodes
#define dqb_fhardlimit dqb_ihardlimit
#define dqb_fsoftlimit dqb_isoftlimit
#ifdef _AIXVERSION_530
#include <sys/statfs.h>
#include <sys/vmount.h>
#endif /* AIX 5.3 */
#else  /* !AIX */
#include <sys/quota.h>
#include <devnm.h>
#endif

/****************************************************************************
try to get the disk space from disk quotas - default version
****************************************************************************/

bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree,
		 uint64_t *dsize)
{
	struct dqblk D;
#if defined(AIX)
#ifdef _AIXVERSION_530
	quota64_t user_quota;
	quotactl(path, QCMD(Q_J2GETQUOTA, USRQUOTA), 0, (char *)&user_quota);
#endif /* AIX 5.3 */
	quotactl(path, QCMD(Q_GETQUOTA, USRQUOTA), 0, (char *)&D);
#else  /* !AIX */
	quotactl(Q_GETQUOTA, "", 0, &D);
#endif /* !AIX */
	return (true);
}

#endif

#if defined(VXFS_QUOTA)

#if defined(SUNOS5)

#include <sys/fs/vx_solaris.h>
#include <sys/fs/vx_machdep.h>
#include <sys/fs/vx_layout.h>
#include <sys/fs/vx_quota.h>
#include <sys/fs/vx_aioctl.h>
#include <sys/fs/vx_ioctl.h>

bool disk_quotas_vxfs(const char *name, char *path, uint64_t *bsize,
		      uint64_t *dfree, uint64_t *dsize)
{
	struct vx_dqblk D;
	struct vx_quotctl quotabuf;
	struct vx_genioctl genbuf;

	genbuf.ioc_cmd = VX_QUOTACTL;
	genbuf.ioc_up = (void *)&quotabuf;

	quotabuf.cmd = VX_GETQUOTA;
	quotabuf.uid = 0;
	quotabuf.addr = (caddr_t)&D;
	ret = ioctl(1, VX_ADMIN_IOCTL, &genbuf);

	return true;
}

#endif /* SUNOS5 || ... */

#endif /* VXFS_QUOTA */

#else /* WITH_QUOTAS */

#error "This test should be called with WITH_QUOTAS defined"

#endif /* WITH_QUOTAS */

#else /* HAVE_SYS_QUOTAS */

#error "This test should not be called for systems with new quota interface"

#endif /* HAVE_SYS_QUOTAS */

int main() { return disk_quotas(NULL, NULL, NULL, NULL); }

/* this test should find out whether legacy quota code in disk_quotas.c
 * compiles. It is a stripped-down version of disk_quotas.c, with samba
 * stuff removed and only system calls, header files, and constants left.
 */

#ifndef HAVE_SYS_QUOTAS

/* just a quick hack because sysquotas.h is included before linux/quota.h */
#ifdef QUOTABLOCK_SIZE
#undef QUOTABLOCK_SIZE
#endif /* defined(QUOTABLOCK_SIZE) */

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

static bool nfs_quotas(char *nfspath, uid_t euser_id, uint64_t *bsize,
		       uint64_t *dfree, uint64_t *dsize)
{
	CLIENT *clnt;
	clnt = clnt_create("host", RQUOTAPROG, RQUOTAVERS, "udp");
	return true;
}

/****************************************************************************
try to get the disk space from disk quotas (SunOS & Solaris2 version)
Quota code by Peter Urbanec (amiga@cse.unsw.edu.au).
****************************************************************************/

bool disk_quotas(const char *path, uint64_t *bsize, uint64_t *dfree,
		 uint64_t *dsize)
{
	int ret;
	struct quotctl command;
	nfs_quotas("", 0, bsize, dfree, dsize);

	command.op = Q_GETQUOTA;
	command.uid = 0;
	command.addr = NULL;
	ret = ioctl(1, Q_QUOTACTL, &command);

	return true;
}

#else /* not SunOS / Solaris */

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
#else  /* !AIX - HP-UX */
#include <sys/quota.h>
#include <devnm.h>
#endif /* AIX */

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

#endif /* SunOS / Solaris */

#else /* WITH_QUOTAS */

#error "This test should be called with WITH_QUOTAS defined"

#endif /* WITH_QUOTAS */

#else /* HAVE_SYS_QUOTAS */

#error "This test should not be called for systems with new quota interface"

#endif /* HAVE_SYS_QUOTAS */

int main() { return disk_quotas(NULL, NULL, NULL, NULL); }

#include <stdio.h>

main()
{
#if !(defined(HAVE_FCNTL_LOCK) || defined(HAVE_STRUCT_FLOCK64))
	printf("ERROR: No locking available. Running Samba would be unsafe\n");
	exit(1);
#endif

#if !(defined(HAVE_SYSV_IPC) || defined(HAVE_SHARED_MMAP))
	printf("WARNING: no shared memory. Running with slow locking code\n");
#endif

#ifdef HAVE_TRAPDOOR_UID
	printf("WARNING: trapdoor uid system - Samba may not operate correctly\n");
#endif

#if !(defined(HAVE_NETMASK_IFCONF) || defined(HAVE_NETMASK_IFREQ) || defined(HAVE_NETMASK_AIX))
	printf("WARNING: No automated netmask determination - use an interfaces line\n");
#endif

#if !(defined(STAT_STATVFS) || defined(STAT_STATVFS64) || defined(STAT_STATFS3_OSF1) || defined(STAT_STATFS2_BSIZE) || defined(STAT_STATFS4) || defined(STAT_STATFS2_FSIZE) || defined(STAT_STATFS2_FS_DATA))
	printf("ERROR: No disk free routine!\n");
	exit(1);
#endif

#if !((defined(HAVE_RANDOM) || defined(HAVE_RAND)) && (defined(HAVE_SRANDOM) || defined(HAVE_SRAND)))
    printf("ERROR: No random or srandom routine!\n");
    exit(1);
#endif

	exit(0);
}

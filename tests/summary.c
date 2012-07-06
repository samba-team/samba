#include <stdio.h>

void exit(int);

int main()
{
#if !defined(HAVE_FCNTL_LOCK)
	printf("ERROR: No locking available. Running Samba would be unsafe\n");
	exit(1);
#endif

#if !(defined(HAVE_IFACE_GETIFADDRS) || defined(HAVE_IFACE_IFCONF) || defined(HAVE_IFACE_IFREQ) || defined(HAVE_IFACE_AIX))
	printf("WARNING: No automated network interface determination\n");
#endif

#if !(defined(USE_SETEUID) || defined(USE_SETREUID) || defined(USE_SETRESUID) || defined(USE_SETUIDX) || defined(USE_LINUX_THREAD_CREDENTIALS))
	printf("ERROR: no seteuid method available\n");
	exit(1);
#endif

#if !(defined(STAT_STATVFS) || defined(STAT_STATFS3_OSF1) || defined(STAT_STATFS2_BSIZE) || defined(STAT_STATFS4) || defined(STAT_STATFS2_FSIZE) || defined(STAT_STATFS2_FS_DATA))
	printf("ERROR: No disk free routine!\n");
	exit(1);
#endif

#if !((defined(HAVE_RANDOM) || defined(HAVE_RAND)) && (defined(HAVE_SRANDOM) || defined(HAVE_SRAND)))
    printf("ERROR: No random or srandom routine!\n");
    exit(1);
#endif

	exit(0);
}

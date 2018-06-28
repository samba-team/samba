#include <stdio.h>

void exit(int);

int main()
{
#if !defined(HAVE_FCNTL_LOCK)
#error "ERROR: No locking available. Running Samba would be unsafe"
#endif

#if !(defined(HAVE_IFACE_GETIFADDRS) || defined(HAVE_IFACE_IFCONF) || defined(HAVE_IFACE_IFREQ) || defined(HAVE_IFACE_AIX))
#warning "WARNING: No automated network interface determination"
#endif

#if !(defined(USE_SETEUID) || defined(USE_SETREUID) || defined(USE_SETRESUID) || defined(USE_SETUIDX) || defined(HAVE_LINUX_THREAD_CREDENTIALS))
#error "ERROR: no seteuid method available"
#endif

#if !(defined(STAT_STATVFS) || defined(STAT_STATFS3_OSF1) || defined(STAT_STATFS2_BSIZE) || defined(STAT_STATFS4) || defined(STAT_STATFS2_FSIZE) || defined(STAT_STATFS2_FS_DATA))
#error "ERROR: No disk free routine!"
#endif

#if !((defined(HAVE_RANDOM) || defined(HAVE_RAND)) && (defined(HAVE_SRANDOM) || defined(HAVE_SRAND)))
#error "ERROR: No random or srandom routine!"
#endif

	exit(0);
}

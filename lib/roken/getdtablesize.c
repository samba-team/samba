#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

int getdtablesize(void)
{
    int files = -1;
#if defined(HAVE_SYSCONF) && defined(_SC_OPEN_MAX)
    files = sysconf(_SC_OPEN_MAX);

#elif definded(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
    struct rlimit res;
    if(getrlimit(RLIMIT_NOFILE, &res) == 0)
	files = res.rlim_cur;

#elif defined(HAVE_SYSCTL) && defined(CTL_KERN) && defined(KERN_MAXFILES)
    int mib[2];
    size_t len;
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_MAXFILES;
    len = sizeof(files);
    sysctl(&mib, 2, &files, sizeof(nfil), NULL, 0);
#endif

#ifdef OPEN_MAX
    if(files < 0)
	files = OPEN_MAX;
#endif

#ifdef NOFILE
    if(files < 0)
	files = NOFILE;
#endif    
    
    return files;
}

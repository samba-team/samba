#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "roken.h"

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
#else /* !defined(HAVE_SYSCONF) */
#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
  struct rlimit res;
  if (getrlimit(RLIMIT_NOFILE, &res) == 0)
    files = res.rlim_cur;
#else /* !definded(HAVE_GETRLIMIT) */
#if defined(HAVE_SYSCTL) && defined(CTL_KERN) && defined(KERN_MAXFILES)
  int mib[2];
  size_t len;
    
  mib[0] = CTL_KERN;
  mib[1] = KERN_MAXFILES;
  len = sizeof(files);
  sysctl(&mib, 2, &files, sizeof(nfil), NULL, 0);
#endif /* defined(HAVE_SYSCTL) */
#endif /* !definded(HAVE_GETRLIMIT) */
#endif /* !defined(HAVE_SYSCONF) */

#ifdef OPEN_MAX
  if (files < 0)
    files = OPEN_MAX;
#endif

#ifdef NOFILE
  if (files < 0)
    files = NOFILE;
#endif    
    
  return files;
}

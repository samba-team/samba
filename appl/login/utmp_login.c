#include "bsd_locl.h"

RCSID("$Id$");

/* update utmp and wtmp - the BSD way */

void utmp_login(char *tty, char *username, char *hostname)
{
#ifndef HAVE_UTMPX_H
    struct utmp utmp;
    struct hostent *he;
    int fd;

    char *ttyx; /* tty w/o /dev/* */
    char *id;

    ttyx = tty;

    if(strncmp(tty, "/dev/", 5) == 0)
	ttyx = tty + 5;

    memset(&utmp, 0, sizeof(utmp));
    utmp.ut_time = time(NULL);
    strncpy(utmp.ut_line, ttyx, sizeof(utmp.ut_line));
    strncpy(utmp.ut_name, username, sizeof(utmp.ut_name));

# ifdef HAVE_UT_USER
    strncpy(utmp.ut_user, username, sizeof(utmp.ut_user));
# endif

# ifdef HAVE_UT_ADDR
    if (hostname[0]) {
	if ((he = gethostbyname(hostname)))
	    memcpy(&utmp.ut_addr, he->h_addr_list[0],
		   sizeof(utmp.ut_addr));
    }
# endif

# ifdef HAVE_UT_HOST
    strncpy(utmp.ut_host, hostname, sizeof(utmp.ut_host));
# endif

# ifdef HAVE_UT_TYPE
    utmp.ut_type = USER_PROCESS;
# endif

# ifdef HAVE_UT_PID
    utmp.ut_pid = getpid();
# endif

# ifdef HAVE_UT_ID
    /* any particular reason to not include "tty" ? */
    id = ttyx;
    if(strncmp(ttyx, "tty", 3) == 0)
	id += 3;
    strncpy(utmp.ut_id, id, sizeof(utmp.ut_id));
# endif


#ifdef HAVE_SETUTENT
    utmpname(_PATH_UTMP);
    setutent();
    pututline(&utmp);
    endutent();
#else

#ifdef HAVE_TTYSLOT
    {
      int ttyno;
      ttyno = ttyslot();
      if (ttyno > 0 && (fd = open(_PATH_UTMP, O_WRONLY, 0)) >= 0) {
	lseek(fd, (long)(ttyno * sizeof(struct utmp)), SEEK_SET);
	write(fd, (char *)&utmp, sizeof(struct utmp));
	close(fd);
      }
    }
#endif /* HAVE_TTYSLOT */
#endif /* HAVE_SETUTENT */

    if ((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND, 0)) >= 0) {
	write(fd, (char *)&utmp, sizeof(struct utmp));
	close(fd);
    }
#endif /* HAVE_UTMPX_H */
}

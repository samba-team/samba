/* Author: Wietse Venema <wietse@wzv.win.tue.nl> */

#include "bsd_locl.h"

#ifdef SYSV_UTMP

/* utmpx_login - update utmp and wtmp after login */

utmpx_login(line, user, host)
char   *line;
char   *user;
char   *host;
{
    struct utmpx *ut;
    pid_t   mypid = getpid();
    int     ret = (-1);

    /*
     * SYSV4 ttymon and login use tty port names with the "/dev/" prefix
     * stripped off. Rlogind and telnetd, on the other hand, make utmpx
     * entries with device names like /dev/pts/nnn. We therefore cannot use
     * getutxline(). Return nonzero if no utmp entry was found with our own
     * process ID for a login or user process.
     */

    while ((ut = getutxent())) {
	if (ut->ut_pid == mypid && (ut->ut_type == INIT_PROCESS
	  || ut->ut_type == LOGIN_PROCESS || ut->ut_type == USER_PROCESS)) {
	    strncpy(ut->ut_line, line, sizeof(ut->ut_line));
	    strncpy(ut->ut_user, user, sizeof(ut->ut_user));
	    strncpy(ut->ut_host, host, sizeof(ut->ut_host));
	    ut->ut_syslen = strlen(host) + 1;
	    if (ut->ut_syslen > sizeof(ut->ut_host))
		ut->ut_syslen = sizeof(ut->ut_host);
	    ut->ut_type = USER_PROCESS;
	    gettimeofday(&(ut->ut_tv));
	    pututxline(ut);
	    updwtmpx(WTMPX_FILE, ut);
	    ret = 0;
	    break;
	}
    }
    endutxent();
    return (ret);
}

#endif /* SYSV_UTMP */

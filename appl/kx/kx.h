/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/un.h>
#include <X11/Xauth.h>

#include <krb.h>

#include <roken.h>

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef SOMAXCONN
#define SOMAXCONN 5
#endif

#ifndef LOG_DAEMON
#define openlog(id,option,facility) openlog((id),(option))
#endif

extern char *prog;

int copy_encrypted (int fd1, int fd2, des_cblock *iv,
		    des_key_schedule schedule);

RETSIGTYPE childhandler (int);

extern char x_socket[];

int get_local_xsocket (int *num);
int connect_local_xsocket (unsigned dnr);

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
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xauth.h>

#include <krb.h>

#include <roken.h>

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef LOG_DAEMON
#define openlog(id,option,facility) openlog((id),(option))
#endif

extern char *prog;

int copy_encrypted (int fd1, int fd2, des_cblock *iv,
		    des_key_schedule schedule);

RETSIGTYPE childhandler (int);

extern char x_socket[];

int get_xsockets (int *unix_socket, int *tcp_socket);
int connect_local_xsocket (unsigned dnr);

#define KX_PORT 2111

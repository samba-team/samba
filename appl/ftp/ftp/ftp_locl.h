/* $Id$ */

#ifndef __FTP_LOCL_H__
#define __FTP_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef SOCKS
#include <socks.h>
#endif

#include <sys/bitypes.h>
#include <sys/cdefs.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_ARPA_FTP_H
#include <arpa/ftp.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_TELNET_H
#include <arpa/telnet.h>
#endif

#include <errno.h>
#include <ctype.h>
#include <glob.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include "ftp_var.h"
#include "extern.h"
#include "common.h"
#include "pathnames.h"

#include "krb4.h"

#include "roken.h"

#ifdef NEED_OPTARG_DECLARATION
extern char *optarg;
#endif
#ifdef NEED_OPTIND_DECLARATION
extern int optind;
#endif
#ifdef NEED_OPTERR_DECLARATION
extern int opterr;
#endif

#if defined(__sun__) && !defined(__svr4)
int fclose(FILE*);
int pclose(FILE*);
#endif

#endif /* __FTP_LOCL_H__ */

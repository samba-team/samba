#ifndef __FTP_LOCL_H__
#define __FTP_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/bitypes.h>
#include <sys/cdefs.h>

#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <arpa/ftp.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include <errno.h>
#include <ctype.h>
#include <glob.h>
#include <netdb.h>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

extern int h_errno;

#include "extern.h"
#include "common.h"
#include "ftp_var.h"
#include "pathnames.h"

#include "krb4.h"

extern char *optarg;
extern int optind, opterr;

#if defined(__sun__) && !defined(__svr4)
int fclose(FILE*);
int pclose(FILE*);
#endif

#endif /* __FTP_LOCL_H__ */

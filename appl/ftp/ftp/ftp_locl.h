#ifndef __FTP_LOCL_H__
#define __FTP_LOCL_H__

#include <sys/param.h>
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

extern int h_errno;

#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>

#include "extern.h"
#include "common.h"
#include "ftp_var.h"
#include "pathnames.h"

#include "krb4.h"

#if defined(__sun__) && !defined(__svr4)
int fclose(FILE*);
int pclose(FILE*);
extern int optind;
#endif

#endif /* __FTP_LOCL_H__ */

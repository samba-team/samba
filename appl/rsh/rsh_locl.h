/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pwd.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <krb.h>
#include <prot.h>
#include <krb5.h>
#include <roken.h>

/*
 *
 */

enum auth_method { AUTH_KRB4, AUTH_KRB5 };

#define KCMD_VERSION "KCMDV0.1"

#define USERNAME_SZ 16
#define COMMAND_SZ 1024

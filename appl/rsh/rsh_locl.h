/* $Id$ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <errno.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <roken.h>
#include <krb.h>
#include <prot.h>
#include <krb5.h>

#ifndef _PATH_NOLOGIN
#define _PATH_NOLOGIN   "/etc/nologin"
#endif

#ifndef _PATH_BSHELL
#define _PATH_BSHELL	"/bin/sh"
#endif

#ifndef _PATH_DEFPATH
#define _PATH_DEFPATH	"/usr/bin:/bin"
#endif

/*
 *
 */

enum auth_method { AUTH_KRB4, AUTH_KRB5 };

extern enum auth_method auth_method;
extern int do_encrypt;
extern krb5_context context;
extern krb5_keyblock *keyblock;
extern des_key_schedule schedule;
extern des_cblock iv;

#define KCMD_VERSION "KCMDV0.1"

#define USERNAME_SZ 16
#define COMMAND_SZ 1024

#define RSH_BUFSIZ 10240

ssize_t do_read (int fd, void *buf, size_t sz);
ssize_t do_write (int fd, void *buf, size_t sz);

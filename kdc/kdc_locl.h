/* 
 * $Id$ 
 */

#ifndef __KDC_LOCL_H__
#define __KDC_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <roken.h>
#include <krb5.h>
#include <hdb_err.h>

#include "hdb.h"

extern struct timeval now;
#define kdc_time (now.tv_sec)

hdb_entry *db_fetch (krb5_context, PrincipalName *, char *);

krb5_error_code mk_des_keyblock (EncryptionKey *);

krb5_error_code tgs_rep(krb5_context, KDC_REQ *, krb5_data *);
krb5_error_code as_rep(krb5_context, KDC_REQ *, krb5_data *);

int maybe_version4(unsigned char*, int);
krb5_error_code do_version4();

void loop (krb5_context);

#endif /* __KDC_LOCL_H__ */

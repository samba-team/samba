/* 
 * $Id$
 */

#ifndef __ADMIN_LOCL_H__
#define __ADMIN_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <krb5.h>
#include <hdb_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "hdb.h"

extern krb5_context context;
extern char *database;

#define DECL(X) void X(int, char **)

DECL(get_entry);
DECL(load);
DECL(merge);
DECL(add_new_key);
DECL(mod_entry);
DECL(dump);
DECL(init);
DECL(get_entry);
DECL(del_entry);
DECL(ext_keytab);
DECL(help);

#endif /* __ADMIN_LOCL_H__ */

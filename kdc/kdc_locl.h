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
#include <fcntl.h>
#include <db.h>
#include <krb5.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "kdc.h"

struct entry{
    char *principal;
    char *key;
    char *kvno;
    char *max_life;
    char *max_renew;
};

#endif /* __KDC_LOCL_H__ */

/* $Id$ */

#ifndef __HDB_LOCL_H__
#define __HDB_LOCL_H__

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <krb5.h>
#include <hdb.h>

#ifdef HAVE_DB_H
#include <db.h>
#endif

#ifdef HAVE_NDBM_H
#include <ndbm.h>
#endif

void hdb_principal2key(krb5_context, krb5_principal, krb5_data*);
void hdb_key2principal(krb5_context, krb5_data*, krb5_principal*);
void hdb_entry2value(krb5_context, hdb_entry*, krb5_data*);
void hdb_value2entry(krb5_context, krb5_data*, hdb_entry*);

#endif /* __HDB_LOCL_H__ */

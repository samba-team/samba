/* $Id$ */

#ifndef __HDB_H__
#define __HDB_H__

#include <hdb_err.h>

typedef struct hdb_entry{
    krb5_principal principal;	/* Principal */
    int kvno;			/* Key version number */
    krb5_keyblock keyblock;	/* Key matching vno */
    time_t max_life;		/* Max ticket lifetime */
    time_t max_renew;		/* Max renewable ticket */
    time_t last_change;		/* Time of last update */
    krb5_principal changed_by;	/* Who did last update */
    time_t expires;		/* Time when principal expires */
    union {
	int i;
	struct {
	    int initial:1;	/* Require AS_REQ */
	    int forwardable:1;	/* Ticket may be forwardable */
	    int renewable:1;	/* Ticket may be renewable */
	    int allow_postdate:1; /* Ticket may be postdated */
	    int server:1;	/* Principal may be server */
	    int locked:1;	/* Principal is locked */
	}b;
    }flags;
}hdb_entry;

typedef struct HDB{
    void *db;

    krb5_error_code (*close)(krb5_context, struct HDB*);
    krb5_error_code (*fetch)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*store)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*delete)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*firstkey)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*nextkey)(krb5_context, struct HDB*, hdb_entry*);
}HDB;

void hdb_free_entry(krb5_context, hdb_entry*);
krb5_error_code hdb_db_open(krb5_context, HDB**, const char*, int, mode_t);
krb5_error_code hdb_ndbm_open(krb5_context, HDB**, const char*, int, mode_t);
krb5_error_code hdb_open(krb5_context, HDB**, const char*, int, mode_t);

krb5_error_code hdb_etype2key(krb5_context, hdb_entry*, 
			      krb5_enctype, krb5_keyblock**);

#define HDB_DEFAULT_DB "heimdal"

#endif /* __HDB_H__ */

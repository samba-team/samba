/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

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
	    unsigned initial:1;	/* Require AS_REQ */
	    unsigned forwardable:1;	/* Ticket may be forwardable */
	    unsigned renewable:1;	/* Ticket may be renewable */
	    unsigned allow_postdate:1; /* Ticket may be postdated */
	    unsigned server:1;	/* Principal may be server */
	    unsigned locked:1;	/* Principal is locked */
	    unsigned v4:1;	/* Version 4 salted key */
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

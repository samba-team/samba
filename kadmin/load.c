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

#include "admin_locl.h"

RCSID("$Id$");

struct entry{
    char *principal;
    char *kvno;
    char *keytype;
    char *key;
    char *max_life;
    char *max_renew;
    char *last_change;
    char *changed_by;
    char *expires;
    char *flags;
};

static char *
skip_next(char *p)
{
    while(*p && !isspace(*p)) 
	p++;
    *p++ = 0;
    while(*p && isspace(*p)) p++;
    return p;
}

time_t
str2time(char *s)
{
    int year, month, date, hour, minute, second;
    struct tm tm;
    sscanf(s, "%04d%02d%02d%02d%02d%02d", 
	   &year, &month, &date, &hour, &minute, &second);
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = date;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = 0;
    return timegm(&tm);
}

static void
doit(char *filename, int merge)
{
#if 0
    FILE *f;
    HDB *db;
    char s[1024];
    char *p;
    int line;
    int err;
    int i;
    int flags = O_RDWR;

    struct entry e;
    hdb_entry ent;

    f = fopen(filename, "r");
    if(f == NULL){
	fprintf(stderr, "%s: %s\n", filename, strerror(errno));
	return;
    }
    if(!merge)
	flags |= O_CREAT | O_TRUNC;
    err = hdb_open(context, &db, database, flags, 0600);
    if(err){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, err));
	fclose(f);
	return;
    }
    line = 0;
    while(fgets(s, sizeof(s), f)){
	line++;
	e.principal = s;
	for(p = s; *p; p++){
	    if(*p == '\\')
		p++;
	    else if(isspace(*p)) {
		*p = 0;
		break;
	    }
	}
	p = skip_next(p);
	e.kvno = p;
	while(*p && isdigit(*p)) p++;
	*p++ = 0;
	e.keytype = p;
	while(*p && isdigit(*p)) p++;
	*p++ = 0;
	e.key = p;
	p = skip_next(p);

	e.max_life = p;
	p = skip_next(p);

	e.max_renew = p;
	p = skip_next(p);

	e.last_change = p;
	p = skip_next(p);

	e.changed_by = p;
	p = skip_next(p);

	e.expires = p;
	p = skip_next(p);

	e.flags = p;
	p = skip_next(p);

	{
	    krb5_principal p;
	    err = krb5_parse_name(context, e.principal, &p);
		if(err){
		    fprintf(stderr, "%s:%s:%s (%s)\n", 
			    filename, 
			    line,
			    krb5_get_err_text(context, err),
			    e.principal);
		    continue;
		}
		ent.principal = *p;
		free(p);
	}
	
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.data = malloc(strlen(e.key)/2+1);
	for(i = 0; i < strlen(e.key); i += 2){
	    unsigned tmp;
	    sscanf(e.key + i, "%2x", &tmp);
	    ((unsigned char *)ent.keyblock.keyvalue.data)[i/2] = tmp;
	}
	ent.keyblock.keyvalue.length = i / 2;
	ent.kvno = atoi(e.kvno);
	ent.max_life = atoi(e.max_life);
	ent.max_renew = atoi(e.max_renew);
	ent.last_change = str2time(e.last_change);
	krb5_parse_name(context, e.changed_by, &ent.changed_by);
	ent.expires = str2time(e.expires);
	ent.flags.i = atoi(e.flags); /* XXX */
	db->store(context, db, &ent);
	hdb_free_entry (context, &ent);
    }
    db->close(context, db);
    fclose(f);
#endif
}

int
load(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: load filename\n");
	return;
    }
    doit(argv[1], 0);
    return 0;
}

int
merge(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: merge filename\n");
	return;
    }
    doit(argv[1], 1);
    return 0;
}

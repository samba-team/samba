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
    char *key;
    char *kvno;
    char *max_life;
    char *max_renew;
};

static void
doit(char *filename, int merge)
{
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
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.key = p;
	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.kvno = p;

	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	while(*p && isspace(*p)) p++;
	e.max_life = p;

	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;
	e.max_renew = p;
	while(*p && !isspace(*p)) 
	    *p++;
	*p++ = 0;

	err = krb5_parse_name(context, e.principal, &ent.principal);
	if(err){
	    fprintf(stderr, "%s:%s:%s (%s)\n", 
		    filename, 
		    line,
		    krb5_get_err_text(context, err),
		    e.principal);
	    continue;
	}
	
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.data = malloc(strlen(e.key)/2+1);
	for(i = 1; i < strlen(e.key) - 1; i += 2){
	    unsigned tmp;
	    sscanf(e.key + i, "%2x", &tmp);
	    ((unsigned char *)ent.keyblock.keyvalue.data)[i/2] = tmp;
	}
	ent.keyblock.keyvalue.length = i / 2;
	ent.kvno = atoi(e.kvno);
	ent.max_life = atoi(e.max_life);
	ent.max_renew = atoi(e.max_renew);
	krb5_build_principal(context, &ent.changed_by,
			     0,
			     ""
			     "kadmin",
			     NULL);
	db->store(context, db, &ent);
	hdb_free_entry (context, &ent);
    }
    db->close(context, db);
    fclose(f);
}

void
load(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: load filename\n");
	return;
    }
    doit(argv[1], 0);
}

void
merge(int argc, char **argv)
{
    if(argc < 2){
	fprintf(stderr, "Usage: merge filename\n");
	return;
    }
    doit(argv[1], 1);
}

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

char *
time2str(time_t t)
{
    static char s[32];
    struct tm *tm;
    tm = gmtime(&t);
    strftime(s, sizeof(s), "%Y%m%d%H%M%S", tm);
    return s;
}

char *
key2str(krb5_keyblock *key)
{
    static char *s;
    unsigned char *p;
    int i;
    if(s)
	free(s);
    s = malloc(key->keyvalue.length*2+10);
    sprintf(s, "%d:", key->keytype);
    p = (unsigned char*)key->keyvalue.data;
    for(i = 0; i < key->keyvalue.length; i++)
	sprintf(s + strlen(s), "%02x", p[i]);
    return s;
}

void
dump(int argc, char **argv)
{
    HDB *db;
    hdb_entry ent;
    int err;
    int i;
    FILE *f;

    if(argc < 2)
	f = stdout;
    else
	f = fopen(argv[1], "w");
    

    err = hdb_open(context, &db, database, O_RDONLY, 0600);
    if(err){
	warnx("hdb_open: %s", krb5_get_err_text(context, err));
	if(f != stdout)
	    fclose(f);
	return;
    }
    err = db->firstkey(context, db, &ent);
    while(err == 0){
	char *p;
	krb5_unparse_name(context, ent.principal, &p);
	fprintf(f, "%s ", p);
	free(p);
	fprintf(f, "%d:%s", ent.kvno, key2str(&ent.keyblock));
	fprintf(f, " %d %d %s", 
		ent.max_life, 
		ent.max_renew, 
		time2str(ent.last_change));
	krb5_unparse_name(context, ent.changed_by, &p);
	fprintf(f, " %s %s %d\n", 
		p,
		time2str(ent.expires),
		ent.flags.i);
	free(p);
	hdb_free_entry(context, &ent);
	err = db->nextkey(context, db, &ent);
    }
    if(f != stdout)
	fclose(f);
    db->close(context, db);
}

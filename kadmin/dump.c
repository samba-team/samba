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

static void
append_hex(char *str, krb5_data *data)
{
    int i;
    char *p = malloc(data->length * 2 + 1);
    for(i = 0; i < data->length; i++)
	sprintf(p + 2 * i, "%02x", ((u_char*)data->data)[i]);
    strcat(str, p);
    free(p);
}

int
hdb_entry2string(hdb_entry *ent, char **str)
{
    char *p;
    char buf[1024] = "";
    int i, j;
    krb5_unparse_name(context, ent->principal, &p);
    strcat(buf, p);
    strcat(buf, " ");
    free(p);
    asprintf(&p, "%d", ent->kvno);
    strcat(buf, p);
    free(p);
    for(i = 0; i < ent->keys.len; i++){
	asprintf(&p, ":%d:%d:", 
		 ent->keys.val[i].mkvno, 
		 ent->keys.val[i].key.keytype);
	strcat(buf, p);
	free(p);
	append_hex(buf, &ent->keys.val[i].key.keyvalue);
	strcat(buf, ":");
	if(ent->keys.val[i].salt)
	    append_hex(buf, ent->keys.val[i].salt);
	else
	    strcat(buf, "-");
    }
    strcat(buf, " ");
    event2string(&ent->created_by, &p);
    strcat(buf, p);
    strcat(buf, " ");
    free(p);
    event2string(ent->modified_by, &p);
    strcat(buf, p);
    strcat(buf, " ");
    free(p);

    if(ent->valid_start)
	strcat(buf, time2str(*ent->valid_start));
    else
	strcat(buf, "-");

    strcat(buf, " ");
    if(ent->valid_end)
	strcat(buf, time2str(*ent->valid_end));
    else
	strcat(buf, "-");

    strcat(buf, " ");
    if(ent->pw_end)
	strcat(buf, time2str(*ent->pw_end));
    else
	strcat(buf, "-");

    strcat(buf, " ");
    if(ent->max_life){
	asprintf(&p, "%d", *ent->max_life);
	strcat(buf, p);
	free(p);
    }else
	strcat(buf, "-");

    strcat(buf, " ");
    if(ent->max_renew){
	asprintf(&p, "%d", *ent->max_renew);
	strcat(buf, p);
	free(p);
    }else
	strcat(buf, "-");
    
    strcat(buf, " ");
    asprintf(&p, "%d", flags2int(&ent->flags));
    strcat(buf, p);
    free(p);

    *str = strdup(buf);
    
    return 0;
}


int
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
	return 0;
    }
    err = db->firstkey(context, db, &ent);
    while(err == 0){
	char *p;
	hdb_entry2string(&ent, &p);
	fprintf(f, "%s\n", p);
	free(p);
	hdb_free_entry(context, &ent);
	err = db->nextkey(context, db, &ent);
    }
    if(f != stdout)
	fclose(f);
    db->close(context, db);
    return 0;
}

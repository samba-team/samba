/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#include <kadm5/private.h>

RCSID("$Id$");

/* 
   This is the present contents of a dump line. This might change at
   any time. Fields are separated by white space.

  principal
  keyblock
  	kvno
	keys...
		mkvno (unused)
		enctype
		keyvalue
		salt (- means use normal salt)
  creation date and principal
  modification date and principal
  principal valid from date (not used)
  principal valid end date (not used)
  principal key expires (not used)
  max ticket life
  max renewable life
  flags
  supported etypes
  */

static void
append_hex(char *str, krb5_data *data)
{
    int i, s = 1;
    char *p;

    p = data->data;
    for(i = 0; i < data->length; i++)
	if(!isalnum((unsigned char)p[i]) && p[i] != '.'){
	    s = 0;
	    break;
	}
    if(s){
	p = calloc(1, data->length + 2 + 1);
	p[0] = '\"';
	p[data->length + 1] = '\"';
	memcpy(p + 1, data->data, data->length);
    }else{
	p = calloc(1, data->length * 2 + 1);
	for(i = 0; i < data->length; i++)
	    sprintf(p + 2 * i, "%02x", ((u_char*)data->data)[i]);
    }
    strcat(str, p);
    free(p);
}

static char *
time2str(time_t t)
{
    static char buf[128];
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", gmtime(&t));
    return buf;
}

static void
event2string(Event *ev, char **str)
{
    char *p;
    char *pr;
    if(ev == NULL){
	*str = strdup("-");
	return;
    }
    krb5_unparse_name(context, ev->principal, &pr);
    asprintf(&p, "%s:%s", time2str(ev->time), pr);
    free(pr);
    *str = p;
}

static int
hdb_entry2string(hdb_entry *ent, char **str)
{
    char *p;
    char buf[1024] = "";
    int i;
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
#if 0
	if(ent->keys.val[i].enctypes != NULL) {
	    int j;
	    for(j = 0; j < ent->keys.val[i].enctypes->len; j++) {
		char tmp[16];
		snprintf(tmp, sizeof(tmp), "%u", 
			 ent->keys.val[i].enctypes->val[j]);
		if(j > 0)
		    strcat(buf, ",");
		strcat(buf, tmp);
	    }
	}
	strcat(buf, ":");
#endif
	append_hex(buf, &ent->keys.val[i].key.keyvalue);
	strcat(buf, ":");
	if(ent->keys.val[i].salt){
	    asprintf(&p, "%u/", ent->keys.val[i].salt->type);
	    strcat(buf, p);
	    free(p);
	    append_hex(buf, &ent->keys.val[i].salt->salt);
	}else
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
    asprintf(&p, "%d", HDBFlags2int(ent->flags));
    strcat(buf, p);
    free(p);
#if 0

    strcat(buf, " ");
    if(ent->etypes == NULL || ent->etypes->len == 0)
	strcat(buf, "-");
    else {
	for(i = 0; i < ent->etypes->len; i++){
	    asprintf(&p, "%u", ent->etypes->val[i]);
	    strcat(buf, p);
	    free(p);
	    if(i != ent->etypes->len - 1)
		strcat(buf, ":");
	}
    }
#endif

    *str = strdup(buf);
    
    return 0;
}

static krb5_error_code
print_entry(krb5_context context, HDB *db, hdb_entry *entry, void *data)
{
    char *p;
    hdb_entry2string(entry, &p);
    fprintf((FILE*)data, "%s\n", p);
    free(p);
    return 0;
}


int
dump(int argc, char **argv)
{
    krb5_error_code ret;
    FILE *f;

    HDB *db = _kadm5_s_get_db(kadm_handle);

    if(argc < 2)
	f = stdout;
    else
	f = fopen(argv[1], "w");
    
    ret = db->open(context, db, O_RDONLY, 0600);
    if(ret){
	krb5_warn(context, ret, "hdb_open");
	if(f != stdout)
	    fclose(f);
	return 0;
    }

    hdb_foreach(context, db, print_entry, f);

    if(f != stdout)
	fclose(f);
    db->close(context, db);
    return 0;
}

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
doit2(HDB *db, hdb_entry *ent, int mod)
{
    int ret;
    hdb_entry def;
    int32_t tmp;
    char buf[1024];
    int i;
    
    ret = db->fetch(context, db, ent);
    
    switch(ret){
    case KRB5_HDB_NOENTRY:
	if(mod){
	    fprintf(stderr, "Entry not found in database\n");
	    return;
	}else{
	    krb5_realm *realm;
	    krb5_principal def_principal;

	    realm = krb5_princ_realm(context, ent->principal);
	    krb5_build_principal(context, &def_principal, 
				 strlen(*realm),
				 *realm,
				 "default",
				 NULL);
	    def.principal = def_principal;
	    if(db->fetch(context, db, &def)){
		/* XXX */
	    }
	    krb5_free_principal (context, def_principal);
	    memset(&ent->flags, 0, sizeof(ent->flags));
	    ent->flags.client = 1;
	    ent->flags.server = 1;
	    ent->flags.forwardable = 1;
	    ent->flags.proxiable = 1;
	    ent->flags.renewable = 1;
	    ent->flags.postdate = 1;
	    ent->max_life = malloc(sizeof(*ent->max_life));
	    *ent->max_life = *def.max_life;
	    ent->max_renew = malloc(sizeof(*ent->max_renew));
	    *ent->max_renew = *def.max_renew;
 	    hdb_free_entry(context, &def);
	    break;
	}
    case 0:
	if(!mod){
	    warnx("Principal exists");
	    return;
	}
	break;
    default:
	errx(1, "dbget: %s", krb5_get_err_text(context, ret));
    }
    {
	time_t t;
	if(ent->max_life){
	    char buf[128];
	    unparse_time (*ent->max_life, buf, sizeof(buf));
	    t = gettime ("Max ticket life", buf);
	}else{
	    t = gettime ("Max ticket life", "unlimited");
	}
	if(t){
	    if(ent->max_life == NULL)
		ent->max_life = malloc(sizeof(*ent->max_life));
	    *ent->max_life = t;
	}else if(ent->max_life){
	    free(ent->max_life);
	    ent->max_life = NULL;
	}
	if(ent->max_renew){
	    char buf[128];
	    unparse_time (*ent->max_renew, buf, sizeof(buf));
	    t = gettime ("Max renewable life", buf);
	}else{
	    t = gettime ("Max renewable life", "unlimited");
	}
	if(t){
	    if(ent->max_renew == NULL)
		ent->max_renew = malloc(sizeof(*ent->max_renew));
	    *ent->max_renew = t;
	}else if(ent->max_renew){
	    free(ent->max_renew);
	    ent->max_renew = NULL;
	}
    }
    while(mod){
	fprintf(stderr, "Change password? (y/n) ");
	fgets(buf, sizeof(buf), stdin);
	if(buf[0] == 'n' || buf[0] == 'y')
	    break;
	fprintf(stderr, "Please answer yes or no.\n");
    }
    if(mod == 0 || buf[0] == 'y'){
	krb5_data salt;
	des_read_pw_string(buf, sizeof(buf), "Password:", 1);
	for (i = 0; i < ent->keys.len; ++i)
	    free_Key (&ent->keys.val[i]);
	free (ent->keys.val);
	if(strcasecmp(buf, "random") == 0) {
	    ent->keys.len = 0;
	    ent->keys.val = NULL;
	    init_des_key(ent);
	} else{
	    ent->keys.len = 1;
	    ent->keys.val = calloc(1, sizeof(*ent->keys.val));
	    set_keys(ent, buf);
	}
    }
    {
	Event *ev;
	krb5_realm *realm;
	ev = malloc(sizeof(*ev));
	ev->time = time(NULL);
	realm = krb5_princ_realm(context, ent->principal);
	
	krb5_build_principal(context, &ev->principal,
			     strlen(*realm),
			     *realm,
			     "kadmin",
			     NULL);
	if(mod){
	    if(ent->modified_by){
		free_Event(ent->modified_by);
		free(ent->modified_by);
	    }
	    ent->modified_by = ev;
	}else{
	    ent->created_by = *ev;
	    free(ev);
	}
    }
    ret = db->store(context, db, ent);
    if(ret == -1){
	perror("dbput");
	exit(1);
    }
}

void
doit(const char *principal, int mod)
{
    HDB *db;
    hdb_entry ent;
    krb5_error_code ret;
    memset(&ent, 0, sizeof(ent));
    if((ret = hdb_open(context, &db, database, O_RDWR, 0600))){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, ret));
	return;
    }
    krb5_parse_name(context, principal, &ent.principal);
    
    doit2(db, &ent, mod);
    db->close(context, db);
    hdb_free_entry(context, &ent);
}
    


int
add_new_key(int argc, char **argv)
{
    if(argc != 2){
	fprintf(stderr, "Usage: add_new_key principal\n");
	return 0;
    }

    doit(argv[1], 0);
    return 0;
}

int
mod_entry(int argc, char **argv)
{
    if(argc != 2){
	fprintf(stderr, "Usage: mod_entry principal\n");
	return 0;
    }

    doit(argv[1], 1);
    return 0;
}

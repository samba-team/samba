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
doit(char *principal, int mod)
{
    HDB *db;
    int err;
    hdb_entry ent;
    hdb_entry def;
    int32_t tmp;
    char buf[1024];
    
    krb5_parse_name(context, principal, &ent.principal);
    
    if((err = hdb_open(context, &db, database, O_RDWR, 0600))){
	fprintf(stderr, "hdb_open: %s\n", krb5_get_err_text(context, err));
	return;
    }
    
    err = db->fetch(context, db, &ent);
    
    switch(err){
    case KRB5_HDB_NOENTRY:
	if(mod){
	    fprintf(stderr, "Entry not found in database\n");
	    goto out;
	}else{
	    krb5_realm *realm;
	    
	    realm = krb5_princ_realm(context, ent.principal);
	    krb5_build_principal(context, &def.principal, 
				 strlen(*realm),
				 *realm,
				 "default",
				 NULL);
	    if(db->fetch(context, db, &def)){
		/* XXX */
	    }
	    ent.flags.i = 0;
	    ent.kvno = 0;
	    ent.max_life = def.max_life;
	    ent.max_renew = def.max_renew;
	    ent.expires = def.expires;
	    hdb_free_entry(context, &def);
	    if(ent.expires)
		ent.expires += time(NULL);
	    break;
	}
    case 0:
	if(!mod){
	    warnx("Principal exists");
	    goto out;
	}
	break;
    default:
	errx(1, "dbget: %s", krb5_get_err_text(context, err));
    }
    printf("Max ticket life [%d]: ", ent.max_life);
    fgets(buf, sizeof(buf), stdin);
    if(sscanf(buf, "%d", &tmp) == 1)
	ent.max_life = tmp;
    printf("Max renewable ticket [%d]: ", ent.max_renew);
    fgets(buf, sizeof(buf), stdin);
    if(sscanf(buf, "%d", &tmp) == 1)
	ent.max_renew = tmp;
    while(mod){
	fprintf(stderr, "Change password? (y/n) ");
	fgets(buf, sizeof(buf), stdin);
	if(buf[0] == 'n' || buf[0] == 'y')
	    break;
	else {
	    fprintf(stderr, "Please answer yes or no.\n");
	    continue;
	}
    }
    if(mod == 0 || buf[0] == 'y'){
	krb5_data salt;
	des_read_pw_string(buf, sizeof(buf), "Password:", 1);
	if(strcasecmp(buf, "random") == 0)
	    krb5_generate_random_keyblock(context,
					  KEYTYPE_DES,
					  &ent.keyblock);
	else{
	    memset(&salt, 0, sizeof(salt));
	    krb5_get_salt(ent.principal, &salt);
	    memset(&ent.keyblock, 0, sizeof(ent.keyblock));
	    krb5_string_to_key(buf, &salt, &ent.keyblock);
	    krb5_data_free(&salt);
	}
	ent.kvno++;
    }
    ent.last_change = time(NULL);
    {
	krb5_realm *realm = krb5_princ_realm(context, ent.principal);
	
	krb5_build_principal(context, &ent.changed_by,
			     strlen(*realm),
			     *realm,
			     "kadmin",
			     NULL);
    }
    err = db->store(context, db, &ent);
    if(err == -1){
	perror("dbput");
	exit(1);
    }
    hdb_free_entry(context, &ent);
out:
    db->close(context, db);
}


int
add_new_key(int argc, char **argv)
{
    if(argc != 2){
	fprintf(stderr, "Usage: add_new_key principal\n");
	return;
    }

    doit(argv[1], 0);
    return 0;
}

int
mod_entry(int argc, char **argv)
{
    if(argc != 2){
	fprintf(stderr, "Usage: mod_entry principal\n");
	return;
    }

    doit(argv[1], 1);
    return 0;
}

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

time_t
get_time(const char *prompt, time_t def)
{
    char buf[1024];
    int tmp;
    
    while(1){
	if(def == 0)
	    printf("%s: [infinite] ", prompt);
	else
	    printf("%s: [%d] ", prompt, def);
	fgets(buf, sizeof(buf), stdin);
	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = 0;
	if(buf[0] == 0)
	    return def;
	if(strncmp(buf, "infinite", strlen(buf)) == 0)
	    return 0;
	if(sscanf(buf, "%d", &tmp) == 1)
	    return tmp;
	printf("Please specify a number\n");
    }
}


void
init(int argc, char **argv)
{
    HDB *db;
    char s[1024];
    char *p;
    int line;
    int err;
    int i;

    int tmp;
    int default_life = 86400;
    int default_renew = 5 * 86400;
    int max_life = 0;
    int max_renew = 0;
    
    hdb_entry ent;

    err = hdb_open(context, &db, database, O_RDWR | O_CREAT, 0600);
    if(err){
	warnx("hdb_open: %s", krb5_get_err_text(context, err));
	return;
    }
    memset(&ent, 0, sizeof(ent));
    for(i = 1; i < argc; i++){
	krb5_build_principal(context, &ent.principal, 
			     strlen(argv[i]), argv[i], 
			     "krbtgt",
			     argv[i],
			     NULL);
	err = db->fetch(context, db, &ent);
	switch(err){
	case 0:
	    fprintf(stderr, "Entry already exists\n");
	    krb5_free_principal(context, ent.principal);
	    continue;
	case KRB5_HDB_NOENTRY:
	    break;
	default:
	    warnx("hdb_fetch: %s", krb5_get_err_text(context, err));
	    db->close(context, db);
	    return;
	}
	
	max_life = get_time("Realm max ticket life", max_life);
	max_renew = get_time("Realm max renewable ticket life", max_renew);
	default_life = get_time("Default ticket life", default_life);
	default_renew = get_time("Default renewable ticket life", 
				 default_renew);
	
	
	/* Create `krbtgt/REALM' */
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.length = 8;
	ent.keyblock.keyvalue.data = malloc(ent.keyblock.keyvalue.length);
	des_new_random_key(ent.keyblock.keyvalue.data);
	ent.kvno = 1;
	ent.max_life = max_life;
	ent.max_renew = max_renew;
	ent.last_change = time(NULL);
	krb5_build_principal(context, &ent.changed_by, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.expires = 0;
	ent.flags.b.forwardable = 1;
	ent.flags.b.renewable = 1;
	ent.flags.b.server = 1;
	db->store(context, db, &ent);
	hdb_free_entry(context, &ent);

	/* Create `default' */
	memset(&ent, 0, sizeof(ent));
	krb5_build_principal(context, &ent.principal,
			     strlen(argv[i]), argv[i],
			     "default",
			     NULL);
	ent.keyblock.keytype = KEYTYPE_DES;
	ent.keyblock.keyvalue.length = 0;
	ent.keyblock.keyvalue.data = NULL;
	ent.kvno = 1;
	ent.max_life = default_life;
	ent.max_renew = default_renew;
	ent.last_change = time(NULL);
	krb5_build_principal(context, &ent.changed_by, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.expires = 0;
	ent.flags.b.locked = 1;
	db->store(context, db, &ent);
	hdb_free_entry(context, &ent);
    }
    db->close(context, db);
}

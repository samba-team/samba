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

int
init(int argc, char **argv)
{
    krb5_error_code ret;
    int i;

    int default_life = 86400;
    int default_renew = 5 * 86400;
    int max_life = 0;
    int max_renew = 0;
    
    hdb_entry ent;

    ret = db->open(context, db, O_RDWR | O_CREAT, 0600);
    if(ret){
	krb5_warn(context, ret, "hdb_open");
	return 0;
    }
    memset(&ent, 0, sizeof(ent));
    for(i = 1; i < argc; i++){
	krb5_build_principal(context, &ent.principal, 
			     strlen(argv[i]), argv[i], 
			     "krbtgt",
			     argv[i],
			     NULL);
	ret = db->fetch(context, db, &ent);
	switch(ret){
	case 0:
	    krb5_warnx(context, "Entry already exists");
	    krb5_free_principal(context, ent.principal);
	    continue;
	case HDB_ERR_NOENTRY:
	    break;
	default:
	    krb5_warn(context, ret, "hdb_fetch");
	    db->close(context, db);
	    return 0;
	}
	
	max_life = getlife("Realm max ticket life", "infinite");
	max_renew = getlife("Realm max renewable ticket life", "infinite");
	default_life = getlife("Default ticket life", "1 day");
	default_renew = getlife("Default renewable ticket life", "7 days");
	
	/* Create `krbtgt/REALM' */
	init_des_key(&ent);
	ent.kvno = 1;
	if(max_life){
	    ent.max_life = malloc(sizeof(*ent.max_life));
	    *ent.max_life = max_life;
	}
	if(max_renew){
	    ent.max_renew = malloc(sizeof(*ent.max_renew));
	    *ent.max_renew = max_renew;
	}
	ent.created_by.time = time(NULL);
	krb5_build_principal(context, &ent.created_by.principal,
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.flags.forwardable = 1;
	ent.flags.proxiable = 1;
	ent.flags.renewable = 1;
	ent.flags.postdate = 1;
	ent.flags.server = 1;
	db->store(context, db, 1, &ent);
	hdb_free_entry(context, &ent);

	/* Create `default' */
	memset(&ent, 0, sizeof(ent));
	krb5_build_principal(context, &ent.principal,
			     strlen(argv[i]), argv[i],
			     "default",
			     NULL);
	if(default_life){
	    ent.max_life = malloc(sizeof(*ent.max_life));
	    *ent.max_life = default_life;
	}
	if(default_renew){
	    ent.max_renew = malloc(sizeof(*ent.max_renew));
	    *ent.max_renew = default_renew;
	}
	ent.created_by.time = time(NULL);
	krb5_build_principal(context, &ent.created_by.principal, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.flags.invalid = 1;
	db->store(context, db, 1, &ent);
	hdb_free_entry(context, &ent);

	/* Create `kadmin/changepw' */
	memset(&ent, 0, sizeof(ent));
	init_des_key(&ent);
	ent.kvno = 1;
	krb5_build_principal(context, &ent.principal,
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     "changepw",
			     NULL);
	if(default_life){
	    ent.max_life = malloc(sizeof(*ent.max_life));
	    *ent.max_life = default_life;
	}
	if(default_renew){
	    ent.max_renew = malloc(sizeof(*ent.max_renew));
	    *ent.max_renew = default_renew;
	}
	ent.created_by.time = time(NULL);
	krb5_build_principal(context, &ent.created_by.principal, 
			     strlen(argv[i]), argv[i],
			     "kadmin",
			     NULL);
	ent.flags.initial   = 1;
	ent.flags.server    = 1;
	ent.flags.change_pw = 1;
	db->store(context, db, 1, &ent);
	hdb_free_entry(context, &ent);
    }
    db->close(context, db);
    return 0;
}

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
doit2(HDB *db, hdb_entry *ent)
{
    char buf[1024];
    int ret;
    krb5_principal hata;
    
    hata = ent->principal;

    ret = db->fetch(context, db, ent);

    switch(ret){
    case HDB_ERR_NOENTRY:
	krb5_warnx(context, "Entry not found in database");
	return;
    case 0:
	krb5_free_principal (context, hata);
	break;
    default:
	krb5_err(context, 1, ret, "dbget");
    }
    
    edit_entry (ent);
    for(;;) {
	fprintf(stderr, "Change password? (y/n) ");
	fgets(buf, sizeof(buf), stdin);
	if(buf[0] == 'n' || buf[0] == 'y' || buf[0] == 'N' || buf[0] == 'Y')
	    break;
	fprintf(stderr, "Please answer yes or no.\n");
    }
    if(buf[0] == 'y' || buf[0] == 'Y')
	if(set_password (ent))
	    return;
	    
    set_modified_by (ent);
    
    ret = db->store(context, db, 1, ent);
    if(ret)
	krb5_err(context, 1, ret, "db->store");
}

static void
doit(const char *principal)
{
    hdb_entry ent;
    krb5_error_code ret;

    memset(&ent, 0, sizeof(ent));
    ret = db->open(context, db, O_RDWR, 0600);
    if(ret) {
	krb5_warn(context, ret, "hdb_open");
	return;
    }
    krb5_parse_name(context, principal, &ent.principal);
    
    doit2(db, &ent);
    db->close(context, db);
    hdb_free_entry(context, &ent);
}
    
int
mod_entry(int argc, char **argv)
{
    if(argc != 2) {
	krb5_warnx(context, "Usage: mod_entry principal");
	return 0;
    }

    doit(argv[1]);
    return 0;
}

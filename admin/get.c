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
get_entry(int argc, char **argv)
{
    krb5_error_code ret;
    hdb_entry ent;
    int i;
    krb5_principal principal;
    
    if(argc != 2) {
	krb5_warnx(context, "Usage: get_entry principal");
	return 0;
    }
	
    ret = db->open(context, db, O_RDONLY, 0600);
    if(ret) {
	krb5_warn(context, ret, "hdb_open");
	return 0;
    }
    
    krb5_parse_name(context, argv[1], &principal);

    memset (&ent, 0, sizeof(ent));

    ent.principal = principal;
    
    ret = db->fetch(context, db, &ent);
    
    switch(ret){
    case HDB_ERR_NOENTRY:
	krb5_warnx(context, "Entry not found in database\n");
	break;
    case 0: {
	char buf[128];
	char *name;

	krb5_free_principal(context, principal);

	krb5_unparse_name(context, ent.principal, &name);
	printf("Principal: %s\n", name);
	free(name);
	if (ent.max_life)
	    putlife (*ent.max_life, buf, sizeof(buf));
	else
	    strcpy (buf, "infinite");
	printf("Max ticket life: %s\n", buf);
	if (ent.max_renew)
	    putlife (*ent.max_renew, buf, sizeof(buf));
	else
	    strcpy (buf, "infinite");
	printf("Max renewable ticket life: %s\n", buf);
	if (ent.created_by.principal)
	    krb5_unparse_name (context, ent.created_by.principal, &name);
	else
	    name = NULL;
	printf("Created by %s at %s\n",
	       name ? name : "<unknown>",
	       time2str(ent.created_by.time));
	free (name);
	if (ent.modified_by) {
	    if (ent.modified_by->principal)
		krb5_unparse_name (context, ent.modified_by->principal, &name);
	    else
		name = NULL;
	    printf("Last modified by %s at %s\n",
		   name ? name : "<unknown>",
		   time2str(ent.modified_by->time));
	    free (name);
	}
	if (ent.valid_start) {
	    printf("Valid from %s\n", time2str(*ent.valid_start));
	}
	if (ent.valid_end) {
	    printf("Valid till %s\n", time2str(*ent.valid_end));
	}
	if (ent.pw_end) {
	    printf("Password expires at %s\n", time2str(*ent.pw_end));
	}
	printf("Kvno: %d\n", ent.kvno);
	printf("Keys: ");
	for(i = 0; i < ent.keys.len; i++){
	    if(i) printf(", ");
	    printf("type = %d, len = %d", ent.keys.val[i].key.keytype,
		   ent.keys.val[i].key.keyvalue.length);
	}
	printf("\nFlags: ");
	print_hdbflags (stdout, ent.flags);
	printf("\n");
	break;
    }
    default:
	krb5_warn(context, ret, "db->fetch");
	break;
    }
    hdb_free_entry (context, &ent);
    db->close(context, db);
    return 0;
}

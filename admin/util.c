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

void
init_des_key(hdb_entry *ent)
{
    Key *k;
    ent->keys.val = realloc(ent->keys.val, 
			    (ent->keys.len + 1) * sizeof(*ent->keys.val));
    k = ent->keys.val + ent->keys.len;
    ent->keys.len++;
    k->mkvno = 0;
    krb5_generate_random_keyblock(context, KEYTYPE_DES, &k->key);
}

void
set_keys(hdb_entry *ent, char *password)
{
    krb5_data salt;
    int i;
    memset(&salt, 0, sizeof(salt));
    krb5_get_salt(ent->principal, &salt);
    for(i = 0; i < ent->keys.len; i++)
	krb5_string_to_key(password, &salt, &ent->keys.val[i].key); /* XXX */
    krb5_data_free(&salt);
    ent->kvno++;
}    

char *
time2str(time_t t)
{
    static char buf[128];
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", gmtime(&t));
    return buf;
}

void
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

int
flags2int(HDBFlags *f)
{
    return (f->initial  << 0) |
	(f->forwardable << 1) |
	(f->proxiable   << 2) |
	(f->renewable   << 3) |
	(f->postdate    << 4) |
	(f->server      << 5) |
	(f->client      << 6) |
	(f->invalid     << 7);
}


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
#include <parse_units.h>

static void
add_key(Key *k, krb5_keytype keytype)
{
    memset(k, 0, sizeof(*k));
    krb5_generate_random_keyblock(context, keytype, &k->key);
}

void
init_des_key(hdb_entry *ent)
{
    Key *k;

    ent->keys.val = realloc(ent->keys.val, 
			    (ent->keys.len + 2) * sizeof(*ent->keys.val));
    k = ent->keys.val + ent->keys.len;
    ent->keys.len += 2;
    ent->kvno++;

    add_key(k++, KEYTYPE_DES);
    add_key(k++, KEYTYPE_DES3);
}

void
set_keys(hdb_entry *ent, char *password)
{
    krb5_data salt;
    int i;

    memset(&salt, 0, sizeof(salt));
    krb5_get_salt(ent->principal, &salt); /* XXX */
    for(i = 0; i < ent->keys.len; i++) {
	krb5_string_to_key(password, &salt, ent->keys.val[i].key.keytype,
			   &ent->keys.val[i].key);
    }
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

void
print_hdbflags (FILE *fp, HDBFlags flags)
{
    char buf[1024];

    unparse_flags (HDBFlags2int(flags), HDBFlags_units, buf, sizeof(buf));
    fprintf (fp, "%s", buf);
}

int
parse_hdbflags (const char *s, HDBFlags *flags)
{
    int t;

    t = parse_flags (s, HDBFlags_units, HDBFlags2int(*flags));
    if (t < 0)
	return t;
    else {
	*flags = int2HDBFlags(t);
	return 0;
    }
}

void
init_entry (HDB *db, hdb_entry *ent)
{
    krb5_realm *realm;
    krb5_principal def_principal;
    hdb_entry def;

    realm = krb5_princ_realm(context, ent->principal);
    krb5_build_principal(context, &def_principal, 
			 strlen(*realm),
			 *realm,
			 "default",
			 NULL);
    def.principal = def_principal;
    if(db->fetch(context, db, &def)) {
	krb5_free_principal(context, def_principal);
	krb5_make_principal(context, &def_principal, NULL, "default", NULL);
	def.principal = def_principal;
	if(db->fetch(context, db, &def)){
	    krb5_warnx(context, "No `default' entry found. "
		       "(have you initialised the database?)");
	    memset(&def, 0, sizeof(def));
	}else
	    krb5_warnx(context, "No `default' principal found for %s, "
		       "using local realms default.", *realm);
    }
    krb5_free_principal (context, def_principal);
    ent->flags.client = 1;
    ent->flags.server = 1;
    ent->flags.forwardable = 1;
    ent->flags.proxiable = 1;
    ent->flags.renewable = 1;
    ent->flags.postdate = 1;
    if(def.max_life){
	ent->max_life = malloc(sizeof(*ent->max_life));
	*ent->max_life = *def.max_life;
    }
    if(def.max_renew){
	ent->max_renew = malloc(sizeof(*ent->max_renew));
	*ent->max_renew = *def.max_renew;
    }
    hdb_free_entry(context, &def);
}

static void
set_event (hdb_entry *ent, Event *ev)
{
    krb5_realm *realm;

    ev->time = time(NULL);
    realm = krb5_princ_realm(context, ent->principal);
	
    krb5_build_principal(context, &ev->principal,
			 strlen(*realm),
			 *realm,
			 "kadmin",
			 NULL);
}

void
set_created_by (hdb_entry *ent)
{
    set_event (ent, &ent->created_by);
}

void
set_modified_by (hdb_entry *ent)
{
    if (ent->modified_by)
	free_Event(ent->modified_by);
    else
	ent->modified_by = malloc(sizeof(*ent->modified_by));
    set_event (ent, ent->modified_by);
}

static void
get_life (const char *name, unsigned **v)
{
    char buf[128];
    time_t t;

    if (*v) {
	unparse_time (**v, buf, sizeof(buf));
	t = getlife (name, buf);
    } else {
	t = getlife (name, "unlimited");
    }
    if (t) {
	if(*v == NULL)
	    *v = malloc(sizeof(**v));
	**v = t;
    } else if(*v) {
	free(*v);
	*v = NULL;
    }
}

static void
get_time (const char *name, time_t **v)
{
    /* XXX */
}

static void
get_flags(const char *name, HDBFlags *flags)
{
    char buf[1024];

    fprintf (stderr, "%s [", name);
    print_hdbflags (stderr, *flags);
    fprintf (stderr, "]: ");
    if(fgets(buf, sizeof(buf), stdin) == NULL)
	return;
    buf[strlen(buf) - 1] = '\0';
    if(*buf != '\0')
	parse_hdbflags(buf, flags);
}

void
edit_entry(hdb_entry *ent)
{
    get_time ("Valid start",  &ent->valid_start);
    get_time ("Valid end",    &ent->valid_end);
    get_time ("Password end", &ent->pw_end);
    get_life ("Max ticket life", &ent->max_life);
    get_life ("Max renewable life", &ent->max_renew);
    get_flags ("Flags", &ent->flags);
}

int
set_password(hdb_entry *ent)
{
    char buf[128];
    int i;

    if(des_read_pw_string(buf, sizeof(buf), "Password:", 1))
	return -1;
    for (i = 0; i < ent->keys.len; ++i)
	free_Key (&ent->keys.val[i]);
    free (ent->keys.val);
    ent->keys.len = 2;
    ent->keys.val = calloc(2, sizeof(*ent->keys.val));
    ent->keys.val[0].key.keytype = KEYTYPE_DES;
    ent->keys.val[1].key.keytype = KEYTYPE_DES3;
    set_keys(ent, buf);
    return 0;
}

int
set_random_key(hdb_entry *ent)
{
    int i;

    for (i = 0; i < ent->keys.len; ++i)
	free_Key (&ent->keys.val[i]);
    free (ent->keys.val);

    ent->keys.len = 0;
    ent->keys.val = NULL;
    init_des_key(ent);
    return 0;
}

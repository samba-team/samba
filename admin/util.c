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
    memset(k, 0, sizeof(*k));
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

/*
 * Perhaps this should not be a struct of bit-fields or rather a union
 * of an int and a struct of bit-fields.
 */

int
flags2int(HDBFlags *f)
{
    return (f->initial      << 0) |
	(f->forwardable     << 1) |
	(f->proxiable       << 2) |
	(f->renewable       << 3) |
	(f->postdate        << 4) |
	(f->server          << 5) |
	(f->client          << 6) |
	(f->invalid         << 7) |
	(f->require_preauth << 8) |
	(f->change_pw       << 9);
}

static struct flag_name {
    const char *name;
    int val;
} flag_names[] = {
    {"initial",		0},
    {"forwardable",	1},
    {"proxiable",	2},
    {"renewable",	3},
    {"postdate",	4},
    {"server",		5},
    {"client",		6},
    {"invalid",		7},
    {"require_preauth",	8},
    {"change_pw",	9},
    {NULL,		0}
};

void
print_flags (FILE *fp, HDBFlags *flags)
{
    struct flag_name *f;
    int first_flag = 1;
    int n = flags2int (flags);

    for(f = flag_names; f->name != NULL; ++f)
	if (n & f->val) {
	    if(!first_flag)
		fprintf(fp, ", ");
	    fprintf(fp, "%s", f->name);
	    first_flag = 0;
	}
}

int
parse_flags (const char *s, HDBFlags *flags)
{
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

void
edit_entry(hdb_entry *ent)
{
    get_time ("Valid start",  &ent->valid_start);
    get_time ("Valid end",    &ent->valid_end);
    get_time ("Password end", &ent->pw_end);
    get_life ("Max ticket life", &ent->max_life);
    get_life ("Max renewable life", &ent->max_renew);
    /* flags */
}

void
set_password(hdb_entry *ent)
{
    char buf[128];
    int i;

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

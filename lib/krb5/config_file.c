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

#include "krb5_locl.h"
RCSID("$Id$");

/*
 * Netinfo implementation from Luke Howard <lukeh@xedoc.com.au>
 */

#ifdef HAVE_NETINFO_NI_H
#include <netinfo/ni.h>
static ni_status
ni_proplist2binding(ni_proplist *pl, krb5_config_section **ret)
{
    int i, j;
    krb5_config_section **next = NULL;

    for (i = 0; i < pl->ni_proplist_len; i++) {
	if (!strcmp(pl->nipl_val[i].nip_name, "name"))
	    continue;

	for (j = 0; j < pl->nipl_val[i].nip_val.ni_namelist_len; j++) {
	    krb5_config_binding *b;

	    b = malloc(sizeof(*b));
	    if (b == NULL)
		return NI_FAILED;
	
	    b->next = NULL;
	    b->type = krb5_config_string;
	    b->name = ni_name_dup(pl->nipl_val[i].nip_name);
	    b->u.string = ni_name_dup(pl->nipl_val[i].nip_val.ninl_val[j]);

	    if (next == NULL) {
		*ret = b;
	    } else {
		*next = b;
	    }
	    next = &b->next;
	}
    }
    return NI_OK;
}

static ni_status
ni_idlist2binding(void *ni, ni_idlist *idlist, krb5_config_section **ret)
{
    int i;
    ni_status nis;
    krb5_config_section **next;

    for (i = 0; i < idlist->ni_idlist_len; i++) {
	ni_proplist pl;
        ni_id nid;
	ni_idlist children;
	krb5_config_binding *b;
	ni_index index;

	nid.nii_instance = 0;
	nid.nii_object = idlist->ni_idlist_val[i];

	nis = ni_read(ni, &nid, &pl);

	if (nis != NI_OK) {
	     return nis;
	}
	index = ni_proplist_match(pl, "name", NULL);
	b = malloc(sizeof(*b));
	if (b == NULL) return NI_FAILED;

	if (i == 0) {
	    *ret = b;
	} else {
	    *next = b;
	}

	b->type = krb5_config_list;
	b->name = ni_name_dup(pl.nipl_val[index].nip_val.ninl_val[0]);
	b->next = NULL;
	b->u.list = NULL;

	/* get the child directories */
	nis = ni_children(ni, &nid, &children);
	if (nis == NI_OK) {
	    nis = ni_idlist2binding(ni, &children, &b->u.list);
	    if (nis != NI_OK) {
		return nis;
	    }
	}

	nis = ni_proplist2binding(&pl, b->u.list == NULL ? &b->u.list : &b->u.list->next);
	ni_proplist_free(&pl);
	if (nis != NI_OK) {
	    return nis;
	}
	next = &b->next;
    }
    ni_idlist_free(idlist);
    return NI_OK;
}

krb5_error_code
krb5_config_parse_file (const char *fname, krb5_config_section **res)
{
    void *ni = NULL, *lastni = NULL;
    int i;
    ni_status nis;
    ni_id nid;
    ni_idlist children;

    krb5_config_section *s;
    int ret;

    s = NULL;

    for (i = 0; i < 256; i++) {
	if (i == 0) {
	    nis = ni_open(NULL, ".", &ni);
	} else {
	    if (lastni != NULL) ni_free(lastni);
	    lastni = ni;
	    nis = ni_open(lastni, "..", &ni);
	}
	if (nis != NI_OK)
	    break;
	nis = ni_pathsearch(ni, &nid, "/locations/kerberos");
	if (nis == NI_OK) {
	    nis = ni_children(ni, &nid, &children);
	    if (nis != NI_OK)
		break;
	    nis = ni_idlist2binding(ni, &children, &s);
	    break;
	}
    }

    if (ni != NULL) ni_free(ni);
    if (ni != lastni && lastni != NULL) ni_free(lastni);

    ret = (nis == NI_OK) ? 0 : -1;
    if (ret == 0) {
	*res = s;
    } else {
	*res = NULL;
    }
    return ret;
}
#else /* !NETINFO_NI_H */

static int parse_section(char *p, krb5_config_section **s,
			 krb5_config_section **res);
static int parse_binding(FILE *f, unsigned *lineno, char *p,
			 krb5_config_binding **b,
			 krb5_config_binding **parent);
static int parse_list(FILE *f, unsigned *lineno, krb5_config_binding **parent);

static int
parse_section(char *p, krb5_config_section **s, krb5_config_section **parent)
{
    char *p1;
    krb5_config_section *tmp;

    p1 = strchr (p + 1, ']');
    if (p1 == NULL)
	return -1;
    *p1 = '\0';
    tmp = malloc(sizeof(*tmp));
    if (tmp == NULL)
	return -1;
    tmp->name = strdup(p+1);
    if (tmp->name == NULL)
	return -1;
    tmp->type = krb5_config_list;
    tmp->u.list = NULL;
    tmp->next = NULL;
    if (*s)
	(*s)->next = tmp;
    else
	*parent = tmp;
    *s = tmp;
    return 0;
}

static int
parse_list(FILE *f, unsigned *lineno, krb5_config_binding **parent)
{
    char buf[BUFSIZ];
    int ret;
    krb5_config_binding *b = NULL;

    for (; fgets(buf, sizeof(buf), f) != NULL; ++*lineno) {
	char *p;

	if (buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';')
	    continue;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '}')
	    return 0;
	ret = parse_binding (f, lineno, p, &b, parent);
	if (ret)
	    return ret;
    }
    return -1;
}

static int
parse_binding(FILE *f, unsigned *lineno, char *p,
	      krb5_config_binding **b, krb5_config_binding **parent)
{
    krb5_config_binding *tmp;
    char *p1;
    int ret = 0;

    p1 = p;
    while (*p && !isspace((unsigned char)*p))
	++p;
    if (*p == '\0')
	return -1;
    *p = '\0';
    tmp = malloc(sizeof(*tmp));
    if (tmp == NULL)
	return -1;
    tmp->name = strdup(p1);
    tmp->next = NULL;
    ++p;
    while (isspace((unsigned char)*p))
	++p;
    if (*p != '=')
	return -1;
    ++p;
    while(isspace((unsigned char)*p))
	++p;
    if (*p == '{') {
	tmp->type = krb5_config_list;
	tmp->u.list = NULL;
	ret = parse_list (f, lineno, &tmp->u.list);
    } else {
	p1 = p;
	while (*p && !isspace((unsigned char)*p))
	    ++p;
	*p = '\0';
	tmp->type = krb5_config_string;
	tmp->u.string = strdup(p1);
    }
    if (*b)
	(*b)->next = tmp;
    else
	*parent = tmp;
    *b = tmp;
    return ret;
}

krb5_error_code
krb5_config_parse_file (const char *fname, krb5_config_section **res)
{
    FILE *f;
    krb5_config_section *s;
    krb5_config_binding *b;
    char buf[BUFSIZ];
    unsigned lineno;
    int ret;

    s = NULL;
    b = NULL;
    f = fopen (fname, "r");
    if (f == NULL)
	return -1;
    *res = NULL;
    for (lineno = 1; fgets(buf, sizeof(buf), f) != NULL; ++lineno) {
	char *p;

	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';')
	    continue;
	if (*p == '[') {
	    ret = parse_section(p, &s, res);
	    if (ret)
		return ret;
	    b = NULL;
	} else if (*p == '}') {
	    return -1;
	} else if(*p != '\0') {
	    ret = parse_binding(f, &lineno, p, &b, &s->u.list);
	    if (ret)
		return ret;
	}
    }
    fclose (f);
    return 0;
}

#endif /* HAVE_NETINFO_NI_H */

static void
free_binding (krb5_config_binding *b)
{
    krb5_config_binding *next_b;

    while (b) {
	free (b->name);
	if (b->type == krb5_config_string)
	    free (b->u.string);
	else if (b->type == krb5_config_list)
	    free_binding (b->u.list);
	else
	    abort ();
	next_b = b->next;
	free (b);
	b = next_b;
    }
}

krb5_error_code
krb5_config_file_free (krb5_config_section *s)
{
    free_binding (s);
    return 0;
}

const void *
krb5_config_get_next (krb5_context context,
		      krb5_config_section *c,
		      krb5_config_binding **pointer,
		      int type,
		      ...)
{
    const char *ret;
    va_list args;

    va_start(args, type);
    ret = krb5_config_vget_next (context, c, pointer, type, args);
    va_end(args);
    return ret;
}

const void *
krb5_config_vget_next (krb5_context context,
		       krb5_config_section *c,
		       krb5_config_binding **pointer,
		       int type,
		       va_list args)
{
    krb5_config_binding *b;
    const char *p;

    if(c == NULL)
	c = context->cf;

    if (c == NULL)
	return NULL;

    if (*pointer == NULL) {
	b = (c != NULL) ? c : context->cf;
	p = va_arg(args, const char *);
	if (p == NULL)
	    return NULL;
    } else {
	b = *pointer;
	p = b->name;
	b = b->next;
    }

    while (b) {
	if (strcmp (b->name, p) == 0) {
	    if (*pointer == NULL)
		p = va_arg(args, const char *);
	    else
		p = NULL;
	    if (type == b->type && p == NULL) {
		*pointer = b;
		return b->u.generic;
	    } else if(b->type == krb5_config_list && p != NULL) {
		b = b->u.list;
	    } else {
		return NULL;
	    }
	} else {
	    b = b->next;
	}
    }
    return NULL;
}

const void *
krb5_config_get (krb5_context context,
		 krb5_config_section *c,
		 int type,
		 ...)
{
    const void *ret;
    va_list args;

    va_start(args, type);
    ret = krb5_config_vget (context, c, type, args);
    va_end(args);
    return ret;
}

const void *
krb5_config_vget (krb5_context context,
		  krb5_config_section *c,
		  int type,
		  va_list args)
{
    krb5_config_binding *foo = NULL;

    return krb5_config_vget_next (context, c, &foo, type, args);
}

const krb5_config_binding *
krb5_config_get_list (krb5_context context,
		      krb5_config_section *c,
		      ...)
{
    const krb5_config_binding *ret;
    va_list args;

    va_start(args, c);
    ret = krb5_config_vget_list (context, c, args);
    va_end(args);
    return ret;
}

const krb5_config_binding *
krb5_config_vget_list (krb5_context context,
		       krb5_config_section *c,
		       va_list args)
{
    return krb5_config_vget (context, c, krb5_config_list, args);
}

const char *
krb5_config_get_string (krb5_context context,
			krb5_config_section *c,
			...)
{
    const char *ret;
    va_list args;

    va_start(args, c);
    ret = krb5_config_vget_string (context, c, args);
    va_end(args);
    return ret;
}

const char *
krb5_config_vget_string (krb5_context context,
			 krb5_config_section *c,
			 va_list args)
{
    return krb5_config_vget (context, c, krb5_config_string, args);
}

char **
krb5_config_vget_strings(krb5_context context,
			 krb5_config_section *c,
			 va_list args)
{
    char **strings = NULL;
    int nstr = 0;
    krb5_config_binding *b = NULL;
    const char *p;
    while((p = krb5_config_vget_next(context, c, &b, 
				     krb5_config_string, args))){
	char *tmp = strdup(p);
	char *pos = NULL;
	char *s;
	if(tmp == NULL)
	    goto cleanup;
	s = strtok_r(tmp, " \t", &pos);
	while(s){
	    char **tmp = realloc(strings, (nstr + 1) * sizeof(*strings));
	    if(tmp == NULL)
		goto cleanup;
	    strings = tmp;
	    strings[nstr] = strdup(s);
	    nstr++;
	    if(strings[nstr-1] == NULL)
		goto cleanup;
	    s = strtok_r(NULL, " \t", &pos);
	}
	free(tmp);
    }
    if(nstr){
	char **tmp = realloc(strings, (nstr + 1) * sizeof(*strings));
	if(strings == NULL)
	    goto cleanup;
	strings = tmp;
	strings[nstr] = NULL;
    }
    return strings;
cleanup:
    while(nstr--)
	free(strings[nstr]);
    free(strings);
    return NULL;

}

char**
krb5_config_get_strings(krb5_context context,
			krb5_config_section *c,
			...)
{
    va_list ap;
    char **ret;
    va_start(ap, c);
    ret = krb5_config_vget_strings(context, c, ap);
    va_end(ap);
    return ret;
}

void
krb5_config_free_strings(char **strings)
{
    char **s = strings;
    while(s && *s){
	free(*s);
	s++;
    }
    free(strings);
}

krb5_boolean
krb5_config_vget_bool_default (krb5_context context,
			       krb5_config_section *c,
			       krb5_boolean def_value,
			       va_list args)
{
    const char *str;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    if(strcasecmp(str, "yes") == 0 ||
       strcasecmp(str, "true") == 0 ||
       atoi(str)) return TRUE;
    return FALSE;
}

krb5_boolean
krb5_config_vget_bool  (krb5_context context,
			krb5_config_section *c,
			va_list args)
{
    return krb5_config_vget_bool_default (context, c, FALSE, args);
}

krb5_boolean
krb5_config_get_bool_default (krb5_context context,
			      krb5_config_section *c,
			      krb5_boolean def_value,
			      ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_bool_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

krb5_boolean
krb5_config_get_bool (krb5_context context,
		      krb5_config_section *c,
		      ...)
{
    va_list ap;
    krb5_boolean ret;
    va_start(ap, c);
    ret = krb5_config_vget_bool (context, c, ap);
    va_end(ap);
    return ret;
}

int
krb5_config_vget_time_default (krb5_context context,
			       krb5_config_section *c,
			       int def_value,
			       va_list args)
{
    const char *str;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    return parse_time (str, NULL);
}

int
krb5_config_vget_time  (krb5_context context,
			krb5_config_section *c,
			va_list args)
{
    return krb5_config_vget_time_default (context, c, -1, args);
}

int
krb5_config_get_time_default (krb5_context context,
			      krb5_config_section *c,
			      int def_value,
			      ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_time_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

int
krb5_config_get_time (krb5_context context,
		      krb5_config_section *c,
		      ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = krb5_config_vget_time (context, c, ap);
    va_end(ap);
    return ret;
}


int
krb5_config_vget_int_default (krb5_context context,
			      krb5_config_section *c,
			      int def_value,
			      va_list args)
{
    const char *str;
    str = krb5_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    else { 
	char *endptr; 
	long l; 
	l = strtol(str, &endptr, 0); 
	if (endptr == str) 
	    return def_value; 
	else 
	    return l;
    }
}

int
krb5_config_vget_int  (krb5_context context,
		       krb5_config_section *c,
		       va_list args)
{
    return krb5_config_vget_int_default (context, c, -1, args);
}

int
krb5_config_get_int_default (krb5_context context,
			     krb5_config_section *c,
			     int def_value,
			     ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = krb5_config_vget_int_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

int
krb5_config_get_int (krb5_context context,
		     krb5_config_section *c,
		     ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = krb5_config_vget_int (context, c, ap);
    va_end(ap);
    return ret;
}

#ifdef TEST

static int print_list (FILE *f, krb5_config_binding *l, unsigned level);
static int print_binding (FILE *f, krb5_config_binding *b, unsigned level);
static int print_section (FILE *f, krb5_config_section *s, unsigned level);
static int print_config (FILE *f, krb5_config_section *c);

static void
tab (FILE *f, unsigned count)
{
    while(count--)
	fprintf (f, "\t");
}

static int
print_list (FILE *f, krb5_config_binding *l, unsigned level)
{
    while(l) {
	print_binding (f, l, level);
	l = l->next;
    }
    return 0;
}

static int
print_binding (FILE *f, krb5_config_binding *b, unsigned level)
{
    tab (f, level);
    fprintf (f, "%s = ", b->name);
    if (b->type == krb5_config_string)
	fprintf (f, "%s\n", b->u.string);
    else if (b->type == krb5_config_list) {
	fprintf (f, "{\n");
	print_list (f, b->u.list, level + 1);
	tab (f, level);
	fprintf (f, "}\n");
    } else
	abort ();
    return 0;
}

static int
print_section (FILE *f, krb5_config_section *s, unsigned level)
{
    fprintf (f, "[%s]\n", s->name);
    print_list (f, s->u.list, level + 1);
    return 0;
}

static int
print_config (FILE *f, krb5_config_section *c)
{
    while (c) {
	print_section (f, c, 0);
	c = c->next;
    }
    return 0;
}


int
main(void)
{
    krb5_config_section *c;

    printf ("%d\n", krb5_config_parse_file ("/etc/krb5.conf", &c));
    print_config (stdout, c);
    printf ("[libdefaults]ticket_lifetime = %s\n",
	    krb5_config_get_string (context, c,
			       "libdefaults",
			       "ticket_lifetime",
			       NULL));
    printf ("[realms]foo = %s\n",
	    krb5_config_get_string (context, c,
			       "realms",
			       "foo",
			       NULL));
    printf ("[realms]ATHENA.MIT.EDU/v4_instance_convert/lithium = %s\n",
	    krb5_config_get_string (context, c,
			       "realms",
			       "ATHENA.MIT.EDU",
			       "v4_instance_convert",
			       "lithium",
			       NULL));
    return 0;
}

#endif /* TEST */

#include "krb5_locl.h"
#include "config_file.h"
RCSID("$Id$");

static int parse_section(char *p, krb5_config_section **s, krb5_config_section **res);
static int parse_binding(FILE *f, unsigned *lineno, char *p, krb5_config_binding **b, krb5_config_binding **parent);
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
    if (*s)
	(*s)->next = tmp;
    else
	*parent = tmp;
    *s = tmp;
    tmp->name = strdup(p+1);
    if (tmp->name == NULL)
	return -1;
    tmp->next = NULL;
    tmp->list = NULL;
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
	while(isspace(*p))
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
    int ret;

    p1 = p;
    while (*p && !isspace(*p))
	++p;
    if (*p == '\0')
	return -1;
    *p = '\0';
    tmp = malloc(sizeof(*tmp));
    if (tmp == NULL)
	return -1;
    if (*b)
	(*b)->next = tmp;
    else
	*parent = tmp;
    *b = tmp;
    tmp->name = strdup(p1);
    tmp->next = NULL;
    ++p;
    while (isspace(*p))
	++p;
    if (*p != '=')
	return -1;
    ++p;
    while(isspace(*p))
	++p;
    if (*p == '{') {
	tmp->type = LIST;
	tmp->u.list = NULL;
	ret = parse_list (f, lineno, &tmp->u.list);
	if (ret)
	    return ret;
    } else {
	tmp->type = STRING;
	tmp->u.string = strdup(p);
    }
    return 0;
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
    for (lineno = 1; fgets(buf, sizeof(buf), f) != NULL; ++lineno) {
	char *p;

	if(buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = '\0';
	p = buf;
	while(isspace(*p))
	    ++p;
	if (*p == '[') {
	    ret = parse_section(p, &s, res);
	    if (ret)
		return ret;
	    b = NULL;
	} else if (*p == '}') {
	    return -1;
	} else if(*p != '\0') {
	    ret = parse_binding(f, &lineno, p, &b, &s->list);
	    if (ret)
		return ret;
	}
    }
    fclose (f);
    return 0;
}

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
    if (b->type == STRING)
	fprintf (f, "%s\n", b->u.string);
    else if (b->type == LIST) {
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
    print_list (f, s->list, level + 1);
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

char *
krb5_config_get_string (krb5_config_section *c, char *section, ...)
{
    char *ret;
    va_list args;

    va_start(args, section);
    ret = krb5_config_vget_string (c, section, args);
    va_end(args);
    return ret;
}

char *
krb5_config_vget_string (krb5_config_section *c, char *section, va_list args)
{
    char *p;
    krb5_config_binding *b;

    while (c && strcmp(c->name, section) != 0)
	c = c->next;
    if (c == NULL)
	return NULL;
    p = va_arg(args, char *);
    for (b = c->list; b; b = b->next)
	if (strcmp (b->name, p) == 0) {
	    p = va_arg(args, char *);
	    if (b->type == STRING)
		if (p == NULL)
		    return b->u.string;
		else
		    return NULL;
	    else if(b->type == LIST)
		if (p == NULL)
		    return NULL;
		else
		    b = b->u.list;
	    else
		abort();
	}
    return NULL;
}

#ifdef TEST

int
main(void)
{
    krb5_config_section *c;

    printf ("%d\n", krb5_config_parse_file ("/etc/krb5.conf", &c));
    print_config (stdout, c);
    printf ("[libdefaults]ticket_lifetime = %s\n",
	    krb5_config_get_string (c,
			       "libdefaults",
			       "ticket_lifetime",
			       NULL));
    printf ("[realms]foo = %s\n",
	    krb5_config_get_string (c,
			       "realms",
			       "foo",
			       NULL));
    printf ("[realms]ATHENA.MIT.EDU/v4_instance_convert/lithium = %s\n",
	    krb5_config_get_string (c,
			       "realms",
			       "ATHENA.MIT.EDU",
			       "v4_instance_convert",
			       "lithium",
			       NULL));
    return 0;
}

#endif /* TEST */

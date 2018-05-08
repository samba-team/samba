/** \ingroup popt
 * \file popt/poptconfig.c
 */

/* (C) 1998-2002 Red Hat, Inc. -- Licensing details are in the COPYING
   file accompanying popt source distributions, available from 
   ftp://ftp.rpm.org/pub/rpm/dist. */

#include "system.h"
#include "poptint.h"
#include <sys/stat.h>

#if defined(HAVE_FNMATCH_H)
#include <fnmatch.h>

#if defined(__LCLINT__)
/*@-declundef -exportheader -incondefs -protoparammatch -redecl -type @*/
extern int fnmatch (const char *__pattern, const char *__name, int __flags)
	/*@*/;
/*@=declundef =exportheader =incondefs =protoparammatch =redecl =type @*/
#endif	/* __LCLINT__ */
#endif

#if defined(HAVE_GLOB_H)
#include <glob.h>

#if defined(__LCLINT__)
/*@-declundef -exportheader -incondefs -protoparammatch -redecl -type @*/
extern int glob (const char *__pattern, int __flags,
		/*@null@*/ int (*__errfunc) (const char *, int),
		/*@out@*/ glob_t *__pglob)
	/*@globals errno, fileSystem @*/
	/*@modifies *__pglob, errno, fileSystem @*/;

/* XXX only annotation is a white lie */
extern void globfree (/*@only@*/ glob_t *__pglob)
	/*@modifies *__pglob @*/;

/* XXX _GNU_SOURCE ifdef and/or retrofit is needed for portability. */
extern int glob_pattern_p (const char *__pattern, int __quote)
        /*@*/;
/*@=declundef =exportheader =incondefs =protoparammatch =redecl =type @*/
#endif	/* __LCLINT__ */

#if !defined(__GLIBC__)
/* Return nonzero if PATTERN contains any metacharacters.
   Metacharacters can be quoted with backslashes if QUOTE is nonzero.  */
static int
glob_pattern_p (const char * pattern, int quote)
	/*@*/
{
    const char * p;
    int open = 0;

    for (p = pattern; *p != '\0'; ++p)
    switch (*p) {
    case '?':
    case '*':
	return 1;
	/*@notreached@*/ /*@switchbreak@*/ break;
    case '\\':
	if (quote && p[1] != '\0')
	  ++p;
	/*@switchbreak@*/ break;
    case '[':
	open = 1;
	/*@switchbreak@*/ break;
    case ']':
	if (open)
	  return 1;
	/*@switchbreak@*/ break;
    }
    return 0;
}
#endif	/* !defined(__GLIBC__) */

/*@unchecked@*/
static int poptGlobFlags = 0;

static int poptGlob_error(/*@unused@*/ UNUSED(const char * epath),
		/*@unused@*/ UNUSED(int eerrno))
	/*@*/
{
    return 1;
}
#endif	/* HAVE_GLOB_H */

/**
 * Return path(s) from a glob pattern.
 * @param con		context
 * @param pattern	glob pattern
 * @retval *acp		no. of paths
 * @retval *avp		array of paths
 * @return		0 on success
 */
static int poptGlob(/*@unused@*/ UNUSED(poptContext con), const char * pattern,
		/*@out@*/ int * acp, /*@out@*/ const char *** avp)
	/*@modifies *acp, *avp @*/
{
    const char * pat = pattern;
    int rc = 0;		/* assume success */

    /* XXX skip the attention marker. */
    if (pat[0] == '@' && pat[1] != '(')
	pat++;

#if defined(HAVE_GLOB_H)
    if (glob_pattern_p(pat, 0)) {
	glob_t _g, *pglob = &_g;

	if (!glob(pat, poptGlobFlags, poptGlob_error, pglob)) {
	    if (acp) {
		*acp = (int) pglob->gl_pathc;
		pglob->gl_pathc = 0;
	    }
	    if (avp) {
/*@-onlytrans@*/
		*avp = (const char **) pglob->gl_pathv;
/*@=onlytrans@*/
		pglob->gl_pathv = NULL;
	    }
/*@-nullstate@*/
	    globfree(pglob);
/*@=nullstate@*/
	} else
	    rc = POPT_ERROR_ERRNO;
    } else
#endif	/* HAVE_GLOB_H */
    {
	if (acp)
	    *acp = 1;
	if (avp && (*avp = calloc((size_t)(1 + 1), sizeof (**avp))) != NULL)
	    (*avp)[0] = xstrdup(pat);
    }

    return rc;
}

/*@access poptContext @*/

int poptSaneFile(const char * fn)
{
    struct stat sb;
    uid_t uid = getuid();

    if (stat(fn, &sb) == -1)
	return 1;
    if ((uid_t)sb.st_uid != uid)
	return 0;
    if (!S_ISREG(sb.st_mode))
	return 0;
/*@-bitwisesigned@*/
    if (sb.st_mode & (S_IWGRP|S_IWOTH))
	return 0;
/*@=bitwisesigned@*/
    return 1;
}

int poptReadFile(const char * fn, char ** bp, size_t * nbp, int flags)
{
    int fdno;
    char * b = NULL;
    off_t nb = 0;
    char * s, * t, * se;
    int rc = POPT_ERROR_ERRNO;	/* assume failure */

    fdno = open(fn, O_RDONLY);
    if (fdno < 0)
	goto exit;

    if ((nb = lseek(fdno, 0, SEEK_END)) == (off_t)-1
     || lseek(fdno, 0, SEEK_SET) == (off_t)-1
     || (b = calloc(sizeof(*b), (size_t)nb + 1)) == NULL
     || read(fdno, (char *)b, (size_t)nb) != (ssize_t)nb)
    {
	int oerrno = errno;
	(void) close(fdno);
	errno = oerrno;
	goto exit;
    }
    if (close(fdno) == -1)
	goto exit;
    if (b == NULL) {
	rc = POPT_ERROR_MALLOC;
	goto exit;
    }
    rc = 0;

   /* Trim out escaped newlines. */
/*@-bitwisesigned@*/
    if (flags & POPT_READFILE_TRIMNEWLINES)
/*@=bitwisesigned@*/
    {
	for (t = b, s = b, se = b + nb; *s && s < se; s++) {
	    switch (*s) {
	    case '\\':
		if (s[1] == '\n') {
		    s++;
		    continue;
		}
		/*@fallthrough@*/
	    default:
		*t++ = *s;
		/*@switchbreak@*/ break;
	    }
	}
	*t++ = '\0';
	nb = (off_t)(t - b);
    }

exit:
    if (rc != 0) {
/*@-usedef@*/
	if (b)
	    free(b);
/*@=usedef@*/
	b = NULL;
	nb = 0;
    }
    if (bp)
	*bp = b;
/*@-usereleased@*/
    else if (b)
	free(b);
/*@=usereleased@*/
    if (nbp)
	*nbp = (size_t)nb;
/*@-compdef -nullstate @*/	/* XXX cannot annotate char ** correctly */
    return rc;
/*@=compdef =nullstate @*/
}

/**
 * Check for application match.
 * @param con		context
 * @param s		config application name
 * return		0 if config application matches
 */
static int configAppMatch(poptContext con, const char * s)
	/*@*/
{
    int rc = 1;

    if (con->appName == NULL)	/* XXX can't happen. */
	return rc;

#if defined(HAVE_GLOB_H) && defined(HAVE_FNMATCH_H)
    if (glob_pattern_p(s, 1)) {
/*@-bitwisesigned@*/
	static int flags = FNM_PATHNAME | FNM_PERIOD;
#ifdef FNM_EXTMATCH
	flags |= FNM_EXTMATCH;
#endif
/*@=bitwisesigned@*/
	rc = fnmatch(s, con->appName, flags);
    } else
#endif
	rc = strcmp(s, con->appName);
    return rc;
}

/*@-compmempass@*/	/* FIX: item->option.longName kept, not dependent. */
static int poptConfigLine(poptContext con, char * line)
	/*@globals fileSystem, internalState @*/
	/*@modifies con, fileSystem, internalState @*/
{
    char *b = NULL;
    size_t nb = 0;
    char * se = line;
    const char * appName;
    const char * entryType;
    const char * opt;
    struct poptItem_s item_buf;
    poptItem item = &item_buf;
    int i, j;
    int rc = POPT_ERROR_BADCONFIG;

    if (con->appName == NULL)
	goto exit;
    
    memset(item, 0, sizeof(*item));

    appName = se;
    while (*se != '\0' && !_isspaceptr(se)) se++;
    if (*se == '\0')
	goto exit;
    else
	*se++ = '\0';

    if (configAppMatch(con, appName)) goto exit;

    while (*se != '\0' && _isspaceptr(se)) se++;
    entryType = se;
    while (*se != '\0' && !_isspaceptr(se)) se++;
    if (*se != '\0') *se++ = '\0';

    while (*se != '\0' && _isspaceptr(se)) se++;
    if (*se == '\0') goto exit;
    opt = se;
    while (*se != '\0' && !_isspaceptr(se)) se++;
    if (opt[0] == '-' && *se == '\0') goto exit;
    if (*se != '\0') *se++ = '\0';

    while (*se != '\0' && _isspaceptr(se)) se++;
    if (opt[0] == '-' && *se == '\0') goto exit;

/*@-temptrans@*/ /* FIX: line alias is saved */
    if (opt[0] == '-' && opt[1] == '-')
	item->option.longName = opt + 2;
    else if (opt[0] == '-' && opt[2] == '\0')
	item->option.shortName = opt[1];
    else {
	const char * fn = opt;

	/* XXX handle globs and directories in fn? */
	if ((rc = poptReadFile(fn, &b, &nb, POPT_READFILE_TRIMNEWLINES)) != 0)
	    goto exit;
	if (b == NULL || nb == 0)
	    goto exit;

	/* Append remaining text to the interpolated file option text. */
	if (*se != '\0') {
	    size_t nse = strlen(se) + 1;
	    if ((b = realloc(b, (nb + nse))) == NULL)	/* XXX can't happen */
		goto exit;
	    (void) stpcpy( stpcpy(&b[nb-1], " "), se);
	    nb += nse;
	}
	se = b;

	/* Use the basename of the path as the long option name. */
	{   const char * longName = strrchr(fn, '/');
	    if (longName != NULL)
		longName++;
	    else
		longName = fn;
	    if (longName == NULL)	/* XXX can't happen. */
		goto exit;
	    /* Single character basenames are treated as short options. */
	    if (longName[1] != '\0')
		item->option.longName = longName;
	    else
		item->option.shortName = longName[0];
	}
    }
/*@=temptrans@*/

    if (poptParseArgvString(se, &item->argc, &item->argv)) goto exit;

/*@-modobserver@*/
    item->option.argInfo = POPT_ARGFLAG_DOC_HIDDEN;
    for (i = 0, j = 0; i < item->argc; i++, j++) {
	const char * f;
	if (!strncmp(item->argv[i], "--POPTdesc=", sizeof("--POPTdesc=")-1)) {
	    f = item->argv[i] + sizeof("--POPTdesc=");
	    if (f[0] == '$' && f[1] == '"') f++;
	    item->option.descrip = f;
	    item->option.argInfo &= ~POPT_ARGFLAG_DOC_HIDDEN;
	    j--;
	} else
	if (!strncmp(item->argv[i], "--POPTargs=", sizeof("--POPTargs=")-1)) {
	    f = item->argv[i] + sizeof("--POPTargs=");
	    if (f[0] == '$' && f[1] == '"') f++;
	    item->option.argDescrip = f;
	    item->option.argInfo &= ~POPT_ARGFLAG_DOC_HIDDEN;
	    item->option.argInfo |= POPT_ARG_STRING;
	    j--;
	} else
	if (j != i)
	    item->argv[j] = item->argv[i];
    }
    if (j != i) {
	item->argv[j] = NULL;
	item->argc = j;
    }
/*@=modobserver@*/

/*@-nullstate@*/ /* FIX: item->argv[] may be NULL */
    if (!strcmp(entryType, "alias"))
	rc = poptAddItem(con, item, 0);
    else if (!strcmp(entryType, "exec"))
	rc = poptAddItem(con, item, 1);
/*@=nullstate@*/
exit:
    rc = 0;	/* XXX for now, always return success */
    if (b)
	free(b);
    return rc;
}
/*@=compmempass@*/

int poptReadConfigFile(poptContext con, const char * fn)
{
    char * b = NULL, *be;
    size_t nb = 0;
    const char *se;
    char *t, *te;
    int rc;
    int xx;

    if ((rc = poptReadFile(fn, &b, &nb, POPT_READFILE_TRIMNEWLINES)) != 0)
	return (errno == ENOENT ? 0 : rc);
    if (b == NULL || nb == 0)
	return POPT_ERROR_BADCONFIG;

    if ((t = malloc(nb + 1)) == NULL)
	goto exit;
    te = t;

    be = (b + nb);
    for (se = b; se < be; se++) {
	switch (*se) {
	  case '\n':
	    *te = '\0';
	    te = t;
	    while (*te && _isspaceptr(te)) te++;
	    if (*te && *te != '#')
		xx = poptConfigLine(con, te);
	    /*@switchbreak@*/ break;
/*@-usedef@*/	/* XXX *se may be uninitialized */
	  case '\\':
	    *te = *se++;
	    /* \ at the end of a line does not insert a \n */
	    if (se < be && *se != '\n') {
		te++;
		*te++ = *se;
	    }
	    /*@switchbreak@*/ break;
	  default:
	    *te++ = *se;
	    /*@switchbreak@*/ break;
/*@=usedef@*/
	}
    }

    free(t);
    rc = 0;

exit:
    if (b)
	free(b);
    return rc;
}

int poptReadConfigFiles(poptContext con, const char * paths)
{
    char * buf = (paths ? xstrdup(paths) : NULL);
    const char * p;
    char * pe;
    int rc = 0;		/* assume success */

    for (p = buf; p != NULL && *p != '\0'; p = pe) {
	const char ** av = NULL;
	int ac = 0;
	int i;
	int xx;

	/* locate start of next path element */
	pe = strchr(p, ':');
	if (pe != NULL && *pe == ':')
	    *pe++ = '\0';
	else
	    pe = (char *) (p + strlen(p));

	xx = poptGlob(con, p, &ac, &av);

	/* work-off each resulting file from the path element */
	for (i = 0; i < ac; i++) {
	    const char * fn = av[i];
	    if (av[i] == NULL)	/* XXX can't happen */
		/*@innercontinue@*/ continue;
	    /* XXX should '@' attention be pushed into poptReadConfigFile? */
	    if (p[0] == '@' && p[1] != '(') {
		if (fn[0] == '@' && fn[1] != '(')
		    fn++;
		xx = poptSaneFile(fn);
		if (!xx && rc == 0)
		    rc = POPT_ERROR_BADCONFIG;
		/*@innercontinue@*/ continue;
	    }
	    xx = poptReadConfigFile(con, fn);
	    if (xx && rc == 0)
		rc = xx;
	    free((void *)av[i]);
	    av[i] = NULL;
	}
	free(av);
	av = NULL;
    }

/*@-usedef@*/
    if (buf)
	free(buf);
/*@=usedef@*/

    return rc;
}

int poptReadDefaultConfig(poptContext con, /*@unused@*/ UNUSED(int useEnv))
{
    static const char _popt_sysconfdir[] = POPT_SYSCONFDIR "/popt";
    static const char _popt_etc[] = "/etc/popt";
    char * home;
    struct stat sb;
    int rc = 0;		/* assume success */

    if (con->appName == NULL) goto exit;

    if (strcmp(_popt_sysconfdir, _popt_etc)) {
	rc = poptReadConfigFile(con, _popt_sysconfdir);
	if (rc) goto exit;
    }

    rc = poptReadConfigFile(con, _popt_etc);
    if (rc) goto exit;

#if defined(HAVE_GLOB_H)
    if (!stat("/etc/popt.d", &sb) && S_ISDIR(sb.st_mode)) {
	const char ** av = NULL;
	int ac = 0;
	int i;

	if ((rc = poptGlob(con, "/etc/popt.d/*", &ac, &av)) == 0) {
	    for (i = 0; rc == 0 && i < ac; i++) {
		const char * fn = av[i];
		if (fn == NULL || strstr(fn, ".rpmnew") || strstr(fn, ".rpmsave"))
		    continue;
		if (!stat(fn, &sb)) {
		    if (!S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode))
			continue;
		}
		rc = poptReadConfigFile(con, fn);
		free((void *)av[i]);
		av[i] = NULL;
	    }
	    free(av);
	    av = NULL;
	}
    }
    if (rc) goto exit;
#endif

    if ((home = getenv("HOME"))) {
	char * fn = malloc(strlen(home) + 20);
	if (fn != NULL) {
	    (void) stpcpy(stpcpy(fn, home), "/.popt");
	    rc = poptReadConfigFile(con, fn);
	    free(fn);
	} else
	    rc = POPT_ERROR_ERRNO;
	if (rc) goto exit;
    }

exit:
    return rc;
}

poptContext
poptFini(poptContext con)
{
    return poptFreeContext(con);
}

poptContext
poptInit(int argc, const char ** argv,
		const struct poptOption * options, const char * configPaths)
{
    poptContext con = NULL;
    const char * argv0;

    if (argv == NULL || argv[0] == NULL || options == NULL)
	return con;

    if ((argv0 = strrchr(argv[0], '/')) != NULL) argv0++;
    else argv0 = argv[0];

    con = poptGetContext(argv0, argc, (const char **)argv, options, 0);
    if (con != NULL&& poptReadConfigFiles(con, configPaths))
	con = poptFini(con);

    return con;
}

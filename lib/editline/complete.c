/*  Copyright 1992 Simmule Turner and Rich Salz.  All rights reserved. 
 *
 *  This software is not subject to any license of the American Telephone 
 *  and Telegraph Company or of the Regents of the University of California. 
 *
 *  Permission is granted to anyone to use this software for any purpose on
 *  any computer system, and to alter it and redistribute it freely, subject
 *  to the following restrictions:
 *  1. The authors are not responsible for the consequences of use of this
 *     software, no matter how awful, even if they arise from flaws in it.
 *  2. The origin of this software must not be misrepresented, either by
 *     explicit claim or by omission.  Since few users ever read sources,
 *     credits must appear in the documentation.
 *  3. Altered versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.  Since few users
 *     ever read sources, credits must appear in the documentation.
 *  4. This notice may not be removed or altered.
 */

/*
**  History and file completion functions for editline library.
*/
#include <config.h>
#include "editline.h"

RCSID("$Id$");

/*
**  strcmp-like sorting predicate for qsort.
*/
static int
compare(p1, p2)
    const void	*p1;
    const void	*p2;
{
    const char	**v1;
    const char	**v2;

    v1 = (const char **)p1;
    v2 = (const char **)p2;
    return strcmp(*v1, *v2);
}

/*
**  Fill in *avp with an array of names that match file, up to its length.
**  Ignore . and .. .
*/
static int
FindMatches(dir, file, avp)
    char	*dir;
    char	*file;
    char	***avp;
{
    char	**av;
    char	**new;
    char	*p;
    DIR		*dp;
    DIRENTRY	*ep;
    size_t	ac;
    size_t	len;

    if ((dp = opendir(dir)) == NULL)
	return 0;

    av = NULL;
    ac = 0;
    len = strlen(file);
    while ((ep = readdir(dp)) != NULL) {
	p = ep->d_name;
	if (p[0] == '.' && (p[1] == '\0' || (p[1] == '.' && p[2] == '\0')))
	    continue;
	if (len && strncmp(p, file, len) != 0)
	    continue;

	if ((ac % MEM_INC) == 0) {
	    if ((new = NEW(char*, ac + MEM_INC)) == NULL)
		break;
	    if (ac) {
		COPYFROMTO(new, av, ac * sizeof (char **));
		DISPOSE(av);
	    }
	    *avp = av = new;
	}

	if ((av[ac] = strdup(p)) == NULL) {
	    if (ac == 0)
		DISPOSE(av);
	    break;
	}
	ac++;
    }

    /* Clean up and return. */
    (void)closedir(dp);
    if (ac)
	qsort(av, ac, sizeof (char **), compare);
    return ac;
}

/*
**  Split a pathname into allocated directory and trailing filename parts.
*/
static int
SplitPath(path, dirpart, filepart)
    char	*path;
    char	**dirpart;
    char	**filepart;
{
    static char	DOT[] = ".";
    char	*dpart;
    char	*fpart;

    if ((fpart = strrchr(path, '/')) == NULL) {
	if ((dpart = strdup(DOT)) == NULL)
	    return -1;
	if ((fpart = strdup(path)) == NULL) {
	    DISPOSE(dpart);
	    return -1;
	}
    }
    else {
	if ((dpart = strdup(path)) == NULL)
	    return -1;
	dpart[fpart - path] = '\0';
	if ((fpart = strdup(++fpart)) == NULL) {
	    DISPOSE(dpart);
	    return -1;
	}
    }
    *dirpart = dpart;
    *filepart = fpart;
    return 0;
}

/*
**  Attempt to complete the pathname, returning an allocated copy.
**  Fill in *unique if we completed it, or set it to 0 if ambiguous.
*/
char *
rl_complete(pathname, unique)
    char	*pathname;
    int		*unique;
{
    char	**av;
    char	*dir;
    char	*file;
    char	*new;
    char	*p;
    size_t	ac;
    size_t	end;
    size_t	i;
    size_t	j;
    size_t	len;

    if (SplitPath(pathname, &dir, &file) < 0)
	return NULL;
    if ((ac = FindMatches(dir, file, &av)) == 0) {
	DISPOSE(dir);
	DISPOSE(file);
	return NULL;
    }

    p = NULL;
    len = strlen(file);
    if (ac == 1) {
	/* Exactly one match -- finish it off. */
	*unique = 1;
	j = strlen(av[0]) - len + 2;
	if ((p = NEW(char, j + 1)) != NULL) {
	    COPYFROMTO(p, av[0] + len, j);
	    if ((new = NEW(char, strlen(dir) + strlen(av[0]) + 2)) != NULL) {
		snprintf (new, sizeof(new),
			  "%s/%s", dir, av[0]);
		rl_add_slash(new, p);
		DISPOSE(new);
	    }
	}
    }
    else {
	*unique = 0;
	if (len) {
	    /* Find largest matching substring. */
	    for (i = len, end = strlen(av[0]); i < end; i++)
		for (j = 1; j < ac; j++)
		    if (av[0][i] != av[j][i])
			goto breakout;
  breakout:
	    if (i > len) {
		j = i - len + 1;
		if ((p = NEW(char, j)) != NULL) {
		    COPYFROMTO(p, av[0] + len, j);
		    p[j - 1] = '\0';
		}
	    }
	}
    }

    /* Clean up and return. */
    DISPOSE(dir);
    DISPOSE(file);
    for (i = 0; i < ac; i++)
	DISPOSE(av[i]);
    DISPOSE(av);
    return p;
}

/*
**  Return all possible completions.
*/
int
rl_list_possib(pathname, avp)
    char	*pathname;
    char	***avp;
{
    char	*dir;
    char	*file;
    int		ac;

    if (SplitPath(pathname, &dir, &file) < 0)
	return 0;
    ac = FindMatches(dir, file, avp);
    DISPOSE(dir);
    DISPOSE(file);
    return ac;
}

/*  $Revision$
**
**  Internal header file for editline library.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRLF		"\r\n"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
typedef struct dirent	DIRENTRY;
#else
#include <sys/dir.h>
typedef struct direct	DIRENTRY;
#endif

#include <roken.h>

#if	!defined(S_ISDIR)
#define S_ISDIR(m)		(((m) & S_IFMT) == S_IFDIR)
#endif	/* !defined(S_ISDIR) */

typedef unsigned char	CHAR;

#define MEM_INC		64
#define SCREEN_INC	256

#define DISPOSE(p)	free((char *)(p))
#define NEW(T, c)	\
	((T *)malloc((unsigned int)(sizeof (T) * (c))))
#define RENEW(p, T, c)	\
	(p = (T *)realloc((char *)(p), (unsigned int)(sizeof (T) * (c))))
#define COPYFROMTO(new, p, len)	\
	(void)memcpy((char *)(new), (char *)(p), (int)(len))


/*
**  Variables and routines internal to this package.
*/
extern int	rl_eof;
extern int	rl_erase;
extern int	rl_intr;
extern int	rl_kill;
extern int	rl_quit;
extern char	*rl_complete(char *, int *);
extern int	rl_list_possib(char *, char ***);
extern void	rl_ttyset(int);
extern void	rl_add_slash(char *, char *);

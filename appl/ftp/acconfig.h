/*
 * $Id$
 */

@TOP@

@BOTTOM@

/* define if struct utmp contains ut_host */
#undef HAVE_UT_HOST

#ifdef __STDC__
#define RCSID(msg) static const char *rcsid[] = { (char *)rcsid, "\0100(#)" msg }
#else
#define RCSID(msg) static char *rcsid[] = { (char *)rcsid, msg }
#endif

#ifndef WTMP_PATH
#define WTMP_PATH "/var/adm/wtmp"
#endif

#define KERBEROS

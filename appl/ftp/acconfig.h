
@TOP@

@BOTTOM@

#undef HAVE___PROGNAME
#undef HAVE_UT_HOST
#undef BROKEN_GETCWD

#ifdef __STDC__
#define RCSID(msg) static const char *rcsid[] = { (char *)rcsid, "\0100(#)" msg }
#else
#define RCSID(msg) static char *rcsid[] = { (char *)rcsid, msg }
#endif

#define WTMP_PATH "/var/adm/wtmp"

#define KERBEROS

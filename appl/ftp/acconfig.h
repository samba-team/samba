
@TOP@

@BOTTOM@

#ifdef __STDC__
#define RCSID(msg) static const char *rcsid[] = { (char *)rcsid, "@(#)" msg }
#else
#define RCSID(msg) static char *rcsid[] = { (char *)rcsid, msg }
#endif

#define WTMP_PATH "/var/adm/wtmp"


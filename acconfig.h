@BOTTOM@

#undef BINDIR 
#undef LIBDIR
#undef LIBEXECDIR
#undef SBINDIR

#undef HAVE_INT8_T
#undef HAVE_INT16_T
#undef HAVE_INT32_T
#undef HAVE_INT64_T
#undef HAVE_U_INT8_T
#undef HAVE_U_INT16_T
#undef HAVE_U_INT32_T
#undef HAVE_U_INT64_T

#undef HAVE_FOUR_VALUED_KRB_PUT_INT

#ifdef HAVE_FOUR_VALUED_KRB_PUT_INT
#define KRB_PUT_INT(F, T, L, S) krb_put_int((F), (T), (L), (S))
#else
#define KRB_PUT_INT(F, T, L, S) krb_put_int((F), (T), (L))
#endif

/*  Define this if you have a IPv6 */
#undef HAVE_IPV6

/* define if getcwd() is broken (such as in SunOS) */
#undef BROKEN_GETCWD

/* Define to isoc_realloc if you have a broken realloc */
#undef BROKEN_REALLOC
#ifdef BROKEN_REALLOC
#define realloc(X, Y) isoc_realloc((X), (Y))
#define isoc_realloc(X, Y) ((X) ? realloc((X), (Y)) : malloc(Y))
#endif

#undef VOID_RETSIGTYPE

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

/* Define if you have a readline compatible library */
#undef HAVE_READLINE

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (char *)rcsid, "\100(#)" msg }

#undef PROTOTYPES

/* Maximum values on all known systems */
#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#if defined(HAVE_SGTTY_H) && defined(__NeXT__)
#define SGTTY
#endif

/* telnet stuff ----------------------------------------------- */

/*
 * Define NDBM if you are using the 4.3 ndbm library (which is part of
 * libc).  If not defined, 4.2 dbm will be assumed.
 */
#if defined(HAVE_DBM_FIRSTKEY)
#define NDBM
#endif

/* define this for OTP support */
#undef OTP

/* define this if you want to use the KDC as a kaserver */
#undef KASERVER

/* define this if you want support for reading kaserver databases in hprop */
#undef KASERVER_DB

/* define this if you have kerberos 5 */
#undef KRB5

/* define this if you want encryption */
#undef ENCRYPTION

/* define this if you want authentication */
#undef AUTHENTICATION

#if defined(ENCRYPTION) && !defined(AUTHENTICATION)
#define AUTHENTICATION 1
#endif

/* define if you want key-deriving des3 code */
#undef NEW_DES3_CODE

/* Set this if you want des encryption */
#undef DES_ENCRYPTION

/* Set this to the default system lead string for telnetd 
 * can contain %-escapes: %s=sysname, %m=machine, %r=os-release
 * %v=os-version, %t=tty, %h=hostname, %d=date and time
 */
#undef USE_IM

/* define this if you want diagnostics in telnetd */
#undef DIAGNOSTICS

/* define this if you want support for broken ENV_{VALUE,VAR} systems  */
#undef ENV_HACK

/*  */
#undef OLD_ENVIRON

/* Used with login -p */
#undef LOGIN_ARGS

/* Define if there are working stream ptys */
#undef STREAMSPTY

/* set this to a sensible login */
#ifndef LOGIN_PATH
#define LOGIN_PATH BINDIR "/login"
#endif

/* operating system kludges ahead */
#undef SunOS

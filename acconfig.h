@BOTTOM@

#undef VERSION
#undef PACKAGE

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

/* Define this to the type ssize_t should be */
#undef ssize_t

/* Define this to the type sig_atomic_t should be */
#undef sig_atomic_t

/* Define this to the type mode_t should be */
#undef mode_t

/*  Define this if struct utmp have ut_user  */
#undef HAVE_UT_USER

/*  Define this if struct utmp have ut_host  */
#undef HAVE_UT_HOST

/*  Define this if struct utmp have ut_addr  */
#undef HAVE_UT_ADDR

/*  Define this if struct utmp have ut_type  */
#undef HAVE_UT_TYPE

/*  Define this if struct utmp have ut_pid  */
#undef HAVE_UT_PID

/*  Define this if struct utmp have ut_id  */
#undef HAVE_UT_ID

/*  Define this if struct utmpx have ut_syslen  */
#undef HAVE_UT_SYSLEN

/*  Define this if struct utmpx have ut_exit  */
#undef HAVE_UT_EXIT

/*  Define this if you have a IPv6 */
#undef HAVE_IPV6

/* define if prototype of gethostbyname is compatible with
   `struct hostent *gethostbyname(const char *)
   */
#undef GETHOSTBYNAME_PROTO_COMPATIBLE

/* define if prototype of gethostbyaddr is compatible with
   `struct hostent *gethostbyaddr(const void *, size_t, int)
   */
#undef GETHOSTBYADDR_PROTO_COMPATIBLE

/* define if prototype of getservbyname is compatible with
   `struct servent *getservbyname(const char *, const char *)
   */
#undef GETSERVBYNAME_PROTO_COMPATIBLE

/* define if prototype of openlog is compatible with
   `void openlog(const char *, int, int)'
   */
#undef OPENLOG_PROTO_COMPATIBLE

/* define if you have h_errno */
#undef HAVE_H_ERRNO

/* define if you have h_errlist but not hstrerror */
#undef HAVE_H_ERRLIST

/* define if you have h_nerr but not hstrerror */
#undef HAVE_H_NERR

/* define if your system doesn't declare h_errlist */
#undef HAVE_H_ERRLIST_DECLARATION

/* define if your system doesn't declare h_nerr */
#undef HAVE_H_NERR_DECLARATION

/* define this if you need a declaration for h_errno */
#undef HAVE_H_ERRNO_DECLARATION

/* define if you need a declaration for optarg */
#undef HAVE_OPTARG_DECLARATION

/* define if you need a declaration for optind */
#undef HAVE_OPTIND_DECLARATION

/* define if you need a declaration for opterr */
#undef HAVE_OPTERR_DECLARATION

/* define if you need a declaration for optopt */
#undef HAVE_OPTOPT_DECLARATION

/* define if you need a declaration for environ */
#undef HAVE_ENVIRON_DECLARATION

/* define if you need a declaration for __progname */
#undef HAVE___PROGNAME_DECLARATION

/* define if the system is missing a prototype for crypt() */
#undef NEED_CRYPT_PROTO

/* define if the system is missing a prototype for strtok_r() */
#undef NEED_STRTOK_R_PROTO

/* define if the system is missing a prototype for strtok_r() */
#undef NEED_HSTRERROR_PROTO

/* define if the system is missing a prototype for snprintf() */
#undef NEED_SNPRINTF_PROTO

/* define if the system is missing a prototype for vsnprintf() */
#undef NEED_VSNPRINTF_PROTO

/* define if the system is missing a prototype for asnprintf() */
#undef NEED_ASNPRINTF_PROTO

/* define if the system is missing a prototype for asprintf() */
#undef NEED_ASPRINTF_PROTO

/* define if the system is missing a prototype for vasnprintf() */
#undef NEED_VASNPRINTF_PROTO

/* define if the system is missing a prototype for vasprintf() */
#undef NEED_VASPRINTF_PROTO

/* Define this if your `struct tm' has a field `tm_gmtoff' */
#undef HAVE_STRUCT_TM_TM_GMTOFF

/* define if getcwd() is broken (such as in SunOS) */
#undef BROKEN_GETCWD

/* Define this if you have a variable `timezone' */
#undef HAVE_TIMEZONE

/*  Define this if you have a struct spwd */
#undef HAVE_STRUCT_SPWD

/*  Define this if struct winsize is declared in sys/termios.h */
#undef HAVE_STRUCT_WINSIZE

/*  Define this if struct winsize has ws_xpixel */
#undef HAVE_WS_XPIXEL

/*  Define this if struct winsize has ws_ypixel */
#undef HAVE_WS_YPIXEL

/*  Define this if struct sockaddr has sa_len */
#undef SOCKADDR_HAS_SA_LEN

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

/* define this if you have kerberos 4 */
#undef KRB4

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

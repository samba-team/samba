
/* 
 * configuration file for telnet 
 *
 * $Id$
 *
 */

#ifndef T_CONFIG_H
#define T_CONFIG_H

@TOP@

/* define this if you want authentication */
#undef AUTHENTICATION

/* define this if you have kerberos 4 */
#undef KRB4

/* define this if you want encryption */
#undef ENCRYPTION

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

/* define this if you want support for line mode in telnetd */
#undef LINEMODE

/* define this if you want support for 4.3BSD kludged line mode  */
#undef KLUDGELINEMODE

/*  */
#undef OLD_ENVIRON

/* Define if login doesn't understand -f */
#undef NO_LOGIN_F

/* Define if login does understand -r */
#undef LOGIN_R

/* Define if login doesn't understand -h */
/* */
#undef NO_LOGIN_H

/* Define if login doesn't understand -p */
#undef NO_LOGIN_P

/* Used with login -p */
#undef LOGIN_ARGS

/* Define if you have setupterm() */
#undef HAVE_SETUPTERM

/* Define if you have tgetent() */
#undef HAVE_TGETENT

/* Define if there are working stream ptys */
#undef STREAMSPTY

@BOTTOM@

#ifdef __STDC__
#define RCSID(msg) static const char *rcsid[] = { (char *)rcsid, "@(#)" msg }
#else
#define RCSID(msg) static char *rcsid[] = { (char *)rcsid, msg }
#endif

/* set this to a sensible login */
#ifndef LOGIN_PATH
#define LOGIN_PATH "/usr/athena/bin/login"
#endif


/* this is left for hysteric reasons :-) */
#ifdef _AIX
#define unix /* well, ok... */
#endif

/*
 * SunOS braindamage! (Sun include files are generally braindead)
 */
#if (defined(sun) || defined(__sun))
#if defined(__svr4__) || defined(__SVR4)
#define SunOS 5
#else
#define SunOS 4
#endif
#endif

#endif /* T_CONFIG_H */

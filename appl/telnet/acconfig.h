
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


/* */
#undef STREAMSPTY

@BOTTOM@

/* set this to a sensible login */
#ifndef LOGIN_PATH
#define LOGIN_PATH "/usr/athena/bin/login"
#endif


#ifdef HAVE_TGETENT
#define TERMCAP 1
#endif

#if defined(HAVE_TERMIOS_H) || defined(HAVE_TERMIO_H)
#define USE_TERMIO 1

/* If this is not a POSIX boxen use SYSV, this may not work on CRAY
 * se telnetd/desf.h */
#ifndef HAVE_TERMIOS_H
#define SYSV_TERMIO
#endif

#endif /* defined(HAVE_TERMIOS_H) || defined(HAVE_TERMIO_H) */

#ifndef HAVE_VFORK
#define vfork fork
#endif

/* os specific tests ahead */

#ifdef sun

#define FILIO_H 1
#define STREAMS 1

#ifdef __svr4__
#define SOLARIS
#endif

#endif /* sun */

#ifdef _AIX
#define unix /* well, ok... */
#endif

#endif /* T_CONFIG_H */

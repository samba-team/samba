@BOTTOM@

#undef PROTOTYPES

#if defined(HAVE_SGTTY_H) && defined(__NeXT__)
#define SGTTY
#endif

/* telnet stuff ----------------------------------------------- */

#if defined(ENCRYPTION) && !defined(AUTHENTICATION)
#define AUTHENTICATION 1
#endif

/* Set this to the default system lead string for telnetd 
 * can contain %-escapes: %s=sysname, %m=machine, %r=os-release
 * %v=os-version, %t=tty, %h=hostname, %d=date and time
 */
#undef USE_IM

/* Used with login -p */
#undef LOGIN_ARGS

/* set this to a sensible login */
#ifndef LOGIN_PATH
#define LOGIN_PATH BINDIR "/login"
#endif

/* random defines */

/*
 * Defining this enables lots of useful (and used) extensions on
 * glibc-based systems such as Linux
 */

#define _GNU_SOURCE

/*
 * this assumes that KRB_C_BIGENDIAN is used.
 * if we can find out endianess at compile-time, do so,
 * otherwise WORDS_BIGENDIAN should already have been defined
 */

#if ENDIANESS_IN_SYS_PARAM_H
#  include <sys/types.h>
#  include <sys/param.h>
#  if BYTE_ORDER == BIG_ENDIAN
#  define WORDS_BIGENDIAN 1
#  endif
#endif

#ifdef ROKEN_RENAME
#include "roken_rename.h"
#endif

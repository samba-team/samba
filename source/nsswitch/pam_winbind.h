/* pam_winbind header file 
   (Solaris needs some macros from Linux for common PAM code)

   Shirish Kalele 2000
*/

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <config.h>

#define MODULE_NAME "pam_winbind"
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD

#if defined(SUNOS5) || defined(SUNOS4) || defined(HPUX)

/* Solaris and HPUX always use dynamic pam modules */
#define PAM_EXTERN extern
#include <security/pam_appl.h> 

#define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifdef HAVE_SECURITY__PAM_MACROS_H
#include <security/_pam_macros.h>
#else
/* Define required macros from (Linux PAM 0.68) security/_pam_macros.h */
#define _pam_drop_reply(/* struct pam_response * */ reply, /* int */ replies) \
do {                                              \
    int reply_i;                                  \
                                                  \
    for (reply_i=0; reply_i<replies; ++reply_i) { \
        if (reply[reply_i].resp) {                \
            _pam_overwrite(reply[reply_i].resp);  \
            free(reply[reply_i].resp);            \
        }                                         \
    }                                             \
    if (reply)                                    \
        free(reply);                              \
} while (0)

#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)

/*
 * Don't just free it, forget it too.
 */

#define _pam_drop(X) SAFE_FREE(X)

#define  x_strdup(s)  ( (s) ? strdup(s):NULL )     
#endif

#define PAM_DEBUG_ARG (1<<0)
#define PAM_USE_AUTHTOK_ARG (1<<1)
#define PAM_UNKNOWN_OK_ARG (1<<2)

#include "winbind_nss_config.h"
#include "winbindd_nss.h"

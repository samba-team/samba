#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif


#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "roken.h"

#ifdef __ultrix
char *crypt(const char*, const char*);
#endif

int
verify_unix_user(char *user, char *password)
{
    struct passwd *pw;
    
    pw = k_getpwnam(user);
    if(pw == NULL)
	return -1;
    if(strlen(pw->pw_passwd) == 0 && strlen(password) == 0)
	return 0;
    if(strcmp(crypt(password, pw->pw_passwd), pw->pw_passwd) == 0)
        return 0;
    return -1;
}


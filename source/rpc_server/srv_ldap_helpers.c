#ifdef USE_LDAP

#include "includes.h"
#include "lber.h"
#include "ldap.h"

extern int DEBUGLEVEL;


#else /* USE_LDAP */
/* this keeps fussy compilers happy */
 void ldap_helper_dummy(void);
 void ldap_helper_dummy(void) {}
#endif /* USE_LDAP */

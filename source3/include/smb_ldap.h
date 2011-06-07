#ifndef _SMB_LDAP_H
#define _SMB_LDAP_H

#if HAVE_LBER_H
#include <lber.h>
#if defined(HPUX) && !defined(_LBER_TYPES_H)
/* Define ber_tag_t and ber_int_t for using
 * HP LDAP-UX Integration products' LDAP libraries.
*/
#ifndef ber_tag_t
typedef unsigned long ber_tag_t;
typedef int ber_int_t;
#endif
#endif /* defined(HPUX) && !defined(_LBER_TYPES_H) */
#ifndef LBER_USE_DER
#define LBER_USE_DER 0x01
#endif
#endif /* HAVE_LBER_H */

#if HAVE_LDAP_H
#include <ldap.h>
#ifndef LDAP_CONST
#define LDAP_CONST const
#endif
#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif
/* Solaris 8 and maybe other LDAP implementations spell this "..._INPROGRESS": */
#if defined(LDAP_SASL_BIND_INPROGRESS) && !defined(LDAP_SASL_BIND_IN_PROGRESS)
#define LDAP_SASL_BIND_IN_PROGRESS LDAP_SASL_BIND_INPROGRESS
#endif
/* Solaris 8 defines SSL_LDAP_PORT, not LDAPS_PORT and it only does so if
   LDAP_SSL is defined - but SSL is not working. We just want the
   port number! Let's just define LDAPS_PORT correct. */
#if !defined(LDAPS_PORT)
#define LDAPS_PORT 636
#endif

/* function declarations not included in proto.h */
LDAP *ldap_open_with_timeout(const char *server, int port, unsigned int to);

#endif /* HAVE_LDAP_H */

#ifndef HAVE_LDAP
#define LDAP void
#define LDAPMessage void
#define LDAPMod void
#define LDAP_CONST const
#define LDAPControl void
struct berval;
struct ldapsam_privates;
#endif /* HAVE_LDAP */

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS 0
#endif

#endif /* _SMB_LDAP_H */

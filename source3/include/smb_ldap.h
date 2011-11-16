/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Guenther Deschner 2005
   Copyright (C) Gerald Carter 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

#ifdef HAVE_LDAP_PVT_H
#include <ldap_pvt.h>
#endif /* HAVE_LDAP_PVT_H */

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

#define LDAP_DEFAULT_TIMEOUT   15
#define LDAP_CONNECTION_DEFAULT_TIMEOUT 2
#define LDAP_PAGE_SIZE 1024

#define ADS_PAGE_CTL_OID 	"1.2.840.113556.1.4.319"

/*
 * Work around versions of the LDAP client libs that don't have the OIDs
 * defined, or have them defined under the old name.
 * This functionality is really a factor of the server, not the client
 *
 */

#if defined(LDAP_EXOP_X_MODIFY_PASSWD) && !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD LDAP_EXOP_X_MODIFY_PASSWD
#elif !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD "1.3.6.1.4.1.4203.1.11.1"
#endif

#if defined(LDAP_EXOP_X_MODIFY_PASSWD_ID) && !defined(LDAP_EXOP_MODIFY_PASSWD_ID)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID LDAP_EXOP_X_MODIFY_PASSWD_ID
#elif !defined(LDAP_EXOP_MODIFY_PASSWD_ID)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID        ((ber_tag_t) 0x80U)
#endif

#if defined(LDAP_EXOP_X_MODIFY_PASSWD_NEW) && !defined(LDAP_EXOP_MODIFY_PASSWD_NEW)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW LDAP_EXOP_X_MODIFY_PASSWD_NEW
#elif !defined(LDAP_EXOP_MODIFY_PASSWD_NEW)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW       ((ber_tag_t) 0x82U)
#endif

#endif /* _SMB_LDAP_H */

/*
   Unix SMB/CIFS implementation.

   nis system include wrappers

   Copyright (C) Andrew Tridgell 2004

     ** NOTE! The following LGPL license applies to the replace
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _nis_passwd_h
#define _nis_passwd_h

#if defined(HAVE_RPC_RPC_H)
/*
 * Check for AUTH_ERROR define conflict with rpc/rpc.h in prot.h.
 */
#if defined(HAVE_SYS_SECURITY_H) && defined(HAVE_RPC_AUTH_ERROR_CONFLICT)
#undef AUTH_ERROR
#endif /* HAVE_SYS_SECURITY_H && HAVE_RPC_AUTH_ERROR_CONFLICT */

#include <rpc/rpc.h>
#endif /* HAVE_RPC_RPC_H */


#if defined (HAVE_NETGROUP)

#if defined(HAVE_RPCSVC_YP_PROT_H)

#include <rpcsvc/yp_prot.h>

#endif /* HAVE_RPCSVC_YP_PROT_H */

#if defined(HAVE_RPCSVC_YPCLNT_H)
#include <rpcsvc/ypclnt.h>
#endif /* HAVE_RPCSVC_YPCLNT_H */

#endif /* HAVE_NETGROUP */

#endif /* _nis_passwd_h */

/*
   Unix SMB/CIFS implementation.

   Implements functions offered by repadmin.exe tool under Windows

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2010

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

#ifndef NET_DRS_H_
#define NET_DRS_H_

#include "librpc/gen_ndr/ndr_drsuapi_c.h"

/* net drs commands context */
struct net_drs_context {
	struct net_context 	*net_ctx;

	/* remote DC name supplied from command line */
	const char 		*dc_name;

	/* DRSUAPI connection context */
	struct dcerpc_binding 	*binding;
	struct dcerpc_pipe 	*drs_pipe;
	struct policy_handle 	bind_handle;

	/* length of bind info structure returned by remote DC
	 * 'net drs bind' command make use of this value */
	uint32_t bind_info_len;

	/* remote DC DRSUAPI capabilities */
	struct drsuapi_DsBindInfo48 info48;

	/* LDAP connection to DC */
	struct net_drs_ldap {
		struct ldb_context 	 *ldb;
		const struct ldb_message *rootdse;
	} ldap;
};


#include "net_drs_proto.h"

#endif /* NET_DRS_H_ */

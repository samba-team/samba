#/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special netlogon types

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
   Copyright (C) Guenther Deschner 2011

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

/* The following definitions come from ../librpc/ndr/ndr_nbt.c  */

#ifndef _LIBRPC_NDR_NDR_NBT_H
#define _LIBRPC_NDR_NDR_NBT_H

#include "librpc/gen_ndr/nbt.h"

NDR_SCALAR_PROTO(nbt_string, const char *)

struct netlogon_samlogon_response
{
	uint32_t ntver;
	union {
		struct NETLOGON_SAM_LOGON_RESPONSE_NT40 nt4;
		struct NETLOGON_SAM_LOGON_RESPONSE nt5;
		struct NETLOGON_SAM_LOGON_RESPONSE_EX nt5_ex;
	} data;

};

enum ndr_err_code ndr_push_NETLOGON_SAM_LOGON_REQUEST(struct ndr_push *ndr, int ndr_flags, const struct NETLOGON_SAM_LOGON_REQUEST *r);
enum ndr_err_code ndr_pull_NETLOGON_SAM_LOGON_REQUEST(struct ndr_pull *ndr, int ndr_flags, struct NETLOGON_SAM_LOGON_REQUEST *r);
enum ndr_err_code ndr_push_NETLOGON_SAM_LOGON_RESPONSE_EX_with_flags(struct ndr_push *ndr, int ndr_flags, const struct NETLOGON_SAM_LOGON_RESPONSE_EX *r);
enum ndr_err_code ndr_pull_NETLOGON_SAM_LOGON_RESPONSE_EX_with_flags(struct ndr_pull *ndr, int ndr_flags, struct NETLOGON_SAM_LOGON_RESPONSE_EX *r,
								     uint32_t nt_version_flags);
enum ndr_err_code ndr_push_netlogon_samlogon_response(struct ndr_push *ndr, int ndr_flags, const struct netlogon_samlogon_response *r);
enum ndr_err_code ndr_pull_netlogon_samlogon_response(struct ndr_pull *ndr, int ndr_flags, struct netlogon_samlogon_response *r);

#endif /* _LIBRPC_NDR_NDR_NBT_H */

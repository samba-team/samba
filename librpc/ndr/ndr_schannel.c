/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special schannel structures

   Copyright (C) Guenther Deschner 2009

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

#include "includes.h"
#include "../librpc/gen_ndr/ndr_schannel.h"
#include "../librpc/ndr/ndr_schannel.h"
#include "../libcli/nbt/libnbt.h"

_PUBLIC_ void ndr_print_NL_AUTH_MESSAGE_BUFFER(struct ndr_print *ndr, const char *name, const union NL_AUTH_MESSAGE_BUFFER *r)
{
	int level;
	level = ndr_print_get_switch_value(ndr, r);
	switch (level) {
		case NL_FLAG_OEM_NETBIOS_DOMAIN_NAME:
			ndr_print_string(ndr, name, r->a);
		break;

		case NL_FLAG_OEM_NETBIOS_COMPUTER_NAME:
			ndr_print_string(ndr, name, r->a);
		break;

		case NL_FLAG_UTF8_DNS_DOMAIN_NAME:
			ndr_print_nbt_string(ndr, name, r->u);
		break;

		case NL_FLAG_UTF8_DNS_HOST_NAME:
			ndr_print_nbt_string(ndr, name, r->u);
		break;

		case NL_FLAG_UTF8_NETBIOS_COMPUTER_NAME:
			ndr_print_nbt_string(ndr, name, r->u);
		break;

		default:
		break;

	}
}

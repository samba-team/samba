/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special ntlmssp structures

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
#include "../librpc/ndr/ndr_ntlmssp.h"

_PUBLIC_ size_t ndr_ntlmssp_string_length(uint32_t negotiate_flags, const char *s)
{
	if (!s) {
		return 0;
	}

	if (negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		return strlen(s) * 2;
	}

	return strlen(s);
}

_PUBLIC_ uint32_t ndr_ntlmssp_negotiated_string_flags(uint32_t negotiate_flags)
{
	uint32_t flags = LIBNDR_FLAG_STR_NOTERM |
			 LIBNDR_FLAG_STR_CHARLEN |
			 LIBNDR_FLAG_REMAINING;

	if (!(negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)) {
		flags |= LIBNDR_FLAG_STR_ASCII;
	}

	return flags;
}

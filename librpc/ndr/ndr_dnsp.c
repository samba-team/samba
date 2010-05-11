/*
   Unix SMB/CIFS implementation.

   Manually parsed structures found in DNSP

   Copyright (C) Andrew Tridgell 2010

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
#include "librpc/gen_ndr/ndr_dnsp.h"

/*
  print a dnsp_name
*/
_PUBLIC_ void ndr_print_dnsp_name(struct ndr_print *ndr, const char *name,
				  const char *dns_name)
{
	ndr->print(ndr, "%-25s: %s", name, dns_name);
}

/*
  pull a dnsp_name
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dnsp_name(struct ndr_pull *ndr, int ndr_flags, const char **name)
{
	uint8_t len, count;
	int i;
	uint32_t total_len;
	char *ret;

	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &len));
	NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &count));

	ret = talloc_strdup(ndr->current_mem_ctx, "");
	if (!ret) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp");
	}
	total_len = 1;

	for (i=0; i<count; i++) {
		uint8_t sublen, newlen;
		NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &sublen));
		newlen = total_len + sublen;
		if (i != count-1) {
			newlen++; /* for the '.' */
		}
		ret = talloc_realloc(ndr->current_mem_ctx, ret, char, newlen);
		if (!ret) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull dnsp");
		}
		NDR_CHECK(ndr_pull_bytes(ndr, (uint8_t *)&ret[total_len-1], sublen));
		if (i != count-1) {
			ret[newlen-2] = '.';
		}
		ret[newlen-1] = 0;
		total_len = newlen;
	}
	(*name) = ret;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_dnsp_name(struct ndr_push *ndr, int ndr_flags, const char *name)
{
	int count, total_len, i;
	/* count the dots */
	for (count=i=0; name[i]; i++) {
		if (name[i] == '.') count++;
	}
	total_len = strlen(name) + 1;
	if (total_len > 255 || count > 255) {
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,
				      "dns_name of length %d larger than 255", total_len);
	}
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)total_len));
	NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)count));
	for (i=0; i<count; i++) {
		const char *p = strchr(name, '.');
		size_t sublen = p?(p-name):strlen(name);
		NDR_CHECK(ndr_push_uint8(ndr, ndr_flags, (uint8_t)sublen));
		NDR_CHECK(ndr_push_bytes(ndr, (const uint8_t *)name, sublen));
		name += sublen + 1;
	}

	return NDR_ERR_SUCCESS;
}

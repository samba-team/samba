/*
   Unix SMB/CIFS implementation.

   manipulate dns name structures

   Copyright (C) 2010 Kai Blin  <kai@samba.org>

   Heavily based on nbtname.c which is:

   Copyright (C) Andrew Tridgell 2005

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

/*
  see rfc1002 for the detailed format of compressed names
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "system/locale.h"
#include "lib/util/util_net.h"

/* don't allow an unlimited number of name components */
#define MAX_COMPONENTS 10

/**
  print a dns string
*/
_PUBLIC_ void ndr_print_dns_string(struct ndr_print *ndr, const char *name, const char *s)
{
	ndr_print_string(ndr, name, s);
}

/*
  pull one component of a dns_string
*/
static enum ndr_err_code ndr_pull_component(struct ndr_pull *ndr,
					    uint8_t **component,
					    uint32_t *offset,
					    uint32_t *max_offset)
{
	uint8_t len;
	unsigned int loops = 0;
	while (loops < 5) {
		if (*offset >= ndr->data_size) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "BAD DNS NAME component");
		}
		len = ndr->data[*offset];
		if (len == 0) {
			*offset += 1;
			*max_offset = MAX(*max_offset, *offset);
			*component = NULL;
			return NDR_ERR_SUCCESS;
		}
		if ((len & 0xC0) == 0xC0) {
			/* its a label pointer */
			if (1 + *offset >= ndr->data_size) {
				return ndr_pull_error(ndr, NDR_ERR_STRING,
						      "BAD DNS NAME component");
			}
			*max_offset = MAX(*max_offset, *offset + 2);
			*offset = ((len&0x3F)<<8) | ndr->data[1 + *offset];
			*max_offset = MAX(*max_offset, *offset);
			loops++;
			continue;
		}
		if ((len & 0xC0) != 0) {
			/* its a reserved length field */
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "BAD DNS NAME component");
		}
		if (*offset + len + 2 > ndr->data_size) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "BAD DNS NAME component");
		}
		*component = (uint8_t*)talloc_strndup(ndr, (const char *)&ndr->data[1 + *offset], len);
		NDR_ERR_HAVE_NO_MEMORY(*component);
		*offset += len + 1;
		*max_offset = MAX(*max_offset, *offset);
		return NDR_ERR_SUCCESS;
	}

	/* too many pointers */
	return ndr_pull_error(ndr, NDR_ERR_STRING, "BAD DNS NAME component");
}

/**
  pull a dns_string from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dns_string(struct ndr_pull *ndr, int ndr_flags, const char **s)
{
	uint32_t offset = ndr->offset;
	uint32_t max_offset = offset;
	unsigned num_components;
	char *name;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	name = NULL;

	/* break up name into a list of components */
	for (num_components=0;num_components<MAX_COMPONENTS;num_components++) {
		uint8_t *component = NULL;
		NDR_CHECK(ndr_pull_component(ndr, &component, &offset, &max_offset));
		if (component == NULL) break;
		if (name) {
			name = talloc_asprintf_append_buffer(name, ".%s", component);
			NDR_ERR_HAVE_NO_MEMORY(name);
		} else {
			name = (char *)component;
		}
	}
	if (num_components == MAX_COMPONENTS) {
		return ndr_pull_error(ndr, NDR_ERR_STRING,
				      "BAD DNS NAME too many components");
	}
	if (num_components == 0) {
		name = talloc_strdup(ndr, "");
		NDR_ERR_HAVE_NO_MEMORY(name);
	}

	(*s) = name;
	ndr->offset = max_offset;

	return NDR_ERR_SUCCESS;
}

/**
  push a dns string to the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_dns_string(struct ndr_push *ndr, int ndr_flags, const char *s)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	while (s && *s) {
		enum ndr_err_code ndr_err;
		char *compname;
		size_t complen;
		uint32_t offset;

		/* see if we have pushed the remaing string allready,
		 * if so we use a label pointer to this string
		 */
		ndr_err = ndr_token_retrieve_cmp_fn(&ndr->dns_string_list, s, &offset, (comparison_fn_t)strcmp, false);
		if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			uint8_t b[2];

			if (offset > 0x3FFF) {
				return ndr_push_error(ndr, NDR_ERR_STRING,
						      "offset for dns string label pointer %u[%08X] > 0x00003FFF",
						      offset, offset);
			}

			b[0] = 0xC0 | (offset>>8);
			b[1] = (offset & 0xFF);

			return ndr_push_bytes(ndr, b, 2);
		}

		complen = strcspn(s, ".");

		/* we need to make sure the length fits into 6 bytes */
		if (complen > 0x3F) {
			return ndr_push_error(ndr, NDR_ERR_STRING,
					      "component length %u[%08X] > 0x0000003F",
					      (unsigned)complen, (unsigned)complen);
		}

		compname = talloc_asprintf(ndr, "%c%*.*s",
						(unsigned char)complen,
						(unsigned char)complen,
						(unsigned char)complen, s);
		NDR_ERR_HAVE_NO_MEMORY(compname);

		/* remember the current componemt + the rest of the string
		 * so it can be reused later
		 */
		NDR_CHECK(ndr_token_store(ndr, &ndr->dns_string_list, s, ndr->offset));

		/* push just this component into the blob */
		NDR_CHECK(ndr_push_bytes(ndr, (const uint8_t *)compname, complen+1));
		talloc_free(compname);

		s += complen;
		if (*s == '.') s++;
	}

	/* if we reach the end of the string and have pushed the last component
	 * without using a label pointer, we need to terminate the string
	 */
	return ndr_push_bytes(ndr, (const uint8_t *)"", 1);
}

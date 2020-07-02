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
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "system/locale.h"
#include "lib/util/util_net.h"
#include "ndr_dns_utils.h"

/* don't allow an unlimited number of name components */
#define MAX_COMPONENTS 128

/**
  print a dns string
*/
_PUBLIC_ void ndr_print_dns_string(struct ndr_print *ndr,
				   const char *name,
				   const char *s)
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
					"BAD DNS NAME component, bad offset");
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
						"BAD DNS NAME component, " \
						"bad label offset");
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
					      "BAD DNS NAME component, " \
					      "reserved length field: 0x%02x",
					      (len &0xC));
		}
		if (*offset + len + 1 > ndr->data_size) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "BAD DNS NAME component, "\
					      "length too long");
		}
		*component = (uint8_t*)talloc_strndup(ndr,
				(const char *)&ndr->data[1 + *offset], len);
		NDR_ERR_HAVE_NO_MEMORY(*component);
		*offset += len + 1;
		*max_offset = MAX(*max_offset, *offset);
		return NDR_ERR_SUCCESS;
	}

	/* too many pointers */
	return ndr_pull_error(ndr, NDR_ERR_STRING,
			      "BAD DNS NAME component, too many pointers");
}

/**
  pull a dns_string from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_dns_string(struct ndr_pull *ndr,
					       int ndr_flags,
					       const char **s)
{
	uint32_t offset = ndr->offset;
	uint32_t max_offset = offset;
	unsigned num_components;
	char *name;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	name = talloc_strdup(ndr->current_mem_ctx, "");

	/* break up name into a list of components */
	for (num_components=0; num_components<MAX_COMPONENTS;
	     num_components++) {
		uint8_t *component = NULL;
		NDR_CHECK(ndr_pull_component(ndr, &component, &offset,
					     &max_offset));
		if (component == NULL) break;
		if (num_components > 0) {
			name = talloc_asprintf_append_buffer(name, ".%s",
							     component);
		} else {
			name = talloc_asprintf_append_buffer(name, "%s",
							     component);
		}
		NDR_ERR_HAVE_NO_MEMORY(name);
	}
	if (num_components == MAX_COMPONENTS) {
		return ndr_pull_error(ndr, NDR_ERR_STRING,
				      "BAD DNS NAME too many components");
	}

	(*s) = name;
	ndr->offset = max_offset;

	return NDR_ERR_SUCCESS;
}

/**
  push a dns string to the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_dns_string(struct ndr_push *ndr,
					       int ndr_flags,
					       const char *s)
{
	return ndr_push_dns_string_list(ndr,
					&ndr->dns_string_list,
					ndr_flags,
					s,
					false);
}

_PUBLIC_ enum ndr_err_code ndr_pull_dns_txt_record(struct ndr_pull *ndr, int ndr_flags, struct dns_txt_record *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		enum ndr_err_code ndr_err;
		uint32_t data_size = ndr->data_size;
		uint32_t record_size = 0;
		ndr_err = ndr_token_retrieve(&ndr->array_size_list, r,
					     &record_size);
		if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NDR_PULL_NEED_BYTES(ndr, record_size);
			ndr->data_size = ndr->offset + record_size;
		}
		NDR_CHECK(ndr_pull_align(ndr, 1));
		NDR_CHECK(ndr_pull_dnsp_string_list(ndr, NDR_SCALARS, &r->txt));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 1));
		ndr->data_size = data_size;
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_dns_res_rec(struct ndr_push *ndr,
						int ndr_flags,
						const struct dns_res_rec *r)
{
	uint32_t _flags_save_STRUCT = ndr->flags;
	uint32_t _saved_offset1, _saved_offset2;
	uint16_t length;
	ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX |
				   LIBNDR_FLAG_NOALIGN);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t _flags_save_name = ndr->flags;

		NDR_CHECK(ndr_push_align(ndr, 4));

		switch (r->rr_type) {
		case DNS_QTYPE_TKEY:
		case DNS_QTYPE_TSIG:
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NO_COMPRESSION);
			break;
		default:
			break;
		}
		NDR_CHECK(ndr_push_dns_string(ndr, NDR_SCALARS, r->name));
		ndr->flags = _flags_save_name;

		NDR_CHECK(ndr_push_dns_qtype(ndr, NDR_SCALARS, r->rr_type));
		NDR_CHECK(ndr_push_dns_qclass(ndr, NDR_SCALARS, r->rr_class));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->ttl));
		_saved_offset1 = ndr->offset;
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, 0));
		if (r->length > 0) {
			uint32_t _saved_offset3;

			NDR_CHECK(ndr_push_set_switch_value(ndr, &r->rdata,
							    r->rr_type));
			_saved_offset3 = ndr->offset;
			NDR_CHECK(ndr_push_dns_rdata(ndr, NDR_SCALARS,
						     &r->rdata));
			if ((ndr->offset != _saved_offset3) &&
			    (r->unexpected.length > 0)) {
				/*
				 * ndr_push_dns_rdata pushed a known
				 * record, but we have something
				 * unexpected. That's invalid.
				 */
				return ndr_push_error(ndr,
						      NDR_ERR_LENGTH,
						      "Invalid...Unexpected " \
						      "blob length is too " \
						      "large");
			}
		}
		if (r->unexpected.length > UINT16_MAX) {
			return ndr_push_error(ndr, NDR_ERR_LENGTH,
					      "Unexpected blob length "\
					      "is too large");
		}

		NDR_CHECK(ndr_push_bytes(ndr, r->unexpected.data,
					 r->unexpected.length));
		NDR_CHECK(ndr_push_trailer_align(ndr, 4));
		length = ndr->offset - (_saved_offset1 + 2);
		_saved_offset2 = ndr->offset;
		ndr->offset = _saved_offset1;
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, length));
		ndr->offset = _saved_offset2;
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_push_dns_rdata(ndr, NDR_BUFFERS,
					     &r->rdata));
	}
	ndr->flags = _flags_save_STRUCT;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_dns_res_rec(struct ndr_pull *ndr,
						int ndr_flags,
						struct dns_res_rec *r)
{
	uint32_t _flags_save_STRUCT = ndr->flags;
	uint32_t _saved_offset1;
	uint32_t pad, length;

	ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX |
				   LIBNDR_FLAG_NOALIGN);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_dns_string(ndr, NDR_SCALARS, &r->name));
		NDR_CHECK(ndr_pull_dns_qtype(ndr, NDR_SCALARS, &r->rr_type));
		NDR_CHECK(ndr_pull_dns_qclass(ndr, NDR_SCALARS, &r->rr_class));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->ttl));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->length));
		_saved_offset1 = ndr->offset;
		if (r->length > 0) {
			NDR_CHECK(ndr_token_store(ndr, &ndr->array_size_list,
						  &r->rdata,
						  r->length));
			NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->rdata,
							    r->rr_type));
			NDR_CHECK(ndr_pull_dns_rdata(ndr, NDR_SCALARS,
						     &r->rdata));
		} else {
			ZERO_STRUCT(r->rdata);
		}
		length = ndr->offset - _saved_offset1;
		if (length > r->length) {
			return ndr_pull_error(ndr, NDR_ERR_LENGTH, "TODO");
		}

		r->unexpected = data_blob_null;
		pad = r->length - length;
		if (pad > 0) {
			NDR_PULL_NEED_BYTES(ndr, pad);
			r->unexpected = data_blob_talloc(ndr->current_mem_ctx,
							 ndr->data +
							 ndr->offset,
							 pad);
			if (r->unexpected.data == NULL) {
				return ndr_pull_error(ndr,
						      NDR_ERR_ALLOC,
						      "Failed to allocate a " \
						      "data blob");
			}
			ndr->offset += pad;
		}


		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_dns_rdata(ndr, NDR_BUFFERS, &r->rdata));
	}
	ndr->flags = _flags_save_STRUCT;
	return NDR_ERR_SUCCESS;
}

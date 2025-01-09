/*
   Unix SMB/CIFS implementation.

   fast routines for getting the wire size of security objects

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan Metzmacher 2006-2008

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
#include "librpc/gen_ndr/ndr_security.h"
#include "../libcli/security/security.h"


/*
 * Find the wire size of a security_ace that has no trailing coda.
 * This is used in ndr_pull_security_ace() generated from security.idl
 * to work out where the coda starts (and in ndr_size_security_ace()
 * just below).
 */
static size_t ndr_size_security_ace_core(const struct security_ace *ace, libndr_flags flags)
{
	size_t ret;

	if (!ace) return 0;

	ret = 8 + ndr_size_dom_sid(&ace->trustee, flags);
	if (sec_ace_object(ace->type)) {
		ret += 4; /* uint32 bitmap ace->object.object.flags */
		if (ace->object.object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
			ret += 16; /* GUID ace->object.object.type.type */
		}
		if (ace->object.object.flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT) {
			ret += 16; /* GUID ace->object.object.inherited_type.inherited_type */
		}
	}

	return ret;
}

/*
  return the wire size of a security_ace
*/
size_t ndr_size_security_ace(const struct security_ace *ace, libndr_flags flags)
{
	size_t base = ndr_size_security_ace_core(ace, flags);
	size_t ret = base;
	if (sec_ace_callback(ace->type)) {
		ret += ace->coda.conditions.length;
	} else if (ace->type == SEC_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE) {
		ret += ndr_size_security_ace_coda(&ace->coda, ace->type, flags);
	} else {
		/*
		 * Normal ACEs have a coda.ignored blob that is always or
		 * almost always empty. We aren't going to push it (it is
		 * ignored), so we don't add that length to the size.
		 */
	}
	/* round up to a multiple of 4  (MS-DTYP 2.4.4.1) */
	ret = (ret + 3ULL) & ~3ULL;
	if (unlikely(ret < base)) {
		/* overflow, and there's not much we can do anyway */
		return 0;
	}
	return ret;
}


static inline enum ndr_err_code ndr_maybe_pull_security_ace_object_ctr(struct ndr_pull *ndr,
								       ndr_flags_type ndr_flags,
								       struct security_ace *r)
{
	/*
	 * If this is not an object ACE (as is usually common),
	 * ndr_pull_security_ace_object_ctr() will do nothing.
	 *
	 * By avoiding calling the function in that case, we avoid some
	 * tallocing and ndr token busywork.
	 */
	bool is_object = sec_ace_object(r->type);
	if (is_object) {
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->object, is_object));
		NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, ndr_flags, &r->object));
	}
	return NDR_ERR_SUCCESS;
}


_PUBLIC_ enum ndr_err_code ndr_pull_security_ace(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct security_ace *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		ssize_t sub_size;
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_security_ace_type(ndr, NDR_SCALARS, &r->type));
		NDR_CHECK(ndr_pull_security_ace_flags(ndr, NDR_SCALARS, &r->flags));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->access_mask));
		NDR_CHECK(ndr_maybe_pull_security_ace_object_ctr(ndr, NDR_SCALARS, r));
		NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &r->trustee));
		sub_size = ndr_subcontext_size_of_ace_coda(r, r->size, ndr->flags);
		if (sub_size == 0 && !sec_ace_has_extra_blob(r->type)) {
			r->coda.ignored.data = NULL;
			r->coda.ignored.length = 0;
		} else {
			struct ndr_pull *_ndr_coda;
			NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_coda, 0, sub_size));
			NDR_CHECK(ndr_pull_set_switch_value(_ndr_coda, &r->coda, r->type));
			NDR_CHECK(ndr_pull_security_ace_coda(_ndr_coda, NDR_SCALARS|NDR_BUFFERS, &r->coda));
			NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_coda, 0, sub_size));
		}
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_maybe_pull_security_ace_object_ctr(ndr, NDR_BUFFERS, r));
	}
	return NDR_ERR_SUCCESS;
}


static inline enum ndr_err_code ndr_maybe_push_security_ace_object_ctr(struct ndr_push *ndr,
								       ndr_flags_type ndr_flags,
								       const struct security_ace *r)
{
	/*
	 * ndr_push_security_ace_object_ctr() does nothing (except tallocing
	 * and ndr_token fiddling) unless the ACE is an object ACE, which is
	 * usually very unlikely.
	 */
	bool is_object = sec_ace_object(r->type);
	if (is_object) {
		NDR_CHECK(ndr_push_set_switch_value(ndr, &r->object, is_object));
		NDR_CHECK(ndr_push_security_ace_object_ctr(ndr, ndr_flags, &r->object));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_security_ace(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct security_ace *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_security_ace_type(ndr, NDR_SCALARS, r->type));
		NDR_CHECK(ndr_push_security_ace_flags(ndr, NDR_SCALARS, r->flags));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, ndr_size_security_ace(r, ndr->flags)));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->access_mask));
		NDR_CHECK(ndr_maybe_push_security_ace_object_ctr(ndr, NDR_SCALARS, r));
		NDR_CHECK(ndr_push_dom_sid(ndr, NDR_SCALARS, &r->trustee));
		if (sec_ace_has_extra_blob(r->type)) {
			struct ndr_push *_ndr_coda;
			size_t coda_size = ndr_subcontext_size_of_ace_coda(
				r,
				ndr_size_security_ace(r, ndr->flags),
				ndr->flags);
			NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_coda, 0, coda_size));
			NDR_CHECK(ndr_push_set_switch_value(_ndr_coda, &r->coda, r->type));
			NDR_CHECK(ndr_push_security_ace_coda(_ndr_coda, NDR_SCALARS|NDR_BUFFERS, &r->coda));
			NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_coda, 0, coda_size));
		}
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_maybe_push_security_ace_object_ctr(ndr, NDR_BUFFERS, r));
	}
	return NDR_ERR_SUCCESS;
}


/*
 * An ACE coda can't be bigger than the space allowed for by
 * ace->size, so we need to check this from the context of the ACE.
 *
 * Usually the coda also can't be any smaller than the remaining
 * space, because it is defined as a blob consuming everything it can.
 *
 * This is only used to find the size for the coda subcontext in
 * security.idl.
 */
size_t ndr_subcontext_size_of_ace_coda(const struct security_ace *ace,
				       size_t ace_size,
				       libndr_flags flags)
{
	size_t core_size;
	if (ace_size == 0) {
		return 0;
	}
	core_size = ndr_size_security_ace_core(ace, flags);
	if (ace_size < core_size) {
		return 0;
	}
	return ace_size - core_size;
}

/*
  return the wire size of a security_acl
*/
size_t ndr_size_security_acl(const struct security_acl *theacl, libndr_flags flags)
{
	size_t ret;
	int i;
	if (!theacl) return 0;
	ret = 8;
	for (i=0;i<theacl->num_aces;i++) {
		ret += ndr_size_security_ace(&theacl->aces[i], flags);
	}
	return ret;
}

/*
  return the wire size of a security descriptor
*/
size_t ndr_size_security_descriptor(const struct security_descriptor *sd, libndr_flags flags)
{
	size_t ret;
	if (!sd) return 0;

	ret = 20;
	ret += ndr_size_dom_sid(sd->owner_sid, flags);
	ret += ndr_size_dom_sid(sd->group_sid, flags);
	ret += ndr_size_security_acl(sd->dacl, flags);
	ret += ndr_size_security_acl(sd->sacl, flags);
	return ret;
}

/*
  return the wire size of a dom_sid
*/
size_t ndr_size_dom_sid(const struct dom_sid *sid, libndr_flags flags)
{
	if (!sid) return 0;
	return 8 + 4*sid->num_auths;
}

size_t ndr_size_dom_sid28(const struct dom_sid *sid, libndr_flags flags)
{
	if (all_zero((const uint8_t *)sid, sizeof(struct dom_sid))) {
		return 0;
	}
	return ndr_size_dom_sid(sid, flags);
}

size_t ndr_size_dom_sid0(const struct dom_sid *sid, libndr_flags flags)
{
	return ndr_size_dom_sid28(sid, flags);
}

/*
  print a dom_sid
*/
void ndr_print_dom_sid(struct ndr_print *ndr, const char *name, const struct dom_sid *sid)
{
	struct dom_sid_buf buf;
	ndr->print(ndr, "%-25s: %s", name, dom_sid_str_buf(sid, &buf));
}

void ndr_print_dom_sid2(struct ndr_print *ndr, const char *name, const struct dom_sid *sid)
{
	ndr_print_dom_sid(ndr, name, sid);
}

void ndr_print_dom_sid28(struct ndr_print *ndr, const char *name, const struct dom_sid *sid)
{
	ndr_print_dom_sid(ndr, name, sid);
}

void ndr_print_dom_sid0(struct ndr_print *ndr, const char *name, const struct dom_sid *sid)
{
	ndr_print_dom_sid(ndr, name, sid);
}


/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
enum ndr_err_code ndr_pull_dom_sid2(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct dom_sid *sid)
{
	uint32_t num_auths;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}
	NDR_CHECK(ndr_pull_uint3264(ndr, NDR_SCALARS, &num_auths));
	NDR_CHECK(ndr_pull_dom_sid(ndr, ndr_flags, sid));
	if (sid->num_auths != num_auths) {
		return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE,
				      "Bad num_auths %"PRIu32"; should equal %"PRId8,
				      num_auths, sid->num_auths);
	}
	return NDR_ERR_SUCCESS;
}

/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
enum ndr_err_code ndr_push_dom_sid2(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct dom_sid *sid)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}
	NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, sid->num_auths));
	return ndr_push_dom_sid(ndr, ndr_flags, sid);
}

/*
  parse a dom_sid28 - this is a dom_sid in a fixed 28 byte buffer, so we need to ensure there are only up to 5 sub_auth
*/
enum ndr_err_code ndr_pull_dom_sid28(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct dom_sid *sid)
{
	enum ndr_err_code status;
	struct ndr_pull *subndr;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	subndr = talloc_zero(ndr, struct ndr_pull);
	NDR_ERR_HAVE_NO_MEMORY(subndr);
	subndr->flags		= ndr->flags;
	subndr->current_mem_ctx	= ndr->current_mem_ctx;

	subndr->data		= ndr->data + ndr->offset;
	subndr->data_size	= 28;
	subndr->offset		= 0;

	status = ndr_pull_advance(ndr, 28);
	if (!NDR_ERR_CODE_IS_SUCCESS(status)) {
		talloc_free(subndr);
		return status;
	}

	status = ndr_pull_dom_sid(subndr, ndr_flags, sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(status)) {
		/* handle a w2k bug which send random data in the buffer */
		ZERO_STRUCTP(sid);
	} else if (sid->num_auths == 0) {
		ZERO_STRUCT(sid->sub_auths);
	}

	talloc_free(subndr);
	return NDR_ERR_SUCCESS;
}

/*
  push a dom_sid28 - this is a dom_sid in a 28 byte fixed buffer
*/
enum ndr_err_code ndr_push_dom_sid28(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct dom_sid *sid)
{
	uint32_t old_offset;
	uint32_t padding;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (sid->num_auths > 5) {
		return ndr_push_error(ndr, NDR_ERR_RANGE,
				      "dom_sid28 allows only up to 5 sub auths [%"PRId8"]",
				      sid->num_auths);
	}

	old_offset = ndr->offset;
	NDR_CHECK(ndr_push_dom_sid(ndr, ndr_flags, sid));

	padding = 28 - (ndr->offset - old_offset);

	if (padding > 0) {
		NDR_CHECK(ndr_push_zero(ndr, padding));
	}

	return NDR_ERR_SUCCESS;
}

/*
  parse a dom_sid0 - this is a dom_sid in a variable byte buffer, which is maybe empty
*/
enum ndr_err_code ndr_pull_dom_sid0(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct dom_sid *sid)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (ndr->data_size == ndr->offset) {
		ZERO_STRUCTP(sid);
		return NDR_ERR_SUCCESS;
	}

	return ndr_pull_dom_sid(ndr, ndr_flags, sid);
}

/*
  push a dom_sid0 - this is a dom_sid in a variable byte buffer, which is maybe empty
*/
enum ndr_err_code ndr_push_dom_sid0(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct dom_sid *sid)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (!sid) {
		return NDR_ERR_SUCCESS;
	}

	if (all_zero((const uint8_t *)sid, sizeof(struct dom_sid))) {
		return NDR_ERR_SUCCESS;
	}

	return ndr_push_dom_sid(ndr, ndr_flags, sid);
}

_PUBLIC_ enum ndr_err_code ndr_push_dom_sid(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct dom_sid *r)
{
	uint32_t cntr_sub_auths_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->sid_rev_num));
		NDR_CHECK(ndr_push_int8(ndr, NDR_SCALARS, r->num_auths));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
		if (r->num_auths < 0 || r->num_auths > ARRAY_SIZE(r->sub_auths)) {
			return ndr_push_error(ndr, NDR_ERR_RANGE, "value (%"PRId8") out of range (0 - %zu)", r->num_auths, ARRAY_SIZE(r->sub_auths));
		}
		for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->sub_auths[cntr_sub_auths_0]));
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_dom_sid(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct dom_sid *r)
{
	uint32_t cntr_sub_auths_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->sid_rev_num));
		NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->num_auths));
		if (r->num_auths < 0 || r->num_auths > ARRAY_SIZE(r->sub_auths)) {
			return ndr_pull_error(ndr, NDR_ERR_RANGE, "value (%"PRId8") out of range (0 - %zu)", r->num_auths, ARRAY_SIZE(r->sub_auths));
		}
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
		ZERO_STRUCT(r->sub_auths);
		for (cntr_sub_auths_0 = 0; cntr_sub_auths_0 < r->num_auths; cntr_sub_auths_0++) {
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->sub_auths[cntr_sub_auths_0]));
		}
	}
	return NDR_ERR_SUCCESS;
}

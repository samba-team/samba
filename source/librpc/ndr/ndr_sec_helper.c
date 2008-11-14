/* 
   Unix SMB/CIFS implementation.

   fast routines for getting the wire size of security objects

   Copyright (C) Andrew Tridgell 2003
   
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

/*
  return the wire size of a dom_sid
*/
size_t ndr_size_dom_sid(const struct dom_sid *sid, int flags)
{
	if (!sid) return 0;
	return 8 + 4*sid->num_auths;
}

size_t ndr_size_dom_sid28(const struct dom_sid *sid, int flags)
{
	struct dom_sid zero_sid;

	if (!sid) return 0;

	ZERO_STRUCT(zero_sid);

	if (memcmp(&zero_sid, sid, sizeof(zero_sid)) == 0) {
		return 0;
	}

	return 8 + 4*sid->num_auths;
}

size_t ndr_size_dom_sid0(const struct dom_sid *sid, int flags)
{
	return ndr_size_dom_sid28(sid, flags);
}

enum ndr_err_code ndr_pull_security_ace(struct ndr_pull *ndr, int ndr_flags, struct security_ace *r)
{
	if (ndr_flags & NDR_SCALARS) {
		uint32_t start_ofs = ndr->offset;
		uint32_t size = 0;
		uint32_t pad = 0;
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_security_ace_type(ndr, NDR_SCALARS, &r->type));
		NDR_CHECK(ndr_pull_security_ace_flags(ndr, NDR_SCALARS, &r->flags));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->access_mask));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->object, r->type));
		NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_SCALARS, &r->object));
		NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &r->trustee));
		size = ndr->offset - start_ofs;
		if (r->size < size) {
			return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
					      "ndr_pull_security_ace: r->size %u < size %u",
					      (unsigned)r->size, size);
		}
		pad = r->size - size;
		NDR_PULL_NEED_BYTES(ndr, pad);
		ndr->offset += pad;
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_security_ace_object_ctr(ndr, NDR_BUFFERS, &r->object));
	}
	return NDR_ERR_SUCCESS;
}

/*
  return the wire size of a security_ace
*/
size_t ndr_size_security_ace(const struct security_ace *ace, int flags)
{
	if (!ace) return 0;
	return 8 + ndr_size_dom_sid(&ace->trustee, flags);
}


/*
  return the wire size of a security_acl
*/
size_t ndr_size_security_acl(const struct security_acl *acl, int flags)
{
	size_t ret;
	int i;
	if (!acl) return 0;
	ret = 8;
	for (i=0;i<acl->num_aces;i++) {
		ret += ndr_size_security_ace(&acl->aces[i], flags);
	}
	return ret;
}

/*
  return the wire size of a security descriptor
*/
size_t ndr_size_security_descriptor(const struct security_descriptor *sd, int flags)
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
  print a dom_sid
*/
void ndr_print_dom_sid(struct ndr_print *ndr, const char *name, const struct dom_sid *sid)
{
	ndr->print(ndr, "%-25s: %s", name, dom_sid_string(ndr, sid));
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


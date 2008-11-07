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

/*
  return the wire size of a security_ace
*/
size_t ndr_size_security_ace(const struct security_ace *ace, int flags)
{
	size_t ret;

	if (!ace) return 0;

	ret = 8 + ndr_size_dom_sid(&ace->trustee, flags);

	switch (ace->type) {
	case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
	case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
	case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT:
	case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT:
		ret += 4; /* uint32 bitmap ace->object.object.flags */
		if (ace->object.object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
			ret += 16; /* GUID ace->object.object.type.type */
		}
		if (ace->object.object.flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT) {
			ret += 16; /* GUID ace->object.object.inherited_typeinherited_type */
		}
		break;
	default:
		break;
	}

	return ret;
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


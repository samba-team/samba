/* 
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling security descriptors
   and related structures

   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "includes.h"

/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
NTSTATUS ndr_pull_dom_sid2(struct ndr_pull *ndr, int ndr_flags, struct dom_sid *sid)
{
	uint32_t num_auths;
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, &num_auths));
	return ndr_pull_dom_sid(ndr, ndr_flags, sid);
}

/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
NTSTATUS ndr_push_dom_sid2(struct ndr_push *ndr, int ndr_flags, struct dom_sid *sid)
{
	if (!(ndr_flags & NDR_SCALARS)) {
		return NT_STATUS_OK;
	}
	NDR_CHECK(ndr_push_uint32(ndr, sid->num_auths));
	return ndr_push_dom_sid(ndr, ndr_flags, sid);
}


/*
  convert a dom_sid to a string
*/
char *dom_sid_string(TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	int i, ofs, maxlen;
	uint32_t ia;
	char *ret;
	
	if (!sid) {
		return talloc_strdup(mem_ctx, "(NULL SID)");
	}

	maxlen = sid->num_auths * 11 + 25;
	ret = talloc(mem_ctx, maxlen);
	if (!ret) return talloc_strdup(mem_ctx, "(SID ERR)");

	ia = (sid->id_auth[5]) +
		(sid->id_auth[4] << 8 ) +
		(sid->id_auth[3] << 16) +
		(sid->id_auth[2] << 24);

	ofs = snprintf(ret, maxlen, "S-%u-%lu", 
		       (unsigned int)sid->sid_rev_num, (unsigned long)ia);

	for (i = 0; i < sid->num_auths; i++) {
		ofs += snprintf(ret + ofs, maxlen - ofs, "-%lu", (unsigned long)sid->sub_auths[i]);
	}
	
	return ret;
}


/*
  print a dom_sid
*/
void ndr_print_dom_sid(struct ndr_print *ndr, const char *name, struct dom_sid *sid)
{
	ndr->print(ndr, "%-25s: %s", name, dom_sid_string(ndr->mem_ctx, sid));
}

void ndr_print_dom_sid2(struct ndr_print *ndr, const char *name, struct dom_sid2 *sid)
{
	ndr_print_dom_sid(ndr, name, sid);
}

/*
  return the wire size of a dom_sid
*/
size_t ndr_size_dom_sid(struct dom_sid *sid)
{
	if (!sid) return 0;
	return 8 + 4*sid->num_auths;
}

/*
  add a rid to a domain dom_sid to make a full dom_sid
*/
struct dom_sid *dom_sid_add_rid(TALLOC_CTX *mem_ctx, 
				const struct dom_sid *domain_sid, 
				uint32_t rid)
{
	struct dom_sid *sid;

	sid = talloc_p(mem_ctx, struct dom_sid);
	if (!sid) return NULL;

	*sid = *domain_sid;
	sid->sub_auths = talloc_array_p(mem_ctx, uint32_t, sid->num_auths+1);
	if (!sid->sub_auths) {
		return NULL;
	}
	memcpy(sid->sub_auths, domain_sid->sub_auths, sid->num_auths*sizeof(uint32_t));
	sid->sub_auths[sid->num_auths] = rid;
	sid->num_auths++;
	return sid;
}

/*
  return the wire size of a security_ace
*/
size_t ndr_size_security_ace(struct security_ace *ace)
{
	if (!ace) return 0;
	return 8 + ndr_size_dom_sid(&ace->trustee);
}


/*
  return the wire size of a security_acl
*/
size_t ndr_size_security_acl(struct security_acl *acl)
{
	size_t ret;
	int i;
	if (!acl) return 0;
	ret = 8;
	for (i=0;i<acl->num_aces;i++) {
		ret += ndr_size_security_ace(&acl->aces[i]);
	}
	return ret;
}

/*
  return the wire size of a security descriptor
*/
size_t ndr_size_security_descriptor(struct security_descriptor *sd)
{
	size_t ret;
	if (!sd) return 0;
	
	ret = 20;
	ret += ndr_size_dom_sid(sd->owner_sid);
	ret += ndr_size_dom_sid(sd->group_sid);
	ret += ndr_size_security_acl(sd->dacl);
	ret += ndr_size_security_acl(sd->sacl);
	return ret;
}

/* 
   talloc and copy a security descriptor
 */
struct security_descriptor *copy_security_descriptor(TALLOC_CTX *mem_ctx, 
							const struct security_descriptor *osd)
{
	struct security_descriptor *nsd;

	/* FIXME */
	DEBUG(1, ("copy_security_descriptor: sorry unimplemented yet\n"));
	nsd = NULL;

	return nsd;
}

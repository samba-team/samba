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
  parse a security_ace
*/
NTSTATUS ndr_pull_security_ace(struct ndr_pull *ndr, struct security_ace *ace)
{
	uint16 size;
	struct ndr_pull_save save;

	ndr_pull_save(ndr, &save);

	NDR_CHECK(ndr_pull_u8(ndr, &ace->type));
	NDR_CHECK(ndr_pull_u8(ndr, &ace->flags));
	NDR_CHECK(ndr_pull_u16(ndr, &size));
	NDR_CHECK(ndr_pull_limit_size(ndr, size, 4));

	NDR_CHECK(ndr_pull_u32(ndr, &ace->access_mask));

	if (sec_ace_object(ace->type)) {
		NDR_ALLOC(ndr, ace->obj);
		NDR_CHECK(ndr_pull_u32(ndr, &ace->obj->flags));
		if (ace->obj->flags & SEC_ACE_OBJECT_PRESENT) {
			NDR_CHECK(ndr_pull_guid(ndr, &ace->obj->object_guid));
		}
		if (ace->obj->flags & SEC_ACE_OBJECT_INHERITED_PRESENT) {
			NDR_CHECK(ndr_pull_guid(ndr, &ace->obj->inherit_guid));
		}
	}


	NDR_CHECK(ndr_pull_dom_sid(ndr, &ace->trustee));

	ndr_pull_restore(ndr, &save);
	NDR_CHECK(ndr_pull_advance(ndr, size));

	return NT_STATUS_OK;	
}

/*
  parse a security_acl
*/
NTSTATUS ndr_pull_security_acl(struct ndr_pull *ndr, struct security_acl *acl)
{
	int i;
	uint16 size;
	struct ndr_pull_save save;

	ndr_pull_save(ndr, &save);

	NDR_CHECK(ndr_pull_u16(ndr, &acl->revision));
	NDR_CHECK(ndr_pull_u16(ndr, &size));
	NDR_CHECK(ndr_pull_limit_size(ndr, size, 4));
	NDR_CHECK(ndr_pull_u32(ndr, &acl->num_aces));

	NDR_ALLOC_N(ndr, acl->aces, acl->num_aces);

	for (i=0;i<acl->num_aces;i++) {
		NDR_CHECK(ndr_pull_security_ace(ndr, &acl->aces[i]));
	}

	ndr_pull_restore(ndr, &save);
	NDR_CHECK(ndr_pull_advance(ndr, size));

	return NT_STATUS_OK;
}	

/*
  parse a security_acl offset and structure
*/
NTSTATUS ndr_pull_security_acl_ofs(struct ndr_pull *ndr, struct security_acl **acl)
{
	uint32 ofs;
	struct ndr_pull_save save;

	NDR_CHECK(ndr_pull_u32(ndr, &ofs));
	if (ofs == 0) {
		/* it is valid for an acl ptr to be NULL */
		*acl = NULL;
		return NT_STATUS_OK;
	}

	ndr_pull_save(ndr, &save);
	NDR_CHECK(ndr_pull_set_offset(ndr, ofs));
	NDR_ALLOC(ndr, *acl);
	NDR_CHECK(ndr_pull_security_acl(ndr, *acl));
	ndr_pull_restore(ndr, &save);

	return NT_STATUS_OK;
}


/*
  parse a dom_sid
*/
NTSTATUS ndr_pull_dom_sid(struct ndr_pull *ndr, struct dom_sid *sid)
{
	int i;

	NDR_CHECK(ndr_pull_u8(ndr, &sid->sid_rev_num));
	NDR_CHECK(ndr_pull_u8(ndr, &sid->num_auths));
	for (i=0;i<6;i++) {
		NDR_CHECK(ndr_pull_u8(ndr, &sid->id_auth[i]));
	}

	NDR_ALLOC_N(ndr, sid->sub_auths, sid->num_auths);

	for (i=0;i<sid->num_auths;i++) {
		NDR_CHECK(ndr_pull_u32(ndr, &sid->sub_auths[i]));
	}

	return NT_STATUS_OK;
}

/*
  parse a dom_sid2 - this is a dom_sid but with an extra copy of the num_auths field
*/
NTSTATUS ndr_pull_dom_sid2(struct ndr_pull *ndr, struct dom_sid *sid)
{
	uint32 num_auths;
	NDR_CHECK(ndr_pull_u32(ndr, &num_auths));
	return ndr_pull_dom_sid(ndr, sid);
}

/*
  parse a dom_sid offset and structure
*/
NTSTATUS ndr_pull_dom_sid_ofs(struct ndr_pull *ndr, struct dom_sid **sid)
{
	uint32 ofs;
	struct ndr_pull_save save;

	NDR_CHECK(ndr_pull_u32(ndr, &ofs));
	if (ofs == 0) {
		/* it is valid for a dom_sid ptr to be NULL */
		*sid = NULL;
		return NT_STATUS_OK;
	}

	ndr_pull_save(ndr, &save);
	NDR_CHECK(ndr_pull_set_offset(ndr, ofs));
	NDR_ALLOC(ndr, *sid);
	NDR_CHECK(ndr_pull_dom_sid(ndr, *sid));
	ndr_pull_restore(ndr, &save);

	return NT_STATUS_OK;
}

/*
  parse a security descriptor 
*/
NTSTATUS ndr_pull_security_descriptor(struct ndr_pull *ndr, 
				      struct security_descriptor **sd)
{
	NDR_ALLOC(ndr, *sd);

	NDR_CHECK(ndr_pull_u8(ndr, &(*sd)->revision));
	NDR_CHECK(ndr_pull_u16(ndr, &(*sd)->type));
	NDR_CHECK(ndr_pull_dom_sid_ofs(ndr, &(*sd)->owner_sid));
	NDR_CHECK(ndr_pull_dom_sid_ofs(ndr, &(*sd)->group_sid));
	NDR_CHECK(ndr_pull_security_acl_ofs(ndr, &(*sd)->sacl));
	NDR_CHECK(ndr_pull_security_acl_ofs(ndr, &(*sd)->dacl));

	return NT_STATUS_OK;
}


/*
  parse a security_ace
*/
NTSTATUS ndr_push_security_ace(struct ndr_push *ndr, struct security_ace *ace)
{
	struct ndr_push_save save1, save2;

	NDR_CHECK(ndr_push_u8(ndr, ace->type));
	NDR_CHECK(ndr_push_u8(ndr, ace->flags));
	ndr_push_save(ndr, &save1);
	NDR_CHECK(ndr_push_u16(ndr, 0));
	NDR_CHECK(ndr_push_u32(ndr, ace->access_mask));

	if (sec_ace_object(ace->type)) {
		NDR_CHECK(ndr_push_u32(ndr, ace->obj->flags));
		if (ace->obj->flags & SEC_ACE_OBJECT_PRESENT) {
			NDR_CHECK(ndr_push_guid(ndr, &ace->obj->object_guid));
		}
		if (ace->obj->flags & SEC_ACE_OBJECT_INHERITED_PRESENT) {
			NDR_CHECK(ndr_push_guid(ndr, &ace->obj->inherit_guid));
		}
	}

	NDR_CHECK(ndr_push_dom_sid(ndr, &ace->trustee));

	ndr_push_save(ndr, &save2);
	ndr_push_restore(ndr, &save1);
	NDR_CHECK(ndr_push_u16(ndr, 2 + save2.offset - save1.offset));
	ndr_push_restore(ndr, &save2);

	return NT_STATUS_OK;	
}


/*
  push a security_acl
*/
NTSTATUS ndr_push_security_acl(struct ndr_push *ndr, struct security_acl *acl)
{
	int i;
	struct ndr_push_save save1, save2;

	NDR_CHECK(ndr_push_u16(ndr, acl->revision));
	ndr_push_save(ndr, &save1);
	NDR_CHECK(ndr_push_u16(ndr, 0));
	NDR_CHECK(ndr_push_u32(ndr, acl->num_aces));
	for (i=0;i<acl->num_aces;i++) {
		NDR_CHECK(ndr_push_security_ace(ndr, &acl->aces[i]));
	}
	ndr_push_save(ndr, &save2);
	ndr_push_restore(ndr, &save1);
	NDR_CHECK(ndr_push_u16(ndr, 2 + save2.offset - save1.offset));
	ndr_push_restore(ndr, &save2);

	return NT_STATUS_OK;
}	

/*
  push a dom_sid
*/
NTSTATUS ndr_push_dom_sid(struct ndr_push *ndr, struct dom_sid *sid)
{
	int i;

	NDR_CHECK(ndr_push_u8(ndr, sid->sid_rev_num));
	NDR_CHECK(ndr_push_u8(ndr, sid->num_auths));
	for (i=0;i<6;i++) {
		NDR_CHECK(ndr_push_u8(ndr, sid->id_auth[i]));
	}
	for (i=0;i<sid->num_auths;i++) {
		NDR_CHECK(ndr_push_u32(ndr, sid->sub_auths[i]));
	}

	return NT_STATUS_OK;
}


/*
  generate a ndr security descriptor 
*/
NTSTATUS ndr_push_security_descriptor(struct ndr_push *ndr, 
				      struct security_descriptor *sd)
{
	struct ndr_push_save save;
	struct ndr_push_save ofs1, ofs2, ofs3, ofs4;

	ndr_push_save(ndr, &save);

	NDR_CHECK(ndr_push_u8(ndr, sd->revision));
	NDR_CHECK(ndr_push_u16(ndr, sd->type));

	NDR_CHECK(ndr_push_offset(ndr, &ofs1));
	NDR_CHECK(ndr_push_offset(ndr, &ofs2));
	NDR_CHECK(ndr_push_offset(ndr, &ofs3));
	NDR_CHECK(ndr_push_offset(ndr, &ofs4));

	if (sd->owner_sid) {
		NDR_CHECK(ndr_push_offset_ptr(ndr, &ofs1, &save));
		NDR_CHECK(ndr_push_dom_sid(ndr, sd->owner_sid));
	}

	if (sd->group_sid) {
		NDR_CHECK(ndr_push_offset_ptr(ndr, &ofs2, &save));
		NDR_CHECK(ndr_push_dom_sid(ndr, sd->group_sid));
	}

	if (sd->sacl) {
		NDR_CHECK(ndr_push_offset_ptr(ndr, &ofs3, &save));
		NDR_CHECK(ndr_push_security_acl(ndr, sd->sacl));
	}

	if (sd->dacl) {
		NDR_CHECK(ndr_push_offset_ptr(ndr, &ofs4, &save));
		NDR_CHECK(ndr_push_security_acl(ndr, sd->dacl));
	}

	return NT_STATUS_OK;
}

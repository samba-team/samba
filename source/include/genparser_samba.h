/*
   Copyright (C) Simo Sorce <idra@samba.org> 2002
   
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

#error SAMBA4 clean up
#error this file should be (re)moved 
#error and all unused stuff should go

#ifndef _GENPARSER_SAMBA_H
#define _GENPARSER_SAMBA_H

const struct parse_struct pinfo_security_ace_info[] = {
{"type", 0, sizeof(uint8), offsetof(struct security_ace_info, type), 0, NULL, 0, gen_dump_uint8, gen_parse_uint8},
{"flags", 0, sizeof(uint8), offsetof(struct security_ace_info, flags), 0, NULL, 0, gen_dump_uint8, gen_parse_uint8},
{"size", 0, sizeof(uint16), offsetof(struct security_ace_info, size), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"info", 0, sizeof(char), offsetof(struct security_ace_info, info), 0, NULL, 0, gen_dump_SEC_ACCESS, gen_parse_SEC_ACCESS},
{"obj_flags", 0, sizeof(uint32), offsetof(struct security_ace_info, obj_flags), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"obj_guid", 0, sizeof(char), offsetof(struct security_ace_info, obj_guid), 0, NULL, 0, gen_dump_GUID, gen_parse_GUID},
{"inh_guid", 0, sizeof(char), offsetof(struct security_ace_info, inh_guid), 0, NULL, 0, gen_dump_GUID, gen_parse_GUID},
{"trustee", 0, sizeof(char), offsetof(struct security_ace_info, trustee), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

const struct parse_struct pinfo_security_acl_info[] = {
{"revision", 0, sizeof(uint16), offsetof(struct security_acl_info, revision), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"size", 0, sizeof(uint16), offsetof(struct security_acl_info, size), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"num_aces", 0, sizeof(uint32), offsetof(struct security_acl_info, num_aces), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"ace", 1, sizeof(struct security_ace_info), offsetof(struct security_acl_info, ace), 0, "size", 0, gen_dump_SEC_ACE, gen_parse_SEC_ACE},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

const struct parse_struct pinfo_security_descriptor_info[] = {
{"revision", 0, sizeof(uint16), offsetof(struct security_descriptor_info, revision), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"type", 0, sizeof(uint16), offsetof(struct security_descriptor_info, type), 0, NULL, 0, gen_dump_uint16, gen_parse_uint16},
{"off_owner_sid", 0, sizeof(uint32), offsetof(struct security_descriptor_info, off_owner_sid), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"off_grp_sid", 0, sizeof(uint32), offsetof(struct security_descriptor_info, off_grp_sid), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"off_sacl", 0, sizeof(uint32), offsetof(struct security_descriptor_info, off_sacl), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"off_dacl", 0, sizeof(uint32), offsetof(struct security_descriptor_info, off_dacl), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"dacl", 1, sizeof(struct security_acl_info), offsetof(struct security_descriptor_info, dacl), 0, NULL, 0, gen_dump_SEC_ACL, gen_parse_SEC_ACL},
{"sacl", 1, sizeof(struct security_acl_info), offsetof(struct security_descriptor_info, sacl), 0, NULL, 0, gen_dump_SEC_ACL, gen_parse_SEC_ACL},
{"owner_sid", 1, sizeof(char), offsetof(struct security_descriptor_info, owner_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{"grp_sid", 1, sizeof(char), offsetof(struct security_descriptor_info, grp_sid), 0, NULL, 0, gen_dump_DOM_SID, gen_parse_DOM_SID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

const struct parse_struct pinfo_luid_attr_info[] = {
{"attr", 0, sizeof(uint32), offsetof(struct LUID_ATTR, attr), 0, NULL, 0, gen_dump_uint32, gen_parse_uint32},
{"luid", 1, sizeof(LUID), offsetof(struct LUID_ATTR, luid), 0, NULL, 0, gen_dump_LUID, gen_parse_LUID},
{NULL, 0, 0, 0, 0, NULL, 0, NULL, NULL}};

#endif /* _GENPARSER_SAMBA_H */

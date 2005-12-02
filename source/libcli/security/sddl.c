/* 
   Unix SMB/CIFS implementation.

   security descriptor description language functions

   Copyright (C) Andrew Tridgell 		2005
      
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
#include "system/iconv.h"
#include "librpc/gen_ndr/ndr_security.h"

struct flag_map {
	const char *name;
	uint32_t flag;
};

/*
  map a series of letter codes into a uint32_t
*/
static BOOL sddl_map_flags(const struct flag_map *map, const char *str, 
			   uint32_t *flags, size_t *len)
{
	const char *str0 = str;
	if (len) *len = 0;
	*flags = 0;
	while (str[0] && isupper(str[0])) {
		int i;
		for (i=0;map[i].name;i++) {
			size_t l = strlen(map[i].name);
			if (strncmp(map[i].name, str, l) == 0) {
				*flags |= map[i].flag;
				str += l;
				if (len) *len += l;
				break;
			}
		}
		if (map[i].name == NULL) {
			DEBUG(1, ("Unknown flag - %s in %s\n", str, str0));
			return False;
		}
	}
	return True;
}

/*
  a mapping between the 2 letter SID codes and sid strings
*/
static const struct {
	const char *code;
	const char *sid;
	uint32_t rid;
} sid_codes[] = {
	{ "AO", SID_BUILTIN_ACCOUNT_OPERATORS },
	{ "BA", SID_BUILTIN_ADMINISTRATORS },
	{ "RU", SID_BUILTIN_PREW2K },
	{ "PO", SID_BUILTIN_PRINT_OPERATORS },
	{ "RS", SID_BUILTIN_RAS_SERVERS },

	{ "AU", SID_NT_AUTHENTICATED_USERS },
	{ "SY", SID_NT_SYSTEM },
	{ "PS", SID_NT_SELF },
	{ "WD", SID_WORLD },
	{ "ED", SID_NT_ENTERPRISE_DCS },

	{ "CO", SID_CREATOR_OWNER },
	{ "CG", SID_CREATOR_GROUP },

	{ "DA", NULL, DOMAIN_RID_ADMINS },
	{ "EA", NULL, DOMAIN_RID_ENTERPRISE_ADMINS },
	{ "DD", NULL, DOMAIN_RID_DCS },
	{ "DU", NULL, DOMAIN_RID_USERS },
	{ "CA", NULL, DOMAIN_RID_CERT_ADMINS },
};

/*
  decode a SID
  It can either be a special 2 letter code, or in S-* format
*/
static struct dom_sid *sddl_decode_sid(TALLOC_CTX *mem_ctx, const char **sddlp,
				       struct dom_sid *domain_sid)
{
	const char *sddl = (*sddlp);
	int i;

	/* see if its in the numeric format */
	if (strncmp(sddl, "S-", 2) == 0) {
		size_t len = strspn(sddl+2, "-0123456789");
		(*sddlp) += len+2;
		return dom_sid_parse_talloc(mem_ctx, sddl);
	}

	/* now check for one of the special codes */
	for (i=0;i<ARRAY_SIZE(sid_codes);i++) {
		if (strncmp(sid_codes[i].code, sddl, 2) == 0) break;
	}
	if (i == ARRAY_SIZE(sid_codes)) {
		DEBUG(1,("Unknown sddl sid code '%2.2s'\n", sddl));
		return NULL;
	}

	(*sddlp) += 2;

	if (sid_codes[i].sid == NULL) {
		return dom_sid_add_rid(mem_ctx, domain_sid, sid_codes[i].rid);
	}

	return dom_sid_parse_talloc(mem_ctx, sid_codes[i].sid);
}

static const struct flag_map ace_types[] = {
	{ "AU", SEC_ACE_TYPE_SYSTEM_AUDIT },
	{ "AL", SEC_ACE_TYPE_SYSTEM_ALARM },
	{ "OA", SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT },
	{ "OD", SEC_ACE_TYPE_ACCESS_DENIED_OBJECT },
	{ "OU", SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT },
	{ "OL", SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT },
	{ "A",  SEC_ACE_TYPE_ACCESS_ALLOWED },
	{ "D",  SEC_ACE_TYPE_ACCESS_DENIED },
	{ NULL, 0 }
};

static const struct flag_map ace_flags[] = {
	{ "OI", SEC_ACE_FLAG_OBJECT_INHERIT },
	{ "CI", SEC_ACE_FLAG_CONTAINER_INHERIT },
	{ "NP", SEC_ACE_FLAG_NO_PROPAGATE_INHERIT },
	{ "IO", SEC_ACE_FLAG_INHERIT_ONLY },
	{ "ID", SEC_ACE_FLAG_INHERITED_ACE },
	{ "SA", SEC_ACE_FLAG_SUCCESSFUL_ACCESS },
	{ "FA", SEC_ACE_FLAG_FAILED_ACCESS },
	{ NULL, 0 },
};

static const struct flag_map ace_access_mask[] = {
	{ "RC", SEC_STD_READ_CONTROL },
	{ "RP", SEC_ADS_READ_PROP },
	{ "WP", SEC_ADS_WRITE_PROP },
	{ "CR", SEC_ADS_CONTROL_ACCESS },
	{ "CC", SEC_ADS_CREATE_CHILD },
	{ "DC", SEC_ADS_DELETE_CHILD },
	{ "LC", SEC_ADS_LIST },
	{ "LO", SEC_ADS_LIST_OBJECT },
	{ "WO", SEC_STD_WRITE_OWNER },
	{ "WD", SEC_STD_WRITE_DAC },
	{ "SD", SEC_STD_DELETE },
	{ "DT", SEC_ADS_DELETE_TREE },
	{ "SW", SEC_ADS_SELF_WRITE },
	{ "GA", SEC_GENERIC_ALL },
	{ "GR", SEC_GENERIC_READ },
	{ "GW", SEC_GENERIC_WRITE },
	{ "GX", SEC_GENERIC_EXECUTE },
	{ NULL, 0 }
};

/*
  decode an ACE
  return True on success, False on failure
  note that this routine modifies the string
*/
static BOOL sddl_decode_ace(TALLOC_CTX *mem_ctx, struct security_ace *ace, char *str,
			    struct dom_sid *domain_sid)
{
	const char *tok[6];
	const char *s;
	int i;
	uint32_t v;
	struct dom_sid *sid;

	ZERO_STRUCTP(ace);

	/* parse out the 6 tokens */
	tok[0] = str;
	for (i=0;i<5;i++) {
		char *ptr = strchr(str, ';');
		if (ptr == NULL) return False;
		*ptr = 0;
		str = ptr+1;
		tok[i+1] = str;
	}

	/* parse ace type */
	if (!sddl_map_flags(ace_types, tok[0], &v, NULL)) {
		return False;
	}
	ace->type = v;

	/* ace flags */
	if (!sddl_map_flags(ace_flags, tok[1], &v, NULL)) {
		return False;
	}
	ace->flags = v;
	
	/* access mask */
	if (strncmp(tok[2], "0x", 2) == 0) {
		ace->access_mask = strtol(tok[2], NULL, 16);
	} else {
		if (!sddl_map_flags(ace_access_mask, tok[2], &v, NULL)) {
			return False;
		}
		ace->access_mask = v;
	}

	/* object */
	if (tok[3][0] != 0) {
		NTSTATUS status = GUID_from_string(tok[3], 
						   &ace->object.object.type.type);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}
	}

	/* inherit object */
	if (tok[4][0] != 0) {
		NTSTATUS status = GUID_from_string(tok[4], 
						   &ace->object.object.inherited_type.inherited_type);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}
	}

	/* trustee */
	s = tok[5];
	sid = sddl_decode_sid(mem_ctx, &s, domain_sid);
	if (sid == NULL) {
		return False;
	}
	ace->trustee = *sid;
	talloc_steal(mem_ctx, sid->sub_auths);
	talloc_free(sid);

	return True;
}

static const struct flag_map acl_flags[] = {
	{ "P", SEC_DESC_DACL_PROTECTED },
	{ "AR", SEC_DESC_DACL_AUTO_INHERIT_REQ },
	{ "AI", SEC_DESC_DACL_AUTO_INHERITED },
	{ NULL, 0 }
};

/*
  decode an ACL
*/
static struct security_acl *sddl_decode_acl(struct security_descriptor *sd, 
					    const char **sddlp, uint32_t *flags,
					    struct dom_sid *domain_sid)
{
	const char *sddl = *sddlp;
	struct security_acl *acl;
	size_t len;

	acl = talloc_zero(sd, struct security_acl);
	if (acl == NULL) return NULL;
	acl->revision = SECURITY_ACL_REVISION_NT4;

	if (isupper(sddl[0]) && sddl[1] == ':') {
		/* its an empty ACL */
		return acl;
	}

	/* work out the ACL flags */
	if (!sddl_map_flags(acl_flags, sddl, flags, &len)) {
		talloc_free(acl);
		return NULL;
	}
	sddl += len;

	/* now the ACEs */
	while (*sddl == '(') {
		char *astr;
		len = strcspn(sddl+1, ")");
		astr = talloc_strndup(acl, sddl+1, len);
		if (astr == NULL || sddl[len+1] != ')') {
			talloc_free(acl);
			return NULL;
		}
		acl->aces = talloc_realloc(acl, acl->aces, struct security_ace, 
					   acl->num_aces+1);
		if (acl->aces == NULL) {
			talloc_free(acl);
			return NULL;
		}
		if (!sddl_decode_ace(acl->aces, &acl->aces[acl->num_aces], 
				     astr, domain_sid)) {
			talloc_free(acl);
			return NULL;
		}
		talloc_free(astr);
		sddl += len+2;
		acl->num_aces++;
	}

	(*sddlp) = sddl;
	return acl;
}

/*
  decode a security descriptor in SDDL format
*/
struct security_descriptor *sddl_decode(TALLOC_CTX *mem_ctx, const char *sddl,
					struct dom_sid *domain_sid)
{
	struct security_descriptor *sd;
	sd = talloc_zero(mem_ctx, struct security_descriptor);

	sd->revision = SECURITY_DESCRIPTOR_REVISION_1;
	sd->type     = SEC_DESC_SELF_RELATIVE;
	
	while (*sddl) {
		uint32_t flags;
		char c = sddl[0];
		if (sddl[1] != ':') goto failed;

		sddl += 2;
		switch (c) {
		case 'D':
			if (sd->dacl != NULL) goto failed;
			sd->dacl = sddl_decode_acl(sd, &sddl, &flags, domain_sid);
			if (sd->dacl == NULL) goto failed;
			sd->type |= flags | SEC_DESC_DACL_PRESENT;
			break;
		case 'S':
			if (sd->sacl != NULL) goto failed;
			sd->sacl = sddl_decode_acl(sd, &sddl, &flags, domain_sid);
			if (sd->sacl == NULL) goto failed;
			/* this relies on the SEC_DESC_SACL_* flags being
			   1 bit shifted from the SEC_DESC_DACL_* flags */
			sd->type |= (flags<<1) | SEC_DESC_SACL_PRESENT;
			break;
		case 'O':
			if (sd->owner_sid != NULL) goto failed;
			sd->owner_sid = sddl_decode_sid(sd, &sddl, domain_sid);
			if (sd->owner_sid == NULL) goto failed;
			break;
		case 'G':
			if (sd->group_sid != NULL) goto failed;
			sd->group_sid = sddl_decode_sid(sd, &sddl, domain_sid);
			if (sd->group_sid == NULL) goto failed;
			break;
		}
	}

	return sd;

failed:
	DEBUG(2,("Badly formatted SDDL '%s'\n", sddl));
	talloc_free(sd);
	return NULL;
}

/*
   Unix SMB/CIFS implementation.

   security descriptor utility functions

   Copyright (C) Andrew Tridgell 		2004

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

#include "replace.h"
#include "libcli/security/security.h"
#include "librpc/ndr/libndr.h"

/*
  return a blank security descriptor (no owners, dacl or sacl)
*/
struct security_descriptor *security_descriptor_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_descriptor *sd;

	sd = talloc(mem_ctx, struct security_descriptor);
	if (!sd) {
		return NULL;
	}
	*sd = (struct security_descriptor){
		.revision = SD_REVISION,

		/*
		 * we mark as self relative, even though it isn't
		 * while it remains a pointer in memory because this
		 * simplifies the ndr code later.  All SDs that we
		 * store/emit are in fact SELF_RELATIVE
		 */
		.type = SEC_DESC_SELF_RELATIVE,
	};

	return sd;
}

struct security_acl *security_acl_dup(TALLOC_CTX *mem_ctx,
					     const struct security_acl *oacl)
{
	struct security_acl *nacl;

	if (oacl == NULL) {
		return NULL;
	}

	if (oacl->aces == NULL && oacl->num_aces > 0) {
		return NULL;
	}

	nacl = talloc (mem_ctx, struct security_acl);
	if (nacl == NULL) {
		return NULL;
	}

	*nacl = (struct security_acl) {
		.revision = oacl->revision,
		.size     = oacl->size,
		.num_aces = oacl->num_aces,
	};
	if (nacl->num_aces == 0) {
		return nacl;
	}

	nacl->aces = (struct security_ace *)talloc_memdup (nacl, oacl->aces, sizeof(struct security_ace) * oacl->num_aces);
	if (nacl->aces == NULL) {
		goto failed;
	}

	return nacl;

 failed:
	talloc_free (nacl);
	return NULL;

}

struct security_acl *security_acl_concatenate(TALLOC_CTX *mem_ctx,
                                              const struct security_acl *acl1,
                                              const struct security_acl *acl2)
{
        struct security_acl *nacl;
        uint32_t i;

        if (!acl1 && !acl2)
                return NULL;

        if (!acl1){
                nacl = security_acl_dup(mem_ctx, acl2);
                return nacl;
        }

        if (!acl2){
                nacl = security_acl_dup(mem_ctx, acl1);
                return nacl;
        }

        nacl = talloc (mem_ctx, struct security_acl);
        if (nacl == NULL) {
                return NULL;
        }

        nacl->revision = acl1->revision;
        nacl->size = acl1->size + acl2->size;
        nacl->num_aces = acl1->num_aces + acl2->num_aces;

        if (nacl->num_aces == 0)
                return nacl;

        nacl->aces = (struct security_ace *)talloc_array (mem_ctx, struct security_ace, acl1->num_aces+acl2->num_aces);
        if ((nacl->aces == NULL) && (nacl->num_aces > 0)) {
                goto failed;
        }

        for (i = 0; i < acl1->num_aces; i++)
                nacl->aces[i] = acl1->aces[i];
        for (i = 0; i < acl2->num_aces; i++)
                nacl->aces[i + acl1->num_aces] = acl2->aces[i];

        return nacl;

 failed:
        talloc_free (nacl);
        return NULL;

}

/*
   talloc and copy a security descriptor
 */
struct security_descriptor *security_descriptor_copy(TALLOC_CTX *mem_ctx,
						     const struct security_descriptor *osd)
{
	struct security_descriptor *nsd;

	nsd = talloc_zero(mem_ctx, struct security_descriptor);
	if (!nsd) {
		return NULL;
	}

	if (osd->owner_sid) {
		nsd->owner_sid = dom_sid_dup(nsd, osd->owner_sid);
		if (nsd->owner_sid == NULL) {
			goto failed;
		}
	}

	if (osd->group_sid) {
		nsd->group_sid = dom_sid_dup(nsd, osd->group_sid);
		if (nsd->group_sid == NULL) {
			goto failed;
		}
	}

	if (osd->sacl) {
		nsd->sacl = security_acl_dup(nsd, osd->sacl);
		if (nsd->sacl == NULL) {
			goto failed;
		}
	}

	if (osd->dacl) {
		nsd->dacl = security_acl_dup(nsd, osd->dacl);
		if (nsd->dacl == NULL) {
			goto failed;
		}
	}

	nsd->revision = osd->revision;
	nsd->type = osd->type;

	return nsd;

 failed:
	talloc_free(nsd);

	return NULL;
}

NTSTATUS security_descriptor_for_client(TALLOC_CTX *mem_ctx,
					const struct security_descriptor *ssd,
					uint32_t sec_info,
					uint32_t access_granted,
					struct security_descriptor **_csd)
{
	struct security_descriptor *csd = NULL;
	uint32_t access_required = 0;

	*_csd = NULL;

	if (sec_info & (SECINFO_OWNER|SECINFO_GROUP)) {
		access_required |= SEC_STD_READ_CONTROL;
	}
	if (sec_info & SECINFO_DACL) {
		access_required |= SEC_STD_READ_CONTROL;
	}
	if (sec_info & SECINFO_SACL) {
		access_required |= SEC_FLAG_SYSTEM_SECURITY;
	}

	if (access_required & (~access_granted)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * make a copy...
	 */
	csd = security_descriptor_copy(mem_ctx, ssd);
	if (csd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * ... and remove everything not wanted
	 */

	if (!(sec_info & SECINFO_OWNER)) {
		TALLOC_FREE(csd->owner_sid);
		csd->type &= ~SEC_DESC_OWNER_DEFAULTED;
	}
	if (!(sec_info & SECINFO_GROUP)) {
		TALLOC_FREE(csd->group_sid);
		csd->type &= ~SEC_DESC_GROUP_DEFAULTED;
	}
	if (!(sec_info & SECINFO_DACL)) {
		TALLOC_FREE(csd->dacl);
		csd->type &= ~(
			SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|
			SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED |
			SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}
	if (!(sec_info & SECINFO_SACL)) {
		TALLOC_FREE(csd->sacl);
		csd->type &= ~(
			SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED |
			SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED |
			SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}

	*_csd = csd;
	return NT_STATUS_OK;
}

/*
  add an ACE to an ACL of a security_descriptor
*/

static NTSTATUS security_descriptor_acl_add(struct security_descriptor *sd,
					    bool add_to_sacl,
					    const struct security_ace *ace,
					    ssize_t _idx)
{
	struct security_acl *acl = NULL;
	ssize_t idx;

	if (add_to_sacl) {
		acl = sd->sacl;
	} else {
		acl = sd->dacl;
	}

	if (acl == NULL) {
		acl = talloc(sd, struct security_acl);
		if (acl == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		acl->revision = SECURITY_ACL_REVISION_NT4;
		acl->size     = 0;
		acl->num_aces = 0;
		acl->aces     = NULL;
	}

	if (_idx < 0) {
		idx = (acl->num_aces + 1) + _idx;
	} else {
		idx = _idx;
	}

	if (idx < 0) {
		return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
	} else if (idx > acl->num_aces) {
		return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
	}

	acl->aces = talloc_realloc(acl, acl->aces,
				   struct security_ace, acl->num_aces+1);
	if (acl->aces == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ARRAY_INSERT_ELEMENT(acl->aces, acl->num_aces, *ace, idx);
	acl->num_aces++;

	if (sec_ace_object(acl->aces[idx].type)) {
		acl->revision = SECURITY_ACL_REVISION_ADS;
	}

	if (add_to_sacl) {
		sd->sacl = acl;
		sd->type |= SEC_DESC_SACL_PRESENT;
	} else {
		sd->dacl = acl;
		sd->type |= SEC_DESC_DACL_PRESENT;
	}

	return NT_STATUS_OK;
}

/*
  add an ACE to the SACL of a security_descriptor
*/

NTSTATUS security_descriptor_sacl_add(struct security_descriptor *sd,
				      const struct security_ace *ace)
{
	return security_descriptor_acl_add(sd, true, ace, -1);
}

/*
  insert an ACE at a given index to the SACL of a security_descriptor

  idx can be negative, which means it's related to the new size from the
  end, so -1 means the ace is appended at the end.
*/

NTSTATUS security_descriptor_sacl_insert(struct security_descriptor *sd,
					 const struct security_ace *ace,
					 ssize_t idx)
{
	return security_descriptor_acl_add(sd, true, ace, idx);
}

/*
  add an ACE to the DACL of a security_descriptor
*/

NTSTATUS security_descriptor_dacl_add(struct security_descriptor *sd,
				      const struct security_ace *ace)
{
	return security_descriptor_acl_add(sd, false, ace, -1);
}

/*
  insert an ACE at a given index to the DACL of a security_descriptor

  idx can be negative, which means it's related to the new size from the
  end, so -1 means the ace is appended at the end.
*/

NTSTATUS security_descriptor_dacl_insert(struct security_descriptor *sd,
					 const struct security_ace *ace,
					 ssize_t idx)
{
	return security_descriptor_acl_add(sd, false, ace, idx);
}

/*
  delete the ACE corresponding to the given trustee in an ACL of a
  security_descriptor
*/

static NTSTATUS security_descriptor_acl_del(struct security_descriptor *sd,
					    bool sacl_del,
					    const struct dom_sid *trustee)
{
	uint32_t i;
	bool found = false;
	struct security_acl *acl = NULL;

	if (sacl_del) {
		acl = sd->sacl;
	} else {
		acl = sd->dacl;
	}

	if (acl == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* there can be multiple ace's for one trustee */

	i = 0;

	while (i<acl->num_aces) {
		if (dom_sid_equal(trustee, &acl->aces[i].trustee)) {
			ARRAY_DEL_ELEMENT(acl->aces, i, acl->num_aces);
			acl->num_aces--;
			if (acl->num_aces == 0) {
				acl->aces = NULL;
			}
			found = true;
		} else {
			i += 1;
		}
	}

	if (!found) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	acl->revision = SECURITY_ACL_REVISION_NT4;

	for (i=0;i<acl->num_aces;i++) {
		if (sec_ace_object(acl->aces[i].type)) {
			acl->revision = SECURITY_ACL_REVISION_ADS;
			break;
		}
	}

	return NT_STATUS_OK;
}

/*
  delete the ACE corresponding to the given trustee in the DACL of a
  security_descriptor
*/

NTSTATUS security_descriptor_dacl_del(struct security_descriptor *sd,
				      const struct dom_sid *trustee)
{
	return security_descriptor_acl_del(sd, false, trustee);
}

/*
  delete the ACE corresponding to the given trustee in the SACL of a
  security_descriptor
*/

NTSTATUS security_descriptor_sacl_del(struct security_descriptor *sd,
				      const struct dom_sid *trustee)
{
	return security_descriptor_acl_del(sd, true, trustee);
}

/*
  delete the given ACE in the SACL or DACL of a security_descriptor
*/
static NTSTATUS security_descriptor_acl_del_ace(struct security_descriptor *sd,
						bool sacl_del,
						const struct security_ace *ace)
{
	uint32_t i;
	bool found = false;
	struct security_acl *acl = NULL;

	if (sacl_del) {
		acl = sd->sacl;
	} else {
		acl = sd->dacl;
	}

	if (acl == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	for (i=0;i<acl->num_aces;i++) {
		if (security_ace_equal(ace, &acl->aces[i])) {
			ARRAY_DEL_ELEMENT(acl->aces, i, acl->num_aces);
			acl->num_aces--;
			if (acl->num_aces == 0) {
				acl->aces = NULL;
			}
			found = true;
			i--;
		}
	}

	if (!found) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	acl->revision = SECURITY_ACL_REVISION_NT4;

	for (i=0;i<acl->num_aces;i++) {
		if (sec_ace_object(acl->aces[i].type)) {
			acl->revision = SECURITY_ACL_REVISION_ADS;
			break;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS security_descriptor_dacl_del_ace(struct security_descriptor *sd,
					  const struct security_ace *ace)
{
	return security_descriptor_acl_del_ace(sd, false, ace);
}

NTSTATUS security_descriptor_sacl_del_ace(struct security_descriptor *sd,
					  const struct security_ace *ace)
{
	return security_descriptor_acl_del_ace(sd, true, ace);
}

static bool security_ace_object_equal(const struct security_ace_object *object1,
				      const struct security_ace_object *object2)
{
	if (object1 == object2) {
		return true;
	}
	if ((object1 == NULL) || (object2 == NULL)) {
		return false;
	}
	if (object1->flags != object2->flags) {
		return false;
	}
	if (object1->flags & SEC_ACE_OBJECT_TYPE_PRESENT
			&& !GUID_equal(&object1->type.type, &object2->type.type)) {
		return false;
	}
	if (object1->flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT
	    && !GUID_equal(&object1->inherited_type.inherited_type,
			   &object2->inherited_type.inherited_type)) {
		return false;
	}

	return true;
}


static bool security_ace_claim_equal(const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim1,
				     const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim2)
{
	uint32_t i;

	if (claim1 == claim2) {
		return true;
	}
	if (claim1 == NULL || claim2 == NULL) {
		return false;
	}
	if (claim1->name != NULL && claim2->name != NULL) {
		if (strcasecmp_m(claim1->name, claim2->name) != 0) {
			return false;
		}
	} else if (claim1->name != NULL || claim2->name != NULL) {
		return false;
	}
	if (claim1->value_type != claim2->value_type) {
		return false;
	}
	if (claim1->flags != claim2->flags) {
		return false;
	}
	if (claim1->value_count != claim2->value_count) {
		return false;
	}
	for (i = 0; i < claim1->value_count; ++i) {
		const union claim_values *values1 = claim1->values;
		const union claim_values *values2 = claim2->values;

		switch (claim1->value_type) {
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
			if (values1[i].int_value != NULL && values2[i].int_value != NULL) {
				if (*values1[i].int_value != *values2[i].int_value) {
					return false;
				}
			} else if (values1[i].int_value != NULL || values2[i].int_value != NULL) {
				return false;
			}
			break;
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
			if (values1[i].uint_value != NULL && values2[i].uint_value != NULL) {
				if (*values1[i].uint_value != *values2[i].uint_value) {
					return false;
				}
			} else if (values1[i].uint_value != NULL || values2[i].uint_value != NULL) {
				return false;
			}
			break;
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
			if (values1[i].string_value != NULL && values2[i].string_value != NULL) {
				if (strcasecmp_m(values1[i].string_value, values2[i].string_value) != 0) {
					return false;
				}
			} else if (values1[i].string_value != NULL || values2[i].string_value != NULL) {
				return false;
			}
			break;
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
			if (values1[i].sid_value != NULL && values2[i].sid_value != NULL) {
				if (data_blob_cmp(values1[i].sid_value, values2[i].sid_value) != 0) {
					return false;
				}
			} else if (values1[i].sid_value != NULL || values2[i].sid_value != NULL) {
				return false;
			}
			break;
		case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
			if (values1[i].octet_value != NULL && values2[i].octet_value != NULL) {
				if (data_blob_cmp(values1[i].octet_value, values2[i].octet_value) != 0) {
					return false;
				}
			} else if (values1[i].octet_value != NULL || values2[i].octet_value != NULL) {
				return false;
			}
			break;
		default:
			break;
		}
	}

	return true;
}

/*
  compare two security ace structures
*/
bool security_ace_equal(const struct security_ace *ace1,
			const struct security_ace *ace2)
{
	if (ace1 == ace2) {
		return true;
	}
	if ((ace1 == NULL) || (ace2 == NULL)) {
		return false;
	}
	if (ace1->type != ace2->type) {
		return false;
	}
	if (ace1->flags != ace2->flags) {
		return false;
	}
	if (ace1->access_mask != ace2->access_mask) {
		return false;
	}
	if (sec_ace_object(ace1->type) &&
	    !security_ace_object_equal(&ace1->object.object,
				       &ace2->object.object))
	{
		return false;
	}
	if (!dom_sid_equal(&ace1->trustee, &ace2->trustee)) {
		return false;
	}

	if (sec_ace_callback(ace1->type)) {
		if (data_blob_cmp(&ace1->coda.conditions, &ace2->coda.conditions) != 0) {
			return false;
		}
	} else if (sec_ace_resource(ace1->type)) {
		if (!security_ace_claim_equal(&ace1->coda.claim, &ace2->coda.claim)) {
			return false;
		}
	} else {
		/*
		 * Don’t require ace1->coda.ignored to match ace2->coda.ignored.
		 */
	}

	return true;
}


/*
  compare two security acl structures
*/
bool security_acl_equal(const struct security_acl *acl1,
			const struct security_acl *acl2)
{
	uint32_t i;

	if (acl1 == acl2) return true;
	if (!acl1 || !acl2) return false;
	if (acl1->revision != acl2->revision) return false;
	if (acl1->num_aces != acl2->num_aces) return false;

	for (i=0;i<acl1->num_aces;i++) {
		if (!security_ace_equal(&acl1->aces[i], &acl2->aces[i])) return false;
	}
	return true;
}

/*
  compare two security descriptors.
*/
bool security_descriptor_equal(const struct security_descriptor *sd1,
			       const struct security_descriptor *sd2)
{
	if (sd1 == sd2) return true;
	if (!sd1 || !sd2) return false;
	if (sd1->revision != sd2->revision) return false;
	if (sd1->type != sd2->type) return false;

	if (!dom_sid_equal(sd1->owner_sid, sd2->owner_sid)) return false;
	if (!dom_sid_equal(sd1->group_sid, sd2->group_sid)) return false;
	if (!security_acl_equal(sd1->sacl, sd2->sacl))      return false;
	if (!security_acl_equal(sd1->dacl, sd2->dacl))      return false;

	return true;
}

/*
  compare two security descriptors, but allow certain (missing) parts
  to be masked out of the comparison
*/
bool security_descriptor_mask_equal(const struct security_descriptor *sd1,
				    const struct security_descriptor *sd2,
				    uint32_t mask)
{
	if (sd1 == sd2) return true;
	if (!sd1 || !sd2) return false;
	if (sd1->revision != sd2->revision) return false;
	if ((sd1->type & mask) != (sd2->type & mask)) return false;

	if (!dom_sid_equal(sd1->owner_sid, sd2->owner_sid)) return false;
	if (!dom_sid_equal(sd1->group_sid, sd2->group_sid)) return false;
	if ((mask & SEC_DESC_DACL_PRESENT) && !security_acl_equal(sd1->dacl, sd2->dacl))      return false;
	if ((mask & SEC_DESC_SACL_PRESENT) && !security_acl_equal(sd1->sacl, sd2->sacl))      return false;

	return true;
}


static struct security_descriptor *security_descriptor_appendv(struct security_descriptor *sd,
							       bool add_ace_to_sacl,
							       va_list ap)
{
	const char *sidstr;

	while ((sidstr = va_arg(ap, const char *))) {
		struct dom_sid *sid;
		struct security_ace *ace = talloc_zero(sd, struct security_ace);
		NTSTATUS status;

		if (ace == NULL) {
			talloc_free(sd);
			return NULL;
		}
		ace->type = va_arg(ap, unsigned int);
		ace->access_mask = va_arg(ap, unsigned int);
		ace->flags = va_arg(ap, unsigned int);
		sid = dom_sid_parse_talloc(ace, sidstr);
		if (sid == NULL) {
			talloc_free(sd);
			return NULL;
		}
		ace->trustee = *sid;
		if (add_ace_to_sacl) {
			status = security_descriptor_sacl_add(sd, ace);
		} else {
			status = security_descriptor_dacl_add(sd, ace);
		}
		/* TODO: check: would talloc_free(ace) here be correct? */
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(sd);
			return NULL;
		}
	}

	return sd;
}

static struct security_descriptor *security_descriptor_createv(TALLOC_CTX *mem_ctx,
							       uint16_t sd_type,
							       const char *owner_sid,
							       const char *group_sid,
							       bool add_ace_to_sacl,
							       va_list ap)
{
	struct security_descriptor *sd;

	sd = security_descriptor_initialise(mem_ctx);
	if (sd == NULL) {
		return NULL;
	}

	sd->type |= sd_type;

	if (owner_sid) {
		sd->owner_sid = dom_sid_parse_talloc(sd, owner_sid);
		if (sd->owner_sid == NULL) {
			talloc_free(sd);
			return NULL;
		}
	}
	if (group_sid) {
		sd->group_sid = dom_sid_parse_talloc(sd, group_sid);
		if (sd->group_sid == NULL) {
			talloc_free(sd);
			return NULL;
		}
	}

	return security_descriptor_appendv(sd, add_ace_to_sacl, ap);
}

/*
  create a security descriptor using string SIDs. This is used by the
  torture code to allow the easy creation of complex ACLs
  This is a varargs function. The list of DACL ACEs ends with a NULL sid.

  Each ACE contains a set of 4 parameters:
  SID, ACCESS_TYPE, MASK, FLAGS

  a typical call would be:

    sd = security_descriptor_dacl_create(mem_ctx,
                                         sd_type_flags,
                                         mysid,
                                         mygroup,
                                         SID_NT_AUTHENTICATED_USERS,
                                         SEC_ACE_TYPE_ACCESS_ALLOWED,
                                         SEC_FILE_ALL,
                                         SEC_ACE_FLAG_OBJECT_INHERIT,
                                         NULL);
  that would create a sd with one DACL ACE
*/

struct security_descriptor *security_descriptor_dacl_create(TALLOC_CTX *mem_ctx,
							    uint16_t sd_type,
							    const char *owner_sid,
							    const char *group_sid,
							    ...)
{
	struct security_descriptor *sd = NULL;
	va_list ap;
	va_start(ap, group_sid);
	sd = security_descriptor_createv(mem_ctx, sd_type, owner_sid,
					 group_sid, false, ap);
	va_end(ap);

	return sd;
}

struct security_descriptor *security_descriptor_sacl_create(TALLOC_CTX *mem_ctx,
							    uint16_t sd_type,
							    const char *owner_sid,
							    const char *group_sid,
							    ...)
{
	struct security_descriptor *sd = NULL;
	va_list ap;
	va_start(ap, group_sid);
	sd = security_descriptor_createv(mem_ctx, sd_type, owner_sid,
					 group_sid, true, ap);
	va_end(ap);

	return sd;
}

struct security_ace *security_ace_create(TALLOC_CTX *mem_ctx,
					 const char *sid_str,
					 enum security_ace_type type,
					 uint32_t access_mask,
					 uint8_t flags)

{
	struct security_ace *ace;
	bool ok;

	ace = talloc_zero(mem_ctx, struct security_ace);
	if (ace == NULL) {
		return NULL;
	}

	ok = dom_sid_parse(sid_str, &ace->trustee);
	if (!ok) {
		talloc_free(ace);
		return NULL;
	}
	ace->type = type;
	ace->access_mask = access_mask;
	ace->flags = flags;

	return ace;
}

/*******************************************************************
 Check for MS NFS ACEs in a sd
*******************************************************************/
bool security_descriptor_with_ms_nfs(const struct security_descriptor *psd)
{
	uint32_t i;

	if (psd->dacl == NULL) {
		return false;
	}

	for (i = 0; i < psd->dacl->num_aces; i++) {
		if (dom_sid_compare_domain(
			    &global_sid_Unix_NFS,
			    &psd->dacl->aces[i].trustee) == 0) {
			return true;
		}
	}

	return false;
}

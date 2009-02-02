/* 
   Unix SMB/CIFS mplementation.
   DSDB schema header
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2006-2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2008

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
#include "dsdb/samdb/samdb.h"

const struct dsdb_attribute *dsdb_attribute_by_attributeID_id(const struct dsdb_schema *schema,
							      uint32_t id)
{
	struct dsdb_attribute *cur;

	/*
	 * 0xFFFFFFFF is used as value when no mapping table is available,
	 * so don't try to match with it
	 */
	if (id == 0xFFFFFFFF) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (cur->attributeID_id != id) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_attribute *dsdb_attribute_by_attributeID_oid(const struct dsdb_schema *schema,
							       const char *oid)
{
	struct dsdb_attribute *cur;

	if (!oid) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (strcmp(cur->attributeID_oid, oid) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_attribute *dsdb_attribute_by_lDAPDisplayName(const struct dsdb_schema *schema,
							       const char *name)
{
	struct dsdb_attribute *cur;

	if (!name) return NULL;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (strcasecmp(cur->lDAPDisplayName, name) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_attribute *dsdb_attribute_by_linkID(const struct dsdb_schema *schema,
						      int linkID)
{
	struct dsdb_attribute *cur;

	/* TODO: add binary search */
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (cur->linkID != linkID) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_governsID_id(const struct dsdb_schema *schema,
						    uint32_t id)
{
	struct dsdb_class *cur;

	/*
	 * 0xFFFFFFFF is used as value when no mapping table is available,
	 * so don't try to match with it
	 */
	if (id == 0xFFFFFFFF) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (cur->governsID_id != id) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_governsID_oid(const struct dsdb_schema *schema,
						     const char *oid)
{
	struct dsdb_class *cur;

	if (!oid) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (strcmp(cur->governsID_oid, oid) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_lDAPDisplayName(const struct dsdb_schema *schema,
						       const char *name)
{
	struct dsdb_class *cur;

	if (!name) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (strcasecmp(cur->lDAPDisplayName, name) != 0) continue;

		return cur;
	}

	return NULL;
}

const struct dsdb_class *dsdb_class_by_cn(const struct dsdb_schema *schema,
					  const char *cn)
{
	struct dsdb_class *cur;

	if (!cn) return NULL;

	/* TODO: add binary search */
	for (cur = schema->classes; cur; cur = cur->next) {
		if (strcasecmp(cur->cn, cn) != 0) continue;

		return cur;
	}

	return NULL;
}

const char *dsdb_lDAPDisplayName_by_id(const struct dsdb_schema *schema,
				       uint32_t id)
{
	const struct dsdb_attribute *a;
	const struct dsdb_class *c;

	/* TODO: add binary search */
	a = dsdb_attribute_by_attributeID_id(schema, id);
	if (a) {
		return a->lDAPDisplayName;
	}

	c = dsdb_class_by_governsID_id(schema, id);
	if (c) {
		return c->lDAPDisplayName;
	}

	return NULL;
}

/** 
    Return a list of linked attributes, in lDAPDisplayName format.

    This may be used to determine if a modification would require
    backlinks to be updated, for example
*/

WERROR dsdb_linked_attribute_lDAPDisplayName_list(const struct dsdb_schema *schema, TALLOC_CTX *mem_ctx, const char ***attr_list_ret)
{
	const char **attr_list = NULL;
	struct dsdb_attribute *cur;
	int i = 0;
	for (cur = schema->attributes; cur; cur = cur->next) {
		if (cur->linkID == 0) continue;
		
		attr_list = talloc_realloc(mem_ctx, attr_list, const char *, i+2);
		if (!attr_list) {
			return WERR_NOMEM;
		}
		attr_list[i] = cur->lDAPDisplayName;
		i++;
	}
	attr_list[i] = NULL;
	*attr_list_ret = attr_list;
	return WERR_OK;
}

const char **merge_attr_list(TALLOC_CTX *mem_ctx, 
		       const char **attrs, const char * const*new_attrs) 
{
	const char **ret_attrs;
	int i;
	size_t new_len, orig_len = str_list_length(attrs);
	if (!new_attrs) {
		return attrs;
	}

	ret_attrs = talloc_realloc(mem_ctx, 
				   attrs, const char *, orig_len + str_list_length(new_attrs) + 1);
	if (ret_attrs) {
		for (i=0; i < str_list_length(new_attrs); i++) {
			ret_attrs[orig_len + i] = new_attrs[i];
		}
		new_len = orig_len + str_list_length(new_attrs);

		ret_attrs[new_len] = NULL;
	}

	return ret_attrs;
}

/*
  Return a merged list of the attributes of exactly one class (not
  considering subclasses, auxillary classes etc)
*/

const char **dsdb_attribute_list(TALLOC_CTX *mem_ctx, const struct dsdb_class *sclass, enum dsdb_attr_list_query query)
{
	const char **attr_list = NULL;
	switch (query) {
	case DSDB_SCHEMA_ALL_MAY:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mayContain);
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMayContain);
		break;
		
	case DSDB_SCHEMA_ALL_MUST:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mustContain);
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMustContain);
		break;
		
	case DSDB_SCHEMA_SYS_MAY:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMayContain);
		break;
		
	case DSDB_SCHEMA_SYS_MUST:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMustContain);
		break;
		
	case DSDB_SCHEMA_MAY:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mayContain);
		break;
		
	case DSDB_SCHEMA_MUST:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mustContain);
		break;
		
	case DSDB_SCHEMA_ALL:
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mayContain);
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMayContain);
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->mustContain);
		attr_list = merge_attr_list(mem_ctx, attr_list, sclass->systemMustContain);
		break;
	}
	return attr_list;
}

static const char **dsdb_full_attribute_list_internal(TALLOC_CTX *mem_ctx, 
						const struct dsdb_schema *schema, 
						const char **class_list,
						enum dsdb_attr_list_query query)
{
	int i;
	const struct dsdb_class *sclass;
	
	const char **attr_list = NULL;
	const char **this_class_list;
	const char **recursive_list;

	for (i=0; class_list && class_list[i]; i++) {
		sclass = dsdb_class_by_lDAPDisplayName(schema, class_list[i]);
		
		this_class_list = dsdb_attribute_list(mem_ctx, sclass, query);
		attr_list = merge_attr_list(mem_ctx, attr_list, this_class_list);

		recursive_list = dsdb_full_attribute_list_internal(mem_ctx, schema, 
								   sclass->systemAuxiliaryClass,
								   query);
		
		attr_list = merge_attr_list(mem_ctx, attr_list, recursive_list);
		
		recursive_list = dsdb_full_attribute_list_internal(mem_ctx, schema, 
								   sclass->auxiliaryClass,
								   query);
		
		attr_list = merge_attr_list(mem_ctx, attr_list, recursive_list);
		
	}
	return attr_list;
}

const char **dsdb_full_attribute_list(TALLOC_CTX *mem_ctx, 
				const struct dsdb_schema *schema, 
				const char **class_list,
				enum dsdb_attr_list_query query)
{
	const char **attr_list = dsdb_full_attribute_list_internal(mem_ctx, schema, class_list, query);
	size_t new_len = str_list_length(attr_list);

	/* Remove duplicates */
	if (new_len > 1) {
		int i;
		qsort(attr_list, new_len,
		      sizeof(*attr_list),
		      (comparison_fn_t)strcasecmp);
		
		for (i=1 ; i < new_len; i++) {
			const char **val1 = &attr_list[i-1];
			const char **val2 = &attr_list[i];
			if (ldb_attr_cmp(*val1, *val2) == 0) {
				memmove(val1, val2, (new_len - i) * sizeof( *attr_list)); 
				new_len--;
				i--;
			}
		}
	}
	return attr_list;
}

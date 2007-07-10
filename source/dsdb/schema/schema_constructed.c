/* 
   Unix SMB/CIFS mplementation.
   DSDB schema constructed attributes
   attributeTypes, objectClasses, dITContentRules...
   
   Copyright (C) Stefan Metzmacher 2006
    
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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "lib/ldb/include/ldb.h"
#include "system/time.h"
#include "lib/charset/charset.h"
#include "librpc/ndr/libndr.h"

static char *dsdb_subSchema_list_append(char *v, const char *list_name)
{
	bool first = true;
	uint32_t i;
	const char *attrs[] = {
		"attr1",
		"attr2",
		"attr3",
		NULL
	};

	if (!attrs) {
		return v;
	}

	v = talloc_asprintf_append(v, "%s ( ", list_name);
	if (!v) return NULL;

	for (i=0; attrs[i]; i++) {
		v = talloc_asprintf_append(v, "%s%s ",
					   (!first ? "$ " : ""),
					   attrs[i]);
		if (!v) return NULL;
		first = false;
	}

	v = talloc_asprintf_append(v, ") ");
	if (!v) return NULL;

	return v;
}

WERROR dsdb_subSchema_attributeTypes(const struct dsdb_schema *schema,
				     TALLOC_CTX *mem_ctx)
{
	struct ldb_message_element *e;
	struct dsdb_attribute *a;

	e = talloc_zero(mem_ctx, struct ldb_message_element);
	W_ERROR_HAVE_NO_MEMORY(e);

	for (a = schema->attributes; a; a = a->next) {
		char *v;

		v = talloc_asprintf(e, "( %s NAME '%s' SYNTAX '%s' ",
				    a->attributeID_oid, a->lDAPDisplayName,
				    a->syntax->ldap_oid);
		W_ERROR_HAVE_NO_MEMORY(v);

		if (a->isSingleValued) {
			v = talloc_asprintf_append(v, "SINGLE-VALUE ");
			W_ERROR_HAVE_NO_MEMORY(v);
		}

		if (a->systemOnly) {
			v = talloc_asprintf_append(v, "NO-USER-MODIFICATION ");
			W_ERROR_HAVE_NO_MEMORY(v);
		}

		v = talloc_asprintf_append(v, ")");
		W_ERROR_HAVE_NO_MEMORY(v);

		DEBUG(0,("%s\n", v));
	}

	return WERR_FOOBAR;
}

WERROR dsdb_subSchema_objectClasses(const struct dsdb_schema *schema,
				    TALLOC_CTX *mem_ctx)
{
	struct ldb_message_element *e;
	struct dsdb_class *c;

	e = talloc_zero(mem_ctx, struct ldb_message_element);
	W_ERROR_HAVE_NO_MEMORY(e);

	for (c = schema->classes; c; c = c->next) {
		const char *class_type;
		char *v;

		switch (c->objectClassCategory) {
		case 0:
			/*
			 * NOTE: this is an type 88 class
			 *       e.g. 2.5.6.6 NAME 'person'
			 *	 but w2k3 gives STRUCTURAL here!
			 */
			class_type = "STRUCTURAL";
			break;
		case 1:
			class_type = "STRUCTURAL";
			break;
		case 2:
			class_type = "ABSTRACT";
			break;
		case 3:
			class_type = "AUXILIARY";
			break;
		default:
			class_type = "UNKNOWN";
			break;
		}

		v = talloc_asprintf(e, "( %s NAME '%s' SUB %s %s ",
				    c->governsID_oid, c->lDAPDisplayName,
				    c->subClassOf, class_type);
		W_ERROR_HAVE_NO_MEMORY(v);

		v = dsdb_subSchema_list_append(v, "MUST");
		W_ERROR_HAVE_NO_MEMORY(v);

		v = dsdb_subSchema_list_append(v, "MAY");
		W_ERROR_HAVE_NO_MEMORY(v);

		v = talloc_asprintf_append(v, ")");
		W_ERROR_HAVE_NO_MEMORY(v);

		DEBUG(0,("%s\n", v));
	}

	return WERR_FOOBAR;
}

WERROR dsdb_subSchema_dITContentRules(const struct dsdb_schema *schema,
				      TALLOC_CTX *mem_ctx)
{
	struct ldb_message_element *e;
	struct dsdb_class *c;

	e = talloc_zero(mem_ctx, struct ldb_message_element);
	W_ERROR_HAVE_NO_MEMORY(e);

	for (c = schema->classes; c; c = c->next) {
		char *v;

		/*
		 * TODO: filter out classes without auxiliary classes
		 */

		v = talloc_asprintf(e, "( %s NAME '%s' ",
				    c->governsID_oid, c->lDAPDisplayName);
		W_ERROR_HAVE_NO_MEMORY(v);

		v = dsdb_subSchema_list_append(v, "AUX");
		W_ERROR_HAVE_NO_MEMORY(v);

		v = dsdb_subSchema_list_append(v, "MUST");
		W_ERROR_HAVE_NO_MEMORY(v);

		v = dsdb_subSchema_list_append(v, "MAY");
		W_ERROR_HAVE_NO_MEMORY(v);

		v = talloc_asprintf_append(v, ")");
		W_ERROR_HAVE_NO_MEMORY(v);

		DEBUG(0,("%s\n", v));
	}

	return WERR_FOOBAR;
}

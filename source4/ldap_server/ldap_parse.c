/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Simo Sorce 2004
   
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
#include "ldap_parse.h"

static char char_from_hex(char a, char b) {
	char m, l;

	if ('0' <= a  && a <= '9') {
		m = a - '0';
	} else if ('A' <= a && a <= 'F') {
		m = 10 + (a - 'A');
	} else if ('a' <= a && a <= 'f') {
		m = 10 + (a - 'a');
	} else {
		return a;
	}

	if ('0' <= b  && b <= '9') {
		l = b - '0';
	} else if ('A' <= b && b <= 'F') {
		l = 10 + (b - 'A');
	} else if ('a' <= b && b <= 'f') {
		l = 10 + (b - 'a');
	} else {
		return a;
	}

	return ((m << 4) + l);
}

static char *parse_slash(char *p, char *end) {
	switch (*(p + 1)) {
	case ',':
	case '=':
	case '\n':
	case '+':
	case '<':
	case '>':
	case '#':
	case ';':
	case '\\':
	case '"':
		memmove(p, p + 1, end - (p + 1));
		return (end - 1);
	default:
		*p = char_from_hex(*(p + 1), *(p + 2));
		memmove(p + 1, p + 3, end - (p + 3));
		return (end - 2);
	}
}

#define LDAP_PARSE_DN_INVALID(x) do {\
	if (x) { \
		dn->comp_num = -1; \
		return dn; \
	} \
} while(0)

#if 0
static void ldap_parse_attributetypedescription(struct ldap_schema *schema, DATA_BLOB *data)
{
	char *desc;

	desc = (char *)talloc(schema, data->lenght + 1);
	memcpy(desc, data->data, data->lenght);
	desc[data->lenght] = '\0';

}

static void ldap_parse_objectclassdescription(struct ldap_schema *schema, DATA_BLOB *data)
{
	char *desc;

	desc = (char *)talloc(schema, data->lenght + 1);
	memcpy(desc, data->data, data->lenght);
	desc[data->lenght] = '\0';

}

static struct ldap_schema *ldap_get_schema(void *mem_ctx, struct ldap_schema *schema, struct ldb_context *ldb)
{
	NTSTATUS status;
	struct ldap_schema *local_schema;
	struct ldb_message **res;
	const char *errstr;
	const char *schema_dn = "cn=schema";
	const char *attr_filter = "attributeTypeDescription=*";
	const char *class_filter = "objectClassDescription=*";
	const char *attrs = "attributeTypeDescription";
	const char *classes = "objectClassDescription";
	enum ldb_scope scope = LDAP_SCOPE_SUBTREE;
	int count, i, j, k;

	local_schema = schema;
	if (local_schema == NULL) {
		local_schema = talloc_p(mem_ctx, struct ldap_schema);
		ALLOC_CHECK(local_schema);
	}

	count = ldb_search(ldb, schema_dn, scope, attr_filter, attrs, &res);

	for (i = 0; i < count; i++) {
		if (res[i]->num_elements == 0) {
			goto attr_done;
		}
		for (j = 0; j < res[i]->num_elements; j++) {
			for (k = 0; res[i]->elements[j].num_values; k++) {
				ldap_parse_attributetypedescription(local_schema, &(res[i]->elements[j].values[k]));
			}
		}
attr_done:
	}

	count = ldb_search(ldb, schema_dn, scope, class_filter, classes, &res);

	for (i = 0; i < count; i++) {
		if (res[i]->num_elements == 0) {
			goto class_done;
		}
		for (j = 0; j < res[i]->num_elements; j++) {
			for (k = 0; res[i]->elements[j].num_values; k++) {
				ldap_parse_objectclassdescription(local_schema, &(res[i]->elements[j].values[k]));
			}
		}
class_done:
	}

	return local_schema;
}
#endif

struct ldap_dn *ldap_parse_dn(void *mem_ctx, const char *orig_dn)
{
	struct ldap_dn *dn;
	struct dn_component *component;
	struct dn_attribute *attribute;
	char *p, *start, *separator, *src, *dest, *dn_copy, *dn_end;
	int i, size, orig_len;

	dn = talloc_p(mem_ctx, struct ldap_dn);
	dn->comp_num = 0;
	dn->components = talloc_array_p(dn, struct dn_component *, 1);
	component = talloc_p(dn, struct dn_component);
	component->attr_num = 0;

	orig_len = strlen(orig_dn);
	if (orig_len == 0) {
		dn->dn = talloc_strdup(dn, orig_dn);
		return dn;
	}

	dn_copy = p = talloc_strdup(mem_ctx, orig_dn);
	dn_end = dn_copy + orig_len + 1;
	do {
		component->attributes = talloc_array_p(component, struct dn_attribute *, 1);
		attribute = talloc_p(component, struct dn_attribute);

		/* skip "spaces" */
		while (*p == ' ' || *p == '\n') {
			p++;
		}

		/* start parsing this component */
		do {
			start = p;

			/* find out key separator '=' */
			while (*p && *p != '=') {
				if (*p == '\\') {
					dn_end = parse_slash(p, dn_end);
				}
				p++;
			}
			separator = p;

			/* remove spaces */
			while (*(p - 1) == ' ' || *(p - 1) == '\n') {
				p--;
			}

			/* save key name */
			LDAP_PARSE_DN_INVALID((p - start) < 1);
			attribute->name = talloc_strndup(attribute, start, p - start);
			DEBUG(10, ("attribute name: [%s]\n", attribute->name));

			p = separator + 1;

			/* skip spaces past the separator */
			p = separator + strspn(p, " \n") + 1;
			start = p;

			/* check if the value is enclosed in QUOTATION */
			if (*p == '"') {
				start = p + 1;
				while (*p && *p != '"') {
					if (*p == '\\') {
						dn_end = parse_slash(p, dn_end);
					}
					p++;
				}

				/* skip spaces until the separator */
				separator = p + strspn(p, " \n");

				if (*separator != ',' && *separator != ';' && *separator != '+') { /* there must be a separator here */
					/* Error Malformed DN */
					DEBUG (0, ("Error: Malformed DN!\n"));
					break;
				}
			} else {
				while (*p && !(*p == ',' || *p == ';' || *p == '+')) {
					if (*p == '\\') {
						dn_end = parse_slash(p, dn_end);
					}
					p++;
				} /* found separator */

				separator = p;

				/* remove spaces */
				while (*(p - 1) == ' ' || *(p - 1) == '\n') {
					p--;
				}
			}

			/* save the value */
			LDAP_PARSE_DN_INVALID((p - start) < 1);
			attribute->value = talloc_strndup(attribute, start, p - start);
			DEBUG(10, ("attribute value: [%s]\n", attribute->value));

			attribute->attribute = talloc_asprintf(attribute,"%s=%s", attribute->name, attribute->value);
			DEBUG(10, ("attribute: [%s]\n", attribute->attribute));

			/* save the attribute */
			component->attributes[component->attr_num] = attribute;
			component->attr_num++;

			if (*separator == '+') { /* expect other attributes in this component */
				component->attributes = talloc_realloc_p(component, component->attributes, struct dn_attribute *, component->attr_num + 1);

				/* allocate new attribute structure */
				attribute = talloc_p(component, struct dn_attribute);

				/* skip spaces past the separator */
				p = separator + strspn(p, " \n");
			}

		} while (*separator == '+');

		/* found component bounds */
		for (i = 0, size = 0; i < component->attr_num; i++) {
			size = size + strlen(component->attributes[i]->attribute) + 1;
		}

		/* rebuild the normlaized component and put it here */
		component->component = dest = talloc(component, size);
		for (i = 0; i < component->attr_num; i++) {
			if (i != 0) {
				*dest = '+';
				dest++;
			}
			src = component->attributes[i]->attribute;
			do {
				*(dest++) = *(src++);
			} while(*src);
			*dest = '\0';
		}
		DEBUG(10, ("component: [%s]\n", component->component));

		dn->components[dn->comp_num] = component;
		dn->comp_num++;

		if (*separator == ',' || *separator == ';') {
			dn->components = talloc_realloc_p(dn, dn->components, struct dn_component *, dn->comp_num + 1);
			component = talloc_p(dn, struct dn_component);
			component->attr_num = 0;
		}
		p = separator + 1;

	} while(*separator == ',' || *separator == ';');

	for (i = 0, size = 0; i < dn->comp_num; i++) {
		size = size + strlen(dn->components[i]->component) + 1;
	}

	/* rebuild the normlaized dn and put it here */
	dn->dn = dest = talloc(dn, size);
	for (i = 0; i < dn->comp_num; i++) {
		if (i != 0) {
			*dest = ',';
			dest++;
		}
		src = dn->components[i]->component;
		do {
			*(dest++) = *(src++);
		} while(*src);
		*dest = '\0';
	}
	DEBUG(10, ("dn: [%s]\n", dn->dn));

	talloc_free(dn_copy);

	return dn;
}

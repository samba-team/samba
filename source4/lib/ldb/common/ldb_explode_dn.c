/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Simo Sorce 2004
   Copyright (C) Derrell Lipman 2005
   
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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_explode_dn.h"

#define LDB_PARSE_DN_INVALID(x) do {            \
	if (x) {                                \
                goto failed;                    \
	}                                       \
} while(0)


/*
 * Forward declarations
 */

static char *
parse_slash(char *p,
            char *end);



/*
 * Public functions
 */

/*
 * ldb_explode_dn()
 *
 * Explode, normalize, and optionally case-fold a DN string.  The result is a
 * structure containing arrays of the constituent RDNs.
 *
 * Parameters:
 *   mem_ctx -
 *     talloc context on which all allocated memory is hung
 *
 *   orig_dn -
 *     The distinguished name, in string format, to be exploded
 *
 *   hUserData -
 *     Data handle provided by the caller, and passed back to the caller in
 *     the case_fold_attr_fn callback function.  This handle is not otherwise
 *     used within this function.
 *
 *   case_fold_attr_fn -
 *     Pointer to a callback function which will be called to determine if a
 *     particular attribute type (name) requires case-folding of its values.
 *     If this function pointer is non-null, then attribute names will always
 *     be case-folded.  Additionally, the function pointed to by
 *     case_fold_attr_fn will be called with the data handle (hUserData) and
 *     an attribute name as its parameters, and should return TRUE or FALSE to
 *     indicate whether values of that attribute type should be case-folded.
 *
 *     If case_fold_attr_fn is null, then neither attribute names nor
 *     attribute values will be case-folded.
 *
 * Returns:
 *   Upon success, an ldb_dn structure pointer is returned, containing the
 *   exploded DN.
 *
 *   If memory could not be allocated or if the DN was improperly formatted,
 *   NULL is returned.
 */
struct ldb_dn *
ldb_explode_dn(void * mem_ctx,
               const char * orig_dn,
               void * hUserData,
               int (*case_fold_attr_fn)(void * hUserData,
                                        char * attr))
{
	struct ldb_dn *             dn;
	struct ldb_dn_component *   component;
	struct ldb_dn_attribute *   attribute;
	char *                      p;
        char *                      start;
        char *                      separator;
        char *                      src;
        char *                      dest;
        char *                      dn_copy;
        char *                      dn_end;
	int                         i;
        int                         size;
        int                         orig_len;

        /* Allocate a structure to hold the exploded DN */
	if ((dn = talloc(mem_ctx, struct ldb_dn)) == NULL) {
            return NULL;
        }

        /* Initially there are no components */
	dn->comp_num = 0;

        /* Allocate the component array, with space for one component */
	if ((dn->components =
             talloc_array(dn, struct ldb_dn_component *, 1)) == NULL) {

                goto failed;
        }

        /* Allocate the first component */
	if ((component = talloc(dn, struct ldb_dn_component)) == NULL) {
                goto failed;
        }

        /* This component has no attributes yet */
	component->attr_num = 0;

        /* Get the length of the provided DN */
	if ((orig_len = strlen(orig_dn)) == 0) {

                /* We found a zero-length DN.  Return it. */
		if ((dn->dn = talloc_strdup(dn, orig_dn)) == NULL) {
                        goto failed;
                }
		return dn;
	}

        /* Copy the provided DN so we can manipulate it */
	if ((dn_copy = p = talloc_strdup(mem_ctx, orig_dn)) == NULL) {
                goto failed;
        }

        /* Our copy may end shorter than the original as we unescape chars */
	dn_end = dn_copy + orig_len + 1;

        /* For each attribute/value pair... */
	do {
                /* Allocate an array to hold the attributes, initially len 1 */
		if ((component->attributes =
                     talloc_array(component,
                                  struct ldb_dn_attribute *, 1)) == NULL) {
                        goto failed;
                }
                
                /* Allocate this attribute */
		if ((attribute =
                     talloc(component, struct ldb_dn_attribute)) == NULL) {
                        goto failed;
                }

		/* skip white space */
		while (*p == ' ' || *p == '\n') {
			p++;
		}

		/* start parsing this component */
		do {
                        /* Save pointer to beginning of attribute name */
			start = p;

			/* find our attribute/value separator '=' */
			while (*p != '\0' && *p != '=') {
				if (*p == '\\') {
					if ((dn_end =
                                             parse_slash(p, dn_end)) == NULL) {
                                                goto failed;
                                        }
				}
				p++;
			}

                        /* Ensure we found the attribute/value separator */
                        if (*p != '=') {
                                goto failed;
                        }

                        /* Save pointer to separator */
			separator = p;

			/* remove trailing white space from attribute name */
			while (p > start &&
                               (*(p - 1) == ' ' || *(p - 1) == '\n')) {

				p--;
			}
			LDB_PARSE_DN_INVALID((p - start) < 1);

			/* save attribute name */
			if ((attribute->name =
                             talloc_strndup(attribute,
                                            start,
                                            p - start)) == NULL) {
                                goto failed;
                        }

                        /* attribute names are always case-folded */
                        p = attribute->name;
                        if ((attribute->name =
                             ldb_casefold(attribute, p)) == NULL) {
                                goto failed;
                        }
                        talloc_free(p);

			ldb_debug(mem_ctx,
                                  LDB_DEBUG_TRACE,
                                  "attribute name: [%s]\n", attribute->name);

                        /* skip white space after the separator */
                        p = separator + 1;
                        p += strspn(p, " \n");
                        
                        /* ensure there's a value here */
                        if (*p == '\0') {
                                goto failed;
                        }

			/* check if the value is enclosed in QUOTATION */
			if (*p == '"') {
                                /* save pointer to beginning of attr value */
				start = p + 1;

                                /* find the trailing QUOTE */
				while (*p != '\0' && *p != '"') {
					if (*p == '\\') {
						if ((dn_end =
                                                     parse_slash(p, dn_end)) == NULL) {
                                                        goto failed;
                                                }
					}

					p++;
				}

                                /* skip spaces until the separator */
                                if (*p == '\0') {
                                        /* We're already at end of string */
                                        separator = p;
                                } else {
                                        /* Skip spaces */
                                        separator = p + 1 + strspn(p+1, " \n");
                                }

                                /* must be end of string or a separator here */
				if (*separator != '\0' &&
                                    *separator != ',' &&
                                    *separator != ';' &&
                                    *separator != '+') { 
					/* Error Malformed DN */
                                        goto failed;
				}
			} else {
                                /*
                                 * Value is not quouted.
                                 */

                                /* save pointer to beginning of value */
                                start = p;

                                /* find end of value */
				while (*p != '\0' &&
                                       *p != ',' &&
                                       *p != ';' &&
                                       *p != '+') {

					if (*p == '\\') {
						if ((dn_end =
                                                     parse_slash(p, dn_end)) == NULL) {
                                                        goto failed;
                                                }
					}

					p++;
				}

                                /* save pointer to the terminating separator */
				separator = p;

				/* remove trailing whitespace */
				while (p > start &&
                                       (*(p - 1) == ' ' ||
                                        *(p - 1) == '\n')) {
                                    
					p--;
				}
			}
			LDB_PARSE_DN_INVALID((p - start) < 1);

			/* save the value */
			if ((attribute->value =
                             talloc_strndup(attribute,
                                            start,
                                            p - start)) == NULL) {
                                goto failed;
                        }

                        /* see if this attribute value needs case folding */
                        if (case_fold_attr_fn != NULL &&
                            (* case_fold_attr_fn)(hUserData,
                                                  attribute->name)) {
                                /* yup, case-fold it. */
                                p = attribute->value;
                                if ((attribute->value =
                                     ldb_casefold(attribute, p)) == NULL) {
                                        goto failed;
                                }
                                talloc_free(p);
                        }

                        ldb_debug(mem_ctx,
                                  LDB_DEBUG_TRACE,
                                  "attribute value: [%s]\n", attribute->value);

                        /* save the entire RDN */
                        if ((attribute->rdn =
                             talloc_asprintf(attribute,
                                             "%s=%s",
                                             attribute->name,
                                             attribute->value)) == NULL) {
                                goto failed;
                        }

                        ldb_debug(mem_ctx,
                                  LDB_DEBUG_TRACE,
                                  "attribute: [%s]\n", attribute->rdn);

                        /* add this attribute to the attribute list */
			component->attributes[component->attr_num] = attribute;
			component->attr_num++;

                        /* is this a multi-valued attribute? */
			if (*separator == '+') {
                                /* Yup.  prepare for the next value. */
                                if ((component->attributes =
                                     talloc_realloc(component,
                                                    component->attributes,
                                                    struct ldb_dn_attribute *,
                                                    component->attr_num + 1)) == NULL) {
                                        goto failed;
                                }

				/* allocate new attribute structure */
				if ((attribute =
                                     talloc(component,
                                            struct ldb_dn_attribute)) == NULL) {
                                        goto failed;
                                }
			}

                        /* if we're not at end of string, skip white space */
                        if (*separator != '\0') {
                                /* skip spaces past the separator */
                                p = separator + 1;
                                p += strspn(p, " \n");
                        }

		} while (*separator == '+');

                /* find total length of all attributes */
		for (i = 0, size = 0; i < component->attr_num; i++) {
			size += strlen(component->attributes[i]->rdn) + 1;
		}

		/*
                 * rebuild the normalized component
                 */

                /* allocate space for the normalized component */
		if ((component->component =
                     dest = talloc_size(component, size)) == NULL) {

                        goto failed;
                }

                /* copy each of the attributes to the normalized component */
		for (i = 0; i < component->attr_num; i++) {
			if (i != 0) {
				*dest++ = '+';
			}
			src = component->attributes[i]->rdn;

                        /* we are guaranteed to have enough space in dest */
                        size = strlen(src);
                        strncpy(dest, src, size + 1);
                        dest += size;
		}

		ldb_debug(mem_ctx,
                          LDB_DEBUG_TRACE,
                          "component: [%s]\n", component->component);

                /* insert the component into the component list */
		dn->components[dn->comp_num] = component;
		dn->comp_num++;

                /* if there are additional components... */
		if (*separator == ',' || *separator == ';') {
                        /* ... then prepare to parse them */
                        if ((dn->components =
                             talloc_realloc(dn,
                                            dn->components,
                                            struct ldb_dn_component *,
                                            dn->comp_num + 1)) == NULL ||
                            (component =
                             talloc(dn, struct ldb_dn_component)) == NULL) {

                                goto failed;
                        }

			component->attr_num = 0;
		}

                /* update pointer to after the separator */
		p = separator + 1;

	} while(*separator == ',' || *separator == ';');

        /* find total length of all components */
	for (i = 0, size = 0; i < dn->comp_num; i++) {
		size = size + strlen(dn->components[i]->component) + 1;
	}

	/* rebuild the normalized DN */
	if ((dn->dn = dest = talloc_size(dn, size)) == NULL) {
                goto failed;
        }

        /* copy the normalized components into the DN */
	for (i = 0; i < dn->comp_num; i++) {

                /* add a separator between DN components */
		if (i != 0) {
			*dest++ = ',';
		}

                /* point to this component of the DN */
		src = dn->components[i]->component;

                /* we are guaranteed to have enough space in dest */
                size = strlen(src);
                strncpy(dest, src, size + 1);
                dest += size;
	}

	ldb_debug(mem_ctx, LDB_DEBUG_TRACE, "dn: [%s]\n", dn->dn);

        /* we don't need the copy of the DN any more */
	talloc_free(dn_copy);

        /* give 'em what they came for! */
	return dn;

failed:
        /* something went wrong.  free memory and tell 'em it failed */
        talloc_free(dn);
        ldb_debug(mem_ctx, LDB_DEBUG_TRACE, "Failed to parse %s\n", orig_dn);
        return NULL;
}


static char *
parse_slash(char *p,
            char *end)
{
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
                if (isxdigit(p[1]) && isxdigit(p[2])) {
                        int             x;

                        sscanf(p + 1, "%02x", &x);
                        *p = (char) x;
                        memmove(p + 1, p + 3, end - (p + 3));
                        return (end - 2);
                } else {
                        return NULL;
                }
	}
}


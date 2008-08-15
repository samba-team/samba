/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2006

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ad2oLschema
 *
 *  Description: utility to convert an AD schema into the format required by OpenLDAP
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb_includes.h"
#include "system/locale.h"
#include "lib/ldb/tools/cmdline.h"
#include "utils/schema_convert.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "dsdb/samdb/samdb.h"

struct schema_conv {
	int count;
	int skipped;
	int failures;
};

enum convert_target {
	TARGET_OPENLDAP,
	TARGET_FEDORA_DS
};
	

static void usage(void)
{
	printf("Usage: ad2oLschema <options>\n");
	printf("\nConvert AD-like LDIF to OpenLDAP schema format\n\n");
	printf("Options:\n");
	printf("  -I inputfile     inputfile of mapped OIDs and skipped attributes/ObjectClasses");
	printf("  -H url           LDB or LDAP server to read schmea from\n");
	printf("  -O outputfile    outputfile otherwise STDOUT\n");
	printf("  -o options       pass options like modules to activate\n");
	printf("              e.g: -o modules:timestamps\n");
	printf("\n");
	printf("Converts records from an AD-like LDIF schema into an openLdap formatted schema\n\n");
	exit(1);
}

static struct ldb_dn *find_schema_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx) 
{
	const char *rootdse_attrs[] = {"schemaNamingContext", NULL};
	struct ldb_dn *schemadn;
	struct ldb_dn *basedn = ldb_dn_new(mem_ctx, ldb, NULL);
	struct ldb_result *rootdse_res;
	struct ldb_result *schema_res;
	int ldb_ret;
	
	if (!basedn) {
		return NULL;
	}
	
	/* Search for rootdse */
	ldb_ret = ldb_search(ldb, basedn, LDB_SCOPE_BASE, NULL, rootdse_attrs, &rootdse_res);
	if (ldb_ret != LDB_SUCCESS) {
		ldb_ret = ldb_search(ldb, basedn, LDB_SCOPE_SUBTREE, 
				 "(&(objectClass=dMD)(cn=Schema))", 
				 NULL, &schema_res);
		if (ldb_ret) {
			printf("cn=Schema Search failed: %s\n", ldb_errstring(ldb));
			return NULL;
		}

		talloc_steal(mem_ctx, schema_res);

		if (schema_res->count != 1) {
			talloc_free(schema_res);
			printf("Failed to find rootDSE");
			return NULL;
		}
		
		schemadn = talloc_steal(mem_ctx, schema_res->msgs[0]->dn);
		talloc_free(schema_res);
		return schemadn;
	}
	
	if (rootdse_res->count != 1) {
		printf("Failed to find rootDSE");
		talloc_free(rootdse_res);
		return NULL;
	}
	
	/* Locate schema */
	schemadn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, rootdse_res->msgs[0], "schemaNamingContext");
	talloc_free(rootdse_res);

	if (!schemadn) {
		return NULL;
	}

	return schemadn;
}


#define IF_NULL_FAIL_RET(x) do {     \
		if (!x) {		\
			ret.failures++; \
			return ret;	\
		}			\
	} while (0) 


static struct schema_conv process_convert(struct ldb_context *ldb, enum convert_target target, FILE *in, FILE *out) 
{
	/* Read list of attributes to skip, OIDs to map */
	TALLOC_CTX *mem_ctx = talloc_new(ldb);
	char *line;
	const char **attrs_skip = NULL;
	int num_skip = 0;
	struct oid_map {
		char *old_oid;
		char *new_oid;
	} *oid_map = NULL;
	int num_oid_maps = 0;
	struct attr_map {
		char *old_attr;
		char *new_attr;
	} *attr_map = NULL;
	int num_attr_maps = 0;	
	struct dsdb_class *objectclass;
	struct dsdb_attribute *attribute;
	struct ldb_dn *schemadn;
	struct schema_conv ret;
	struct dsdb_schema *schema;
	const char *seperator;
	char *error_string;

	int ldb_ret;

	ret.count = 0;
	ret.skipped = 0;
	ret.failures = 0;

	while ((line = afdgets(fileno(in), mem_ctx, 0))) {
		/* Blank Line */
		if (line[0] == '\0') {
			continue;
		}
		/* Comment */
		if (line[0] == '#') {
			continue;
		}
		if (isdigit(line[0])) {
			char *p = strchr(line, ':');
			IF_NULL_FAIL_RET(p);
			p[0] = '\0';
			p++;
			oid_map = talloc_realloc(mem_ctx, oid_map, struct oid_map, num_oid_maps + 2);
			trim_string(line, " ", " ");
			oid_map[num_oid_maps].old_oid = talloc_move(oid_map, &line);
			trim_string(p, " ", " ");
			oid_map[num_oid_maps].new_oid = p;
			num_oid_maps++;
			oid_map[num_oid_maps].old_oid = NULL;
		} else {
			char *p = strchr(line, ':');
			if (p) {
				/* remap attribute/objectClass */
				p[0] = '\0';
				p++;
				attr_map = talloc_realloc(mem_ctx, attr_map, struct attr_map, num_attr_maps + 2);
				trim_string(line, " ", " ");
				attr_map[num_attr_maps].old_attr = talloc_move(attr_map, &line);
				trim_string(p, " ", " ");
				attr_map[num_attr_maps].new_attr = p;
				num_attr_maps++;
				attr_map[num_attr_maps].old_attr = NULL;
			} else {
				/* skip attribute/objectClass */
				attrs_skip = talloc_realloc(mem_ctx, attrs_skip, const char *, num_skip + 2);
				trim_string(line, " ", " ");
				attrs_skip[num_skip] = talloc_move(attrs_skip, &line);
				num_skip++;
				attrs_skip[num_skip] = NULL;
			}
		}
	}

	schemadn = find_schema_dn(ldb, mem_ctx);
	if (!schemadn) {
		printf("Failed to find schema DN: %s\n", ldb_errstring(ldb));
		ret.failures = 1;
		return ret;
	}
	
	ldb_ret = dsdb_schema_from_schema_dn(mem_ctx, ldb,
					     lp_iconv_convenience(cmdline_lp_ctx),
					     schemadn, &schema, &error_string);
	if (ldb_ret != LDB_SUCCESS) {
		printf("Failed to load schema: %s\n", error_string);
		ret.failures = 1;
		return ret;
	}

	switch (target) {
	case TARGET_OPENLDAP:
		seperator = "\n  ";
		break;
	case TARGET_FEDORA_DS:
		seperator = "\n  ";
		fprintf(out, "dn: cn=schema\n");
		break;
	}

	for (attribute=schema->attributes; attribute; attribute = attribute->next) {
		const char *name = attribute->lDAPDisplayName;
		const char *description = attribute->adminDescription;
		const char *oid = attribute->attributeID_oid;
		const char *syntax = attribute->attributeSyntax_oid;
		bool single_value = attribute->isSingleValued;

		const struct syntax_map *const_map = find_syntax_map_by_ad_oid(syntax);
		struct syntax_map map, *map_p = NULL;
		char *schema_entry = NULL;
		int j;

		/* We have been asked to skip some attributes/objectClasses */
		if (attrs_skip && str_list_check_ci(attrs_skip, name)) {
			ret.skipped++;
			continue;
		}

		/* We might have been asked to remap this oid, due to a conflict */
		for (j=0; oid && oid_map && oid_map[j].old_oid; j++) {
			if (strcasecmp(oid, oid_map[j].old_oid) == 0) {
				oid =  oid_map[j].new_oid;
				break;
			}
		}
		
		if (const_map) {
			map = *const_map;
			
			/* We might have been asked to remap this oid,
			 * due to a conflict, or lack of
			 * implementation */
			for (j=0; map.Standard_OID && oid_map && oid_map[j].old_oid; j++) {
				if (strcasecmp(map.Standard_OID, oid_map[j].old_oid) == 0) {
					map.Standard_OID =  oid_map[j].new_oid;
					break;
				}
			}

			map_p = &map;
		}

		/* We might have been asked to remap this name, due to a conflict */
		for (j=0; name && attr_map && attr_map[j].old_attr; j++) {
			if (strcasecmp(name, attr_map[j].old_attr) == 0) {
				name =  attr_map[j].new_attr;
				break;
			}
		}
		
		switch (target) {
		case TARGET_OPENLDAP:
			schema_entry = talloc_asprintf(mem_ctx, 
						       "attributetype (");
			break;
		case TARGET_FEDORA_DS:
			schema_entry = talloc_asprintf(mem_ctx, 
						       "attributeTypes: (");
			break;
		}
		IF_NULL_FAIL_RET(schema_entry);

		schema_entry = talloc_asprintf_append(schema_entry, 
						      "%s%s%s", seperator, oid, seperator);

		schema_entry = talloc_asprintf_append(schema_entry, 
						      "NAME '%s'%s", name, seperator);
		IF_NULL_FAIL_RET(schema_entry);

		if (description) {
#if 0 /* If you want to re-enable this, you must first figure out a sane escaping of ' in the description */
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "DESC '%s' ", description);
			IF_NULL_FAIL_RET(schema_entry);
#endif
		}

		if (map_p) {
			if (map_p->equality) {
				schema_entry = talloc_asprintf_append(schema_entry, 
								      "EQUALITY %s%s", map_p->equality, seperator);
				IF_NULL_FAIL_RET(schema_entry);
			}
			if (map_p->substring) {
				schema_entry = talloc_asprintf_append(schema_entry, 
								      "SUBSTR %s%s", map_p->substring, seperator);
				IF_NULL_FAIL_RET(schema_entry);
			}

			syntax = map_p->Standard_OID;
		}

		schema_entry = talloc_asprintf_append(schema_entry, 
						      "SYNTAX %s%s", syntax, seperator);
		IF_NULL_FAIL_RET(schema_entry);

		if (single_value) {
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "SINGLE-VALUE%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
		}
		
		schema_entry = talloc_asprintf_append(schema_entry, 
						      ")");

		switch (target) {
		case TARGET_OPENLDAP:
			fprintf(out, "%s\n\n", schema_entry);
			break;
		case TARGET_FEDORA_DS:
			fprintf(out, "%s\n", schema_entry);
			break;
		}
		ret.count++;
	}

	/* This is already sorted to have 'top' and similar classes first */
	for (objectclass=schema->classes; objectclass; objectclass = objectclass->next) {
		const char *name = objectclass->lDAPDisplayName;
		const char *description = objectclass->adminDescription;
		const char *oid = objectclass->governsID_oid;
		const char *subClassOf = objectclass->subClassOf;
		int objectClassCategory = objectclass->objectClassCategory;
		char **must;
		char **may;
		char *schema_entry = NULL;
		const char *objectclass_name_as_list[] = {
			objectclass->lDAPDisplayName,
			NULL
		};
		int j;
		
		/* We have been asked to skip some attributes/objectClasses */
		if (attrs_skip && str_list_check_ci(attrs_skip, name)) {
			ret.skipped++;
			continue;
		}

		/* We might have been asked to remap this oid, due to a conflict */
		for (j=0; oid_map && oid_map[j].old_oid; j++) {
			if (strcasecmp(oid, oid_map[j].old_oid) == 0) {
				oid =  oid_map[j].new_oid;
				break;
			}
		}
		
		/* We might have been asked to remap this name, due to a conflict */
		for (j=0; name && attr_map && attr_map[j].old_attr; j++) {
			if (strcasecmp(name, attr_map[j].old_attr) == 0) {
				name =  attr_map[j].new_attr;
				break;
			}
		}
		
		may = dsdb_full_attribute_list(mem_ctx, schema, objectclass_name_as_list, DSDB_SCHEMA_ALL_MAY);

		must = dsdb_full_attribute_list(mem_ctx, schema, objectclass_name_as_list, DSDB_SCHEMA_ALL_MUST);

		switch (target) {
		case TARGET_OPENLDAP:
			schema_entry = talloc_asprintf(mem_ctx, 
						       "objectclass (");
			break;
		case TARGET_FEDORA_DS:
			schema_entry = talloc_asprintf(mem_ctx, 
						       "objectClasses: (");
			break;
		}
		schema_entry = talloc_asprintf_append(schema_entry, 
						      "%s%s%s", seperator, oid, seperator);
						      
		IF_NULL_FAIL_RET(schema_entry);
		if (!schema_entry) {
			ret.failures++;
			break;
		}

		schema_entry = talloc_asprintf_append(schema_entry, 
						      "NAME '%s'%s", name, seperator);
		IF_NULL_FAIL_RET(schema_entry);

		if (!schema_entry) return ret;

		if (description) {
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "DESC '%s'%s", description, seperator);
			IF_NULL_FAIL_RET(schema_entry);
		}

		if (subClassOf) {
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "SUP %s%s", subClassOf, seperator);
			IF_NULL_FAIL_RET(schema_entry);
		}
		
		switch (objectClassCategory) {
		case 1:
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "STRUCTURAL%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
			break;
		case 2:
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "ABSTRACT%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
			break;
		case 3:
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "AUXILIARY%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
			break;
		}

#define APPEND_ATTRS(attributes) \
		do {						\
			int k;						\
			for (k=0; attributes && attributes[k]; k++) { \
				int attr_idx; \
				const char *attr_name = attributes[k];  \
				/* We might have been asked to remap this name, due to a conflict */ \
				for (attr_idx=0; attr_name && attr_map && attr_map[attr_idx].old_attr; attr_idx++) { \
					if (strcasecmp(attr_name, attr_map[attr_idx].old_attr) == 0) { \
						attr_name =  attr_map[attr_idx].new_attr; \
						break;			\
					}				\
				}					\
									\
				schema_entry = talloc_asprintf_append(schema_entry, \
								      "%s ", \
								      attr_name); \
				IF_NULL_FAIL_RET(schema_entry);		\
				if (attributes[k+1]) { \
					IF_NULL_FAIL_RET(schema_entry);	\
					if (target == TARGET_OPENLDAP && ((k+1)%5 == 0)) { \
						schema_entry = talloc_asprintf_append(schema_entry, \
										      "$%s ", seperator); \
						IF_NULL_FAIL_RET(schema_entry);	\
					} else {			\
						schema_entry = talloc_asprintf_append(schema_entry, \
										      "$ "); \
					}				\
				}					\
			}						\
		} while (0)

		if (must) {
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "MUST ( ");
			IF_NULL_FAIL_RET(schema_entry);

			APPEND_ATTRS(must);

			schema_entry = talloc_asprintf_append(schema_entry, 
							      ")%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
		}

		if (may) {
			schema_entry = talloc_asprintf_append(schema_entry, 
							      "MAY ( ");
			IF_NULL_FAIL_RET(schema_entry);

			APPEND_ATTRS(may);

			schema_entry = talloc_asprintf_append(schema_entry, 
							      ")%s", seperator);
			IF_NULL_FAIL_RET(schema_entry);
		}

		schema_entry = talloc_asprintf_append(schema_entry, 
						      ")");

		switch (target) {
		case TARGET_OPENLDAP:
			fprintf(out, "%s\n\n", schema_entry);
			break;
		case TARGET_FEDORA_DS:
			fprintf(out, "%s\n", schema_entry);
			break;
		}
		ret.count++;
	}

	return ret;
}

 int main(int argc, const char **argv)
{
	TALLOC_CTX *ctx;
	struct ldb_cmdline *options;
	FILE *in = stdin;
	FILE *out = stdout;
	struct ldb_context *ldb;
	struct schema_conv ret;
	const char *target_str;
	enum convert_target target;

	ctx = talloc_new(NULL);
	ldb = ldb_init(ctx, NULL);

	options = ldb_cmdline_process(ldb, argc, argv, usage);

	if (options->input) {
		in = fopen(options->input, "r");
		if (!in) {
			perror(options->input);
			exit(1);
		}
	}
	if (options->output) {
		out = fopen(options->output, "w");
		if (!out) {
			perror(options->output);
			exit(1);
		}
	}

	target_str = lp_parm_string(cmdline_lp_ctx, NULL, "convert", "target");

	if (!target_str || strcasecmp(target_str, "openldap") == 0) {
		target = TARGET_OPENLDAP;
	} else if (strcasecmp(target_str, "fedora-ds") == 0) {
		target = TARGET_FEDORA_DS;
	} else {
		printf("Unsupported target: %s\n", target_str);
		exit(1);
	}

	ret = process_convert(ldb, target, in, out);

	fclose(in);
	fclose(out);

	printf("Converted %d records (skipped %d) with %d failures\n", ret.count, ret.skipped, ret.failures);

	return 0;
}

/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2006-2008

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
#include "ldb.h"
#include "system/locale.h"
#include "lib/ldb/tools/cmdline.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"
#include "dsdb/samdb/samdb.h"

struct schema_conv {
	int count;
	int skipped;
	int failures;
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
	ldb_ret = ldb_search(ldb, mem_ctx, &rootdse_res,
			     basedn, LDB_SCOPE_BASE, rootdse_attrs, NULL);
	if (ldb_ret != LDB_SUCCESS) {
		ldb_ret = ldb_search(ldb, mem_ctx, &schema_res, basedn, LDB_SCOPE_SUBTREE,
				     NULL, "(&(objectClass=dMD)(cn=Schema))");
		if (ldb_ret) {
			printf("cn=Schema Search failed: %s\n", ldb_errstring(ldb));
			return NULL;
		}

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


static struct schema_conv process_convert(struct ldb_context *ldb, enum dsdb_schema_convert_target target, FILE *in, FILE *out) 
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
			if (!p) {
				ret.failures++;
				return ret;
			}
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
		const char *oid = attribute->attributeID_oid;
		const char *syntax = attribute->attributeSyntax_oid;
		const char *equality = NULL, *substring = NULL;
		bool single_value = attribute->isSingleValued;

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
		
		if (attribute->syntax) {
			/* We might have been asked to remap this oid,
			 * due to a conflict, or lack of
			 * implementation */
			syntax = attribute->syntax->ldap_oid;
			/* We might have been asked to remap this oid, due to a conflict */
			for (j=0; syntax && oid_map && oid_map[j].old_oid; j++) {
				if (strcasecmp(syntax, oid_map[j].old_oid) == 0) {
					syntax =  oid_map[j].new_oid;
					break;
				}
			}
			
			equality = attribute->syntax->equality;
			substring = attribute->syntax->substring;
		}

		/* We might have been asked to remap this name, due to a conflict */
		for (j=0; name && attr_map && attr_map[j].old_attr; j++) {
			if (strcasecmp(name, attr_map[j].old_attr) == 0) {
				name =  attr_map[j].new_attr;
				break;
			}
		}
		
		schema_entry = schema_attribute_description(mem_ctx, 
							    target, 
							    seperator, 
							    oid, 
							    name, 
							    equality, 
							    substring, 
							    syntax, 
							    single_value, 
							    false,
							    NULL, NULL,
							    NULL, NULL,
							    false, false);

		if (schema_entry == NULL) {
			ret.failures++;
			return ret;
		}

		switch (target) {
		case TARGET_OPENLDAP:
			fprintf(out, "attributetype %s\n\n", schema_entry);
			break;
		case TARGET_FEDORA_DS:
			fprintf(out, "attributeTypes: %s\n", schema_entry);
			break;
		}
		ret.count++;
	}

	/* This is already sorted to have 'top' and similar classes first */
	for (objectclass=schema->classes; objectclass; objectclass = objectclass->next) {
		const char *name = objectclass->lDAPDisplayName;
		const char *oid = objectclass->governsID_oid;
		const char *subClassOf = objectclass->subClassOf;
		int objectClassCategory = objectclass->objectClassCategory;
		const char **must;
		const char **may;
		char *schema_entry = NULL;
		const char *objectclass_name_as_list[] = {
			objectclass->lDAPDisplayName,
			NULL
		};
		int j;
		int attr_idx;
		
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

		for (j=0; may && may[j]; j++) {
			/* We might have been asked to remap this name, due to a conflict */ 
			for (attr_idx=0; attr_map && attr_map[attr_idx].old_attr; attr_idx++) { 
				if (strcasecmp(may[j], attr_map[attr_idx].old_attr) == 0) { 
					may[j] =  attr_map[attr_idx].new_attr; 
					break;				
				}					
			}						
		}

		must = dsdb_full_attribute_list(mem_ctx, schema, objectclass_name_as_list, DSDB_SCHEMA_ALL_MUST);

		for (j=0; must && must[j]; j++) {
			/* We might have been asked to remap this name, due to a conflict */ 
			for (attr_idx=0; attr_map && attr_map[attr_idx].old_attr; attr_idx++) { 
				if (strcasecmp(must[j], attr_map[attr_idx].old_attr) == 0) { 
					must[j] =  attr_map[attr_idx].new_attr; 
					break;				
				}					
			}						
		}

		schema_entry = schema_class_description(mem_ctx, target, 
							seperator,
							oid, 
							name,
							NULL, 
							subClassOf,
							objectClassCategory,
							must,
							may,
							NULL);
		if (schema_entry == NULL) {
			ret.failures++;
			return ret;
		}

		switch (target) {
		case TARGET_OPENLDAP:
			fprintf(out, "objectclass %s\n\n", schema_entry);
			break;
		case TARGET_FEDORA_DS:
			fprintf(out, "objectClasses: %s\n", schema_entry);
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
	enum dsdb_schema_convert_target target;

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

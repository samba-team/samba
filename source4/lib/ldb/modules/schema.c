/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb schema module
 *
 *  Description: add schema check functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

struct attribute_syntax {
	const char *name;
	const char *syntax_id;
};

static struct attribute_syntax attrsyn[] = {
		{ "Object(DS-DN)", "2.5.5.1"},
		{ "String(Object-Identifier)", "2.5.5.2"},
		{ "", "2.5.5.3"},
		{ "String(Teletex)", "2.5.5.4"},
		{ "String(IA5)", "2.5.5.5"}, /* Also String(Printable) */
		{ "String(Numeric)", "2.5.5.6"},
		{ "Object(DN-Binary)", "2.5.5.7"}, /* Also Object(OR-Name) */
		{ "Boolean", "2.5.5.8"},
		{ "Integer", "2.5.5.9"}, /* Also Enumeration (3 types ?) ... */
		{ "String(Octet)", "2.5.5.10"}, /* Also Object(Replica-Link) */
		{ "String(UTC-Time)", "2.5.5.11"}, /* Also String(Generalized-Time) */
		{ "String(Unicode)", "2.5.5.12"},
		{ "Object(Presentation-Address)", "2.5.5.13"},
		{ "Object(DN-String)", "2.5.5.14"}, /* Also Object(Access-Point) */
		{ "String(NT-Sec-Desc))", "2.5.5.15"},
		{ "LargeInteger", "2.5.5.16"}, /* Also Interval ... */
		{ "String(Sid)", "2.5.5.17"}
	};

#define SCHEMA_TALLOC_CHECK(root, mem, ret) do { if (!mem) { talloc_free(root); return ret;} } while(0);

struct private_data {
	struct ldb_context *schema_db;
	const char *error_string;
};

/* close */
static int schema_close(struct ldb_module *module)
{
	return ldb_next_close(module);
}

/* search */
static int schema_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	return ldb_next_search(module, base, scope, expression, attrs, res); 
}

/* search_free */
static int schema_search_free(struct ldb_module *module, struct ldb_message **res)
{
	return ldb_next_search_free(module, res);
}

struct check_list {
	int check;
	char *name;
};

struct attr_list {
	int syntax;
	char *name;
};

struct objc_list {
	int aux;
	char *name;
};

struct schema_structures {
	struct check_list *cl;
	struct objc_list *ol;
	struct attr_list *must;
	struct attr_list *may;
	int num_cl;
	int num_objc;
	int num_must;
	int num_may;
};

/* add_record */
static int schema_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct ldb_message **srch;
	struct schema_structures *ss;
	int i, j, k, l;
	int ret;

	/* First implementation:
		Build up a list of must and mays from each objectclass
		Check all the musts are there and all the other attributes are mays
		Throw an error in case a check fail
		Free all structures and commit the change
	*/

	ss = talloc_p(module, struct schema_structures);
	if (!ss) {
		return -1;
	}

	ss->ol = NULL;
	ss->num_objc = 0;
	ss->num_cl = msg->num_elements;
	ss->cl = talloc_array_p(ss, struct check_list, ss->num_cl);
	SCHEMA_TALLOC_CHECK(ss, ss->cl, -1);
	for (i = 0, j = 0; i < msg->num_elements; i++) {
		if (strcasecmp(msg->elements[i].name, "objectclass") == 0) {
			ss->num_objc = msg->elements[i].num_values;
			ss->ol = talloc_array_p(ss, struct objc_list, ss->num_objc);
			SCHEMA_TALLOC_CHECK(ss, ss->ol, -1);
			for (k = 0; k < ss->num_objc; k++) {
				ss->ol[k].name = talloc_strndup(ss->ol, msg->elements[i].values[k].data, msg->elements[i].values[k].length);
				SCHEMA_TALLOC_CHECK(ss, ss->ol[k].name, -1);
				ss->ol[k].aux = 0;
			}
		}

		ss->cl[j].check = 0;
		ss->cl[j].name = talloc_strdup(ss->cl, msg->elements[i].name);
		SCHEMA_TALLOC_CHECK(ss, ss->cl[j].name, -1);
		j++;
	}

	/* find all other objectclasses recursively */
	ss->must = NULL;
	ss->may = NULL;
	ss->num_must = 0;
	ss->num_may = 0;
	for (i = 0; i < ss->num_objc; i++) {
		char *filter;

		filter = talloc_asprintf(ss, "lDAPDisplayName=%s", ss->ol[i].name);
		SCHEMA_TALLOC_CHECK(ss, filter, -1);
		ret = ldb_search(data->schema_db, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
		if (ret == 0) {
			int ok;

			ok = 0;
			/* suppose auxiliary classess are not required */
			if (ss->ol[i].aux) {
				int d;
				ok = 1;
				ss->num_objc -= 1;
				for (d = i; d < ss->num_objc; d++) {
					ss->ol[d] = ss->ol[d + 1];
				}
				i -= 1;
			}
			if (!ok) {
				/* Schema Violation: Object Class Description Not Found */
				data->error_string = "ObjectClass not found";
				talloc_free(ss);
				return -1;
			}
			continue;
		} else {
			if (ret < 0) {
				/* Schema DB Error: Error occurred retrieving Object Class Description */
				data->error_string = "Internal error. Error retrieving schema objectclass";
				talloc_free(ss);
				return -1;
			}
			if (ret > 1) {
				/* Schema DB Error: Too Many Records */
				data->error_string = "Internal error. Too many records searching for schema objectclass";
				talloc_free(ss);
				return -1;
			}
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in kust and may attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int o, is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (strcasecmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = 1;
				is_class = 1;
			}
			if (strcasecmp((*srch)->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				o = (*srch)->elements[j].num_values;
				ss->ol = talloc_realloc_p(ss, ss->ol, struct objc_list, ss->num_objc + o);
				SCHEMA_TALLOC_CHECK(ss, ss->ol, -1);
				for (k = 0, l = 0; k < o; k++) {
					int c, found, len;

					found = 0;
					for (c = 0; c < ss->num_objc; c++) {
						len = strlen(ss->ol[c].name);
						if (len == (*srch)->elements[j].values[k].length) {
							if (strncasecmp(ss->ol[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
								found = 1;
								break;
							}
						}
					}
					if (!found) {
						ss->ol[l + ss->num_objc].name = talloc_strndup(ss->ol, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
						SCHEMA_TALLOC_CHECK(ss, ss->ol[l + ss->num_objc].name, -1);
						ss->ol[l + ss->num_objc].aux = is_aux;
						l++;
					}
				}
				ss->num_objc += l;
			} else {

				if (strcasecmp((*srch)->elements[j].name, "mustContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ss->must = talloc_realloc_p(ss, ss->must, struct attr_list, ss->num_must + m);
					SCHEMA_TALLOC_CHECK(ss, ss->must, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ss->num_must; c++) {
							len  = strlen(ss->must[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ss->must[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ss->must[l + ss->num_must].name = talloc_strndup(ss->must, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ss->must[l + ss->num_must].name, -1);
							l++;
						}
					}
					ss->num_must += l;
				}

				if (strcasecmp((*srch)->elements[j].name, "mayContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMayContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ss->may = talloc_realloc_p(ss, ss->may, struct attr_list, ss->num_may + m);
					SCHEMA_TALLOC_CHECK(ss, ss->may, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ss->num_may; c++) {
							len = strlen(ss->may[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ss->may[c].name, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ss->may[l + ss->num_may].name = talloc_strndup(ss->may, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ss->may[l + ss->num_may].name, -1);
							l++;
						}
					}
					ss->num_may += l;
				}
			}
		}

		ldb_search_free(data->schema_db, srch);
	}

	/* now check all musts are present */
	for (i = 0; i < ss->num_must; i++) {
		int found;

		found = 0;
		for (j = 0; j < ss->num_cl; j++) {
			if (strcasecmp(ss->must[i].name, ss->cl[j].name) == 0) {
				ss->cl[j].check = 1;
				found = 1;
				break;
			}
		}

		if ( ! found ) {
			/* TODO: set the error string */
			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(ss);
			return -1;
		}
	}

	/* now check all others atribs are found in mays */
	for (i = 0; i < ss->num_cl; i++) {

		if ( ! ss->cl[i].check ) {
			int found;

			found = 0;
			for (j = 0; j < ss->num_may; j++) {
				if (strcasecmp(ss->may[j].name, ss->cl[i].name) == 0) {
					ss->cl[i].check = 1;
					found = 1;
					break;
				}
			}

			if ( ! found ) {
				data->error_string = "Objectclass violation, an invalid attribute name was found";
				talloc_free(ss);
				return -1;
			}
		}
	}

	talloc_free(ss);

	return ldb_next_add_record(module, msg);
}

/* modify_record */
static int schema_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct ldb_message **srch;
	struct schema_structures *ss, *ms;
	int i, j, k, l;
	int ret;

	/* First implementation:
		Retrieve the ldap entry and get the objectclasses,
		add msg contained objectclasses if any.
		Build up a list of must and mays from each objectclass
		Check all musts for the defined objectclass and it's specific
		inheritance are there.
		Check all other the attributes are mays or musts.
		Throw an error in case a check fail.
		Free all structures and commit the change.
	*/

	ss = talloc_p(module, struct schema_structures);
	if (!ss) {
		return -1;
	}

	ms = talloc_p(module, struct schema_structures);
	SCHEMA_TALLOC_CHECK(ss, ms, -1);

	ms->ol = NULL;
	ms->num_objc = 0;
	ms->num_cl = msg->num_elements;
	ms->cl = talloc_array_p(ms, struct check_list, ms->num_cl);
	SCHEMA_TALLOC_CHECK(ss, ms->cl, -1);
	for (i = 0, j = 0; i < msg->num_elements; i++) {
		if (strcasecmp(msg->elements[i].name, "objectclass") == 0) {
			ms->num_objc = msg->elements[i].num_values;
			ms->ol = talloc_array_p(ms, struct objc_list, ms->num_objc);
			SCHEMA_TALLOC_CHECK(ss, ms->ol, -1);
			for (k = 0; k < ms->num_objc; k++) {
				ms->ol[k].name = talloc_strndup(ms->ol, msg->elements[i].values[k].data, msg->elements[i].values[k].length);
				SCHEMA_TALLOC_CHECK(ss, ms->ol[k].name, -1);
				ms->ol[k].aux = 0;
			}
		}

		ms->cl[j].check = 0;
		ms->cl[j].name = talloc_strdup(ms->cl, msg->elements[i].name);
		SCHEMA_TALLOC_CHECK(ss, ms->cl[j].name, -1);
		j++;
	}

	/* find all modify objectclasses recursively if any objectclass is being added */
	ms->must = NULL;
	ms->may = NULL;
	ms->num_must = 0;
	ms->num_may = 0;
	for (i = 0; i < ms->num_objc; i++) {
		char *filter;

		filter = talloc_asprintf(ss, "lDAPDisplayName=%s", ms->ol[i].name);
		SCHEMA_TALLOC_CHECK(ss, filter, -1);
		ret = ldb_search(data->schema_db, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
		if (ret == 0) {
			int ok;

			ok = 0;
			/* suppose auxiliary classess are not required */
			if (ms->ol[i].aux) {
				int d;
				ok = 1;
				ms->num_objc -= 1;
				for (d = i; d < ms->num_objc; d++) {
					ms->ol[d] = ms->ol[d + 1];
				}
				i -= 1;
			}
			if (!ok) {
				/* Schema Violation: Object Class Description Not Found */
				data->error_string = "ObjectClass not found";
				talloc_free(ss);
				return -1;
			}
			continue;
		} else {
			if (ret < 0) {
				/* Schema DB Error: Error occurred retrieving Object Class Description */
				data->error_string = "Internal error. Error retrieving schema objectclass";
				talloc_free(ss);
				return -1;
			}
			if (ret > 1) {
				/* Schema DB Error: Too Many Records */
				data->error_string = "Internal error. Too many records searching for schema objectclass";
				talloc_free(ss);
				return -1;
			}
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in kust and may attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int o, is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (strcasecmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = 1;
				is_class = 1;
			}
			if (strcasecmp((*srch)->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				o = (*srch)->elements[j].num_values;
				ms->ol = talloc_realloc_p(ms, ms->ol, struct objc_list, ms->num_objc + o);
				SCHEMA_TALLOC_CHECK(ss, ms->ol, -1);
				for (k = 0, l = 0; k < o; k++) {
					int c, found, len;

					found = 0;
					for (c = 0; c < ms->num_objc; c++) {
						len = strlen(ms->ol[c].name);
						if (len == (*srch)->elements[j].values[k].length) {
							if (strncasecmp(ss->ol[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
								found = 1;
								break;
							}
						}
					}
					if (!found) {
						ms->ol[l + ms->num_objc].name = talloc_strndup(ms->ol, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
						SCHEMA_TALLOC_CHECK(ss, ms->ol[l + ms->num_objc].name, -1);
						ms->ol[l + ms->num_objc].aux = is_aux;
						l++;
					}
				}
				ms->num_objc += l;
			} else {

				if (strcasecmp((*srch)->elements[j].name, "mustContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ms->must = talloc_realloc_p(ms, ms->must, struct attr_list, ms->num_must + m);
					SCHEMA_TALLOC_CHECK(ss, ms->must, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ms->num_must; c++) {
							len  = strlen(ms->must[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ms->must[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ms->must[l + ms->num_must].name = talloc_strndup(ms->must, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ms->must[l + ms->num_must].name, -1);
							l++;
						}
					}
					ms->num_must += l;
				}

				if (strcasecmp((*srch)->elements[j].name, "mayContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMayContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ms->may = talloc_realloc_p(ms, ms->may, struct attr_list, ms->num_may + m);
					SCHEMA_TALLOC_CHECK(ss, ms->may, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ms->num_may; c++) {
							len = strlen(ms->may[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ms->may[c].name, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ms->may[l + ms->num_may].name = talloc_strndup(ms->may, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ms->may[l + ms->num_may].name, -1);
							l++;
						}
					}
					ms->num_may += l;
				}
			}
		}

		ldb_search_free(data->schema_db, srch);
	}

	/* now search for the original object objectclasses */

	ss->ol = NULL;
	ss->num_objc = 0;

	/* find all other objectclasses recursively */
	{
		char *filter = talloc_asprintf(ss, "dn=%s", msg->dn);
		const char *attrs[] = {"objectClass", NULL};

		ret = ldb_search(module->ldb, NULL, LDB_SCOPE_SUBTREE, filter, attrs, &srch);
		if (ret == 1) {
			for (i = 0; i < msg->num_elements; i++) {
				ss->num_objc = (*srch)->elements[i].num_values;
				ss->ol = talloc_array_p(ss, struct objc_list, ss->num_objc);
				SCHEMA_TALLOC_CHECK(ss, ss->ol, -1);
				for (k = 0; k < ss->num_objc; k++) {
					ss->ol[k].name = talloc_strndup(ss->ol, (*srch)->elements[i].values[k].data, (*srch)->elements[i].values[k].length);
					SCHEMA_TALLOC_CHECK(ss, ss->ol[k].name, -1);
					ss->ol[k].aux = 0;
				}
			}
			ldb_search_free(module->ldb, srch);
		} else {
			ldb_search_free(module->ldb, srch);
			return -1;
		}
	}

	ss->must = NULL;
	ss->may = NULL;
	ss->num_must = 0;
	ss->num_may = 0;
	for (i = 0; i < ss->num_objc; i++) {
		char *filter;

		filter = talloc_asprintf(ss, "lDAPDisplayName=%s", ss->ol[i].name);
		SCHEMA_TALLOC_CHECK(ss, filter, -1);
		ret = ldb_search(data->schema_db, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
		if (ret == 0) {
			int ok;

			ok = 0;
			/* suppose auxiliary classess are not required */
			if (ss->ol[i].aux) {
				int d;
				ok = 1;
				ss->num_objc -= 1;
				for (d = i; d < ss->num_objc; d++) {
					ss->ol[d] = ss->ol[d + 1];
				}
				i -= 1;
			}
			if (!ok) {
				/* Schema Violation: Object Class Description Not Found */
				data->error_string = "ObjectClass not found";
				talloc_free(ss);
				return -1;
			}
			continue;
		} else {
			if (ret < 0) {
				/* Schema DB Error: Error occurred retrieving Object Class Description */
				data->error_string = "Internal error. Error retrieving schema objectclass";
				talloc_free(ss);
				return -1;
			}
			if (ret > 1) {
				/* Schema DB Error: Too Many Records */
				data->error_string = "Internal error. Too many records searching for schema objectclass";
				talloc_free(ss);
				return -1;
			}
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in kust and may attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int o, is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (strcasecmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = 1;
				is_class = 1;
			}
			if (strcasecmp((*srch)->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				o = (*srch)->elements[j].num_values;
				ss->ol = talloc_realloc_p(ss, ss->ol, struct objc_list, ss->num_objc + o);
				SCHEMA_TALLOC_CHECK(ss, ss->ol, -1);
				for (k = 0, l = 0; k < o; k++) {
					int c, found, len;

					found = 0;
					for (c = 0; c < ss->num_objc; c++) {
						len = strlen(ss->ol[c].name);
						if (len == (*srch)->elements[j].values[k].length) {
							if (strncasecmp(ss->ol[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
								found = 1;
								break;
							}
						}
					}
					if (!found) {
						ss->ol[l + ss->num_objc].name = talloc_strndup(ss->ol, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
						SCHEMA_TALLOC_CHECK(ss, ss->ol[l + ss->num_objc].name, -1);
						ss->ol[l + ss->num_objc].aux = is_aux;
						l++;
					}
				}
				ss->num_objc += l;
			} else {

				if (strcasecmp((*srch)->elements[j].name, "mustContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ss->must = talloc_realloc_p(ss, ss->must, struct attr_list, ss->num_must + m);
					SCHEMA_TALLOC_CHECK(ss, ss->must, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ss->num_must; c++) {
							len  = strlen(ss->must[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ss->must[c].name, (*srch)->elements[j].values[k].data, len) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ss->must[l + ss->num_must].name = talloc_strndup(ss->must, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ss->must[l + ss->num_must].name, -1);
							l++;
						}
					}
					ss->num_must += l;
				}

				if (strcasecmp((*srch)->elements[j].name, "mayContain") == 0 || strcasecmp((*srch)->elements[j].name, "SystemMayContain") == 0) {
					int m;

					m = (*srch)->elements[j].num_values;

					ss->may = talloc_realloc_p(ss, ss->may, struct attr_list, ss->num_may + m);
					SCHEMA_TALLOC_CHECK(ss, ss->may, -1);
					for (k = 0, l = 0; k < m; k++) {
						int c, found, len;

						found = 0;
						for (c = 0; c < ss->num_may; c++) {
							len = strlen(ss->may[c].name);
							if (len == (*srch)->elements[j].values[k].length) {
								if (strncasecmp(ss->may[c].name, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length) == 0) {
									found = 1;
									break;
								}
							}
						}
						if (!found) {
							ss->may[l + ss->num_may].name = talloc_strndup(ss->may, (*srch)->elements[j].values[k].data, (*srch)->elements[j].values[k].length);
							SCHEMA_TALLOC_CHECK(ss, ss->may[l + ss->num_may].name, -1);
							l++;
						}
					}
					ss->num_may += l;
				}
			}
		}

		ldb_search_free(data->schema_db, srch);
	}

	/* now check all entries are present either as musts or mays of curent objectclasses */
	/* do not return errors there may be attirbutes defined in new objectclasses */
	/* just mark them as being proved valid attribs */
	for (i = 0; i < ms->num_cl; i++) {
		int found;

		found = 0;
		for (j = 0; j < ss->num_may; j++) {
			if (strcasecmp(ss->may[j].name, ms->cl[i].name) == 0) {
				ms->cl[i].check = 1;
				found = 1;
				break;
			}
		}
		if ( ! found) {
			for (j = 0; j < ss->num_must; j++) {
				if (strcasecmp(ss->must[j].name, ms->cl[i].name) == 0) {
					ms->cl[i].check = 1;
					break;
				}
			}
		}
	}

	/* now check all new objectclasses musts are present */
	for (i = 0; i < ms->num_must; i++) {
		int found;

		found = 0;
		for (j = 0; j < ms->num_cl; j++) {
			if (strcasecmp(ms->must[i].name, ms->cl[j].name) == 0) {
				ms->cl[j].check = 1;
				found = 1;
				break;
			}
		}

		if ( ! found ) {
			/* TODO: set the error string */
			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(ss);
			return -1;
		}
	}

	/* now check all others atribs are found in mays */
	for (i = 0; i < ms->num_cl; i++) {

		if ( ! ms->cl[i].check ) {
			int found;

			found = 0;
			for (j = 0; j < ms->num_may; j++) {
				if (strcasecmp(ms->may[j].name, ms->cl[i].name) == 0) {
					ms->cl[i].check = 1;
					found = 1;
					break;
				}
			}

			if ( ! found ) {
				data->error_string = "Objectclass violation, an invalid attribute name was found";
				talloc_free(ss);
				return -1;
			}
		}
	}

	talloc_free(ss);

	return ldb_next_modify_record(module, msg);
}

/* delete_record */
static int schema_delete_record(struct ldb_module *module, const char *dn)
{
	struct private_data *data = (struct private_data *)module->private_data;
	return ldb_next_delete_record(module, dn);
}

/* rename_record */
static int schema_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	return ldb_next_rename_record(module, olddn, newdn);
}

static int schema_named_lock(struct ldb_module *module, const char *name) {
	return ldb_next_named_lock(module, name);
}

static int schema_named_unlock(struct ldb_module *module, const char *name) {
	return ldb_next_named_unlock(module, name);
}

/* return extended error information */
static const char *schema_errstring(struct ldb_module *module)
{
	struct private_data *data = (struct private_data *)module->private_data;

	if (data->error_string) {
		const char *error;

		error = data->error_string;
		data->error_string = NULL;
		return error;
	}

	return ldb_next_errstring(module);
}

static const struct ldb_module_ops schema_ops = {
	"schema",
	schema_close, 
	schema_search,
	schema_search_free,
	schema_add_record,
	schema_modify_record,
	schema_delete_record,
	schema_rename_record,
	schema_named_lock,
	schema_named_unlock,
	schema_errstring,
};

#define SCHEMA_PREFIX		"schema:"
#define SCHEMA_PREFIX_LEN	7

#ifdef HAVE_DLOPEN_DISABLED
struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *schema_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;
	struct private_data *data;
	char *db_url = NULL;
	int i;

	ctx = talloc_p(ldb, struct ldb_module);
	if (!ctx) {
		return NULL;
	}

	if (options) {
		for (i = 0; options[i] != NULL; i++) {
			if (strncmp(options[i], SCHEMA_PREFIX, SCHEMA_PREFIX_LEN) == 0) {
				db_url = talloc_strdup(ctx, &options[i][SCHEMA_PREFIX_LEN]);
				SCHEMA_TALLOC_CHECK(ctx, db_url, NULL);
			}
		}
	}

	if (!db_url) { /* search if it is defined in the calling ldb */
		int ret;
		const char * attrs[] = { "@SCHEMADB", NULL };
		struct ldb_message **msgs;

		ret = ldb_search(ldb, "", LDB_SCOPE_BASE, "dn=@MODULES", (const char * const *)attrs, &msgs);
		if (ret == 0) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "Schema DB not found\n");
			ldb_search_free(ldb, msgs);
			return NULL;
		} else {
			if (ret < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for schema db, bailing out!\n", ldb_errstring(ldb));
				ldb_search_free(ldb, msgs);
				return NULL;
			}
			if (ret > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found, bailing out\n");
				ldb_search_free(ldb, msgs);
				return NULL;
			}

			db_url = talloc_strndup(ctx, msgs[0]->elements[0].values[0].data, msgs[0]->elements[0].values[0].length);
			SCHEMA_TALLOC_CHECK(ctx, db_url, NULL);
		}

		ldb_search_free(ldb, msgs);
	}

	data = talloc_p(ctx, struct private_data);
	SCHEMA_TALLOC_CHECK(ctx, data, NULL);

	data->schema_db = ldb_connect(db_url, 0, NULL); 
	SCHEMA_TALLOC_CHECK(ctx, data->schema_db, NULL);

	data->error_string = NULL;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &schema_ops;

	return ctx;
}

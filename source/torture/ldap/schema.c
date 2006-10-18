/* 
   Unix SMB/CIFS mplementation.
   LDAP schema tests
   
   Copyright (C) Stefan Metzmacher 2006
    
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
#include "libcli/ldap/ldap_client.h"
#include "lib/cmdline/popt_common.h"
#include "db_wrap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"

#include "torture/torture.h"
#include "torture/ldap/proto.h"

struct dsdb_attribute {
	struct dsdb_attribute *prev, *next;

	const char *lDAPDisplayName;
	const char *attributeID;
	uint32_t attID;
	struct GUID schemaIDGUID;

	uint32_t searchFlags;
	BOOL systemOnly;
	uint32_t systemFlags;
	BOOL isMemberOfPartialAttributeSet;

	const char *attributeSyntax;
	uint32_t oMSyntax;

	BOOL isSingleValued;
	uint32_t rangeLower;
	uint32_t rangeUpper;

	BOOL showInAdvancedViewOnly;
	const char *adminDisplayName;
	const char *adminDescription;
};

struct dsdb_objectClass {
	struct dsdb_objectClass *prev, *next;

	const char *subClassOf;

	const char *governsID;
	const char *rDNAttID;

	BOOL showInAdvancedViewOnly;
	const char *adminDisplayName;
	const char *adminDescription;

	uint32_t objectClassCategory;
	const char *lDAPDisplayName;

	struct GUID schemaIDGUID;

	BOOL systemOnly;

	const char **systemPossSuperiors;
	const char **systemMayContain;

	const char **possSuperiors;
	const char **mayContain;

	const char *defaultSecurityDescriptor;

	uint32_t systemFlags;
	BOOL defaultHidingValue;

	const char *defaultObjectCategory;
};

struct dsdb_schema {
	struct dsdb_attribute *attributes;
	struct dsdb_objectClass *objectClasses;
};

struct test_rootDSE {
	const char *defaultdn;
	const char *rootdn;
	const char *configdn;
	const char *schemadn;
};

struct test_schema_ctx {
	struct ldb_paged_control *ctrl;
	uint32_t count;
	BOOL pending;

	int (*callback)(void *, struct ldb_context *ldb, struct ldb_message *);
	void *private_data;
};

static BOOL test_search_rootDSE(struct ldb_context *ldb, struct test_rootDSE *root)
{
	int ret;
	struct ldb_message *msg;
	struct ldb_result *r;

	d_printf("Testing RootDSE Search\n");

	ret = ldb_search(ldb, ldb_dn_new(ldb), LDB_SCOPE_BASE, 
			 NULL, NULL, &r);
	if (ret != LDB_SUCCESS) {
		return False;
	} else if (r->count != 1) {
		talloc_free(r);
		return False;
	}

	msg = r->msgs[0];

	root->defaultdn	= ldb_msg_find_attr_as_string(msg, "defaultNamingContext", NULL);
	talloc_steal(ldb, root->defaultdn);
	root->rootdn	= ldb_msg_find_attr_as_string(msg, "rootDomainNamingContext", NULL);
	talloc_steal(ldb, root->rootdn);
	root->configdn	= ldb_msg_find_attr_as_string(msg, "configurationNamingContext", NULL);
	talloc_steal(ldb, root->configdn);
	root->schemadn	= ldb_msg_find_attr_as_string(msg, "schemaNamingContext", NULL);
	talloc_steal(ldb, root->schemadn);

	talloc_free(r);

	return True;
}

static int test_schema_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct test_schema_ctx *actx = talloc_get_type(context, struct test_schema_ctx);
	int ret = LDB_SUCCESS;

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		actx->count++;
		ret = actx->callback(actx->private_data, ldb, ares->message);
		break;

	case LDB_REPLY_REFERRAL:
		break;

	case LDB_REPLY_DONE:
		if (ares->controls) {
			struct ldb_paged_control *ctrl = NULL;
			int i;

			for (i=0; ares->controls[i]; i++) {
				if (strcmp(LDB_CONTROL_PAGED_RESULTS_OID, ares->controls[i]->oid) == 0) {
					ctrl = talloc_get_type(ares->controls[i]->data, struct ldb_paged_control);
					break;
				}
			}

			if (!ctrl) break;

			talloc_free(actx->ctrl->cookie);
			actx->ctrl->cookie = talloc_steal(actx->ctrl->cookie, ctrl->cookie);
			actx->ctrl->cookie_len = ctrl->cookie_len;

			if (actx->ctrl->cookie_len > 0) {
				actx->pending = True;
			}
		}
		break;
		
	default:
		d_printf("%s: unknown Reply Type %u\n", __location__, ares->type);
		return LDB_ERR_OTHER;
	}

	if (talloc_free(ares) == -1) {
		d_printf("talloc_free failed\n");
		actx->pending = 0;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ret) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return LDB_SUCCESS;
}

static BOOL test_create_schema_type(struct ldb_context *ldb, struct test_rootDSE *root,
				    const char *filter,
				    int (*callback)(void *, struct ldb_context *ldb, struct ldb_message *),
				    void *private_data)
{
	struct ldb_control **ctrl;
	struct ldb_paged_control *control;
	struct ldb_request *req;
	int ret;
	struct test_schema_ctx *actx;

	req = talloc(ldb, struct ldb_request);
	actx = talloc(req, struct test_schema_ctx);

	ctrl = talloc_array(req, struct ldb_control *, 2);
	ctrl[0] = talloc(ctrl, struct ldb_control);
	ctrl[0]->oid = LDB_CONTROL_PAGED_RESULTS_OID;
	ctrl[0]->critical = True;
	control = talloc(ctrl[0], struct ldb_paged_control);
	control->size = 1000;
	control->cookie = NULL;
	control->cookie_len = 0;
	ctrl[0]->data = control;
	ctrl[1] = NULL;

	req->operation = LDB_SEARCH;
	req->op.search.base = ldb_dn_explode(req, root->schemadn);
	req->op.search.scope = LDB_SCOPE_SUBTREE;
	req->op.search.tree = ldb_parse_tree(req, filter);
	if (req->op.search.tree == NULL) return -1;
	req->op.search.attrs = NULL;
	req->controls = ctrl;
	req->context = actx;
	req->callback = test_schema_search_callback;
	ldb_set_timeout(ldb, req, 0);

	actx->count		= 0;
	actx->ctrl		= control;
	actx->callback		= callback;
	actx->private_data	= private_data;
again:
	actx->pending		= False;

	ret = ldb_request(ldb, req);
	if (ret != LDB_SUCCESS) {
		d_printf("search failed - %s\n", ldb_errstring(ldb));
		return False;
	}

	ret = ldb_wait(req->handle, LDB_WAIT_ALL);
       	if (ret != LDB_SUCCESS) {
		d_printf("search error - %s\n", ldb_errstring(ldb));
		return False;
	}

	if (actx->pending)
		goto again;

	d_printf("filter[%s] count[%u]\n", filter, actx->count);
	return True;
}

#define GET_STRING(p, elem, strict) do { \
	(p)->elem = samdb_result_string(msg, #elem, NULL);\
	if (strict && (p)->elem == NULL) { \
		d_printf("%s: %s == NULL\n", __location__, #elem); \
		goto failed; \
	} \
	(void)talloc_steal(p, (p)->elem); \
} while (0)

#define GET_BOOL(p, elem, strict) do { \
	const char *str; \
	str = samdb_result_string(msg, #elem, NULL);\
	if (str == NULL) { \
		if (strict) { \
			d_printf("%s: %s == NULL\n", __location__, #elem); \
			goto failed; \
		} else { \
			(p)->elem = False; \
		} \
	} else if (strcasecmp("TRUE", str) == 0) { \
		(p)->elem = True; \
	} else if (strcasecmp("FALSE", str) == 0) { \
		(p)->elem = False; \
	} else { \
		d_printf("%s: %s == %s\n", __location__, #elem, str); \
		goto failed; \
	} \
} while (0)

#define GET_UINT32(p, elem) do { \
	(p)->elem = samdb_result_uint(msg, #elem, 0);\
} while (0)

#define GET_GUID(p, elem) do { \
	(p)->elem = samdb_result_guid(msg, #elem);\
} while (0)

static int test_add_attribute(void *ptr, struct ldb_context *ldb, struct ldb_message *msg)
{
	struct dsdb_schema *schema = talloc_get_type(ptr, struct dsdb_schema);
	struct dsdb_attribute *attr;

	attr = talloc_zero(schema, struct dsdb_attribute);

	GET_STRING(attr, lDAPDisplayName, True);
	GET_STRING(attr, attributeID, True);
	attr->attID = UINT32_MAX;
	GET_GUID(attr, schemaIDGUID);

	GET_UINT32(attr, searchFlags);
	GET_BOOL(attr, systemOnly, False);
	GET_UINT32(attr, systemFlags);
	GET_BOOL(attr, isMemberOfPartialAttributeSet, False);

	GET_STRING(attr, attributeSyntax, True);
	GET_UINT32(attr, oMSyntax);

	GET_BOOL(attr, isSingleValued, True);
	GET_UINT32(attr, rangeLower);
	GET_UINT32(attr, rangeUpper);

	GET_BOOL(attr, showInAdvancedViewOnly, False);
	GET_STRING(attr, adminDisplayName, True);
	GET_STRING(attr, adminDescription, True);

	DLIST_ADD_END(schema->attributes, attr, struct dsdb_attribute *);
	return LDB_SUCCESS;
failed:
	return LDB_ERR_OTHER;
}

static int test_add_class(void *ptr, struct ldb_context *ldb, struct ldb_message *msg)
{
	struct dsdb_schema *schema = talloc_get_type(ptr, struct dsdb_schema);
	struct dsdb_objectClass *obj;

	obj = talloc_zero(schema, struct dsdb_objectClass);

	GET_STRING(obj, subClassOf, True);

	GET_STRING(obj, governsID, True);
	GET_STRING(obj, rDNAttID, True);

	GET_BOOL(obj, showInAdvancedViewOnly, False);
	GET_STRING(obj, adminDisplayName, True);
	GET_STRING(obj, adminDescription, True);

	GET_UINT32(obj, objectClassCategory);
	GET_STRING(obj, lDAPDisplayName, True);

	GET_GUID(obj, schemaIDGUID);

	GET_BOOL(obj, systemOnly, False);

	obj->systemPossSuperiors= NULL;
	obj->systemMayContain	= NULL;

	obj->possSuperiors	= NULL;
	obj->mayContain		= NULL;

	GET_STRING(obj, defaultSecurityDescriptor, False);

	GET_UINT32(obj, systemFlags);
	GET_BOOL(obj, defaultHidingValue, True);

	GET_STRING(obj, defaultObjectCategory, True);

	DLIST_ADD_END(schema->objectClasses, obj, struct dsdb_objectClass *);
	return LDB_SUCCESS;
failed:
	return LDB_ERR_OTHER;
}

static BOOL test_create_schema(struct ldb_context *ldb, struct test_rootDSE *root, struct dsdb_schema **_schema)
{
	BOOL ret = True;
	struct dsdb_schema *schema;

	schema = talloc_zero(ldb, struct dsdb_schema);

	d_printf("Fetching attributes...\n");
	ret &= test_create_schema_type(ldb, root, "(objectClass=attributeSchema)",
				       test_add_attribute, schema);
	d_printf("Fetching objectClasses...\n");
	ret &= test_create_schema_type(ldb, root, "(objectClass=classSchema)",
				       test_add_class, schema);

	if (ret == True) {
		*_schema = schema;
	}
	return ret;
}

static BOOL test_dump_not_replicated(struct ldb_context *ldb, struct test_rootDSE *root, struct dsdb_schema *schema)
{
	struct dsdb_attribute *a;
	uint32_t a_i = 1;

	d_printf("Dumping not replicated attributes\n");

	for (a=schema->attributes; a; a = a->next) {
		if (!(a->systemFlags & 0x00000001)) continue;
		d_printf("attr[%4u]: '%s'\n", a_i++,
			 a->lDAPDisplayName);
	}

	return True;
}

static BOOL test_dump_partial(struct ldb_context *ldb, struct test_rootDSE *root, struct dsdb_schema *schema)
{
	struct dsdb_attribute *a;
	uint32_t a_i = 1;

	d_printf("Dumping attributes which are provided by the global catalog\n");

	for (a=schema->attributes; a; a = a->next) {
		if (!(a->systemFlags & 0x00000002) && !a->isMemberOfPartialAttributeSet) continue;
		d_printf("attr[%4u]:  %u %u '%s'\n", a_i++,
			 a->systemFlags & 0x00000002, a->isMemberOfPartialAttributeSet,
			 a->lDAPDisplayName);
	}

	return True;
}

static BOOL test_dump_contructed(struct ldb_context *ldb, struct test_rootDSE *root, struct dsdb_schema *schema)
{
	struct dsdb_attribute *a;
	uint32_t a_i = 1;

	d_printf("Dumping constructed attributes\n");

	for (a=schema->attributes; a; a = a->next) {
		if (!(a->systemFlags & 0x00000004)) continue;
		d_printf("attr[%4u]: '%s'\n", a_i++,
			 a->lDAPDisplayName);
	}

	return True;
}

static BOOL test_dump_sorted_syntax(struct ldb_context *ldb, struct test_rootDSE *root, struct dsdb_schema *schema)
{
	struct dsdb_attribute *a;
	uint32_t a_i = 1;
	uint32_t i;
	const char *syntaxes[] = {
		"2.5.5.0",
		"2.5.5.1",
		"2.5.5.2",
		"2.5.5.3",
		"2.5.5.4",
		"2.5.5.5",
		"2.5.5.6",
		"2.5.5.7",
		"2.5.5.8",
		"2.5.5.9",
		"2.5.5.10",
		"2.5.5.11",
		"2.5.5.12",
		"2.5.5.13",
		"2.5.5.14",
		"2.5.5.15",
		"2.5.5.16",
		"2.5.5.17"
	};

	for (i=0; i < ARRAY_SIZE(syntaxes); i++) {
		for (a=schema->attributes; a; a = a->next) {
			if (strcmp(syntaxes[i], a->attributeSyntax) != 0) continue;
			d_printf("attr[%4u]: %s %u '%s'\n", a_i++,
				 a->attributeSyntax, a->oMSyntax,
				 a->lDAPDisplayName);
		}
	}

	return True;
}

BOOL torture_ldap_schema(struct torture_context *torture)
{
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *host = torture_setting_string(torture, "host", NULL);
	char *url;
	struct test_rootDSE rootDSE;
	struct dsdb_schema *schema = NULL;

	mem_ctx = talloc_init("torture_ldap_basic");
	ZERO_STRUCT(rootDSE);

	url = talloc_asprintf(mem_ctx, "ldap://%s/", host);

	ldb = ldb_wrap_connect(mem_ctx, url,
			       NULL,
			       cmdline_credentials,
			       0, NULL);
	if (!ldb) goto failed;

	ret &= test_search_rootDSE(ldb, &rootDSE);
	if (!ret) goto failed;
	ret &= test_create_schema(ldb, &rootDSE, &schema);
	if (!ret) goto failed;

	ret &= test_dump_not_replicated(ldb, &rootDSE, schema);
	ret &= test_dump_partial(ldb, &rootDSE, schema);
	ret &= test_dump_contructed(ldb, &rootDSE, schema);
	ret &= test_dump_sorted_syntax(ldb, &rootDSE, schema);

failed:
	talloc_free(mem_ctx);
	return ret;
}

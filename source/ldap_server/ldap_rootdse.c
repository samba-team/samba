/* 
   Unix SMB/CIFS implementation.
   LDAP server ROOT DSE
   Copyright (C) Stefan Metzmacher 2004
   
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
#include "dynconfig.h"
#include "ldap_server/ldap_server.h"
#include "system/time.h"
#include "lib/ldb/include/ldb.h"

#define ATTR_BLOB_CONST(val) data_blob_talloc(mem_ctx, val, sizeof(val)-1)
#define ATTR_SINGLE_NOVAL(ctx, attr, blob, num, nam) do { \
	attr->name = talloc_strdup(ctx, nam);\
	if (!attr->name) {\
		return NT_STATUS_NO_MEMORY;\
	}\
	attr->num_values = num; \
	attr->values = blob;\
} while(0)
#define ALLOC_CHECK(ptr) do {\
	if (!(ptr)) {\
		return NT_STATUS_NO_MEMORY;\
	}\
} while(0)


struct rootdse_db_context {
	struct ldb_context *ldb;
	struct rootdse_db_context **static_ptr;
};

/*
  this is used to catch debug messages from ldb
*/
static void rootdse_db_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0);
static void rootdse_db_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap)
{
	char *s = NULL;
	if (DEBUGLEVEL < 4 && level > LDB_DEBUG_WARNING) {
		return;
	}
	vasprintf(&s, fmt, ap);
	if (!s) return;
	DEBUG(level, ("rootdse: %s\n", s));
	free(s);
}


/* destroy the last connection to the sam */
static int rootdse_db_destructor(void *ctx)
{
	struct rootdse_db_context *rd_ctx = ctx;
	ldb_close(rd_ctx->ldb);
	*(rd_ctx->static_ptr) = NULL;
	return 0;
}				 

/*
  connect to the SAM database
  return an opaque context pointer on success, or NULL on failure
 */
static void *rootdse_db_connect(TALLOC_CTX *mem_ctx)
{
	static struct rootdse_db_context *ctx;
	char *db_path;
	/*
	  the way that unix fcntl locking works forces us to have a
	  static ldb handle here rather than a much more sensible
	  approach of having the ldb handle as part of the
	  ldap base structures. Otherwise we would try to open
	  the ldb more than once, and tdb would rightly refuse the
	  second open due to the broken nature of unix locking.
	*/
	if (ctx != NULL) {
		return talloc_reference(mem_ctx, ctx);
	}

	ctx = talloc_p(mem_ctx, struct rootdse_db_context);
	if (ctx == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ctx->static_ptr = &ctx;

	db_path = talloc_asprintf(ctx, "tdb://%s/rootdse.ldb", dyn_PRIVATE_DIR);
	if (db_path == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	DEBUG(10, ("opening %s\n", db_path));
	ctx->ldb = ldb_connect(db_path, 0, NULL);
	if (ctx->ldb == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	talloc_set_destructor(ctx, rootdse_db_destructor);
	ldb_set_debug(ctx->ldb, rootdse_db_debug, NULL);

	return ctx;
}


static NTSTATUS fill_dynamic_values(void *mem_ctx, struct ldap_attribute *attrs)
{
	/* 
	 * currentTime
	 * 20040918090350.0Z
	 */

	DEBUG(10, ("fill_dynamic_values for %s\n", attrs[0].name));

	if (strcasecmp(attrs->name, "currentTime") == 0)
	{
		int num_currentTime = 1;
		DATA_BLOB *currentTime = talloc_array_p(mem_ctx, DATA_BLOB, num_currentTime);
		char *str = ldap_timestring(mem_ctx, time(NULL));
		ALLOC_CHECK(str);
		currentTime[0].data = (uint8_t *)str;
		currentTime[0].length = strlen(str);
		ATTR_SINGLE_NOVAL(mem_ctx, attrs, currentTime, num_currentTime, "currentTime");
		return NT_STATUS_OK;
	}

	/* 
	 * subschemaSubentry 
	 * CN=Aggregate,CN=Schema,CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * dsServiceName
	 * CN=NTDS Settings,CN=NETBIOSNAME,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * namingContexts
	 * DC=DOM,DC=TLD
	 * CN=Configuration,DC=DOM,DC=TLD
	 * CN=Schema,CN=Configuration,DC=DOM,DC=TLD
	 * DC=DomainDnsZones,DC=DOM,DC=TLD
	 * DC=ForestDnsZones,DC=DOM,DC=TLD
	 */

	/* 
	 * defaultNamingContext
	 * DC=DOM,DC=TLD
	 */

	/* 
	 * schemaNamingContext
	 * CN=Schema,CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * configurationNamingContext
	 * CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * rootDomainNamingContext
	 * DC=DOM,DC=TLD
	 */

	/* 
	 * supportedControl
	 * 1.2.840.113556.1.4.319
	 * 1.2.840.113556.1.4.801
	 * 1.2.840.113556.1.4.473
	 * 1.2.840.113556.1.4.528
	 * 1.2.840.113556.1.4.417
	 * 1.2.840.113556.1.4.619
	 * 1.2.840.113556.1.4.841
	 * 1.2.840.113556.1.4.529
	 * 1.2.840.113556.1.4.805
	 * 1.2.840.113556.1.4.521
	 * 1.2.840.113556.1.4.970
	 * 1.2.840.113556.1.4.1338
	 * 1.2.840.113556.1.4.474
	 * 1.2.840.113556.1.4.1339
	 * 1.2.840.113556.1.4.1340
	 * 1.2.840.113556.1.4.1413
	 * 2.16.840.1.113730.3.4.9
	 * 2.16.840.1.113730.3.4.10
	 * 1.2.840.113556.1.4.1504
	 * 1.2.840.113556.1.4.1852
	 * 1.2.840.113556.1.4.802
	 */

	/* 
	 * supportedLDAPVersion 
	 * 3
	 * 2
	 */
	if (strcasecmp(attrs->name, "supportedLDAPVersion") == 0)
	{
		int num_supportedLDAPVersion = 1;
		DATA_BLOB *supportedLDAPVersion = talloc_array_p(mem_ctx, DATA_BLOB, num_supportedLDAPVersion);
		supportedLDAPVersion[0] = ATTR_BLOB_CONST("3");
		ATTR_SINGLE_NOVAL(mem_ctx, attrs, supportedLDAPVersion, num_supportedLDAPVersion, "supportedLDAPVersion");
		return NT_STATUS_OK;
	}

	/* 
	 * supportedLDAPPolicies
	 * MaxPoolThreads
	 * MaxDatagramRecv
	 * MaxReceiveBuffer
	 * InitRecvTimeout
	 * MaxConnections
	 * MaxConnIdleTime
	 * MaxPageSize
	 * MaxQueryDuration
	 * MaxTempTableSize
	 * MaxResultSetSize
	 * MaxNotificationPerConn
	 * MaxValRange
	 */

	/* 
	 * highestCommittedUSN 
	 * 4555
	 */

	/* 
	 * supportedSASLMechanisms
	 * GSSAPI
	 * GSS-SPNEGO
	 * EXTERNAL
	 * DIGEST-MD5
	 */

	/* 
	 * dnsHostName
	 * netbiosname.dom.tld
	 */

	/* 
	 * ldapServiceName
	 * dom.tld:netbiosname$@DOM.TLD
	 */

	/* 
	 * serverName:
	 * CN=NETBIOSNAME,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * supportedCapabilities
	 * 1.2.840.113556.1.4.800
	 * 1.2.840.113556.1.4.1670
	 * 1.2.840.113556.1.4.1791
	 */

	/* 
	 * isSynchronized:
	 * TRUE/FALSE
	 */

	/* 
	 * isGlobalCatalogReady
	 * TRUE/FALSE
	 */

	/* 
	 * domainFunctionality
	 * 0
	 */

	/* 
	 * forestFunctionality
	 * 0
	 */

	/* 
	 * domainControllerFunctionality
	 * 2
	 */

	{
		DATA_BLOB *x = talloc_array_p(mem_ctx, DATA_BLOB, 1);
		x[0] = ATTR_BLOB_CONST("0");
		ATTR_SINGLE_NOVAL(mem_ctx, attrs, x, 1, attrs->name);
	}
	return NT_STATUS_OK;
}

static NTSTATUS rootdse_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	NTSTATUS status;
	void *local_ctx;
	struct ldap_SearchResEntry *ent;
	struct ldap_Result *done;
	struct ldb_message **res;
	int result = LDAP_SUCCESS;
	struct ldapsrv_reply *ent_r, *done_r;
	struct	rootdse_db_context *rootdsedb;
	const char *errstr = NULL;
	int count, j, y;
	const char **attrs = NULL;

	if (r->scope != LDAP_SEARCH_SCOPE_BASE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	local_ctx = talloc_named(call, 0, "rootdse_Search local memory context");
	ALLOC_CHECK(local_ctx);

	rootdsedb = rootdse_db_connect(local_ctx);
	ALLOC_CHECK(rootdsedb);

	if (r->num_attributes >= 1) {
		attrs = talloc_array_p(rootdsedb, const char *, r->num_attributes+1);
		ALLOC_CHECK(attrs);

		for (j=0; j < r->num_attributes; j++) {
			DEBUG(10,("rootDSE_Search: attrs: [%s]\n",r->attributes[j]));
			attrs[j] = r->attributes[j];
		}
		attrs[j] = NULL;
	}

	ldb_set_alloc(rootdsedb->ldb, talloc_realloc_fn, rootdsedb);
	count = ldb_search(rootdsedb->ldb, "", 0, "dn=cn=rootDSE", attrs, &res);

	if (count == 1) {
		ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
		ALLOC_CHECK(ent_r);

		ent = &ent_r->msg.r.SearchResultEntry;
		ent->dn = "";
		ent->num_attributes = 0;
		ent->attributes = NULL;
		if (res[0]->num_elements == 0) {
			goto queue_reply;
		}
		ent->num_attributes = res[0]->num_elements;
		ent->attributes = talloc_array_p(ent_r, struct ldap_attribute, ent->num_attributes);
		ALLOC_CHECK(ent->attributes);
		for (j=0; j < ent->num_attributes; j++) {
			ent->attributes[j].name = talloc_steal(ent->attributes, res[0]->elements[j].name);
			ent->attributes[j].num_values = 0;
			ent->attributes[j].values = NULL;
			ent->attributes[j].num_values = res[0]->elements[j].num_values;
			if (ent->attributes[j].num_values == 1 &&
				strncmp(res[0]->elements[j].values[0].data, "_DYNAMIC_", 9) == 0) {
				status = fill_dynamic_values(ent->attributes, &(ent->attributes[j]));
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			} else {
				ent->attributes[j].values = talloc_array_p(ent->attributes,
								DATA_BLOB, ent->attributes[j].num_values);
				ALLOC_CHECK(ent->attributes[j].values);
				for (y=0; y < ent->attributes[j].num_values; y++) {
					ent->attributes[j].values[y].length = res[0]->elements[j].values[y].length;
					ent->attributes[j].values[y].data = talloc_steal(ent->attributes[j].values,
										res[0]->elements[j].values[y].data);
				}
			}
		}
queue_reply:
		status = ldapsrv_queue_reply(call, ent_r);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	ALLOC_CHECK(done_r);

	if (count == 1) {
		DEBUG(10,("rootdse_Search: results: [%d]\n",count));
		result = LDAP_SUCCESS;
		errstr = NULL;
	} else if (count == 0) {
		DEBUG(10,("rootdse_Search: no results\n"));
		result = LDAP_NO_SUCH_OBJECT;
		errstr = ldb_errstring(rootdsedb->ldb);
	} else if (count > 1) {
		DEBUG(10,("rootdse_Search: too many results[%d]\n", count));
		result = LDAP_OTHER; 
		errstr = "internal error";	
	} else if (count == -1) {
		DEBUG(10,("rootdse_Search: error\n"));
		result = LDAP_OTHER;
		errstr = ldb_errstring(rootdsedb->ldb);
	}

	done = &done_r->msg.r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r,errstr):NULL);;
	done->referral = NULL;

	talloc_free(local_ctx);

	return ldapsrv_queue_reply(call, done_r);
}

static const struct ldapsrv_partition_ops rootdse_ops = {
	.Search		= rootdse_Search
};

const struct ldapsrv_partition_ops *ldapsrv_get_rootdse_partition_ops(void)
{
	return &rootdse_ops;
}

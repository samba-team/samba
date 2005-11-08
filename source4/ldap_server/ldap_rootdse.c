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
#include "ldap_server/ldap_server.h"
#include "system/time.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"

#define ATTR_BLOB_CONST(val) data_blob_talloc(mem_ctx, val, sizeof(val)-1)

#define ATTR_SINGLE_NOVAL(ctx, attr, blob, num, nam) do { \
	attr->name = talloc_strdup(ctx, nam);\
	NT_STATUS_HAVE_NO_MEMORY(attr->name);\
	attr->num_values = num; \
	attr->values = blob;\
} while(0)

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


/*
  connect to the SAM database
 */
NTSTATUS rootdse_Init(struct ldapsrv_partition *partition, struct ldapsrv_connection *conn)
{
	char *db_path;
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx = talloc_new(partition);

	db_path = talloc_asprintf(mem_ctx, "tdb://%s", 
				  private_path(mem_ctx, "rootdse.ldb"));
	if (db_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ldb = ldb_wrap_connect(mem_ctx, db_path, 0, NULL);
	if (ldb == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ldb_set_debug(ldb, rootdse_db_debug, NULL);

	talloc_steal(partition, ldb);
	partition->private = ldb;
	return NT_STATUS_OK;
}


static NTSTATUS fill_dynamic_values(void *mem_ctx, struct ldb_message_element *attrs)
{
	/* 
	 * currentTime
	 * 20040918090350.0Z
	 */

	DEBUG(10, ("fill_dynamic_values for %s\n", attrs[0].name));

	if (strcasecmp(attrs->name, "currentTime") == 0)
	{
		int num_currentTime = 1;
		DATA_BLOB *currentTime = talloc_array(mem_ctx, DATA_BLOB, num_currentTime);
		char *str = ldb_timestring(mem_ctx, time(NULL));
		NT_STATUS_HAVE_NO_MEMORY(str);
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
		DATA_BLOB *supportedLDAPVersion = talloc_array(mem_ctx, DATA_BLOB, num_supportedLDAPVersion);
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
		DATA_BLOB *x = talloc_array(mem_ctx, DATA_BLOB, 1);
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
	struct ldb_result *res = NULL;
	int result = LDAP_SUCCESS;
	struct ldapsrv_reply *ent_r, *done_r;
	struct ldb_context *ldb;
	const char *errstr = NULL;
	int ret, j;
	const char **attrs = NULL;

	if (r->scope != LDAP_SEARCH_SCOPE_BASE) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	local_ctx = talloc_named(call, 0, "rootdse_Search local memory context");
	NT_STATUS_HAVE_NO_MEMORY(local_ctx);

	ldb = talloc_get_type(partition->private, struct ldb_context);

	if (r->num_attributes >= 1) {
		attrs = talloc_array(ldb, const char *, r->num_attributes+1);
		NT_STATUS_HAVE_NO_MEMORY(attrs);

		for (j=0; j < r->num_attributes; j++) {
			DEBUG(10,("rootDSE_Search: attrs: [%s]\n",r->attributes[j]));
			attrs[j] = r->attributes[j];
		}
		attrs[j] = NULL;
	}

	ret = ldb_search(ldb, ldb_dn_explode(local_ctx, "cn=rootDSE"), 0, NULL, attrs, &res);
	talloc_steal(local_ctx, res);

	if (ret == LDB_SUCCESS && res->count == 1) {
		ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
		NT_STATUS_HAVE_NO_MEMORY(ent_r);

		ent = &ent_r->msg->r.SearchResultEntry;
		ent->dn = "";
		ent->num_attributes = 0;
		ent->attributes = NULL;
		if (res->msgs[0]->num_elements == 0) {
			goto queue_reply;
		}
		ent->num_attributes = res->msgs[0]->num_elements;
		ent->attributes = talloc_steal(ent_r, res->msgs[0]->elements);

		for (j=0; j < ent->num_attributes; j++) {
			if (ent->attributes[j].num_values == 1 &&
			    ent->attributes[j].values[0].length >= 9 &&
			    strncmp((char *)ent->attributes[j].values[0].data, "_DYNAMIC_", 9) == 0) {
				status = fill_dynamic_values(ent->attributes, &(ent->attributes[j]));
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		}
queue_reply:
		ldapsrv_queue_reply(call, ent_r);
	}

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	NT_STATUS_HAVE_NO_MEMORY(done_r);

	if (ret != LDB_SUCCESS) {
		DEBUG(10,("rootdse_Search: error\n"));
		result = LDAP_OTHER;
		errstr = ldb_errstring(ldb);
	} else if (res->count == 0) {
		DEBUG(10,("rootdse_Search: no results\n"));
		result = LDAP_NO_SUCH_OBJECT;
		errstr = ldb_errstring(ldb);
	} else if (res->count == 1) {
		DEBUG(10,("rootdse_Search: results: [%d]\n", res->count));
		result = LDAP_SUCCESS;
		errstr = NULL;
	} else if (res->count > 1) {
		DEBUG(10,("rootdse_Search: too many results[%d]\n", res->count));
		result = LDAP_OTHER; 
		errstr = "internal error";	
	}

	done = &done_r->msg->r.SearchResultDone;
	done->dn = NULL;
	done->resultcode = result;
	done->errormessage = (errstr?talloc_strdup(done_r,errstr):NULL);;
	done->referral = NULL;

	talloc_free(local_ctx);

	ldapsrv_queue_reply(call, done_r);
	return NT_STATUS_OK;
}

static const struct ldapsrv_partition_ops rootdse_ops = {
	.Init           = rootdse_Init,
	.Search		= rootdse_Search
};

const struct ldapsrv_partition_ops *ldapsrv_get_rootdse_partition_ops(void)
{
	return &rootdse_ops;
}

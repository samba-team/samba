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

#define ATTR_BLOB_CONST(val) data_blob_talloc(attrs, val, sizeof(val)-1)
#define ATTR_SINGLE_NOVAL(attr, blob, num, nam) do { \
	attr.name = talloc_strdup(attrs, nam);\
	if (!attr.name) {\
		return NT_STATUS_NO_MEMORY;\
	}\
	attr.num_values = num; \
	attr.values = blob;\
} while(0)

static NTSTATUS rootdse_Search(struct ldapsrv_partition *partition, struct ldapsrv_call *call,
				     struct ldap_SearchRequest *r)
{
	struct ldap_SearchResEntry *ent;
	struct ldap_Result *done;
	int code = 0;
	struct ldapsrv_reply *ent_r, *done_r;
	int num_attrs = 3;
	struct ldap_attribute *attrs;

	DEBUG(10, ("Root DSE: %s\n", r->filter));

	if (r->scope != LDAP_SEARCH_SCOPE_BASE) {
		code = 32; /* nosuchobject */
		goto no_base_scope;
	}

	attrs = talloc_array_p(call, struct ldap_attribute, num_attrs); 
	if (!attrs) {
		return NT_STATUS_NO_MEMORY;
	}

	/* 
	 * currentTime
	 * 20040918090350.0Z
	 */
	{
		int num_currentTime = 1;
		DATA_BLOB *currentTime = talloc_array_p(attrs, DATA_BLOB, num_currentTime);
		char *str = ldap_timestring(call, time(NULL));
		if (!str) {
			return NT_STATUS_NO_MEMORY;
		}
		currentTime[0].data = str;
		currentTime[0].length = strlen(str);
		ATTR_SINGLE_NOVAL(attrs[0], currentTime, num_currentTime, "currentTime");
	}

	/* 
	 * subschemaSubentry 
	 * CN=Aggregate,CN=Schema,CN=Configuration,DC=DOM,DC=TLD
	 */

	/* 
	 * dsServiceName
	 * CN=NTDS Settings,CN=NETBIOSNAME,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=DOM,DC=TLD
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
	{
		int num_supportedLDAPVersion = 1;
		DATA_BLOB *supportedLDAPVersion = talloc_array_p(attrs, DATA_BLOB, num_supportedLDAPVersion);
		supportedLDAPVersion[0] = ATTR_BLOB_CONST("3");
		ATTR_SINGLE_NOVAL(attrs[1], supportedLDAPVersion, num_supportedLDAPVersion, "supportedLDAPVersion");
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
	{
		int num_dnsHostName = 1;
		DATA_BLOB *dnsHostName = talloc_array_p(attrs, DATA_BLOB, num_dnsHostName);
		dnsHostName[0] = data_blob_talloc(attrs, lp_netbios_name(),strlen(lp_netbios_name()));
		ATTR_SINGLE_NOVAL(attrs[2], dnsHostName, num_dnsHostName, "dnsHostName");
	}

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


	ent_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultEntry);
	if (!ent_r) {
		return NT_STATUS_NO_MEMORY;
	}

	ent = &ent_r->msg.r.SearchResultEntry;
	ent->dn = "";
	ent->num_attributes = num_attrs;
	ent->attributes = attrs;

	ldapsrv_queue_reply(call, ent_r);

no_base_scope:

	done_r = ldapsrv_init_reply(call, LDAP_TAG_SearchResultDone);
	if (!done_r) {
		return NT_STATUS_NO_MEMORY;
	}

	done = &done_r->msg.r.SearchResultDone;
	done->resultcode = code;
	done->dn = NULL;
	done->errormessage = NULL;
	done->referral = NULL;

	return ldapsrv_queue_reply(call, done_r);
}

static const struct ldapsrv_partition_ops rootdse_ops = {
	.Search		= rootdse_Search
};

const struct ldapsrv_partition_ops *ldapsrv_get_rootdse_partition_ops(void)
{
	return &rootdse_ops;
}

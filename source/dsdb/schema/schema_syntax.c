/* 
   Unix SMB/CIFS mplementation.
   DSDB schema syntaxes
   
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
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/drsuapi.h"

static WERROR dsdb_syntax_FOOBAR_drsuapi_to_ldb(const struct dsdb_schema *schema,
						const struct dsdb_attribute *attr,
						const struct drsuapi_DsReplicaAttribute *in,
						TALLOC_CTX *mem_ctx,
						struct ldb_message_element *out)
{
	return WERR_FOOBAR;
}

static WERROR dsdb_syntax_FOOBAR_ldb_to_drsuapi(const struct dsdb_schema *schema,
						const struct dsdb_attribute *attr,
						const struct ldb_message_element *in,
						TALLOC_CTX *mem_ctx,
						struct drsuapi_DsReplicaAttribute *out)
{
	return WERR_FOOBAR;
}

#define OMOBJECTCLASS(val) { .length = sizeof(val) - 1, .data = discard_const_p(uint8_t, val) }

static const struct dsdb_syntax dsdb_syntaxes[] = {
	{
		.name			= "Boolean",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.7",
		.oMSyntax		= 1,
		.attributeSyntax_oid	= "2.5.5.8",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Integer",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.27",
		.oMSyntax		= 2,
		.attributeSyntax_oid	= "2.5.5.9",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(Octet)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.40",
		.oMSyntax		= 4,
		.attributeSyntax_oid	= "2.5.5.10",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(Sid)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.40",
		.oMSyntax		= 4,
		.attributeSyntax_oid	= "2.5.5.17",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(Object-Identifier)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.38",
		.oMSyntax		= 6,
		.attributeSyntax_oid	= "2.5.5.2",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Enumeration",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.27",
		.oMSyntax		= 10,
		.attributeSyntax_oid	= "2.5.5.9",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(Numeric)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.36",
		.oMSyntax		= 18,
		.attributeSyntax_oid	= "2.5.5.6",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(Printable)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.44",
		.oMSyntax		= 19,
		.attributeSyntax_oid	= "2.5.5.5",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(Teletex)",
		.ldap_oid		= "1.2.840.113556.1.4.905",
		.oMSyntax		= 20,
		.attributeSyntax_oid	= "2.5.5.4",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(IA5)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.26",
		.oMSyntax		= 22,
		.attributeSyntax_oid	= "2.5.5.5",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(UTC-Time)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.53",
		.oMSyntax		= 23,
		.attributeSyntax_oid	= "2.5.5.11",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(Generalized-Time)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.24",
		.oMSyntax		= 24,
		.attributeSyntax_oid	= "2.5.5.11",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "String(Case Sensitive)",
		.ldap_oid		= "1.2.840.113556.1.4.1362",
		.oMSyntax		= 27,
		.attributeSyntax_oid	= "2.5.5.3",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(Unicode)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.15",
		.oMSyntax		= 64,
		.attributeSyntax_oid	= "2.5.5.12",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Interval/LargeInteger",
		.ldap_oid		= "1.2.840.113556.1.4.906",
		.oMSyntax		= 65,
		.attributeSyntax_oid	= "2.5.5.16",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "String(NT-Sec-Desc)",
		.ldap_oid		= "1.2.840.113556.1.4.907",
		.oMSyntax		= 66,
		.attributeSyntax_oid	= "2.5.5.15",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Object(DS-DN)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.12",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2b\x0c\x02\x87\x73\x1c\x00\x85\x4a"),
		.attributeSyntax_oid	= "2.5.5.1",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Object(DN-Binary)",
		.ldap_oid		= "1.2.840.113556.1.4.903",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x0b"),
		.attributeSyntax_oid	= "2.5.5.7",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "Object(OR-Name)",
		.ldap_oid		= "1.2.840.113556.1.4.1221",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x56\x06\x01\x02\x05\x0b\x1D"),
		.attributeSyntax_oid	= "2.5.5.7",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
		.name			= "Object(Replica-Link)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.40",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x06"),
		.attributeSyntax_oid	= "2.5.5.10",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.43",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2b\x0c\x02\x87\x73\x1c\x00\x85\x5c"),
		.attributeSyntax_oid	= "2.5.5.13",
		.name			= "Object(Presentation-Address)",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "Object(Access-Point)",
		.ldap_oid		= "1.3.6.1.4.1.1466.115.121.1.2",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2b\x0c\x02\x87\x73\x1c\x00\x85\x3e"),
		.attributeSyntax_oid	= "2.5.5.14",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	},{
	/* not used in w2k3 forest */
		.name			= "Object(DN-String)",
		.ldap_oid		= "1.2.840.113556.1.4.904",
		.oMSyntax		= 127,
		.oMObjectClass		= OMOBJECTCLASS("\x2a\x86\x48\x86\xf7\x14\x01\x01\x01\x0c"),
		.attributeSyntax_oid	= "2.5.5.14",
		.drsuapi_to_ldb		= dsdb_syntax_FOOBAR_drsuapi_to_ldb,
		.ldb_to_drsuapi		= dsdb_syntax_FOOBAR_ldb_to_drsuapi,
	}
};

const struct dsdb_syntax *dsdb_syntax_for_attribute(const struct dsdb_attribute *attr)
{
	uint32_t i;

	for (i=0; i < ARRAY_SIZE(dsdb_syntaxes); i++) {
		if (attr->oMSyntax != dsdb_syntaxes[i].oMSyntax) continue;

		if (attr->oMObjectClass.length != dsdb_syntaxes[i].oMObjectClass.length) continue;

		if (attr->oMObjectClass.length) {
			int ret;
			ret = memcmp(attr->oMObjectClass.data,
				     dsdb_syntaxes[i].oMObjectClass.data,
				     attr->oMObjectClass.length);
			if (ret != 0) continue;
		}

		if (strcmp(attr->attributeSyntax_oid, dsdb_syntaxes[i].attributeSyntax_oid) != 0) continue;

		return &dsdb_syntaxes[i];
	}

	return NULL;
}

WERROR dsdb_attribute_drsuapi_to_ldb(const struct dsdb_schema *schema,
				     const struct drsuapi_DsReplicaAttribute *in,
				     TALLOC_CTX *mem_ctx,
				     struct ldb_message_element *out)
{
	const struct dsdb_attribute *sa;

	sa = dsdb_attribute_by_attributeID_id(schema, in->attid);
	if (!sa) {
		return WERR_FOOBAR;
	}

	return sa->syntax->drsuapi_to_ldb(schema, sa, in, mem_ctx, out);
}

WERROR dsdb_attribute_ldb_to_drsuapi(const struct dsdb_schema *schema,
				     const struct ldb_message_element *in,
				     TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsReplicaAttribute *out)
{
	const struct dsdb_attribute *sa;

	sa = dsdb_attribute_by_lDAPDisplayName(schema, in->name);
	if (!sa) {
		return WERR_FOOBAR;
	}

	return sa->syntax->ldb_to_drsuapi(schema, sa, in, mem_ctx, out);
}

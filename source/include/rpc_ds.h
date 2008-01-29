/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Gerald Carter			2002
      
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _RPC_DS_H /* _RPC_LSA_H */
#define _RPC_DS_H 

/* Opcodes available on PIPE_NETLOGON */

#define DS_ENUM_DOM_TRUSTS      0x28

typedef struct {
	/* static portion of structure */
	uint32		netbios_ptr;
	uint32		dns_ptr;
	uint32		flags;
	uint32		parent_index;
	uint32		trust_type;
	uint32		trust_attributes;
	uint32		sid_ptr;
	struct GUID	guid;
	
	UNISTR2		netbios_domain;
	UNISTR2		dns_domain;
	DOM_SID2	sid;

} DS_DOMAIN_TRUSTS;

struct ds_domain_trust {
	/* static portion of structure */
	uint32		flags;
	uint32		parent_index;
	uint32		trust_type;
	uint32		trust_attributes;
	struct GUID	guid;
	
	DOM_SID	sid;
	char *netbios_domain;
	char *dns_domain;
};

typedef struct {

	uint32			ptr;
	uint32			max_count;
	DS_DOMAIN_TRUSTS 	*trusts;
	
} DS_DOMAIN_TRUSTS_CTR;

/* Trust flags */

#define DS_DOMAIN_IN_FOREST           0x0001 	/* domains in the forest to which 
						   we belong; even different domain trees */
#define DS_DOMAIN_DIRECT_OUTBOUND     0x0002  	/* trusted domains */
#define DS_DOMAIN_TREE_ROOT           0x0004  	/* root of a forest */
#define DS_DOMAIN_PRIMARY             0x0008  	/* our domain */
#define DS_DOMAIN_NATIVE_MODE         0x0010  	/* native mode AD servers */
#define DS_DOMAIN_DIRECT_INBOUND      0x0020 	/* trusting domains */

/* Trust types */

#define DS_DOMAIN_TRUST_TYPE_DOWNLEVEL   0x00000001
#define DS_DOMAIN_TRUST_TYPE_UPLEVEL     0x00000002

/* Trust attributes */

#define DS_DOMAIN_TRUST_ATTRIB_NON_TRANSITIVE         0x00000001
#define DS_DOMAIN_TRUST_ATTRIB_UPLEVEL_ONLY           0x00000002            
#define DS_DOMAIN_TRUST_ATTRIB_QUARANTINED_DOMAIN     0x00000004            
#define DS_DOMAIN_TRUST_ATTRIB_FOREST_TRANSITIVE      0x00000008            
#define DS_DOMAIN_TRUST_ATTRIB_CROSS_ORG              0x00000010            
#define DS_DOMAIN_TRUST_ATTRIB_IN_FOREST              0x00000020            
#define DS_DOMAIN_TRUST_ATTRIB_EXTERNAL               0x00000040            



/* DS_Q_ENUM_DOM_TRUSTS - DsEnumerateDomainTrusts() request */
typedef struct 
{
	uint32		server_ptr;
	UNISTR2		server;
	uint32		flags;
	
} DS_Q_ENUM_DOM_TRUSTS;

/* DS_R_ENUM_DOM_TRUSTS - DsEnumerateDomainTrusts() response */
typedef struct 
{
	uint32			num_domains;
	DS_DOMAIN_TRUSTS_CTR	domains;
		
	NTSTATUS status;

} DS_R_ENUM_DOM_TRUSTS;


#endif /* _RPC_DS_H */

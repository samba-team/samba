/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1997-2000
   Copyright (C) Jean François Micouleau      1998-2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   
   
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

#ifndef _RPC_SAMR_H /* _RPC_SAMR_H */
#define _RPC_SAMR_H 

/*******************************************************************
 the following information comes from a QuickView on samsrv.dll,
 and gives an idea of exactly what is needed:
 
x SamrAddMemberToAlias
x SamrAddMemberToGroup
SamrAddMultipleMembersToAlias
x SamrChangePasswordUser
x SamrCloseHandle
x SamrConnect
x SamrCreateAliasInDomain
x SamrCreateGroupInDomain
x SamrCreateUserInDomain
? SamrDeleteAlias
SamrDeleteGroup
x SamrDeleteUser
x SamrEnumerateAliasesInDomain
SamrEnumerateDomainsInSamServer
x SamrEnumerateGroupsInDomain
x SamrEnumerateUsersInDomain
SamrGetUserDomainPasswordInformation
SamrLookupDomainInSamServer
? SamrLookupIdsInDomain
x SamrLookupNamesInDomain
x SamrOpenAlias
x SamrOpenDomain
x SamrOpenGroup
x SamrOpenUser
x SamrQueryDisplayInformation
x SamrQueryInformationAlias
SamrQueryInformationDomain
? SamrQueryInformationUser
x SamrQuerySecurityObject
SamrRemoveMemberFromAlias
SamrRemoveMemberFromForiegnDomain
SamrRemoveMemberFromGroup
SamrRemoveMultipleMembersFromAlias
x SamrSetInformationAlias
SamrSetInformationDomain
x SamrSetInformationGroup
x SamrSetInformationUser
SamrSetMemberAttributesOfGroup
SamrSetSecurityObject
SamrShutdownSamServer
SamrTestPrivateFunctionsDomain
SamrTestPrivateFunctionsUser

********************************************************************/

#define SAMR_CONNECT_ANON      0x00
#define SAMR_CLOSE_HND         0x01
#define SAMR_SET_SEC_OBJECT    0x02
#define SAMR_QUERY_SEC_OBJECT  0x03

#define SAMR_UNKNOWN_4         0x04 /* profile info? */
#define SAMR_LOOKUP_DOMAIN     0x05
#define SAMR_ENUM_DOMAINS      0x06
#define SAMR_OPEN_DOMAIN       0x07
#define SAMR_QUERY_DOMAIN_INFO 0x08
#define SAMR_SET_DOMAIN_INFO   0x09

#define SAMR_CREATE_DOM_GROUP  0x0a
#define SAMR_ENUM_DOM_GROUPS   0x0b
#define SAMR_ENUM_DOM_USERS    0x0d
#define SAMR_CREATE_DOM_ALIAS  0x0e
#define SAMR_ENUM_DOM_ALIASES  0x0f
#define SAMR_QUERY_USERALIASES 0x10

#define SAMR_LOOKUP_NAMES      0x11
#define SAMR_LOOKUP_RIDS       0x12

#define SAMR_OPEN_GROUP        0x13
#define SAMR_QUERY_GROUPINFO   0x14
#define SAMR_SET_GROUPINFO     0x15
#define SAMR_ADD_GROUPMEM      0x16
#define SAMR_DELETE_DOM_GROUP  0x17
#define SAMR_DEL_GROUPMEM      0x18
#define SAMR_QUERY_GROUPMEM    0x19
#define SAMR_UNKNOWN_1A        0x1a

#define SAMR_OPEN_ALIAS        0x1b
#define SAMR_QUERY_ALIASINFO   0x1c
#define SAMR_SET_ALIASINFO     0x1d
#define SAMR_DELETE_DOM_ALIAS  0x1e
#define SAMR_ADD_ALIASMEM      0x1f
#define SAMR_DEL_ALIASMEM      0x20
#define SAMR_QUERY_ALIASMEM    0x21

#define SAMR_OPEN_USER         0x22
#define SAMR_DELETE_DOM_USER   0x23
#define SAMR_QUERY_USERINFO    0x24
#define SAMR_SET_USERINFO2     0x25 /* this is SAMR_SET_USERINFO! */
#define SAMR_QUERY_USERGROUPS  0x27

#define SAMR_QUERY_DISPINFO    0x28
#define SAMR_GET_DISPENUM_INDEX 0x29
#define SAMR_UNKNOWN_2a        0x2a
#define SAMR_UNKNOWN_2b        0x2b
#define SAMR_GET_USRDOM_PWINFO 0x2c
#define SAMR_REMOVE_SID_FOREIGN_DOMAIN        0x2d
#define SAMR_QUERY_DOMAIN_INFO2  0x2e /* looks like an alias for SAMR_QUERY_DOMAIN_INFO */
#define SAMR_UNKNOWN_2f        0x2f
#define SAMR_QUERY_DISPINFO3   0x30 /* Alias for SAMR_QUERY_DISPINFO
				       with info level 3 */
#define SAMR_UNKNOWN_31        0x31
#define SAMR_CREATE_USER       0x32
#define SAMR_QUERY_DISPINFO4   0x33 /* Alias for SAMR_QUERY_DISPINFO
				       with info level 4 */
#define SAMR_ADDMULTI_ALIASMEM 0x34

#define SAMR_UNKNOWN_35        0x35
#define SAMR_UNKNOWN_36        0x36
#define SAMR_CHGPASSWD_USER    0x37
#define SAMR_GET_DOM_PWINFO    0x38
#define SAMR_CONNECT           0x39
#define SAMR_SET_USERINFO      0x3A /* this is SAMR_SET_USERINFO2! */
#define SAMR_CONNECT4          0x3E
#define SAMR_CHGPASSWD_USER3   0x3F
#define SAMR_CONNECT5          0x40

#define PASS_MUST_CHANGE_AT_NEXT_LOGON	0x01
#define PASS_DONT_CHANGE_AT_NEXT_LOGON	0x00

#define MAX_SAM_ENTRIES_W2K 0x400
#define MAX_SAM_ENTRIES_W95 50
/* The following should be the greater of the preceeding two. */
#define MAX_SAM_ENTRIES MAX_SAM_ENTRIES_W2K

typedef struct samr_entry_info
{
	uint32 rid;
	UNIHDR hdr_name;

} SAM_ENTRY;

/* SAMR_Q_ENUM_DOM_GROUPS - SAM rids and names */
typedef struct q_samr_enum_dom_groups_info
{
	POLICY_HND pol;          /* policy handle */

	/* this is possibly an enumeration context handle... */
	uint32 start_idx;         /* 0x0000 0000 */

	uint32 max_size;              /* 0x0000 ffff */

} SAMR_Q_ENUM_DOM_GROUPS;


/* SAMR_R_ENUM_DOM_GROUPS - SAM rids and names */
typedef struct r_samr_enum_dom_groups_info
{
	uint32 next_idx;
	uint32 ptr_entries1;

	uint32 num_entries2;
	uint32 ptr_entries2;

	uint32 num_entries3;

	SAM_ENTRY *sam;
	UNISTR2 *uni_grp_name;

	uint32 num_entries4;

	NTSTATUS status;

} SAMR_R_ENUM_DOM_GROUPS;


/* SAMR_Q_ENUM_DOM_ALIASES - SAM rids and names */
typedef struct q_samr_enum_dom_aliases_info
{
	POLICY_HND pol;          /* policy handle */

	/* this is possibly an enumeration context handle... */
	uint32 start_idx;         /* 0x0000 0000 */

	uint32 max_size;              /* 0x0000 ffff */

} SAMR_Q_ENUM_DOM_ALIASES;


/* SAMR_R_ENUM_DOM_ALIASES - SAM rids and names */
typedef struct r_samr_enum_dom_aliases_info
{
	uint32 next_idx;
	uint32 ptr_entries1;

	uint32 num_entries2;
	uint32 ptr_entries2;

	uint32 num_entries3;

	SAM_ENTRY *sam;
	UNISTR2 *uni_grp_name;

	uint32 num_entries4;

	NTSTATUS status;

} SAMR_R_ENUM_DOM_ALIASES;

/* these are from the old rpc_samr.h - they are needed while the merge
   is still going on */
#define MAX_SAM_SIDS 15

#endif /* _RPC_SAMR_H */

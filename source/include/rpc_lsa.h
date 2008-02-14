/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell               1992-1997
   Copyright (C) Luke Kenneth Casson Leighton  1996-1997
   Copyright (C) Paul Ashton                   1997
   Copyright (C) Gerald (Jerry) Carter         2005
   
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

#ifndef _RPC_LSA_H /* _RPC_LSA_H */
#define _RPC_LSA_H 

/* Opcodes available on PIPE_LSARPC */

#define LSA_CLOSE              0x00
#define LSA_DELETE             0x01
#define LSA_ENUM_PRIVS         0x02
#define LSA_QUERYSECOBJ        0x03
#define LSA_SETSECOBJ          0x04
#define LSA_CHANGEPASSWORD     0x05
#define LSA_OPENPOLICY         0x06
#define LSA_QUERYINFOPOLICY    0x07
#define LSA_SETINFOPOLICY      0x08
#define LSA_CLEARAUDITLOG      0x09
#define LSA_CREATEACCOUNT      0x0a
#define LSA_ENUM_ACCOUNTS      0x0b
#define LSA_CREATETRUSTDOM     0x0c	/* TODO: implement this one  -- jerry */
#define LSA_ENUMTRUSTDOM       0x0d
#define LSA_LOOKUPNAMES        0x0e
#define LSA_LOOKUPSIDS         0x0f
#define LSA_CREATESECRET       0x10	/* TODO: implement this one  -- jerry */
#define LSA_OPENACCOUNT	       0x11
#define LSA_ENUMPRIVSACCOUNT   0x12
#define LSA_ADDPRIVS           0x13
#define LSA_REMOVEPRIVS        0x14
#define LSA_GETQUOTAS          0x15
#define LSA_SETQUOTAS          0x16
#define LSA_GETSYSTEMACCOUNT   0x17
#define LSA_SETSYSTEMACCOUNT   0x18
#define LSA_OPENTRUSTDOM       0x19
#define LSA_QUERYTRUSTDOMINFO  0x1a
#define LSA_SETINFOTRUSTDOM    0x1b
#define LSA_OPENSECRET         0x1c	/* TODO: implement this one  -- jerry */
#define LSA_SETSECRET          0x1d	/* TODO: implement this one  -- jerry */
#define LSA_QUERYSECRET        0x1e
#define LSA_LOOKUPPRIVVALUE    0x1f
#define LSA_LOOKUPPRIVNAME     0x20
#define LSA_PRIV_GET_DISPNAME  0x21
#define LSA_DELETEOBJECT       0x22	/* TODO: implement this one  -- jerry */
#define LSA_ENUMACCTWITHRIGHT  0x23	/* TODO: implement this one  -- jerry */
#define LSA_ENUMACCTRIGHTS     0x24
#define LSA_ADDACCTRIGHTS      0x25
#define LSA_REMOVEACCTRIGHTS   0x26
#define LSA_QUERYTRUSTDOMINFOBYSID  0x27
#define LSA_SETTRUSTDOMINFO    0x28
#define LSA_DELETETRUSTDOM     0x29
#define LSA_STOREPRIVDATA      0x2a
#define LSA_RETRPRIVDATA       0x2b
#define LSA_OPENPOLICY2        0x2c
#define LSA_UNK_GET_CONNUSER   0x2d /* LsaGetConnectedCredentials ? */
#define LSA_QUERYINFO2         0x2e
#define LSA_QUERYTRUSTDOMINFOBYNAME 0x30
#define LSA_QUERYDOMINFOPOL    0x35
#define LSA_OPENTRUSTDOMBYNAME 0x37

#define LSA_LOOKUPSIDS2        0x39
#define LSA_LOOKUPNAMES2       0x3a
#define LSA_LOOKUPNAMES3       0x44
#define LSA_LOOKUPSIDS3        0x4c
#define LSA_LOOKUPNAMES4       0x4d

/* XXXX these are here to get a compile! */
#define LSA_LOOKUPRIDS      0xFD

#define LSA_AUDIT_NUM_CATEGORIES_NT4	7
#define LSA_AUDIT_NUM_CATEGORIES_WIN2K	9
#define LSA_AUDIT_NUM_CATEGORIES LSA_AUDIT_NUM_CATEGORIES_NT4

#define POLICY_VIEW_LOCAL_INFORMATION    0x00000001
#define POLICY_VIEW_AUDIT_INFORMATION    0x00000002
#define POLICY_GET_PRIVATE_INFORMATION   0x00000004
#define POLICY_TRUST_ADMIN               0x00000008
#define POLICY_CREATE_ACCOUNT            0x00000010
#define POLICY_CREATE_SECRET             0x00000020
#define POLICY_CREATE_PRIVILEGE          0x00000040
#define POLICY_SET_DEFAULT_QUOTA_LIMITS  0x00000080
#define POLICY_SET_AUDIT_REQUIREMENTS    0x00000100
#define POLICY_AUDIT_LOG_ADMIN           0x00000200
#define POLICY_SERVER_ADMIN              0x00000400
#define POLICY_LOOKUP_NAMES              0x00000800

#define POLICY_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED_ACCESS  |\
                            POLICY_VIEW_LOCAL_INFORMATION    |\
                            POLICY_VIEW_AUDIT_INFORMATION    |\
                            POLICY_GET_PRIVATE_INFORMATION   |\
                            POLICY_TRUST_ADMIN               |\
                            POLICY_CREATE_ACCOUNT            |\
                            POLICY_CREATE_SECRET             |\
                            POLICY_CREATE_PRIVILEGE          |\
                            POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            POLICY_SET_AUDIT_REQUIREMENTS    |\
                            POLICY_AUDIT_LOG_ADMIN           |\
                            POLICY_SERVER_ADMIN              |\
                            POLICY_LOOKUP_NAMES )


#define POLICY_READ       ( STANDARD_RIGHTS_READ_ACCESS      |\
                            POLICY_VIEW_AUDIT_INFORMATION    |\
                            POLICY_GET_PRIVATE_INFORMATION)

#define POLICY_WRITE      ( STD_RIGHT_READ_CONTROL_ACCESS     |\
                            POLICY_TRUST_ADMIN               |\
                            POLICY_CREATE_ACCOUNT            |\
                            POLICY_CREATE_SECRET             |\
                            POLICY_CREATE_PRIVILEGE          |\
                            POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            POLICY_SET_AUDIT_REQUIREMENTS    |\
                            POLICY_AUDIT_LOG_ADMIN           |\
                            POLICY_SERVER_ADMIN)

#define POLICY_EXECUTE    ( STANDARD_RIGHTS_EXECUTE_ACCESS   |\
                            POLICY_VIEW_LOCAL_INFORMATION    |\
                            POLICY_LOOKUP_NAMES )

/*******************************************************/

/*******************************************************/

#define MAX_REF_DOMAINS 32

/* DOM_TRUST_HDR */
typedef struct dom_trust_hdr
{
	UNIHDR hdr_dom_name; /* referenced domain unicode string headers */
	uint32 ptr_dom_sid;

} DOM_TRUST_HDR;
	
/* DOM_TRUST_INFO */
typedef struct dom_trust_info
{
	UNISTR2  uni_dom_name; /* domain name unicode string */
	DOM_SID2 ref_dom     ; /* referenced domain SID */

} DOM_TRUST_INFO;
	
/* DOM_R_REF */
typedef struct dom_ref_info
{
	uint32 num_ref_doms_1; /* num referenced domains */
	uint32 ptr_ref_dom; /* pointer to referenced domains */
	uint32 max_entries; /* 32 - max number of entries */
	uint32 num_ref_doms_2; /* num referenced domains */

	DOM_TRUST_HDR  hdr_ref_dom[MAX_REF_DOMAINS]; /* referenced domains */
	DOM_TRUST_INFO ref_dom    [MAX_REF_DOMAINS]; /* referenced domains */

} DOM_R_REF;

/* the domain_idx points to a SID associated with the name */

/* LSA_TRANS_NAME - translated name */
typedef struct lsa_trans_name_info
{
	uint16 sid_name_use; /* value is 5 for a well-known group; 2 for a domain group; 1 for a user... */
	UNIHDR hdr_name; 
	uint32 domain_idx; /* index into DOM_R_REF array of SIDs */

} LSA_TRANS_NAME;

/* LSA_TRANS_NAME2 - translated name */
typedef struct lsa_trans_name_info2
{
	uint16 sid_name_use; /* value is 5 for a well-known group; 2 for a domain group; 1 for a user... */
	UNIHDR hdr_name; 
	uint32 domain_idx; /* index into DOM_R_REF array of SIDs */
	uint32 unknown;

} LSA_TRANS_NAME2;

/* This number is based on Win2k and later maximum response allowed */
#define MAX_LOOKUP_SIDS 20480	/* 0x5000 */

/* LSA_TRANS_NAME_ENUM - LSA Translated Name Enumeration container */
typedef struct lsa_trans_name_enum_info
{
	uint32 num_entries;
	uint32 ptr_trans_names;
	uint32 num_entries2;
	
	LSA_TRANS_NAME *name; /* translated names  */
	UNISTR2 *uni_name;

} LSA_TRANS_NAME_ENUM;

/* LSA_TRANS_NAME_ENUM2 - LSA Translated Name Enumeration container 2 */
typedef struct lsa_trans_name_enum_info2
{
	uint32 num_entries;
	uint32 ptr_trans_names;
	uint32 num_entries2;
	
	LSA_TRANS_NAME2 *name; /* translated names  */
	UNISTR2 *uni_name;

} LSA_TRANS_NAME_ENUM2;

/* LSA_SID_ENUM - LSA SID enumeration container */
typedef struct lsa_sid_enum_info
{
	uint32 num_entries;
	uint32 ptr_sid_enum;
	uint32 num_entries2;
	
	uint32 *ptr_sid; /* domain SID pointers to be looked up. */
	DOM_SID2 *sid; /* domain SIDs to be looked up. */

} LSA_SID_ENUM;

/* LSA_Q_LOOKUP_SIDS - LSA Lookup SIDs */
typedef struct lsa_q_lookup_sids
{
	POLICY_HND          pol; /* policy handle */
	LSA_SID_ENUM        sids;
	LSA_TRANS_NAME_ENUM names;
	uint16              level;
	uint32              mapped_count;

} LSA_Q_LOOKUP_SIDS;

/* LSA_R_LOOKUP_SIDS - response to LSA Lookup SIDs */
typedef struct lsa_r_lookup_sids
{
	uint32              ptr_dom_ref;
	DOM_R_REF           *dom_ref; /* domain reference info */

	LSA_TRANS_NAME_ENUM names;
	uint32              mapped_count;

	NTSTATUS            status; /* return code */

} LSA_R_LOOKUP_SIDS;

/* LSA_Q_LOOKUP_SIDS2 - LSA Lookup SIDs 2*/
typedef struct lsa_q_lookup_sids2
{
	POLICY_HND          pol; /* policy handle */
	LSA_SID_ENUM        sids;
	LSA_TRANS_NAME_ENUM2 names;
	uint16              level;
	uint32              mapped_count;
	uint32              unknown1;
	uint32              unknown2;

} LSA_Q_LOOKUP_SIDS2;

/* LSA_R_LOOKUP_SIDS2 - response to LSA Lookup SIDs 2*/
typedef struct lsa_r_lookup_sids2
{
	uint32              ptr_dom_ref;
	DOM_R_REF           *dom_ref; /* domain reference info */

	LSA_TRANS_NAME_ENUM2 names;
	uint32              mapped_count;

	NTSTATUS            status; /* return code */

} LSA_R_LOOKUP_SIDS2;

/* LSA_Q_LOOKUP_SIDS3 - LSA Lookup SIDs 3 */
typedef struct lsa_q_lookup_sids3
{
	LSA_SID_ENUM        sids;
	LSA_TRANS_NAME_ENUM2 names;
	uint16              level;
	uint32              mapped_count;
	uint32              unknown1;
	uint32              unknown2;

} LSA_Q_LOOKUP_SIDS3;

/* LSA_R_LOOKUP_SIDS3 - response to LSA Lookup SIDs 3 */
typedef struct lsa_r_lookup_sids3
{
	uint32              ptr_dom_ref;
	DOM_R_REF           *dom_ref; /* domain reference info */

	LSA_TRANS_NAME_ENUM2 names;
	uint32              mapped_count;

	NTSTATUS            status; /* return code */

} LSA_R_LOOKUP_SIDS3;

/* LSA_Q_LOOKUP_NAMES - LSA Lookup NAMEs */
typedef struct lsa_q_lookup_names
{
	POLICY_HND pol; /* policy handle */
	uint32 num_entries;
	uint32 num_entries2;
	UNIHDR  *hdr_name; /* name buffer pointers */
	UNISTR2 *uni_name; /* names to be looked up */

	uint32 num_trans_entries;
	uint32 ptr_trans_sids; /* undocumented domain SID buffer pointer */
	uint16 lookup_level;
	uint32 mapped_count;

} LSA_Q_LOOKUP_NAMES;

/* LSA_R_LOOKUP_NAMES - response to LSA Lookup NAMEs by name */
typedef struct lsa_r_lookup_names
{
	uint32 ptr_dom_ref;
	DOM_R_REF *dom_ref; /* domain reference info */

	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;
	DOM_RID *dom_rid; /* domain RIDs being looked up */

	uint32 mapped_count;

	NTSTATUS status; /* return code */
} LSA_R_LOOKUP_NAMES;

/* LSA_Q_LOOKUP_NAMES2 - LSA Lookup NAMEs 2*/
typedef struct lsa_q_lookup_names2
{
	POLICY_HND pol; /* policy handle */
	uint32 num_entries;
	uint32 num_entries2;
	UNIHDR  *hdr_name; /* name buffer pointers */
	UNISTR2 *uni_name; /* names to be looked up */

	uint32 num_trans_entries;
	uint32 ptr_trans_sids; /* undocumented domain SID buffer pointer */
	uint16 lookup_level;
	uint32 mapped_count;
	uint32 unknown1;
	uint32 unknown2;

} LSA_Q_LOOKUP_NAMES2;

/* LSA_R_LOOKUP_NAMES2 - response to LSA Lookup NAMEs by name 2 */
typedef struct lsa_r_lookup_names2
{
	uint32 ptr_dom_ref;
	DOM_R_REF *dom_ref; /* domain reference info */

	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;
	DOM_RID2 *dom_rid; /* domain RIDs being looked up */

	uint32 mapped_count;

	NTSTATUS status; /* return code */
} LSA_R_LOOKUP_NAMES2;

/* LSA_Q_LOOKUP_NAMES3 - LSA Lookup NAMEs 3 */
typedef struct lsa_q_lookup_names3
{
	POLICY_HND pol; /* policy handle */
	uint32 num_entries;
	uint32 num_entries2;
	UNIHDR  *hdr_name; /* name buffer pointers */
	UNISTR2 *uni_name; /* names to be looked up */

	uint32 num_trans_entries;
	uint32 ptr_trans_sids; /* undocumented domain SID buffer pointer */
	uint16 lookup_level;
	uint32 mapped_count;
	uint32 unknown1;
	uint32 unknown2;

} LSA_Q_LOOKUP_NAMES3;

/* Sid type used in lookupnames3 and lookupnames4. */
typedef struct lsa_translatedsid3 {
	uint8 sid_type;
	DOM_SID2 *sid2;
	uint32 sid_idx;
	uint32 unknown;
} LSA_TRANSLATED_SID3;

/* LSA_R_LOOKUP_NAMES3 - response to LSA Lookup NAMEs by name 3 */
typedef struct lsa_r_lookup_names3
{
	uint32 ptr_dom_ref;
	DOM_R_REF *dom_ref; /* domain reference info */

	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;
	LSA_TRANSLATED_SID3 *trans_sids;

	uint32 mapped_count;

	NTSTATUS status; /* return code */
} LSA_R_LOOKUP_NAMES3;

/* LSA_Q_LOOKUP_NAMES4 - LSA Lookup NAMEs 4 */
typedef struct lsa_q_lookup_names4
{
	uint32 num_entries;
	uint32 num_entries2;
	UNIHDR  *hdr_name; /* name buffer pointers */
	UNISTR2 *uni_name; /* names to be looked up */

	uint32 num_trans_entries;
	uint32 ptr_trans_sids; /* undocumented domain SID buffer pointer */
	uint16 lookup_level;
	uint32 mapped_count;
	uint32 unknown1;
	uint32 unknown2;

} LSA_Q_LOOKUP_NAMES4;

/* LSA_R_LOOKUP_NAMES3 - response to LSA Lookup NAMEs by name 4 */
typedef struct lsa_r_lookup_names4
{
	uint32 ptr_dom_ref;
	DOM_R_REF *dom_ref; /* domain reference info */

	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;
	LSA_TRANSLATED_SID3 *trans_sids;

	uint32 mapped_count;

	NTSTATUS status; /* return code */
} LSA_R_LOOKUP_NAMES4;

/* LSA_Q_ENUM_ACCT_RIGHTS - LSA enum account rights */
typedef struct
{
	POLICY_HND pol; /* policy handle */
	DOM_SID2 sid;
} LSA_Q_ENUM_ACCT_RIGHTS;

/* LSA_R_ENUM_ACCT_RIGHTS - LSA enum account rights */
typedef struct
{
	uint32 count;
	UNISTR4_ARRAY *rights;
	NTSTATUS status;
} LSA_R_ENUM_ACCT_RIGHTS;


/* LSA_Q_ADD_ACCT_RIGHTS - LSA add account rights */
typedef struct
{
	POLICY_HND pol; /* policy handle */
	DOM_SID2 sid;
	uint32 count;
	UNISTR4_ARRAY *rights;
} LSA_Q_ADD_ACCT_RIGHTS;

/* LSA_R_ADD_ACCT_RIGHTS - LSA add account rights */
typedef struct
{
	NTSTATUS status;
} LSA_R_ADD_ACCT_RIGHTS;


/* LSA_Q_REMOVE_ACCT_RIGHTS - LSA remove account rights */
typedef struct
{
	POLICY_HND pol; /* policy handle */
	DOM_SID2 sid;
	uint32 removeall;
	uint32 count;
	UNISTR4_ARRAY *rights;
} LSA_Q_REMOVE_ACCT_RIGHTS;

/* LSA_R_REMOVE_ACCT_RIGHTS - LSA remove account rights */
typedef struct
{
	NTSTATUS status;
} LSA_R_REMOVE_ACCT_RIGHTS;


typedef struct {
	UNIHDR hdr;
	UNISTR2 unistring;
} LSA_STRING;

typedef struct lsa_q_addprivs
{
	POLICY_HND pol; /* policy handle */
	uint32 count;
	PRIVILEGE_SET set;
} LSA_Q_ADDPRIVS;

typedef struct lsa_r_addprivs
{
	NTSTATUS status;
} LSA_R_ADDPRIVS;


typedef struct lsa_q_removeprivs
{
	POLICY_HND pol; /* policy handle */
	uint32 allrights;
	uint32 ptr;
	uint32 count;
	PRIVILEGE_SET set;
} LSA_Q_REMOVEPRIVS;

typedef struct lsa_r_removeprivs
{
	NTSTATUS status;
} LSA_R_REMOVEPRIVS;

#endif /* _RPC_LSA_H */

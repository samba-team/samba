/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

#ifndef _RPC_LSA_H /* _RPC_LSA_H */
#define _RPC_LSA_H 

#include "rpc_misc.h"

enum SID_NAME_USE
{
	SID_NAME_USER    = 1, /* user */
	SID_NAME_DOM_GRP = 2, /* domain group */
	SID_NAME_DOMAIN  = 3, /* domain: don't know what this is */
	SID_NAME_ALIAS   = 4, /* local group */
	SID_NAME_WKN_GRP = 5, /* well-known group */
	SID_NAME_DELETED = 6, /* deleted account: needed for c2 rating */
	SID_NAME_INVALID = 7, /* invalid account */
	SID_NAME_UNKNOWN = 8  /* oops. */
};

/* LSA ACE permissions */

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

#define POLICY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED          |\
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


#define POLICY_READ       (STANDARD_RIGHTS_READ              |\
                            POLICY_VIEW_AUDIT_INFORMATION    |\
                            POLICY_GET_PRIVATE_INFORMATION)

#define POLICY_WRITE      (STANDARD_RIGHTS_WRITE             |\
                            POLICY_TRUST_ADMIN               |\
                            POLICY_CREATE_ACCOUNT            |\
                            POLICY_CREATE_SECRET             |\
                            POLICY_CREATE_PRIVILEGE          |\
                            POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            POLICY_SET_AUDIT_REQUIREMENTS    |\
                            POLICY_AUDIT_LOG_ADMIN           |\
                            POLICY_SERVER_ADMIN)

#define POLICY_EXECUTE    (STANDARD_RIGHTS_EXECUTE           |\
                            POLICY_VIEW_LOCAL_INFORMATION    |\
                            POLICY_LOOKUP_NAMES )

/* ntlsa pipe */
#define LSA_CLOSE              0x00
#define LSA_OPENPOLICY         0x06
#define LSA_QUERYINFOPOLICY    0x07
#define LSA_QUERYSECOBJECT     0x03
#define LSA_ENUMTRUSTDOM       0x0d
#define LSA_LOOKUPNAMES        0x0e
#define LSA_LOOKUPSIDS         0x0f
#define LSA_CREATESECRET       0x10
#define LSA_OPENSECRET         0x1c
#define LSA_SETSECRET          0x1d
#define LSA_QUERYSECRET        0x1e
#define LSA_OPENPOLICY2        0x2c

#define LSA_MAX_GROUPS 32
#define LSA_MAX_SIDS 32

/* DOM_QUERY - info class 3 and 5 LSA Query response */
typedef struct dom_query_info
{
  uint16 uni_dom_max_len; /* domain name string length * 2 */
  uint16 uni_dom_str_len; /* domain name string length * 2 */
  uint32 buffer_dom_name; /* undocumented domain name string buffer pointer */
  uint32 buffer_dom_sid; /* undocumented domain SID string buffer pointer */
  UNISTR2 uni_domain_name; /* domain name (unicode string) */
  DOM_SID2 dom_sid; /* domain SID */

} DOM_QUERY;

/* level 5 is same as level 3.  we hope. */
typedef DOM_QUERY DOM_QUERY_3;
typedef DOM_QUERY DOM_QUERY_5;

typedef struct seq_qos_info
{
	uint32 len; /* 12 */
	uint16 sec_imp_level; /* 0x02 - impersonation level */
	uint8  sec_ctxt_mode; /* 0x01 - context tracking mode */
	uint8  effective_only; /* 0x00 - effective only */
	uint32 unknown;        /* 0x2000 0000 - not known */

} LSA_SEC_QOS;

typedef struct obj_attr_info
{
	uint32 len;          /* 0x18 - length (in bytes) inc. the length field. */
	uint32 ptr_root_dir; /* 0 - root directory (pointer) */
	uint32 ptr_obj_name; /* 0 - object name (pointer) */
	uint32 attributes;   /* 0 - attributes (undocumented) */
	uint32 ptr_sec_desc; /* 0 - security descriptior (pointer) */
	uint32 ptr_sec_qos;  /* security quality of service */
	LSA_SEC_QOS *sec_qos;

} LSA_OBJ_ATTR;

/* LSA_Q_OPEN_POL - LSA Query Open Policy */
typedef struct lsa_q_open_pol_info
{
	uint32 ptr;         /* undocumented buffer pointer */
	uint16 system_name; /* system name BUG!!! (should be \\server!) */
	LSA_OBJ_ATTR attr ; /* object attributes */

	uint32 des_access; /* desired access attributes */

} LSA_Q_OPEN_POL;

/* LSA_R_OPEN_POL - response to LSA Open Policy */
typedef struct lsa_r_open_pol_info
{
	POLICY_HND pol; /* policy handle */
	uint32 status; /* return code */

} LSA_R_OPEN_POL;

/* LSA_Q_OPEN_POL2 - LSA Query Open Policy */
typedef struct lsa_q_open_pol2_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	LSA_OBJ_ATTR attr           ; /* object attributes */

	uint32 des_access; /* desired access attributes */

} LSA_Q_OPEN_POL2;

/* LSA_R_OPEN_POL2 - response to LSA Open Policy */
typedef struct lsa_r_open_pol2_info
{
	POLICY_HND pol; /* policy handle */
	uint32 status; /* return code */

} LSA_R_OPEN_POL2;

/* LSA_Q_QUERY_SEC_OBJ - LSA query security */
typedef struct lsa_query_sec_obj_info
{
	POLICY_HND pol; /* policy handle */
	uint32 sec_info;

} LSA_Q_QUERY_SEC_OBJ;

/* LSA_R_QUERY_SEC_OBJ - probably an open */
typedef struct r_lsa_query_sec_obj_info
{
	uint32 ptr;
	SEC_DESC_BUF buf;

	uint32 status;         /* return status */

} LSA_R_QUERY_SEC_OBJ;

/* LSA_Q_QUERY_INFO - LSA query info policy */
typedef struct lsa_query_info
{
	POLICY_HND pol; /* policy handle */
	uint8 info_class; /* info class */

} LSA_Q_QUERY_INFO;

/* LSA_R_QUERY_INFO - response to LSA query info policy */
typedef struct lsa_r_query_info
{
	uint32 undoc_buffer; /* undocumented buffer pointer */
	uint16 info_class; /* info class (same as info class in request) */
    
	union
	{
        	DOM_QUERY_3 id3;
		DOM_QUERY_5 id5;

	} dom;

	uint32 status; /* return code */

} LSA_R_QUERY_INFO;

/* LSA_Q_CREATE_SECRET - LSA Create Secret */
typedef struct lsa_q_create_secret_info
{
	POLICY_HND pol;
	UNIHDR hdr_secret;
	UNISTR2 uni_secret;

	uint32 des_access; /* desired access attributes */

} LSA_Q_CREATE_SECRET;

/* LSA_R_CREATE_SECRET - response to LSA Open Secret */
typedef struct lsa_r_create_secret_info
{
	POLICY_HND pol;
	uint32 status;

} LSA_R_CREATE_SECRET;

/* LSA_Q_OPEN_SECRET - LSA Open Secret */
typedef struct lsa_q_open_secret_info
{
	POLICY_HND pol;
	UNIHDR hdr_secret;
	UNISTR2 uni_secret;

	uint32 des_access; /* desired access attributes */

} LSA_Q_OPEN_SECRET;

/* LSA_R_OPEN_SECRET - response to LSA Open Secret */
typedef struct lsa_r_open_secret_info
{
	POLICY_HND pol;
	uint32 status;

} LSA_R_OPEN_SECRET;

typedef struct lsa_secret_value_info
{
	uint32 ptr_secret;
	STRHDR2 hdr_secret;
	STRING2 enc_secret; /* encrypted, see nt_encrypt_string2 */

} LSA_SECRET_VALUE;

typedef struct lsa_secret_info_info
{
	uint32 ptr_value;
	LSA_SECRET_VALUE value;

	uint32 ptr_update;
	NTTIME last_update; /* N.B. 64-bit alignment? */

} LSA_SECRET_INFO;

/* LSA_SECRET - LSA Secret */
typedef struct lsa_q_secret_info
{
	LSA_SECRET_INFO curinfo;
	LSA_SECRET_INFO oldinfo;

} LSA_SECRET;

/* LSA_Q_QUERY_SECRET - LSA Query Secret */
typedef struct lsa_q_query_secret_info
{
	POLICY_HND pol;

	LSA_SECRET sec;

} LSA_Q_QUERY_SECRET;

/* LSA_R_QUERY_SECRET - response to LSA Query Secret */
typedef struct lsa_r_query_secret_info
{
	LSA_SECRET sec;

	uint32 status;

} LSA_R_QUERY_SECRET;

/* LSA_Q_SET_SECRET - LSA Set Secret */
typedef struct lsa_q_set_secret_info
{
	POLICY_HND pol;

	LSA_SECRET_VALUE value;
	uint32 unknown;

} LSA_Q_SET_SECRET;

/* LSA_R_SET_SECRET - response to LSA Set Secret */
typedef struct lsa_r_set_secret_info
{
	uint32 status;

} LSA_R_SET_SECRET;

/* LSA_Q_ENUM_TRUST_DOM - LSA enumerate trusted domains */
typedef struct lsa_enum_trust_dom_info
{
	POLICY_HND pol; /* policy handle */
	uint32 enum_context; /* enumeration context handle */
	uint32 preferred_len; /* preferred maximum length */

} LSA_Q_ENUM_TRUST_DOM;

#define MAX_TRUSTED_DOMS 10

/* LSA_R_ENUM_TRUST_DOM - response to LSA enumerate trusted domains */
typedef struct lsa_r_enum_trust_dom_info
{
	uint32 enum_context; /* enumeration context handle */
	uint32 num_domains; /* number of domains */
	uint32 ptr_enum_domains; /* buffer pointer to num domains */

	/* this lot is only added if ptr_enum_domains is non-NULL */
	uint32 num_domains2; /* number of domains */
	UNIHDR2 *hdr_domain_name;
	UNISTR2 *uni_domain_name;
	DOM_SID2 *domain_sid;

	uint32 status; /* return code */

} LSA_R_ENUM_TRUST_DOM;

/* LSA_Q_CLOSE */
typedef struct lsa_q_close_info
{
	POLICY_HND pol; /* policy handle */

} LSA_Q_CLOSE;

/* LSA_R_CLOSE */
typedef struct lsa_r_close_info
{
	POLICY_HND pol; /* policy handle.  should be all zeros. */

	uint32 status; /* return code */

} LSA_R_CLOSE;


#define MAX_REF_DOMAINS 10

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
	uint32 sid_name_use; /* value is 5 for a well-known group; 2 for a domain group; 1 for a user... */
	UNIHDR hdr_name; 
	uint32 domain_idx; /* index into DOM_R_REF array of SIDs */

} LSA_TRANS_NAME;

#define MAX_LOOKUP_SIDS 30

/* LSA_TRANS_NAME_ENUM - LSA Translated Name Enumeration container */
typedef struct lsa_trans_name_enum_info
{
	uint32 num_entries;
	uint32 ptr_trans_names;
	uint32 num_entries2;
	
	LSA_TRANS_NAME name    [MAX_LOOKUP_SIDS]; /* translated names  */
	UNISTR2        uni_name[MAX_LOOKUP_SIDS]; 

} LSA_TRANS_NAME_ENUM;

/* LSA_SID_ENUM - LSA SID enumeration container */
typedef struct lsa_sid_enum_info
{
	uint32 num_entries;
	uint32 ptr_sid_enum;
	uint32 num_entries2;
	
	uint32   ptr_sid[MAX_LOOKUP_SIDS]; /* domain SID pointers to be looked up. */
	DOM_SID2 sid    [MAX_LOOKUP_SIDS]; /* domain SIDs to be looked up. */

} LSA_SID_ENUM;

/* LSA_Q_LOOKUP_SIDS - LSA Lookup SIDs */
typedef struct lsa_q_lookup_sids
{
	POLICY_HND          pol; /* policy handle */
	LSA_SID_ENUM        sids;
	LSA_TRANS_NAME_ENUM names;
	LOOKUP_LEVEL        level;
	uint32              mapped_count;

} LSA_Q_LOOKUP_SIDS;

/* LSA_R_LOOKUP_SIDS - response to LSA Lookup SIDs */
typedef struct lsa_r_lookup_sids
{
	uint32              ptr_dom_ref;
	DOM_R_REF           *dom_ref; /* domain reference info */

	LSA_TRANS_NAME_ENUM *names;
	uint32              mapped_count;

	uint32              status; /* return code */

} LSA_R_LOOKUP_SIDS;


/* LSA_Q_LOOKUP_NAMES - LSA Lookup NAMEs */
typedef struct lsa_q_lookup_names
{
    POLICY_HND pol; /* policy handle */
    uint32 num_entries;
    uint32 num_entries2;
    UNIHDR  hdr_name[MAX_LOOKUP_SIDS]; /* name buffer pointers */
    UNISTR2 uni_name[MAX_LOOKUP_SIDS]; /* names to be looked up */

    uint32 num_trans_entries; 
    uint32 ptr_trans_sids; /* undocumented domain SID buffer pointer */
    uint32 lookup_level; 
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
	DOM_RID2 *dom_rid; /* domain RIDs being looked up */

	uint32 mapped_count; 

	uint32 status; /* return code */

} LSA_R_LOOKUP_NAMES;


#endif /* _RPC_LSA_H */


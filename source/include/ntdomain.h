/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) John H Terpstra 1996-1997
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

#ifndef _NT_DOMAIN_H /* _NT_DOMAIN_H */
#define _NT_DOMAIN_H 

#ifdef NTDOMAIN

/* RPC packet types */

enum RPC_PKT_TYPE
{
	RPC_REQUEST = 0x00,
	RPC_RESPONSE = 0x02,
	RPC_BIND     = 0x0B,
	RPC_BINDACK  = 0x0C
};

/* Allowable account control bits */
#define ACB_DISABLED   0x0001  /* 1 = User account disabled */
#define ACB_HOMDIRREQ  0x0002  /* 1 = Home directory required */
#define ACB_PWNOTREQ   0x0004  /* 1 = User password not required */
#define ACB_TEMPDUP    0x0008  /* 1 = Temporary duplicate account */
#define ACB_NORMAL     0x0010  /* 1 = Normal user account */
#define ACB_MNS        0x0020  /* 1 = MNS logon user account */
#define ACB_DOMTRUST   0x0040  /* 1 = Interdomain trust account */
#define ACB_WSTRUST    0x0080  /* 1 = Workstation trust account */
#define ACB_SVRTRUST   0x0100  /* 1 = Server trust account */
#define ACB_PWNOEXP    0x0200  /* 1 = User password does not expire */
#define ACB_AUTOLOCK   0x0400  /* 1 = Account auto locked */

#define SAMR_CLOSE          0x01
#define SAMR_OPEN_SECRET    0x07
#define SAMR_LOOKUP_RIDS    0x11
#define SAMR_UNKNOWN_3      0x03
#define SAMR_UNKNOWN_22     0x22
#define SAMR_UNKNOWN_24     0x24
#define SAMR_UNKNOWN_34     0x34
#define SAMR_OPEN_POLICY    0x39

#define LSA_OPENPOLICY      0x2c
#define LSA_QUERYINFOPOLICY 0x07
#define LSA_ENUMTRUSTDOM    0x0d
#define LSA_REQCHAL         0x04
#define LSA_SRVPWSET        0x06
#define LSA_SAMLOGON        0x02
#define LSA_SAMLOGOFF       0x03
#define LSA_LOGON_CTRL2     0x0e
#define LSA_AUTH2           0x0f
#define LSA_CLOSE           0x00

/* XXXX these are here to get a compile! */

#define LSA_OPENSECRET      0xFF
#define LSA_LOOKUPSIDS      0xFE
#define LSA_LOOKUPRIDS      0xFD
#define LSA_LOOKUPNAMES     0xFC

/* srvsvc pipe */
#define NETSERVERGETINFO 0x15
#define NETSHAREENUM     0x0f

/* well-known RIDs - Relative IDs */

/* RIDs - Well-known users ... */
#define DOMAIN_USER_RID_ADMIN          (0x000001F4L)
#define DOMAIN_USER_RID_GUEST          (0x000001F5L)

/* RIDs - well-known groups ... */
#define DOMAIN_GROUP_RID_ADMINS        (0x00000200L)
#define DOMAIN_GROUP_RID_USERS         (0x00000201L)
#define DOMAIN_GROUP_RID_GUESTS        (0x00000202L)

/* RIDs - well-known aliases ... */
#define DOMAIN_ALIAS_RID_ADMINS        (0x00000220L)
#define DOMAIN_ALIAS_RID_USERS         (0x00000221L)
#define DOMAIN_ALIAS_RID_GUESTS        (0x00000222L)
#define DOMAIN_ALIAS_RID_POWER_USERS   (0x00000223L)

#define DOMAIN_ALIAS_RID_ACCOUNT_OPS   (0x00000224L)
#define DOMAIN_ALIAS_RID_SYSTEM_OPS    (0x00000225L)
#define DOMAIN_ALIAS_RID_PRINT_OPS     (0x00000226L)
#define DOMAIN_ALIAS_RID_BACKUP_OPS    (0x00000227L)

#define DOMAIN_ALIAS_RID_REPLICATOR    (0x00000228L)



/* 64 bit time (100usec) since ????? - cifs6.txt, section 3.5, page 30 */
typedef struct nttime_info
{
  uint32 low;
  uint32 high;

} NTTIME;
 

#define MAXSUBAUTHS 15 /* max sub authorities in a SID */

/* DOM_SID - security id */
typedef struct sid_info
{
  uint8  sid_rev_num;             /* SID revision number */
  uint8  num_auths;               /* number of sub-authorities */
  uint8  id_auth[6];              /* Identifier Authority */
  uint32 sub_auths[MAXSUBAUTHS];  /* pointer to sub-authorities. */

} DOM_SID;

/* UNIHDR - unicode string header */
typedef struct unihdr_info
{
  uint16 uni_max_len;
  uint16 uni_str_len;
  uint32 undoc; /* usually has a value of 4 */

} UNIHDR;

/* UNIHDR2 - unicode string header and undocumented buffer */
typedef struct unihdr2_info
{
  UNIHDR unihdr;
  uint32 undoc_buffer; /* undocumented 32 bit buffer pointer */

} UNIHDR2;

/* clueless as to what maximum length should be */
#define MAX_UNISTRLEN 1024

/* UNISTR - unicode string size and buffer */
typedef struct unistr_info
{
  uint16 buffer[MAX_UNISTRLEN]; /* unicode characters. ***MUST*** be null-terminated */

} UNISTR;

/* UNISTR2 - unicode string size and buffer */
typedef struct unistr2_info
{
  uint32 uni_max_len;
  uint32 undoc;
  uint32 uni_str_len;
  uint16 buffer[MAX_UNISTRLEN]; /* unicode characters. **NOT** necessarily null-terminated */

} UNISTR2;

/* DOM_SID2 - domain SID structure - SIDs stored in unicode */
typedef struct domsid2_info
{
  uint32 type; /* value is 5 */
  uint32 undoc; /* value is 0 */

  UNIHDR2 hdr; /* XXXX conflict between hdr and str for length */
  UNISTR  str; /* XXXX conflict between hdr and str for length */

} DOM_SID2;

/* DOM_RID2 - domain RID structure for ntlsa pipe */
typedef struct domrid2_info
{
  uint32 type; /* value is 5 */
  uint32 undoc; /* value is non-zero */
  uint32 rid;
  uint32 rid_idx; /* don't know what this is */

} DOM_RID2;

/* DOM_RID3 - domain RID structure for samr pipe */
typedef struct domrid3_info
{
  uint32 rid;        /* domain-relative (to a SID) id */
  uint32 type1;      /* value is 0x1 */
  uint32 ptr_type;   /* undocumented pointer */
  uint32 type2;      /* value is 0x1 */

} DOM_RID3;

/* DOM_CLNT_SRV - client / server names */
typedef struct clnt_srv_info
{
  uint32  undoc_buffer; /* undocumented 32 bit buffer pointer */
  UNISTR2 uni_logon_srv; /* logon server name */
  uint32  undoc_buffer2; /* undocumented 32 bit buffer pointer */
  UNISTR2 uni_comp_name; /* client machine name */

} DOM_CLNT_SRV;

/* DOM_LOG_INFO - login info */
typedef struct log_info
{
  uint32  undoc_buffer; /* undocumented 32 bit buffer pointer */
  UNISTR2 uni_logon_srv; /* logon server name */
  UNISTR2 uni_acct_name; /* account name */
  uint16  sec_chan;      /* secure channel type */
  UNISTR2 uni_comp_name; /* client machine name */

} DOM_LOG_INFO;

/* DOM_CLNT_INFO - client info */
typedef struct clnt_info
{
  DOM_LOG_INFO login;
  DOM_CRED     cred;

} DOM_CLNT_INFO;

/* DOM_CLNT_INFO2 - client info */
typedef struct clnt_info2
{
  DOM_CLNT_SRV login;
  uint32        ptr_cred;
  DOM_CRED      cred;

} DOM_CLNT_INFO2;

/* DOM_LOGON_ID - logon id */
typedef struct logon_info
{
  uint32 low;
  uint32 high;

} DOM_LOGON_ID;

/* ARC4_OWF */
typedef struct arc4_owf_info
{
  uint8 data[16];

} ARC4_OWF;


/* DOM_ID_INFO_1 */
typedef struct id_info_1
{
  uint32            ptr_id_info1;        /* pointer to id_info_1 */
  UNIHDR            hdr_domain_name;     /* domain name unicode header */
  uint32            param_ctrl;          /* param control */
  DOM_LOGON_ID      logon_id;            /* logon ID */
  UNIHDR            hdr_user_name;       /* user name unicode header */
  UNIHDR            hdr_wksta_name;      /* workgroup name unicode header */
  ARC4_OWF          arc4_lm_owf;         /* arc4 LM OWF Password */
  ARC4_OWF          arc4_nt_owf;         /* arc4 NT OWF Password */
  UNISTR2           uni_domain_name;     /* domain name unicode string */
  UNISTR2           uni_user_name;       /* user name unicode string */
  UNISTR2           uni_wksta_name;      /* workgroup name unicode string */

} DOM_ID_INFO_1;

/* SAM_INFO - sam logon/off id structure */
typedef struct sam_info
{
  DOM_CLNT_INFO2 client;
  uint32         ptr_rtn_cred; /* pointer to return credentials */
  DOM_CRED       rtn_cred; /* return credentials */
  uint16         logon_level;
  uint16         switch_value;
  
  union
  {
    DOM_ID_INFO_1 *id1; /* auth-level 1 */

  } auth;
  
} DOM_SAM_INFO;

/* DOM_GID - group id + user attributes */
typedef struct gid_info
{
  uint32 g_rid;  /* a group RID */
  uint32 attr;

} DOM_GID;

/* RPC_HDR - ms rpc header */
typedef struct rpc_hdr_info
{
  uint8  major; /* 5 - RPC major version */
  uint8  minor; /* 0 - RPC minor version */
  uint8  pkt_type; /* 2 - RPC response packet */
  uint8  frag; /* 3 - first frag + last frag */
  uint32 pack_type; /* 0x1000 0000 - packed data representation */
  uint16 frag_len; /* fragment length - data size (bytes) inc header and tail. */
  uint16 auth_len; /* 0 - authentication length  */
  uint32 call_id; /* call identifier.  matches 12th uint32 of incoming RPC data. */

} RPC_HDR;

/* RPC_HDR_RR - ms request / response rpc header */
typedef struct rpc_hdr_rr_info
{
  RPC_HDR hdr;

  uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id;   /* 0 - presentation context identifier */
  uint8  cancel_count; /* 0 - cancel count */
  uint8  opnum;        /* opnum */
  uint8  reserved;     /* 0 - reserved. */

} RPC_HDR_RR;

/* the interfaces are numbered. as yet I haven't seen more than one interface
 * used on the same pipe name
 * srvsvc
 *   abstract (0x4B324FC8, 0x01D31670, 0x475A7812, 0x88E16EBF, 0x00000003)
 *   transfer (0x8A885D04, 0x11C91CEB, 0x0008E89F, 0x6048102B, 0x00000002)
 */
/* RPC_IFACE */
typedef struct rpc_iface_info
{
  uint8 data[16];    /* 16 bytes of number */
  uint32 version;    /* the interface number */

} RPC_IFACE;


/* this seems to be the same string name depending on the name of the pipe,
 * but is more likely to be linked to the interface name
 * "srvsvc", "\\PIPE\\ntsvcs"
 * "samr", "\\PIPE\\lsass"
 * "wkssvc", "\\PIPE\\wksvcs"
 * "NETLOGON", "\\PIPE\\NETLOGON"
 */
/* RPC_ADDR_STR */
typedef struct rpc_addr_info
{
  uint16 len;   /* length of the string including null terminator */
  fstring str; /* the string above in single byte, null terminated form */

} RPC_ADDR_STR;

/* RPC_HDR_BBA */
typedef struct rpc_hdr_bba_info
{
  uint16 max_tsize;       /* maximum transmission fragment size (0x1630) */
  uint16 max_rsize;       /* max receive fragment size (0x1630) */
  uint32 assoc_gid;       /* associated group id (0x0) */

} RPC_HDR_BBA;

/* RPC_BIND_REQ - ms req bind */
typedef struct rpc_bind_req_info
{
  RPC_HDR_BBA bba;

  uint32 num_elements;    /* the number of elements (0x1) */
  uint16 context_id;      /* presentation context identifier (0x0) */
  uint8 num_syntaxes;     /* the number of syntaxes (has always been 1?)(0x1) */

  RPC_IFACE abstract;     /* num and vers. of interface client is using */
  RPC_IFACE transfer;     /* num and vers. of interface to use for replies */
  
} RPC_HDR_RB;

/* RPC_RESULTS - can only cope with one reason, right now... */
typedef struct rpc_results_info
{
/* uint8[] # 4-byte alignment padding, against SMB header */

  uint8 num_results; /* the number of results (0x01) */

/* uint8[] # 4-byte alignment padding, against SMB header */

  uint16 result; /* result (0x00 = accept) */
  uint16 reason; /* reason (0x00 = no reason specified) */

} RPC_RESULTS;

/* RPC_HDR_BA */
typedef struct rpc_hdr_ba_info
{
  RPC_HDR_BBA bba;

  RPC_ADDR_STR addr    ;  /* the secondary address string, as described earlier */
  RPC_RESULTS  res     ; /* results and reasons */
  RPC_IFACE    transfer; /* the transfer syntax from the request */

} RPC_HDR_BA;


/* DOM_QUERY - info class 3 and 5 LSA Query response */
typedef struct dom_query_info
{
  uint16 uni_dom_max_len; /* domain name string length * 2 */
  uint16 uni_dom_str_len; /* domain name string length * 2 */
  uint32 buffer_dom_name; /* undocumented domain name string buffer pointer */
  uint32 buffer_dom_sid; /* undocumented domain SID string buffer pointer */
  UNISTR2 uni_domain_name; /* domain name (unicode string) */
  DOM_SID dom_sid; /* domain SID */

} DOM_QUERY;

/* level 5 is same as level 3.  we hope. */
typedef DOM_QUERY DOM_QUERY_3;
typedef DOM_QUERY DOM_QUERY_5;

#define POL_HND_SIZE 20

/* LSA_POL_HND */
typedef struct lsa_policy_info
{
  uint8 data[POL_HND_SIZE]; /* policy handle */

} LSA_POL_HND;

/* OBJ_ATTR (object attributes) */
typedef struct object_attributes_info
{
	uint32 len;          /* 0x18 - length (in bytes) inc. the length field. */
	uint32 ptr_root_dir; /* 0 - root directory (pointer) */
	uint32 ptr_obj_name; /* 0 - object name (pointer) */
	uint32 attributes;   /* 0 - attributes (undocumented) */
	uint32 ptr_sec_desc; /* 0 - security descriptior (pointer) */
	uint32 sec_qos;      /* 0 - security quality of service */

} LSA_OBJ_ATTR;

/* LSA_Q_LOGON_CTRL2 - LSA Netr Logon Control 2*/
typedef struct lsa_q_logon_ctrl2_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x1 */
	uint32       query_level;   /* 0x1 */
	uint32       switch_value;  /* 0x1 */

} LSA_Q_LOGON_CTRL2;

/* LSA_R_LOGON_CTRL2 - response to LSA Logon Control2 */
typedef struct lsa_r_logon_ctrl2_info
{
	LSA_POL_HND pol; /* policy handle */
	uint32 status; /* return code */

} LSA_R_LOGON_CTRL2;

/* LSA_Q_OPEN_POL - LSA Query Open Policy */
typedef struct lsa_q_open_pol_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	LSA_OBJ_ATTR attr           ; /* object attributes */

	uint32 des_access; /* desired access attributes */

} LSA_Q_OPEN_POL;

/* LSA_R_OPEN_POL - response to LSA Open Policy */
typedef struct lsa_r_open_pol_info
{
	LSA_POL_HND pol; /* policy handle */

	uint32 status; /* return code */

} LSA_R_OPEN_POL;

/* LSA_Q_QUERY_INFO - LSA query info policy */
typedef struct lsa_query_info
{
	LSA_POL_HND pol; /* policy handle */
    uint16 info_class; /* info class */

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

/* LSA_Q_ENUM_TRUST_DOM - LSA enumerate trusted domains */
typedef struct lsa_enum_trust_dom_info
{
	LSA_POL_HND pol; /* policy handle */
    uint32 enum_context; /* enumeration context handle */
    uint32 preferred_len; /* preferred maximum length */

} LSA_Q_ENUM_TRUST_DOM;

/* LSA_R_ENUM_TRUST_DOM - response to LSA enumerate trusted domains */
typedef struct lsa_r_enum_trust_dom_info
{
	LSA_POL_HND pol; /* policy handle */

    uint32 status; /* return code */

} LSA_R_ENUM_TRUST_DOM;

/* LSA_Q_CLOSE */
typedef struct lsa_q_close_info
{
	LSA_POL_HND pol; /* policy handle */

} LSA_Q_CLOSE;

/* LSA_R_CLOSE */
typedef struct lsa_r_close_info
{
	LSA_POL_HND pol; /* policy handle.  should be all zeros. */

	uint32 status; /* return code */

} LSA_R_CLOSE;


#define MAX_REF_DOMAINS 10

/* DOM_R_REF */
typedef struct dom_ref_info
{
    uint32 undoc_buffer; /* undocumented buffer pointer. */
    uint32 num_ref_doms_1; /* num referenced domains? */
    uint32 buffer_dom_name; /* undocumented domain name buffer pointer. */
    uint32 max_entries; /* 32 - max number of entries */
    uint32 num_ref_doms_2; /* 4 - num referenced domains? */

    UNIHDR2 hdr_dom_name; /* domain name unicode string header */
    UNIHDR2 hdr_ref_dom[MAX_REF_DOMAINS]; /* referenced domain unicode string headers */

    UNISTR uni_dom_name; /* domain name unicode string */
    DOM_SID ref_dom[MAX_REF_DOMAINS]; /* referenced domain SIDs */

} DOM_R_REF;

#define MAX_LOOKUP_SIDS 10

/* LSA_Q_LOOKUP_SIDS - LSA Lookup SIDs */
typedef struct lsa_q_lookup_sids
{
    LSA_POL_HND pol_hnd; /* policy handle */
    uint32 num_entries;
    uint32 buffer_dom_sid; /* undocumented domain SID buffer pointer */
    uint32 buffer_dom_name; /* undocumented domain name buffer pointer */
    uint32 buffer_lookup_sids[MAX_LOOKUP_SIDS]; /* undocumented domain SID pointers to be looked up. */
    DOM_SID dom_sids[MAX_LOOKUP_SIDS]; /* domain SIDs to be looked up. */
    uint8 undoc[16]; /* completely undocumented 16 bytes */

} LSA_Q_LOOKUP_SIDS;

/* LSA_R_LOOKUP_SIDS - response to LSA Lookup SIDs */
typedef struct lsa_r_lookup_sids
{
    DOM_R_REF dom_ref; /* domain reference info */

    uint32 num_entries;
    uint32 undoc_buffer; /* undocumented buffer pointer */
    uint32 num_entries2; 

    DOM_SID2 dom_sid[MAX_LOOKUP_SIDS]; /* domain SIDs being looked up */

    uint32 num_entries3; 

  uint32 status; /* return code */

} LSA_R_LOOKUP_SIDS;

/* DOM_NAME - XXXX not sure about this structure */
typedef struct dom_name_info
{
    uint32 uni_str_len;
	UNISTR str;

} DOM_NAME;


#define UNKNOWN_LEN 1

/* LSA_Q_LOOKUP_RIDS - LSA Lookup RIDs */
typedef struct lsa_q_lookup_rids
{

    LSA_POL_HND pol_hnd; /* policy handle */
    uint32 num_entries;
    uint32 num_entries2;
    uint32 buffer_dom_sid; /* undocumented domain SID buffer pointer */
    uint32 buffer_dom_name; /* undocumented domain name buffer pointer */
    DOM_NAME lookup_name[MAX_LOOKUP_SIDS]; /* names to be looked up */
    uint8 undoc[UNKNOWN_LEN]; /* completely undocumented bytes of unknown length */

} LSA_Q_LOOKUP_RIDS;

/* LSA_R_LOOKUP_RIDS - response to LSA Lookup RIDs by name */
typedef struct lsa_r_lookup_rids
{
    DOM_R_REF dom_ref; /* domain reference info */

    uint32 num_entries;
    uint32 undoc_buffer; /* undocumented buffer pointer */

    uint32 num_entries2; 
    DOM_RID2 dom_rid[MAX_LOOKUP_SIDS]; /* domain RIDs being looked up */

    uint32 num_entries3; 

  uint32 status; /* return code */

} LSA_R_LOOKUP_RIDS;



/* NEG_FLAGS */
typedef struct lsa_neg_flags_info
{
    uint32 neg_flags; /* negotiated flags */

} NEG_FLAGS;


/* LSA_Q_REQ_CHAL */
typedef struct lsa_q_req_chal_info
{
    uint32  undoc_buffer; /* undocumented buffer pointer */
    UNISTR2 uni_logon_srv; /* logon server unicode string */
    UNISTR2 uni_logon_clnt; /* logon client unicode string */
    DOM_CHAL clnt_chal; /* client challenge */

} LSA_Q_REQ_CHAL;


/* LSA_R_REQ_CHAL */
typedef struct lsa_r_req_chal_info
{
    DOM_CHAL srv_chal; /* server challenge */

  uint32 status; /* return code */

} LSA_R_REQ_CHAL;



/* LSA_Q_AUTH_2 */
typedef struct lsa_q_auth2_info
{
    DOM_LOG_INFO clnt_id; /* client identification info */
    DOM_CHAL clnt_chal;     /* client-calculated credentials */

    NEG_FLAGS clnt_flgs; /* usually 0x0000 01ff */

} LSA_Q_AUTH_2;


/* LSA_R_AUTH_2 */
typedef struct lsa_r_auth2_info
{
    DOM_CHAL srv_chal;     /* server-calculated credentials */
    NEG_FLAGS srv_flgs; /* usually 0x0000 01ff */

  uint32 status; /* return code */

} LSA_R_AUTH_2;


/* LSA_Q_SRV_PWSET */
typedef struct lsa_q_srv_pwset_info
{
    DOM_CLNT_INFO clnt_id; /* client identification/authentication info */
    char pwd[16]; /* new password - undocumented. */

} LSA_Q_SRV_PWSET;
    
/* LSA_R_SRV_PWSET */
typedef struct lsa_r_srv_pwset_info
{
    DOM_CRED srv_cred;     /* server-calculated credentials */

  uint32 status; /* return code */

} LSA_R_SRV_PWSET;

#define LSA_MAX_GROUPS 32
#define LSA_MAX_SIDS 32

/* LSA_USER_INFO */
typedef struct lsa_q_user_info
{
	uint32 ptr_user_info;

	NTTIME logon_time;            /* logon time */
	NTTIME logoff_time;           /* logoff time */
	NTTIME kickoff_time;          /* kickoff time */
	NTTIME pass_last_set_time;    /* password last set time */
	NTTIME pass_can_change_time;  /* password can change time */
	NTTIME pass_must_change_time; /* password must change time */

	UNIHDR hdr_user_name;    /* username unicode string header */
	UNIHDR hdr_full_name;    /* user's full name unicode string header */
	UNIHDR hdr_logon_script; /* logon script unicode string header */
	UNIHDR hdr_profile_path; /* profile path unicode string header */
	UNIHDR hdr_home_dir;     /* home directory unicode string header */
	UNIHDR hdr_dir_drive;    /* home directory drive unicode string header */

	uint16 logon_count;  /* logon count */
	uint16 bad_pw_count; /* bad password count */

	uint32 user_id;       /* User ID */
	uint32 group_id;      /* Group ID */
	uint32 num_groups;    /* num groups */
	uint32 buffer_groups; /* undocumented buffer pointer to groups. */
	uint32 user_flgs;     /* user flags */

	char user_sess_key[16]; /* unused user session key */

	UNIHDR hdr_logon_srv; /* logon server unicode string header */
	UNIHDR hdr_logon_dom; /* logon domain unicode string header */

	uint32 buffer_dom_id; /* undocumented logon domain id pointer */
	char padding[40];    /* unused padding bytes.  expansion room */

	uint32 num_other_sids; /* 0 - num_sids */
	uint32 buffer_other_sids; /* NULL - undocumented pointer to SIDs. */
	
	UNISTR2 uni_user_name;    /* username unicode string */
	UNISTR2 uni_full_name;    /* user's full name unicode string */
	UNISTR2 uni_logon_script; /* logon script unicode string */
	UNISTR2 uni_profile_path; /* profile path unicode string */
	UNISTR2 uni_home_dir;     /* home directory unicode string */
	UNISTR2 uni_dir_drive;    /* home directory drive unicode string */

	uint32 num_groups2;        /* num groups */
	DOM_GID gids[LSA_MAX_GROUPS]; /* group info */

	UNISTR2 uni_logon_srv; /* logon server unicode string */
	UNISTR2 uni_logon_dom; /* logon domain unicode string */

	DOM_SID dom_sid;           /* domain SID */
	DOM_SID other_sids[LSA_MAX_SIDS]; /* undocumented - domain SIDs */

} LSA_USER_INFO;


/* LSA_Q_SAM_LOGON */
typedef struct lsa_q_sam_logon_info
{
    DOM_SAM_INFO sam_id;

} LSA_Q_SAM_LOGON;

/* LSA_R_SAM_LOGON */
typedef struct lsa_r_sam_logon_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
	uint16 switch_value; /* 3 - indicates type of USER INFO */
    LSA_USER_INFO *user;

    uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */

  uint32 status; /* return code */

} LSA_R_SAM_LOGON;


/* LSA_Q_SAM_LOGOFF */
typedef struct lsa_q_sam_logoff_info
{
    DOM_SAM_INFO sam_id;

} LSA_Q_SAM_LOGOFF;

/* LSA_R_SAM_LOGOFF */
typedef struct lsa_r_sam_logoff_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
  uint32 status; /* return code */

} LSA_R_SAM_LOGOFF;


/* SH_INFO_1 (pointers to level 1 share info strings) */
typedef struct ptr_share_info1
{
	uint32 ptr_netname; /* pointer to net name. */
	uint32 type;        /* type of share.  0 - undocumented. */
	uint32 ptr_remark;  /* pointer to comment. */

} SH_INFO_1;

/* SH_INFO_1_STR (level 1 share info strings) */
typedef struct str_share_info1
{
	UNISTR2 uni_netname; /* unicode string of net name */
	UNISTR2 uni_remark;  /* unicode string of comment. */

} SH_INFO_1_STR;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_SHARE_ENTRIES 32

/* SHARE_INFO_1_CONTAINER  */
typedef struct share_info_ctr
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_share_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */
	SH_INFO_1     info_1    [MAX_SHARE_ENTRIES]; /* share entry pointers */
	SH_INFO_1_STR info_1_str[MAX_SHARE_ENTRIES]; /* share entry strings */
	uint32 num_entries_read3;                    /* EntriesRead2 */
	uint32 padding;                              /* padding */

} SHARE_INFO_1_CTR;


/* SRV_Q_NET_SHARE_ENUM */
typedef struct q_net_share_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* server name */

	uint32 share_level;          /* share level */
	uint32 switch_value;         /* switch value */

	uint32 ptr_share_info;       /* pointer to SHARE_INFO_1_CTR */

	union
    {
		SHARE_INFO_1_CTR info1; /* share info with 0 entries */

    } share;

	uint32 preferred_len;        /* preferred maximum length (0xffff ffff) */

} SRV_Q_NET_SHARE_ENUM;


/* SRV_R_NET_SHARE_ENUM */
typedef struct r_net_share_enum_info
{
	uint32 share_level;          /* share level */
	uint32 switch_value;         /* switch value */

	uint32 ptr_share_info;       /* pointer to SHARE_INFO_1_CTR */
	union
    {
		SHARE_INFO_1_CTR info1; /* share info container */

    } share;

	uint32 status;               /* return status */

} SRV_R_NET_SHARE_ENUM;


/* SAMR_Q_CLOSE - probably a policy handle close */
typedef struct q_samr_close_info
{
    LSA_POL_HND pol;          /* policy handle */

} SAMR_Q_CLOSE;


/* SAMR_R_CLOSE - probably a policy handle close */
typedef struct r_samr_close_info
{
    LSA_POL_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} SAMR_R_CLOSE;


/****************************************************************************
SAMR_Q_OPEN_SECRET - unknown_0 values seen associated with SIDs:

0x0000 0200 and a specific   domain sid - S-1-5-21-44c01ca6-797e5c3d-33f83fd0
0x0000 0280 and a well-known domain sid - S-1-5-20
0x2000 0000 and a well-known domain sid - S-1-5-20
0x2000 0000 and a specific   domain sid - S-1-5-21-44c01ca6-797e5c3d-33f83fd0
*****************************************************************************/

/* SAMR_Q_OPEN_SECRET - probably an open secret */
typedef struct q_samr_open_secret_info
{
    LSA_POL_HND pol;          /* policy handle */
	uint32 unknown_0;         /* 0x2000 0000; 0x0000 0211; 0x0000 0280; 0x0000 0200 - unknown */
	DOM_SID dom_sid;          /* domain SID */

} SAMR_Q_OPEN_SECRET;


/* SAMR_R_OPEN_SECRET - probably an open */
typedef struct r_samr_open_secret_info
{
    LSA_POL_HND pol;       /* policy handle associated with the SID */
	uint32 status;         /* return status */

} SAMR_R_OPEN_SECRET;


/****************************************************************************
SAMR_Q_LOOKUP_RIDS - do a conversion (only one!) from name to RID.

the policy handle allocated by an "samr open secret" call is associated
with a SID.  this policy handle is what is queried here, *not* the SID
itself.  the response to the lookup rids is relative to this SID.
*****************************************************************************/
/* SAMR_Q_LOOKUP_RIDS - probably a "read SAM entry" */
typedef struct q_samr_lookup_names_info
{
    LSA_POL_HND pol;             /* policy handle */

	uint32 num_rids1;            /* 1          - number of rids being looked up */
	uint32 rid;                  /* 0000 03e8  - RID of the server being queried? */
	uint32 ptr;                  /* 0          - 32 bit unknown */
	uint32 num_rids2;            /* 1          - number of rids being looked up */

	UNIHDR  hdr_mach_acct;       /* unicode machine account name header */
	UNISTR2 uni_mach_acct;       /* unicode machine account name */

} SAMR_Q_LOOKUP_RIDS;


/* SAMR_R_LOOKUP_RIDS - probably an open */
typedef struct r_samr_lookup_names_info
{
	uint32 num_entries;
	uint32 undoc_buffer; /* undocumented buffer pointer */

	uint32 num_entries2; 
	DOM_RID3 dom_rid[MAX_LOOKUP_SIDS]; /* domain RIDs being looked up */

	uint32 num_entries3; 

	uint32 status; /* return code */

} SAMR_R_LOOKUP_RIDS;


/* SAMR_Q_UNKNOWN_22 - probably an open */
typedef struct q_samr_unknown_22_info
{
    LSA_POL_HND pol;          /* policy handle */
	uint32 unknown_id_0;      /* 0x0000 03E8 - 32 bit unknown id */

} SAMR_Q_UNKNOWN_22;


/* SAMR_R_UNKNOWN_22 - probably an open */
typedef struct r_samr_unknown_22_info
{
    LSA_POL_HND pol;       /* policy handle associated with unknown id */
	uint32 status;         /* return status */

} SAMR_R_UNKNOWN_22;


/* SAMR_Q_UNKNOWN_24 - probably a get sam info */
typedef struct q_samr_unknown_24_info
{
    LSA_POL_HND pol;          /* policy handle associated with unknown id */
	uint16 unknown_0;         /* 0x0015 or 0x0011 - 16 bit unknown */

} SAMR_Q_UNKNOWN_24;


/* SAMR_R_UNKNOWN_24 - probably a get sam info */
typedef struct r_samr_unknown_24_info
{
	uint32 ptr;            /* pointer */
	uint16 unknown_0;      /* 0x0015 or 0x0011 - 16 bit unknown (same as above) */
	uint16 unknown_1;      /* 0x8b73 - 16 bit unknown */
	uint8  padding_0[16];  /* 0 - padding 16 bytes */
	NTTIME expiry;         /* expiry time or something? */
	uint8  padding_1[24];  /* 0 - padding 24 bytes */

	UNIHDR hdr_mach_acct;  /* unicode header for machine account */
	uint32 padding_2;      /* 0 - padding 4 bytes */

	uint32 ptr_1;          /* pointer */
	uint8  padding_3[32];  /* 0 - padding 32 bytes */
	uint32 padding_4;      /* 0 - padding 4 bytes */

	uint32 ptr_2;          /* pointer */
	uint32 padding_5;      /* 0 - padding 4 bytes */

	uint32 ptr_3;          /* pointer */
	uint8  padding_6[32];  /* 0 - padding 32 bytes */

	uint32 unknown_id_0;   /* unknown id associated with policy handle */
	uint16 unknown_2;      /* 0x0201      - 16 bit unknown */
	uint32 unknown_3;      /* 0x0000 0080 - 32 bit unknown */
	uint16 unknown_4;      /* 0x003f      - 16 bit unknown */
	uint16 unknown_5;      /* 0x003c      - 16 bit unknown */

	uint8  padding_7[16];  /* 0 - padding 16 bytes */
	uint32 padding_8;      /* 0 - padding 4 bytes */
	
	UNISTR2 uni_mach_acct; /* unicode string for machine account */

	uint8  padding_9[48];  /* 0 - padding 48 bytes */

	uint32 status;         /* return status */

} SAMR_R_UNKNOWN_24;


/* SAMR_Q_UNKNOWN_32 - probably a "create SAM entry" */
typedef struct q_samr_unknown_32_info
{
    LSA_POL_HND pol;             /* policy handle */

	UNIHDR  hdr_mach_acct;       /* unicode machine account name header */
	UNISTR2 uni_mach_acct;       /* unicode machine account name */

	uint32 unknown_0;            /* 32 bit unknown */
	uint16 unknown_1;            /* 16 bit unknown */
	uint16 unknown_2;            /* 16 bit unknown */

} SAMR_Q_UNKNOWN_32;


/* SAMR_R_UNKNOWN_32 - probably a "create SAM entry" */
typedef struct r_samr_unknown_32_info
{
    LSA_POL_HND pol;       /* policy handle */
	uint32 unknown_0;      /* 0x0000 0030 - 32 bit unknown */
	uint32 padding;        /* 0           - 4 byte padding */

	uint32 status;         /* return status - 0xC000 0099: user exists */

} SAMR_R_UNKNOWN_32;


/* SAMR_Q_OPEN_POLICY - probably an open */
typedef struct q_samr_open_policy_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* unicode server name starting with '\\' */

	uint32 unknown_0;            /* 32 bit unknown */

} SAMR_Q_OPEN_POLICY;


/* SAMR_R_OPEN_POLICY - probably an open */
typedef struct r_samr_open_policy_info
{
    LSA_POL_HND pol;       /* policy handle */
	uint32 status;             /* return status */

} SAMR_R_OPEN_POLICY;


/* WKS_Q_UNKNOWN_0 - probably a capabilities request */
typedef struct q_wks_unknown_0_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* unicode server name starting with '\\' */

	uint32 unknown_0;            /* 0x64 - 32 bit unknown */
	uint16 unknown_1;            /* 16 bit unknown */

} WKS_Q_UNKNOWN_0;


/* WKS_R_UNKNOWN_0 - probably a capabilities request */
typedef struct r_wks_unknown_0_info
{
	uint32 unknown_0;          /* 64 - unknown */
	uint32 ptr_1;              /* pointer 1 */
	uint32 unknown_1;          /* 0x0000 01f4 - unknown */
	uint32 ptr_srv_name;       /* pointer to server name */
	uint32 ptr_dom_name;       /* pointer to domain name */
	uint32 unknown_2;          /* 4 - unknown */
	uint32 unknown_3;          /* 0 - unknown */

	UNISTR2 uni_srv_name;      /* unicode server name */
	UNISTR2 uni_dom_name;      /* unicode domainn name */
	uint32 status;             /* return status */

} WKS_R_UNKNOWN_0;

#endif /* NTDOMAIN */

#endif /* _NT_DOMAIN_H */


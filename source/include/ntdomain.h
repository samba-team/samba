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


/* RPC packet types */

enum RPC_PKT_TYPE
{
	RPC_REQUEST = 0x00,
	RPC_RESPONSE = 0x02,
	RPC_BIND     = 0x0B,
	RPC_BINDACK  = 0x0C
};

/* Secure Channel types.  used in NetrServerAuthenticate negotiation */
#define SEC_CHAN_WKSTA   2
#define SEC_CHAN_DOMAIN  4

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

#define REG_OPEN_POLICY     0x02
#define REG_OPEN_ENTRY      0x0f
#define REG_INFO            0x11
#define REG_CLOSE           0x05

/*******************************************************************
 the following information comes from a QuickView on samsrv.dll,
 and gives an idea of exactly what is needed:
 
SamrAddMemberToAlias
SamrAddMemberToGroup
SamrAddMultipleMembersToAlias
SamrChangePasswordUser
x SamrCloseHandle
x SamrConnect
SamrCreateAliasInDomain
SamrCreateGroupInDomain
SamrCreateUserInDomain
SamrDeleteAlias
SamrDeleteGroup
SamrDeleteUser
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
SamrOpenGroup
x SamrOpenUser
x SamrQueryDisplayInformation
x SamrQueryInformationAlias
SamrQueryInformationDomain
? SamrQueryInformationUser
SamrQuerySecurityObject
SamrRemoveMemberFromAlias
SamrRemoveMemberFromForiegnDomain
SamrRemoveMemberFromGroup
SamrRemoveMultipleMembersFromAlias
SamrSetInformationAlias
SamrSetInformationDomain
SamrSetInformationGroup
SamrSetInformationUser
SamrSetMemberAttributesOfGroup
SamrSetSecurityObject
SamrShutdownSamServer
SamrTestPrivateFunctionsDomain
SamrTestPrivateFunctionsUser

********************************************************************/

#define SAMR_CLOSE_HND         0x01
#define SAMR_OPEN_DOMAIN       0x07
#define SAMR_LOOKUP_IDS        0x10
#define SAMR_LOOKUP_NAMES      0x11
#define SAMR_UNKNOWN_3         0x03
#define SAMR_QUERY_DISPINFO    0x28
#define SAMR_OPEN_USER         0x22
#define SAMR_QUERY_USERINFO    0x24
#define SAMR_QUERY_USERGROUPS  0x27
#define SAMR_UNKNOWN_12        0x12
#define SAMR_UNKNOWN_21        0x21
#define SAMR_UNKNOWN_32        0x32
#define SAMR_UNKNOWN_34        0x34
#define SAMR_CONNECT           0x39
#define SAMR_OPEN_ALIAS        0x1b
#define SAMR_QUERY_ALIASINFO   0x1c
#define SAMR_ENUM_DOM_USERS    0x0d
#define SAMR_ENUM_DOM_ALIASES  0x0f
#define SAMR_ENUM_DOM_GROUPS   0x30

/* ntlsa pipe */
#define LSA_OPENPOLICY         0x2c
#define LSA_QUERYINFOPOLICY    0x07
#define LSA_ENUMTRUSTDOM       0x0d
#define LSA_CLOSE              0x00
#define LSA_OPENSECRET         0x1C

/* XXXX these are here to get a compile! */
#define LSA_LOOKUPSIDS      0xFE
#define LSA_LOOKUPRIDS      0xFD
#define LSA_LOOKUPNAMES     0xFC

/* NETLOGON pipe */
#define NET_REQCHAL            0x04
#define NET_SRVPWSET           0x06
#define NET_SAMLOGON           0x02
#define NET_SAMLOGOFF          0x03
#define NET_AUTH2              0x0f
#define NET_LOGON_CTRL2        0x0e
#define NET_TRUST_DOM_LIST     0x13

/* srvsvc pipe */
#define SRV_NETCONNENUM      0x08
#define SRV_NETFILEENUM      0x09
#define SRV_NETSESSENUM      0x0c
#define SRV_NETSHAREENUM     0x0f
#define SRV_NET_SRV_GET_INFO 0x15
#define SRV_NET_SRV_SET_INFO 0x16

/* wkssvc pipe */
#define WKS_UNKNOWN_0    0x00


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


/* 32 bit time (sec) since 01jan1970 - cifs6.txt, section 3.5, page 30 */
typedef struct time_info
{
  uint32 time;

} UTIME;


/* 64 bit time (100usec) since ????? - cifs6.txt, section 3.5, page 30 */
typedef struct nttime_info
{
  uint32 low;
  uint32 high;

} NTTIME;
 
/* ENUM_HND */
typedef struct enum_hnd_info
{
	uint32 ptr_hnd;          /* pointer to enumeration handle */
	uint32 handle;           /* enumeration handle */

} ENUM_HND;

/* DOM_CHAL - challenge info */
typedef struct chal_info
{
  uchar data[8]; /* credentials */
} DOM_CHAL;

/* DOM_CREDs - timestamped client or server credentials */
typedef struct cred_info
{
  DOM_CHAL challenge; /* credentials */
  UTIME timestamp;    /* credential time-stamp */

} DOM_CRED;

#define MAXSUBAUTHS 15 /* max sub authorities in a SID */

/* DOM_SID - security id */
typedef struct sid_info
{
  uint8  sid_rev_num;             /* SID revision number */
  uint8  num_auths;               /* number of sub-authorities */
  uint8  id_auth[6];              /* Identifier Authority */
  uint32 sub_auths[MAXSUBAUTHS];  /* pointer to sub-authorities. */

} DOM_SID;

/* DOM_SID2 - security id */
typedef struct sid_info_2
{
	uint32 num_auths; /* length, bytes, including length of len :-) */

	DOM_SID sid;

} DOM_SID2;

/* DOM_SID3 example:
   0x14 0x035b 0x0002 S-1-1
   0x18 0x07ff 0x000f S-1-5-20-DOMAIN_ALIAS_RID_ADMINS
   0x18 0x07ff 0x000f S-1-5-20-DOMAIN_ALIAS_RID_ACCOUNT_OPS
   0x24 0x0044 0x0002 S-1-5-21-nnn-nnn-nnn-0x03f1
 */

/* DOM_SID3 example:
   0x24 0x0044 0x0002 S-1-5-21-nnn-nnn-nnn-0x03ee
   0x18 0x07ff 0x000f S-1-5-20-DOMAIN_ALIAS_RID_ADMINS
   0x14 0x035b 0x0002 S-1-1
 */

/* DOM_SID3 - security id */
typedef struct sid_info_3
{
	uint16 len; /* length, bytes, including length of len :-) */
	
	uint16 unknown_0;
	uint16 unknown_1;

	DOM_SID sid;

} DOM_SID3;

/* UNIHDR - unicode string header */
typedef struct unihdr_info
{
  uint16 uni_max_len;
  uint16 uni_str_len;
  uint32 buffer; /* usually has a value of 4 */

} UNIHDR;

/* UNIHDR2 - unicode string header and undocumented buffer */
typedef struct unihdr2_info
{
  UNIHDR unihdr;
  uint32 buffer; /* 32 bit buffer pointer */

} UNIHDR2;

/* clueless as to what maximum length should be */
#define MAX_UNISTRLEN 256

/* UNISTR - unicode string size and buffer */
typedef struct unistr_info
{
  uint16 buffer[MAX_UNISTRLEN]; /* unicode characters. ***MUST*** be null-terminated */

} UNISTR;

/* UNINOTSTR2 - unicode string, size (in uint8 ascii chars) and buffer */
/* pathetic.  some stupid team of \PIPE\winreg writers got the concept */
/* of a unicode string different from the other \PIPE\ writers */
typedef struct uninotstr2_info
{
  uint32 uni_max_len;
  uint32 undoc;
  uint32 uni_buf_len;
  uint16 buffer[MAX_UNISTRLEN]; /* unicode characters. **NOT** necessarily null-terminated */

} UNINOTSTR2;

/* UNISTR2 - unicode string size (in uint16 unicode chars) and buffer */
typedef struct unistr2_info
{
  uint32 uni_max_len;
  uint32 undoc;
  uint32 uni_str_len;
  uint16 buffer[MAX_UNISTRLEN]; /* unicode characters. **NOT** necessarily null-terminated */

} UNISTR2;


/* DOM_STR_SID - domain SID structure - SIDs stored in unicode */
typedef struct domsid2_info
{
  uint32 type; /* value is 5 */
  uint32 undoc; /* value is 0 */

  UNIHDR2 hdr; /* XXXX conflict between hdr and str for length */
  UNISTR  str; /* XXXX conflict between hdr and str for length */

} DOM_STR_SID;

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

/* DOM_RID4 - rid + user attributes */
typedef struct domrid4_info
{
  uint32 unknown;      
  uint16 attr;
  uint32 rid;  /* user RID */

} DOM_RID4;

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
  
  uint16         switch_value2;

} DOM_SAM_INFO;

/* DOM_GID - group id + user attributes */
typedef struct gid_info
{
  uint32 g_rid;  /* a group RID */
  uint32 attr;

} DOM_GID;

typedef struct logon_hours_info
{
	uint32 len; /* normally 21 bytes */
	uint8 hours[32];

} LOGON_HRS;

#define LSA_MAX_GROUPS 32
#define LSA_MAX_SIDS 32

/* SAM_USER_INFO_15 */
typedef struct sam_user_info_15
{
	NTTIME logon_time;            /* logon time */
	NTTIME logoff_time;           /* logoff time */
	NTTIME kickoff_time;          /* kickoff time */
	NTTIME pass_last_set_time;    /* password last set time */
	NTTIME pass_can_change_time;  /* password can change time */
	NTTIME pass_must_change_time; /* password must change time */

	UNIHDR hdr_user_name;    /* username unicode string header */
	UNIHDR hdr_full_name;    /* user's full name unicode string header */
	UNIHDR hdr_home_dir;     /* home directory unicode string header */
	UNIHDR hdr_dir_drive;    /* home drive unicode string header */
	UNIHDR hdr_profile_path; /* profile path unicode string header */
	UNIHDR hdr_logon_script; /* logon script unicode string header */
	UNIHDR hdr_description;  /* user description */

	uint16 logon_count;  /* logon count */
	uint16 bad_pw_count; /* bad password count */

	uint32 ptr_padding2;         /* unknown pointer 0 */
	uint32 unknown_0;

	uint32 ptr_padding3;         /* unknown pointer 1 */
	uint32 unknown_1;

	uint32 ptr_unknown6;         /* unknown pointer 3 */
	uint8 unknown_2[32];    /* user passwords? */

	uint32 user_rid;      /* User ID */
	uint32 group_rid;     /* Group ID */

	uint16 acb_info;
	/* uint8 pad[2] */

	uint32 unknown_3; /* 0x00ff ffff */

	uint16 logon_divs; /* 0x0000 00a8 which is 168 which is num hrs in a week */
	/* uint8 pad[2] */
	uint32 ptr_logon_hrs; /* unknown pointer */

	uint32 unknown_5;     /* 0x0002 0000 */

	uint8 padding1[8];

	UNISTR2 uni_user_name;    /* username unicode string */
	UNISTR2 uni_full_name;    /* user's full name unicode string */
	UNISTR2 uni_home_dir;     /* home directory unicode string */
	UNISTR2 uni_dir_drive;    /* home directory drive unicode string */
	UNISTR2 uni_profile_path; /* profile path unicode string */
	UNISTR2 uni_logon_script; /* logon script unicode string */
	UNISTR2 uni_description;  /* user description unicode string */

	uint8 padding2[32];
	uint32 padding3;

	uint32 unknown_6; /* 0x0000 04ec */
	uint32 padding4;

	LOGON_HRS logon_hrs;

} SAM_USER_INFO_15;


/* SAM_USER_INFO_11 */
typedef struct sam_user_info_11
{
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

	uint32 rid_user;       /* user RID */
	uint32 rid_group;      /* group RID */

	uint16 acct_ctrl;      /* 0080 - ACB_XXXX */
	uint16 unknown_3;      /* 16 bit padding */

	uint16 unknown_4;      /* 0x003f      - 16 bit unknown */
	uint16 unknown_5;      /* 0x003c      - 16 bit unknown */

	uint8  padding_7[16];  /* 0 - padding 16 bytes */
	uint32 padding_8;      /* 0 - padding 4 bytes */
	
	UNISTR2 uni_mach_acct; /* unicode string for machine account */

	uint8  padding_9[48];  /* 0 - padding 48 bytes */

} SAM_USER_INFO_11;


/* SAM_USER_INFO_10 */
typedef struct sam_user_info_10
{
	uint32 rid_group;

} SAM_USER_INFO_10;

/* LSA_USER_INFO_3 */
typedef struct lsa_user_info_3
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

	uint8 user_sess_key[16]; /* unused user session key */

	UNIHDR hdr_logon_srv; /* logon server unicode string header */
	UNIHDR hdr_logon_dom; /* logon domain unicode string header */

	uint32 buffer_dom_id; /* undocumented logon domain id pointer */
	uint8 padding[40];    /* unused padding bytes.  expansion room */

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

	DOM_SID2 dom_sid;           /* domain SID */
	DOM_SID2 other_sids[LSA_MAX_SIDS]; /* undocumented - domain SIDs */

} LSA_USER_INFO_3;


/* RPC_IFACE */
typedef struct rpc_iface_info
{
  uint8 data[16];    /* 16 bytes of rpc interface identification */
  uint32 version;    /* the interface version number */

} RPC_IFACE;

struct pipe_id_info
{
	char *client_pipe;
	RPC_IFACE abstr_syntax; /* this one is the abstract syntax id */

	char *server_pipe;  /* this one is the secondary syntax name */
	RPC_IFACE trans_syntax; /* this one is the primary syntax id */
};

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
  uint8  context_id;   /* 0 - presentation context identifier */
  uint8  cancel_count; /* 0 - cancel count */
  uint8  opnum;        /* opnum */
  uint8  reserved;     /* 0 - reserved. */

} RPC_HDR_RR;

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
  DOM_SID2 dom_sid; /* domain SID */

} DOM_QUERY;

/* level 5 is same as level 3.  we hope. */
typedef DOM_QUERY DOM_QUERY_3;
typedef DOM_QUERY DOM_QUERY_5;

#define POL_HND_SIZE 20

/* POLICY_HND */
typedef struct lsa_policy_info
{
  uint8 data[POL_HND_SIZE]; /* policy handle */

} POLICY_HND;

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

/********************************************************
 Logon Control Query

 query_level 0x1 - pdc status
 query_level 0x3 - number of logon attempts.

 ********************************************************/
/* NET_Q_LOGON_CTRL2 - LSA Netr Logon Control 2*/
typedef struct net_q_logon_ctrl2_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x1 */
	uint32       query_level;   /* 0x1, 0x3 */
	uint32       switch_value;  /* 0x1 */

} NET_Q_LOGON_CTRL2;

/* NETLOGON_INFO_1 - pdc status info, i presume */
typedef struct netlogon_1_info
{
	uint32 flags;            /* 0x0 - undocumented */
	uint32 pdc_status;       /* 0x0 - undocumented */

} NETLOGON_INFO_1;

/* NETLOGON_INFO_2 - pdc status info, plus trusted domain info */
typedef struct netlogon_2_info
{
	uint32  flags;            /* 0x0 - undocumented */
	uint32  pdc_status;       /* 0x0 - undocumented */
	uint32  ptr_trusted_dc_name; /* pointer to trusted domain controller name */
	uint32  tc_status;           /* 0x051f - ERROR_NO_LOGON_SERVERS */
	UNISTR2 uni_trusted_dc_name; /* unicode string - trusted dc name */

} NETLOGON_INFO_2;

/* NETLOGON_INFO_3 - logon status info, i presume */
typedef struct netlogon_3_info
{
	uint32 flags;            /* 0x0 - undocumented */
	uint32 logon_attempts;   /* number of logon attempts */
	uint32 reserved_1;       /* 0x0 - undocumented */
	uint32 reserved_2;       /* 0x0 - undocumented */
	uint32 reserved_3;       /* 0x0 - undocumented */
	uint32 reserved_4;       /* 0x0 - undocumented */
	uint32 reserved_5;       /* 0x0 - undocumented */

} NETLOGON_INFO_3;

/*******************************************************
 Logon Control Response

 switch_value is same as query_level in request 
 *******************************************************/

/* NET_R_LOGON_CTRL2 - response to LSA Logon Control2 */
typedef struct net_r_logon_ctrl2_info
{
	uint32       switch_value;  /* 0x1, 0x3 */
	uint32       ptr;

	union
	{
		NETLOGON_INFO_1 info1;
		NETLOGON_INFO_2 info2;
		NETLOGON_INFO_3 info3;

	} logon;

	uint32 status; /* return code */

} NET_R_LOGON_CTRL2;

/* NET_Q_TRUST_DOM_LIST - LSA Query Trusted Domains */
typedef struct net_q_trust_dom_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x31 */

} NET_Q_TRUST_DOM_LIST;

#define MAX_TRUST_DOMS 1

/* NET_R_TRUST_DOM_LIST - response to LSA Trusted Domains */
typedef struct net_r_trust_dom_info
{
	UNISTR2 uni_trust_dom_name[MAX_TRUST_DOMS];

	uint32 status; /* return code */

} NET_R_TRUST_DOM_LIST;

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
	POLICY_HND pol; /* policy handle */
	uint32 status; /* return code */

} LSA_R_OPEN_POL;

/* LSA_Q_QUERY_INFO - LSA query info policy */
typedef struct lsa_query_info
{
	POLICY_HND pol; /* policy handle */
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
	POLICY_HND pol; /* policy handle */
    uint32 enum_context; /* enumeration context handle */
    uint32 preferred_len; /* preferred maximum length */

} LSA_Q_ENUM_TRUST_DOM;

/* LSA_R_ENUM_TRUST_DOM - response to LSA enumerate trusted domains */
typedef struct lsa_r_enum_trust_dom_info
{
	uint32 enum_context; /* enumeration context handle */
	uint32 num_domains; /* number of domains */
	uint32 ptr_enum_domains; /* buffer pointer to num domains */

	/* this lot is only added if ptr_enum_domains is non-NULL */
		uint32 num_domains2; /* number of domains */
		UNIHDR2 hdr_domain_name;
		UNISTR2 uni_domain_name;
		DOM_SID2 other_domain_sid;

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
    DOM_SID2 ref_dom[MAX_REF_DOMAINS]; /* referenced domain SIDs */

} DOM_R_REF;

#define MAX_LOOKUP_SIDS 10

/* LSA_Q_LOOKUP_SIDS - LSA Lookup SIDs */
typedef struct lsa_q_lookup_sids
{
    POLICY_HND pol_hnd; /* policy handle */
    uint32 num_entries;
    uint32 buffer_dom_sid; /* undocumented domain SID buffer pointer */
    uint32 buffer_dom_name; /* undocumented domain name buffer pointer */
    uint32 buffer_lookup_sids[MAX_LOOKUP_SIDS]; /* undocumented domain SID pointers to be looked up. */
    DOM_SID2 dom_sids[MAX_LOOKUP_SIDS]; /* domain SIDs to be looked up. */
    uint8 undoc[16]; /* completely undocumented 16 bytes */

} LSA_Q_LOOKUP_SIDS;

/* LSA_R_LOOKUP_SIDS - response to LSA Lookup SIDs */
typedef struct lsa_r_lookup_sids
{
    DOM_R_REF dom_ref; /* domain reference info */

    uint32 num_entries;
    uint32 undoc_buffer; /* undocumented buffer pointer */
    uint32 num_entries2; 

    DOM_STR_SID str_sid[MAX_LOOKUP_SIDS]; /* domain SIDs being looked up */

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

    POLICY_HND pol_hnd; /* policy handle */
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
typedef struct neg_flags_info
{
    uint32 neg_flags; /* negotiated flags */

} NEG_FLAGS;


/* NET_Q_REQ_CHAL */
typedef struct net_q_req_chal_info
{
    uint32  undoc_buffer; /* undocumented buffer pointer */
    UNISTR2 uni_logon_srv; /* logon server unicode string */
    UNISTR2 uni_logon_clnt; /* logon client unicode string */
    DOM_CHAL clnt_chal; /* client challenge */

} NET_Q_REQ_CHAL;


/* NET_R_REQ_CHAL */
typedef struct net_r_req_chal_info
{
    DOM_CHAL srv_chal; /* server challenge */

  uint32 status; /* return code */

} NET_R_REQ_CHAL;



/* NET_Q_AUTH_2 */
typedef struct net_q_auth2_info
{
    DOM_LOG_INFO clnt_id; /* client identification info */
    DOM_CHAL clnt_chal;     /* client-calculated credentials */

    NEG_FLAGS clnt_flgs; /* usually 0x0000 01ff */

} NET_Q_AUTH_2;


/* NET_R_AUTH_2 */
typedef struct net_r_auth2_info
{
    DOM_CHAL srv_chal;     /* server-calculated credentials */
    NEG_FLAGS srv_flgs; /* usually 0x0000 01ff */

  uint32 status; /* return code */

} NET_R_AUTH_2;


/* NET_Q_SRV_PWSET */
typedef struct net_q_srv_pwset_info
{
    DOM_CLNT_INFO clnt_id; /* client identification/authentication info */
    uint8 pwd[16]; /* new password - undocumented. */

} NET_Q_SRV_PWSET;
    
/* NET_R_SRV_PWSET */
typedef struct net_r_srv_pwset_info
{
    DOM_CRED srv_cred;     /* server-calculated credentials */

  uint32 status; /* return code */

} NET_R_SRV_PWSET;

/* NET_Q_SAM_LOGON */
typedef struct net_q_sam_logon_info
{
    DOM_SAM_INFO sam_id;

} NET_Q_SAM_LOGON;

/* NET_R_SAM_LOGON */
typedef struct net_r_sam_logon_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
	uint16 switch_value; /* 3 - indicates type of USER INFO */
    LSA_USER_INFO_3 *user;

    uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */

  uint32 status; /* return code */

} NET_R_SAM_LOGON;


/* NET_Q_SAM_LOGOFF */
typedef struct net_q_sam_logoff_info
{
    DOM_SAM_INFO sam_id;

} NET_Q_SAM_LOGOFF;

/* NET_R_SAM_LOGOFF */
typedef struct net_r_sam_logoff_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
  uint32 status; /* return code */

} NET_R_SAM_LOGOFF;


/* SESS_INFO_0 (pointers to level 0 session info strings) */
typedef struct ptr_sess_info0
{
	uint32 ptr_name; /* pointer to name. */

} SESS_INFO_0;

/* SESS_INFO_0_STR (level 0 session info strings) */
typedef struct str_sess_info0
{
	UNISTR2 uni_name; /* unicode string of name */

} SESS_INFO_0_STR;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_SESS_ENTRIES 32

/* SRV_SESS_INFO_0 */
typedef struct srv_sess_info_0_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_sess_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	SESS_INFO_0     info_0    [MAX_SESS_ENTRIES]; /* session entry pointers */
	SESS_INFO_0_STR info_0_str[MAX_SESS_ENTRIES]; /* session entry strings */

} SRV_SESS_INFO_0;

/* SESS_INFO_1 (pointers to level 1 session info strings) */
typedef struct ptr_sess_info1
{
	uint32 ptr_name; /* pointer to name. */
	uint32 ptr_user; /* pointer to user name. */

	uint32 num_opens;
	uint32 open_time;
	uint32 idle_time;
	uint32 user_flags;

} SESS_INFO_1;

/* SESS_INFO_1_STR (level 1 session info strings) */
typedef struct str_sess_info1
{
	UNISTR2 uni_name; /* unicode string of name */
	UNISTR2 uni_user; /* unicode string of user */

} SESS_INFO_1_STR;

/* SRV_SESS_INFO_1 */
typedef struct srv_sess_info_1_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_sess_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	SESS_INFO_1     info_1    [MAX_SESS_ENTRIES]; /* session entry pointers */
	SESS_INFO_1_STR info_1_str[MAX_SESS_ENTRIES]; /* session entry strings */

} SRV_SESS_INFO_1;

/* SRV_SESS_INFO_CTR */
typedef struct srv_sess_info_ctr_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_sess_ctr;       /* pointer to sess info union */
	union
    {
		SRV_SESS_INFO_0 info0; /* session info level 0 */
		SRV_SESS_INFO_1 info1; /* session info level 1 */

    } sess;

} SRV_SESS_INFO_CTR;


/* SRV_Q_NET_SESS_ENUM */
typedef struct q_net_sess_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* server name */

	uint32 ptr_qual_name;         /* pointer (to qualifier name) */
	UNISTR2 uni_qual_name;        /* qualifier name "\\qualifier" */

	uint32 sess_level;          /* session level */

	SRV_SESS_INFO_CTR *ctr;

	uint32 preferred_len;        /* preferred maximum length (0xffff ffff) */
	ENUM_HND enum_hnd;

} SRV_Q_NET_SESS_ENUM;

/* SRV_R_NET_SESS_ENUM */
typedef struct r_net_sess_enum_info
{
	uint32 sess_level;          /* share level */

	SRV_SESS_INFO_CTR *ctr;

	uint32 total_entries;                    /* total number of entries */
	ENUM_HND enum_hnd;

	uint32 status;               /* return status */

} SRV_R_NET_SESS_ENUM;

/* CONN_INFO_0 (pointers to level 0 connection info strings) */
typedef struct ptr_conn_info0
{
	uint32 id; /* connection id. */

} CONN_INFO_0;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_CONN_ENTRIES 32

/* SRV_CONN_INFO_0 */
typedef struct srv_conn_info_0_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_conn_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	CONN_INFO_0     info_0    [MAX_CONN_ENTRIES]; /* connection entry pointers */

} SRV_CONN_INFO_0;

/* CONN_INFO_1 (pointers to level 1 connection info strings) */
typedef struct ptr_conn_info1
{
	uint32 id;   /* connection id */
	uint32 type; /* 0x3 */
	uint32 num_opens;
	uint32 num_users;
	uint32 open_time;

	uint32 ptr_usr_name; /* pointer to user name. */
	uint32 ptr_net_name; /* pointer to network name (e.g IPC$). */

} CONN_INFO_1;

/* CONN_INFO_1_STR (level 1 connection info strings) */
typedef struct str_conn_info1
{
	UNISTR2 uni_usr_name; /* unicode string of user */
	UNISTR2 uni_net_name; /* unicode string of name */

} CONN_INFO_1_STR;

/* SRV_CONN_INFO_1 */
typedef struct srv_conn_info_1_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_conn_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	CONN_INFO_1     info_1    [MAX_CONN_ENTRIES]; /* connection entry pointers */
	CONN_INFO_1_STR info_1_str[MAX_CONN_ENTRIES]; /* connection entry strings */

} SRV_CONN_INFO_1;

/* SRV_CONN_INFO_CTR */
typedef struct srv_conn_info_ctr_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_conn_ctr;       /* pointer to conn info union */
	union
    {
		SRV_CONN_INFO_0 info0; /* connection info level 0 */
		SRV_CONN_INFO_1 info1; /* connection info level 1 */

    } conn;

} SRV_CONN_INFO_CTR;


/* SRV_Q_NET_CONN_ENUM */
typedef struct q_net_conn_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name) */
	UNISTR2 uni_srv_name;        /* server name "\\server" */

	uint32 ptr_qual_name;         /* pointer (to qualifier name) */
	UNISTR2 uni_qual_name;        /* qualifier name "\\qualifier" */

	uint32 conn_level;          /* connection level */

	SRV_CONN_INFO_CTR *ctr;

	uint32 preferred_len;        /* preferred maximum length (0xffff ffff) */
	ENUM_HND enum_hnd;

} SRV_Q_NET_CONN_ENUM;

/* SRV_R_NET_CONN_ENUM */
typedef struct r_net_conn_enum_info
{
	uint32 conn_level;          /* share level */

	SRV_CONN_INFO_CTR *ctr;

	uint32 total_entries;                    /* total number of entries */
	ENUM_HND enum_hnd;

	uint32 status;               /* return status */

} SRV_R_NET_CONN_ENUM;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_SHARE_ENTRIES 32

/* SH_INFO_1 (pointers to level 1 share info strings) */
typedef struct ptr_share_info1
{
	uint32 ptr_netname; /* pointer to net name. */
	uint32 type; /* ipc, print, disk ... */
	uint32 ptr_remark; /* pointer to comment. */

} SH_INFO_1;

/* SH_INFO_1_STR (level 1 share info strings) */
typedef struct str_share_info1
{
	UNISTR2 uni_netname; /* unicode string of net name */
	UNISTR2 uni_remark; /* unicode string of comment */

} SH_INFO_1_STR;

/* SRV_SHARE_INFO_1 */
typedef struct share_info_1_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_share_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	SH_INFO_1     info_1    [MAX_SHARE_ENTRIES]; /* share entry pointers */
	SH_INFO_1_STR info_1_str[MAX_SHARE_ENTRIES]; /* share entry strings */

} SRV_SHARE_INFO_1;

/* SRV_SHARE_INFO_CTR */
typedef struct srv_share_info_1_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_share_ctr;       /* pointer to share info union */
	union
    {
		SRV_SHARE_INFO_1 info1; /* file info with 0 entries */

    } share;

} SRV_SHARE_INFO_CTR;

/* SRV_Q_NET_SHARE_ENUM */
typedef struct q_net_share_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* server name */

	uint32 share_level;          /* share level */

	SRV_SHARE_INFO_CTR *ctr;     /* share info container */

	uint32 preferred_len;        /* preferred maximum length (0xffff ffff) */

	ENUM_HND enum_hnd;

} SRV_Q_NET_SHARE_ENUM;


/* SRV_R_NET_SHARE_ENUM */
typedef struct r_net_share_enum_info
{
	uint32 share_level;          /* share level */
	SRV_SHARE_INFO_CTR *ctr;     /* share info container */

	uint32 total_entries;                    /* total number of entries */
	ENUM_HND enum_hnd;

	uint32 status;               /* return status */

} SRV_R_NET_SHARE_ENUM;

/* FILE_INFO_3 (level 3 file info strings) */
typedef struct file_info3_info
{
	uint32 id;            /* file index */
	uint32 perms;         /* file permissions. don't know what format */
	uint32 num_locks;     /* file locks */
	uint32 ptr_path_name; /* file name */
	uint32 ptr_user_name; /* file owner */

} FILE_INFO_3;

/* FILE_INFO_3_STR (level 3 file info strings) */
typedef struct str_file_info3_info
{
	UNISTR2 uni_path_name; /* unicode string of file name */
	UNISTR2 uni_user_name; /* unicode string of file owner. */

} FILE_INFO_3_STR;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_FILE_ENTRIES 32

/* SRV_FILE_INFO_3 */
typedef struct srv_file_info_3
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_file_info;                        /* Buffer */

	uint32 num_entries_read2;                    /* EntriesRead */

	FILE_INFO_3     info_3    [MAX_FILE_ENTRIES]; /* file entry details */
	FILE_INFO_3_STR info_3_str[MAX_FILE_ENTRIES]; /* file entry strings */

} SRV_FILE_INFO_3;

/* SRV_FILE_INFO_CTR */
typedef struct srv_file_info_3_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_file_ctr;       /* pointer to file info union */
	union
    {
		SRV_FILE_INFO_3 info3; /* file info with 0 entries */

    } file;

} SRV_FILE_INFO_CTR;


/* SRV_Q_NET_FILE_ENUM */
typedef struct q_net_file_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* server name */

	uint32 ptr_qual_name;         /* pointer (to qualifier name) */
	UNISTR2 uni_qual_name;        /* qualifier name "\\qualifier" */

	uint32 file_level;          /* file level */

	SRV_FILE_INFO_CTR *ctr;

	uint32 preferred_len; /* preferred maximum length (0xffff ffff) */
	ENUM_HND enum_hnd;

} SRV_Q_NET_FILE_ENUM;


/* SRV_R_NET_FILE_ENUM */
typedef struct r_net_file_enum_info
{
	uint32 file_level;          /* file level */

	SRV_FILE_INFO_CTR *ctr;

	uint32 total_entries;                    /* total number of files */
	ENUM_HND enum_hnd;

	uint32 status;        /* return status */

} SRV_R_NET_FILE_ENUM;

/* SRV_INFO_101 */
typedef struct srv_info_101_info
{
	uint32 platform_id;     /* 0x500 */
	uint32 ptr_name;        /* pointer to server name */
	uint32 ver_major;       /* 0x4 */
	uint32 ver_minor;       /* 0x2 */
	uint32 srv_type;        /* browse etc type */
	uint32 ptr_comment;     /* pointer to server comment */

	UNISTR2 uni_name;       /* server name "server" */
	UNISTR2 uni_comment;    /* server comment "samba x.x.x blah" */

} SRV_INFO_101;

/* SRV_INFO_102  */
typedef struct srv_info_102_info
{
	uint32 platform_id;     /* 0x500 */
	uint32 ptr_name;        /* pointer to server name */
	uint32 ver_major;       /* 0x4 */
	uint32 ver_minor;       /* 0x2 */
	uint32 srv_type;        /* browse etc type */
	uint32 ptr_comment;     /* pointer to server comment */
	uint32 users;           /* 0xffff ffff*/
	uint32 disc;            /* 0xf */
	uint32 hidden;          /* 0x0 */
	uint32 announce;        /* 240 */
	uint32 ann_delta;       /* 3000 */
	uint32 licenses;        /* 0 */
	uint32 ptr_usr_path;    /* pointer to user path */

	UNISTR2 uni_name;       /* server name "server" */
	UNISTR2 uni_comment;    /* server comment "samba x.x.x blah" */
	UNISTR2 uni_usr_path;   /* "c:\" (eh?) */

} SRV_INFO_102;


/* SRV_INFO_CTR */
typedef struct srv_info_ctr_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_srv_ctr;         /* pointer to server info */
	union
    {
		SRV_INFO_102 sv102; /* server info level 102 */
		SRV_INFO_101 sv101; /* server info level 101 */

    } srv;

} SRV_INFO_CTR;

/* SRV_Q_NET_SRV_GET_INFO */
typedef struct q_net_srv_get_info
{
	uint32  ptr_srv_name;
	UNISTR2 uni_srv_name; /* "\\server" */
	uint32  switch_value;

} SRV_Q_NET_SRV_GET_INFO;

/* SRV_R_NET_SRV_GET_INFO */
typedef struct r_net_srv_get_info
{
	SRV_INFO_CTR *ctr;

	uint32 status;               /* return status */

} SRV_R_NET_SRV_GET_INFO;

/* SRV_Q_NET_SRV_SET_INFO */
typedef struct q_net_srv_set_info
{
	uint32  ptr_srv_name;
	UNISTR2 uni_srv_name; /* "\\server" */
	uint32  switch_value;

	SRV_INFO_CTR *ctr;

} SRV_Q_NET_SRV_SET_INFO;


/* SRV_R_NET_SRV_SET_INFO */
typedef struct r_net_srv_set_info
{
	uint32 switch_value;         /* switch value */

	uint32 status;               /* return status */

} SRV_R_NET_SRV_SET_INFO;


/* SAMR_Q_CLOSE_HND - probably a policy handle close */
typedef struct q_samr_close_hnd_info
{
    POLICY_HND pol;          /* policy handle */

} SAMR_Q_CLOSE_HND;


/* SAMR_R_CLOSE_HND - probably a policy handle close */
typedef struct r_samr_close_hnd_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} SAMR_R_CLOSE_HND;


/****************************************************************************
SAMR_Q_UNKNOWN_3 - info level 4.  returns SIDs.
*****************************************************************************/

/* SAMR_Q_UNKNOWN_3 - probably get domain info... */
typedef struct q_samr_unknown_3_info
{
    POLICY_HND pol;          /* policy handle */
	uint16 switch_value;     /* 0x0000 0004 */
	/* uint8 pad[2] */

} SAMR_Q_UNKNOWN_3;

#define MAX_SAM_SIDS 15

/* SAM_SID_STUFF */
typedef struct sid_stuff_info
{
	uint16 unknown_2; /* 0x0001 */
	uint16 unknown_3; /* 0x8004 */

	uint8 padding1[8];

	uint32 unknown_4; /* 0x0000 0014 */
	uint32 unknown_5; /* 0x0000 0014 */

	uint16 unknown_6; /* 0x0002 */
	uint16 unknown_7; /* 0x5800 */

	uint32 num_sids;

	uint16 padding2;

	DOM_SID3 sid[MAX_SAM_SIDS];

} SAM_SID_STUFF;

/* SAMR_R_UNKNOWN_3 - probably an open */
typedef struct r_samr_unknown_3_info
{
	uint32 ptr_0;
	uint32 sid_stuff_len0;

	uint32 ptr_1;
	uint32 sid_stuff_len1;

	SAM_SID_STUFF sid_stuff;

	uint32 status;         /* return status */

} SAMR_R_UNKNOWN_3;


/****************************************************************************
SAMR_Q_OPEN_DOMAIN - unknown_0 values seen associated with SIDs:

0x0000 03f1 and a specific   domain sid - S-1-5-21-44c01ca6-797e5c3d-33f83fd0
0x0000 0200 and a specific   domain sid - S-1-5-21-44c01ca6-797e5c3d-33f83fd0
*****************************************************************************/

/* SAMR_Q_OPEN_DOMAIN - probably an open secret */
typedef struct q_samr_open_domain_info
{
    POLICY_HND pol;           /* policy handle */
	uint32 rid;               /* 0x2000 0000; 0x0000 0211; 0x0000 0280; 0x0000 0200 - a RID? */
	DOM_SID2 dom_sid;         /* domain SID */

} SAMR_Q_OPEN_DOMAIN;


/* SAMR_R_OPEN_DOMAIN - probably an open */
typedef struct r_samr_open_domain_info
{
    POLICY_HND pol;        /* policy handle associated with the SID */
	uint32 status;         /* return status */

} SAMR_R_OPEN_DOMAIN;


#define MAX_SAM_ENTRIES 250

typedef struct samr_entry_info
{
	uint32 rid;
	UNIHDR hdr_name;

} SAM_ENTRY;

/* SAMR_Q_ENUM_DOM_USERS - SAM rids and names */
typedef struct q_samr_enum_dom_users_info
{
	POLICY_HND pol;          /* policy handle */

	uint16 req_num_entries;   /* number of values (0 indicates unlimited?) */
	uint16 unknown_0;         /* enumeration context? */
	uint16 acb_mask;          /* 0x0000 indicates all */
	uint16 unknown_1;         /* 0x0000 */

	uint32 max_size;              /* 0x0000 ffff */

} SAMR_Q_ENUM_DOM_USERS;


/* SAMR_R_ENUM_DOM_USERS - SAM rids and names */
typedef struct r_samr_enum_dom_users_info
{
	uint16 total_num_entries;  /* number of entries that match without the acb mask */
	uint16 unknown_0;          /* same as unknown_0 (enum context?) in request */
	uint32 ptr_entries1;       /* actual number of entries to follow, having masked some out */

	uint32 num_entries2;
	uint32 ptr_entries2;

	uint32 num_entries3;

	SAM_ENTRY sam[MAX_SAM_ENTRIES];
	UNISTR2 uni_acct_name[MAX_SAM_ENTRIES];

	uint32 num_entries4;

	uint32 status;

} SAMR_R_ENUM_DOM_USERS;


typedef struct samr_entry_info3
{
	uint32 grp_idx;

	uint32 rid_grp;
	uint32 attr;

	UNIHDR hdr_grp_name;
	UNIHDR hdr_grp_desc;

} SAM_ENTRY3;

typedef struct samr_str_entry_info3
{
	UNISTR2 uni_grp_name;
	UNISTR2 uni_grp_desc;

} SAM_STR3;

/* SAMR_Q_ENUM_DOM_GROUPS - SAM rids and names */
typedef struct q_samr_enum_dom_groups_info
{
	POLICY_HND pol;          /* policy handle */

	/* these are possibly an enumeration context handle... */
	uint16 switch_level;      /* 0x0003 */
	uint16 unknown_0;         /* 0x0000 */
	uint32 start_idx;       /* presumably the start enumeration index */
	uint32 unknown_1;       /* 0x0000 07d0 */

	uint32 max_size;        /* 0x0000 7fff */

} SAMR_Q_ENUM_DOM_GROUPS;


/* SAMR_R_ENUM_DOM_GROUPS - SAM rids and names */
typedef struct r_samr_enum_dom_groups_info
{
	uint32 unknown_0;        /* 0x0000 0492 or 0x0000 00be */
	uint32 unknown_1;        /* 0x0000 049a or 0x0000 00be */
	uint32 switch_level;     /* 0x0000 0003 */

	uint32 num_entries;
	uint32 ptr_entries;

	uint32 num_entries2;

	SAM_ENTRY3 sam[MAX_SAM_ENTRIES];
	SAM_STR3   str[MAX_SAM_ENTRIES];

	uint32 status;

} SAMR_R_ENUM_DOM_GROUPS;



/* SAMR_Q_ENUM_DOM_ALIASES - SAM rids and names */
typedef struct q_samr_enum_dom_aliases_info
{
	POLICY_HND pol;          /* policy handle */

	/* this is possibly an enumeration context handle... */
	uint32 unknown_0;         /* 0x0000 0000 */

	uint32 max_size;              /* 0x0000 ffff */

} SAMR_Q_ENUM_DOM_ALIASES;

/* SAMR_R_ENUM_DOM_ALIASES - SAM rids and names */
typedef struct r_samr_enum_dom_aliases_info
{
	uint32 num_entries;
	uint32 ptr_entries;

	uint32 num_entries2;
	uint32 ptr_entries2;

	uint32 num_entries3;

	SAM_ENTRY sam[MAX_SAM_ENTRIES];
	UNISTR2 uni_grp_name[MAX_SAM_ENTRIES];

	uint32 num_entries4;

	uint32 status;

} SAMR_R_ENUM_DOM_ALIASES;



/* SAMR_Q_QUERY_DISPINFO - SAM rids, names and descriptions */
typedef struct q_samr_query_disp_info
{
	POLICY_HND pol;        /* policy handle */

	uint16 switch_level;    /* 0x0001 and 0x0002 seen */
	uint16 unknown_0;       /* 0x0000 and 0x2000 seen */
	uint32 start_idx;       /* presumably the start enumeration index */
	uint32 unknown_1;       /* 0x0000 07d0, 0x0000 0400 and 0x0000 0200 seen */

	uint32 max_size;        /* 0x0000 7fff, 0x0000 7ffe and 0x0000 3fff seen*/

} SAMR_Q_QUERY_DISPINFO;

typedef struct samr_entry_info1
{
	uint32 user_idx;

	uint32 rid_user;
	uint16 acb_info;
	uint16 pad;

	UNIHDR hdr_acct_name;
	UNIHDR hdr_user_name;
	UNIHDR hdr_user_desc;

} SAM_ENTRY1;

typedef struct samr_str_entry_info1
{
	UNISTR2 uni_acct_name;
	UNISTR2 uni_full_name;
	UNISTR2 uni_acct_desc;

} SAM_STR1;

typedef struct sam_entry_info_1
{
	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;

	SAM_ENTRY1 sam[MAX_SAM_ENTRIES];
	SAM_STR1   str[MAX_SAM_ENTRIES];


} SAM_INFO_1;

typedef struct samr_entry_info2
{
	uint32 user_idx;

	uint32 rid_user;
	uint16 acb_info;
	uint16 pad;

	UNIHDR hdr_srv_name;
	UNIHDR hdr_srv_desc;

} SAM_ENTRY2;

typedef struct samr_str_entry_info2
{
	UNISTR2 uni_srv_name;
	UNISTR2 uni_srv_desc;

} SAM_STR2;

typedef struct sam_entry_info_2
{
	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;

	SAM_ENTRY2 sam[MAX_SAM_ENTRIES];
	SAM_STR2   str[MAX_SAM_ENTRIES];

} SAM_INFO_2;

typedef struct sam_info_ctr_info
{
	union
	{
		SAM_INFO_1 *info1; /* server info */
		SAM_INFO_2 *info2; /* user info */
		void       *info; /* allows assignment without typecasting, */

	} sam;

} SAM_INFO_CTR;

/* SAMR_R_QUERY_DISPINFO - SAM rids, names and descriptions */
typedef struct r_samr_query_dispinfo_info
{
	uint32 unknown_0;        /* container length? 0x0000 0492 or 0x0000 00be */
	uint32 unknown_1;        /* container length? 0x0000 049a or 0x0000 00be */
	uint16 switch_level;     /* 0x0001 or 0x0002 */
	/*uint8 pad[2] */

	SAM_INFO_CTR *ctr;

	uint32 status;

} SAMR_R_QUERY_DISPINFO;



/* SAMR_Q_QUERY_ALIASINFO - SAM Alias Info */
typedef struct q_samr_enum_alias_info
{
	POLICY_HND pol;        /* policy handle */

	uint16 switch_level;    /* 0x0003 seen */

} SAMR_Q_QUERY_ALIASINFO;

typedef struct samr_alias_info3
{
	UNIHDR hdr_acct_desc;
	UNISTR2 uni_acct_desc;

} ALIAS_INFO3;

/* SAMR_R_QUERY_ALIASINFO - SAM rids, names and descriptions */
typedef struct r_samr_query_aliasinfo_info
{
	uint32 ptr;        
	uint16 switch_value;     /* 0x0003 */
	/* uint8[2] padding */

	union
    {
		ALIAS_INFO3 info3;

    } alias;

	uint32 status;

} SAMR_R_QUERY_ALIASINFO;


/* SAMR_Q_QUERY_USERGROUPS - */
typedef struct q_samr_query_usergroup_info
{
    POLICY_HND pol;          /* policy handle associated with unknown id */

} SAMR_Q_QUERY_USERGROUPS;

/* SAMR_R_QUERY_USERGROUPS - probably a get sam info */
typedef struct r_samr_query_usergroup_info
{
	uint32 ptr_0;            /* pointer */
	uint32 num_entries;      /* number of RID groups */
	uint32 ptr_1;            /* pointer */
	uint32 num_entries2;     /* number of RID groups */

	DOM_GID *gid; /* group info */

	uint32 status;         /* return status */

} SAMR_R_QUERY_USERGROUPS;


/* SAMR_Q_QUERY_USERINFO - probably a get sam info */
typedef struct q_samr_query_user_info
{
    POLICY_HND pol;          /* policy handle associated with unknown id */
	uint16 switch_value;         /* 0x0015, 0x0011 or 0x0010 - 16 bit unknown */

} SAMR_Q_QUERY_USERINFO;

/* SAMR_R_QUERY_USERINFO - probably a get sam info */
typedef struct r_samr_query_user_info
{
	uint32 ptr;            /* pointer */
	uint16 switch_value;      /* 0x0015, 0x0011 or 0x0010 - same as in query */
	/* uint8[2] padding. */

	union
	{
		SAM_USER_INFO_10 *id10; /* auth-level 10 */
		SAM_USER_INFO_11 *id11; /* auth-level 11 */
		SAM_USER_INFO_15 *id15; /* auth-level 15 */
		void* id; /* to make typecasting easy */

	} info;

	uint32 status;         /* return status */

} SAMR_R_QUERY_USERINFO;


/****************************************************************************
SAMR_Q_LOOKUP_IDS - do a conversion (only one!) from name to RID.

the policy handle allocated by an "samr open secret" call is associated
with a SID.  this policy handle is what is queried here, *not* the SID
itself.  the response to the lookup rids is relative to this SID.
*****************************************************************************/
/* SAMR_Q_LOOKUP_IDS */
typedef struct q_samr_lookup_ids_info
{
    POLICY_HND pol;       /* policy handle */

	uint32 num_sids1;      /* number of rids being looked up */
	uint32 ptr;            /* buffer pointer */
	uint32 num_sids2;      /* number of rids being looked up */

	uint32   ptr_sid[MAX_LOOKUP_SIDS]; /* pointers to sids to be looked up */
	DOM_SID2 sid    [MAX_LOOKUP_SIDS]; /* sids to be looked up. */

} SAMR_Q_LOOKUP_IDS;


/* SAMR_R_LOOKUP_IDS */
typedef struct r_samr_lookup_ids_info
{
	uint32 num_entries;
	uint32 ptr; /* undocumented buffer pointer */

	uint32 num_entries2; 
	uint32 rid[MAX_LOOKUP_SIDS]; /* domain RIDs being looked up */

	uint32 status; /* return code */

} SAMR_R_LOOKUP_IDS;


/****************************************************************************
SAMR_Q_LOOKUP_NAMES - do a conversion from SID to RID.

the policy handle allocated by an "samr open secret" call is associated
with a SID.  this policy handle is what is queried here, *not* the SID
itself.  the response to the lookup rids is relative to this SID.
*****************************************************************************/
/* SAMR_Q_LOOKUP_NAMES */
typedef struct q_samr_lookup_names_info
{
    POLICY_HND pol;       /* policy handle */

	uint32 num_rids1;      /* number of rids being looked up */
	uint32 rid;            /* 0x0000 03e8 - RID of the server doing the query? */
	uint32 ptr;            /* 0x0000 0000 - 32 bit unknown */
	uint32 num_rids2;      /* number of rids being looked up */

	UNIHDR  hdr_user_name[MAX_LOOKUP_SIDS]; /* unicode account name header */
	UNISTR2 uni_user_name[MAX_LOOKUP_SIDS]; /* unicode account name string */

} SAMR_Q_LOOKUP_NAMES;


/* SAMR_R_LOOKUP_NAMES */
typedef struct r_samr_lookup_names_info
{
	uint32 num_entries;
	uint32 undoc_buffer; /* undocumented buffer pointer */

	uint32 num_entries2; 
	DOM_RID3 dom_rid[MAX_LOOKUP_SIDS]; /* domain RIDs being looked up */

	uint32 num_entries3; 

	uint32 status; /* return code */

} SAMR_R_LOOKUP_NAMES;


/****************************************************************************
SAMR_Q_UNKNOWN_12 - do a conversion from RID groups to something.

called to resolve domain RID groups.
*****************************************************************************/
/* SAMR_Q_UNKNOWN_12 */
typedef struct q_samr_unknown_12_info
{
    POLICY_HND pol;       /* policy handle */

	uint32 num_gids1;      /* number of rids being looked up */
	uint32 rid;            /* 0x0000 03e8 - RID of the server doing the query? */
	uint32 ptr;            /* 0x0000 0000 - 32 bit unknown */
	uint32 num_gids2;      /* number of rids being looked up */

	uint32 gid[MAX_LOOKUP_SIDS]; /* domain RIDs being looked up */

} SAMR_Q_UNKNOWN_12;


/****************************************************************************
SAMR_R_UNKNOWN_12 - do a conversion from group RID to names

*****************************************************************************/
/* SAMR_R_UNKNOWN_12 */
typedef struct r_samr_unknown_12_info
{
    POLICY_HND pol;       /* policy handle */

	uint32 num_aliases1;      /* number of aliases being looked up */
	uint32 ptr_aliases;       /* pointer to aliases */
	uint32 num_aliases2;      /* number of aliases being looked up */

	UNIHDR  hdr_als_name[MAX_LOOKUP_SIDS]; /* unicode account name header */
	UNISTR2 uni_als_name[MAX_LOOKUP_SIDS]; /* unicode account name string */

	uint32 num_als_usrs1;      /* number of users in aliases being looked up */
	uint32 ptr_als_usrs;       /* pointer to users in aliases */
	uint32 num_als_usrs2;      /* number of users in aliases being looked up */

	uint32 num_als_usrs[MAX_LOOKUP_SIDS]; /* number of users per group */

	uint32 status;

} SAMR_R_UNKNOWN_12;


/* SAMR_Q_OPEN_USER - probably an open */
typedef struct q_samr_open_user_info
{
    POLICY_HND domain_pol;       /* policy handle */
	uint32 unknown_0;     /* 32 bit unknown - 0x02011b */
	uint32 user_rid;      /* user RID */

} SAMR_Q_OPEN_USER;


/* SAMR_R_OPEN_USER - probably an open */
typedef struct r_samr_open_user_info
{
    POLICY_HND user_pol;       /* policy handle associated with unknown id */
	uint32 status;         /* return status */

} SAMR_R_OPEN_USER;


/* SAMR_Q_UNKNOWN_13 - probably an open alias in domain */
typedef struct q_samr_unknown_13_info
{
    POLICY_HND alias_pol;        /* policy handle */

	uint16 unknown_1;            /* 16 bit unknown - 0x0200 */
	uint16 unknown_2;            /* 16 bit unknown - 0x0000 */

} SAMR_Q_UNKNOWN_13;


/* SAMR_Q_UNKNOWN_21 - probably an open group in domain */
typedef struct q_samr_unknown_21_info
{
    POLICY_HND group_pol;        /* policy handle */

	uint16 unknown_1;            /* 16 bit unknown - 0x0477 */
	uint16 unknown_2;            /* 16 bit unknown - 0x0000 */

} SAMR_Q_UNKNOWN_21;


/* SAMR_Q_UNKNOWN_32 - probably a "create SAM entry" */
typedef struct q_samr_unknown_32_info
{
    POLICY_HND pol;             /* policy handle */

	UNIHDR  hdr_mach_acct;       /* unicode machine account name header */
	UNISTR2 uni_mach_acct;       /* unicode machine account name */

	uint32 acct_ctrl;            /* 32 bit ACB_XXXX */
	uint16 unknown_1;            /* 16 bit unknown - 0x00B0 */
	uint16 unknown_2;            /* 16 bit unknown - 0xe005 */

} SAMR_Q_UNKNOWN_32;


/* SAMR_R_UNKNOWN_32 - probably a "create SAM entry" */
typedef struct r_samr_unknown_32_info
{
    POLICY_HND pol;       /* policy handle */

	/* rid4.unknown - fail: 0030 success: 0x03ff */
	DOM_RID4 rid4;         /* rid and attributes */

	uint32 status;         /* return status - fail: 0xC000 0099: user exists */

} SAMR_R_UNKNOWN_32;


/* SAMR_Q_OPEN_ALIAS - probably an open */
typedef struct q_samr_open_alias_info
{
	uint32 unknown_0;         /* 0x0000 0008 */
	uint32 rid_alias;        /* rid */

} SAMR_Q_OPEN_ALIAS;


/* SAMR_R_OPEN_ALIAS - probably an open */
typedef struct r_samr_open_alias_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} SAMR_R_OPEN_ALIAS;


/* SAMR_Q_CONNECT - probably an open */
typedef struct q_samr_connect_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* unicode server name starting with '\\' */

	uint32 unknown_0;            /* 32 bit unknown */

} SAMR_Q_CONNECT;


/* SAMR_R_CONNECT - probably an open */
typedef struct r_samr_connect_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} SAMR_R_CONNECT;



/* REG_Q_OPEN_POLICY */
typedef struct q_reg_open_policy_info
{
	uint32 ptr;
	uint16 unknown_0; /* 0x5da0      - 16 bit unknown */
	uint32 level;     /* 0x0000 0001 - 32 bit unknown */
	uint16 unknown_1; /* 0x0200      - 16 bit unknown */

} REG_Q_OPEN_POLICY;

/* REG_R_OPEN_POLICY */
typedef struct r_reg_open_policy_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} REG_R_OPEN_POLICY;


/* REG_Q_CLOSE */
typedef struct reg_q_close_info
{
	POLICY_HND pol; /* policy handle */

} REG_Q_CLOSE;

/* REG_R_CLOSE */
typedef struct reg_r_close_info
{
	POLICY_HND pol; /* policy handle.  should be all zeros. */

	uint32 status; /* return code */

} REG_R_CLOSE;


/* REG_Q_INFO */
typedef struct q_reg_info_info
{
    POLICY_HND pol;        /* policy handle */

	UNIHDR  hdr_type;       /* unicode product type header */
	UNISTR2 uni_type;       /* unicode product type - "ProductType" */

	uint32 ptr1;            /* pointer */
	NTTIME time;            /* current time? */
	uint8  major_version1;  /* 0x4 - os major version? */
	uint8  minor_version1;  /* 0x1 - os minor version? */
	uint8  pad1[10];        /* padding - zeros */

	uint32 ptr2;            /* pointer */
	uint8  major_version2;  /* 0x4 - os major version? */
	uint8  minor_version2;  /* 0x1 - os minor version? */
	uint8  pad2[2];         /* padding - zeros */

	uint32 ptr3;            /* pointer */
	uint32 unknown;         /* 0x0000 0000 */

} REG_Q_INFO;

/* REG_R_INFO */
typedef struct r_reg_info_info
{ 
	uint32 ptr1;            /* buffer pointer */
	uint32 level;          /* 0x1 - info level? */

	uint32     ptr_type;       /* pointer to o/s type */
	UNINOTSTR2 uni_type;      /* unicode string o/s type - "LanmanNT" */

	uint32 ptr2;           /* pointer to unknown_0 */
	uint32 unknown_0;      /* 0x12 */

	uint32 ptr3;           /* pointer to unknown_1 */
	uint32 unknown_1;      /* 0x12 */

	uint32 status;         /* return status */

} REG_R_INFO;


/* REG_Q_OPEN_ENTRY */
typedef struct q_reg_open_entry_info
{
    POLICY_HND pol;        /* policy handle */

	UNIHDR  hdr_name;       /* unicode registry string header */
	UNISTR2 uni_name;       /* unicode registry string name */

	uint32 unknown_0;       /* 32 bit unknown - 0x0000 0000 */
	uint16 unknown_1;       /* 16 bit unknown - 0x0000 */
	uint16 unknown_2;       /* 16 bit unknown - 0x0200 */

} REG_Q_OPEN_ENTRY;



/* REG_R_OPEN_ENTRY */
typedef struct r_reg_open_entry_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} REG_R_OPEN_ENTRY;


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


#endif /* _NT_DOMAIN_H */


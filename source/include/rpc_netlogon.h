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

#ifndef _RPC_NETLOGON_H /* _RPC_NETLOGON_H */
#define _RPC_NETLOGON_H 


/* NETLOGON pipe */
#define NET_SAMLOGON           0x02
#define NET_SAMLOGOFF          0x03
#define NET_REQCHAL            0x04
#define NET_AUTH               0x05
#define NET_SRVPWSET           0x06
#define NET_SAM_DELTAS         0x07
#define NET_LOGON_CTRL         0x0c
#define NET_AUTH2              0x0f
#define NET_LOGON_CTRL2        0x0e
#define NET_SAM_SYNC           0x10
#define NET_TRUST_DOM_LIST     0x13

/* Secure Channel types.  used in NetrServerAuthenticate negotiation */
#define SEC_CHAN_WKSTA   2
#define SEC_CHAN_DOMAIN  4
#define SEC_CHAN_BDC     6

/* Returned delta types */
#define SAM_DELTA_DOMAIN_INFO  0x01 /* Domain */
#define SAM_DELTA_GROUP_INFO   0x02 /* Domain groups */
#define SAM_DELTA_ACCOUNT_INFO 0x05 /* Users */
#define SAM_DELTA_GROUP_MEM    0x08 /* Group membership */
#define SAM_DELTA_ALIAS_INFO   0x09 /* Local groups */
#define SAM_DELTA_ALIAS_MEM    0x0C /* Local group membership */
#define SAM_DELTA_UNKNOWN      0x0D /* Privilige stuff */
#define SAM_DELTA_UNKNOWN2     0x10 /* Privilige stuff */
#define SAM_DELTA_SAM_STAMP    0x16 /* Some kind of journal record? */

/* SAM database types */
#define SAM_DATABASE_DOMAIN    0x00 /* Domain users and groups */
#define SAM_DATABASE_BUILTIN   0x01 /* BUILTIN users and groups */
#define SAM_DATABASE_PRIVS     0x02 /* Priviliges? */

#if 0
/* I think this is correct - it's what gets parsed on the wire. JRA. */
/* NET_USER_INFO_2 */
typedef struct net_user_info_2
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

	UNISTR2 uni_user_name;    /* username unicode string */
	UNISTR2 uni_full_name;    /* user's full name unicode string */
	UNISTR2 uni_logon_script; /* logon script unicode string */
	UNISTR2 uni_profile_path; /* profile path unicode string */
	UNISTR2 uni_home_dir;     /* home directory unicode string */
	UNISTR2 uni_dir_drive;    /* home directory drive unicode string */

	uint32 num_groups2;        /* num groups */
	DOM_GID *gids; /* group info */

	UNISTR2 uni_logon_srv; /* logon server unicode string */
	UNISTR2 uni_logon_dom; /* logon domain unicode string */

	DOM_SID2 dom_sid;           /* domain SID */

	uint32 num_other_groups;        /* other groups */
	DOM_GID *other_gids; /* group info */
	DOM_SID2 *other_sids; /* undocumented - domain SIDs */

} NET_USER_INFO_2;
#endif

/* NET_USER_INFO_3 */
typedef struct net_user_info_3
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

	uint32 user_rid;       /* User RID */
	uint32 group_rid;      /* Group RID */

	uint32 num_groups;    /* num groups */
	uint32 buffer_groups; /* undocumented buffer pointer to groups. */
	uint32 user_flgs;     /* user flags */

	uint8 user_sess_key[16]; /* unused user session key */

	UNIHDR hdr_logon_srv; /* logon server unicode string header */
	UNIHDR hdr_logon_dom; /* logon domain unicode string header */

	uint32 buffer_dom_id; /* undocumented logon domain id pointer */
	uint8 padding[40];    /* unused padding bytes.  expansion room */

	uint32 num_other_sids; /* number of foreign/trusted domain sids */
	uint32 buffer_other_sids;
	
	UNISTR2 uni_user_name;    /* username unicode string */
	UNISTR2 uni_full_name;    /* user's full name unicode string */
	UNISTR2 uni_logon_script; /* logon script unicode string */
	UNISTR2 uni_profile_path; /* profile path unicode string */
	UNISTR2 uni_home_dir;     /* home directory unicode string */
	UNISTR2 uni_dir_drive;    /* home directory drive unicode string */

	uint32 num_groups2;        /* num groups */
	DOM_GID *gids; /* group info */

	UNISTR2 uni_logon_srv; /* logon server unicode string */
	UNISTR2 uni_logon_dom; /* logon domain unicode string */

	DOM_SID2 dom_sid;           /* domain SID */

	uint32 num_other_groups;        /* other groups */
	DOM_GID *other_gids; /* group info */
	DOM_SID2 *other_sids; /* foreign/trusted domain SIDs */

} NET_USER_INFO_3;


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

/********************************************************
 Logon Control Query

 This is generated by a nltest /bdc_query:DOMAIN

 query_level 0x1, function_code 0x1

 ********************************************************/

/* NET_Q_LOGON_CTRL - LSA Netr Logon Control */

typedef struct net_q_logon_ctrl_info
{
	uint32 ptr;
	UNISTR2 uni_server_name;
	uint32 function_code;
	uint32 query_level;
} NET_Q_LOGON_CTRL;

/* NET_R_LOGON_CTRL - LSA Netr Logon Control */

typedef struct net_r_logon_ctrl_info
{
	uint32 switch_value;
	uint32 ptr;

	union {
		NETLOGON_INFO_1 info1;
	} logon;

	NTSTATUS status;
} NET_R_LOGON_CTRL;

/********************************************************
 Logon Control2 Query

 query_level 0x1 - pdc status
 query_level 0x3 - number of logon attempts.

 ********************************************************/

/* NET_Q_LOGON_CTRL2 - LSA Netr Logon Control 2 */
typedef struct net_q_logon_ctrl2_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x1 */
	uint32       query_level;   /* 0x1, 0x3 */
	uint32       switch_value;  /* 0x1 */

} NET_Q_LOGON_CTRL2;

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

	NTSTATUS status; /* return code */

} NET_R_LOGON_CTRL2;

/* NET_Q_TRUST_DOM_LIST - LSA Query Trusted Domains */
typedef struct net_q_trust_dom_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */

} NET_Q_TRUST_DOM_LIST;

#define MAX_TRUST_DOMS 1

/* NET_R_TRUST_DOM_LIST - response to LSA Trusted Domains */
typedef struct net_r_trust_dom_info
{
	UNISTR2 uni_trust_dom_name[MAX_TRUST_DOMS];

	NTSTATUS status; /* return code */

} NET_R_TRUST_DOM_LIST;


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
	NTSTATUS status; /* return code */
} NET_R_REQ_CHAL;

/* NET_Q_AUTH */
typedef struct net_q_auth_info
{
	DOM_LOG_INFO clnt_id; /* client identification info */
	DOM_CHAL clnt_chal;     /* client-calculated credentials */
} NET_Q_AUTH;

/* NET_R_AUTH */
typedef struct net_r_auth_info
{
	DOM_CHAL srv_chal;     /* server-calculated credentials */
	NTSTATUS status; /* return code */
} NET_R_AUTH;

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
	NTSTATUS status; /* return code */
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

  NTSTATUS status; /* return code */

} NET_R_SRV_PWSET;

/* NET_ID_INFO_2 */
typedef struct net_network_info_2
{
	uint32            ptr_id_info2;        /* pointer to id_info_2 */
	UNIHDR            hdr_domain_name;     /* domain name unicode header */
	uint32            param_ctrl;          /* param control (0x2) */
	DOM_LOGON_ID      logon_id;            /* logon ID */
	UNIHDR            hdr_user_name;       /* user name unicode header */
	UNIHDR            hdr_wksta_name;      /* workstation name unicode header */
	uint8             lm_chal[8];          /* lan manager 8 byte challenge */
	STRHDR            hdr_nt_chal_resp;    /* nt challenge response */
	STRHDR            hdr_lm_chal_resp;    /* lm challenge response */

	UNISTR2           uni_domain_name;     /* domain name unicode string */
	UNISTR2           uni_user_name;       /* user name unicode string */
	UNISTR2           uni_wksta_name;      /* workgroup name unicode string */
	STRING2           nt_chal_resp;        /* nt challenge response */
	STRING2           lm_chal_resp;        /* lm challenge response */

} NET_ID_INFO_2;

/* NET_ID_INFO_1 */
typedef struct id_info_1
{
	uint32            ptr_id_info1;        /* pointer to id_info_1 */
	UNIHDR            hdr_domain_name;     /* domain name unicode header */
	uint32            param_ctrl;          /* param control */
	DOM_LOGON_ID      logon_id;            /* logon ID */
	UNIHDR            hdr_user_name;       /* user name unicode header */
	UNIHDR            hdr_wksta_name;      /* workstation name unicode header */
	OWF_INFO          lm_owf;              /* LM OWF Password */
	OWF_INFO          nt_owf;              /* NT OWF Password */
	UNISTR2           uni_domain_name;     /* domain name unicode string */
	UNISTR2           uni_user_name;       /* user name unicode string */
	UNISTR2           uni_wksta_name;      /* workgroup name unicode string */

} NET_ID_INFO_1;

#define INTERACTIVE_LOGON_TYPE 1
#define NET_LOGON_TYPE 2

/* NET_ID_INFO_CTR */
typedef struct net_id_info_ctr_info
{
  uint16         switch_value;
  
  union
  {
    NET_ID_INFO_1 id1; /* auth-level 1 - interactive user login */
    NET_ID_INFO_2 id2; /* auth-level 2 - workstation referred login */

  } auth;
  
} NET_ID_INFO_CTR;

/* SAM_INFO - sam logon/off id structure */
typedef struct sam_info
{
  DOM_CLNT_INFO2  client;
  uint32          ptr_rtn_cred; /* pointer to return credentials */
  DOM_CRED        rtn_cred; /* return credentials */
  uint16          logon_level;
  NET_ID_INFO_CTR *ctr;

} DOM_SAM_INFO;

/* NET_Q_SAM_LOGON */
typedef struct net_q_sam_logon_info
{
    DOM_SAM_INFO sam_id;
	uint16          validation_level;

} NET_Q_SAM_LOGON;

/* NET_R_SAM_LOGON */
typedef struct net_r_sam_logon_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
	uint16 switch_value; /* 3 - indicates type of USER INFO */
    NET_USER_INFO_3 *user;

    uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */

  NTSTATUS status; /* return code */

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
    
  NTSTATUS status; /* return code */

} NET_R_SAM_LOGOFF;

/* NET_Q_SAM_SYNC */
typedef struct net_q_sam_sync_info
{
	UNISTR2 uni_srv_name; /* \\PDC */
	UNISTR2 uni_cli_name; /* BDC */
	DOM_CRED cli_creds;
	DOM_CRED ret_creds;

	uint32 database_id;
	uint32 restart_state;
	uint32 sync_context;

	uint32 max_size;       /* preferred maximum length */

} NET_Q_SAM_SYNC;

/* SAM_DELTA_HDR */
typedef struct sam_delta_hdr_info
{
	uint16 type;  /* type of structure attached */
	uint16 type2;
	uint32 target_rid;

	uint32 type3;
	uint32 ptr_delta;

} SAM_DELTA_HDR;

/* SAM_DOMAIN_INFO (0x1) */
typedef struct sam_domain_info_info
{
	UNIHDR hdr_dom_name;
	UNIHDR hdr_oem_info;

	UINT64_S force_logoff;
	uint16   min_pwd_len;
	uint16   pwd_history_len;
	UINT64_S max_pwd_age;
	UINT64_S min_pwd_age;
	UINT64_S dom_mod_count;
	NTTIME   creation_time;

	BUFHDR2 hdr_sec_desc; /* security descriptor */
	UNIHDR hdr_unknown;
	uint8 reserved[40];

	UNISTR2 uni_dom_name;
	UNISTR2 buf_oem_info; /* never seen */

	BUFFER4 buf_sec_desc;
	UNISTR2 buf_unknown;

} SAM_DOMAIN_INFO;

/* SAM_GROUP_INFO (0x2) */
typedef struct sam_group_info_info
{
	UNIHDR hdr_grp_name;
	DOM_GID gid;
	UNIHDR hdr_grp_desc;
	BUFHDR2 hdr_sec_desc;  /* security descriptor */
	uint8 reserved[48];

	UNISTR2 uni_grp_name;
	UNISTR2 uni_grp_desc;
	BUFFER4 buf_sec_desc;

} SAM_GROUP_INFO;

/* SAM_PWD */
typedef struct sam_passwd_info
{
	/* this structure probably contains password history */
	/* this is probably a count of lm/nt pairs */
	uint32 unk_0; /* 0x0000 0002 */

	UNIHDR hdr_lm_pwd;
	uint8  buf_lm_pwd[16];

	UNIHDR hdr_nt_pwd;
	uint8  buf_nt_pwd[16];

	UNIHDR hdr_empty_lm;
	UNIHDR hdr_empty_nt;

} SAM_PWD;

/* SAM_ACCOUNT_INFO (0x5) */
typedef struct sam_account_info_info
{
	UNIHDR hdr_acct_name;
	UNIHDR hdr_full_name;

	uint32 user_rid;
	uint32 group_rid;

	UNIHDR hdr_home_dir;
	UNIHDR hdr_dir_drive;
	UNIHDR hdr_logon_script;
	UNIHDR hdr_acct_desc;
	UNIHDR hdr_workstations;

	NTTIME logon_time;
	NTTIME logoff_time;

	uint32 logon_divs; /* 0xA8 */
	uint32 ptr_logon_hrs;

	uint16 bad_pwd_count;
	uint16 logon_count;
	NTTIME pwd_last_set_time;
	NTTIME acct_expiry_time;

	uint32 acb_info;
	uint8 nt_pwd[16];
	uint8 lm_pwd[16];
	uint8 nt_pwd_present;
	uint8 lm_pwd_present;
	uint8 pwd_expired;

	UNIHDR hdr_comment;
	UNIHDR hdr_parameters;
	uint16 country;
	uint16 codepage;

	BUFHDR2 hdr_sec_desc;  /* security descriptor */

	UNIHDR  hdr_profile;
	UNIHDR  hdr_reserved[3];  /* space for more strings */
	uint32  dw_reserved[4];   /* space for more data - first two seem to
				     be an NTTIME */

	UNISTR2 uni_acct_name;
	UNISTR2 uni_full_name;
	UNISTR2 uni_home_dir;
	UNISTR2 uni_dir_drive;
	UNISTR2 uni_logon_script;
	UNISTR2 uni_acct_desc;
	UNISTR2 uni_workstations;

	uint32 unknown1; /* 0x4EC */
	uint32 unknown2; /* 0 */

	BUFFER4 buf_logon_hrs;
	UNISTR2 uni_comment;
	UNISTR2 uni_parameters;
	SAM_PWD pass;
	BUFFER4 buf_sec_desc;
	UNISTR2 uni_profile;

} SAM_ACCOUNT_INFO;

/* SAM_GROUP_MEM_INFO (0x8) */
typedef struct sam_group_mem_info_info
{
	uint32 ptr_rids;
	uint32 ptr_attribs;
	uint32 num_members;
	uint8 unknown[16];

	uint32 num_members2;
	uint32 *rids;

	uint32 num_members3;
	uint32 *attribs;

} SAM_GROUP_MEM_INFO;

/* SAM_ALIAS_INFO (0x9) */
typedef struct sam_alias_info_info
{
	UNIHDR hdr_als_name;
	uint32 als_rid;
	BUFHDR2 hdr_sec_desc;  /* security descriptor */
	UNIHDR hdr_als_desc;
	uint8 reserved[40];

	UNISTR2 uni_als_name;
	BUFFER4 buf_sec_desc;
	UNISTR2 uni_als_desc;

} SAM_ALIAS_INFO;

/* SAM_ALIAS_MEM_INFO (0xC) */
typedef struct sam_alias_mem_info_info
{
	uint32 num_members;
	uint32 ptr_members;
	uint8 unknown[16];

	uint32 num_sids;
	uint32 *ptr_sids;
	DOM_SID2 *sids;

} SAM_ALIAS_MEM_INFO;

/* SAM_DELTA_STAMP (0x16) */
typedef struct
{
        uint32 seqnum;
        uint32 dom_mod_count_ptr;
	UINT64_S dom_mod_count;  /* domain mod count at last sync */
} SAM_DELTA_STAMP;

typedef union sam_delta_ctr_info
{
	SAM_DOMAIN_INFO    domain_info ;
	SAM_GROUP_INFO     group_info  ;
	SAM_ACCOUNT_INFO   account_info;
	SAM_GROUP_MEM_INFO grp_mem_info;
	SAM_ALIAS_INFO     alias_info  ;
	SAM_ALIAS_MEM_INFO als_mem_info;
        SAM_DELTA_STAMP    stamp;
} SAM_DELTA_CTR;

/* NET_R_SAM_SYNC */
typedef struct net_r_sam_sync_info
{
	DOM_CRED srv_creds;

	uint32 sync_context;

	uint32 ptr_deltas;
	uint32 num_deltas;
	uint32 ptr_deltas2;
	uint32 num_deltas2;

	SAM_DELTA_HDR *hdr_deltas;
	SAM_DELTA_CTR *deltas;

	NTSTATUS status;
} NET_R_SAM_SYNC;

/* NET_Q_SAM_DELTAS */
typedef struct net_q_sam_deltas_info
{
	UNISTR2 uni_srv_name;
	UNISTR2 uni_cli_name;
	DOM_CRED cli_creds;
	DOM_CRED ret_creds;

	uint32 database_id;
	UINT64_S dom_mod_count;  /* domain mod count at last sync */

	uint32 max_size;       /* preferred maximum length */

} NET_Q_SAM_DELTAS;

/* NET_R_SAM_DELTAS */
typedef struct net_r_sam_deltas_info
{
	DOM_CRED srv_creds;

	UINT64_S dom_mod_count;   /* new domain mod count */

	uint32 ptr_deltas;
	uint32 num_deltas;
	uint32 num_deltas2;

	SAM_DELTA_HDR *hdr_deltas;
	SAM_DELTA_CTR *deltas;

	NTSTATUS status;
} NET_R_SAM_DELTAS;

#endif /* _RPC_NETLOGON_H */

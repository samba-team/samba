/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jean François Micouleau 2002
   
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

#ifndef _RPC_NETLOGON_H /* _RPC_NETLOGON_H */
#define _RPC_NETLOGON_H 


/* NETLOGON pipe */
#define NET_SAMLOGON		0x02
#define NET_SAMLOGOFF		0x03
#define NET_REQCHAL		0x04
#define NET_AUTH		0x05
#define NET_SRVPWSET		0x06
#define NET_SAM_DELTAS		0x07
#define NET_GETDCNAME		0x0b
#define NET_LOGON_CTRL		0x0c
#define NET_GETANYDCNAME	0x0d
#define NET_AUTH2		0x0f
#define NET_LOGON_CTRL2		0x0e
#define NET_SAM_SYNC		0x10
#define NET_TRUST_DOM_LIST	0x13
#define NET_DSR_GETDCNAME	0x14
#define NET_AUTH3		0x1a
#define NET_DSR_GETDCNAMEEX	0x1b
#define NET_DSR_GETSITENAME	0x1c
#define NET_DSR_GETDCNAMEEX2	0x22
#define NET_SAMLOGON_EX		0x27

/* Returned delta types */
#define SAM_DELTA_DOMAIN_INFO    0x01
#define SAM_DELTA_GROUP_INFO     0x02
#define SAM_DELTA_RENAME_GROUP   0x04
#define SAM_DELTA_ACCOUNT_INFO   0x05
#define SAM_DELTA_RENAME_USER    0x07
#define SAM_DELTA_GROUP_MEM      0x08
#define SAM_DELTA_ALIAS_INFO     0x09
#define SAM_DELTA_RENAME_ALIAS   0x0b
#define SAM_DELTA_ALIAS_MEM      0x0c
#define SAM_DELTA_POLICY_INFO    0x0d
#define SAM_DELTA_TRUST_DOMS     0x0e
#define SAM_DELTA_PRIVS_INFO     0x10 /* DT_DELTA_ACCOUNTS */
#define SAM_DELTA_SECRET_INFO    0x12
#define SAM_DELTA_DELETE_GROUP   0x14
#define SAM_DELTA_DELETE_USER    0x15
#define SAM_DELTA_MODIFIED_COUNT 0x16

/* flags use when sending a NETLOGON_CONTROL request */

#define NETLOGON_CONTROL_SYNC			0x2
#define NETLOGON_CONTROL_REDISCOVER		0x5
#define NETLOGON_CONTROL_TC_QUERY		0x6
#define NETLOGON_CONTROL_TRANSPORT_NOTIFY	0x7
#define NETLOGON_CONTROL_SET_DBFLAG		0xfffe

/* Some flag values reverse engineered from NLTEST.EXE */
/* used in the NETLOGON_CONTROL[2] reply */

#define NL_CTRL_IN_SYNC          0x0000
#define NL_CTRL_REPL_NEEDED      0x0001
#define NL_CTRL_REPL_IN_PROGRESS 0x0002
#define NL_CTRL_FULL_SYNC        0x0004

#define LOGON_KRB5_FAIL_CLOCK_SKEW	0x02000000

/* Flags for controlling the behaviour of a particular logon */

/* sets NETLOGON_SERVER_TRUST_ACCOUNT user_flag */
#if 0
#define MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT	0x00000020
#define MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT	0x00000800

/* updates the "logon time" on network logon */
#define MSV1_0_UPDATE_LOGON_STATISTICS		0x00000004

/* returns the user parameters in the driveletter */
#define MSV1_0_RETURN_USER_PARAMETERS		0x00000008

/* returns the profilepath in the driveletter and 
 * sets LOGON_PROFILE_PATH_RETURNED user_flag */
#define MSV1_0_RETURN_PROFILE_PATH		0x00000200
#endif

#if 0
/* I think this is correct - it's what gets parsed on the wire. JRA. */
/* NET_USER_INFO_2 */
typedef struct net_user_info_2 {
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

/* NET_USER_INFO_2 */
typedef struct net_user_info_2 {
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

	uint8 user_sess_key[16]; /* user session key */

	UNIHDR hdr_logon_srv; /* logon server unicode string header */
	UNIHDR hdr_logon_dom; /* logon domain unicode string header */

	uint32 buffer_dom_id; /* undocumented logon domain id pointer */
	uint8 lm_sess_key[8];	/* lm session key */
	uint32 acct_flags;	/* account flags */
	uint32 unknown[7];	/* unknown */

	UNISTR2 uni_user_name;    /* username unicode string */
	UNISTR2 uni_full_name;    /* user's full name unicode string */
	UNISTR2 uni_logon_script; /* logon script unicode string */
	UNISTR2 uni_profile_path; /* profile path unicode string */
	UNISTR2 uni_home_dir;     /* home directory unicode string */
	UNISTR2 uni_dir_drive;    /* home directory drive unicode string */

	UNISTR2 uni_logon_srv; /* logon server unicode string */
	UNISTR2 uni_logon_dom; /* logon domain unicode string */

	DOM_SID2 dom_sid;           /* domain SID */
} NET_USER_INFO_2;

/* NET_USER_INFO_3 */
typedef struct net_user_info_3 {
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

	uint8 user_sess_key[16]; /* user session key */

	UNIHDR hdr_logon_srv; /* logon server unicode string header */
	UNIHDR hdr_logon_dom; /* logon domain unicode string header */

	uint32 buffer_dom_id; /* undocumented logon domain id pointer */
	uint8 lm_sess_key[8];	/* lm session key */
	uint32 acct_flags;	/* account flags */
	uint32 unknown[7];	/* unknown */

	uint32 num_other_sids; /* number of foreign/trusted domain sids */
	uint32 buffer_other_sids;
	
	/* The next three uint32 are not really part of user_info_3 but here
	 * for parsing convenience.  They are only valid in Kerberos PAC
	 * parsing - Guenther */
	uint32 ptr_res_group_dom_sid;
	uint32 res_group_count;
	uint32 ptr_res_groups;

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

	DOM_SID2 *other_sids; /* foreign/trusted domain SIDs */
	uint32 *other_sids_attrib;
} NET_USER_INFO_3;

/* NEG_FLAGS */
typedef struct neg_flags_info {
	uint32 neg_flags; /* negotiated flags */
} NEG_FLAGS;


/* NET_Q_REQ_CHAL */
typedef struct net_q_req_chal_info {
	uint32  undoc_buffer; /* undocumented buffer pointer */
	UNISTR2 uni_logon_srv; /* logon server unicode string */
	UNISTR2 uni_logon_clnt; /* logon client unicode string */
	DOM_CHAL clnt_chal; /* client challenge */
} NET_Q_REQ_CHAL;


/* NET_R_REQ_CHAL */
typedef struct net_r_req_chal_info {
	DOM_CHAL srv_chal; /* server challenge */
	NTSTATUS status; /* return code */
} NET_R_REQ_CHAL;

/* NET_Q_AUTH */
typedef struct net_q_auth_info {
	DOM_LOG_INFO clnt_id; /* client identification info */
	DOM_CHAL clnt_chal;     /* client-calculated credentials */
} NET_Q_AUTH;

/* NET_R_AUTH */
typedef struct net_r_auth_info {
	DOM_CHAL srv_chal;     /* server-calculated credentials */
	NTSTATUS status; /* return code */
} NET_R_AUTH;

/* NET_Q_AUTH_2 */
typedef struct net_q_auth2_info {
	DOM_LOG_INFO clnt_id; /* client identification info */
	DOM_CHAL clnt_chal;     /* client-calculated credentials */

	NEG_FLAGS clnt_flgs; /* usually 0x0000 01ff */
} NET_Q_AUTH_2;


/* NET_R_AUTH_2 */
typedef struct net_r_auth2_info {
	DOM_CHAL srv_chal;     /* server-calculated credentials */
	NEG_FLAGS srv_flgs; /* usually 0x0000 01ff */
	NTSTATUS status; /* return code */
} NET_R_AUTH_2;

/* NET_Q_AUTH_3 */
typedef struct net_q_auth3_info {
	DOM_LOG_INFO clnt_id;	/* client identification info */
	DOM_CHAL clnt_chal;		/* client-calculated credentials */
	NEG_FLAGS clnt_flgs;	/* usually 0x6007 ffff */
} NET_Q_AUTH_3;

/* NET_R_AUTH_3 */
typedef struct net_r_auth3_info {
	DOM_CHAL srv_chal;	/* server-calculated credentials */
	NEG_FLAGS srv_flgs;	/* usually 0x6007 ffff */
	uint32 unknown;		/* 0x0000045b */
	NTSTATUS status;	/* return code */
} NET_R_AUTH_3;


/* NET_Q_SRV_PWSET */
typedef struct net_q_srv_pwset_info {
	DOM_CLNT_INFO clnt_id; /* client identification/authentication info */
	uint8 pwd[16]; /* new password - undocumented. */
} NET_Q_SRV_PWSET;
    
/* NET_R_SRV_PWSET */
typedef struct net_r_srv_pwset_info {
	DOM_CRED srv_cred;     /* server-calculated credentials */

	NTSTATUS status; /* return code */
} NET_R_SRV_PWSET;

/* NET_ID_INFO_2 */
typedef struct net_network_info_2 {
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
typedef struct id_info_1 {
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
typedef struct net_id_info_ctr_info {
	uint16         switch_value;
  
	union {
		NET_ID_INFO_1 id1; /* auth-level 1 - interactive user login */
		NET_ID_INFO_2 id2; /* auth-level 2 - workstation referred login */
	} auth;
} NET_ID_INFO_CTR;

/* SAM_INFO - sam logon/off id structure */
typedef struct sam_info {
	DOM_CLNT_INFO2  client;
	uint32          ptr_rtn_cred; /* pointer to return credentials */
	DOM_CRED        rtn_cred; /* return credentials */
	uint16          logon_level;
	NET_ID_INFO_CTR *ctr;
} DOM_SAM_INFO;

/* SAM_INFO - sam logon/off id structure - no creds */
typedef struct sam_info_ex {
	DOM_CLNT_SRV	client;
	uint16          logon_level;
	NET_ID_INFO_CTR *ctr;
} DOM_SAM_INFO_EX;

/* NET_Q_SAM_LOGON */
typedef struct net_q_sam_logon_info {
	DOM_SAM_INFO sam_id;
	uint16          validation_level;
} NET_Q_SAM_LOGON;

/* NET_Q_SAM_LOGON_EX */
typedef struct net_q_sam_logon_info_ex {
	DOM_SAM_INFO_EX sam_id;
	uint16          validation_level;
	uint32 flags;
} NET_Q_SAM_LOGON_EX;

/* NET_R_SAM_LOGON */
typedef struct net_r_sam_logon_info {
	uint32 buffer_creds; /* undocumented buffer pointer */
	DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
	uint16 switch_value; /* 3 - indicates type of USER INFO */
	NET_USER_INFO_3 *user;

	uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */

	NTSTATUS status; /* return code */
} NET_R_SAM_LOGON;

/* NET_R_SAM_LOGON_EX */
typedef struct net_r_sam_logon_info_ex {
	uint16 switch_value; /* 3 - indicates type of USER INFO */
	NET_USER_INFO_3 *user;

	uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */
	uint32 flags;

	NTSTATUS status; /* return code */
} NET_R_SAM_LOGON_EX;

/* LOCKOUT_STRING */
typedef struct account_lockout_string {
	uint32 array_size;
	uint32 offset;
	uint32 length;
/*	uint16 *bindata;	*/
	uint64 lockout_duration;
	uint64 reset_count;
	uint32 bad_attempt_lockout;
	uint32 dummy;
} LOCKOUT_STRING;

/* HDR_LOCKOUT_STRING */
typedef struct hdr_account_lockout_string {
	uint16 size;
	uint16 length;
	uint32 buffer;
} HDR_LOCKOUT_STRING;

#define DSGETDC_VALID_FLAGS ( \
    DS_FORCE_REDISCOVERY | \
    DS_DIRECTORY_SERVICE_REQUIRED | \
    DS_DIRECTORY_SERVICE_PREFERRED | \
    DS_GC_SERVER_REQUIRED | \
    DS_PDC_REQUIRED | \
    DS_BACKGROUND_ONLY | \
    DS_IP_REQUIRED | \
    DS_KDC_REQUIRED | \
    DS_TIMESERV_REQUIRED | \
    DS_WRITABLE_REQUIRED | \
    DS_GOOD_TIMESERV_PREFERRED | \
    DS_AVOID_SELF | \
    DS_ONLY_LDAP_NEEDED | \
    DS_IS_FLAT_NAME | \
    DS_IS_DNS_NAME | \
    DS_RETURN_FLAT_NAME  | \
    DS_RETURN_DNS_NAME )

struct DS_DOMAIN_CONTROLLER_INFO {
	const char *domain_controller_name;
	const char *domain_controller_address;
	int32 domain_controller_address_type;
	struct GUID *domain_guid;
	const char *domain_name;
	const char *dns_forest_name;
	uint32 flags;
	const char *dc_site_name;
	const char *client_site_name;
};

#endif /* _RPC_NETLOGON_H */

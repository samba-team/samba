/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if(x) {free(x); x=NULL;} } while(0)
#endif

#ifndef _WINBINDD_NTDOM_H
#define _WINBINDD_NTDOM_H

#define WINBINDD_SOCKET_NAME "pipe"            /* Name of PF_UNIX socket */
#define WINBINDD_SOCKET_DIR  "/tmp/.winbindd"  /* Name of PF_UNIX dir */
#define WINBINDD_PRIV_SOCKET_SUBDIR "winbindd_privileged" /* name of subdirectory of lp_lockdir() to hold the 'privileged' pipe */
#define WINBINDD_DOMAIN_ENV  "WINBINDD_DOMAIN" /* Environment variables */
#define WINBINDD_DONT_ENV    "_NO_WINBINDD"

/* Update this when you change the interface.  */

#define WINBIND_INTERFACE_VERSION 10

/* Socket commands */

enum winbindd_cmd {

	WINBINDD_INTERFACE_VERSION,    /* Always a well known value */

	/* Get users and groups */

	WINBINDD_GETPWNAM,
	WINBINDD_GETPWUID,
	WINBINDD_GETGRNAM,
	WINBINDD_GETGRGID,
	WINBINDD_GETGROUPS,

	/* Enumerate users and groups */

	WINBINDD_SETPWENT,
	WINBINDD_ENDPWENT,
	WINBINDD_GETPWENT,
	WINBINDD_SETGRENT,
	WINBINDD_ENDGRENT,
	WINBINDD_GETGRENT,

	/* PAM authenticate and password change */

	WINBINDD_PAM_AUTH,
	WINBINDD_PAM_AUTH_CRAP,
	WINBINDD_PAM_CHAUTHTOK,

	/* List various things */

	WINBINDD_LIST_USERS,         /* List w/o rid->id mapping */
	WINBINDD_LIST_GROUPS,        /* Ditto */
	WINBINDD_LIST_TRUSTDOM,

	/* SID conversion */

	WINBINDD_LOOKUPSID,
	WINBINDD_LOOKUPNAME,

	/* Lookup functions */

	WINBINDD_SID_TO_UID,       
	WINBINDD_SID_TO_GID,
	WINBINDD_UID_TO_SID,
	WINBINDD_GID_TO_SID,
	WINBINDD_ALLOCATE_RID,

	/* Miscellaneous other stuff */

	WINBINDD_CHECK_MACHACC,     /* Check machine account pw works */
	WINBINDD_PING,              /* Just tell me winbind is running */
	WINBINDD_INFO,              /* Various bit of info.  Currently just tidbits */
	WINBINDD_DOMAIN_NAME,       /* The domain this winbind server is a member of (lp_workgroup()) */

	WINBINDD_DOMAIN_INFO,	/* Most of what we know from
				   struct winbindd_domain */

	WINBINDD_SHOW_SEQUENCE, /* display sequence numbers of domains */

	/* WINS commands */

	WINBINDD_WINS_BYIP,
	WINBINDD_WINS_BYNAME,

	/* account management commands */

	WINBINDD_CREATE_USER,
	WINBINDD_CREATE_GROUP,
	WINBINDD_ADD_USER_TO_GROUP,
	WINBINDD_REMOVE_USER_FROM_GROUP,
	WINBINDD_SET_USER_PRIMARY_GROUP,
	WINBINDD_DELETE_USER,
	WINBINDD_DELETE_GROUP,
	
	/* this is like GETGRENT but gives an empty group list */
	WINBINDD_GETGRLST,

	WINBINDD_NETBIOS_NAME,       /* The netbios name of the server */

	/* find the location of our privileged pipe */
	WINBINDD_PRIV_PIPE_DIR,

	/* return a list of group sids for a user sid */
	WINBINDD_GETUSERSIDS,	

	/* Placeholder for end of cmd list */
	WINBINDD_NUM_CMDS
};

typedef struct winbindd_pw {
	fstring pw_name;
	fstring pw_passwd;
	uid_t pw_uid;
	gid_t pw_gid;
	fstring pw_gecos;
	fstring pw_dir;
	fstring pw_shell;
} WINBINDD_PW;


typedef struct winbindd_gr {
	fstring gr_name;
	fstring gr_passwd;
	gid_t gr_gid;
	int num_gr_mem;
	int gr_mem_ofs;   /* offset to group membership */
	char **gr_mem;
} WINBINDD_GR;


#define WBFLAG_PAM_INFO3_NDR  		0x0001
#define WBFLAG_PAM_INFO3_TEXT 		0x0002
#define WBFLAG_PAM_USER_SESSION_KEY     0x0004
#define WBFLAG_PAM_LMKEY      		0x0008
#define WBFLAG_PAM_CONTACT_TRUSTDOM 	0x0010
#define WBFLAG_QUERY_ONLY		0x0020
#define WBFLAG_ALLOCATE_RID		0x0040
#define WBFLAG_PAM_UNIX_NAME            0x0080
#define WBFLAG_PAM_AFS_TOKEN            0x0100
#define WBFLAG_PAM_NT_STATUS_SQUASH     0x0200

/* Winbind request structure */

struct winbindd_request {
	uint32 length;
	enum winbindd_cmd cmd;   /* Winbindd command to execute */
	pid_t pid;               /* pid of calling process */
	uint32 flags;            /* flags relavant to a given request */
	fstring domain_name;	/* name of domain for which the request applies */

	union {
		fstring winsreq;     /* WINS request */
		fstring username;    /* getpwnam */
		fstring groupname;   /* getgrnam */
		uid_t uid;           /* getpwuid, uid_to_sid */
		gid_t gid;           /* getgrgid, gid_to_sid */
		struct {
			/* We deliberatedly don't split into domain/user to
                           avoid having the client know what the separator
                           character is. */	
			fstring user;
			fstring pass;
		        fstring required_membership_sid;
		} auth;              /* pam_winbind auth module */
                struct {
                        unsigned char chal[8];
                        fstring user;
                        fstring domain;
                        fstring lm_resp;
                        uint16 lm_resp_len;
                        fstring nt_resp;
                        uint16 nt_resp_len;
			fstring workstation;
		        fstring required_membership_sid;
                } auth_crap;
                struct {
                    fstring user;
                    fstring oldpass;
                    fstring newpass;
                } chauthtok;         /* pam_winbind passwd module */
		fstring sid;         /* lookupsid, sid_to_[ug]id */
		struct {
			fstring dom_name;       /* lookupname */
			fstring name;       
		} name;
		uint32 num_entries;  /* getpwent, getgrent */
		struct {
			fstring username;
			fstring groupname;
		} acct_mgt;
	} data;
	char null_term;
};

/* Response values */

enum winbindd_result {
	WINBINDD_ERROR,
	WINBINDD_OK
};

/* Winbind response structure */

struct winbindd_response {
    
	/* Header information */

	uint32 length;                        /* Length of response */
	enum winbindd_result result;          /* Result code */

	/* Fixed length return data */
	
	union {
		int interface_version;  /* Try to ensure this is always in the same spot... */
		
		fstring winsresp;		/* WINS response */

		/* getpwnam, getpwuid */
		
		struct winbindd_pw pw;

		/* getgrnam, getgrgid */

		struct winbindd_gr gr;

		uint32 num_entries; /* getpwent, getgrent */
		struct winbindd_sid {
			fstring sid;        /* lookupname, [ug]id_to_sid */
			int type;
		} sid;
		struct winbindd_name {
			fstring dom_name;       /* lookupsid */
			fstring name;       
			int type;
		} name;
		uid_t uid;          /* sid_to_uid */
		gid_t gid;          /* sid_to_gid */
		struct winbindd_info {
			char winbind_separator;
			fstring samba_version;
		} info;
		fstring domain_name;
		fstring netbios_name;

		struct auth_reply {
			uint32 nt_status;
			fstring nt_status_string;
			fstring error_string;
			int pam_error;
			char user_session_key[16];
			char first_8_lm_hash[8];
		} auth;
		uint32 rid;	/* create user or group or allocate rid */
		struct {
			fstring name;
			fstring alt_name;
			fstring sid;
			BOOL native_mode;
			BOOL active_directory;
			BOOL primary;
			uint32 sequence_number;
		} domain_info;
	} data;

	/* Variable length return data */

	void *extra_data;               /* getgrnam, getgrgid, getgrent */
};

#endif

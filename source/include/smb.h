/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) John H Terpstra 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton 1998
   
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

#ifndef _SMB_H
#define _SMB_H

#include "md5.h"
#include "hmacmd5.h"

#define BUFFER_SIZE (0xFFFF)
#define SAFETY_MARGIN 1024

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139
#define SMB_PORT2 445

#define False (0)
#define True (1)
#define Auto (2)

#ifndef _BOOL
typedef int BOOL;
#define _BOOL       /* So we don't typedef BOOL again in vfs.h */
#endif

/* limiting size of ipc replies */
#define REALLOC(ptr,size) Realloc(ptr,MAX((size),4*1024))

#define SIZEOFWORD 2

#ifndef DEF_CREATE_MASK
#define DEF_CREATE_MASK (0755)
#endif

/* how long to wait for secondary SMB packets (milli-seconds) */
#define SMB_SECONDARY_WAIT (60*1000)

/* Debugging stuff */

#include <debug.h>

/* this defines the error codes that receive_smb can put in smb_read_error */
#define READ_TIMEOUT 1
#define READ_EOF 2
#define READ_ERROR 3


#define DIR_STRUCT_SIZE 43

/* these define all the command types recognised by the server - there
are lots of gaps so probably there are some rare commands that are not
implemented */

#define pSETDIR '\377'

/* these define the attribute byte as seen by DOS */
#define aRONLY (1L<<0)
#define aHIDDEN (1L<<1)
#define aSYSTEM (1L<<2)
#define aVOLID (1L<<3)
#define aDIR (1L<<4)
#define aARCH (1L<<5)

/* deny modes */
#define DENY_DOS 0
#define DENY_ALL 1
#define DENY_WRITE 2
#define DENY_READ 3
#define DENY_NONE 4
#define DENY_FCB 7

/* open modes */
#define DOS_OPEN_RDONLY 0
#define DOS_OPEN_WRONLY 1
#define DOS_OPEN_RDWR 2
#define DOS_OPEN_FCB 0xF

/* define shifts and masks for share and open modes. */
#define OPEN_MODE_MASK 0xF
#define SHARE_MODE_SHIFT 4
#define SHARE_MODE_MASK 0x7
#define GET_OPEN_MODE(x) ((x) & OPEN_MODE_MASK)
#define SET_OPEN_MODE(x) ((x) & OPEN_MODE_MASK)
#define GET_DENY_MODE(x) (((x)>>SHARE_MODE_SHIFT) & SHARE_MODE_MASK)
#define SET_DENY_MODE(x) ((x)<<SHARE_MODE_SHIFT)

/* Sync on open file (not sure if used anymore... ?) */
#define FILE_SYNC_OPENMODE (1<<14)
#define GET_FILE_SYNC_OPENMODE(x) (((x) & FILE_SYNC_OPENMODE) ? True : False)

/* allow delete on open file mode (used by NT SMB's). */
#define ALLOW_SHARE_DELETE (1<<15)
#define GET_ALLOW_SHARE_DELETE(x) (((x) & ALLOW_SHARE_DELETE) ? True : False)
#define SET_ALLOW_SHARE_DELETE(x) ((x) ? ALLOW_SHARE_DELETE : 0)

/* delete on close flag (used by NT SMB's). */
#define DELETE_ON_CLOSE_FLAG (1<<16)
#define GET_DELETE_ON_CLOSE_FLAG(x) (((x) & DELETE_ON_CLOSE_FLAG) ? True : False)
#define SET_DELETE_ON_CLOSE_FLAG(x) ((x) ? DELETE_ON_CLOSE_FLAG : 0)

/* open disposition values */
#define FILE_EXISTS_FAIL 0
#define FILE_EXISTS_OPEN 1
#define FILE_EXISTS_TRUNCATE 2

/* mask for open disposition. */
#define FILE_OPEN_MASK 0x3

#define GET_FILE_OPEN_DISPOSITION(x) ((x) & FILE_OPEN_MASK)
#define SET_FILE_OPEN_DISPOSITION(x) ((x) & FILE_OPEN_MASK)

/* The above can be OR'ed with... */
#define FILE_CREATE_IF_NOT_EXIST 0x10
#define FILE_FAIL_IF_NOT_EXIST 0

#define GET_FILE_CREATE_DISPOSITION(x) ((x) & (FILE_CREATE_IF_NOT_EXIST|FILE_FAIL_IF_NOT_EXIST))

/* share types */
#define STYPE_DISKTREE  0	/* Disk drive */
#define STYPE_PRINTQ    1	/* Spooler queue */
#define STYPE_DEVICE    2	/* Serial device */
#define STYPE_IPC       3	/* Interprocess communication (IPC) */
#define STYPE_HIDDEN    0x80000000 /* share is a hidden one (ends with $) */

/* SMB X/Open error codes for the ERRDOS error class */
#define ERRbadfunc 1 /* Invalid function (or system call) */
#define ERRbadfile 2 /* File not found (pathname error) */
#define ERRbadpath 3 /* Directory not found */
#define ERRnofids 4 /* Too many open files */
#define ERRnoaccess 5 /* Access denied */
#define ERRbadfid 6 /* Invalid fid */
#define ERRnomem 8 /* Out of memory */
#define ERRbadmem 9 /* Invalid memory block address */
#define ERRbadenv 10 /* Invalid environment */
#define ERRbadaccess 12 /* Invalid open mode */
#define ERRbaddata 13 /* Invalid data (only from ioctl call) */
#define ERRres 14 /* reserved */
#define ERRbaddrive 15 /* Invalid drive */
#define ERRremcd 16 /* Attempt to delete current directory */
#define ERRdiffdevice 17 /* rename/move across different filesystems */
#define ERRnofiles 18 /* no more files found in file search */
#define ERRbadshare 32 /* Share mode on file conflict with open mode */
#define ERRlock 33 /* Lock request conflicts with existing lock */
#define ERRunsup 50 /* Request unsupported, returned by Win 95, RJS 20Jun98 */
#define ERRfilexists 80 /* File in operation already exists */
#define ERRcannotopen 110 /* Cannot open the file specified */
#define ERRunknownlevel 124
#define ERRrename 183
#define ERRbadpipe 230 /* Named pipe invalid */
#define ERRpipebusy 231 /* All instances of pipe are busy */
#define ERRpipeclosing 232 /* named pipe close in progress */
#define ERRnotconnected 233 /* No process on other end of named pipe */
#define ERRmoredata 234 /* More data to be returned */
#define ERRbaddirectory 267 /* Invalid directory name in a path. */
#define ERROR_EAS_DIDNT_FIT 275 /* Extended attributes didn't fit */
#define ERROR_EAS_NOT_SUPPORTED 282 /* Extended attributes not supported */
#define ERROR_NOTIFY_ENUM_DIR 1022 /* Buffer too small to return change notify. */
#define ERRunknownipc 2142


/* here's a special one from observing NT */
#define ERRnoipc 66 /* don't support ipc */

/* Error codes for the ERRSRV class */

#define ERRerror 1 /* Non specific error code */
#define ERRbadpw 2 /* Bad password */
#define ERRbadtype 3 /* reserved */
#define ERRaccess 4 /* No permissions to do the requested operation */
#define ERRinvnid 5 /* tid invalid */
#define ERRinvnetname 6 /* Invalid servername */
#define ERRinvdevice 7 /* Invalid device */
#define ERRqfull 49 /* Print queue full */
#define ERRqtoobig 50 /* Queued item too big */
#define ERRinvpfid 52 /* Invalid print file in smb_fid */
#define ERRsmbcmd 64 /* Unrecognised command */
#define ERRsrverror 65 /* smb server internal error */
#define ERRfilespecs 67 /* fid and pathname invalid combination */
#define ERRbadlink 68 /* reserved */
#define ERRbadpermits 69 /* Access specified for a file is not valid */
#define ERRbadpid 70 /* reserved */
#define ERRsetattrmode 71 /* attribute mode invalid */
#define ERRpaused 81 /* Message server paused */
#define ERRmsgoff 82 /* Not receiving messages */
#define ERRnoroom 83 /* No room for message */
#define ERRrmuns 87 /* too many remote usernames */
#define ERRtimeout 88 /* operation timed out */
#define ERRnoresource  89 /* No resources currently available for request. */
#define ERRtoomanyuids 90 /* too many userids */
#define ERRbaduid 91 /* bad userid */
#define ERRuseMPX 250 /* temporarily unable to use raw mode, use MPX mode */
#define ERRuseSTD 251 /* temporarily unable to use raw mode, use standard mode */
#define ERRcontMPX 252 /* resume MPX mode */
#define ERRbadPW /* reserved */
#define ERRnosupport 0xFFFF
#define ERRunknownsmb 22 /* from NT 3.5 response */


/* Error codes for the ERRHRD class */

#define ERRnowrite 19 /* read only media */
#define ERRbadunit 20 /* Unknown device */
#define ERRnotready 21 /* Drive not ready */
#define ERRbadcmd 22 /* Unknown command */
#define ERRdata 23 /* Data (CRC) error */
#define ERRbadreq 24 /* Bad request structure length */
#define ERRseek 25
#define ERRbadmedia 26
#define ERRbadsector 27
#define ERRnopaper 28
#define ERRwrite 29 /* write fault */
#define ERRread 30 /* read fault */
#define ERRgeneral 31 /* General hardware failure */
#define ERRwrongdisk 34
#define ERRFCBunavail 35
#define ERRsharebufexc 36 /* share buffer exceeded */
#define ERRdiskfull 39

#ifndef _PSTRING
#define PSTRING_LEN 1024
#define FSTRING_LEN 128

typedef char pstring[PSTRING_LEN];
typedef char fstring[FSTRING_LEN];
#define _PSTRING
#endif

/* pipe string names */
#define PIPE_LANMAN   "\\PIPE\\LANMAN"
#define PIPE_BROWSER  "\\PIPE\\browser"
#define PIPE_SRVSVC   "\\PIPE\\srvsvc"
#define PIPE_SAMR     "\\PIPE\\samr"
#define PIPE_WINREG   "\\PIPE\\winreg"
#define PIPE_WKSSVC   "\\PIPE\\wkssvc"
#define PIPE_NETLOGON "\\PIPE\\NETLOGON"
#define PIPE_SVCCTL   "\\PIPE\\svcctl"
#define PIPE_NTLSA    "\\PIPE\\ntlsa"
#define PIPE_NTSVCS   "\\PIPE\\ntsvcs"
#define PIPE_LSASS    "\\PIPE\\lsass"
#define PIPE_LSARPC   "\\PIPE\\lsarpc"
#define PIPE_EPMAPPER "\\PIPE\\epmapper"
#define PIPE_ATSVC    "\\PIPE\\atsvc"
#define PIPE_SPOOLSS  "\\PIPE\\spoolss"
#define PIPE_EVENTLOG "\\PIPE\\EVENTLOG"

/* 64 bit time (100usec) since ????? - cifs6.txt, section 3.5, page 30 */
typedef struct nttime_info
{
  uint32 low;
  uint32 high;

} NTTIME;

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
#define ACB_PWLOCK     0x0800  /* 1 = Password is locked and connot be changed remotely */
 
#define MAX_HOURS_LEN 32

struct sam_passwd
{
	NTTIME logon_time;            /* logon time */
	NTTIME logoff_time;           /* logoff time */
	NTTIME kickoff_time;          /* kickoff time */
	NTTIME pass_last_set_time;    /* password last set time */
	NTTIME pass_can_change_time;  /* password can change time */
	NTTIME pass_must_change_time; /* password must change time */

	char *unix_name;    /* unix username string */
	char *nt_name;      /* nt username string */
	char *full_name;    /* user's full name string */
	char *home_dir;     /* home directory string */
	char *dir_drive;    /* home directory drive string */
	char *logon_script; /* logon script string */
	char *profile_path; /* profile path string */
	char *acct_desc  ;  /* user description string */
	char *workstations; /* login from workstations string */
	char *unknown_str ; /* don't know what this is, yet. */
	char *munged_dial ; /* munged path name and dial-back tel number */

	uid_t unix_uid;       /* this is actually the unix uid_t */
	gid_t unix_gid;        /* this is actually the unix gid_t */
	uint32 user_rid;      /* Primary User ID */
	uint32 group_rid;     /* Primary Group ID */

	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */

	uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
	uint32 unknown_3; /* 0x00ff ffff */

	uint16 logon_divs; /* 168 - number of hours in a week */
	uint32 hours_len; /* normally 21 bytes */
	uint8 hours[MAX_HOURS_LEN];

	uint32 unknown_5; /* 0x0002 0000 */
	uint32 unknown_6; /* 0x0000 04ec */
};

struct smb_passwd
{
	uid_t unix_uid;     /* unix userid */
	char *unix_name;     /* unix username string */

	uint32 user_rid;     /* Primary User ID */
	char *nt_name;     /* unix username string */

	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */

	uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
	time_t pass_last_set_time;    /* password last set time */
};


struct sam_disp_info
{
	uint32 user_rid;      /* Primary User ID */
	char *nt_name;        /* username string */
	char *full_name;      /* user's full name string */
};

struct use_info
{
	BOOL connected;
	char *srv_name;
	char *user_name;
	char *domain;
};

#define MAXSUBAUTHS 15 /* max sub authorities in a SID */

/* DOM_SID - security id */
typedef struct sid_info
{
  uint8  sid_rev_num;             /* SID revision number */
  uint8  num_auths;               /* number of sub-authorities */
  uint8  id_auth[6];              /* Identifier Authority */
  /*
   * Note that the values in these uint32's are in *native* byteorder,
   * not neccessarily little-endian...... JRA.
   */
  uint32 sub_auths[MAXSUBAUTHS];  /* pointer to sub-authorities. */

} DOM_SID;


typedef struct group_name_info
{
	char *nt_name;
	char *nt_domain;
	char *unix_name;

	DOM_SID sid;
	uint32 type;
	uint32 unix_id;

} DOM_NAME_MAP;

/* map either local aliases, domain groups or builtin aliases */
typedef enum 
{
	DOM_MAP_LOCAL,
	DOM_MAP_DOMAIN,
	DOM_MAP_USER

} DOM_MAP_TYPE;


/*** query a local group, get a list of these: shows who is in that group ***/

/* local group member info */
typedef struct local_grp_member_info
{
	DOM_SID sid    ; /* matches with name */
	uint8   sid_use; /* usr=1 grp=2 dom=3 alias=4 wkng=5 del=6 inv=7 unk=8 */
	fstring name   ; /* matches with sid: must be of the form "DOMAIN\account" */

} LOCAL_GRP_MEMBER;

/* enumerate these to get list of local groups */

/* local group info */
typedef struct local_grp_info
{
	fstring name;
	fstring comment;
	uint32  rid; /* alias rid */

} LOCAL_GRP;

/*** query a domain group, get a list of these: shows who is in that group ***/

/* domain group info */
typedef struct domain_grp_member_info
{
	fstring name;
	uint8   attr; /* attributes forced to be set to 0x7: SE_GROUP_xxx */
	uint32  rid; /* rid of domain group member */
	uint8   sid_use; /* usr=1 grp=2 dom=3 alias=4 wkng=5 del=6 inv=7 unk=8 */

} DOMAIN_GRP_MEMBER;

/*** enumerate these to get list of domain groups ***/

/* domain group member info */
typedef struct domain_grp_info
{
	fstring name;
	fstring comment;
	uint32  rid; /* group rid */
	uint8   attr; /* attributes forced to be set to 0x7: SE_GROUP_xxx */

} DOMAIN_GRP;

/* DOM_CHAL - challenge info */
typedef struct chal_info
{
  uchar data[8]; /* credentials */
} DOM_CHAL;

/* 32 bit time (sec) since 01jan1970 - cifs6.txt, section 3.5, page 30 */
typedef struct time_info
{
  uint32 time;
} UTIME;

/* DOM_CREDs - timestamped client or server credentials */
typedef struct cred_info
{  
  DOM_CHAL challenge; /* credentials */
  UTIME timestamp;    /* credential time-stamp */
} DOM_CRED;

/* Structure used when SMBwritebmpx is active */
typedef struct
{
  size_t wr_total_written; /* So we know when to discard this */
  int32 wr_timeout;
  int32 wr_errclass;
  int32 wr_error; /* Cached errors */
  BOOL  wr_mode; /* write through mode) */
  BOOL  wr_discard; /* discard all further data */
} write_bmpx_struct;

/*
 * Structure used to indirect fd's from the files_struct.
 * Needed as POSIX locking is based on file and process, not
 * file descriptor and process.
 */

typedef struct file_fd_struct
{
	struct file_fd_struct *next, *prev;
	uint16 ref_count;
	uint16 uid_cache_count;
	uid_t uid_users_cache[10];
	SMB_DEV_T dev;
	SMB_INO_T inode;
	int fd;
	int fd_readonly;
	int fd_writeonly;
	int real_open_flags;
	BOOL delete_on_close;
} file_fd_struct;

typedef struct files_struct
{
	struct files_struct *next, *prev;
	int fnum;
	struct connection_struct *conn;
	file_fd_struct *fd_ptr;
	SMB_OFF_T pos;
	SMB_OFF_T size;
	mode_t mode;
	uint16 vuid;
	char *mmap_ptr;
	SMB_OFF_T mmap_size;
	write_bmpx_struct *wbmpx_ptr;
	struct timeval open_time;
        int share_mode;
	time_t pending_modtime;
	BOOL open;
	BOOL can_lock;
	BOOL can_read;
	BOOL can_write;
	BOOL print_file;
	BOOL modified;
	BOOL granted_oplock;
	BOOL sent_oplock_break;
	BOOL is_directory;
	char *fsp_name;
} files_struct;

/*
 * Structure used to keep directory state information around.
 * Used in NT change-notify code.
 */

typedef struct
{
  time_t modify_time;
  time_t status_time;
} dir_status_struct;

struct uid_cache {
  int entries;
  uid_t list[UID_CACHE_SIZE];
};

typedef struct
{
  char *name;
  BOOL is_wild;
} name_compare_entry;

/* Include VFS stuff */

#include "vfs.h"


#include "vagent.h"

typedef struct connection_struct
{
	struct connection_struct *next, *prev;
	unsigned cnum; /* an index passed over the wire */
	int service;
	BOOL force_user;
	struct uid_cache uid_cache;
	void *dirptr;
	BOOL printer;
	BOOL ipc;
	BOOL read_only;
	BOOL admin_user;
	char *dirpath;
	char *connectpath;
	char *origpath;
        struct vfs_ops vfs_ops;             /* Filesystem operations */
        struct vfs_connection_struct *vfs_conn;

	char *user; /* name of user who *opened* this connection */

	uid_t uid; /* uid of user who *opened* this connection */
	gid_t gid; /* gid of user who *opened* this connection */
	char client_address[18]; /* string version of client ip address */

	/* This groups info is valid for the user that *opened* the connection */
	int ngroups;
	gid_t *groups;
	
	uint16 vuid; /* vuid of user who *opened* this connection, or UID_FIELD_INVALID */

	pid_t smbd_pid; /* smbd process id of user that *opened* this connection*/

	/* following groups stuff added by ih */

	time_t lastused;
	BOOL used;
	int num_files_open;
	name_compare_entry *hide_list; /* Per-share list of files to return as hidden. */
	name_compare_entry *veto_list; /* Per-share list of files to veto (never show). */
	name_compare_entry *veto_oplock_list; /* Per-share list of files to refuse oplocks on. */       

} connection_struct;

/* Domain controller authentication protocol info */
struct dcinfo
{
  DOM_CHAL clnt_chal; /* Initial challenge received from client */
  DOM_CHAL srv_chal;  /* Initial server challenge */
  DOM_CRED clnt_cred; /* Last client credential */
  DOM_CRED srv_cred;  /* Last server credential */

  uchar  sess_key[8]; /* Session key */
  uchar  md4pw[16];   /* md4(machine password) */
};


enum {LPQ_QUEUED,LPQ_PAUSED,LPQ_SPOOLING,LPQ_PRINTING};

typedef struct
{
  int job;
  int size;
  int status;
  int priority;
  time_t time;
  char user[30];
  char file[100];
} print_queue_struct;

enum {LPSTAT_OK, LPSTAT_STOPPED, LPSTAT_ERROR};

typedef struct
{
  fstring message;
  int status;
}  print_status_struct;

/* used for server information: client, nameserv and ipc */
struct server_info_struct
{
  fstring name;
  uint32 type;
  fstring comment;
  fstring domain; /* used ONLY in ipc.c NOT namework.c */
  BOOL server_added; /* used ONLY in ipc.c NOT namework.c */
};


/* used for network interfaces */
struct interface
{
	struct interface *next;
	struct in_addr ip;
	struct in_addr bcast;
	struct in_addr nmask;
};

/* struct returned by get_share_modes */
typedef struct
{
  int pid;
  uint16 op_port;
  uint16 op_type;
  int share_mode;
  struct timeval time;
} share_mode_entry;


/* each implementation of the share mode code needs
   to support the following operations */
struct share_ops {
	BOOL (*stop_mgmt)(void);
	BOOL (*lock_entry)(connection_struct *, SMB_DEV_T , SMB_INO_T , int *);
	BOOL (*unlock_entry)(connection_struct *, SMB_DEV_T , SMB_INO_T , int );
	int (*get_entries)(connection_struct *, int , SMB_DEV_T , SMB_INO_T , share_mode_entry **);
	void (*del_entry)(int , files_struct *);
	BOOL (*set_entry)(int, files_struct *, uint16 , uint16 );
    BOOL (*mod_entry)(int, files_struct *, void (*)(share_mode_entry *, SMB_DEV_T, SMB_INO_T, void *), void *);
	int (*forall)(void (*)(share_mode_entry *, char *));
	void (*status)(FILE *);
};

/* each implementation of the shared memory code needs
   to support the following operations */
struct shmem_ops {
	BOOL (*shm_close)( void );
	int (*shm_alloc)(int );
	BOOL (*shm_free)(int );
	int (*get_userdef_off)(void);
	void *(*offset2addr)(int );
	int (*addr2offset)(void *addr);
	BOOL (*lock_hash_entry)(unsigned int);
	BOOL (*unlock_hash_entry)( unsigned int );
	BOOL (*get_usage)(int *,int *,int *);
	unsigned (*hash_size)(void);
};

/*
 * Each implementation of the password database code needs
 * to support the following operations.
 */

struct smb_passdb_ops
{
	/*
	 * Password database operations.
	 */
	void *(*startsmbpwent)(BOOL);
	void (*endsmbpwent)(void *);
	SMB_BIG_UINT (*getsmbpwpos)(void *);
	BOOL (*setsmbpwpos)(void *, SMB_BIG_UINT);

	/*
	 * smb password database query functions.
	 */
	struct smb_passwd *(*getsmbpwnam)(const char *);
	struct smb_passwd *(*getsmbpwuid)(uid_t);
	struct smb_passwd *(*getsmbpwent)(void *);

	/*
	 * smb password database modification functions.
	 */
	BOOL (*add_smbpwd_entry)(struct smb_passwd *);
	BOOL (*mod_smbpwd_entry)(struct smb_passwd *, BOOL);

#if 0
  /*
   * password checking functions
   */
  struct smb_passwd *(*smb_password_chal  )(const char *username, const char lm_pass[24], const char nt_pass[24], char chal[8]);
  struct smb_passwd *(*smb_password_check )(const char *username, const char lm_hash[16], const char nt_hash[16]);
  struct passwd     *(*unix_password_check)(const char *username, const char *pass, int pass_len);
#endif
};

/*
 * Each implementation of the password database code needs
 * to support the following operations.
 */

struct sam_passdb_ops {
  /*
   * Password database operations.
   */
  void *(*startsam21pwent)(BOOL);
  void (*endsam21pwent)(void *);
  SMB_BIG_UINT (*getsam21pwpos)(void *);
  BOOL (*setsam21pwpos)(void *, SMB_BIG_UINT);

  /*
   * sam password database query functions.
   */
  struct sam_passwd *(*getsam21pwntnam)(const char *);
  struct sam_passwd *(*getsam21pwuid)(uid_t);
  struct sam_passwd *(*getsam21pwrid)(uint32);
  struct sam_passwd *(*getsam21pwent)(void *);

  /*
   * sam password database modification functions.
   */
  BOOL (*add_sam21pwd_entry)(struct sam_passwd *);
  BOOL (*mod_sam21pwd_entry)(struct sam_passwd *, BOOL);

  /*
   * sam query display info functions.
   */
  struct sam_disp_info *(*getsamdispntnam)(const char *);
  struct sam_disp_info *(*getsamdisprid)(uint32);
  struct sam_disp_info *(*getsamdispent)(void *);

};

/*
 * Each implementation of the passgrp database code needs
 * to support the following operations.
 */

struct passgrp_ops
{
	/*
	 * Password group database ops.
	 */
	void *(*startsmbgrpent)(BOOL);
	void (*endsmbgrpent)(void *);
	SMB_BIG_UINT (*getsmbgrppos)(void *);
	BOOL (*setsmbgrppos)(void *, SMB_BIG_UINT);

	/*
	 * smb passgrp database query functions, by user attributes.
	 */
	struct smb_passwd *(*getsmbgrpntnam)(const char *, uint32**, int*, uint32**, int*);
	struct smb_passwd *(*getsmbgrpuid)(uid_t , uint32**, int*, uint32**, int*);
	struct smb_passwd *(*getsmbgrprid)(uint32, uint32**, int*, uint32**, int*);
	struct smb_passwd *(*getsmbgrpent)(void *, uint32**, int*, uint32**, int*);
};

/*
 * Each implementation of the group database code needs
 * to support the following operations.
 *
 * This allows enumeration, modification and addition of groups.  there
 * is _no_ deletion of groups: you can only modify them to a status of
 * "deleted" (this by the way is a requirement of c2 rating)
 */

struct groupdb_ops
{
	/*
	 * Group database ops.
	 */
	void *(*startgroupent)(BOOL);
	void (*endgroupent)(void *);
	SMB_BIG_UINT (*getgrouppos)(void *);
	BOOL (*setgrouppos)(void *, SMB_BIG_UINT);

	/*
	 * group database query functions. 
	 */
	DOMAIN_GRP *(*getgroupntnam)(const char *, DOMAIN_GRP_MEMBER **, int *);
	DOMAIN_GRP *(*getgroupgid)(gid_t , DOMAIN_GRP_MEMBER **, int *);
	DOMAIN_GRP *(*getgrouprid)(uint32, DOMAIN_GRP_MEMBER **, int *);
	DOMAIN_GRP *(*getgroupent)(void *, DOMAIN_GRP_MEMBER **, int *);

	/*
	 * group database modification functions.
	 */
	BOOL (*add_group_entry)(DOMAIN_GRP *);
	BOOL (*mod_group_entry)(DOMAIN_GRP *);
	BOOL (*del_group_entry)(uint32);

	BOOL (*add_group_member)(uint32, uint32);
	BOOL (*del_group_member)(uint32, uint32);

	/*
	 * user group functions
	 */
	BOOL (*getusergroupsntnam)(const char *, DOMAIN_GRP **, int *);
};

/*
 * Each implementation of the alias database code needs
 * to support the following operations.
 *
 * This allows enumeration, modification and addition of aliases.  there
 * is _no_ deletion of aliases: you can only modify them to a status of
 * "deleted" (this by the way is a requirement of c2 rating)
 */

struct aliasdb_ops
{
	/*
	 * Alias database ops.
	 */
	void *(*startaliasent)(BOOL);
	void (*endaliasent)(void *);
	SMB_BIG_UINT (*getaliaspos)(void *);
	BOOL (*setaliaspos)(void *, SMB_BIG_UINT);

	/*
	 * alias database query functions. 
	 */
	LOCAL_GRP *(*getaliasntnam)(const char *, LOCAL_GRP_MEMBER **, int *);
	LOCAL_GRP *(*getaliasgid)(gid_t , LOCAL_GRP_MEMBER **, int *);
	LOCAL_GRP *(*getaliasrid)(uint32, LOCAL_GRP_MEMBER **, int *);
	LOCAL_GRP *(*getaliasent)(void *, LOCAL_GRP_MEMBER **, int *);

	/*
	 * alias database modification functions.
	 */
	BOOL (*add_alias_entry)(LOCAL_GRP *);
	BOOL (*mod_alias_entry)(LOCAL_GRP *);
	BOOL (*del_alias_entry)(uint32);

	BOOL (*add_alias_member)(uint32, const DOM_SID*);
	BOOL (*del_alias_member)(uint32, const DOM_SID*);

	/*
	 * user alias functions
	 */
	BOOL (*getuseraliasntnam)(const char *, LOCAL_GRP **, int *);
};

/* this is used for smbstatus */

struct connect_record
{
  int magic;
  int pid;
  int cnum;
  uid_t uid;
  gid_t gid;
  char name[24];
  char addr[24];
  char machine[128];
  time_t start;
};

/* This is used by smbclient to send it to a smbfs mount point */
struct connection_options {
  int protocol;
  /* Connection-Options */
  uint32 max_xmit;
  uint16 server_vuid;
  uint16 tid;
  /* The following are LANMAN 1.0 options */
  uint16 sec_mode;
  uint16 max_mux;
  uint16 max_vcs;
  uint16 rawmode;
  uint32 sesskey;
  /* The following are NT LM 0.12 options */
  uint32 maxraw;
  uint32 capabilities;
  uint16 serverzone;
};

/* key and data in the connections database - used in smbstatus and smbd */
struct connections_key {
	pid_t pid;
	int cnum;
	fstring name;
};

struct connections_data {
	int magic;
	pid_t pid;
	int cnum;
	uid_t uid;
	gid_t gid;
	char name[24];
	char addr[24];
	char machine[128];
	time_t start;
};


/* key and data records in the tdb locking database */
struct locking_key {
	SMB_DEV_T dev;
	SMB_INO_T inode;
};

struct locking_data {
	int num_share_mode_entries;
	/* the following two entries are implicit 
	   share_mode_entry modes[num_share_mode_entries];
           char file_name[];
	*/
};

/* the following are used by loadparm for option lists */
typedef enum
{
  P_BOOL,P_BOOLREV,P_CHAR,P_INTEGER,P_OCTAL,
  P_STRING,P_USTRING,P_GSTRING,P_UGSTRING,P_ENUM,P_PTR,P_SEP
} parm_type;

typedef enum
{
  P_LOCAL,P_GLOBAL,P_SEPARATOR,P_NONE
} parm_class;

struct enum_list {
	int value;
	char *name;
};

struct parm_struct
{
	char *label;
	parm_type type;
	parm_class class;
	void *ptr;
	BOOL (*special)(char *, char **);
	struct enum_list *enum_list;
	unsigned flags;
	union {
		BOOL bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
	} def;
};

struct bitmap {
	uint32 *b;
	int n;
};

#define FLAG_BASIC 1 /* fundamental options */
#define FLAG_HIDE  2 /* options that should be hidden in SWAT */
#define FLAG_PRINT 4 /* printing options */
#define FLAG_GLOBAL 8 /* local options that should be globally settable in SWAT */
#define FLAG_DEPRECATED 0x10 /* options that should no longer be used */

#ifndef LOCKING_VERSION
#define LOCKING_VERSION 4
#endif /* LOCKING_VERSION */


/* the basic packet size, assuming no words or bytes */
#define smb_size 39

/* offsets into message for common items */
#define smb_com 8
#define smb_rcls 9
#define smb_reh 10
#define smb_err 11
#define smb_flg 13
#define smb_flg2 14
#define smb_reb 13
#define smb_tid 28
#define smb_pid 30
#define smb_uid 32
#define smb_mid 34
#define smb_wct 36
#define smb_vwv 37
#define smb_vwv0 37
#define smb_vwv1 39
#define smb_vwv2 41
#define smb_vwv3 43
#define smb_vwv4 45
#define smb_vwv5 47
#define smb_vwv6 49
#define smb_vwv7 51
#define smb_vwv8 53
#define smb_vwv9 55
#define smb_vwv10 57
#define smb_vwv11 59
#define smb_vwv12 61
#define smb_vwv13 63
#define smb_vwv14 65
#define smb_vwv15 67
#define smb_vwv16 69
#define smb_vwv17 71

/* flag defines. CIFS spec 3.1.1 */
#define FLAG_SUPPORT_LOCKREAD       0x01
#define FLAG_CLIENT_BUF_AVAIL       0x02
#define FLAG_RESERVED               0x04
#define FLAG_CASELESS_PATHNAMES     0x08
#define FLAG_CANONICAL_PATHNAMES    0x10
#define FLAG_REQUEST_OPLOCK         0x20
#define FLAG_REQUEST_BATCH_OPLOCK   0x40
#define FLAG_REPLY                  0x80

/* the complete */
#define SMBmkdir      0x00   /* create directory */
#define SMBrmdir      0x01   /* delete directory */
#define SMBopen       0x02   /* open file */
#define SMBcreate     0x03   /* create file */
#define SMBclose      0x04   /* close file */
#define SMBflush      0x05   /* flush file */
#define SMBunlink     0x06   /* delete file */
#define SMBmv         0x07   /* rename file */
#define SMBgetatr     0x08   /* get file attributes */
#define SMBsetatr     0x09   /* set file attributes */
#define SMBread       0x0A   /* read from file */
#define SMBwrite      0x0B   /* write to file */
#define SMBlock       0x0C   /* lock byte range */
#define SMBunlock     0x0D   /* unlock byte range */
#define SMBctemp      0x0E   /* create temporary file */
#define SMBmknew      0x0F   /* make new file */
#define SMBchkpth     0x10   /* check directory path */
#define SMBexit       0x11   /* process exit */
#define SMBlseek      0x12   /* seek */
#define SMBtcon       0x70   /* tree connect */
#define SMBtconX      0x75   /* tree connect and X*/
#define SMBtdis       0x71   /* tree disconnect */
#define SMBnegprot    0x72   /* negotiate protocol */
#define SMBdskattr    0x80   /* get disk attributes */
#define SMBsearch     0x81   /* search directory */
#define SMBsplopen    0xC0   /* open print spool file */
#define SMBsplwr      0xC1   /* write to print spool file */
#define SMBsplclose   0xC2   /* close print spool file */
#define SMBsplretq    0xC3   /* return print queue */
#define SMBsends      0xD0   /* send single block message */
#define SMBsendb      0xD1   /* send broadcast message */
#define SMBfwdname    0xD2   /* forward user name */
#define SMBcancelf    0xD3   /* cancel forward */
#define SMBgetmac     0xD4   /* get machine name */
#define SMBsendstrt   0xD5   /* send start of multi-block message */
#define SMBsendend    0xD6   /* send end of multi-block message */
#define SMBsendtxt    0xD7   /* send text of multi-block message */

/* Core+ protocol */
#define SMBlockread	  0x13   /* Lock a range and read */
#define SMBwriteunlock 0x14 /* Unlock a range then write */
#define SMBreadbraw   0x1a  /* read a block of data with no smb header */
#define SMBwritebraw  0x1d  /* write a block of data with no smb header */
#define SMBwritec     0x20  /* secondary write request */
#define SMBwriteclose 0x2c  /* write a file then close it */

/* dos extended protocol */
#define SMBreadBraw      0x1A   /* read block raw */
#define SMBreadBmpx      0x1B   /* read block multiplexed */
#define SMBreadBs        0x1C   /* read block (secondary response) */
#define SMBwriteBraw     0x1D   /* write block raw */
#define SMBwriteBmpx     0x1E   /* write block multiplexed */
#define SMBwriteBs       0x1F   /* write block (secondary request) */
#define SMBwriteC        0x20   /* write complete response */
#define SMBsetattrE      0x22   /* set file attributes expanded */
#define SMBgetattrE      0x23   /* get file attributes expanded */
#define SMBlockingX      0x24   /* lock/unlock byte ranges and X */
#define SMBtrans         0x25   /* transaction - name, bytes in/out */
#define SMBtranss        0x26   /* transaction (secondary request/response) */
#define SMBioctl         0x27   /* IOCTL */
#define SMBioctls        0x28   /* IOCTL  (secondary request/response) */
#define SMBcopy          0x29   /* copy */
#define SMBmove          0x2A   /* move */
#define SMBecho          0x2B   /* echo */
#define SMBopenX         0x2D   /* open and X */
#define SMBreadX         0x2E   /* read and X */
#define SMBwriteX        0x2F   /* write and X */
#define SMBsesssetupX    0x73   /* Session Set Up & X (including User Logon) */
#define SMBffirst        0x82   /* find first */
#define SMBfunique       0x83   /* find unique */
#define SMBfclose        0x84   /* find close */
#define SMBinvalid       0xFE   /* invalid command */

/* Extended 2.0 protocol */
#define SMBtrans2        0x32   /* TRANS2 protocol set */
#define SMBtranss2       0x33   /* TRANS2 protocol set, secondary command */
#define SMBfindclose     0x34   /* Terminate a TRANSACT2_FINDFIRST */
#define SMBfindnclose    0x35   /* Terminate a TRANSACT2_FINDNOTIFYFIRST */
#define SMBulogoffX      0x74   /* user logoff */

/* NT SMB extensions. */
#define SMBnttrans       0xA0   /* NT transact */
#define SMBnttranss      0xA1   /* NT transact secondary */
#define SMBntcreateX     0xA2   /* NT create and X */
#define SMBntcancel      0xA4   /* NT cancel */

/* These are the TRANS2 sub commands */
#define TRANSACT2_OPEN                        0
#define TRANSACT2_FINDFIRST                   1
#define TRANSACT2_FINDNEXT                    2
#define TRANSACT2_QFSINFO                     3
#define TRANSACT2_SETFSINFO                   4
#define TRANSACT2_QPATHINFO                   5
#define TRANSACT2_SETPATHINFO                 6
#define TRANSACT2_QFILEINFO                   7
#define TRANSACT2_SETFILEINFO                 8
#define TRANSACT2_FSCTL                       9
#define TRANSACT2_IOCTL                     0xA
#define TRANSACT2_FINDNOTIFYFIRST           0xB
#define TRANSACT2_FINDNOTIFYNEXT            0xC
#define TRANSACT2_MKDIR                     0xD
#define TRANSACT2_SESSION_SETUP             0xE
#define TRANSACT2_GET_DFS_REFERRAL         0x10
#define TRANSACT2_REPORT_DFS_INCONSISTANCY 0x11

/* These are the NT transact sub commands. */
#define NT_TRANSACT_CREATE                 1
#define NT_TRANSACT_IOCTL                  2
#define NT_TRANSACT_SET_SECURITY_DESC      3
#define NT_TRANSACT_NOTIFY_CHANGE          4
#define NT_TRANSACT_RENAME                 5
#define NT_TRANSACT_QUERY_SECURITY_DESC    6
#define NT_TRANSACT_GET_DFS_REFERRAL    0x10

/* these are the trans2 sub fields for primary requests */
#define smb_tpscnt smb_vwv0
#define smb_tdscnt smb_vwv1
#define smb_mprcnt smb_vwv2
#define smb_mdrcnt smb_vwv3
#define smb_msrcnt smb_vwv4
#define smb_flags smb_vwv5
#define smb_timeout smb_vwv6
#define smb_pscnt smb_vwv9
#define smb_psoff smb_vwv10
#define smb_dscnt smb_vwv11
#define smb_dsoff smb_vwv12
#define smb_suwcnt smb_vwv13
#define smb_setup smb_vwv14
#define smb_setup0 smb_setup
#define smb_setup1 (smb_setup+2)
#define smb_setup2 (smb_setup+4)

/* these are for the secondary requests */
#define smb_spscnt smb_vwv2
#define smb_spsoff smb_vwv3
#define smb_spsdisp smb_vwv4
#define smb_sdscnt smb_vwv5
#define smb_sdsoff smb_vwv6
#define smb_sdsdisp smb_vwv7
#define smb_sfid smb_vwv8

/* and these for responses */
#define smb_tprcnt smb_vwv0
#define smb_tdrcnt smb_vwv1
#define smb_prcnt smb_vwv3
#define smb_proff smb_vwv4
#define smb_prdisp smb_vwv5
#define smb_drcnt smb_vwv6
#define smb_droff smb_vwv7
#define smb_drdisp smb_vwv8

/* these are for the NT trans primary request. */
#define smb_nt_MaxSetupCount smb_vwv0
#define smb_nt_Flags (smb_vwv0 + 1)
#define smb_nt_TotalParameterCount (smb_vwv0 + 3)
#define smb_nt_TotalDataCount (smb_vwv0 + 7)
#define smb_nt_MaxParameterCount (smb_vwv0 + 11)
#define smb_nt_MaxDataCount (smb_vwv0 + 15)
#define smb_nt_ParameterCount (smb_vwv0 + 19)
#define smb_nt_ParameterOffset (smb_vwv0 + 23)
#define smb_nt_DataCount (smb_vwv0 + 27)
#define smb_nt_DataOffset (smb_vwv0 + 31)
#define smb_nt_SetupCount (smb_vwv0 + 35)
#define smb_nt_Function (smb_vwv0 + 36)
#define smb_nt_SetupStart (smb_vwv0 + 38)

/* these are for the NT trans secondary request. */
#define smb_nts_TotalParameterCount (smb_vwv0 + 3)
#define smb_nts_TotalDataCount (smb_vwv0 + 7)
#define smb_nts_ParameterCount (smb_vwv0 + 11)
#define smb_nts_ParameterOffset (smb_vwv0 + 15)
#define smb_nts_ParameterDisplacement (smb_vwv0 + 19)
#define smb_nts_DataCount (smb_vwv0 + 23)
#define smb_nts_DataOffset (smb_vwv0 + 27)
#define smb_nts_DataDisplacement (smb_vwv0 + 31)

/* these are for the NT trans reply. */
#define smb_ntr_TotalParameterCount (smb_vwv0 + 3)
#define smb_ntr_TotalDataCount (smb_vwv0 + 7)
#define smb_ntr_ParameterCount (smb_vwv0 + 11)
#define smb_ntr_ParameterOffset (smb_vwv0 + 15)
#define smb_ntr_ParameterDisplacement (smb_vwv0 + 19)
#define smb_ntr_DataCount (smb_vwv0 + 23)
#define smb_ntr_DataOffset (smb_vwv0 + 27)
#define smb_ntr_DataDisplacement (smb_vwv0 + 31)

/* these are for the NT create_and_X */
#define smb_ntcreate_NameLength (smb_vwv0 + 5)
#define smb_ntcreate_Flags (smb_vwv0 + 7)
#define smb_ntcreate_RootDirectoryFid (smb_vwv0 + 11)
#define smb_ntcreate_DesiredAccess (smb_vwv0 + 15)
#define smb_ntcreate_AllocationSize (smb_vwv0 + 19)
#define smb_ntcreate_FileAttributes (smb_vwv0 + 27)
#define smb_ntcreate_ShareAccess (smb_vwv0 + 31)
#define smb_ntcreate_CreateDisposition (smb_vwv0 + 35)
#define smb_ntcreate_CreateOptions (smb_vwv0 + 39)
#define smb_ntcreate_ImpersonationLevel (smb_vwv0 + 43)
#define smb_ntcreate_SecurityFlags (smb_vwv0 + 47)

/* this is used on a TConX. I'm not sure the name is very helpful though */
#define SMB_SUPPORT_SEARCH_BITS        0x0001

/* these are the constants used in the above call. */
/* DesiredAccess */
/* File Specific access rights. */
#define FILE_READ_DATA        0x001
#define FILE_WRITE_DATA       0x002
#define FILE_APPEND_DATA      0x004
#define FILE_READ_EA          0x008
#define FILE_WRITE_EA         0x010
#define FILE_EXECUTE          0x020
#define FILE_DELETE_CHILD     0x040
#define FILE_READ_ATTRIBUTES  0x080
#define FILE_WRITE_ATTRIBUTES 0x100
 
/* Generic access masks & rights. */
#define SPECIFIC_RIGHTS_MASK 0x00FFFFL
#define STANDARD_RIGHTS_MASK 0xFF0000L
#define DELETE_ACCESS        (1L<<16)
#define READ_CONTROL_ACCESS  (1L<<17)
#define WRITE_DAC_ACCESS     (1L<<18)
#define WRITE_OWNER_ACCESS   (1L<<19)
#define SYNCHRONIZE_ACCESS   (1L<<20)
#define SYSTEM_SECURITY_ACCESS (1L<<24)

/* Flags field. */
#define REQUEST_OPLOCK 2
#define REQUEST_BATCH_OPLOCK 4
#define OPEN_DIRECTORY 8

/* ShareAccess field. */
#define FILE_SHARE_NONE 0 /* Cannot be used in bitmask. */
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4

/* FileAttributesField */
#define FILE_ATTRIBUTE_READONLY aRONLY
#define FILE_ATTRIBUTE_HIDDEN aHIDDEN
#define FILE_ATTRIBUTE_SYSTEM aSYSTEM
#define FILE_ATTRIBUTE_DIRECTORY aDIR
#define FILE_ATTRIBUTE_ARCHIVE aARCH
#define FILE_ATTRIBUTE_NORMAL 0x80L
#define FILE_ATTRIBUTE_TEMPORARY 0x100L
#define FILE_ATTRIBUTE_COMPRESSED 0x800L
#define SAMBA_ATTRIBUTES_MASK 0x7F

/* Flags - combined with attributes. */
#define FILE_FLAG_WRITE_THROUGH    0x80000000L
#define FILE_FLAG_NO_BUFFERING     0x20000000L
#define FILE_FLAG_RANDOM_ACCESS    0x10000000L
#define FILE_FLAG_SEQUENTIAL_SCAN  0x08000000L
#define FILE_FLAG_DELETE_ON_CLOSE  0x04000000L
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000L
#define FILE_FLAG_POSIX_SEMANTICS  0x01000000L

/* CreateDisposition field. */
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5

/* CreateOptions field. */
#define FILE_DIRECTORY_FILE       0x0001
#define FILE_WRITE_THROUGH        0x0002
#define FILE_SEQUENTIAL_ONLY      0x0004
#define FILE_NON_DIRECTORY_FILE   0x0040
#define FILE_NO_EA_KNOWLEDGE      0x0200
#define FILE_EIGHT_DOT_THREE_ONLY 0x0400
#define FILE_RANDOM_ACCESS        0x0800
#define FILE_DELETE_ON_CLOSE      0x1000

/* Responses when opening a file. */
#define FILE_WAS_OPENED 1
#define FILE_WAS_CREATED 2
#define FILE_WAS_OVERWRITTEN 3

/* File type flags */
#define FILE_TYPE_DISK  0
#define FILE_TYPE_BYTE_MODE_PIPE 1
#define FILE_TYPE_MESSAGE_MODE_PIPE 2
#define FILE_TYPE_PRINTER 3
#define FILE_TYPE_COMM_DEVICE 4
#define FILE_TYPE_UNKNOWN 0xFFFF

/* Flag for NT transact rename call. */
#define RENAME_REPLACE_IF_EXISTS 1

/* Filesystem Attributes. */
#define FILE_CASE_SENSITIVE_SEARCH 0x1
#define FILE_CASE_PRESERVED_NAMES 0x2
#define FILE_UNICODE_ON_DISK 0x4
#define FILE_PERISITANT_ACLS 0x8

/* ChangeNotify flags. */
#define FILE_NOTIFY_CHANGE_FILE_NAME   0x001
#define FILE_NOTIFY_CHANGE_DIR_NAME    0x002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES  0x004
#define FILE_NOTIFY_CHANGE_SIZE        0x008
#define FILE_NOTIFY_CHANGE_LAST_WRITE  0x010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS 0x020
#define FILE_NOTIFY_CHANGE_CREATION    0x040
#define FILE_NOTIFY_CHANGE_EA          0x080
#define FILE_NOTIFY_CHANGE_SECURITY    0x100

/* where to find the base of the SMB packet proper */
#define smb_base(buf) (((char *)(buf))+4)


#define SMB_SUCCESS 0  /* The request was successful. */
#define ERRDOS 0x01 /*  Error is from the core DOS operating system set. */
#define ERRSRV 0x02  /* Error is generated by the server network file manager.*/
#define ERRHRD 0x03  /* Error is an hardware error. */
#define ERRCMD 0xFF  /* Command was not in the "SMB" format. */

#ifdef HAVE_STDARG_H
int slprintf(char *str, int n, char *format, ...)
#ifdef __GNUC__
     __attribute__ ((format (printf, 3, 4)))
#endif
;
#else
int slprintf();
#endif

#ifdef WITH_DFS
void dfs_unlogin(void);
extern int dcelogin_atmost_once;
#endif

#ifdef NOSTRDUP
char *strdup(char *s);
#endif

#ifndef SIGNAL_CAST
#define SIGNAL_CAST (RETSIGTYPE (*)(int))
#endif

#ifndef SELECT_CAST
#define SELECT_CAST
#endif


/* Some POSIX definitions for those without */
 
#ifndef S_IFDIR
#define S_IFDIR         0x4000
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   ((mode & 0xF000) == S_IFDIR)
#endif
#ifndef S_IRWXU
#define S_IRWXU 00700           /* read, write, execute: owner */
#endif
#ifndef S_IRUSR
#define S_IRUSR 00400           /* read permission: owner */
#endif
#ifndef S_IWUSR
#define S_IWUSR 00200           /* write permission: owner */
#endif
#ifndef S_IXUSR
#define S_IXUSR 00100           /* execute permission: owner */
#endif
#ifndef S_IRWXG
#define S_IRWXG 00070           /* read, write, execute: group */
#endif
#ifndef S_IRGRP
#define S_IRGRP 00040           /* read permission: group */
#endif
#ifndef S_IWGRP
#define S_IWGRP 00020           /* write permission: group */
#endif
#ifndef S_IXGRP
#define S_IXGRP 00010           /* execute permission: group */
#endif
#ifndef S_IRWXO
#define S_IRWXO 00007           /* read, write, execute: other */
#endif
#ifndef S_IROTH
#define S_IROTH 00004           /* read permission: other */
#endif
#ifndef S_IWOTH
#define S_IWOTH 00002           /* write permission: other */
#endif
#ifndef S_IXOTH
#define S_IXOTH 00001           /* execute permission: other */
#endif


/* these are used in NetServerEnum to choose what to receive */
#define SV_TYPE_WORKSTATION         0x00000001
#define SV_TYPE_SERVER              0x00000002
#define SV_TYPE_SQLSERVER           0x00000004
#define SV_TYPE_DOMAIN_CTRL         0x00000008
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010
#define SV_TYPE_TIME_SOURCE         0x00000020
#define SV_TYPE_AFP                 0x00000040
#define SV_TYPE_NOVELL              0x00000080
#define SV_TYPE_DOMAIN_MEMBER       0x00000100
#define SV_TYPE_PRINTQ_SERVER       0x00000200
#define SV_TYPE_DIALIN_SERVER       0x00000400
#define SV_TYPE_SERVER_UNIX         0x00000800
#define SV_TYPE_NT                  0x00001000
#define SV_TYPE_WFW                 0x00002000
#define SV_TYPE_SERVER_MFPN         0x00004000
#define SV_TYPE_SERVER_NT           0x00008000
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000
#define SV_TYPE_BACKUP_BROWSER      0x00020000
#define SV_TYPE_MASTER_BROWSER      0x00040000
#define SV_TYPE_DOMAIN_MASTER       0x00080000
#define SV_TYPE_SERVER_OSF          0x00100000
#define SV_TYPE_SERVER_VMS          0x00200000
#define SV_TYPE_WIN95_PLUS          0x00400000
#define SV_TYPE_ALTERNATE_XPORT     0x20000000  
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  
#define SV_TYPE_DOMAIN_ENUM         0x80000000
#define SV_TYPE_ALL                 0xFFFFFFFF  

/* what server type are we currently  - JHT Says we ARE 4.20 */
/* this was set by JHT in liaison with Jeremy Allison early 1997 */
/* setting to 4.20 at same time as announcing ourselves as NT Server */
/* History: */
/* Version 4.0 - never made public */
/* Version 4.10 - New to 1.9.16p2, lost in space 1.9.16p3 to 1.9.16p9 */
/*		- Reappeared in 1.9.16p11 with fixed smbd services */
/* Version 4.20 - To indicate that nmbd and browsing now works better */

#define DEFAULT_MAJOR_VERSION 0x04
#define DEFAULT_MINOR_VERSION 0x00

/* Browser Election Values */
#define BROWSER_ELECTION_VERSION	0x010f
#define BROWSER_CONSTANT	0xaa55

/* NT Flags2 bits - cifs6.txt section 3.1.2 */
   
#define FLAGS2_LONG_PATH_COMPONENTS   0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES    0x0002
#define FLAGS2_EXT_SEC                0x0800
#define FLAGS2_DFS_PATHNAMES          0x1000
#define FLAGS2_READ_PERMIT_NO_EXECUTE 0x2000
#define FLAGS2_32_BIT_ERROR_CODES     0x4000 
#define FLAGS2_UNICODE_STRINGS        0x8000

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE          0x00000001
#define CAP_MPX_MODE          0x00000002
#define CAP_UNICODE           0x00000004
#define CAP_LARGE_FILES       0x00000008
#define CAP_NT_SMBS           0x00000010
#define CAP_RPC_REMOTE_APIS   0x00000020
#define CAP_STATUS32          0x00000040
#define CAP_LEVEL_II_OPLOCKS  0x00000080
#define CAP_LOCK_AND_READ     0x00000100
#define CAP_NT_FIND           0x00000200
#define CAP_DFS               0x00001000
#define CAP_LARGE_READX       0x00004000
#define CAP_EXTENDED_SECURITY 0x80000000

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets */
enum protocol_types {PROTOCOL_NONE,PROTOCOL_CORE,PROTOCOL_COREPLUS,PROTOCOL_LANMAN1,PROTOCOL_LANMAN2,PROTOCOL_NT1};

/* security levels */
enum security_types {SEC_SHARE,SEC_USER,SEC_SERVER,SEC_DOMAIN};

/* server roles */
enum server_types
{
	ROLE_DOMAIN_NONE,
	ROLE_DOMAIN_MEMBER,
	ROLE_DOMAIN_BDC,
	ROLE_DOMAIN_PDC
};

/* printing types */
enum printing_types {PRINT_BSD,PRINT_SYSV,PRINT_AIX,PRINT_HPUX,
		     PRINT_QNX,PRINT_PLP,PRINT_LPRNG,PRINT_SOFTQ};

/* Remote architectures we know about. */
enum remote_arch_types {RA_UNKNOWN, RA_WFWG, RA_OS2, RA_WIN95, RA_WINNT, RA_SAMBA};

/* case handling */
enum case_handling {CASE_LOWER,CASE_UPPER};

#ifdef WITH_SSL
/* SSL version options */
enum ssl_version_enum {SMB_SSL_V2,SMB_SSL_V3,SMB_SSL_V23,SMB_SSL_TLS1};
#endif /* WITH_SSL */

/*
 * Global value meaing that the smb_uid field should be
 * ingored (in share level security and protocol level == CORE)
 */

#define UID_FIELD_INVALID 0
#define VUID_OFFSET 100 /* Amount to bias returned vuid numbers */

/* Defines needed for multi-codepage support. */
#define MSDOS_LATIN_1_CODEPAGE 850
#define KANJI_CODEPAGE 932
#define HANGUL_CODEPAGE 949
#define BIG5_CODEPAGE 950
#define SIMPLIFIED_CHINESE_CODEPAGE 936

#ifdef KANJI
/* 
 * Default client code page - Japanese 
 */
#define DEFAULT_CLIENT_CODE_PAGE KANJI_CODEPAGE
#else /* KANJI */
/* 
 * Default client code page - 850 - Western European 
 */
#define DEFAULT_CLIENT_CODE_PAGE MSDOS_LATIN_1_CODEPAGE
#endif /* KANJI */

/* 
 * Size of buffer to use when moving files across filesystems. 
 */
#define COPYBUF_SIZE (8*1024)

/* 
 * Integers used to override error codes. 
 */
extern int unix_ERR_class;
extern int unix_ERR_code;

/*
 * Map the Core and Extended Oplock requesst bits down
 * to common bits (EXCLUSIVE_OPLOCK & BATCH_OPLOCK).
 */

/*
 * Core protocol.
 */
#define CORE_OPLOCK_REQUEST(inbuf) \
    ((CVAL(inbuf,smb_flg)&(FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK))>>5)

/*
 * Extended protocol.
 */
#define EXTENDED_OPLOCK_REQUEST(inbuf) ((SVAL(inbuf,smb_vwv2)&((1<<1)|(1<<2)))>>1)

/* Lock types. */
#define LOCKING_ANDX_SHARED_LOCK 0x1
#define LOCKING_ANDX_OPLOCK_RELEASE 0x2
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x4
#define LOCKING_ANDX_CANCEL_LOCK 0x8
#define LOCKING_ANDX_LARGE_FILES 0x10

/* Oplock levels */
#define OPLOCKLEVEL_NONE 0
#define OPLOCKLEVEL_II 1

/*
 * Bits we test with.
 */

#define NO_OPLOCK 0
#define EXCLUSIVE_OPLOCK 1
#define BATCH_OPLOCK 2
#define LEVEL_II_OPLOCK 4

#define EXCLUSIVE_OPLOCK_TYPE(lck) ((lck) & (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
#define BATCH_OPLOCK_TYPE(lck) ((lck) & BATCH_OPLOCK)
#define LEVEL_II_OPLOCK_TYPE(lck) ((lck) & LEVEL_II_OPLOCK)

#define CORE_OPLOCK_GRANTED (1<<5)
#define EXTENDED_OPLOCK_GRANTED (1<<15)

/*
 * Loopback command offsets.
 */

#define OPBRK_CMD_LEN_OFFSET 0
#define OPBRK_CMD_PORT_OFFSET 4
#define OPBRK_CMD_HEADER_LEN 6

#define OPBRK_MESSAGE_CMD_OFFSET 0

/*
 * Oplock break command code to send over the udp socket.
 * 
 * Form of this is :
 *
 *  0     2       6        10       14    14+devsize 14+devsize+inodesize
 *  +----+--------+--------+--------+-------+--------+
 *  | cmd| pid    | sec    | usec   | dev   |  inode |
 *  +----+--------+--------+--------+-------+--------+
 */

#define OPLOCK_BREAK_CMD 0x1
#define OPLOCK_BREAK_PID_OFFSET 2
#define OPLOCK_BREAK_SEC_OFFSET 6
#define OPLOCK_BREAK_USEC_OFFSET 10
#define OPLOCK_BREAK_DEV_OFFSET 14
#define OPLOCK_BREAK_INODE_OFFSET (OPLOCK_BREAK_DEV_OFFSET + sizeof(SMB_DEV_T))
#define OPLOCK_BREAK_MSG_LEN (OPLOCK_BREAK_INODE_OFFSET + sizeof(SMB_INO_T))

/*
 * Capabilities abstracted for different systems.
 */

#define KERNEL_OPLOCK_CAPABILITY 0x1

#if defined(HAVE_KERNEL_OPLOCKS)
/*
 * Oplock break command code sent via the kernel interface.
 *
 * Form of this is :
 *
 *  0     2       2+devsize 2+devsize+inodesize
 *  +----+--------+--------+
 *  | cmd| dev    |  inode |
 *  +----+--------+--------+
 */

#define KERNEL_OPLOCK_BREAK_CMD 0x2
#define KERNEL_OPLOCK_BREAK_DEV_OFFSET 2
#define KERNEL_OPLOCK_BREAK_INODE_OFFSET (KERNEL_OPLOCK_BREAK_DEV_OFFSET + sizeof(SMB_DEV_T))
#define KERNEL_OPLOCK_BREAK_MSG_LEN (KERNEL_OPLOCK_BREAK_INODE_OFFSET + sizeof(SMB_INO_T))

#endif /* HAVE_KERNEL_OPLOCKS */

#define CMD_REPLY 0x8000

#include "smb_macros.h"

#include "nt_printing.h"

typedef struct
{
	uint32 pid;
	uint16 vuid;

} vuser_key;

#include "ntdomain.h"

typedef struct
{
  uid_t uid; /* uid of a validated user */
  gid_t gid; /* gid of a validated user */

  fstring requested_name; /* user name from the client */
  fstring name; /* unix user name of a validated user */
  fstring real_name;   /* to store real name from password file - simeon */
  BOOL guest;

  /* following groups stuff added by ih */
  /* This groups info is needed for when we become_user() for this uid */
  int n_groups;
  gid_t *groups;

	NET_USER_INFO_3 usr;

} user_struct;

struct current_user
{
	connection_struct *conn;
	vuser_key key;
	uid_t uid;
	gid_t gid;
	int ngroups;
	gid_t *groups;
};

/* A netbios name structure. */
struct nmb_name {
  char         name[17];
  char         scope[64];
  unsigned int name_type;
};


#include "dfs.h"

/*
 * Size of new password account encoding string. DO NOT CHANGE.
 */

#define NEW_PW_FORMAT_SPACE_PADDED_LEN 14

/*
   Do you want session setups at user level security with a invalid
   password to be rejected or allowed in as guest? WinNT rejects them
   but it can be a pain as it means "net view" needs to use a password

   You have 3 choices in the setting of map_to_guest:

   "NEVER_MAP_TO_GUEST" means session setups with an invalid password
   are rejected. This is the default.

   "MAP_TO_GUEST_ON_BAD_USER" means session setups with an invalid password
   are rejected, unless the username does not exist, in which case it
   is treated as a guest login

   "MAP_TO_GUEST_ON_BAD_PASSWORD" means session setups with an invalid password
   are treated as a guest login

   Note that map_to_guest only has an effect in user or server
   level security.
*/

#define NEVER_MAP_TO_GUEST 0
#define MAP_TO_GUEST_ON_BAD_USER 1
#define MAP_TO_GUEST_ON_BAD_PASSWORD 2

/* associate bit field or enumeration field with a string */
struct field_info
{
	uint32 bits;
	char *str;
};

#define AGENT_CMD_CON       0
#define AGENT_CMD_CON_ANON  2
#define AGENT_CMD_CON_REUSE 1

#define MAX_MAX_MUX_LIMIT 16

struct nmb_state
{
	struct in_addr ip;
	int port;
};

struct pwd_info
{
	BOOL null_pwd;
	BOOL cleartext;
	BOOL crypted;

	fstring password;

	uchar smb_lm_pwd[16];
	uchar smb_nt_pwd[16];

	uchar smb_lm_owf[24];
	uchar smb_nt_owf[128];
	size_t nt_owf_len;

	uchar lm_cli_chal[8];
	uchar nt_cli_chal[128];
	size_t nt_cli_chal_len;
};

typedef struct subst_creds
{
	uid_t uid;
	fstring nt_username;
	fstring client_addr;
	fstring local_machine;
	fstring client_name;
	fstring remote_proto;
	fstring remote_arch;
	fstring myhostname;
	fstring remote_machine;

} CREDS_SUBST;

#include "rpc_creds.h"

struct ntdom_info
{
	unsigned char usr_sess_key[16];   /* Current user session key. */
	uint32 ntlmssp_cli_flgs;           /* ntlmssp client flags */
	uint32 ntlmssp_srv_flgs;           /* ntlmssp server flags */

	unsigned char sess_key[16];        /* Client NETLOGON session key. */
	DOM_CRED clnt_cred;                /* Client NETLOGON credential. */

	int max_recv_frag;
	int max_xmit_frag;

	vuser_key key;
};

struct msrpc_state
{
	fstring pipe_name;
	struct user_creds usr;
	struct ntdom_info nt;
	cli_auth_fns *auth;
	void *auth_info;

	int fd;
	BOOL redirect;
	BOOL initialised;
	char *inbuf;
	char *outbuf;
};

typedef struct netsec_creds
{
	fstring domain;
	fstring myname;

	uchar sess_key[16]; /* NETLOGON session key */

} netsec_creds;

struct policy;
struct bitmap;

typedef struct policy_cache
{
	struct policy *Policy;
	struct bitmap *bmap;
} policy_cache;

#include "client.h"
#include "rpcclient.h"

#endif /* _SMB_H */

/* _SMB_H */

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
#ifndef _SMB_H
#define _SMB_H

enum display_type   { DISPLAY_NONE, DISPLAY_TXT, DISPLAY_HTML };
enum action_type    { ACTION_HEADER, ACTION_ENUMERATE, ACTION_FOOTER };

#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 127
#endif

#ifndef MAX_OPEN_FILES
#define MAX_OPEN_FILES 50
#endif

#ifndef GUEST_ACCOUNT
#define GUEST_ACCOUNT "nobody"
#endif

#define BUFFER_SIZE (0xFFFF)
#define SAFETY_MARGIN 1024

/* Default size of shared memory used for share mode locking */
#ifndef SHMEM_SIZE
#define SHMEM_SIZE 102400
#endif

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139

#define False (0)
#define True (1)
#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETB(ptr,bit) ((((char *)ptr)[0] & (1<<(bit)))!=0)
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)

#define IS_BITS_SET_ALL(var,bit) (((var)&(bit))==(bit))
#define IS_BITS_SET_SOME(var,bit) (((var)&(bit))!=0)
#define IS_BITS_CLR_ALL(var,bit) (((var)&(~(bit)))==0)

#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((char *)(p1)) - (char *)(p2)))

typedef int BOOL;

/* limiting size of ipc replies */
#define REALLOC(ptr,size) Realloc(ptr,MAX((size),4*1024))

/*
   Samba needs type definitions for int16, int32, uint16 and uint32.
   
   Normally these are signed and unsigned 16 and 32 bit integers, but
   they actually only need to be at least 16 and 32 bits
   respectively. Thus if your word size is 8 bytes just defining them
   as signed and unsigned int will work.
*/

/* afs/stds.h defines int16 and int32 */
#ifndef AFS_AUTH
typedef short int16;
typedef int int32;
#endif

#ifndef uint8
typedef unsigned char uint8;
#endif

#ifndef uint16
typedef unsigned short uint16;
#endif

#ifndef uint32
typedef unsigned int uint32;
#endif

#ifndef uchar
#define uchar unsigned char
#endif
#ifndef int16
#define int16 short
#endif
#ifndef uint16
#define uint16 unsigned short
#endif
#ifndef uint32
#define uint32 unsigned int
#endif

typedef char pstring[1024];
typedef char fstring[128];
typedef fstring string;

#include "ntdomain.h"

#define SIZEOFWORD 2

#ifndef DEF_CREATE_MASK
#define DEF_CREATE_MASK (0755)
#endif

/* how long to wait for secondary SMB packets (milli-seconds) */
#define SMB_SECONDARY_WAIT (60*1000)

/* debugging code */
#ifndef SYSLOG
#define DEBUG(level,body) ((DEBUGLEVEL>=(level))?(Debug1 body):0)
#else
extern int syslog_level;

#define DEBUG(level,body) ((DEBUGLEVEL>=(level))? (syslog_level = (level), Debug1 body):0)
#endif

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

/* share types */
#define STYPE_DISKTREE  0	/* Disk drive */
#define STYPE_PRINTQ    1	/* Spooler queue */
#define STYPE_DEVICE    2	/* Serial device */
#define STYPE_IPC       3	/* Interprocess communication (IPC) */
#define STYPE_HIDDEN    0x80000000 /* share is a hidden one (ends with $) */

/* SMB X/Open error codes for the ERRdos error class */
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
#define ERRfilexists 80 /* File in operation already exists */
#define ERRcannotopen 110 /* Cannot open the file specified */
#define ERRunknownlevel 124
#define ERRbadpipe 230 /* Named pipe invalid */
#define ERRpipebusy 231 /* All instances of pipe are busy */
#define ERRpipeclosing 232 /* named pipe close in progress */
#define ERRnotconnected 233 /* No process on other end of named pipe */
#define ERRmoredata 234 /* More data to be returned */
#define ERRbaddirectory 267 /* Invalid directory name in a path. */
#define ERROR_EAS_DIDNT_FIT 275 /* Extended attributes didn't fit */
#define ERROR_EAS_NOT_SUPPORTED 282 /* Extended attributes not supported */
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


/* pipe strings */
#define PIPE_LANMAN   "\\PIPE\\LANMAN"
#define PIPE_SRVSVC   "\\PIPE\\srvsvc"
#define PIPE_SAMR     "\\PIPE\\samr"
#define PIPE_WINREG   "\\PIPE\\winreg"
#define PIPE_WKSSVC   "\\PIPE\\wkssvc"
#define PIPE_NETLOGON "\\PIPE\\NETLOGON"
#define PIPE_NTLSA    "\\PIPE\\ntlsa"
#define PIPE_NTSVCS   "\\PIPE\\ntsvcs"
#define PIPE_LSASS    "\\PIPE\\lsass"
#define PIPE_LSARPC   "\\PIPE\\lsarpc"

/* NETLOGON opcodes and data structures */

#define UDP_NET_QUERYFORPDC	     7 /* Query for PDC */
#define UDP_NET_QUERYFORPDC_R   12 /* Response to Query for PDC */
#define UDP_NET_SAMLOGON        18
#define UDP_NET_SAMLOGON_R      19

typedef struct 
{
	uint32 rid;
	char *name;

} rid_name;

struct smb_passwd
{
	int smb_userid;
	fstring smb_name;
	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */
	/* Other fields / flags may be added later */
	uint16 acct_ctrl;
};

/* this is probably going to max out at one... :-) */
#define MAX_CLIENT_CONNECTIONS 30

/* tconX-specific information */
struct tcon_state
{
	int cnum;
	fstring full_share;
	char dev[16];
};

struct cli_state
{
	int fd;
	int pid;
	int mid;
	int uid;
	int protocol;
	int sec_mode;
	int error;
	int privileges;
	fstring eff_name;

	struct tcon_state con[MAX_CLIENT_CONNECTIONS];
	int num_tcons;

	fstring full_dest_host_name;
	char called_netbios_name[16];
	char calling_netbios_name[16];

	uchar cryptkey[8];
	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int readbraw_supported;
	int writebraw_supported;
	int timeout;
	int max_xmit;
	char *outbuf;
	char *inbuf;
	int bufsize;
	int initialised;
};


struct current_user
{
  int cnum, id;
  int uid, gid;
  int ngroups;
  gid_t *groups;
  int *igroups;
  int *attrs;
};

typedef struct
{
  int size;
  int mode;
  int uid;
  int gid;
  /* these times are normally kept in GMT */
  time_t mtime;
  time_t atime;
  time_t ctime;
  pstring name;

} file_info;

/* Domain controller authentication protocol info */
struct dcinfo
{
  DOM_CHAL clnt_chal; /* Initial challenge received from client */
  DOM_CHAL srv_chal;  /* Initial server challenge */
  DOM_CRED clnt_cred; /* Last client credential */
  DOM_CRED srv_cred;  /* Last server credential */

  uchar  sess_key[16]; /* Session key */
  uchar  md4pw[16];   /* md4(machine password) */
};

struct acct_info
{
	POLICY_HND acct_pol; /* use this as a reference */
	fstring acct_name; /* account name */
	uint32 smb_userid; /* domain-relative RID */
};

struct nt_client_info
{
	/************* \PIPE\srvsvc stuff ******************/

	uint16 srvsvc_fnum;
	
	/************* \PIPE\NETLOGON stuff ******************/

	uint16 netlogon_fnum;

	fstring mach_acct;

	uint8 sess_key[16];
	DOM_CRED clnt_cred;
	DOM_CRED rtn_cred;

	DOM_ID_INFO_1 id1;
	LSA_USER_INFO_3 user_info3;

	/************** \PIPE\lsarpc stuff ********************/

	uint16 lsarpc_fnum;

	POLICY_HND lsa_info_pol;

	/* domain member */
	fstring level3_dom;
	fstring level3_sid;

	/* domain controller */
	fstring level5_dom;
	fstring level5_sid;

	/************** \PIPE\samr stuff  ********************/

	uint16 samr_fnum;

	POLICY_HND samr_pol_connect;
	POLICY_HND samr_pol_open_domain;
	POLICY_HND samr_pol_open_user;

	struct acct_info sam[MAX_SAM_ENTRIES];
	int num_sam_entries;
};


struct tar_client_info
{
	int blocksize;
	BOOL inc;
	BOOL reset;
	BOOL excl;
	char type;
	int attrib;
	char **cliplist;
	int clipn;
	int tp;
	int num_files;
	int buf_size;
	int bytes_written;
	char *buf;
	int handle;
	int print_mode;
	char *file_mode;
};

struct client_info 
{
	struct in_addr dest_ip;
	fstring dest_host;
	fstring query_host;
	uint8 name_type;

	fstring myhostname;
	fstring username;
	fstring workgroup;
	fstring mach_acct;

	pstring cur_dir;
	pstring base_dir;
	pstring file_sel;

	fstring service;
	fstring share;
	fstring svc_type;

	time_t newer_than;
	int archive_level;
	int dir_total;
	int put_total_time_ms;
	int put_total_size;
	int get_total_time_ms;
	int get_total_size;
	int print_mode;
	BOOL translation;
	BOOL recurse_dir;
	BOOL prompt;
	BOOL lowercase;
	BOOL abort_mget;

	struct tar_client_info tar;
	struct nt_client_info dom;
};

/* Structure used when SMBwritebmpx is active */
typedef struct
        {
	int   wr_total_written; /* So we know when to discard this */
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

typedef struct
{
  uint16 ref_count;
  uint32 dev;
  uint32 inode;
  int fd;
  int fd_readonly;
  int fd_writeonly;
  int real_open_flags;
} file_fd_struct;

typedef struct
{
  int cnum;
  file_fd_struct *fd_ptr;
  int pos;
  uint32 size;
  int mode;
  int uid;
  char *mmap_ptr;
  uint32 mmap_size;
  write_bmpx_struct *wbmpx_ptr;
  struct timeval open_time;
  BOOL open;
  BOOL can_lock;
  BOOL can_read;
  BOOL can_write;
  BOOL share_mode;
  BOOL print_file;
  BOOL modified;
  BOOL granted_oplock;
  char *name;
} files_struct;

struct mem_buf
{
	char *data;
	uint32 data_size;
	uint32 data_used;

	uint32 margin; /* safety margin when reallocing. */
			    /* this can be abused quite nicely */

	uint8 align; /* alignment of data structures (smb, dce/rpc, udp etc) */
	uint32 start_offset; /* when used with mem_array, this can be non-zero */
};

#define mem_buffer mem_buf /* for now... */

struct api_struct
{
  char *name;
  uint8 opnum;
  void (*fn) (int uid, struct mem_buf*, int*, struct mem_buf*, int*);
};

struct uid_cache {
  int entries;
  int list[UID_CACHE_SIZE];
};

typedef struct
{
  char *name;
  BOOL is_wild;
} name_compare_entry;

typedef struct
{
  int service;
  BOOL force_user;
  struct uid_cache uid_cache;
  void *dirptr;
  BOOL open;
  BOOL printer;
  BOOL ipc;
  BOOL read_only;
  BOOL admin_user;
  char *dirpath;
  char *connectpath;
  char *origpath;
  char *user; /* name of user who *opened* this connection */
  int uid; /* uid of user who *opened* this connection */
  int gid; /* gid of user who *opened* this connection */

  uint16 vuid; /* vuid of user who *opened* this connection, or UID_FIELD_INVALID */

  /* following groups stuff added by ih */

  /* This groups info is valid for the user that *opened* the connection */
  int ngroups;
  gid_t *groups;
  int *igroups; /* an integer version - some OSes are broken :-( */
  int *attrs;

  time_t lastused;
  BOOL used;
  int num_files_open;
  name_compare_entry *hide_list; /* Per-share list of files to return as hidden. */
  name_compare_entry *veto_list; /* Per-share list of files to veto (never show). */

} connection_struct;

typedef struct
{
  int uid; /* uid of a validated user */
  int gid; /* gid of a validated user */

  fstring name; /* name of a validated user */
  fstring real_name;   /* to store real name from password file - simeon */
  BOOL guest;

  /* following groups stuff added by ih */
  /* This groups info is needed for when we become_user() for this uid */
  int n_groups;
  gid_t *groups;
  int *igroups; /* an integer version - some OSes are broken :-( */
  int *attrs; /* attributes associated with each gid */

  int n_sids;
  int *sids;

  /* per-user authentication information on NT RPCs */
  struct dcinfo dc;

} user_struct;


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
	BOOL (*lock_entry)(int , uint32 , uint32 , int *);
	BOOL (*unlock_entry)(int , uint32 , uint32 , int );
	BOOL (*get_entries)(int , int , uint32 , uint32 , share_mode_entry **);
	void (*del_entry)(int , int );
	BOOL (*set_entry)(int , int , uint16 , uint16 );
	BOOL (*remove_oplock)(int , int);
	int (*forall)(void (*)(share_mode_entry *, char *));
	void (*status)(FILE *);
};

/* each implementation of the shared memory code needs
   to support the following operations */
struct shmem_ops {
	BOOL (*close)( void );
	int (*alloc)(int );
	BOOL (*free)(int );
	int (*get_userdef_off)(void);
	void *(*offset2addr)(int );
	int (*addr2offset)(void *addr);
	BOOL (*lock_hash_entry)(unsigned int);
	BOOL (*unlock_hash_entry)( unsigned int );
	BOOL (*get_usage)(int *,int *,int *);
	unsigned (*hash_size)(void);
};


/* this is used for smbstatus */
struct connect_record
{
  int magic;
  int pid;
  int cnum;
  int uid;
  int gid;
  char name[24];
  char addr[24];
  char machine[128];
  time_t start;
};

#ifndef LOCKING_VERSION
#define LOCKING_VERSION 4
#endif /* LOCKING_VERSION */

/* these are useful macros for checking validity of handles */
#define VALID_FNUM(fnum)   (((fnum) >= 0) && ((fnum) < MAX_OPEN_FILES))
#define OPEN_FNUM(fnum)    (VALID_FNUM(fnum) && Files[fnum].open)
#define VALID_CNUM(cnum)   (((cnum) >= 0) && ((cnum) < MAX_CONNECTIONS))
#define OPEN_CNUM(cnum)    (VALID_CNUM(cnum) && Connections[cnum].open)
#define IS_IPC(cnum)       (VALID_CNUM(cnum) && Connections[cnum].ipc)
#define IS_PRINT(cnum)       (VALID_CNUM(cnum) && Connections[cnum].printer)
#define FNUM_OK(fnum,c) (OPEN_FNUM(fnum) && (c)==Files[fnum].cnum)

#define CHECK_FNUM(fnum,c) if (!FNUM_OK(fnum,c)) \
                               return(ERROR(ERRDOS,ERRbadfid))
#define CHECK_READ(fnum) if (!Files[fnum].can_read) \
                               return(ERROR(ERRDOS,ERRbadaccess))
#define CHECK_WRITE(fnum) if (!Files[fnum].can_write) \
                               return(ERROR(ERRDOS,ERRbadaccess))
#define CHECK_ERROR(fnum) if (HAS_CACHED_ERROR(fnum)) \
                               return(CACHED_ERROR(fnum))

/* translates a connection number into a service number */
#define SNUM(cnum)         (Connections[cnum].service)

/* access various service details */
#define SERVICE(snum)      (lp_servicename(snum))
#define PRINTCAP           (lp_printcapname())
#define PRINTCOMMAND(snum) (lp_printcommand(snum))
#define PRINTERNAME(snum)  (lp_printername(snum))
#define CAN_WRITE(cnum)    (OPEN_CNUM(cnum) && !Connections[cnum].read_only)
#define VALID_SNUM(snum)   (lp_snum_ok(snum))
#define GUEST_OK(snum)     (VALID_SNUM(snum) && lp_guest_ok(snum))
#define GUEST_ONLY(snum)   (VALID_SNUM(snum) && lp_guest_only(snum))
#define CAN_SETDIR(snum)   (!lp_no_set_dir(snum))
#define CAN_PRINT(cnum)    (OPEN_CNUM(cnum) && lp_print_ok(SNUM(cnum)))
#define POSTSCRIPT(cnum)   (OPEN_CNUM(cnum) && lp_postscript(SNUM(cnum)))
#define MAP_HIDDEN(cnum)   (OPEN_CNUM(cnum) && lp_map_hidden(SNUM(cnum)))
#define MAP_SYSTEM(cnum)   (OPEN_CNUM(cnum) && lp_map_system(SNUM(cnum)))
#define MAP_ARCHIVE(cnum)   (OPEN_CNUM(cnum) && lp_map_archive(SNUM(cnum)))
#define IS_HIDDEN_PATH(cnum,path)  (is_in_path((path),Connections[(cnum)].hide_list))
#define IS_VETO_PATH(cnum,path)  (is_in_path((path),Connections[(cnum)].veto_list))

#define SMBENCRYPT()       (lp_encrypted_passwords())

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
#define NT_TRANSACT_CREATE                1
#define NT_TRANSACT_IOCTL                 2
#define NT_TRANSACT_SET_SECURITY_DESC     3
#define NT_TRANSACT_NOTIFY_CHANGE         4
#define NT_TRANSACT_RENAME                5
#define NT_TRANSACT_QUERY_SECURITY_DESC   6

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

/* where to find the base of the SMB packet proper */
#define smb_base(buf) (((char *)(buf))+4)


/* bit-field in SessSetup response "setup action" */
#define SESSION_LOGGED_ON_AS_USER 0x1

#define SUCCESS 0  /* The request was successful. */
#define ERRDOS 0x01 /*  Error is from the core DOS operating system set. */
#define ERRSRV 0x02  /* Error is generated by the server network file manager.*/
#define ERRHRD 0x03  /* Error is an hardware error. */
#define ERRCMD 0xFF  /* Command was not in the "SMB" format. */

#ifdef __STDC__
int Debug1(char *, ...);
#else
int Debug1();
#endif

#ifdef DFS_AUTH
void dfs_unlogin(void);
extern int dcelogin_atmost_once;
#endif

#if AJT
void ajt_panic(void);
#endif

#ifdef NOSTRDUP
char *strdup(char *s);
#endif

#ifdef REPLACE_STRLEN
int Strlen(char *);
#endif

#ifdef REPLACE_STRSTR
char *Strstr(char *s, char *p);
#endif

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef ABS
#define ABS(a) ((a)>0?(a):(-(a)))
#endif

#ifndef SIGNAL_CAST
#define SIGNAL_CAST
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
#define DEFAULT_MINOR_VERSION 0x02

/* Browser Election Values */
#define BROWSER_ELECTION_VERSION	0x010f
#define BROWSER_CONSTANT	0xaa55


/* NT Flags2 bits - cifs6.txt section 3.1.2 */

#define FLAGS2_LONG_PATH_COMPONENTS   0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES    0x0002
#define FLAGS2_DFS_PATHNAMES          0x1000
#define FLAGS2_READ_PERMIT_NO_EXECUTE 0x2000
#define FLAGS2_32_BIT_ERROR_CODES     0x4000
#define FLAGS2_UNICODE_STRINGS        0x8000

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE         0x0001
#define CAP_MPX_MODE         0x0002
#define CAP_UNICODE          0x0004
#define CAP_LARGE_FILES      0x0008
#define CAP_NT_SMBS          0x0010
#define CAP_RPC_REMOTE_APIS  0x0020
#define CAP_STATUS32         0x0040
#define CAP_LEVEL_II_OPLOCKS 0x0080
#define CAP_LOCK_AND_READ    0x0100
#define CAP_NT_FIND          0x0200
#define CAP_DFS              0x1000
#define CAP_LARGE_READX      0x4000

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets */
enum protocol_types
{
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1
};

/* security levels */
enum security_types
{
	SEC_SHARE,
	SEC_USER,
	SEC_SERVER
};

/* bit-masks for security mode.  see cifs6.txt Negprot 4.1.1 server response */
#define USE_USER_LEVEL_SECURITY 0x01
#define USE_CHALLENGE_RESPONSE  0x02

/* printing types */
enum printing_types
{
	PRINT_BSD,
	PRINT_SYSV,
	PRINT_AIX,
	PRINT_HPUX,
	PRINT_QNX,
	PRINT_PLP,
	PRINT_LPRNG
};

/* Remote architectures we know about. */
enum remote_arch_types {RA_UNKNOWN, RA_WFWG, RA_OS2, RA_WIN95, RA_WINNT, RA_SAMBA};

/* case handling */
enum case_handling {CASE_LOWER,CASE_UPPER};


/* Macros to get at offsets within smb_lkrng and smb_unlkrng
   structures. We cannot define these as actual structures
   due to possible differences in structure packing
   on different machines/compilers. */

#define SMB_LPID_OFFSET(indx) (10 * (indx))
#define SMB_LKOFF_OFFSET(indx) ( 2 + (10 * (indx)))
#define SMB_LKLEN_OFFSET(indx) ( 6 + (10 * (indx)))

/* Macro to cache an error in a write_bmpx_struct */
#define CACHE_ERROR(w,c,e) ((w)->wr_errclass = (c), (w)->wr_error = (e), \
			    w->wr_discard = True, -1)
/* Macro to test if an error has been cached for this fnum */
#define HAS_CACHED_ERROR(fnum) (Files[(fnum)].open && \
				Files[(fnum)].wbmpx_ptr && \
				Files[(fnum)].wbmpx_ptr->wr_discard)
/* Macro to turn the cached error into an error packet */
#define CACHED_ERROR(fnum) cached_error_packet(inbuf,outbuf,fnum,__LINE__)

/* these are the datagram types */
#define DGRAM_DIRECT_UNIQUE 0x10

#define ERROR(class,x) error_packet(inbuf,outbuf,class,x,__LINE__)

/* this is how errors are generated */
#define UNIXERROR(defclass,deferror) unix_error_packet(inbuf,outbuf,defclass,deferror,__LINE__)

#define ROUNDUP(x,g) (((x)+((g)-1))&~((g)-1))

/*
 * Global value meaing that the smb_uid field should be
 * ingored (in share level security and protocol level == CORE)
 */

#define UID_FIELD_INVALID 0
#define VUID_OFFSET 100 /* Amount to bias returned vuid numbers */

#endif 

/* Defines needed for multi-codepage support. */
#define KANJI_CODEPAGE 932

#ifdef KANJI
/* 
 * Default client code page - Japanese 
 */
#define DEFAULT_CLIENT_CODE_PAGE KANJI_CODEPAGE
#else /* KANJI */
/* 
 * Default client code page - 850 - Western European 
 */
#define DEFAULT_CLIENT_CODE_PAGE 850
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
#define CORE_OPLOCK_REQUEST(inbuf) ((CVAL(inbuf,smb_flg)&((1<<5)|(1<<6)))>>5)

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
#define EXCLUSIVE_OPLOCK 1
#define BATCH_OPLOCK 2

#define CORE_OPLOCK_GRANTED (1<<5)
#define EXTENDED_OPLOCK_GRANTED (1<<15)

/*
 * Loopback command offsets.
 */

#define UDP_CMD_LEN_OFFSET 0
#define UDP_CMD_PORT_OFFSET 4
#define UDP_CMD_HEADER_LEN 6

#define UDP_MESSAGE_CMD_OFFSET 0

/*
 * Oplock break command code to send over the udp socket.
 * 
 * Form of this is :
 *
 *  0     2       6        10       14      18       22
 *  +----+--------+--------+--------+-------+--------+
 *  | cmd| pid    | dev    | inode  | sec   |  usec  |
 *  +----+--------+--------+--------+-------+--------+
 */

#define OPLOCK_BREAK_CMD 0x1
#define OPLOCK_BREAK_PID_OFFSET 2
#define OPLOCK_BREAK_DEV_OFFSET 6
#define OPLOCK_BREAK_INODE_OFFSET 10
#define OPLOCK_BREAK_SEC_OFFSET 14
#define OPLOCK_BREAK_USEC_OFFSET 18
#define OPLOCK_BREAK_MSG_LEN 22


#define CMD_REPLY 0x8000

/* _SMB_H */

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

#define BUFFER_SIZE (0xFFFF)
#define SAFETY_MARGIN 1024

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139

#define False (0)
#define True (1)
#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETB(ptr,bit) ((((char *)ptr)[0] & (1<<(bit)))!=0)
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)
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


typedef char pstring[1024];
typedef char fstring[128];

/* pipe strings */
#define PIPE_LANMAN   "\\PIPE\\LANMAN"
#define PIPE_SRVSVC   "\\PIPE\\srvsvc"
#define PIPE_SAMR     "\\PIPE\\samr"
#define PIPE_WKSSVC   "\\PIPE\\wkssvc"
#define PIPE_NETLOGON "\\PIPE\\NETLOGON"
#define PIPE_NTLSA    "\\PIPE\\ntlsa"
#define PIPE_NTSVCS   "\\PIPE\\ntsvcs"
#define PIPE_LSASS    "\\PIPE\\lsass"
#define PIPE_LSARPC   "\\PIPE\\lsarpc"

/* 32 bit time (sec) since 01jan1970 - cifs6.txt, section 3.5, page 30 */
typedef struct time_info
{
  uint32 time;

} UTIME;

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

struct smb_passwd
{
	int smb_userid;
	char *smb_name;
	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */
        uint16 acct_ctrl;
	/* Other fields / flags may be added later */
};

struct cli_state {
	int fd;
	int cnum;
	int pid;
	int mid;
	int uid;
	int protocol;
	int sec_mode;
	int error;
	int privilages;
	fstring eff_name;
	fstring desthost;
	char cryptkey[8];
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
  int cnum, vuid;
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
  uint16 uid_cache_count;
  uid_t uid_users_cache[10];
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
  int vuid;
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
  BOOL sent_oplock_break;
  BOOL reserved;
  char *name;
} files_struct;


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
  name_compare_entry *veto_oplock_list; /* Per-share list of files to refuse oplocks on. */

} connection_struct;

/* NTDOMAIN defines needed here. */

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

/* End of NTDOMAIN defines needed here. */

typedef struct
{
  int uid; /* uid of a validated user */
  int gid; /* gid of a validated user */

  fstring requested_name; /* user name from the client */
  fstring name; /* unix user name of a validated user */
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

#ifdef NTDOMAIN
  /* per-user authentication information on NT RPCs */
  struct dcinfo dc;
#endif /* NTDOMAIN */

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
	int (*get_entries)(int , int , uint32 , uint32 , share_mode_entry **);
	void (*del_entry)(int , int );
	BOOL (*set_entry)(int , int , uint16 , uint16 );
	BOOL (*remove_oplock)(int , int);
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

/* This is used by smbclient to send it to a smbfs mount point */
struct connection_options {
  int protocol;
  /* Connection-Options */
  uint32 max_xmit;
  uint16 server_uid;
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
#define IS_VETO_OPLOCK_PATH(cnum,path)  (is_in_path((path),Connections[(cnum)].veto_oplock_list))

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


#define SMB_SUCCESS 0  /* The request was successful. */
#define ERRDOS 0x01 /*  Error is from the core DOS operating system set. */
#define ERRSRV 0x02  /* Error is generated by the server network file manager.*/
#define ERRHRD 0x03  /* Error is an hardware error. */
#define ERRCMD 0xFF  /* Command was not in the "SMB" format. */

#ifdef __STDC__
int Debug1(char *, ...);
int slprintf(char *str, int n, char *format, ...);
#else
int Debug1();
int slprintf();
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
enum protocol_types {PROTOCOL_NONE,PROTOCOL_CORE,PROTOCOL_COREPLUS,PROTOCOL_LANMAN1,PROTOCOL_LANMAN2,PROTOCOL_NT1};

/* security levels */
enum security_types {SEC_SHARE,SEC_USER,SEC_SERVER};

/* printing types */
enum printing_types {PRINT_BSD,PRINT_SYSV,PRINT_AIX,PRINT_HPUX,
		     PRINT_QNX,PRINT_PLP,PRINT_LPRNG,PRINT_SOFTQ};

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

/***************************************************************
 OPLOCK section.
****************************************************************/

/*
 * Map the Core and Extended Oplock request bits down
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

/***************************************************************
 End of OPLOCK section.
****************************************************************/

/***************************************************************
 NT Domain section.
****************************************************************/

/* NETLOGON opcodes and data structures */

enum RPC_PKT_TYPE
{
	RPC_REQUEST = 0x00,
	RPC_RESPONSE = 0x02,
	RPC_BIND     = 0x0B,
	RPC_BINDACK  = 0x0C
};

#define NET_QUERYFORPDC	     7 /* Query for PDC */
#define NET_QUERYFORPDC_R   12 /* Response to Query for PDC */
#define NET_SAMLOGON        18
#define NET_SAMLOGON_R      19

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

  uint32 alloc_hint; /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id; /* 0 - presentation context identifier */
  uint8  cancel_count; /* 0 - cancel count */
  uint8  opnum; /* request: 0 - reserved.  response: opnum */

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

#endif /* _SMB_H */
/* _SMB_H */

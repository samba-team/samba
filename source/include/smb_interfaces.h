/* 
   Unix SMB/CIFS implementation.
   SMB request interface structures
   Copyright (C) Andrew Tridgell			2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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


/* Globally Unique ID */
#define GUID_SIZE 16

/* 64 bit time (100 nanosec) 1601 - cifs6.txt, section 3.5, page 30 */
typedef uint64_t NTTIME;

/* 8 byte aligned 'hyper' type from MS IDL */
typedef uint64_t HYPER_T;



/* this structure is just a wrapper for a string, the only reason we
   bother with this is that it allows us to check the length provided
   on the wire in testsuite test code to ensure that we are
   terminating names in the same way that win2003 is. The *ONLY* time
   you should ever look at the 'private_length' field in this
   structure is inside compliance test code, in all other cases just
   use the null terminated char* as the definitive definition of the
   string

   also note that this structure is only used in packets where there
   is an explicit length provided on the wire (hence the name). That
   length is placed in 'private_length'. For packets where the length
   is always determined by NULL or packet termination a normal char*
   is used in the structure definition.
 */
typedef struct {
	uint32 private_length;
	const char *s;
} WIRE_STRING;


/*
  this header defines the structures and unions used between the SMB
  parser and the backends.
*/

/* struct used for SMBlseek call */
struct smb_seek {
	struct {
		uint16 fnum;
		uint16 mode;
		int32  offset; /* signed */
	} in;
	struct {
		int32 offset;
	} out;
};


/* struct used in unlink() call */
struct smb_unlink {
	struct {
		const char *pattern;
		uint16 attrib;
	} in;
};


/* struct used in chkpath() call */
struct smb_chkpath {
	struct {
		const char *path;
	} in;
};

enum mkdir_level {RAW_MKDIR_GENERIC, RAW_MKDIR_MKDIR, RAW_MKDIR_T2MKDIR};

/* union used in mkdir() call */
union smb_mkdir {
	/* generic level */
	struct {
		enum mkdir_level level;
	} generic;

	struct {
		enum mkdir_level level;
		struct {
			const char *path;
		} in;
	} mkdir;

	struct {
		enum mkdir_level level;
		struct {
			const char *path;
			uint_t num_eas;
			struct ea_struct *eas;			
		} in;
	} t2mkdir;
};

/* struct used in rmdir() call */
struct smb_rmdir {
	struct {
		const char *path;
	} in;
};

/* struct used in rename() call */
enum rename_level {RAW_RENAME_RENAME, RAW_RENAME_NTRENAME};

union smb_rename {
	struct {
		enum rename_level level;
	} generic;

	/* SMBrename interface */
	struct {
		enum rename_level level;

		struct {
			const char *pattern1;
			const char *pattern2;
			uint16 attrib;
		} in;
	} rename;


	/* SMBntrename interface */
	struct {
		enum rename_level level;

		struct {
			uint16 attrib;
			uint16 flags; /* see RENAME_FLAG_* */
			uint32 cluster_size;
			const char *old_name;
			const char *new_name;
		} in;
	} ntrename;
};

enum tcon_level {RAW_TCON_TCON, RAW_TCON_TCONX};

/* union used in tree connect call */
union smb_tcon {
	/* generic interface */
	struct {
		enum tcon_level level;
	} generic;

	/* SMBtcon interface */
	struct {
		enum tcon_level level;

		struct {
			const char *service;
			const char *password;
			const char *dev;
		} in;
		struct {
			uint16 max_xmit;
			uint16 cnum;
		} out;
	} tcon;

	/* SMBtconX interface */
	struct {
		enum tcon_level level;

		struct {
			uint16 flags;
			DATA_BLOB password;
			const char *path;
			const char *device;
		} in;
		struct {
			uint16 options;
			char *dev_type;
			char *fs_type;
			uint16 cnum;
		} out;
	} tconx;
};


enum sesssetup_level {RAW_SESSSETUP_GENERIC, RAW_SESSSETUP_OLD, RAW_SESSSETUP_NT1, RAW_SESSSETUP_SPNEGO};

/* union used in session_setup call */
union smb_sesssetup {
	
	/* generic interface - used for auto selecting based on negotiated
	   protocol options */
	struct {
		enum sesssetup_level level;

		struct {
			uint32 sesskey;
			uint32 capabilities;
			const char *password;
			const char *user;
			const char *domain;
		} in;
		struct {
			uint16 vuid;
			char *os;
			char *lanman;
			char *domain;
		} out;		
	} generic;

	/* the pre-NT1 interface */
	struct {
		enum sesssetup_level level;

		struct {
			uint16 bufsize;
			uint16 mpx_max;
			uint16 vc_num;
			uint32 sesskey;
			DATA_BLOB password;
			const char *user;
			const char *domain;
			const char *os;
			const char *lanman;
		} in;
		struct {
			uint16 action;
			uint16 vuid;
			char *os;
			char *lanman;
			char *domain;
		} out;
	} old;

	/* the NT1 interface */
	struct {
		enum sesssetup_level level;

		struct {
			uint16 bufsize;
			uint16 mpx_max;
			uint16 vc_num;
			uint32 sesskey;
			uint32 capabilities;
			DATA_BLOB password1;
			DATA_BLOB password2;
			const char *user;
			const char *domain;
			const char *os;
			const char *lanman;
		} in;
		struct {
			uint16 action;
			uint16 vuid;
			char *os;
			char *lanman;
			char *domain;
		} out;
	} nt1;


	/* the SPNEGO interface */
	struct {
		enum sesssetup_level level;

		struct {
			uint16 bufsize;
			uint16 mpx_max;
			uint16 vc_num;
			uint32 sesskey;
			uint32 capabilities;
			DATA_BLOB secblob;
			const char *os;
			const char *lanman;
			const char *domain;
		} in;
		struct {
			uint16 action;
			DATA_BLOB secblob;
			char *os;
			char *lanman;
			char *domain;
			uint16 vuid;
		} out;
	} spnego;
};

/* Note that the specified enum values are identical to the actual info-levels used
 * on the wire.
 */
enum fileinfo_level {RAW_FILEINFO_GENERIC                    = 0xF000, 
		     RAW_FILEINFO_GETATTR,                   /* SMBgetatr */
		     RAW_FILEINFO_GETATTRE,                  /* SMBgetattrE */
		     RAW_FILEINFO_STANDARD                   = SMB_QFILEINFO_STANDARD,
		     RAW_FILEINFO_EA_SIZE                    = SMB_QFILEINFO_EA_SIZE,
		     RAW_FILEINFO_ALL_EAS                    = SMB_QFILEINFO_ALL_EAS,
		     RAW_FILEINFO_IS_NAME_VALID              = SMB_QFILEINFO_IS_NAME_VALID,
		     RAW_FILEINFO_BASIC_INFO                 = SMB_QFILEINFO_BASIC_INFO, 
		     RAW_FILEINFO_STANDARD_INFO              = SMB_QFILEINFO_STANDARD_INFO,
		     RAW_FILEINFO_EA_INFO                    = SMB_QFILEINFO_EA_INFO,
		     RAW_FILEINFO_NAME_INFO                  = SMB_QFILEINFO_NAME_INFO, 
		     RAW_FILEINFO_ALL_INFO                   = SMB_QFILEINFO_ALL_INFO,
		     RAW_FILEINFO_ALT_NAME_INFO              = SMB_QFILEINFO_ALT_NAME_INFO,
		     RAW_FILEINFO_STREAM_INFO                = SMB_QFILEINFO_STREAM_INFO,
		     RAW_FILEINFO_COMPRESSION_INFO           = SMB_QFILEINFO_COMPRESSION_INFO,
		     RAW_FILEINFO_UNIX_BASIC                 = SMB_QFILEINFO_UNIX_BASIC,
		     RAW_FILEINFO_UNIX_LINK                  = SMB_QFILEINFO_UNIX_LINK,
		     RAW_FILEINFO_BASIC_INFORMATION          = SMB_QFILEINFO_BASIC_INFORMATION,
		     RAW_FILEINFO_STANDARD_INFORMATION       = SMB_QFILEINFO_STANDARD_INFORMATION,
		     RAW_FILEINFO_INTERNAL_INFORMATION       = SMB_QFILEINFO_INTERNAL_INFORMATION,
		     RAW_FILEINFO_EA_INFORMATION             = SMB_QFILEINFO_EA_INFORMATION,
		     RAW_FILEINFO_ACCESS_INFORMATION         = SMB_QFILEINFO_ACCESS_INFORMATION,
		     RAW_FILEINFO_NAME_INFORMATION           = SMB_QFILEINFO_NAME_INFORMATION,
		     RAW_FILEINFO_POSITION_INFORMATION       = SMB_QFILEINFO_POSITION_INFORMATION,
		     RAW_FILEINFO_MODE_INFORMATION           = SMB_QFILEINFO_MODE_INFORMATION,
		     RAW_FILEINFO_ALIGNMENT_INFORMATION      = SMB_QFILEINFO_ALIGNMENT_INFORMATION,
		     RAW_FILEINFO_ALL_INFORMATION            = SMB_QFILEINFO_ALL_INFORMATION,
		     RAW_FILEINFO_ALT_NAME_INFORMATION       = SMB_QFILEINFO_ALT_NAME_INFORMATION,
		     RAW_FILEINFO_STREAM_INFORMATION         = SMB_QFILEINFO_STREAM_INFORMATION,
		     RAW_FILEINFO_COMPRESSION_INFORMATION    = SMB_QFILEINFO_COMPRESSION_INFORMATION,
		     RAW_FILEINFO_NETWORK_OPEN_INFORMATION   = SMB_QFILEINFO_NETWORK_OPEN_INFORMATION,
		     RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION  = SMB_QFILEINFO_ATTRIBUTE_TAG_INFORMATION
};


/* union used in qfileinfo() and qpathinfo() backend calls */
union smb_fileinfo {
	/* generic interface:
	 * matches RAW_FILEINFO_GENERIC */
	struct {
		enum fileinfo_level level;

		/* each level can be called on either a pathname or a
		 * filename, in either case the return format is
		 * identical */
		union smb_fileinfo_in {
			const char *fname;
			uint16 fnum;
		} in;
		
		struct {
			uint16 attrib;
			uint32 ea_size;
			uint_t num_eas;
			struct ea_struct {
				uint8 flags;
				WIRE_STRING name;
				DATA_BLOB value;
			} *eas;		
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint32 ex_attrib;	
			uint64_t alloc_size;
			uint64_t size;
			uint32 nlink;
			WIRE_STRING fname;	
			WIRE_STRING alt_fname;	
			uint8 delete_pending;
			uint8 directory;
			uint64_t compressed_size;
			uint16 format;
			uint8 unit_shift;
			uint8 chunk_shift;
			uint8 cluster_shift;
			uint64_t file_id;
			uint32 access_flags; /* seen 0x001f01ff from w2k3 */
			uint64_t position;
			uint32 mode;
			uint32 alignment_requirement;
			uint32 reparse_tag;
			uint_t num_streams;
			struct stream_struct {
				uint64_t size;
				uint64_t alloc_size;
				WIRE_STRING stream_name;
			} *streams;
		} out;
	} generic;


	/* SMBgetatr interface:
	 * matches RAW_FILEINFO_GETATTR */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint16 attrib;
			uint32 size;
			time_t write_time;
		} out;
	} getattr;

	/* SMBgetattrE interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			time_t create_time;
			time_t access_time;
			time_t write_time;
			uint32 size;
			uint32 alloc_size;
			uint16 attrib;
		} out;
	} getattre;

	/* trans2 RAW_FILEINFO_STANDARD interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			time_t create_time;
			time_t access_time;
			time_t write_time;
			uint32 size;
			uint32 alloc_size;
			uint16 attrib;
		} out;
	} standard;

	/* trans2 RAW_FILEINFO_EA_SIZE interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			time_t create_time;
			time_t access_time;
			time_t write_time;
			uint32 size;
			uint32 alloc_size;
			uint16 attrib;
			uint32 ea_size;
		} out;
	} ea_size;

	/* trans2 RAW_FILEINFO_ALL_EAS interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			/* the ea_size is implied by the list */
			uint_t num_eas;
			struct ea_struct *eas;
		} out;
	} all_eas;

	/* trans2 qpathinfo RAW_FILEINFO_IS_NAME_VALID interface 
	   only valid for a QPATHNAME call - no returned data */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;
	} is_name_valid;

	/* RAW_FILEINFO_BASIC_INFO and RAW_FILEINFO_BASIC_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint32 attrib;
		} out;
	} basic_info;
		

	/* RAW_FILEINFO_STANDARD_INFO and RAW_FILEINFO_STANDARD_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint64_t alloc_size;
			uint64_t size;
			uint32 nlink;
			BOOL delete_pending;
			BOOL directory;
		} out;
	} standard_info;
	
	/* RAW_FILEINFO_EA_INFO and RAW_FILEINFO_EA_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint32 ea_size;
		} out;
	} ea_info;

	/* RAW_FILEINFO_NAME_INFO and RAW_FILEINFO_NAME_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			WIRE_STRING fname;
		} out;
	} name_info;

	/* RAW_FILEINFO_ALL_INFO and RAW_FILEINFO_ALL_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint32 attrib;
			uint64_t alloc_size;
			uint64_t size;
			uint32 nlink;
			uint8 delete_pending;
			uint8 directory;
			uint32 ea_size;
			WIRE_STRING fname;
		} out;
	} all_info;	

	/* RAW_FILEINFO_ALT_NAME_INFO and RAW_FILEINFO_ALT_NAME_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			WIRE_STRING fname;
		} out;
	} alt_name_info;

	/* RAW_FILEINFO_STREAM_INFO and RAW_FILEINFO_STREAM_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint_t num_streams;
			struct stream_struct *streams;
		} out;
	} stream_info;
	
	/* RAW_FILEINFO_COMPRESSION_INFO and RAW_FILEINFO_COMPRESSION_INFORMATION interfaces */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint64_t compressed_size;
			uint16 format;
			uint8 unit_shift;
			uint8 chunk_shift;
			uint8 cluster_shift;
		} out;
	} compression_info;

	/* RAW_FILEINFO_UNIX_BASIC interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint64_t end_of_file;
			uint64_t num_bytes;
			NTTIME status_change_time;
			NTTIME access_time;
			NTTIME change_time;
			uint64_t uid;
			uint64_t gid;
			uint32 file_type;
			uint64_t dev_major;
			uint64_t dev_minor;
			uint64_t unique_id;
			uint64_t permissions;
			uint64_t nlink;
		} out;
	} unix_basic_info;

	/* RAW_FILEINFO_UNIX_LINK interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			WIRE_STRING link_dest;
		} out;
	} unix_link_info;

	/* RAW_FILEINFO_INTERNAL_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint64_t file_id;
		} out;
	} internal_information;

	/* RAW_FILEINFO_ACCESS_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint32 access_flags; /* seen 0x001f01ff from w2k3 */
		} out;
	} access_information;

	/* RAW_FILEINFO_POSITION_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint64_t position;
		} out;
	} position_information;

	/* RAW_FILEINFO_MODE_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint32 mode;
		} out;
	} mode_information;

	/* RAW_FILEINFO_ALIGNMENT_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint32 alignment_requirement;
		} out;
	} alignment_information;

	/* RAW_FILEINFO_NETWORK_OPEN_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint64_t alloc_size;
			uint64_t size;
			uint32 attrib;
		} out;
	} network_open_information;


	/* RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION interface */
	struct {
		enum fileinfo_level level;
		union smb_fileinfo_in in;

		struct {
			uint32 attrib;
			uint32 reparse_tag;
		} out;
	} attribute_tag_information;
};


enum setfileinfo_level {
	RAW_SFILEINFO_GENERIC		      = 0xF000, 
	RAW_SFILEINFO_SETATTR,		      /* SMBsetatr */
	RAW_SFILEINFO_SETATTRE,		      /* SMBsetattrE */
	RAW_SFILEINFO_STANDARD                = SMB_SFILEINFO_STANDARD,
	RAW_SFILEINFO_EA_SET                  = SMB_SFILEINFO_EA_SET,
	RAW_SFILEINFO_BASIC_INFO              = SMB_SFILEINFO_BASIC_INFO,
	RAW_SFILEINFO_DISPOSITION_INFO        = SMB_SFILEINFO_DISPOSITION_INFO,
	RAW_SFILEINFO_ALLOCATION_INFO         = SMB_SFILEINFO_ALLOCATION_INFO,
	RAW_SFILEINFO_END_OF_FILE_INFO        = SMB_SFILEINFO_END_OF_FILE_INFO,
	RAW_SFILEINFO_UNIX_BASIC              = SMB_SFILEINFO_UNIX_BASIC,
	RAW_SFILEINFO_UNIX_LINK               = SMB_SFILEINFO_UNIX_LINK,
	RAW_SFILEINFO_UNIX_HLINK	      = SMB_SFILEINFO_UNIX_HLINK,
	RAW_SFILEINFO_BASIC_INFORMATION       = SMB_SFILEINFO_BASIC_INFORMATION,
	RAW_SFILEINFO_RENAME_INFORMATION      = SMB_SFILEINFO_RENAME_INFORMATION,
	RAW_SFILEINFO_DISPOSITION_INFORMATION = SMB_SFILEINFO_DISPOSITION_INFORMATION,
	RAW_SFILEINFO_POSITION_INFORMATION    = SMB_SFILEINFO_POSITION_INFORMATION,
	RAW_SFILEINFO_MODE_INFORMATION        = SMB_SFILEINFO_MODE_INFORMATION,
	RAW_SFILEINFO_ALLOCATION_INFORMATION  = SMB_SFILEINFO_ALLOCATION_INFORMATION,
	RAW_SFILEINFO_END_OF_FILE_INFORMATION = SMB_SFILEINFO_END_OF_FILE_INFORMATION,
	RAW_SFILEINFO_1023                    = SMB_SFILEINFO_1023,
	RAW_SFILEINFO_1025                    = SMB_SFILEINFO_1025,
	RAW_SFILEINFO_1029                    = SMB_SFILEINFO_1029,
	RAW_SFILEINFO_1032                    = SMB_SFILEINFO_1032,
	RAW_SFILEINFO_1039                    = SMB_SFILEINFO_1039,
	RAW_SFILEINFO_1040                    = SMB_SFILEINFO_1040
};

/* union used in setfileinfo() and setpathinfo() calls */
union smb_setfileinfo {
	/* generic interface */
	struct {
		enum setfileinfo_level level;

		/* we are combining setfileinfo and setpathinfo into one 
		   interface */
		union setfileinfo_file {
			const char *fname;
			uint16 fnum;
		} file;
	} generic;

	/* RAW_SFILEINFO_SETATTR (SMBsetatr) interface - only via setpathinfo() */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;
		struct {
			uint16 attrib;
			time_t write_time;
		} in;
	} setattr;

	/* RAW_SFILEINFO_SETATTRE (SMBsetattrE) interface - only via setfileinfo() */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			time_t create_time;
			time_t access_time;
			time_t write_time;
		} in;
	} setattre;

	
	/* RAW_SFILEINFO_STANDARD interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;
		struct {
			time_t create_time;
			time_t access_time;
			time_t write_time;
			/* notice that size, alloc_size and attrib are not settable,
			   unlike the corresponding qfileinfo level */
		} in;
	} standard;

	/* RAW_SFILEINFO_EA_SET interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;
		struct {
			struct ea_struct ea;
		} in;
	} ea_set;

	/* RAW_SFILEINFO_BASIC_INFO and
	   RAW_SFILEINFO_BASIC_INFORMATION interfaces */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint32 attrib;
		} in;
	} basic_info;

	/* RAW_SFILEINFO_DISPOSITION_INFO and 
	   RAW_SFILEINFO_DISPOSITION_INFORMATION interfaces */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			BOOL delete_on_close;
		} in;
	} disposition_info;

	/* RAW_SFILEINFO_ALLOCATION_INFO and 
	   RAW_SFILEINFO_ALLOCATION_INFORMATION interfaces */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			/* w2k3 rounds this up to nearest 4096 */
			uint64_t alloc_size;
		} in;
	} allocation_info;
	
	/* RAW_SFILEINFO_END_OF_FILE_INFO and 
	   RAW_SFILEINFO_END_OF_FILE_INFORMATION interfaces */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			uint64_t size;
		} in;
	} end_of_file_info;

	/* RAW_SFILEINFO_RENAME_INFORMATION interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			uint8 overwrite;
			uint32 root_fid;
			const char *new_name;
		} in;
	} rename_information;

	/* RAW_SFILEINFO_POSITION_INFORMATION interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			uint64_t position;
		} in;
	} position_information;

	/* RAW_SFILEINFO_MODE_INFORMATION interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;

		struct {
			/* valid values seem to be 0, 2, 4 and 6 */
			uint32 mode;
		} in;
	} mode_information;



	/* RAW_SFILEINFO_UNIX_BASIC interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;
		struct {
			uint32 mode; /* yuck - this field remains to fix compile of libcli/clifile.c */
			uint64_t end_of_file;
			uint64_t num_bytes;
			NTTIME status_change_time;
			NTTIME access_time;
			NTTIME change_time;
			uint64_t uid;
			uint64_t gid;
			uint32 file_type;
			uint64_t dev_major;
			uint64_t dev_minor;
			uint64_t unique_id;
			uint64_t permissions;
			uint64_t nlink;
		} in;
	} unix_basic;
	
	/* RAW_SFILEINFO_UNIX_LINK, RAW_SFILEINFO_UNIX_HLINK interface */
	struct {
		enum setfileinfo_level level;
		union setfileinfo_file file;
		struct {
			const char *link_dest;
		} in;
	} unix_link, unix_hlink;
};


enum fsinfo_level {RAW_QFS_GENERIC                        = 0xF000, 
		   RAW_QFS_DSKATTR,                         /* SMBdskattr */
		   RAW_QFS_ALLOCATION                     = SMB_QFS_ALLOCATION,
		   RAW_QFS_VOLUME                         = SMB_QFS_VOLUME,
		   RAW_QFS_VOLUME_INFO                    = SMB_QFS_VOLUME_INFO,
		   RAW_QFS_SIZE_INFO                      = SMB_QFS_SIZE_INFO,
		   RAW_QFS_DEVICE_INFO                    = SMB_QFS_DEVICE_INFO,
		   RAW_QFS_ATTRIBUTE_INFO                 = SMB_QFS_ATTRIBUTE_INFO,
		   RAW_QFS_UNIX_INFO                      = SMB_QFS_UNIX_INFO,
		   RAW_QFS_VOLUME_INFORMATION		  = SMB_QFS_VOLUME_INFORMATION,
		   RAW_QFS_SIZE_INFORMATION               = SMB_QFS_SIZE_INFORMATION,
		   RAW_QFS_DEVICE_INFORMATION             = SMB_QFS_DEVICE_INFORMATION,
		   RAW_QFS_ATTRIBUTE_INFORMATION          = SMB_QFS_ATTRIBUTE_INFORMATION,
		   RAW_QFS_QUOTA_INFORMATION              = SMB_QFS_QUOTA_INFORMATION,
		   RAW_QFS_FULL_SIZE_INFORMATION          = SMB_QFS_FULL_SIZE_INFORMATION,
		   RAW_QFS_OBJECTID_INFORMATION           = SMB_QFS_OBJECTID_INFORMATION};


/* union for fsinfo() backend call. Note that there are no in
   structures, as this call only contains out parameters */
union smb_fsinfo {
	/* generic interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint32 block_size;
			uint64_t blocks_total;
			uint64_t blocks_free;
			uint32 fs_id;
			NTTIME create_time;
			uint32 serial_number;
			uint32 fs_attr;
			uint32 max_file_component_length;
			uint32 device_type;
			uint32 device_characteristics;
			uint64_t quota_soft;
			uint64_t quota_hard;
			uint64_t quota_flags;
			struct GUID guid;
			char *volume_name;
			char *fs_type;
		} out;
	} generic;

	/* SMBdskattr interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint16 units_total;
			uint16 blocks_per_unit;
			uint16 block_size;
			uint16 units_free;
		} out;
	} dskattr;

	/* trans2 RAW_QFS_ALLOCATION interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint32 fs_id;
			uint32 sectors_per_unit;
			uint32 total_alloc_units;
			uint32 avail_alloc_units;
			uint16 bytes_per_sector;
		} out;
	} allocation;

	/* TRANS2 RAW_QFS_VOLUME interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint32 serial_number;
			WIRE_STRING volume_name;
		} out;
	} volume;

	/* TRANS2 RAW_QFS_VOLUME_INFO and RAW_QFS_VOLUME_INFORMATION interfaces */
	struct {
		enum fsinfo_level level;

		struct {
			NTTIME create_time;
			uint32 serial_number;
			WIRE_STRING volume_name;
		} out;
	} volume_info;

	/* trans2 RAW_QFS_SIZE_INFO and RAW_QFS_SIZE_INFORMATION interfaces */
	struct {
		enum fsinfo_level level;

		struct {
			uint64_t total_alloc_units;
			uint64_t avail_alloc_units; /* maps to call_avail_alloc_units */
			uint32 sectors_per_unit;
			uint32 bytes_per_sector;
		} out;
	} size_info;

	/* TRANS2 RAW_QFS_DEVICE_INFO and RAW_QFS_DEVICE_INFORMATION interfaces */
	struct {
		enum fsinfo_level level;

		struct {
			uint32 device_type;
			uint32 characteristics;
		} out;
	} device_info;


	/* TRANS2 RAW_QFS_ATTRIBUTE_INFO and RAW_QFS_ATTRIBUTE_INFORMATION interfaces */
	struct {
		enum fsinfo_level level;

		struct {
			uint32 fs_attr;
			uint32 max_file_component_length;
			WIRE_STRING fs_type;
		} out;
	} attribute_info;


	/* TRANS2 RAW_QFS_UNIX_INFO interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint16 major_version;
			uint16 minor_version;
			uint64_t capability;
		} out;
	} unix_info;

	/* trans2 RAW_QFS_QUOTA_INFORMATION interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint64_t unknown[3];
			uint64_t quota_soft;
			uint64_t quota_hard;
			uint64_t quota_flags;
		} out;
	} quota_information;	

	/* trans2 RAW_QFS_FULL_SIZE_INFORMATION interface */
	struct {
		enum fsinfo_level level;

		struct {
			uint64_t total_alloc_units;
			uint64_t call_avail_alloc_units;
			uint64_t actual_avail_alloc_units;
			uint32 sectors_per_unit;
			uint32 bytes_per_sector;
		} out;
	} full_size_information;

	/* trans2 RAW_QFS_OBJECTID_INFORMATION interface */
	struct {
		enum fsinfo_level level;

		struct {
			struct GUID  guid;
			uint64_t unknown[6];
		} out;
	} objectid_information;	
};



enum open_level {RAW_OPEN_OPEN, RAW_OPEN_OPENX, 
		 RAW_OPEN_MKNEW, RAW_OPEN_CREATE, 
		 RAW_OPEN_CTEMP, RAW_OPEN_SPLOPEN,
		 RAW_OPEN_NTCREATEX, RAW_OPEN_T2OPEN};

/* the generic interface is defined to be equal to the NTCREATEX interface */
#define RAW_OPEN_GENERIC RAW_OPEN_NTCREATEX

/* union for open() backend call */
union smb_open {
	/* SMBNTCreateX interface */
	struct {
		enum open_level level;

		struct {
			uint32 flags;
			uint32 root_fid;
			uint32 access_mask;
			uint64_t alloc_size;
			uint32 file_attr;
			uint32 share_access;
			uint32 open_disposition;
			uint32 create_options;
			uint32 impersonation;
			uint8  security_flags;
			const char *fname;
		} in;

		struct {
			uint8 oplock_level;
			uint16 fnum;
			uint32 create_action;
			NTTIME create_time;
			NTTIME access_time;
			NTTIME write_time;
			NTTIME change_time;
			uint32 attrib;
			uint64_t alloc_size;
			uint64_t size;
			uint16 file_type;
			uint16 ipc_state;
			uint8  is_directory;
		} out;
	} ntcreatex, generic;

	/* TRANS2_OPEN interface */
	struct {
		enum open_level level;

		struct {
			uint16 flags;
			uint16 open_mode;
			uint16 file_attrs;
			time_t write_time;
			uint16 open_func;
			uint32 size;
			uint32 timeout;
			const char *fname;
			uint_t num_eas;
			struct ea_struct *eas;			
		} in;

		struct {
			uint16 fnum;
			uint16 attrib;
			time_t write_time;
			uint32 size;
			uint16 access;
			uint16 ftype;
			uint16 devstate;
			uint16 action;
			uint32 unknown;
		} out;
	} t2open;

	/* SMBopen interface */
	struct {
		enum open_level level;

		struct {
			uint16 flags;
			uint16 search_attrs;
			const char *fname;
		} in;
		struct {
			uint16 fnum;
			uint16 attrib;
			time_t write_time;
			uint32 size;
			uint16 rmode;
		} out;
	} open;

	/* SMBopenX interface */
	struct {
		enum open_level level;

		struct {
			uint16 flags;
			uint16 open_mode;
			uint16 search_attrs; /* not honoured by win2003 */
			uint16 file_attrs;
			time_t write_time; /* not honoured by win2003 */
			uint16 open_func;
			uint32 size; /* note that this sets the
					initial file size, not
					just allocation size */
			uint32 timeout; /* not honoured by win2003 */
			const char *fname;
		} in;
		struct {
			uint16 fnum;
			uint16 attrib;
			time_t write_time;
			uint32 size;
			uint16 access;
			uint16 ftype;
			uint16 devstate;
			uint16 action;
			uint32 unique_fid;
			uint32 access_mask;
			uint32 unknown;
		} out;
	} openx;

	/* SMBmknew interface */
	struct {
		enum open_level level;

		struct {
			uint16 attrib;
			time_t write_time;
			const char *fname;
		} in;
		struct {
			uint16 fnum;
		} out;
	} mknew, create;

	/* SMBctemp interface */
	struct {
		enum open_level level;

		struct {
			uint16 attrib;
			time_t write_time;
			const char *directory;
		} in;
		struct {
			uint16 fnum;
			/* temp name, relative to directory */
			char *name; 
		} out;
	} ctemp;

	/* SMBsplopen interface */
	struct {
		enum open_level level;

		struct {
			uint16 setup_length;
			uint16 mode;
			const char *ident;
		} in;
		struct {
			uint16 fnum;
		} out;
	} splopen;
};



enum read_level {RAW_READ_GENERIC, RAW_READ_READBRAW, RAW_READ_LOCKREAD, RAW_READ_READ, RAW_READ_READX};

/* union for read() backend call 

   note that .infoX.out.data will be allocated before the backend is
   called. It will be big enough to hold the maximum size asked for
*/
union smb_read {
	/* generic interface */
	struct {
		enum read_level level;

		struct {
			uint16 fnum;
			uint64_t offset;
			uint32    size;
		} in;
		struct {
			char *data;
			uint32 nread;
		} out;
	} generic;


	/* SMBreadbraw interface */
	struct {
		enum read_level level;

		struct {
			uint16 fnum;
			uint64_t offset;
			uint16  maxcnt;
			uint16  mincnt;
			uint32  timeout;
		} in;
		struct {
			char *data;
			uint32 nread;
		} out;
	} readbraw;


	/* SMBlockandread interface */
	struct {
		enum read_level level;

		struct {
			uint16 fnum;
			uint16 count;
			uint32 offset;
			uint16 remaining;
		} in;
		struct {
			char *data;
			uint16 nread;
		} out;
	} lockread;

	/* SMBread interface */
	struct {
		enum read_level level;

		struct {
			uint16 fnum;
			uint16 count;
			uint32 offset;
			uint16 remaining;
		} in;
		struct {
			char *data;
			uint16 nread;
		} out;
	} read;

	/* SMBreadX interface */
	struct {
		enum read_level level;

		struct {
			uint16 fnum;
			uint64_t offset;
			uint16 mincnt;
			uint16 maxcnt;
			uint16 remaining;
		} in;
		struct {
			char *data;
			uint16 remaining;
			uint16 compaction_mode;
			uint16 nread;
		} out;
	} readx;
};


enum write_level {RAW_WRITE_GENERIC, RAW_WRITE_WRITEUNLOCK, RAW_WRITE_WRITE, 
		  RAW_WRITE_WRITEX, RAW_WRITE_WRITECLOSE, RAW_WRITE_SPLWRITE};

/* union for write() backend call 
*/
union smb_write {
	/* generic interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint64_t offset;
			uint32    count;
			const char *data;
		} in;
		struct {
			uint32 nwritten;
		} out;
	} generic;


	/* SMBwriteunlock interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint16 count;
			uint32 offset;
			uint16 remaining;
			const char *data;
		} in;
		struct {
			uint32 nwritten;
		} out;
	} writeunlock;

	/* SMBwrite interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint16 count;
			uint32 offset;
			uint16 remaining;
			const char *data;
		} in;
		struct {
			uint16 nwritten;
		} out;
	} write;

	/* SMBwriteX interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint64_t offset;
			uint16 wmode;
			uint16 remaining;
			uint32 count;
			const char *data;
		} in;
		struct {
			uint32 nwritten;
			uint16 remaining;
		} out;
	} writex;

	/* SMBwriteclose interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint16 count;
			uint32 offset;
			time_t mtime;
			const char *data;
		} in;
		struct {
			uint16 nwritten;
		} out;
	} writeclose;

	/* SMBsplwrite interface */
	struct {
		enum write_level level;

		struct {
			uint16 fnum;
			uint16 count;
			const char *data;
		} in;
	} splwrite;
};


enum lock_level {RAW_LOCK_GENERIC, RAW_LOCK_LOCK, RAW_LOCK_UNLOCK, RAW_LOCK_LOCKX};

/* union for lock() backend call 
*/
union smb_lock {
	/* generic interface */
	struct {
		enum lock_level level;

	} generic;

	/* SMBlock interface */
	struct {
		enum lock_level level;

		struct {
			uint16 fnum;
			uint32 count;
			uint32 offset;
		} in;
	} lock;

	/* SMBunlock interface */
	struct {
		enum lock_level level;

		struct {
			uint16 fnum;
			uint32 count;
			uint32 offset;
		} in;
	} unlock;

	/* SMBlockingX interface */
	struct {
		enum lock_level level;

		struct {
			uint16 fnum;
			uint16 mode;
			uint32 timeout;
			uint16 ulock_cnt;
			uint16 lock_cnt;
			struct smb_lock_entry {
				uint16 pid;
				uint64_t offset;
				uint64_t count;
			} *locks; /* unlocks are first in the arrray */
		} in;
	} lockx;
};


enum close_enum {RAW_CLOSE_GENERIC, RAW_CLOSE_CLOSE, RAW_CLOSE_SPLCLOSE};

/*
  union for close() backend call
*/
union smb_close {
	/* generic interface */
	struct {
		enum close_enum level;

		struct {
			uint16 fnum;
		} in;
	} generic;

	/* SMBclose interface */
	struct {
		enum close_enum level;

		struct {
			uint16 fnum;
			time_t write_time;
		} in;
	} close;

	/* SMBsplclose interface - empty! */
	struct {
		enum close_enum level;

		struct {
			uint16 fnum;
		} in;
	} splclose;
};


enum lpq_level {RAW_LPQ_GENERIC, RAW_LPQ_RETQ};

/*
  union for lpq() backend
*/
union smb_lpq {
	/* generic interface */
	struct {
		enum lpq_level level;

	} generic;


	/* SMBsplretq interface */
	struct {
		enum lpq_level level;

		struct {
			uint16 maxcount;
			uint16 startidx;
		} in;
		struct {
			uint16 count;
			uint16 restart_idx;
			struct {
				time_t time;
				uint8 status;
				uint16 job;
				uint32 size;
				char *user;
			} *queue;
		} out;
	} retq;
};

enum ioctl_level {RAW_IOCTL_IOCTL, RAW_IOCTL_NTIOCTL};

/*
  union for ioctl() backend
*/
union smb_ioctl {
	/* generic interface */
	struct {
		enum ioctl_level level;

	} generic;

	/* struct for SMBioctl */
	struct {
		enum ioctl_level level;
		struct {
			uint16 fnum;
			uint32 request;
		} in;
		struct {
			DATA_BLOB blob;
		} out;
	} ioctl;


	/* struct for NT ioctl call */
	struct {
		enum ioctl_level level;
		struct {
			uint32 function;
			uint16 fnum;
			BOOL fsctl;
			uint8 filter;
		} in;
		struct {
			DATA_BLOB blob;
		} out;
	} ntioctl;
};

/* struct for SMBflush */
struct smb_flush {
	struct {
		uint16 fnum;
	} in;
};


/* struct for SMBcopy */
struct smb_copy {
	struct {
		uint16 tid2;
		uint16 ofun;
		uint16 flags;
		const char *path1;
		const char *path2;
	} in;
	struct {
		uint16 count;
	} out;
};


/* struct for transact/transact2 call */
struct smb_trans2 {
	struct {
		uint16 max_param;
		uint16 max_data;
		uint8  max_setup;
		uint16 flags;
		uint32 timeout;
		uint8  setup_count;
		uint16 *setup;
		const char *trans_name; /* SMBtrans only */
		DATA_BLOB params;
		DATA_BLOB data;
	} in;

	struct {
		uint8  setup_count;
		uint16 *setup;
		DATA_BLOB params;
		DATA_BLOB data;
	} out;
};

/* struct for nttransact2 call */
struct smb_nttrans {
	struct {
		uint8  max_setup;
		uint32 max_param;
		uint32 max_data;
		uint32 setup_count;
		uint16 function;
		uint16 *setup;
		DATA_BLOB params;
		DATA_BLOB data;
	} in;

	struct {
		uint8  setup_count;
		uint16 *setup;
		DATA_BLOB params;
		DATA_BLOB data;
	} out;
};


/* struct for nttrans change notify call */
struct smb_notify {
	struct {
		uint32 buffer_size;
		uint32 completion_filter;
		uint16 fnum;
		BOOL recursive;
	} in;

	struct {
		uint32 num_changes;
		struct {
			uint32 action;
			WIRE_STRING name;
		} *changes;
	} out;
};


enum search_level {RAW_SEARCH_GENERIC                 = 0xF000, 
		   RAW_SEARCH_SEARCH,                 /* SMBsearch */ 
		   RAW_SEARCH_FCLOSE,				  /* SMBfclose */
		   RAW_SEARCH_STANDARD                = SMB_FIND_STANDARD,
		   RAW_SEARCH_EA_SIZE                 = SMB_FIND_EA_SIZE,
		   RAW_SEARCH_DIRECTORY_INFO          = SMB_FIND_DIRECTORY_INFO,
		   RAW_SEARCH_FULL_DIRECTORY_INFO     = SMB_FIND_FULL_DIRECTORY_INFO,
		   RAW_SEARCH_NAME_INFO               = SMB_FIND_NAME_INFO,
		   RAW_SEARCH_BOTH_DIRECTORY_INFO     = SMB_FIND_BOTH_DIRECTORY_INFO,
		   RAW_SEARCH_ID_FULL_DIRECTORY_INFO  = SMB_FIND_ID_FULL_DIRECTORY_INFO,
		   RAW_SEARCH_ID_BOTH_DIRECTORY_INFO  = SMB_FIND_ID_BOTH_DIRECTORY_INFO,
		   RAW_SEARCH_UNIX_INFO               = SMB_FIND_UNIX_INFO};

	
/* union for file search */
union smb_search_first {
	struct {
		enum search_level level;
	} generic;
	
	/* search (old) findfirst interface */
	struct {
		enum search_level level;
	
		struct {
			uint16 max_count;
			uint16 search_attrib;
			const char *pattern;
		} in;
		struct {
			int16 count;
		} out;
	} search_first;

	/* trans2 findfirst interface */
	struct {
		enum search_level level;
		
		struct {
			uint16 search_attrib;
			uint16 max_count;
			uint16 flags;
			uint32 storage_type;
			const char *pattern;
		} in;
		struct {
			uint16 handle;
			uint16 count;
			uint16 end_of_search;
		} out;
	} t2ffirst;
};

/* union for file search continue */
union smb_search_next {
	struct {
		enum search_level level;
	} generic;

	/* search (old) findnext interface */
	struct {
		enum search_level level;
	
		struct {
			uint16 max_count;
			uint16 search_attrib;
			DATA_BLOB search_id;
		} in;
		struct {
			uint16 count;
		} out;
	} search_next;
	
	/* trans2 findnext interface */
	struct {
		enum search_level level;
		
		struct {
			uint16 handle;
			uint16 max_count;
			uint32 resume_key;
			uint16 flags;
			const char *last_name;
		} in;
		struct {
			uint16 count;
			uint16 end_of_search;
		} out;
	} t2fnext;
};

/* union for search reply file data */
union smb_search_data {
	/* search (old) findfirst */
	struct {
		uint16 attrib;
		time_t write_time;
		uint32 size;
		DATA_BLOB search_id;  /* used to resume search from this point */
		char *name;
	} search;
	
	/* trans2 findfirst RAW_SEARCH_STANDARD level */
	struct {
		uint32 resume_key;
		time_t create_time;
		time_t access_time;
		time_t write_time;
		uint32 size;
		uint32 alloc_size;
		uint16 attrib;
		WIRE_STRING name;
	} standard;

	/* trans2 findfirst RAW_SEARCH_EA_SIZE level */
	struct {
		uint32 resume_key;
		time_t create_time;
		time_t access_time;
		time_t write_time;
		uint32 size;
		uint32 alloc_size;
		uint16 attrib;
		uint32 ea_size;
		WIRE_STRING name;
	} ea_size;

	/* RAW_SEARCH_DIRECTORY_INFO interface */
	struct {
		uint32 file_index;
		NTTIME create_time;
		NTTIME access_time;
		NTTIME write_time;
		NTTIME change_time;
		uint64_t  size;
		uint64_t  alloc_size;
		uint32   attrib;
		WIRE_STRING name;
	} directory_info;

	/* RAW_SEARCH_FULL_DIRECTORY_INFO interface */
	struct {
		uint32 file_index;
		NTTIME create_time;
		NTTIME access_time;
		NTTIME write_time;
		NTTIME change_time;
		uint64_t  size;
		uint64_t  alloc_size;
		uint32   attrib;
		uint32   ea_size;
		WIRE_STRING name;
	} full_directory_info;

	/* RAW_SEARCH_NAME_INFO interface */
	struct {
		uint32 file_index;
		WIRE_STRING name;
	} name_info;

	/* RAW_SEARCH_BOTH_DIRECTORY_INFO interface */
	struct {
		uint32 file_index;
		NTTIME create_time;
		NTTIME access_time;
		NTTIME write_time;
		NTTIME change_time;
		uint64_t  size;
		uint64_t  alloc_size;
		uint32   attrib;
		uint32   ea_size;
		WIRE_STRING short_name;
		WIRE_STRING name;
	} both_directory_info;

	/* RAW_SEARCH_ID_FULL_DIRECTORY_INFO interface */
	struct {
		uint32 file_index;
		NTTIME create_time;
		NTTIME access_time;
		NTTIME write_time;
		NTTIME change_time;
		uint64_t size;
		uint64_t alloc_size;
		uint32 attrib;
		uint32 ea_size;
		uint64_t file_id;
		WIRE_STRING name;
	} id_full_directory_info;

	/* RAW_SEARCH_ID_BOTH_DIRECTORY_INFO interface */
	struct {
		uint32 file_index;
		NTTIME create_time;
		NTTIME access_time;
		NTTIME write_time;
		NTTIME change_time;
		uint64_t size;
		uint64_t alloc_size;
		uint32  attrib;
		uint32  ea_size;
		uint64_t file_id;
		WIRE_STRING short_name;
		WIRE_STRING name;
	} id_both_directory_info;

	/* RAW_SEARCH_UNIX_INFO interface */
	struct {
		uint32 file_index;
		uint64_t size;
		uint64_t alloc_size;
		NTTIME status_change_time;
		NTTIME access_time;
		NTTIME change_time;
		uint64_t uid;
		uint64_t gid;
		uint32 file_type;
		uint64_t dev_major;
		uint64_t dev_minor;
		uint64_t unique_id;
		uint64_t permissions;
		uint64_t nlink;		
		const char *name;
	} unix_info;
};


enum search_close_level {RAW_FINDCLOSE_GENERIC, RAW_FINDCLOSE_CLOSE};

/* union for file search close */
union smb_search_close {
	struct {
		enum search_close_level level;
	} generic;

	/* SMBfclose (old search) interface */
	struct {
		enum search_level level;
	
		struct {
			uint16 max_count;
			uint16 search_attrib;
			DATA_BLOB search_id;
		} in;
		struct {
			uint16 count;
		} out;
	} search_next;
	
	/* SMBfindclose interface */
	struct {
		enum search_close_level level;
		
		struct {
			uint16 handle;
		} in;
	} findclose;
};


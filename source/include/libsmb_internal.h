#ifndef _LIBSMB_INTERNAL_H_
#define _LIBSMB_INTERNAL_H_

#define SMBC_MAX_NAME  1023
#define SMBC_FILE_MODE (S_IFREG | 0444)
#define SMBC_DIR_MODE  (S_IFDIR | 0555)


#include "../include/libsmbclient.h"


struct _SMBCSRV {
	struct cli_state cli;
	dev_t dev;
	BOOL no_pathinfo2;
	int server_fd;

	SMBCSRV *next, *prev;
	
};

/* 
 * Keep directory entries in a list 
 */
struct smbc_dir_list {
	struct smbc_dir_list *next;
	struct smbc_dirent *dirent;
};


/*
 * Structure for open file management
 */ 
struct _SMBCFILE {
	int cli_fd; 
	char *fname;
	off_t offset;
	struct _SMBCSRV *srv;
	BOOL file;
	struct smbc_dir_list *dir_list, *dir_end, *dir_next;
	int dir_type, dir_error;

	SMBCFILE *next, *prev;
};


struct smbc_internal_data {

	/** INTERNAL: is this handle initialized ? 
	 */
	int     _initialized;

	/** INTERNAL: dirent pointer location 
	 */
	char    _dirent[512];  

	/** INTERNAL: server connection list
	 */
	SMBCSRV * _servers;
	
	/** INTERNAL: open file/dir list
	 */
	SMBCFILE * _files;
};	


#endif

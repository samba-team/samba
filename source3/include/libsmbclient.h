/*=====================================================================
  Unix SMB/Netbios implementation.
  SMB client library API definitions
  Copyright (C) Andrew Tridgell 1998
  Copyright (C) Richard Sharpe 2000
  Copyright (C) John Terpsra 2000
  Copyright (C) Tom Jansen (Ninja ISD) 2002 

   
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
  =====================================================================*/

#ifndef SMBCLIENT_H_INCLUDED
#define SMBCLIENT_H_INCLUDED

/*-------------------------------------------------------------------*/
/* The following are special comments to instruct DOXYGEN (automated 
 * documentation tool:
*/
/** \defgroup libsmbclient
*/
/** \defgroup structure Data Structures Type and Constants
*   \ingroup libsmbclient
*   Data structures, types, and constants
*/
/** \defgroup callback Callback function types
*   \ingroup libsmbclient
*   Callback functions
*/
/** \defgroup file File Functions
*   \ingroup libsmbclient
*   Functions used to access individual file contents
*/
/** \defgroup directory Directory Functions
*   \ingroup libsmbclient
*   Functions used to access directory entries
*/
/** \defgroup attribute Attributes Functions
*   \ingroup libsmbclient
*   Functions used to view or change file and directory attributes
*/
/** \defgroup print Print Functions
*   \ingroup libsmbclient
*   Functions used to access printing functionality
*/
/** \defgroup misc Miscellaneous Functions
*   \ingroup libsmbclient
*   Functions that don't fit in to other categories
*/
/*-------------------------------------------------------------------*/   

/* Make sure we have the following includes for now ... */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SMBC_WORKGROUP      1
#define SMBC_SERVER         2
#define SMBC_FILE_SHARE     3
#define SMBC_PRINTER_SHARE  4
#define SMBC_COMMS_SHARE    5
#define SMBC_IPC_SHARE      6
#define SMBC_DIR            7
#define SMBC_FILE           8
#define SMBC_LINK           9

/**@ingroup structure
 * Structure that represents a directory entry.
 *
 */
struct smbc_dirent 
{
	/** Type of entity.
	    SMBC_WORKGROUP=1,
	    SMBC_SERVER=2, 
	    SMBC_FILE_SHARE=3,
	    SMBC_PRINTER_SHARE=4,
	    SMBC_COMMS_SHARE=5,
	    SMBC_IPC_SHARE=6,
	    SMBC_DIR=7,
	    SMBC_FILE=8,
	    SMBC_LINK=9,*/ 
	unsigned int smbc_type; 

	/** Length of this smbc_dirent in bytes
	 */
	unsigned int dirlen;
	/** The length of the comment string in bytes (includes null 
	 *  terminator)
	 */
	unsigned int commentlen;
	/** Points to the null terminated comment string 
	 */
	char *comment;
	/** The length of the name string in bytes (includes null 
	 *  terminator)
	 */
	unsigned int namelen;
	/** Points to the null terminated name string 
	 */
	char name[1];
};


/**@ingroup structure
 * Structure that represents a print job.
 *
 */
#ifndef _CLIENT_H
struct print_job_info 
{
	/** numeric ID of the print job
	 */
	unsigned short id;
    
	/** represents print job priority (lower numbers mean higher priority)
	 */
	unsigned short priority;
    
	/** Size of the print job
	 */
	size_t size;
    
	/** Name of the user that owns the print job
	 */
	char user[128];
  
	/** Name of the print job. This will have no name if an anonymous print
	 *  file was opened. Ie smb://server/printer
	 */
	char name[128];

	/** Time the print job was spooled
	 */
	time_t t;
};
#endif /* _CLIENT_H */


/**@ingroup structure
 * Server handle 
 */
typedef struct _SMBCSRV  SMBCSRV;

/**@ingroup structure
 * File or directory handle 
 */
typedef struct _SMBCFILE SMBCFILE;

/**@ingroup structure
 * File or directory handle 
 */
typedef struct _SMBCCTX SMBCCTX;





/**@ingroup callback
 * Authentication callback function type.
 * 
 * Type for the the authentication function called by the library to
 * obtain authentication credentals
 *
 * @param srv       Server being authenticated to
 *
 * @param shr       Share being authenticated to
 *
 * @param wg        Pointer to buffer containing a "hint" for the
 *                  workgroup to be authenticated.  Should be filled in
 *                  with the correct workgroup if the hint is wrong.
 * 
 * @param wglen     The size of the workgroup buffer in bytes
 *
 * @param un        Pointer to buffer containing a "hint" for the
 *                  user name to be use for authentication. Should be
 *                  filled in with the correct workgroup if the hint is
 *                  wrong.
 * 
 * @param unlen     The size of the username buffer in bytes
 *
 * @param pw        Pointer to buffer containing to which password 
 *                  copied
 * 
 * @param pwlen     The size of the password buffer in bytes
 *           
 */
typedef void (*smbc_get_auth_data_fn)(const char *srv, 
                                      const char *shr,
                                      char *wg, int wglen, 
                                      char *un, int unlen,
                                      char *pw, int pwlen);


/**@ingroup callback
 * Print job info callback function type.
 *
 * @param i         pointer to print job information structure
 *
 */ 
typedef void (*smbc_list_print_job_fn)(struct print_job_info *i);
		

/**@ingroup callback
 * Check if a server is still good
 *
 * @param c         pointer to smb context
 *
 * @param srv       pointer to server to check
 *
 * @return          0 when connection is good. 1 on error.
 *
 */ 
typedef int (*smbc_check_server_fn)(SMBCCTX * c, SMBCSRV *srv);

/**@ingroup callback
 * Remove a server if unused
 *
 * @param c         pointer to smb context
 *
 * @param srv       pointer to server to remove
 *
 * @return          0 on success. 1 on failure.
 *
 */ 
typedef int (*smbc_remove_unused_server_fn)(SMBCCTX * c, SMBCSRV *srv);


/**@ingroup callback
 * Add a server to the cache system
 *
 * @param c         pointer to smb context
 *
 * @param srv       pointer to server to add
 *
 * @param server    server name 
 *
 * @param share     share name
 *
 * @param workgroup workgroup used to connect
 *
 * @param username  username used to connect
 *
 * @return          0 on success. 1 on failure.
 *
 */ 
typedef int (*smbc_add_cached_srv_fn)   (SMBCCTX * c, SMBCSRV *srv, 
				    char * server, char * share, 
				    char * workgroup, char * username);


/**@ingroup callback
 * Look up a server in the cache system
 *
 * @param c         pointer to smb context
 *
 * @param server    server name to match
 *
 * @param share     share name to match
 *
 * @param workgroup workgroup to match
 *
 * @param username  username to match
 *
 * @return          pointer to SMBCSRV on success. NULL on failure.
 *
 */ 
typedef SMBCSRV * (*smbc_get_cached_srv_fn)   (SMBCCTX * c, char * server, 
					       char * share, char * workgroup, char * username);


/**@ingroup callback
 * Check if a server is still good
 *
 * @param c         pointer to smb context
 *
 * @param srv       pointer to server to remove
 *
 * @return          0 when found and removed. 1 on failure.
 *
 */ 
typedef int (*smbc_remove_cached_srv_fn)(SMBCCTX * c, SMBCSRV *srv);


/**@ingroup callback
 * Try to remove all servers from the cache system and disconnect
 *
 * @param c         pointer to smb context
 *
 * @return          0 when found and removed. 1 on failure.
 *
 */ 
typedef int (*smbc_purge_cached_fn)     (SMBCCTX * c);




/**@ingroup structure
 * Structure that contains a client context information 
 * This structure is know as SMBCCTX
 */
struct _SMBCCTX {
	/** debug level 
	 */
	int     debug;
	
	/** netbios name used for making connections
	 */
	char * netbios_name;

	/** workgroup name used for making connections 
	 */
	char * workgroup;

	/** username used for making connections 
	 */
	char * user;

	/** timeout used for waiting on connections / response data (in milliseconds)
	 */
	int timeout;

	/** callable functions for files:
	 * For usage and return values see the smbc_* functions
	 */ 
	SMBCFILE * (*open)    (SMBCCTX *c, const char *fname, int flags, mode_t mode);
	SMBCFILE * (*creat)   (SMBCCTX *c, const char *path, mode_t mode);
	ssize_t    (*read)    (SMBCCTX *c, SMBCFILE *file, void *buf, size_t count);
	ssize_t    (*write)   (SMBCCTX *c, SMBCFILE *file, void *buf, size_t count);
	int        (*unlink)  (SMBCCTX *c, const char *fname);
	int        (*rename)  (SMBCCTX *ocontext, const char *oname, 
			       SMBCCTX *ncontext, const char *nname);
	off_t      (*lseek)   (SMBCCTX *c, SMBCFILE * file, off_t offset, int whence);
	int        (*stat)    (SMBCCTX *c, const char *fname, struct stat *st);
	int        (*fstat)   (SMBCCTX *c, SMBCFILE *file, struct stat *st);
	int        (*close)   (SMBCCTX *c, SMBCFILE *file);

	/** callable functions for dirs
	 */ 
	SMBCFILE * (*opendir) (SMBCCTX *c, const char *fname);
	int        (*closedir)(SMBCCTX *c, SMBCFILE *dir);
	struct smbc_dirent * (*readdir)(SMBCCTX *c, SMBCFILE *dir);
	int        (*getdents)(SMBCCTX *c, SMBCFILE *dir, 
			       struct smbc_dirent *dirp, int count);
	int        (*mkdir)   (SMBCCTX *c, const char *fname, mode_t mode);
	int        (*rmdir)   (SMBCCTX *c, const char *fname);
	off_t      (*telldir) (SMBCCTX *c, SMBCFILE *dir);
	int        (*lseekdir)(SMBCCTX *c, SMBCFILE *dir, off_t offset);
	int        (*fstatdir)(SMBCCTX *c, SMBCFILE *dir, struct stat *st);

	/** callable functions for printing
	 */ 
	int        (*print_file)(SMBCCTX *c_file, const char *fname, 
				 SMBCCTX *c_print, const char *printq);
	SMBCFILE * (*open_print_job)(SMBCCTX *c, const char *fname);
	int        (*list_print_jobs)(SMBCCTX *c, const char *fname, smbc_list_print_job_fn fn);
	int        (*unlink_print_job)(SMBCCTX *c, const char *fname, int id);


	/** Callbacks
	 * These callbacks _always_ have to be initialized because they will not be checked
	 * at dereference for increased speed.
	 */
	struct _smbc_callbacks {
		/** authentication function callback: called upon auth requests
		 */
		smbc_get_auth_data_fn auth_fn;
		
		/** check if a server is still good
		 */
		smbc_check_server_fn check_server_fn;

		/** remove a server if unused
		 */
		smbc_remove_unused_server_fn remove_unused_server_fn;

		/** Cache subsystem
		 * For an example cache system see samba/source/libsmb/libsmb_cache.c
		 * Cache subsystem functions follow.
		 */

		/** server cache addition 
		 */
		smbc_add_cached_srv_fn add_cached_srv_fn;

		/** server cache lookup 
		 */
		smbc_get_cached_srv_fn get_cached_srv_fn;

		/** server cache removal
		 */
		smbc_remove_cached_srv_fn remove_cached_srv_fn;
		
		/** server cache purging, try to remove all cached servers (disconnect)
		 */
		smbc_purge_cached_fn purge_cached_fn;
	} callbacks;


	/** Space to store private data of the server cache.
	 */
	struct smbc_server_cache * server_cache;

	/** INTERNAL DATA
	 * do _NOT_ touch this from your program !
	 */
	struct smbc_internal_data * internal;
	
};


/**@ingroup misc
 * Create a new SBMCCTX (a context).
 *
 * Must be called before the context is passed to smbc_context_init()
 *
 * @return          The given SMBCCTX pointer on success, NULL on error with errno set:
 *                  - ENOMEM Out of memory
 *
 * @see             smbc_free_context(), smbc_init_context()
 *
 * @note            Do not forget to smbc_init_context() the returned SMBCCTX pointer !
 */
SMBCCTX * smbc_new_context(void);

/**@ingroup misc
 * Delete a SBMCCTX (a context) acquired from smbc_new_context().
 *
 * The context will be deleted if possible.
 *
 * @param context   A pointer to a SMBCCTX obtained from smbc_new_context()
 *
 * @param shutdown_ctx   If 1, all connections and files will be closed even if they are busy.
 *
 *
 * @return          Returns 0 on succes. Returns 1 on failure with errno set:
 *                  - EBUSY Server connections are still used, Files are open or cache 
 *                          could not be purged
 *                  - EBADF context == NULL
 *
 * @see             smbc_new_context()
 *
 * @note            It is advised to clean up all the contexts with shutdown_ctx set to 1
 *                  just before exit()'ing. When shutdown_ctx is 0, this function can be
 *                  use in periodical cleanup functions for example.
 */
int smbc_free_context(SMBCCTX * context, int shutdown_ctx);


/**@ingroup misc
 * Initialize a SBMCCTX (a context).
 *
 * Must be called before using any SMBCCTX API function
 *
 * @param context   A pointer to a SMBCCTX obtained from smbc_new_context()
 *
 * @return          A pointer to the given SMBCCTX on success, NULL on error with errno set:
 *                  - EBADF  NULL context given
 *                  - ENOMEM Out of memory
 *                  - ENOENT The smb.conf file would not load
 *
 * @see             smbc_new_context()
 *
 * @note            my_context = smbc_init_context(smbc_new_context()) is perfectly safe, 
 *                  but it might leak memory on smbc_context_init() failure. Avoid this.
 *                  You'll have to call smbc_free_context() yourself on failure.  
 */

SMBCCTX * smbc_init_context(SMBCCTX * context);

/**@ingroup misc
 * Initialize the samba client library.
 *
 * Must be called before using any of the smbclient API function
 *  
 * @param fn        The function that will be called to obtaion 
 *                  authentication credentials.
 *
 * @param debug     Allows caller to set the debug level. Can be
 *                  changed in smb.conf file. Allows caller to set
 *                  debugging if no smb.conf.
 *   
 * @return          0 on success, < 0 on error with errno set:
 *                  - ENOMEM Out of memory
 *                  - ENOENT The smb.conf file would not load
 *
 */

int smbc_init(smbc_get_auth_data_fn fn, int debug);

/**@ingroup file
 * Open a file on an SMB server.
 *
 * @param furl      The smb url of the file to be opened. 
 *
 * @param flags     Is one of O_RDONLY, O_WRONLY or O_RDWR which 
 *                  request opening  the  file  read-only,write-only
 *                  or read/write. flags may also be bitwise-or'd with
 *                  one or  more of  the following: 
 *                  O_CREAT - If the file does not exist it will be 
 *                  created.
 *                  O_EXCL - When  used with O_CREAT, if the file 
 *                  already exists it is an error and the open will 
 *                  fail. 
 *                  O_TRUNC - If the file already exists it will be
 *                  truncated.
 *                  O_APPEND The  file  is  opened  in  append mode 
 *
 * @param mode      mode specifies the permissions to use if a new 
 *                  file is created.  It  is  modified  by  the 
 *                  process's umask in the usual way: the permissions
 *                  of the created file are (mode & ~umask) 
 *
 *                  Not currently use, but there for future use.
 *                  We will map this to SYSTEM, HIDDEN, etc bits
 *                  that reverses the mapping that smbc_fstat does.
 *
 * @return          Valid file handle, < 0 on error with errno set:
 *                  - ENOMEM  Out of memory
 *                  - EINVAL if an invalid parameter passed, like no 
 *                  file, or smbc_init not called.
 *                  - EEXIST  pathname already exists and O_CREAT and 
 *                  O_EXCL were used.
 *                  - EISDIR  pathname  refers  to  a  directory  and  
 *                  the access requested involved writing.
 *                  - EACCES  The requested access to the file is not 
 *                  allowed 
 *                  - ENODEV The requested share does not exist
 *                  - ENOTDIR A file on the path is not a directory
 *                  - ENOENT  A directory component in pathname does 
 *                  not exist.
 *
 * @see             smbc_creat()
 *
 * @note            This call uses an underlying routine that may create
 *                  a new connection to the server specified in the URL.
 *                  If the credentials supplied in the URL, or via the
 *                  auth_fn in the smbc_init call, fail, this call will
 *                  try again with an empty username and password. This 
 *                  often gets mapped to the guest account on some machines.
 */

int smbc_open(const char *furl, int flags, mode_t mode);

/**@ingroup file
 * Create a file on an SMB server.
 *
 * Same as calling smbc_open() with flags = O_CREAT|O_WRONLY|O_TRUNC 
 *   
 * @param furl      The smb url of the file to be created
 *  
 * @param mode      mode specifies the permissions to use if  a  new  
 *                  file is created.  It  is  modified  by  the 
 *                  process's umask in the usual way: the permissions
 *                  of the created file are (mode & ~umask)
 *
 *                  NOTE, the above is not true. We are dealing with 
 *                  an SMB server, which has no concept of a umask!
 *      
 * @return          Valid file handle, < 0 on error with errno set:
 *                  - ENOMEM  Out of memory
 *                  - EINVAL if an invalid parameter passed, like no 
 *                  file, or smbc_init not called.
 *                  - EEXIST  pathname already exists and O_CREAT and
 *                  O_EXCL were used.
 *                  - EISDIR  pathname  refers  to  a  directory  and
 *                  the access requested involved writing.
 *                  - EACCES  The requested access to the file is not
 *                  allowed 
 *                  - ENOENT  A directory component in pathname does 
 *                  not exist.
 *                  - ENODEV The requested share does not exist.
 * @see             smbc_open()
 *
 */

int smbc_creat(const char *furl, mode_t mode);

/**@ingroup file
 * Read from a file using an opened file handle.
 *
 * @param fd        Open file handle from smbc_open() or smbc_creat()
 *
 * @param buf       Pointer to buffer to recieve read data
 *
 * @param bufsize   Size of buf in bytes
 *
 * @return          Number of bytes read, < 0 on error with errno set:
 *                  - EISDIR fd refers to a directory
 *                  - EBADF  fd  is  not  a valid file descriptor or 
 *                  is not open for reading.
 *                  - EINVAL fd is attached to an object which is 
 *                  unsuitable for reading, or no buffer passed or
 *		    smbc_init not called.
 *
 * @see             smbc_open(), smbc_write()
 *
 */
ssize_t smbc_read(int fd, void *buf, size_t bufsize);


/**@ingroup file
 * Write to a file using an opened file handle.
 *
 * @param fd        Open file handle from smbc_open() or smbc_creat()
 *
 * @param buf       Pointer to buffer to recieve read data
 *
 * @param bufsize   Size of buf in bytes
 *
 * @return          Number of bytes written, < 0 on error with errno set:
 *                  - EISDIR fd refers to a directory.
 *                  - EBADF  fd  is  not  a valid file descriptor or 
 *                  is not open for reading.
 *                  - EINVAL fd is attached to an object which is 
 *                  unsuitable for reading, or no buffer passed or
 *		    smbc_init not called.
 *
 * @see             smbc_open(), smbc_read()
 *
 */
ssize_t smbc_write(int fd, void *buf, size_t bufsize);


/**@ingroup file
 * Seek to a specific location in a file.
 *
 * @param fd        Open file handle from smbc_open() or smbc_creat()
 * 
 * @param offset    Offset in bytes from whence
 * 
 * @param whence    A location in the file:
 *                  - SEEK_SET The offset is set to offset bytes from
 *                  the beginning of the file
 *                  - SEEK_CUR The offset is set to current location 
 *                  plus offset bytes.
 *                  - SEEK_END The offset is set to the size of the 
 *                  file plus offset bytes.
 *
 * @return          Upon successful completion, lseek returns the 
 *                  resulting offset location as measured in bytes 
 *                  from the beginning  of the file. Otherwise, a value
 *                  of (off_t)-1 is returned and errno is set to 
 *                  indicate the error:
 *                  - EBADF  Fildes is not an open file descriptor.
 *                  - EINVAL Whence is not a proper value or smbc_init
 *		      not called.
 *
 * @todo Are all the whence values really supported?
 * 
 * @todo Are errno values complete and correct?
 */
off_t smbc_lseek(int fd, off_t offset, int whence);


/**@ingroup file
 * Close an open file handle.
 *
 * @param fd        The file handle to close
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EBADF  fd isn't a valid open file descriptor
 *                  - EINVAL smbc_init() failed or has not been called
 *
 * @see             smbc_open(), smbc_creat()
 */
int smbc_close(int fd);


/**@ingroup directory
 * Unlink (delete) a file or directory.
 *
 * @param furl      The smb url of the file to delete
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EACCES or EPERM Write  access  to the directory 
 *                  containing pathname is not allowed or one  
 *                  of  the  directories in pathname did not allow
 *                  search (execute) permission
 *                  - ENOENT A directory component in pathname does
 *                  not exist
 *                  - EINVAL NULL was passed in the file param or
 *		      smbc_init not called.
 *                  - EACCES You do not have access to the file
 *                  - ENOMEM Insufficient kernel memory was available
 *
 * @see             smbc_rmdir()s
 *
 * @todo Are errno values complete and correct?
 */
int smbc_unlink(const char *furl);


/**@ingroup directory
 * Rename or move a file or directory.
 * 
 * @param ourl      The original smb url (source url) of file or 
 *                  directory to be moved
 * 
 * @param nurl      The new smb url (destination url) of the file
 *                  or directory after the move.  Currently nurl must
 *                  be on the same share as ourl.
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EISDIR nurl is an existing directory, but ourl is
 *                  not a directory.
 *                  - EEXIST nurl is  a  non-empty directory, 
 *                  i.e., contains entries other than "." and ".."
 *                  - EINVAL The  new  url  contained  a path prefix 
 *                  of the old, or, more generally, an  attempt was
 *                  made  to make a directory a subdirectory of itself
 *		    or smbc_init not called.
 *                  - ENOTDIR A component used as a directory in ourl 
 *                  or nurl path is not, in fact, a directory.  Or, 
 *                  ourl  is a directory, and newpath exists but is not
 *                  a directory.
 *                  - EACCES or EPERM Write access to the directory 
 *                  containing ourl or nurl is not allowed for the 
 *                  process's effective uid,  or  one of the 
 *                  directories in ourl or nurl did not allow search
 *                  (execute) permission,  or ourl  was  a  directory
 *                  and did not allow write permission.
 *                  - ENOENT A  directory component in ourl or nurl 
 *                  does not exist.
 *                  - EXDEV Rename across shares not supported.
 *                  - ENOMEM Insufficient kernel memory was available.
 *                  - EEXIST The target file, nurl, already exists.
 *
 *
 * @todo Are we going to support copying when urls are not on the same
 *       share?  I say no... NOTE. I agree for the moment.
 *
 */
int smbc_rename(const char *ourl, const char *nurl);


/**@ingroup directory
 * Open a directory used to obtain directory entries.
 *
 * @param durl      The smb url of the directory to open
 *
 * @return          Valid directory handle. < 0 on error with errno set:
 *                  - EACCES Permission denied.
 *                  - EINVAL A NULL file/URL was passed, or the URL would
 *                  not parse, or was of incorrect form or smbc_init not
 *                  called.
 *                  - ENOENT durl does not exist, or name is an 
 *                  - ENOMEM Insufficient memory to complete the 
 *                  operation.                              
 *                  - ENOTDIR name is not a directory.
 *                  - EPERM the workgroup could not be found.
 *                  - ENODEV the workgroup or server could not be found.
 *
 * @see             smbc_getdents(), smbc_readdir(), smbc_closedir()
 *
 */
int smbc_opendir(const char *durl);


/**@ingroup directory
 * Close a directory handle opened by smbc_opendir().
 *
 * @param dh        Directory handle to close
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EBADF dh is an invalid directory handle
 *
 * @see             smbc_opendir()
 */
int smbc_closedir(int dh);


/**@ingroup directory
 * Get multiple directory entries.
 *
 * smbc_getdents() reads as many dirent structures from the an open 
 * directory handle into a specified memory area as will fit.
 *
 * @param dh        Valid directory as returned by smbc_opendir()
 *
 * @param dirp      pointer to buffer that will receive the directory
 *                  entries.
 * 
 * @param count     The size of the dirp buffer in bytes
 *
 * @returns         If any dirents returned, return will indicate the
 *                  total size. If there were no more dirents available,
 *                  0 is returned. < 0 indicates an error.
 *                  - EBADF  Invalid directory handle
 *                  - EINVAL Result buffer is too small or smbc_init
 *		    not called.
 *                  - ENOENT No such directory.
 * @see             , smbc_dirent, smbc_readdir(), smbc_open()
 *
 * @todo Are errno values complete and correct?
 *
 * @todo Add example code so people know how to parse buffers.
 */
int smbc_getdents(unsigned int dh, struct smbc_dirent *dirp, int count);


/**@ingroup directory
 * Get a single directory entry.
 *
 * @param dh        Valid directory as returned by smbc_opendir()
 *
 * @return          A pointer to a smbc_dirent structure, or NULL if an
 *                  error occurs or end-of-directory is reached:
 *                  - EBADF Invalid directory handle
 *                  - EINVAL smbc_init() failed or has not been called
 *
 * @see             smbc_dirent, smbc_getdents(), smbc_open()
 */
struct smbc_dirent* smbc_readdir(unsigned int dh);


/**@ingroup directory
 * Get the current directory offset.
 *
 * smbc_telldir() may be used in conjunction with smbc_readdir() and
 * smbc_lseekdir().
 *
 * @param dh        Valid directory as returned by smbc_opendir()
 *
 * @return          The current location in the directory stream or -1
 *                  if an error occur.  The current location is not
 *                  an offset. Becuase of the implementation, it is a 
 *                  handle that allows the library to find the entry
 *                  later.
 *                  - EBADF dh is not a valid directory handle
 *                  - EINVAL smbc_init() failed or has not been called
 *                  - ENOTDIR if dh is not a directory
 *
 * @see             smbc_readdir()
 *
 */
off_t smbc_telldir(int dh);


/**@ingroup directory
 * lseek on directories.
 *
 * smbc_lseekdir() may be used in conjunction with smbc_readdir() and
 * smbc_telldir(). (rewind by smbc_lseekdir(fd, NULL))
 *
 * @param fd        Valid directory as returned by smbc_opendir()
 * 
 * @param offset    The offset (as returned by smbc_telldir). Can be
 *                  NULL, in which case we will rewind
 *
 * @return          0 on success, -1 on failure
 *                  - EBADF dh is not a valid directory handle
 *                  - ENOTDIR if dh is not a directory
 *                  - EINVAL offset did not refer to a valid dirent or
 *		      smbc_init not called.
 *
 * @see             smbc_telldir()
 *
 *
 * @todo In what does the reture and errno values mean?
 */
int smbc_lseekdir(int fd, off_t offset);

/**@ingroup directory
 * Create a directory.
 *
 * @param durl      The url of the directory to create
 *
 * @param mode      Specifies  the  permissions to use. It is modified
 *                  by the process's umask in the usual way: the 
 *                  permissions of the created file are (mode & ~umask).
 * 
 * @return          0 on success, < 0 on error with errno set:
 *                  - EEXIST directory url already exists
 *                  - EACCES The parent directory does not allow write
 *                  permission to the process, or one of the directories
 *                  - ENOENT A directory component in pathname does not
 *                  exist.
 *                  - EINVAL NULL durl passed or smbc_init not called.
 *                  - ENOMEM Insufficient memory was available.
 *
 * @see             smbc_rmdir()
 *
 */
int smbc_mkdir(const char *durl, mode_t mode);


/**@ingroup directory
 * Remove a directory.
 * 
 * @param durl      The smb url of the directory to remove
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EACCES or EPERM Write access to the directory
 *                  containing pathname was not allowed.
 *                  - EINVAL durl is NULL or smbc_init not called.
 *                  - ENOENT A directory component in pathname does not
 *                  exist.
 *                  - ENOTEMPTY directory contains entries.
 *                  - ENOMEM Insufficient kernel memory was available.
 *
 * @see             smbc_mkdir(), smbc_unlink() 
 *
 * @todo Are errno values complete and correct?
 */
int smbc_rmdir(const char *durl);


/**@ingroup attribute
 * Get information about a file or directory.
 *
 * @param url       The smb url to get information for
 *
 * @param st        pointer to a buffer that will be filled with 
 *                  standard Unix struct stat information.
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - ENOENT A component of the path file_name does not
 *                  exist.
 *                  - EINVAL a NULL url was passed or smbc_init not called.
 *                  - EACCES Permission denied.
 *                  - ENOMEM Out of memory
 *                  - ENOTDIR The target dir, url, is not a directory.
 *
 * @see             Unix stat()
 *
 */
int smbc_stat(const char *url, struct stat *st);


/**@ingroup attribute
 * Get file information via an file descriptor.
 * 
 * @param fd        Open file handle from smbc_open() or smbc_creat()
 *
 * @param st        pointer to a buffer that will be filled with 
 *                  standard Unix struct stat information.
 * 
 * @return          EBADF  filedes is bad.
 *                  - EACCES Permission denied.
 *                  - EBADF fd is not a valid file descriptor
 *                  - EINVAL Problems occurred in the underlying routines
 *		      or smbc_init not called.
 *                  - ENOMEM Out of memory
 *
 * @see             smbc_stat(), Unix stat()
 *
 */
int smbc_fstat(int fd, struct stat *st);


/**@ingroup attribue
 * Change the ownership of a file or directory.
 *
 * @param url       The smb url of the file or directory to change 
 *                  ownership of.
 *
 * @param owner     I have no idea?
 *
 * @param group     I have not idea?
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EPERM  The effective UID does not match the owner
 *                  of the file, and is not zero; or the owner or group
 *                  were specified incorrectly.
 *                  - ENOENT The file does not exist.
 *                  - ENOMEM Insufficient was available.
 *                  - ENOENT file or directory does not exist
 *
 * @todo Are we actually going to be able to implement this function
 *
 * @todo How do we abstract owner and group uid and gid?
 *
 */
int smbc_chown(const char *url, uid_t owner, gid_t group);


/**@ingroup attribute
 * Change the permissions of a file.
 *
 * @param url       The smb url of the file or directory to change
 *                  permissions of
 * 
 * @param mode      The permissions to set:
 *                  - Put good explaination of permissions here!
 *
 * @return          0 on success, < 0 on error with errno set:
 *                  - EPERM  The effective UID does not match the owner
 *                  of the file, and is not zero
 *                  - ENOENT The file does not exist.
 *                  - ENOMEM Insufficient was available.
 *                  - ENOENT file or directory does not exist
 *
 * @todo Actually implement this fuction?
 *
 * @todo Are errno values complete and correct?
 */
int smbc_chmod(const char *url, mode_t mode);


/**@ingroup print
 * Print a file given the name in fname. It would be a URL ...
 * 
 * @param fname     The URL of a file on a remote SMB server that the
 *                  caller wants printed
 *
 * @param printq    The URL of the print share to print the file to.
 *
 * @return          0 on success, < 0 on error with errno set:         
 *
 *                  - EINVAL fname or printq was NULL or smbc_init not
 * 		      not called.
 *                  and errors returned by smbc_open
 *
 */                                     
int smbc_print_file(const char *fname, const char *printq);

/**@ingroup print
 * Open a print file that can be written to by other calls. This simply
 * does an smbc_open call after checking if there is a file name on the
 * URI. If not, a temporary name is added ...
 *
 * @param fname     The URL of the print share to print to?
 *
 * @returns         A file handle for the print file if successful.
 *                  Returns -1 if an error ocurred and errno has the values
 *                  - EINVAL fname was NULL or smbc_init not called.
 *                  - all errors returned by smbc_open
 *
 */
int smbc_open_print_job(const char *fname);

/**@ingroup print
 * List the print jobs on a print share, for the moment, pass a callback 
 *
 * @param purl      The url of the print share to list the jobs of
 * 
 * @param fn        Callback function the receives printjob info
 * 
 * @return          0 on success, < 0 on error with errno set: 
 *                  - EINVAL fname was NULL or smbc_init not called
 *                  - EACCES ???
 */
int smbc_list_print_jobs(const char *purl, smbc_list_print_job_fn fn);

/**@ingroup print
 * Delete a print job 
 *
 * @param purl      Url of the print share
 *
 * @param id        The id of the job to delete
 *
 * @return          0 on success, < 0 on error with errno set: 
 *                  - EINVAL fname was NULL or smbc_init not called
 *
 * @todo    what errno values are possible here?
 */
int smbc_unlink_print_job(const char *purl, int id);


#endif /* SMBCLIENT_H_INCLUDED */

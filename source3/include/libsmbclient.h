/*=====================================================================
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB client library API definitions
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000
   Copyright (C) John Terpsra 2000
   
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
/** \defgroup structure Data Structures Type and Constants
*   Data structures, types, and constants
*/
/** \defgroup file File Functions
*   Functions used to access individual file contents
*/
/** \defgroup directory Directory Functions
*   Functions used to access directory entries
*/
/** \defgroup attribute Attributes Functions
*   Functions used to view or change file and directory attributes
*/
/** \defgroup print Print Functions
*   Functions used to access printing functionality
*/
/** \defgroup attribute Miscellaneous Functions
*   Functions that don't fit in to other categories
*/
/*-------------------------------------------------------------------*/   

/* Make sure we have the following includes for now ... */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SMBC_MAX_NAME       1023
#define SMBC_WORKGROUP      1
#define SMBC_SERVER         2
#define SMBC_FILE_SHARE     3
#define SMBC_PRINTER_SHARE  4
#define SMBC_COMMS_SHARE    5
#define SMBC_IPC_SHARE      6
#define SMBC_DIR            7
#define SMBC_FILE           8
#define SMBC_LINK           9

#define SMBC_FILE_MODE (S_IFREG | 0444)
#define SMBC_DIR_MODE  (S_IFDIR | 0555)

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
    uint smbc_type; 

    /** Length of this smbc_dirent in bytes
     */
    uint dirlen;
    /** The length of the comment string in bytes (includes null 
     *  terminator)
     */
    uint commentlen;
    /** Points to the null terminated comment string 
     */
    char *comment;
    /** The length of the name string in bytes (includes null 
     *  terminator)
     */
    uint namelen;
    /** Points to the null terminated name string 
     */
    char name[1];
};


#ifndef _CLIENT_H
typedef unsigned short uint16;

/**@ingroup structure
 * Structure that represents a print job.
 *
 * @todo    Make sure the discriptions of structure members are correct.
 */
struct print_job_info 
{
    /** numeric ID of the print job
     */
    uint16 id;
    
    /** represents print job priority (lower numbers mean higher priority?)
     */
    uint16 priority;
    
    /** Size of the print job
     */
    size_t size;
    
    /** Name of the user that owns the print job
     */
    char user[128];
  
    /** Name of the print job
     */
    char name[128];

    /** Time the print job was spooled?
    */
    time_t t;
};
#endif


/**@ingroup structure
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
 *                  workgroup to be authenticated.  Should be filled
 *                  with the correct workgroup if the hint is wrong.
 * 
 * @param wglen     The size of the workgroup buffer in bytes
 *
 * @param un        Pointer to buffer containing a "hint" for the
 *                  user name to be use for authentication. Should be
 *                  filled with the correct workgroup if the hint is
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


/**@ingroup structure
 * Print job info callback function type.
 *
 * @param i         pointer to print job information structure
 *
 */ 
typedef void (*smbc_get_print_job_info)(struct print_job_info *i);


/**@ingroup misc
 * Initialize the samba client library.
 *
 * Must be called before using any of the smbclient API function
 *  
 * @param fn        The function that will be called to obtaion 
 *                  authentication credentials.
 *
 * @param debug     Allows caller to set the debug level. Can be
 *                  changed in smb.conf file.
 *   
 * @return          0 on success, < 0 on error with errno set:
 *                  - ENOMEM Out of memory
 *
 * @todo Why do we need to pass in debug information?
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
 *                  Not currently use, but there for future use
 *                  when we figure this out.
 *
 * @return          Valid file handle, < 0 on error with errno set:
 *                  - ENOMEM  Out of memory
 *                  - EEXIST  pathname already exists and O_CREAT and 
 *                  O_EXCL were used.
 *                  - EISDIR  pathname  refers  to  a  directory  and  
 *                  the access requested involved writing.
 *                  - EACCES  The requested access to the file is not 
 *                  allowed 
 *                  - ENOENT  A directory component in pathname does 
 *                  not exist.
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             smbc_creat()
 *
 * @todo Mode needs to be better explained if there is any differences
 *       from standard open().
 *
 * @todo Are errno values complete and correct? They look OK.
 *
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
 * @return          Valid file handle, < 0 on error with errno set:
 *                  - ENOMEM  Out of memory
 *                  - EEXIST  pathname already exists and O_CREAT and
 *                  O_EXCL were used.
 *                  - EISDIR  pathname  refers  to  a  directory  and
 *                  the access requested involved writing.
 *                  - EACCES  The requested access to the file is not
 *                  allowed 
 *                  - ENOENT  A directory component in pathname does 
 *                  not exist.
 *                  - EUCLEAN smbc_init() failed or has not been called
 * @see             smbc_open()
 *
 * @todo Are errno values complete and correct?
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
 *                  unsuitable for reading.
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             smbc_open(), smbc_write()
 *
 * @todo Are errno values complete and correct?
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
 *                  unsuitable for reading.
 *                  - EUCLEAN smbc_init() failed or has not been called
 * @see             smbc_open(), smbc_read()
 *
 * @todo Are errno values complete and correct?
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
 *                  - EINVAL Whence is not a proper value.  
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  - ENOMEM Insufficient kernel memory was availabl
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  made  to make a directory a subdirectory of itself.
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
 *                  - ENOMEM Insufficient kernel memory was available.
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @todo Are errno values complete and correct?
 *
 * @todo Are we going to support copying when urls are not on the same
 *       share?  I say no...
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
 *                  - ENOENT durl does not exist, or name is an 
 *                  - ENOMEM Insufficient memory to complete the 
 *                  operation.                              
 *                  - ENOTDIR name is not a directory.
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             smbc_getdents(), smbc_readdir(), smbc_closedir()
 *
 * @todo Are errno values complete and correct?
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
 * smbc_getdents() reads several dirent structures from the an open 
 * directory handle into a specified memory area.
 *
 * @param dh        Valid directory as returned by smbc_opendir()
 *
 * @param dirp      pointer to buffer that will receive the directory
 *                  entries.
 * 
 * @param count     The size of the dirp buffer in bytes
 *
 * @returns         - EBADF  Invalid directory handle
 *                  - EINVAL Result buffer is too small
 *                  - ENOENT No such directory.
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  if an error occur.
 *                  - EBADF dh is not a valid directory handle
 *
 * @see             smbc_readdir()
 *
 * @todo What in the is the offset related to bytes or directory entry
 *       number?
*/
off_t smbc_telldir(int dh);


/**@ingroup directory
 * lseek on directories.
 *
 * smbc_lseekdir() may be used in conjunction with smbc_readdir() and
 * smbc_telldir(). (rewind by smbc_lseekdir(fd, 0, SEEK_SET))
 *
 * @param dh        Valid directory as returned by smbc_opendir()
 * 
 * @param offset    The offset (as returned by smbc_telldir) from
 *                  whence
 *
 * @param whence    A location in the directory stream:
 *                  - SEEK_SET this is the only one that makes sense...
 *                  - SEEK_CUR ???
 *                  - SEEK_END ???
 *
 * @return          I have no idea?
 *
 * @see             smbc_telldir()
 *
 * @todo What in the is the offset related to?  Bytes or directory 
 *       entry number?
 *
 * @todo In what do SEEK_SET and friends really mean?
 *
 * @todo In what does the reture and errno values mean?
 */
int smbc_lseekdir(int dh, off_t offset, int whence);


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
 *                  - ENOMEM Insufficient memory was available.
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             smbc_rmdir()
 *
 * @todo Are errno values complete and correct?
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
 *                  - ENOENT A directory component in pathname does not
 *                  exist.
 *                  - ENOTEMPTY directory contains entries.
 *                  - ENOMEM Insufficient kernel memory was available.
 *                  - EUCLEAN smbc_init() failed or has not been called
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
 *                  - EACCES Permission denied.
 *                  - ENOMEM Out of memory
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             Unix stat()
 *
 * @todo Are errno values complete and correct?
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
 *                  -EACCES Permission denied.
 *                  -ENOMEM Out of memory
 *                  - EUCLEAN smbc_init() failed or has not been called
 *
 * @see             smbc_stat(), Unix stat()
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
 * @param fname     I do not know what this is it the url of the file 
 *                  to print?
 *
 * @param printq    I do not know what this is, is it the url of the
 *                  printer to print to?
 *
  * @return          0 on success, < 0 on error with errno set:         
 *
 * @todo I have no idea what this does.  What is fname?  What is 
 *       printq?
 *
 * @todo What errno values are possible here
 */                                     
int smbc_print_file(const char *fname, const char *printq);

/**@ingroup print
 * Open a print file that can be written to by other calls. This simply
 * does an smbc_open call after checking if there is a file name on the
 * URI. If not, a temporary name is added ...
 *
 * @param fname     Is this the url of a print share?
 *
 * @returns         A file handle right?
 *
 * @todo    What errno values are possible here
 *
 * @todo    What is fname is it the url of a print share?
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
 *
 * @todo    what errno values are possible here?
 */

int smbc_list_print_jobs(const char *purl, smbc_get_print_job_info fn);

/**@ingroup print
 * Delete a print job 
 *
 * @param purl      Url of the print share
 *
 * @param id        The id of the job to delete
 *
 * @return          0 on success, < 0 on error with errno set: 
 *
 * @todo    what errno values are possible here?
 */
int smbc_unlink_print_job(const char *purl, int id);


#endif /* SMBCLIENT_H_INCLUDED */

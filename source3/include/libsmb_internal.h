#ifndef _LIBSMB_INTERNAL_H_
#define _LIBSMB_INTERNAL_H_

#define SMBC_MAX_NAME  1023
#define SMBC_FILE_MODE (S_IFREG | 0444)
#define SMBC_DIR_MODE  (S_IFDIR | 0555)


#include "include/libsmbclient.h"


struct _SMBCSRV {
	struct cli_state cli;
	dev_t dev;
	BOOL no_pathinfo2;
        BOOL no_nt_session;
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
         *
         * Leave room for any urlencoded filename and the comment field.
         *
         * We really should use sizeof(struct smbc_dirent) plus (NAME_MAX * 3)
         * plus whatever the max length of a comment is, plus a couple of null
         * terminators (one after the filename, one after the comment).
         *
         * According to <linux/limits.h>, NAME_MAX is 255.  Is it longer
         * anyplace else?
         */
	char    _dirent[1024];

	/** INTERNAL: server connection list
	 */
	SMBCSRV * _servers;
	
	/** INTERNAL: open file/dir list
	 */
	SMBCFILE * _files;
        /** user options selections that apply to this session
         */
        struct _smbc_options {

                /*
                 * From how many local master browsers should the list of
                 * workgroups be retrieved?  It can take up to 12 minutes or
                 * longer after a server becomes a local master browser, for
                 * it to have the entire browse list (the list of
                 * workgroups/domains) from an entire network.  Since a client
                 * never knows which local master browser will be found first,
                 * the one which is found first and used to retrieve a browse
                 * list may have an incomplete or empty browse list.  By
                 * requesting the browse list from multiple local master
                 * browsers, a more complete list can be generated.  For small
                 * networks (few workgroups), it is recommended that this
                 * value be set to 0, causing the browse lists from all found
                 * local master browsers to be retrieved and merged.  For
                 * networks with many workgroups, a suitable value for this
                 * variable is probably somewhere around 3. (Default: 3).
                 */
                int browse_max_lmb_count;

                /*
                 * There is a difference in the desired return strings from
                 * smbc_readdir() depending upon whether the filenames are to
                 * be displayed to the user, or whether they are to be
                 * appended to the path name passed to smbc_opendir() to call
                 * a further smbc_ function (e.g. open the file with
                 * smbc_open()).  In the former case, the filename should be
                 * in "human readable" form.  In the latter case, the smbc_
                 * functions expect a URL which must be url-encoded.  Those
                 * functions decode the URL.  If, for example, smbc_readdir()
                 * returned a file name of "abc%20def.txt", passing a path
                 * with this file name attached to smbc_open() would cause
                 * smbc_open to attempt to open the file "abc def.txt" since
                 * the %20 is decoded into a space.
                 *
                 * Set this option to True if the names returned by
                 * smbc_readdir() should be url-encoded such that they can be
                 * passed back to another smbc_ call.  Set it to False if the
                 * names returned by smbc_readdir() are to be presented to the
                 * user.
                 *
                 * For backwards compatibility, this option defaults to False.
                 */
                int urlencode_readdir_entries;

                /*
                 * Some Windows versions appear to have a limit to the number
                 * of concurrent SESSIONs and/or TREE CONNECTions.  In
                 * one-shot programs (i.e. the program runs and then quickly
                 * ends, thereby shutting down all connections), it is
                 * probably reasonable to establish a new connection for each
                 * share.  In long-running applications, the limitation can be
                 * avoided by using only a single connection to each server,
                 * and issuing a new TREE CONNECT when the share is accessed.
                 */
                int one_share_per_server;
        } options;
};	


#endif

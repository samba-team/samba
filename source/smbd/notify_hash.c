#define OLD_NTDOMAIN 1
/*
   Unix SMB/Netbios implementation.
   Version 3.0
   change notify handling - hash based implementation
   Copyright (C) Jeremy Allison 1994-1998
   Copyright (C) Andrew Tridgell 2000

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

#include "includes.h"

extern int DEBUGLEVEL;


struct change_data {
	time_t last_check_time; /* time we last checked this entry */
	time_t modify_time; /* Info from the directory we're monitoring. */ 
	time_t status_time; /* Info from the directory we're monitoring. */
	time_t total_time; /* Total time of all directory entries - don't care if it wraps. */
	unsigned int num_entries; /* Zero or the number of files in the directory. */
};


/****************************************************************************
 Create the hash we will use to determine if the contents changed.
*****************************************************************************/
static BOOL notify_hash(connection_struct *conn, char *path, uint32 flags, 
			struct change_data *data)
{
	SMB_STRUCT_STAT st;
	pstring full_name;
	char *p;
	char *fname;
	size_t remaining_len;
	size_t fullname_len;
	void *dp;

	ZERO_STRUCTP(data);

	if(dos_stat(path, &st) == -1) return False;
 
	data->modify_time = st.st_mtime;
	data->status_time = st.st_ctime;

	/*
	 * If we are to watch for changes that are only stored
	 * in inodes of files, not in the directory inode, we must
	 * scan the directory and produce a unique identifier with
	 * which we can determine if anything changed. We use the
	 * modify and change times from all the files in the
	 * directory, added together (ignoring wrapping if it's
	 * larger than the max time_t value).
	 */

	if (!(flags & (FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE))) return True;

	dp = OpenDir(conn, path, True);
	if (dp == NULL)	return False;

	data->num_entries = 0;
	
	pstrcpy(full_name, path);
	pstrcat(full_name, "/");
	
	fullname_len = strlen(full_name);
	remaining_len = sizeof(full_name) - fullname_len - 1;
	p = &full_name[fullname_len];
	
	while ((fname = ReadDirName(dp))) {
		if(strequal(fname, ".") || strequal(fname, "..")) continue;		

		data->num_entries++;
		safe_strcpy(p, fname, remaining_len);

		ZERO_STRUCT(st);

		/*
		 * Do the stat - but ignore errors.
		 */		
		dos_stat(full_name, &st);
		data->total_time += (st.st_mtime + st.st_ctime);
	}
	
	CloseDir(dp);
	
	return True;
}


/****************************************************************************
register a change notify request
*****************************************************************************/
static void *hash_register_notify(connection_struct *conn, char *path, uint32 flags)
{
	struct change_data data;

	if (!notify_hash(conn, path, flags, &data)) return NULL;

	data.last_check_time = time(NULL);

	return (void *)memdup(&data, sizeof(data));
}

/****************************************************************************
check if a change notify should be issued 
*****************************************************************************/
static BOOL hash_check_notify(connection_struct *conn, uint16 vuid, char *path, uint32 flags, void *datap, time_t t)
{
	struct change_data *data = (struct change_data *)datap;
	struct change_data data2;

	if (t < data->last_check_time + lp_change_notify_timeout()) return False;

	if (!become_user(conn,vuid)) return True;
	if (!become_service(conn,True)) {
		unbecome_user();
		return True;
	}

	if (!notify_hash(conn, path, flags, &data2) ||
	    data2.modify_time != data->modify_time ||
	    data2.status_time != data->status_time ||
	    data2.total_time != data->total_time ||
	    data2.num_entries != data->num_entries) {
		unbecome_user();
		return True;
	}

	data->last_check_time = t;	    
	unbecome_user();

	return False;
}

/****************************************************************************
remove a change notify data structure
*****************************************************************************/
static void hash_remove_notify(void *datap)
{
	free(datap);
}


/****************************************************************************
setup hash based change notify
****************************************************************************/
struct cnotify_fns *hash_notify_init(void) 
{
	static struct cnotify_fns cnotify;

	cnotify.register_notify = hash_register_notify;
	cnotify.check_notify = hash_check_notify;
	cnotify.remove_notify = hash_remove_notify;
	cnotify.select_time = lp_change_notify_timeout();

	return &cnotify;
}


/*
  change_notify_reply_packet(cnbp->request_buf,ERRSRV,ERRaccess);
  change_notify_reply_packet(cnbp->request_buf,0,NT_STATUS_NOTIFY_ENUM_DIR);

  chain_size = 0;
  file_chain_reset();

  uint16 vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : 
  SVAL(cnbp->request_buf,smb_uid);
*/

#undef OLD_NTDOMAIN

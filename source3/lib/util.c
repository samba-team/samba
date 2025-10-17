/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @brief  Small functions that don't fit anywhere else
 * @file   util.c
 */

#include "includes.h"
#include "system/passwd.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "lib/util/memcache.h"
#include "util_tdb.h"
#include "ctdbd_conn.h"
#include "../lib/util/util_pw.h"
#include "messages.h"
#include "lib/messaging/messages_dgm.h"
#include "libcli/security/security.h"
#include "serverid.h"
#include "lib/util/sys_rw.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/util_process.h"
#include "lib/dbwrap/dbwrap_ctdb.h"
#include "lib/gencache.h"
#include "lib/util/string_wrappers.h"
#include "lib/util/strv.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

/* Max allowable allococation - 256mb - 0x10000000 */
#define MAX_ALLOC_SIZE (1024*1024*256)

static enum protocol_types Protocol = PROTOCOL_COREPLUS;

void set_Protocol(enum protocol_types  p)
{
	Protocol = p;
}

static enum remote_arch_types ra_type = RA_UNKNOWN;

void gfree_all( void )
{
	gfree_loadparm();
	gfree_charcnv();
	gfree_interfaces();
	gfree_debugsyms();
	gfree_memcache();

}

/*******************************************************************
 Check if a file exists - call vfs_file_exist for samba files.
********************************************************************/

bool file_exist_stat(const char *fname,SMB_STRUCT_STAT *sbuf,
		     bool fake_dir_create_times)
{
	SMB_STRUCT_STAT st;
	if (!sbuf)
		sbuf = &st;

	if (sys_stat(fname, sbuf, fake_dir_create_times) != 0)
		return(False);

	return((S_ISREG(sbuf->st_ex_mode)) || (S_ISFIFO(sbuf->st_ex_mode)));
}

/*******************************************************************
 Check if a unix domain socket exists - call vfs_file_exist for samba files.
********************************************************************/

bool socket_exist(const char *fname)
{
	SMB_STRUCT_STAT st;
	if (sys_stat(fname, &st, false) != 0)
		return(False);

	return S_ISSOCK(st.st_ex_mode);
}

/*******************************************************************
 Returns the size in bytes of the named given the stat struct.
********************************************************************/

uint64_t get_file_size_stat(const SMB_STRUCT_STAT *sbuf)
{
	return sbuf->st_ex_size;
}

/****************************************************************************
 Check two stats have identical dev and ino fields.
****************************************************************************/

bool check_same_dev_ino(const SMB_STRUCT_STAT *sbuf1,
                        const SMB_STRUCT_STAT *sbuf2)
{
	return ((sbuf1->st_ex_dev == sbuf2->st_ex_dev) &&
		(sbuf1->st_ex_ino == sbuf2->st_ex_ino));
}

/****************************************************************************
 Check if a stat struct is identical for use.
****************************************************************************/

bool check_same_stat(const SMB_STRUCT_STAT *sbuf1,
		     const SMB_STRUCT_STAT *sbuf2)
{
	return ((sbuf1->st_ex_uid == sbuf2->st_ex_uid) &&
		(sbuf1->st_ex_gid == sbuf2->st_ex_gid) &&
		check_same_dev_ino(sbuf1, sbuf2));
}

/*******************************************************************
 Show a smb message structure.
********************************************************************/

void show_msg(const char *buf)
{
	char *msg = NULL;
	int i;
	int bcc=0;

	if (!DEBUGLVL(5))
		return;

	msg = talloc_asprintf(
		talloc_tos(),
		"size=%d\nsmb_com=0x%x\nsmb_rcls=%d\n"
		"smb_reh=%d\nsmb_err=%d\nsmb_flg=%d\nsmb_flg2=%d\n"
		"smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\n"
		"smt_wct=%d\n",
		smb_len(buf),
		(int)CVAL(buf, smb_com),
		(int)CVAL(buf, smb_rcls),
		(int)CVAL(buf, smb_reh),
		(int)SVAL(buf, smb_err),
		(int)CVAL(buf, smb_flg),
		(int)SVAL(buf, smb_flg2),
		(int)SVAL(buf, smb_tid),
		(int)SVAL(buf, smb_pid),
		(int)SVAL(buf, smb_uid),
		(int)SVAL(buf, smb_mid),
		(int)CVAL(buf, smb_wct));

	for (i=0;i<(int)CVAL(buf,smb_wct);i++) {
		talloc_asprintf_addbuf(&msg,
				       "smb_vwv[%2d]=%5d (0x%X)\n",
				       i,
				       SVAL(buf, smb_vwv + 2 * i),
				       SVAL(buf, smb_vwv + 2 * i));
	}

	bcc = (int)SVAL(buf,smb_vwv+2*(CVAL(buf,smb_wct)));

	talloc_asprintf_addbuf(&msg, "smb_bcc=%d\n", bcc);

	if (DEBUGLEVEL >= 10) {
		if (DEBUGLEVEL < 50) {
			bcc = MIN(bcc, 512);
		}
		dump_data_addbuf((const uint8_t *)smb_buf_const(buf),
				 bcc,
				 &msg);
	}

	DEBUG(5, ("%s", msg));
	TALLOC_FREE(msg);
}

/*******************************************************************
 Setup only the byte count for a smb message.
********************************************************************/

int set_message_bcc(char *buf,int num_bytes)
{
	int num_words = CVAL(buf,smb_wct);
	SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);
	_smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
	return (smb_size + num_words*2 + num_bytes);
}

/*******************************************************************
 Add a data blob to the end of a smb_buf, adjusting bcc and smb_len.
 Return the bytes added
********************************************************************/

ssize_t message_push_blob(uint8_t **outbuf, DATA_BLOB blob)
{
	size_t newlen = smb_len(*outbuf) + 4 + blob.length;
	uint8_t *tmp;

	if (!(tmp = talloc_realloc(NULL, *outbuf, uint8_t, newlen))) {
		DEBUG(0, ("talloc failed\n"));
		return -1;
	}
	*outbuf = tmp;

	memcpy(tmp + smb_len(tmp) + 4, blob.data, blob.length);
	set_message_bcc((char *)tmp, smb_buflen(tmp) + blob.length);
	return blob.length;
}

/*******************************************************************
 Reduce a file name, removing .. elements.
********************************************************************/

static char *dos_clean_name(TALLOC_CTX *ctx, const char *s)
{
	char *p = NULL;
	char *str = NULL;

	DEBUG(3,("dos_clean_name [%s]\n",s));

	/* remove any double slashes */
	str = talloc_all_string_sub(ctx, s, "\\\\", "\\");
	if (!str) {
		return NULL;
	}

	/* Remove leading .\\ characters */
	if(strncmp(str, ".\\", 2) == 0) {
		trim_string(str, ".\\", NULL);
		if(*str == 0) {
			str = talloc_strdup(ctx, ".\\");
			if (!str) {
				return NULL;
			}
		}
	}

	while ((p = strstr_m(str,"\\..\\")) != NULL) {
		char *s1;

		*p = 0;
		s1 = p+3;

		if ((p=strrchr_m(str,'\\')) != NULL) {
			*p = 0;
		} else {
			*str = 0;
		}
		str = talloc_asprintf(ctx,
				"%s%s",
				str,
				s1);
		if (!str) {
			return NULL;
		}
	}

	trim_string(str,NULL,"\\..");
	return talloc_all_string_sub(ctx, str, "\\.\\", "\\");
}

/*******************************************************************
 Reduce a file name, removing .. elements.
********************************************************************/

char *unix_clean_name(TALLOC_CTX *ctx, const char *s)
{
	char *p = NULL;
	char *str = NULL;

	DEBUG(3,("unix_clean_name [%s]\n",s));

	/* remove any double slashes */
	str = talloc_all_string_sub(ctx, s, "//","/");
	if (!str) {
		return NULL;
	}

	/* Remove leading ./ characters */
	if(strncmp(str, "./", 2) == 0) {
		trim_string(str, "./", NULL);
		if(*str == 0) {
			str = talloc_strdup(ctx, "./");
			if (!str) {
				return NULL;
			}
		}
	}

	while ((p = strstr_m(str,"/../")) != NULL) {
		char *s1;

		*p = 0;
		s1 = p+3;

		if ((p=strrchr_m(str,'/')) != NULL) {
			*p = 0;
		} else {
			*str = 0;
		}
		str = talloc_asprintf(ctx,
				"%s%s",
				str,
				s1);
		if (!str) {
			return NULL;
		}
	}

	trim_string(str,NULL,"/..");
	return talloc_all_string_sub(ctx, str, "/./", "/");
}

char *clean_name(TALLOC_CTX *ctx, const char *s)
{
	char *str = dos_clean_name(ctx, s);
	if (!str) {
		return NULL;
	}
	return unix_clean_name(ctx, str);
}

/*******************************************************************
 Write data into an fd at a given offset. Ignore seek errors.
********************************************************************/

ssize_t write_data_at_offset(int fd, const char *buffer, size_t N, off_t pos)
{
	size_t total=0;
	ssize_t ret;

	if (pos == (off_t)-1) {
		return write_data(fd, buffer, N);
	}
#if defined(HAVE_PWRITE) || defined(HAVE_PRWITE64)
	while (total < N) {
		ret = sys_pwrite(fd,buffer + total,N - total, pos);
		if (ret == -1 && errno == ESPIPE) {
			return write_data(fd, buffer + total,N - total);
		}
		if (ret == -1) {
			DEBUG(0,("write_data_at_offset: write failure. Error = %s\n", strerror(errno) ));
			return -1;
		}
		if (ret == 0) {
			return total;
		}
		total += ret;
		pos += ret;
	}
	return (ssize_t)total;
#else
	/* Use lseek and write_data. */
	if (lseek(fd, pos, SEEK_SET) == -1) {
		if (errno != ESPIPE) {
			return -1;
		}
	}
	return write_data(fd, buffer, N);
#endif
}

static int reinit_after_fork_pipe[2] = { -1, -1 };

NTSTATUS init_before_fork(void)
{
	int ret;

	ret = pipe(reinit_after_fork_pipe);
	if (ret == -1) {
		NTSTATUS status;

		status = map_nt_error_from_unix_common(errno);

		DEBUG(0, ("Error creating child_pipe: %s\n",
			  nt_errstr(status)));

		return status;
	}

	return NT_STATUS_OK;
}

/**
 * @brief Get a fd to watch for our parent process to exit
 *
 * Samba parent processes open a pipe that naturally closes when the
 * parent exits. Child processes can watch the read end of the pipe
 * for readability: Readability with 0 bytes to read means the parent
 * has exited and the child process might also want to exit.
 */

int parent_watch_fd(void)
{
	return reinit_after_fork_pipe[0];
}

/**
 * Detect died parent by detecting EOF on the pipe
 */
static void reinit_after_fork_pipe_handler(struct tevent_context *ev,
					   struct tevent_fd *fde,
					   uint16_t flags,
					   void *private_data)
{
	char c;

	if (sys_read(reinit_after_fork_pipe[0], &c, 1) != 1) {
		/*
		 * we have reached EOF on stdin, which means the
		 * parent has exited. Shutdown the server
		 */
		TALLOC_FREE(fde);
		(void)kill(getpid(), SIGTERM);
	}
}


NTSTATUS reinit_after_fork(struct messaging_context *msg_ctx,
			   struct tevent_context *ev_ctx,
			   bool parent_longlived)
{
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	/*
	 * The main process thread should never
	 * allow per_thread_cwd_enable() to be
	 * called.
	 */
	per_thread_cwd_disable();

	if (reinit_after_fork_pipe[1] != -1) {
		close(reinit_after_fork_pipe[1]);
		reinit_after_fork_pipe[1] = -1;
	}

	/* tdb needs special fork handling */
	if (tdb_reopen_all(parent_longlived ? 1 : 0) != 0) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
		status = NT_STATUS_OPEN_FAILED;
		goto done;
	}

	if (ev_ctx != NULL) {
		/*
		 * The parent can have different private data for the callbacks,
		 * which are gone in the child. Reset the callbacks to be safe.
		 */
		tevent_set_trace_callback(ev_ctx, NULL, NULL);
		tevent_set_trace_fd_callback(ev_ctx, NULL, NULL);
		tevent_set_trace_signal_callback(ev_ctx, NULL, NULL);
		tevent_set_trace_timer_callback(ev_ctx, NULL, NULL);
		tevent_set_trace_immediate_callback(ev_ctx, NULL, NULL);
		tevent_set_trace_queue_callback(ev_ctx, NULL, NULL);
		if (tevent_re_initialise(ev_ctx) != 0) {
			smb_panic(__location__ ": Failed to re-initialise event context");
		}
	}

	if (reinit_after_fork_pipe[0] != -1) {
		struct tevent_fd *fde;

		fde = tevent_add_fd(ev_ctx, ev_ctx /* TALLOC_CTX */,
				    reinit_after_fork_pipe[0], TEVENT_FD_READ,
				    reinit_after_fork_pipe_handler, NULL);
		if (fde == NULL) {
			smb_panic(__location__ ": Failed to add reinit_after_fork pipe event");
		}
	}

	if (msg_ctx) {
		/*
		 * For clustering, we need to re-init our ctdbd connection after the
		 * fork
		 */
		status = messaging_reinit(msg_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("messaging_reinit() failed: %s\n",
				 nt_errstr(status)));
			goto done;
		}

		if (lp_clustering()) {
			ret = ctdb_async_ctx_reinit(
				NULL, messaging_tevent_context(msg_ctx));
			if (ret != 0) {
				DBG_ERR("db_ctdb_async_ctx_reinit failed: %s\n",
					strerror(errno));
				return map_nt_error_from_unix(ret);
			}
		}
	}

 done:
	return status;
}

/****************************************************************************
 (Hopefully) efficient array append.
****************************************************************************/

void add_to_large_array(TALLOC_CTX *mem_ctx, size_t element_size,
			void *element, void *_array, uint32_t *num_elements,
			ssize_t *array_size)
{
	void **array = (void **)_array;

	if (*array_size < 0) {
		return;
	}

	if (*array == NULL) {
		if (*array_size == 0) {
			*array_size = 128;
		}

		if (*array_size >= MAX_ALLOC_SIZE/element_size) {
			goto error;
		}

		*array = talloc_size(mem_ctx, element_size * (*array_size));
		if (*array == NULL) {
			goto error;
		}
	}

	if (*num_elements == *array_size) {
		*array_size *= 2;

		if (*array_size >= MAX_ALLOC_SIZE/element_size) {
			goto error;
		}

		*array = TALLOC_REALLOC(mem_ctx, *array,
					element_size * (*array_size));

		if (*array == NULL) {
			goto error;
		}
	}

	memcpy((char *)(*array) + element_size*(*num_elements),
	       element, element_size);
	*num_elements += 1;

	return;

 error:
	*num_elements = 0;
	*array_size = -1;
}

/****************************************************************************
 Get my own domain name, or "" if we have none.
****************************************************************************/

char *get_mydnsdomname(TALLOC_CTX *ctx)
{
	const char *domname;
	char *p;

	domname = get_mydnsfullname();
	if (!domname) {
		return NULL;
	}

	p = strchr_m(domname, '.');
	if (p) {
		p++;
		return talloc_strdup(ctx, p);
	} else {
		return talloc_strdup(ctx, "");
	}
}

bool process_exists(const struct server_id pid)
{
	return serverid_exists(&pid);
}

/*******************************************************************
 Convert a uid into a user name.
********************************************************************/

const char *uidtoname(uid_t uid)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *name = NULL;
	struct passwd *pass = NULL;

	pass = getpwuid_alloc(ctx,uid);
	if (pass) {
		name = talloc_strdup(ctx,pass->pw_name);
		TALLOC_FREE(pass);
	} else {
		name = talloc_asprintf(ctx,
				"%ld",
				(long int)uid);
	}
	return name;
}

/*******************************************************************
 Convert a gid into a group name.
********************************************************************/

char *gidtoname(gid_t gid)
{
	struct group *grp;

	grp = getgrgid(gid);
	if (grp) {
		return talloc_strdup(talloc_tos(), grp->gr_name);
	}
	else {
		return talloc_asprintf(talloc_tos(),
					"%d",
					(int)gid);
	}
}

/*******************************************************************
 Convert a user name into a uid.
********************************************************************/

uid_t nametouid(const char *name)
{
	struct passwd *pass;
	char *p;
	uid_t u;

	pass = Get_Pwnam_alloc(talloc_tos(), name);
	if (pass) {
		u = pass->pw_uid;
		TALLOC_FREE(pass);
		return u;
	}

	u = (uid_t)strtol(name, &p, 0);
	if ((p != name) && (*p == '\0'))
		return u;

	return (uid_t)-1;
}

/*******************************************************************
 Convert a name to a gid_t if possible. Return -1 if not a group.
********************************************************************/

gid_t nametogid(const char *name)
{
	struct group *grp;
	char *p;
	gid_t g;

	g = (gid_t)strtol(name, &p, 0);
	if ((p != name) && (*p == '\0'))
		return g;

	grp = getgrnam(name);
	if (grp)
		return(grp->gr_gid);
	return (gid_t)-1;
}

/*******************************************************************
 Something really nasty happened - panic !
********************************************************************/

static void call_panic_action(const char *why, bool as_root)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *cmd;
	int result;

	cmd = lp_panic_action(talloc_tos(), lp_sub);
	if (cmd == NULL || cmd[0] == '\0') {
		return;
	}

	DBG_ERR("Calling panic action [%s]\n", cmd);

#if defined(HAVE_PRCTL) && defined(PR_SET_PTRACER)
	/*
	 * Make sure all children can attach a debugger.
	 */
	prctl(PR_SET_PTRACER, getpid(), 0, 0, 0);
#endif

	if (as_root) {
		become_root();
	}

	result = system(cmd);

	if (as_root) {
		unbecome_root();
	}

	if (result == -1)
		DBG_ERR("fork failed in panic action: %s\n",
			strerror(errno));
	else
		DBG_ERR("action returned status %d\n",
			WEXITSTATUS(result));
}

void smb_panic_s3(const char *why)
{
	call_panic_action(why, false);
	dump_core();
}

void log_panic_action(const char *msg)
{
	DBG_ERR("%s", msg);
	call_panic_action(msg, true);
}

/*******************************************************************
  A readdir wrapper which just returns the file name.
 ********************************************************************/

const char *readdirname(DIR *p)
{
	struct dirent *ptr;
	char *dname;

	if (!p)
		return(NULL);

	ptr = (struct dirent *)readdir(p);
	if (!ptr)
		return(NULL);

	dname = ptr->d_name;

	return talloc_strdup(talloc_tos(), dname);
}

/*******************************************************************
 Utility function used to decide if the last component
 of a path matches a (possibly wildcarded) entry in a namelist.
********************************************************************/

bool is_in_path(const char *name,
		struct name_compare_entry *namelist,
		bool case_sensitive)
{
	const char *last_component;

	/* if we have no list it's obviously not in the path */
	if ((namelist == NULL) || (namelist[0].name == NULL)) {
		return False;
	}

	/* Do not reject path components if namelist is set to '.*' */
	if (ISDOT(name) || ISDOTDOT(name)) {
		return false;
	}

	DEBUG(8, ("is_in_path: %s\n", name));

	/* Get the last component of the unix name. */
	last_component = strrchr_m(name, '/');
	if (!last_component) {
		last_component = name;
	} else {
		last_component++; /* Go past '/' */
	}

	for(; namelist->name != NULL; namelist++) {
		if(namelist->is_wild) {
			if (mask_match(last_component, namelist->name, case_sensitive)) {
				DEBUG(8,("is_in_path: mask match succeeded\n"));
				return True;
			}
		} else {
			if((case_sensitive && (strcmp(last_component, namelist->name) == 0))||
						(!case_sensitive && (strcasecmp_m(last_component, namelist->name) == 0))) {
				DEBUG(8,("is_in_path: match succeeded\n"));
				return True;
			}
		}
	}
	DEBUG(8,("is_in_path: match not found\n"));
	return False;
}

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 Simple routine to query existing file locks. Cruft in NFS and 64->32 bit mapping
 is dealt with in posix.c
 Returns True if we have information regarding this lock region (and returns
 F_UNLCK in *ptype if the region is unlocked). False if the call failed.
****************************************************************************/

bool fcntl_getlock(int fd, int op, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	struct flock lock;
	int ret;

	DEBUG(8,("fcntl_getlock fd=%d op=%d offset=%.0f count=%.0f type=%d\n",
		    fd,op,(double)*poffset,(double)*pcount,*ptype));

	lock.l_type = *ptype;
	lock.l_whence = SEEK_SET;
	lock.l_start = *poffset;
	lock.l_len = *pcount;
	lock.l_pid = 0;

	ret = sys_fcntl_ptr(fd,op,&lock);

	if (ret == -1) {
		int saved_errno = errno;
		DEBUG(3,("fcntl_getlock: lock request failed at offset %.0f count %.0f type %d (%s)\n",
			(double)*poffset,(double)*pcount,*ptype,strerror(errno)));
		errno = saved_errno;
		return False;
	}

	*ptype = lock.l_type;
	*poffset = lock.l_start;
	*pcount = lock.l_len;
	*ppid = lock.l_pid;

	DEBUG(3,("fcntl_getlock: fd %d is returned info %d pid %u\n",
			fd, (int)lock.l_type, (unsigned int)lock.l_pid));
	return True;
}

#if defined(HAVE_OFD_LOCKS)
int map_process_lock_to_ofd_lock(int op)
{
	switch (op) {
	case F_GETLK:
	case F_OFD_GETLK:
		op = F_OFD_GETLK;
		break;
	case F_SETLK:
	case F_OFD_SETLK:
		op = F_OFD_SETLK;
		break;
	case F_SETLKW:
	case F_OFD_SETLKW:
		op = F_OFD_SETLKW;
		break;
	default:
		return -1;
	}
	return op;
}
#else /* HAVE_OFD_LOCKS */
int map_process_lock_to_ofd_lock(int op)
{
	return op;
}
#endif /* HAVE_OFD_LOCKS */

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ALL

/*******************************************************************
 Is the name specified one of my netbios names.
 Returns true if it is equal, false otherwise.
********************************************************************/

static bool nb_name_equal(const char *s1, const char *s2)
{
	int cmp = strncasecmp_m(s1, s2, MAX_NETBIOSNAME_LEN-1);
	return (cmp == 0);
}

bool is_myname(const char *s)
{
	const char **aliases = NULL;
	bool ok = false;

	ok = nb_name_equal(lp_netbios_name(), s);
	if (ok) {
		goto done;
	}

	aliases = lp_netbios_aliases();
	if (aliases == NULL) {
		goto done;
	}

	while (*aliases != NULL) {
		ok = nb_name_equal(*aliases, s);
		if (ok) {
			goto done;
		}
		aliases += 1;
	}

done:
	DBG_DEBUG("is_myname(\"%s\") returns %d\n", s, (int)ok);
	return ok;
}

/*******************************************************************
 we distinguish between 2K and XP by the "Native Lan Manager" string
   WinXP => "Windows 2002 5.1"
   WinXP 64bit => "Windows XP 5.2"
   Win2k => "Windows 2000 5.0"
   NT4   => "Windows NT 4.0"
   Win9x => "Windows 4.0"
 Windows 2003 doesn't set the native lan manager string but
 they do set the domain to "Windows 2003 5.2" (probably a bug).
********************************************************************/

void ra_lanman_string( const char *native_lanman )
{
	if ( strcmp( native_lanman, "Windows 2002 5.1" ) == 0 )
		set_remote_arch( RA_WINXP );
	else if ( strcmp( native_lanman, "Windows XP 5.2" ) == 0 )
		set_remote_arch( RA_WINXP64 );
	else if ( strcmp( native_lanman, "Windows Server 2003 5.2" ) == 0 )
		set_remote_arch( RA_WIN2K3 );
}

static const char *remote_arch_strings[] = {
	[RA_UNKNOWN] =	"UNKNOWN",
	[RA_WFWG] =	"WfWg",
	[RA_OS2] =	"OS2",
	[RA_WIN95] =	"Win95",
	[RA_WINNT] =	"WinNT",
	[RA_WIN2K] =	"Win2K",
	[RA_WINXP] =	"WinXP",
	[RA_WIN2K3] =	"Win2K3",
	[RA_VISTA] =	"Vista",
	[RA_SAMBA] =	"Samba",
	[RA_CIFSFS] =	"CIFSFS",
	[RA_WINXP64] =	"WinXP64",
	[RA_OSX] =	"OSX",
};

const char *get_remote_arch_str(void)
{
	if (ra_type >= ARRAY_SIZE(remote_arch_strings)) {
		/*
		 * set_remote_arch() already checks this so ra_type
		 * should be in the allowed range, but anyway, let's
		 * do another bound check here.
		 */
		DBG_ERR("Remote arch info out of sync [%d] missing\n", ra_type);
		ra_type = RA_UNKNOWN;
	}
	return remote_arch_strings[ra_type];
}

enum remote_arch_types get_remote_arch_from_str(const char *remote_arch_string)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(remote_arch_strings); i++) {
		if (strcmp(remote_arch_string, remote_arch_strings[i]) == 0) {
			return i;
		}
	}
	return RA_UNKNOWN;
}

/*******************************************************************
 Set the horrid remote_arch string based on an enum.
********************************************************************/

void set_remote_arch(enum remote_arch_types type)
{
	if (ra_type >= ARRAY_SIZE(remote_arch_strings)) {
		/*
		 * This protects against someone adding values to enum
		 * remote_arch_types without updating
		 * remote_arch_strings array.
		 */
		DBG_ERR("Remote arch info out of sync [%d] missing\n", ra_type);
		ra_type = RA_UNKNOWN;
		return;
	}

	ra_type = type;
	DEBUG(10,("set_remote_arch: Client arch is \'%s\'\n",
		  get_remote_arch_str()));
}

/*******************************************************************
 Get the remote_arch type.
********************************************************************/

enum remote_arch_types get_remote_arch(void)
{
	return ra_type;
}

#define RA_CACHE_TTL 7*24*3600

static bool remote_arch_cache_key(const struct GUID *client_guid,
				  fstring key)
{
	struct GUID_txt_buf guid_buf;
	const char *guid_string = NULL;

	guid_string = GUID_buf_string(client_guid, &guid_buf);
	if (guid_string == NULL) {
		return false;
	}

	fstr_sprintf(key, "RA/%s", guid_string);
	return true;
}

struct ra_parser_state {
	bool found;
	enum remote_arch_types ra;
};

static void ra_parser(const struct gencache_timeout *t,
		      DATA_BLOB blob,
		      void *priv_data)
{
	struct ra_parser_state *state = (struct ra_parser_state *)priv_data;
	const char *ra_str = NULL;

	if (gencache_timeout_expired(t)) {
		return;
	}

	if ((blob.length == 0) || (blob.data[blob.length-1] != '\0')) {
		DBG_ERR("Remote arch cache key not a string\n");
		return;
	}

	ra_str = (const char *)blob.data;
	DBG_INFO("Got remote arch [%s] from cache\n", ra_str);

	state->ra = get_remote_arch_from_str(ra_str);
	state->found = true;
	return;
}

static bool remote_arch_cache_get(const struct GUID *client_guid)
{
	bool ok;
	fstring ra_key;
	struct ra_parser_state state = (struct ra_parser_state) {
		.found = false,
		.ra = RA_UNKNOWN,
	};

	ok = remote_arch_cache_key(client_guid, ra_key);
	if (!ok) {
		return false;
	}

	ok = gencache_parse(ra_key, ra_parser, &state);
	if (!ok || !state.found) {
		return true;
	}

	if (state.ra == RA_UNKNOWN) {
		return true;
	}

	set_remote_arch(state.ra);
	return true;
}

static bool remote_arch_cache_set(const struct GUID *client_guid)
{
	bool ok;
	fstring ra_key;
	const char *ra_str = NULL;

	if (get_remote_arch() == RA_UNKNOWN) {
		return true;
	}

	ok = remote_arch_cache_key(client_guid, ra_key);
	if (!ok) {
		return false;
	}

	ra_str = get_remote_arch_str();
	if (ra_str == NULL) {
		return false;
	}

	ok = gencache_set(ra_key, ra_str, time(NULL) + RA_CACHE_TTL);
	if (!ok) {
		return false;
	}

	return true;
}

bool remote_arch_cache_update(const struct GUID *client_guid)
{
	bool ok;

	if (get_remote_arch() == RA_UNKNOWN) {

		become_root();
		ok = remote_arch_cache_get(client_guid);
		unbecome_root();

		return ok;
	}

	become_root();
	ok = remote_arch_cache_set(client_guid);
	unbecome_root();

	return ok;
}

bool remote_arch_cache_delete(const struct GUID *client_guid)
{
	bool ok;
	fstring ra_key;

	ok = remote_arch_cache_key(client_guid, ra_key);
	if (!ok) {
		return false;
	}

	become_root();
	ok = gencache_del(ra_key);
	unbecome_root();

	if (!ok) {
		return false;
	}

	return true;
}


/*****************************************************************************
 Provide a checksum on a string

 Input:  s - the null-terminated character string for which the checksum
             will be calculated.

  Output: The checksum value calculated for s.
*****************************************************************************/

int str_checksum(const char *s)
{
	TDB_DATA key;
	if (s == NULL)
		return 0;

	key = (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			   .dsize = strlen(s) };

	return tdb_jenkins_hash(&key);
}

/*****************************************************************
 Zero a memory area then free it. Used to catch bugs faster.
*****************************************************************/

void zero_free(void *p, size_t size)
{
	memset(p, 0, size);
	SAFE_FREE(p);
}

/*****************************************************************
 Set our open file limit to a requested max and return the limit.
*****************************************************************/

int set_maxfiles(int requested_max)
{
#if (defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE))
	struct rlimit rlp;
	int saved_current_limit;

	if(getrlimit(RLIMIT_NOFILE, &rlp)) {
		DEBUG(0,("set_maxfiles: getrlimit (1) for RLIMIT_NOFILE failed with error %s\n",
			strerror(errno) ));
		/* just guess... */
		return requested_max;
	}

	/*
	 * Set the fd limit to be real_max_open_files + MAX_OPEN_FUDGEFACTOR to
	 * account for the extra fd we need
	 * as well as the log files and standard
	 * handles etc. Save the limit we want to set in case
	 * we are running on an OS that doesn't support this limit (AIX)
	 * which always returns RLIM_INFINITY for rlp.rlim_max.
	 */

	/* Try raising the hard (max) limit to the requested amount. */

#if defined(RLIM_INFINITY)
	if (rlp.rlim_max != RLIM_INFINITY) {
		int orig_max = rlp.rlim_max;

		if ( rlp.rlim_max < requested_max )
			rlp.rlim_max = requested_max;

		/* This failing is not an error - many systems (Linux) don't
			support our default request of 10,000 open files. JRA. */

		if(setrlimit(RLIMIT_NOFILE, &rlp)) {
			DEBUG(3,("set_maxfiles: setrlimit for RLIMIT_NOFILE for %d max files failed with error %s\n",
				(int)rlp.rlim_max, strerror(errno) ));

			/* Set failed - restore original value from get. */
			rlp.rlim_max = orig_max;
		}
	}
#endif

	/* Now try setting the soft (current) limit. */

	saved_current_limit = rlp.rlim_cur = MIN(requested_max,rlp.rlim_max);

	if(setrlimit(RLIMIT_NOFILE, &rlp)) {
		DEBUG(0,("set_maxfiles: setrlimit for RLIMIT_NOFILE for %d files failed with error %s\n",
			(int)rlp.rlim_cur, strerror(errno) ));
		/* just guess... */
		return saved_current_limit;
	}

	if(getrlimit(RLIMIT_NOFILE, &rlp)) {
		DEBUG(0,("set_maxfiles: getrlimit (2) for RLIMIT_NOFILE failed with error %s\n",
			strerror(errno) ));
		/* just guess... */
		return saved_current_limit;
    }

#if defined(RLIM_INFINITY)
	if(rlp.rlim_cur == RLIM_INFINITY)
		return saved_current_limit;
#endif

	if((int)rlp.rlim_cur > saved_current_limit)
		return saved_current_limit;

	return rlp.rlim_cur;
#else /* !defined(HAVE_GETRLIMIT) || !defined(RLIMIT_NOFILE) */
	/*
	 * No way to know - just guess...
	 */
	return requested_max;
#endif
}

/*****************************************************************
 malloc that aborts with smb_panic on fail or zero size.
 *****************************************************************/

void *smb_xmalloc_array(size_t size, unsigned int count)
{
	void *p;
	if (size == 0) {
		smb_panic("smb_xmalloc_array: called with zero size");
	}
        if (count >= MAX_ALLOC_SIZE/size) {
                smb_panic("smb_xmalloc_array: alloc size too large");
        }
	if ((p = SMB_MALLOC(size*count)) == NULL) {
		DEBUG(0, ("smb_xmalloc_array failed to allocate %lu * %lu bytes\n",
			(unsigned long)size, (unsigned long)count));
		smb_panic("smb_xmalloc_array: malloc failed");
	}
	return p;
}

/*****************************************************************
 Get local hostname and cache result.
*****************************************************************/

char *myhostname(void)
{
	static char *ret;
	if (ret == NULL) {
		ret = get_myname(NULL);
	}
	return ret;
}

/*****************************************************************
 Get local hostname and cache result.
*****************************************************************/

char *myhostname_upper(void)
{
	static char *ret;
	if (ret == NULL) {
		char *name = get_myname(NULL);
		if (name == NULL) {
			return NULL;
		}
		ret = strupper_talloc(NULL, name);
		talloc_free(name);
	}
	return ret;
}

/*******************************************************************
 Given a filename - get its directory name
********************************************************************/

bool parent_dirname(TALLOC_CTX *mem_ctx, const char *dir, char **parent,
		    const char **name)
{
	char *p;
	ptrdiff_t len;

	p = strrchr_m(dir, '/'); /* Find final '/', if any */

	if (p == NULL) {
		if (!(*parent = talloc_strdup(mem_ctx, "."))) {
			return False;
		}
		if (name) {
			*name = dir;
		}
		return True;
	}

	len = p-dir;

	*parent = talloc_strndup(mem_ctx, dir, len);
	if (*parent == NULL) {
		return False;
	}

	if (name) {
		*name = p+1;
	}
	return True;
}

/*******************************************************************
 Determine if a pattern contains any Microsoft wildcard characters.
*******************************************************************/

bool ms_has_wild(const char *s)
{
	const char *found = strpbrk(s, "*?<>\"");
	return (found != NULL);
}

bool ms_has_wild_w(const smb_ucs2_t *s)
{
	smb_ucs2_t c;
	if (!s) return False;
	while ((c = *s++)) {
		switch (c) {
		case UCS2_CHAR('*'):
		case UCS2_CHAR('?'):
		case UCS2_CHAR('<'):
		case UCS2_CHAR('>'):
		case UCS2_CHAR('"'):
			return True;
		}
	}
	return False;
}

/*******************************************************************
 A wrapper that handles case sensitivity and the special handling
 of the ".." name.
*******************************************************************/

bool mask_match(const char *string, const char *pattern, bool is_case_sensitive)
{
	if (ISDOTDOT(string))
		string = ".";
	if (ISDOT(pattern))
		return False;

	return ms_fnmatch_protocol(pattern, string, Protocol, is_case_sensitive) == 0;
}

/*******************************************************************
 A wrapper that handles a list of patterns and calls mask_match()
 on each.  Returns True if any of the patterns match.
*******************************************************************/

bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive)
{
       while (listLen-- > 0) {
               if (mask_match(string, *list++, is_case_sensitive))
                       return True;
       }
       return False;
}

struct server_id interpret_pid(const char *pid_string)
{
	return server_id_from_string(get_my_vnn(), pid_string);
}

/****************************************************************
 Check if an offset into a buffer is safe.
 If this returns True it's safe to indirect into the byte at
 pointer ptr+off.
****************************************************************/

bool is_offset_safe(const char *buf_base, size_t buf_len, char *ptr, size_t off)
{
	const char *end_base = buf_base + buf_len;
	char *end_ptr = ptr + off;

	if (!buf_base || !ptr) {
		return False;
	}

	if (end_base < buf_base || end_ptr < ptr) {
		return False; /* wrap. */
	}

	if (end_ptr < end_base) {
		return True;
	}
	return False;
}

/****************************************************************
 Return a safe pointer into a string within a buffer, or NULL.
****************************************************************/

char *get_safe_str_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off)
{
	if (!is_offset_safe(buf_base, buf_len, ptr, off)) {
		return NULL;
	}
	/* Check if a valid string exists at this offset. */
	if (skip_string(buf_base,buf_len, ptr + off) == NULL) {
		return NULL;
	}
	return ptr + off;
}


/****************************************************************
 Split DOM\user into DOM and user. Do not mix with winbind variants of that
 call (they take care of winbind separator and other winbind specific settings).
****************************************************************/

bool split_domain_user(TALLOC_CTX *mem_ctx,
		       const char *full_name,
		       char **domain,
		       char **user)
{
	const char *p = NULL;

	p = strchr_m(full_name, '\\');

	if (p != NULL) {
		*domain = talloc_strndup(mem_ctx, full_name,
					 PTR_DIFF(p, full_name));
		if (*domain == NULL) {
			return false;
		}
		*user = talloc_strdup(mem_ctx, p+1);
		if (*user == NULL) {
			TALLOC_FREE(*domain);
			return false;
		}
	} else {
		*domain = NULL;
		*user = talloc_strdup(mem_ctx, full_name);
		if (*user == NULL) {
			return false;
		}
	}

	return true;
}

/****************************************************************
 strip off leading '\\' from a hostname
****************************************************************/

const char *strip_hostname(const char *s)
{
	if (!s) {
		return NULL;
	}

	if (strlen_m(s) < 3) {
		return s;
	}

	if (s[0] == '\\') s++;
	if (s[0] == '\\') s++;

	return s;
}

bool any_nt_status_not_ok(NTSTATUS err1, NTSTATUS err2, NTSTATUS *result)
{
	if (!NT_STATUS_IS_OK(err1)) {
		*result = err1;
		return true;
	}
	if (!NT_STATUS_IS_OK(err2)) {
		*result = err2;
		return true;
	}
	return false;
}

int timeval_to_msec(struct timeval t)
{
	return t.tv_sec * 1000 + (t.tv_usec+999) / 1000;
}

/*******************************************************************
 Check a given DOS pathname is valid for a share.
********************************************************************/

char *valid_share_pathname(TALLOC_CTX *ctx, const char *dos_pathname)
{
	char *ptr = NULL;

	if (!dos_pathname) {
		return NULL;
	}

	ptr = talloc_strdup(ctx, dos_pathname);
	if (!ptr) {
		return NULL;
	}
	/* Convert any '\' paths to '/' */
	unix_format(ptr);
	ptr = unix_clean_name(ctx, ptr);
	if (!ptr) {
		return NULL;
	}

	/* NT is braindead - it wants a C: prefix to a pathname ! So strip it. */
	if (strlen(ptr) > 2 && ptr[1] == ':' && ptr[0] != '/')
		ptr += 2;

	/* Only absolute paths allowed. */
	if (*ptr != '/')
		return NULL;

	return ptr;
}

/*******************************************************************
 Return True if the filename is one of the special executable types.
********************************************************************/

bool is_executable(const char *fname)
{
	if ((fname = strrchr_m(fname,'.'))) {
		if (strequal(fname,".com") ||
		    strequal(fname,".dll") ||
		    strequal(fname,".exe") ||
		    strequal(fname,".sym")) {
			return True;
		}
	}
	return False;
}

/****************************************************************************
 Open a file with a share mode - old openX method - map into NTCreate.
****************************************************************************/

bool map_open_params_to_ntcreate(const char *smb_base_fname,
				 int deny_mode, int open_func,
				 uint32_t *paccess_mask,
				 uint32_t *pshare_mode,
				 uint32_t *pcreate_disposition,
				 uint32_t *pcreate_options,
				 uint32_t *pprivate_flags)
{
	uint32_t access_mask;
	uint32_t share_mode;
	uint32_t create_disposition;
	uint32_t create_options = FILE_NON_DIRECTORY_FILE;
	uint32_t private_flags = 0;

	DBG_DEBUG("fname = %s, deny_mode = 0x%x, open_func = 0x%x\n",
		  smb_base_fname,
		  (unsigned int)deny_mode,
		  (unsigned int)open_func);

	/* Create the NT compatible access_mask. */
	switch (GET_OPENX_MODE(deny_mode)) {
		case DOS_OPEN_EXEC: /* Implies read-only - used to be FILE_READ_DATA */
		case DOS_OPEN_RDONLY:
			access_mask = FILE_GENERIC_READ;
			break;
		case DOS_OPEN_WRONLY:
			access_mask = FILE_GENERIC_WRITE;
			break;
		case DOS_OPEN_RDWR:
		case DOS_OPEN_FCB:
			access_mask = FILE_GENERIC_READ|FILE_GENERIC_WRITE;
			break;
		default:
			DBG_DEBUG("bad open mode = 0x%x\n",
				  (unsigned int)GET_OPENX_MODE(deny_mode));
			return False;
	}

	/* Create the NT compatible create_disposition. */
	switch (open_func) {
		case OPENX_FILE_EXISTS_FAIL|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_CREATE;
			break;

		case OPENX_FILE_EXISTS_OPEN:
			create_disposition = FILE_OPEN;
			break;

		case OPENX_FILE_EXISTS_OPEN|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_OPEN_IF;
			break;

		case OPENX_FILE_EXISTS_TRUNCATE:
			create_disposition = FILE_OVERWRITE;
			break;

		case OPENX_FILE_EXISTS_TRUNCATE|OPENX_FILE_CREATE_IF_NOT_EXIST:
			create_disposition = FILE_OVERWRITE_IF;
			break;

		default:
			/* From samba4 - to be confirmed. */
			if (GET_OPENX_MODE(deny_mode) == DOS_OPEN_EXEC) {
				create_disposition = FILE_CREATE;
				break;
			}
			DBG_DEBUG("bad open_func 0x%x\n",
				  (unsigned int)open_func);
			return False;
	}

	/* Create the NT compatible share modes. */
	switch (GET_DENY_MODE(deny_mode)) {
		case DENY_ALL:
			share_mode = FILE_SHARE_NONE;
			break;

		case DENY_WRITE:
			share_mode = FILE_SHARE_READ;
			break;

		case DENY_READ:
			share_mode = FILE_SHARE_WRITE;
			break;

		case DENY_NONE:
			share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
			break;

		case DENY_DOS:
			private_flags |= NTCREATEX_FLAG_DENY_DOS;
	                if (is_executable(smb_base_fname)) {
				share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;
			} else {
				if (GET_OPENX_MODE(deny_mode) == DOS_OPEN_RDONLY) {
					share_mode = FILE_SHARE_READ;
				} else {
					share_mode = FILE_SHARE_NONE;
				}
			}
			break;

		case DENY_FCB:
			private_flags |= NTCREATEX_FLAG_DENY_FCB;
			share_mode = FILE_SHARE_NONE;
			break;

		default:
			DEBUG(10,("map_open_params_to_ntcreate: bad deny_mode 0x%x\n",
				(unsigned int)GET_DENY_MODE(deny_mode) ));
			return False;
	}

	DBG_DEBUG("file %s, access_mask = 0x%x, "
		  "share_mode = 0x%x, create_disposition = 0x%x, "
		  "create_options = 0x%x private_flags = 0x%x\n",
		  smb_base_fname,
		  (unsigned int)access_mask,
		  (unsigned int)share_mode,
		  (unsigned int)create_disposition,
		  (unsigned int)create_options,
		  (unsigned int)private_flags);

	if (paccess_mask) {
		*paccess_mask = access_mask;
	}
	if (pshare_mode) {
		*pshare_mode = share_mode;
	}
	if (pcreate_disposition) {
		*pcreate_disposition = create_disposition;
	}
	if (pcreate_options) {
		*pcreate_options = create_options;
	}
	if (pprivate_flags) {
		*pprivate_flags = private_flags;
	}

	return True;

}

/*************************************************************************
 Return a talloced copy of a struct security_unix_token. NULL on fail.
*************************************************************************/

struct security_unix_token *copy_unix_token(TALLOC_CTX *ctx, const struct security_unix_token *tok)
{
	struct security_unix_token *cpy;

	cpy = talloc(ctx, struct security_unix_token);
	if (!cpy) {
		return NULL;
	}

	*cpy = (struct security_unix_token){
		.uid = tok->uid,
		.gid = tok->gid,
		.ngroups = tok->ngroups,
	};

	if (tok->ngroups) {
		/* Make this a talloc child of cpy. */
		cpy->groups = (gid_t *)talloc_memdup(
			cpy, tok->groups, tok->ngroups * sizeof(gid_t));
		if (!cpy->groups) {
			TALLOC_FREE(cpy);
			return NULL;
		}
	}
	return cpy;
}

/****************************************************************************
 Return a root token
****************************************************************************/

struct security_unix_token *root_unix_token(TALLOC_CTX *mem_ctx)
{
	struct security_unix_token *t = NULL;

	t = talloc_zero(mem_ctx, struct security_unix_token);
	if (t == NULL) {
		return NULL;
	}

	/*
	 * This is not needed, but lets make it explicit, not implicit.
	 */
	*t = (struct security_unix_token) {
		.uid = 0,
		.gid = 0,
		.ngroups = 0,
		.groups = NULL
	};

	return t;
}

char *utok_string(TALLOC_CTX *mem_ctx, const struct security_unix_token *tok)
{
	char *str;
	uint32_t i;

	str = talloc_asprintf(
		mem_ctx,
		"uid=%ju, gid=%ju, %"PRIu32" groups:",
		(uintmax_t)(tok->uid),
		(uintmax_t)(tok->gid),
		tok->ngroups);

	for (i=0; i<tok->ngroups; i++) {
		talloc_asprintf_addbuf(
			&str, " %ju", (uintmax_t)tok->groups[i]);
	}

	return str;
}

/****************************************************************************
 Check that a file matches a particular file type.
****************************************************************************/

bool dir_check_ftype(uint32_t mode, uint32_t dirtype)
{
	uint32_t mask;

	/* Check the "may have" search bits. */
	if (((mode & ~dirtype) &
			(FILE_ATTRIBUTE_HIDDEN |
			 FILE_ATTRIBUTE_SYSTEM |
			 FILE_ATTRIBUTE_DIRECTORY)) != 0) {
		return false;
	}

	/* Check the "must have" bits,
	   which are the may have bits shifted eight */
	/* If must have bit is set, the file/dir can
	   not be returned in search unless the matching
	   file attribute is set */
	mask = ((dirtype >> 8) & (FILE_ATTRIBUTE_DIRECTORY|
				    FILE_ATTRIBUTE_ARCHIVE|
				   FILE_ATTRIBUTE_READONLY|
				     FILE_ATTRIBUTE_HIDDEN|
				     FILE_ATTRIBUTE_SYSTEM)); /* & 0x37 */
	if(mask) {
		if((mask & (mode & (FILE_ATTRIBUTE_DIRECTORY|
				      FILE_ATTRIBUTE_ARCHIVE|
				     FILE_ATTRIBUTE_READONLY|
				       FILE_ATTRIBUTE_HIDDEN|
					FILE_ATTRIBUTE_SYSTEM))) == mask) {
			/* check if matching attribute present */
			return true;
		} else {
			return false;
		}
	}

	return true;
}
